'use strict';
/*
 * NetGuard detection + response engine.
 *
 * Every agent sample goes through ingest():
 *   1. learn a per-device traffic baseline (Welford mean/variance), then keep it adaptive (EWMA,
 *      frozen while an anomaly is in progress so an attack cannot "teach" the model that it is normal)
 *   2. run detectors: traffic flood, per-source flood, port scan, connection flood, SSH/login
 *      brute force, sudden traffic drop, exposed risky services, device offline
 *   3. respond: raise a de-duplicated alert, block the attacking IP (fleet-wide or per device,
 *      with TTL), notify a webhook, and push everything live to the dashboard
 * Agents receive the full desired block list in every response and reconcile their firewall to it.
 */
const { db } = require('./db');
const hub = require('./hub');
const { now, cleanIp, isLoopbackOrSpecial, clamp, json } = require('./util');
const { getSettings } = require('./settings');
const { sendWebhook } = require('./notify');

const states = new Map(); // deviceId -> runtime state (rebuilt after restart; baseline re-learns)

const RISKY_PORTS = {
  23: 'Telnet', 2323: 'Telnet (alt)', 3389: 'Remote Desktop', 5900: 'VNC', 445: 'SMB', 139: 'NetBIOS',
  6379: 'Redis', 27017: 'MongoDB', 9200: 'Elasticsearch', 3306: 'MySQL', 5432: 'PostgreSQL',
  502: 'Modbus/TCP (no authentication)', 20000: 'DNP3', 44818: 'EtherNet/IP', 102: 'Siemens S7',
};
const K = { low: 6, medium: 4, high: 3 };
const MULT = { low: 3, medium: 2.2, high: 1.6 };
const MIN_DELTA = { low: 150, medium: 80, high: 40 };

function stateFor(device) {
  let s = states.get(device.id);
  if (!s) {
    s = {
      userId: device.user_id, n: 0, mean: 0, m2: 0, variance: 0, learned: false, over: 0, low: 0,
      protect: new Set(), agentIp: null, enforced: [], lastPps: 0,
      scan: new Map(), brute: new Map(), cooldown: new Map(), warned: new Set(),
      safeUntil: 0, attackUntil: 0, thr: null,
    };
    states.set(device.id, s);
  }
  return s;
}
const forgetDevice = (id) => states.delete(id);

// ------------------------------------------------------------------ logging / alert plumbing
function log(userId, deviceId, level, msg) {
  const ts = now();
  let demo = 0;
  if (deviceId) { const d = db.prepare('SELECT virtual FROM devices WHERE id=?').get(deviceId); demo = d && d.virtual ? 1 : 0; }
  const r = db.prepare('INSERT INTO logs(user_id,device_id,ts,level,msg,demo) VALUES(?,?,?,?,?,?)').run(userId, deviceId || null, ts, level, String(msg).slice(0, 500), demo);
  hub.emit(userId, 'log', { id: Number(r.lastInsertRowid), ts, level, msg, device_id: deviceId || null, demo });
}

function protectedReason(userId, ip) {
  if (isLoopbackOrSpecial(ip)) return 'special/loopback address';
  if (db.prepare('SELECT 1 FROM allowlist WHERE user_id=? AND ip=?').get(userId, ip)) return 'on your allowlist';
  for (const st of states.values()) {
    if (st.userId !== userId) continue;
    if (st.protect.has(ip)) return 'this is your own device, gateway or DNS server';
    if (st.agentIp === ip) return 'this is the address your agent connects from';
  }
  return null;
}

// Real devices only ever receive REAL blocks; the demo device only ever sees demo blocks.
// This is what guarantees a simulator action can never reach a real firewall.
function desiredBlocks(userId, deviceId) {
  const d = db.prepare('SELECT virtual, mode FROM devices WHERE id=?').get(deviceId);
  if (d && d.virtual) {
    return db.prepare('SELECT ip FROM blocks WHERE user_id=? AND demo=1 AND active=1 AND (expires IS NULL OR expires>?) AND device_id=?')
      .all(userId, now(), deviceId).map((r) => r.ip);
  }
  // Dry run: a monitor-only device only ever receives blocks the owner created by hand, never automatic ones.
  const onlyManual = d && d.mode === 'monitor' ? " AND source='manual'" : '';
  return db.prepare(`SELECT ip FROM blocks WHERE user_id=? AND demo=0 AND active=1 AND (expires IS NULL OR expires>?) AND (scope='fleet' OR device_id=?)${onlyManual}`)
    .all(userId, now(), deviceId).map((r) => r.ip);
}

function appliedCount(userId, ip) {
  let n = 0;
  for (const st of states.values()) if (st.userId === userId && !st.virtual && st.enforced.includes(ip)) n += 1;
  return n;
}

function addBlock(userId, { ip, reason, source = 'auto', scope = 'fleet', deviceId = null, alertId = null, ttlMin = 0, demo = 0 }) {
  if (demo) { scope = 'device'; }
  const existing = db.prepare('SELECT * FROM blocks WHERE user_id=? AND ip=? AND active=1 AND demo=?').get(userId, ip, demo ? 1 : 0);
  if (existing) return { block: existing, created: false };
  const t = now();
  const r = db.prepare('INSERT INTO blocks(user_id,device_id,ip,reason,source,scope,alert_id,active,created,expires,demo) VALUES(?,?,?,?,?,?,?,1,?,?,?)')
    .run(userId, scope === 'device' ? deviceId : null, ip, reason.slice(0, 300), source, scope, alertId, t, ttlMin > 0 ? t + ttlMin * 60000 : null, demo ? 1 : 0);
  const block = db.prepare('SELECT * FROM blocks WHERE id=?').get(Number(r.lastInsertRowid));
  hub.emit(userId, 'block', { ...block, applied: 0 });
  log(userId, deviceId, 'OK', `${demo ? '[Demo] ' : ''}Firewall rule created: block ${ip} (${source}, ${scope === 'fleet' ? 'all devices' : 'one device'})`);
  return { block, created: true };
}

function removeBlock(userId, id) {
  const b = db.prepare('SELECT * FROM blocks WHERE id=? AND user_id=? AND active=1').get(id, userId);
  if (!b) return false;
  db.prepare('UPDATE blocks SET active=0 WHERE id=?').run(id);
  hub.emit(userId, 'unblock', { id, ip: b.ip });
  log(userId, b.device_id || null, 'INFO', `${b.demo ? '[Demo] ' : ''}Block removed: ${b.ip}`);
  return true;
}

const fresh = (d) => db.prepare('SELECT mode FROM devices WHERE id=?').get(d.id) || d; // mode may change while the agent is running
function raise(device, a) {
  const userId = device.user_id;
  const st = stateFor(device);
  const t = now();
  const key = `${a.type}|${a.src_ip || ''}`;
  const last = st.cooldown.get(key);
  if (a.src_ip) st.attackUntil = t + 10000;
  if (last && t - last.at < 60000) {
    db.prepare('UPDATE alerts SET count=count+1, updated=? WHERE id=?').run(t, last.id);
    hub.emit(userId, 'alert_update', { id: last.id, updated: t });
    return last.id;
  }
  const cfg = getSettings(userId);
  const r = db.prepare('INSERT INTO alerts(user_id,device_id,device_name,type,severity,src_ip,title,detail,status,count,created,updated,demo) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)')
    .run(userId, device.id, device.name, a.type, a.severity, a.src_ip || null, a.title.slice(0, 300), JSON.stringify(a.detail || {}), 'open', 1, t, t, device.virtual ? 1 : 0);
  const id = Number(r.lastInsertRowid);
  st.cooldown.set(key, { at: t, id });
  if (['critical', 'high'].includes(a.severity)) st.attackUntil = t + 10000;

  let action = a.action || null;
  if (a.src_ip && a.blockable) {
    const why = protectedReason(userId, a.src_ip);
    if (why) action = `Not blocked: ${why}`;
    else if (device.virtual) {
      // Demo traffic: the block exists only on the simulated device and is labelled Demo. It never touches a real device.
      const { block } = addBlock(userId, { ip: a.src_ip, reason: a.title, source: 'auto', scope: 'device', deviceId: device.id, alertId: id, ttlMin: cfg.block_ttl_min, demo: 1 });
      action = `[Demo] Blocked ${a.src_ip} on the simulated device` + (block.expires ? ` for ${cfg.block_ttl_min} min` : '');
    }
    else if (!cfg.auto_block) action = 'Auto-block is off. Review and block manually.';
    else if ((fresh(device).mode || 'live') === 'monitor') {
      action = `Dry run: would have blocked ${a.src_ip}. This device is in monitor-only mode, so nothing was blocked.`;
    }
    else {
      const { block } = addBlock(userId, {
        ip: a.src_ip, reason: a.title, source: 'auto', scope: cfg.block_scope, deviceId: device.id, alertId: id, ttlMin: cfg.block_ttl_min,
      });
      action = `Blocked ${a.src_ip}` + (cfg.block_scope === 'fleet' ? ' on all your devices' : ` on ${device.name}`) + (block.expires ? ` for ${cfg.block_ttl_min} min` : '');
    }
  }
  if (action) db.prepare('UPDATE alerts SET action=? WHERE id=?').run(action, id);
  const row = db.prepare('SELECT * FROM alerts WHERE id=?').get(id);
  hub.emit(userId, 'alert', publicAlert(row));
  log(userId, device.id, a.severity === 'critical' || a.severity === 'high' ? 'CRIT' : 'WARN', `${device.virtual ? '[Demo] ' : ''}${a.title}${action ? ' | ' + action : ''}`);

  if (cfg.webhook_url && !device.virtual && ['critical', 'high'].includes(a.severity)) {
    sendWebhook(cfg.webhook_url, {
      text: `[NetGuard AI] ${a.severity.toUpperCase()}: ${a.title} on ${device.name}${action ? '. ' + action : ''}`,
      alert: { type: a.type, severity: a.severity, src_ip: a.src_ip || null, device: device.name, action },
    }).catch((e) => log(userId, device.id, 'WARN', 'Webhook failed: ' + e.message));
  }
  return id;
}

const publicAlert = (r) => ({ ...r, detail: json(r.detail) });

// ------------------------------------------------------------------ payload validation
function str(v, max) { return typeof v === 'string' ? v.replace(/[^\x20-\x7e]/g, '').slice(0, max) : ''; }
function normalize(raw) {
  const r = raw && typeof raw === 'object' ? raw : {};
  const arr = (v, max) => (Array.isArray(v) ? v.slice(0, max) : []);
  const t = {
    pps: clamp(r.pps, 0, 1e8, 0), hostname: str(r.hostname, 100), os: str(r.os, 60), agent_version: str(r.agent_version, 20),
    enforce: !!r.enforce, interval: clamp(r.interval, 1, 60, 2), power: str(r.power, 20),
    sources: [], connections: [], listening: [], auth_failures: {}, own_ips: [], enforced: [],
  };
  for (const s of arr(r.sources, 500)) {
    const ip = cleanIp(s && s.ip); if (!ip) continue;
    t.sources.push({
      ip, pkts: clamp(s.pkts, 0, 1e9, 0), syns: clamp(s.syns, 0, 1e9, 0),
      ports: arr(s.ports, 300).map((p) => clamp(p, 0, 65535, 0)).filter(Boolean),
    });
  }
  for (const c of arr(r.connections, 3000)) {
    const ip = cleanIp(c && c.ip); if (!ip) continue;
    t.connections.push({ ip, lport: clamp(c.lport, 0, 65535, 0), state: str(c.state, 16) });
  }
  for (const l of arr(r.listening, 500)) {
    t.listening.push({ port: clamp(l && l.port, 0, 65535, 0), addr: str(l && l.addr, 45), proc: str(l && l.proc, 40) });
  }
  if (r.auth_failures && typeof r.auth_failures === 'object') {
    for (const [k, v] of Object.entries(r.auth_failures).slice(0, 200)) { const ip = cleanIp(k); if (ip) t.auth_failures[ip] = clamp(v, 0, 1e6, 0); }
  }
  for (const k of ['own_ips', 'gateways', 'enforced']) {
    const out = arr(r[k], 200).map(cleanIp).filter(Boolean);
    if (k === 'enforced') t.enforced = out; else t.own_ips.push(...out);
  }
  return t;
}

// ------------------------------------------------------------------ main entry point
function ingest(device, raw, remoteAddr) {
  const t = normalize(raw);
  const userId = device.user_id;
  const cfg = getSettings(userId);
  const st = stateFor(device);
  const ts = now();
  st.virtual = !!device.virtual;
  st.agentIp = device.virtual ? null : cleanIp(remoteAddr || '');
  st.protect = new Set(t.own_ips);
  st.enforced = t.enforced;

  const wasStatus = device.status;
  db.prepare('UPDATE devices SET hostname=?, os=?, agent_version=?, enforce=?, status=?, last_seen=? WHERE id=?')
    .run(t.hostname || device.hostname, t.os || device.os, t.agent_version || device.agent_version, t.enforce ? 1 : 0, 'online', ts, device.id);
  if (wasStatus !== 'online') {
    log(userId, device.id, 'OK', `${device.name} is online${t.hostname ? ' (' + t.hostname + ')' : ''}${t.enforce ? ', enforcement ON' : ', monitor-only'}`);
    hub.emit(userId, 'device', { id: device.id, status: 'online', last_seen: ts });
  }

  const x = t.pps;
  st.lastPps = x;
  let anomalous = false;

  // ---- 1. adaptive baseline -------------------------------------------------------------
  if (!st.learned) {
    st.n += 1;
    const d = x - st.mean; st.mean += d / st.n; st.m2 += d * (x - st.mean);
    if (st.n >= cfg.learn_samples) {
      st.variance = st.m2 / Math.max(1, st.n - 1);
      st.learned = true;
      log(userId, device.id, 'OK', `${device.name}: baseline learned, normal traffic about ${Math.round(st.mean)} pkt/s`);
    }
  } else {
    const std = Math.sqrt(st.variance);
    const thr = Math.max(st.mean + K[cfg.sensitivity] * std, st.mean * MULT[cfg.sensitivity], st.mean + MIN_DELTA[cfg.sensitivity]);
    st.thr = thr;
    if (x > thr) { st.over += 1; anomalous = true; } else {
      st.over = 0;
      const a = 0.02, dv = x - st.mean;
      st.mean += a * dv; st.variance = (1 - a) * (st.variance + a * dv * dv);
    }
    // sudden drop to ~0: link cut, device crashed, emergency shutdown
    if (st.mean >= 20 && x < st.mean * 0.05) st.low += 1; else st.low = 0;

    if (anomalous && (st.over >= 2 || x > thr * 3)) {
      const top = topSource(t, x);
      raise(device, {
        type: 'flood', severity: 'critical', src_ip: top ? top.ip : null, blockable: !!top,
        title: `Traffic spike: ${Math.round(x)} pkt/s (normal about ${Math.round(st.mean)})` + (top ? ` from ${top.ip}` : ' from many sources'),
        action: top ? null : 'Distributed flood: no single source to block. Rate-limit upstream or enable your provider\'s DDoS protection.',
        detail: { pps: Math.round(x), baseline_mean: Math.round(st.mean), threshold: Math.round(thr), top_source: top },
      });
    }
    if (st.low >= 3) {
      raise(device, {
        type: 'traffic_drop', severity: 'high', title: `Traffic dropped to ${Math.round(x)} pkt/s (normal about ${Math.round(st.mean)})`,
        action: 'Check link, power and the device itself.', detail: { pps: Math.round(x), baseline_mean: Math.round(st.mean) },
      });
    }
  }

  // ---- 2. per-source detectors ----------------------------------------------------------
  const ignorable = (ip) => isLoopbackOrSpecial(ip) || st.protect.has(ip) || !!db.prepare('SELECT 1 FROM allowlist WHERE user_id=? AND ip=?').get(userId, ip);

  for (const s of t.sources) {
    if (ignorable(s.ip)) continue;
    if (s.pkts >= cfg.src_pps_limit || s.syns >= cfg.src_pps_limit * 0.6) {
      raise(device, {
        type: 'flood', severity: 'critical', src_ip: s.ip, blockable: true,
        title: `Traffic spike: ${Math.round(Math.max(s.pkts, x))} pkt/s from ${s.ip}`,
        detail: { pkts_per_s: Math.round(s.pkts), syn_per_s: Math.round(s.syns), limit: cfg.src_pps_limit },
      });
    }
    trackScan(st, s.ip, s.ports, ts);
  }
  const perIp = new Map();
  for (const c of t.connections) {
    if (ignorable(c.ip)) continue;
    perIp.set(c.ip, (perIp.get(c.ip) || 0) + 1);
    if (c.lport) trackScan(st, c.ip, [c.lport], ts);
  }
  for (const [ip, n] of perIp) {
    if (n >= cfg.conn_limit) {
      raise(device, {
        type: 'conn_flood', severity: 'high', src_ip: ip, blockable: true,
        title: `${n} simultaneous connections from ${ip} (limit ${cfg.conn_limit})`, detail: { connections: n, limit: cfg.conn_limit },
      });
    }
  }
  for (const [ip, m] of st.scan) {
    for (const [p, at] of m) if (ts - at > 30000) m.delete(p);
    if (!m.size) { st.scan.delete(ip); continue; }
    if (m.size >= cfg.port_scan_ports) {
      raise(device, {
        type: 'port_scan', severity: 'high', src_ip: ip, blockable: true,
        title: `Port scan: ${ip} probed ${m.size} different ports in 30 s`, detail: { ports: [...m.keys()].sort((a, b) => a - b).slice(0, 60) },
      });
    }
  }
  for (const [ip, n] of Object.entries(t.auth_failures)) {
    if (!n || ignorable(ip)) continue;
    const list = (st.brute.get(ip) || []).filter((e) => ts - e.at < 60000);
    list.push({ at: ts, n }); st.brute.set(ip, list);
    const total = list.reduce((a, e) => a + e.n, 0);
    if (total >= cfg.brute_force_attempts) {
      raise(device, {
        type: 'brute_force', severity: 'high', src_ip: ip, blockable: true,
        title: `Brute force: ${total} failed logins from ${ip} in 60 s`, detail: { failed_logins: total, window_s: 60 },
      });
    }
  }
  for (const [ip, list] of st.brute) { if (!list.some((e) => ts - e.at < 60000)) st.brute.delete(ip); }

  // ---- 3. exposure check ----------------------------------------------------------------
  for (const l of t.listening) {
    const wildcard = ['0.0.0.0', '::', '*', ''].includes(l.addr);
    if (wildcard && RISKY_PORTS[l.port] && !st.warned.has(l.port)) {
      st.warned.add(l.port);
      raise(device, {
        type: 'exposed_service', severity: 'medium',
        title: `${RISKY_PORTS[l.port]} (port ${l.port}) is listening on all interfaces${l.proc ? ' [' + l.proc + ']' : ''}`,
        action: 'Bind it to localhost or restrict it with a firewall.', detail: l,
      });
    }
  }

  // ---- 4. persist + push live -----------------------------------------------------------
  db.prepare('INSERT INTO metrics(device_id,ts,pps,conns) VALUES(?,?,?,?)').run(device.id, ts, x, t.connections.length);
  hub.emit(userId, 'telemetry', {
    device_id: device.id, ts, pps: Math.round(x), conns: t.connections.length, status: statusOf(st, ts),
    baseline: st.learned ? Math.round(st.mean) : null, threshold: st.thr ? Math.round(st.thr) : null,
    learning: st.learned ? 1 : Math.min(1, st.n / cfg.learn_samples), power: t.power || null, enforce: t.enforce,
  });
  return { ok: true, blocks: desiredBlocks(userId, device.id), interval: t.interval };
}

function topSource(t, pps) {
  if (t.sources.length) {
    const s = [...t.sources].sort((a, b) => b.pkts - a.pkts)[0];
    if (s.pkts >= 0.4 * pps) return { ip: s.ip, pkts: Math.round(s.pkts) };
  } else if (t.connections.length >= 20) {
    const m = new Map();
    for (const c of t.connections) m.set(c.ip, (m.get(c.ip) || 0) + 1);
    const [ip, n] = [...m].sort((a, b) => b[1] - a[1])[0];
    if (n >= 0.3 * t.connections.length && n >= 20) return { ip, connections: n };
  }
  return null;
}

function trackScan(st, ip, ports, ts) {
  if (!ports || !ports.length) return;
  let m = st.scan.get(ip);
  if (!m) { m = new Map(); st.scan.set(ip, m); }
  for (const p of ports) m.set(p, ts);
}

function statusOf(st, ts = now()) {
  if (st.safeUntil > ts) return 'safe_mode';
  if (!st.learned) return 'learning';
  if (st.attackUntil > ts || st.over > 0) return 'under_attack';
  return 'nominal';
}

// Out-of-band events from sensors / PLC gateways, e.g. a physical anomaly (arc, over-temperature).
function ingestEvent(device, ev) {
  const userId = device.user_id;
  const st = stateFor(device);
  const sev = ['critical', 'high', 'medium', 'low', 'info'].includes(ev.severity) ? ev.severity : 'high';
  const ip = cleanIp(ev.src_ip);
  const title = str(ev.title, 200) || 'Sensor event';
  if (ev.action === 'shutdown') st.safeUntil = now() + clamp(ev.hold_s, 1, 3600, 30) * 1000;
  raise(device, {
    type: str(ev.type, 30) || 'sensor_event', severity: sev, title, src_ip: ip, blockable: !!ip && ev.block === true,
    action: ev.action === 'shutdown' ? 'Emergency shutdown: load shed, devices in safe mode. Awaiting operator reset.' : null,
    detail: { ...(ev.detail && typeof ev.detail === 'object' ? json(JSON.stringify(ev.detail).slice(0, 2000)) : {}), sensor: str(ev.sensor, 60) },
  });
  hub.emit(userId, 'telemetry_state', { device_id: device.id, status: statusOf(st) });
  return { ok: true };
}

// ------------------------------------------------------------------ background sweeps
function sweep() {
  const t = now();
  // expire blocks
  for (const b of db.prepare('SELECT * FROM blocks WHERE active=1 AND expires IS NOT NULL AND expires<?').all(t)) {
    db.prepare('UPDATE blocks SET active=0 WHERE id=?').run(b.id);
    hub.emit(b.user_id, 'unblock', { id: b.id, ip: b.ip });
    log(b.user_id, null, 'INFO', `Block expired: ${b.ip}`);
  }
  // offline watchdog (real agents only)
  for (const d of db.prepare("SELECT d.* FROM devices d JOIN users u ON u.id=d.user_id WHERE d.virtual=0 AND u.read_only=0 AND d.status='online'").all()) {
    if (t - (d.last_seen || 0) > 30000) {
      db.prepare("UPDATE devices SET status='offline' WHERE id=?").run(d.id);
      hub.emit(d.user_id, 'device', { id: d.id, status: 'offline', last_seen: d.last_seen });
      raise({ ...d, status: 'offline' }, { type: 'device_offline', severity: 'medium', title: `${d.name} stopped reporting`, action: 'Agent stopped, host is down or the network path is cut.' });
    }
  }
}
function prune() {
  const t = now();
  db.prepare('DELETE FROM metrics WHERE ts<?').run(t - 6 * 3600 * 1000);
  db.prepare('DELETE FROM alerts WHERE created<?').run(t - 90 * 86400 * 1000);
  for (const u of db.prepare('SELECT id FROM users').all()) {
    db.prepare('DELETE FROM logs WHERE user_id=? AND id < (SELECT COALESCE(MAX(id),0) FROM logs WHERE user_id=?) - 2000').run(u.id, u.id);
  }
  db.prepare('DELETE FROM blocks WHERE active=0 AND created<?').run(t - 30 * 86400 * 1000);
}
setInterval(sweep, 10000).unref();
setInterval(prune, 3600000).unref();

module.exports = {
  ingest, ingestEvent, addBlock, removeBlock, protectedReason, desiredBlocks, appliedCount, publicAlert, forgetDevice,
  log, stateFor, statusOf, states,
};
