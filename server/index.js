'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { db } = require('./db');
const auth = require('./auth');
const hub = require('./hub');
const engine = require('./engine');
const sim = require('./simulator');
const { getSettings, saveSettings } = require('./settings');
const { sendWebhook } = require('./notify');
const { now, cleanIp, clamp, json, randToken } = require('./util');

const PORT = Number(process.env.PORT) || 3000;
const PUBLIC = path.join(__dirname, '..', 'public');
const AGENT_DIR = path.join(__dirname, '..', 'agent');
const SECURE = process.env.COOKIE_SECURE === '1' || process.env.NODE_ENV === 'production';
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const ALLOW_SIGNUP = process.env.ALLOW_SIGNUP !== '0';

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.json': 'application/json', '.py': 'text/x-python; charset=utf-8' };

const HEADERS = {
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Opener-Policy': 'same-origin', 'Permissions-Policy': 'geolocation=(), camera=(), microphone=()',
};
if (SECURE) HEADERS['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';

class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
const bad = (msg, status = 400) => new HttpError(status, msg);

function clientIp(req) {
  if (TRUST_PROXY && req.headers['x-forwarded-for']) return cleanIp(String(req.headers['x-forwarded-for']).split(',')[0]) || 'unknown';
  return cleanIp(req.socket.remoteAddress || '') || 'unknown';
}

function readBody(req, limit = 2 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => { size += c.length; if (size > limit) { reject(bad('Body too large', 413)); req.destroy(); } else chunks.push(c); });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(bad('Invalid JSON')); }
    });
    req.on('error', reject);
  });
}

function send(res, status, body, extra = {}) {
  const data = typeof body === 'string' ? body : JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...HEADERS, ...extra });
  res.end(data);
}

const routes = []; // {method, re, keys, handler, mode}
function route(method, p, mode, handler) {
  const keys = [];
  const re = new RegExp('^' + p.replace(/:(\w+)/g, (_, k) => { keys.push(k); return '([^/]+)'; }) + '$');
  routes.push({ method, re, keys, mode, handler });
}

const publicDevice = (d) => {
  const st = engine.states.get(d.id);
  return {
    id: d.id, name: d.name, virtual: !!d.virtual, hostname: d.hostname, os: d.os, agent_version: d.agent_version,
    enforce: !!d.enforce, status: d.status, last_seen: d.last_seen, key_prefix: d.virtual ? null : d.key_prefix, created: d.created,
    live: st ? { pps: Math.round(st.lastPps), baseline: st.learned ? Math.round(st.mean) : null, state: engine.statusOf(st) } : null,
  };
};
const userDevice = (user, id) => {
  const d = db.prepare('SELECT * FROM devices WHERE id=? AND user_id=?').get(Number(id), user.id);
  if (!d) throw bad('Device not found', 404);
  return d;
};
function createDevice(userId, name, virtual = 0) {
  const k = auth.newApiKey();
  const r = db.prepare('INSERT INTO devices(user_id,name,key_hash,key_prefix,virtual,status,created) VALUES(?,?,?,?,?,?,?)')
    .run(userId, name, k.hash, k.prefix, virtual, virtual ? 'online' : 'pending', now());
  return { id: Number(r.lastInsertRowid), key: k.key };
}
const checkIp = (v) => { const ip = cleanIp(String(v || '')); if (!ip) throw bad('Enter a valid IPv4 or IPv6 address'); return ip; };

// ------------------------------------------------------------------ auth routes
const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/;
route('POST', '/api/auth/signup', 'public', async (req, res, ctx) => {
  if (!ALLOW_SIGNUP) throw bad('Sign-ups are disabled on this server', 403);
  if (!auth.rateLimit('signup:' + ctx.ip, 10, 3600000)) throw bad('Too many sign-ups, try later', 429);
  const { email, password, name } = ctx.body;
  if (typeof email !== 'string' || !EMAIL.test(email)) throw bad('Enter a valid email');
  if (typeof password !== 'string' || password.length < 8 || password.length > 200) throw bad('Password must be 8 to 200 characters');
  const em = email.trim().toLowerCase();
  if (db.prepare('SELECT 1 FROM users WHERE email=?').get(em)) throw bad('An account with this email already exists', 409);
  const r = db.prepare('INSERT INTO users(email,name,pass_hash,created) VALUES(?,?,?,?)')
    .run(em, String(name || em.split('@')[0]).slice(0, 60), auth.hashPassword(password), now());
  const uid = Number(r.lastInsertRowid);
  engine.log(uid, null, 'INFO', 'Welcome to NetGuard AI. Add your first device to start protecting it.');
  const token = auth.createSession(uid);
  send(res, 201, { ok: true }, { 'Set-Cookie': auth.cookieHeader(token, SECURE) });
});

route('POST', '/api/auth/login', 'public', async (req, res, ctx) => {
  if (!auth.rateLimit('login:' + ctx.ip, 10, 15 * 60000)) throw bad('Too many attempts, wait 15 minutes', 429);
  const em = String(ctx.body.email || '').trim().toLowerCase();
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(em);
  const ok = u ? auth.verifyPassword(String(ctx.body.password || ''), u.pass_hash) : (auth.verifyPassword('x', 's1$AAAAAAAAAAAAAAAAAAAAAA==$' + 'A'.repeat(86)), false);
  if (!ok) throw bad('Wrong email or password', 401);
  send(res, 200, { ok: true }, { 'Set-Cookie': auth.cookieHeader(auth.createSession(u.id), SECURE) });
});

route('POST', '/api/auth/logout', 'user', async (req, res, ctx) => {
  auth.destroySession(ctx.user.token);
  send(res, 200, { ok: true }, { 'Set-Cookie': auth.clearCookieHeader() });
});

route('POST', '/api/auth/password', 'user', async (req, res, ctx) => {
  const u = db.prepare('SELECT pass_hash FROM users WHERE id=?').get(ctx.user.id);
  if (!auth.verifyPassword(String(ctx.body.current || ''), u.pass_hash)) throw bad('Current password is wrong', 403);
  const pw = ctx.body.password;
  if (typeof pw !== 'string' || pw.length < 8 || pw.length > 200) throw bad('New password must be 8 to 200 characters');
  db.prepare('UPDATE users SET pass_hash=? WHERE id=?').run(auth.hashPassword(pw), ctx.user.id);
  auth.destroyUserSessions(ctx.user.id);
  send(res, 200, { ok: true }, { 'Set-Cookie': auth.cookieHeader(auth.createSession(ctx.user.id), SECURE) });
});

route('GET', '/api/me', 'user', async (req, res, ctx) => send(res, 200, { id: ctx.user.id, email: ctx.user.email, name: ctx.user.name }));

// ------------------------------------------------------------------ devices
route('GET', '/api/devices', 'user', async (req, res, ctx) =>
  send(res, 200, db.prepare('SELECT * FROM devices WHERE user_id=? ORDER BY virtual DESC, id').all(ctx.user.id).map(publicDevice)));

route('POST', '/api/devices', 'user', async (req, res, ctx) => {
  const name = String(ctx.body.name || '').trim().slice(0, 60);
  if (!name) throw bad('Give the device a name');
  const n = db.prepare('SELECT COUNT(*) c FROM devices WHERE user_id=?').get(ctx.user.id).c;
  if (n >= 100) throw bad('Device limit reached');
  const d = createDevice(ctx.user.id, name);
  send(res, 201, { device: publicDevice(db.prepare('SELECT * FROM devices WHERE id=?').get(d.id)), api_key: d.key });
});

route('POST', '/api/devices/:id/rotate-key', 'user', async (req, res, ctx) => {
  const d = userDevice(ctx.user, ctx.params.id);
  if (d.virtual) throw bad('The demo device has no key');
  const k = auth.newApiKey();
  db.prepare('UPDATE devices SET key_hash=?, key_prefix=? WHERE id=?').run(k.hash, k.prefix, d.id);
  send(res, 200, { api_key: k.key });
});

route('DELETE', '/api/devices/:id', 'user', async (req, res, ctx) => {
  const d = userDevice(ctx.user, ctx.params.id);
  if (d.virtual) throw bad('The demo device cannot be removed');
  db.prepare('DELETE FROM devices WHERE id=?').run(d.id);
  engine.forgetDevice(d.id);
  send(res, 200, { ok: true });
});

route('GET', '/api/metrics/:id', 'user', async (req, res, ctx) => {
  const d = userDevice(ctx.user, ctx.params.id);
  const mins = clamp(ctx.query.get('minutes'), 1, 360, 5);
  send(res, 200, db.prepare('SELECT ts,pps FROM metrics WHERE device_id=? AND ts>? ORDER BY ts DESC LIMIT 900').all(d.id, now() - mins * 60000).reverse());
});

// ------------------------------------------------------------------ alerts
route('GET', '/api/alerts', 'user', async (req, res, ctx) => {
  const status = ctx.query.get('status');
  const limit = clamp(ctx.query.get('limit'), 1, 500, 100);
  const rows = status && ['open', 'ack', 'resolved'].includes(status)
    ? db.prepare('SELECT * FROM alerts WHERE user_id=? AND status=? ORDER BY created DESC LIMIT ?').all(ctx.user.id, status, limit)
    : db.prepare('SELECT * FROM alerts WHERE user_id=? ORDER BY created DESC LIMIT ?').all(ctx.user.id, limit);
  send(res, 200, rows.map(engine.publicAlert));
});

route('PATCH', '/api/alerts/:id', 'user', async (req, res, ctx) => {
  if (!['open', 'ack', 'resolved'].includes(ctx.body.status)) throw bad('Invalid status');
  const r = db.prepare('UPDATE alerts SET status=? WHERE id=? AND user_id=?').run(ctx.body.status, Number(ctx.params.id), ctx.user.id);
  if (!r.changes) throw bad('Alert not found', 404);
  hub.emit(ctx.user.id, 'alert_status', { id: Number(ctx.params.id), status: ctx.body.status });
  send(res, 200, { ok: true });
});

route('POST', '/api/alerts/:id/block', 'user', async (req, res, ctx) => {
  const a = db.prepare('SELECT * FROM alerts WHERE id=? AND user_id=?').get(Number(ctx.params.id), ctx.user.id);
  if (!a || !a.src_ip) throw bad('This alert has no source IP to block', 404);
  const why = engine.protectedReason(ctx.user.id, a.src_ip);
  if (why) throw bad(`Cannot block ${a.src_ip}: ${why}`, 409);
  const cfg = getSettings(ctx.user.id);
  const { block } = engine.addBlock(ctx.user.id, { ip: a.src_ip, reason: a.title, source: 'manual', scope: 'fleet', alertId: a.id, ttlMin: cfg.block_ttl_min });
  db.prepare('UPDATE alerts SET action=? WHERE id=?').run(`Blocked ${a.src_ip} manually`, a.id);
  send(res, 200, { ok: true, block });
});

// ------------------------------------------------------------------ blocks + allowlist
route('GET', '/api/blocks', 'user', async (req, res, ctx) => {
  const rows = db.prepare('SELECT * FROM blocks WHERE user_id=? AND active=1 ORDER BY created DESC').all(ctx.user.id);
  const enforcing = db.prepare('SELECT COUNT(*) c FROM devices WHERE user_id=? AND enforce=1 AND status=\'online\'').get(ctx.user.id).c;
  send(res, 200, { enforcing_devices: enforcing, blocks: rows.map((b) => ({ ...b, applied: engine.appliedCount(ctx.user.id, b.ip) })) });
});

route('POST', '/api/blocks', 'user', async (req, res, ctx) => {
  const ip = checkIp(ctx.body.ip);
  const why = engine.protectedReason(ctx.user.id, ip);
  if (why) throw bad(`Cannot block ${ip}: ${why}`, 409);
  const ttl = clamp(ctx.body.ttl_min, 0, 60 * 24 * 365, 0);
  const { block } = engine.addBlock(ctx.user.id, { ip, reason: String(ctx.body.reason || 'Blocked manually').slice(0, 200), source: 'manual', scope: 'fleet', ttlMin: ttl });
  send(res, 201, block);
});

route('DELETE', '/api/blocks/:id', 'user', async (req, res, ctx) => {
  if (!engine.removeBlock(ctx.user.id, Number(ctx.params.id))) throw bad('Block not found', 404);
  send(res, 200, { ok: true });
});

route('GET', '/api/allowlist', 'user', async (req, res, ctx) => send(res, 200, db.prepare('SELECT id,ip,note FROM allowlist WHERE user_id=?').all(ctx.user.id)));
route('POST', '/api/allowlist', 'user', async (req, res, ctx) => {
  const ip = checkIp(ctx.body.ip);
  db.prepare('INSERT OR IGNORE INTO allowlist(user_id,ip,note) VALUES(?,?,?)').run(ctx.user.id, ip, String(ctx.body.note || '').slice(0, 100));
  for (const b of db.prepare('SELECT id FROM blocks WHERE user_id=? AND ip=? AND active=1').all(ctx.user.id, ip)) engine.removeBlock(ctx.user.id, b.id);
  send(res, 201, { ok: true });
});
route('DELETE', '/api/allowlist/:id', 'user', async (req, res, ctx) => {
  db.prepare('DELETE FROM allowlist WHERE id=? AND user_id=?').run(Number(ctx.params.id), ctx.user.id);
  send(res, 200, { ok: true });
});

// ------------------------------------------------------------------ settings, stats, logs
route('GET', '/api/settings', 'user', async (req, res, ctx) => send(res, 200, getSettings(ctx.user.id)));
route('PUT', '/api/settings', 'user', async (req, res, ctx) => {
  try { send(res, 200, saveSettings(ctx.user.id, ctx.body)); } catch (e) { throw bad(e.message); }
});
route('POST', '/api/settings/test-webhook', 'user', async (req, res, ctx) => {
  const url = getSettings(ctx.user.id).webhook_url;
  if (!url) throw bad('Save a webhook URL first');
  try { await sendWebhook(url, { text: '[NetGuard AI] Test notification. Alerts will arrive here.' }); } catch (e) { throw bad('Webhook failed: ' + e.message); }
  send(res, 200, { ok: true });
});

route('GET', '/api/stats', 'user', async (req, res, ctx) => {
  const u = ctx.user.id, day = now() - 86400000;
  const c = (sql, ...a) => db.prepare(sql).get(...a).c;
  send(res, 200, {
    devices: c('SELECT COUNT(*) c FROM devices WHERE user_id=?', u),
    online: c("SELECT COUNT(*) c FROM devices WHERE user_id=? AND status='online'", u),
    open_alerts: c("SELECT COUNT(*) c FROM alerts WHERE user_id=? AND status='open'", u),
    alerts_24h: c('SELECT COUNT(*) c FROM alerts WHERE user_id=? AND created>?', u, day),
    blocked_total: c("SELECT COUNT(*) c FROM blocks WHERE user_id=? AND source='auto'", u),
    active_blocks: c('SELECT COUNT(*) c FROM blocks WHERE user_id=? AND active=1', u),
  });
});

route('GET', '/api/logs', 'user', async (req, res, ctx) =>
  send(res, 200, db.prepare('SELECT id,ts,level,msg,device_id FROM logs WHERE user_id=? ORDER BY id DESC LIMIT ?').all(ctx.user.id, clamp(ctx.query.get('limit'), 1, 500, 80)).reverse()));

// ------------------------------------------------------------------ insights, export
function insightsFor(u) {
  const t = now(), cfg = getSettings(u);
  const devs = db.prepare('SELECT status, enforce, virtual FROM devices WHERE user_id=? AND virtual=0').all(u);
  const open = db.prepare("SELECT severity, COUNT(*) c FROM alerts WHERE user_id=? AND status='open' GROUP BY severity").all(u);
  const n = (sev) => (open.find((o) => o.severity === sev) || { c: 0 }).c;
  // security score: starts at 100, loses points for real, fixable problems; each one comes with the fix
  const factors = [];
  const hit = (label, pts, fix) => { if (pts > 0) factors.push({ label, points: pts, fix }); };
  hit(`${n('critical')} open critical alert(s)`, Math.min(45, n('critical') * 15), 'Review and resolve them on the Alerts page');
  hit(`${n('high')} open high alert(s)`, Math.min(21, n('high') * 7), 'Acknowledge or resolve them on the Alerts page');
  hit(`${n('medium')} open medium alert(s)`, Math.min(10, n('medium') * 2), 'Acknowledge or resolve them');
  if (!cfg.auto_block) hit('Automatic blocking is off', 10, 'Turn on "Block attackers automatically" in Settings');
  const off = devs.filter((d) => d.status === 'offline').length;
  hit(`${off} device(s) offline`, Math.min(16, off * 8), 'Check that the agent is still running on them');
  const mon = devs.filter((d) => d.status === 'online' && !d.enforce).length;
  hit(`${mon} device(s) in monitor-only mode`, Math.min(10, mon * 5), 'Restart the agent with --enforce so it can block');
  if (!cfg.webhook_url) hit('No notifications set up', 3, 'Add a Slack or Discord webhook in Settings');
  const score = devs.length ? Math.max(0, 100 - factors.reduce((a, f) => a + f.points, 0)) : null;
  if (!devs.length) factors.length = 0;

  const since24 = t - 86400000;
  const buckets = Array.from({ length: 24 }, (_, i) => ({ start: since24 + i * 3600000, critical: 0, high: 0, other: 0 }));
  for (const a of db.prepare('SELECT created, severity FROM alerts WHERE user_id=? AND created>?').all(u, since24)) {
    const b = buckets[Math.min(23, Math.floor((a.created - since24) / 3600000))];
    if (a.severity === 'critical') b.critical++; else if (a.severity === 'high') b.high++; else b.other++;
  }
  const since7 = t - 7 * 86400000;
  const by_type = db.prepare('SELECT type, COUNT(*) c FROM alerts WHERE user_id=? AND created>? GROUP BY type ORDER BY c DESC').all(u, since7);
  const attackers = db.prepare("SELECT src_ip ip, COUNT(*) alerts, MAX(created) last, GROUP_CONCAT(DISTINCT type) types FROM alerts WHERE user_id=? AND src_ip IS NOT NULL AND created>? GROUP BY src_ip ORDER BY alerts DESC, last DESC LIMIT 6").all(u, since7)
    .map((a) => ({ ...a, types: String(a.types || '').split(','), blocked: !!db.prepare('SELECT 1 FROM blocks WHERE user_id=? AND ip=? AND active=1').get(u, a.ip) }));
  return { score, factors, timeline: buckets, by_type, attackers, auto_block: !!cfg.auto_block, sensitivity: cfg.sensitivity };
}
route('GET', '/api/insights', 'user', async (req, res, ctx) => send(res, 200, insightsFor(ctx.user.id)));

route('GET', '/api/alerts.csv', 'user', async (req, res, ctx) => {
  const cell = (v) => { let s = String(v == null ? '' : v); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; };
  const rows = db.prepare('SELECT * FROM alerts WHERE user_id=? ORDER BY created DESC LIMIT 5000').all(ctx.user.id);
  const csv = ['time_utc,severity,type,title,source_ip,device,action,status,count']
    .concat(rows.map((a) => [new Date(a.created).toISOString(), a.severity, a.type, a.title, a.src_ip, a.device_name, a.action, a.status, a.count].map(cell).join(','))).join('\r\n');
  res.writeHead(200, { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename="netguard-alerts.csv"', 'Cache-Control': 'no-store', ...HEADERS });
  res.end(csv);
});

// ------------------------------------------------------------------ IP inspector, threat hunt, copilot
const LABEL = { flood: 'traffic flood', port_scan: 'port scan', brute_force: 'brute-force login', conn_flood: 'connection flood', exposed_port: 'exposed service', physical_anomaly: 'physical event', traffic_drop: 'traffic drop', device_offline: 'device offline', canary: 'canary trap' };
const lab = (t) => LABEL[t] || String(t).replace(/_/g, ' ');
const ago = (ts) => { const m = Math.round((now() - ts) / 60000); return m < 1 ? 'just now' : m < 90 ? m + ' min ago' : m < 2880 ? Math.round(m / 60) + ' h ago' : Math.round(m / 1440) + ' days ago'; };
function ipReport(u, ip) {
  const alerts = db.prepare('SELECT id,created,type,severity,title,action,status FROM alerts WHERE user_id=? AND src_ip=? ORDER BY created DESC LIMIT 30').all(u, ip);
  const blocks = db.prepare('SELECT reason,source,created,expires,active FROM blocks WHERE user_id=? AND ip=? ORDER BY created DESC LIMIT 10').all(u, ip);
  const allow = db.prepare('SELECT note FROM allowlist WHERE user_id=? AND ip=?').get(u, ip);
  const protectedWhy = engine.protectedReason(u, ip) || null;
  const types = [...new Set(alerts.map((a) => a.type))];
  const active = blocks.some((b) => b.active);
  let verdict = 'Unknown: NetGuard has never seen this address.';
  if (allow) verdict = 'Trusted: this address is on your allowlist.';
  else if (protectedWhy) verdict = 'Protected: ' + protectedWhy + '.';
  else if (active) verdict = 'Dangerous: currently blocked.';
  else if (alerts.length) verdict = `Suspicious: caused ${alerts.length} alert(s) (${types.map(lab).join(', ')}).`;
  return { ip, verdict, allowlisted: !!allow, protected: protectedWhy, blocked: active, first_seen: alerts.length ? alerts[alerts.length - 1].created : null, last_seen: alerts.length ? alerts[0].created : null, alerts, blocks };
}
route('GET', '/api/ip/:ip', 'user', async (req, res, ctx) => send(res, 200, ipReport(ctx.user.id, checkIp(ctx.params.ip))));

route('GET', '/api/hunt', 'user', async (req, res, ctx) => {
  const q = String(ctx.query.get('q') || '').trim().slice(0, 80);
  if (q.length < 2) throw bad('Type at least 2 characters');
  const like = '%' + q.replace(/[\\%_]/g, (c) => '\\' + c) + '%';
  const alerts = db.prepare("SELECT id,created,type,severity,title,src_ip,device_name,action,status FROM alerts WHERE user_id=? AND (title LIKE ? ESCAPE '\\' OR src_ip LIKE ? ESCAPE '\\' OR type LIKE ? ESCAPE '\\' OR device_name LIKE ? ESCAPE '\\' OR action LIKE ? ESCAPE '\\') ORDER BY created DESC LIMIT 50").all(ctx.user.id, like, like, like, like, like);
  const logs = db.prepare("SELECT id,ts,level,msg FROM logs WHERE user_id=? AND msg LIKE ? ESCAPE '\\' ORDER BY id DESC LIMIT 50").all(ctx.user.id, like);
  send(res, 200, { alerts, logs });
});

// A rule-based security assistant. It answers only from this user's own data (no outside AI service).
route('POST', '/api/copilot', 'user', async (req, res, ctx) => {
  if (!auth.rateLimit('cop:' + ctx.user.id, 60, 60000)) throw bad('Slow down', 429);
  const u = ctx.user.id, q = String(ctx.body.question || '').toLowerCase().slice(0, 300), I = insightsFor(u);
  const links = [];
  let ans;
  const ipm = q.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
  const total24 = I.timeline.reduce((a, b) => a + b.critical + b.high + b.other, 0);
  const devs = db.prepare('SELECT name,status,enforce FROM devices WHERE user_id=? AND virtual=0').all(u);
  if (ipm && cleanIp(ipm[0])) {
    const r = ipReport(u, cleanIp(ipm[0]));
    ans = `${r.ip}: ${r.verdict}` + (r.last_seen ? ` Last seen ${ago(r.last_seen)}.` : '');
    if (!r.blocked && !r.allowlisted && !r.protected && r.alerts.length) links.push({ label: 'Open in IP Inspector', href: '#/tools?ip=' + r.ip });
  } else if (/safe|score|secur|protect|risk/.test(q)) {
    ans = I.score == null ? 'You have no real devices yet, so there is nothing to score. Add a device on the Devices page.' : `Your security score is ${I.score}/100 (${I.score >= 85 ? 'well protected' : I.score >= 60 ? 'needs attention' : 'at risk'}).` + (I.factors.length ? ' To raise it: ' + I.factors.map((f) => `${f.fix.toLowerCase()} (+${f.points})`).join('; ') + '.' : ' Nothing needs fixing.');
  } else if (/who|attack|top|hacker|ip/.test(q) && !/how|what should/.test(q)) {
    ans = I.attackers.length ? 'Top attackers this week: ' + I.attackers.slice(0, 4).map((a) => `${a.ip} (${a.types.map(lab).join(', ')}, ${a.blocked ? 'blocked' : 'NOT blocked'})`).join('; ') + '.' : 'No attackers seen in the last 7 days.';
    if (I.attackers.some((a) => !a.blocked)) links.push({ label: 'Block them on the dashboard', href: '#/dashboard' });
  } else if (/do|fix|improve|recommend|advice|should|next|help me/.test(q)) {
    ans = I.factors.length ? 'My recommendations, most important first: ' + I.factors.sort((a, b) => b.points - a.points).map((f, i) => `${i + 1}. ${f.fix}`).join(' ') : 'Everything looks healthy. Keep your agents updated and review alerts weekly.';
    links.push({ label: 'Open Settings', href: '#/settings' });
  } else if (/block/.test(q)) {
    const n = db.prepare('SELECT COUNT(*) c FROM blocks WHERE user_id=? AND active=1').get(u).c;
    ans = `${n} address(es) are blocked right now. Automatic blocking is ${I.auto_block ? 'on' : 'OFF'}.`; links.push({ label: 'Open Blocklist', href: '#/blocks' });
  } else if (/device|agent|online|offline|server/.test(q)) {
    ans = devs.length ? devs.map((d) => `${d.name}: ${d.status}${d.status === 'online' ? (d.enforce ? ', enforcing' : ', monitor-only') : ''}`).join('. ') + '.' : 'No devices yet.';
    links.push({ label: 'Open Devices', href: '#/devices' });
  } else if (/today|happen|summary|status|report|24|hour|overview|going on/.test(q)) {
    const worst = I.by_type[0];
    ans = total24 ? `In the last 24 hours NetGuard raised ${total24} alert(s)` + (worst ? `, mostly ${lab(worst.type)}` : '') + `. ${I.attackers.filter((a) => a.blocked).length} attacker(s) are blocked. Security score: ${I.score == null ? 'n/a' : I.score + '/100'}.` : 'Quiet day: no alerts in the last 24 hours.';
    links.push({ label: 'Open full incident report', href: '#/report' });
  } else {
    ans = 'I can answer from your own data. Try: "Am I safe?", "What happened today?", "Who is attacking me?", "What should I do?", "Which devices are online?", or paste an IP address to check it.';
  }
  send(res, 200, { answer: ans, links });
});

// ------------------------------------------------------------------ canary traps (honeytokens)
// A trap URL looks like a forgotten admin link. Nobody legitimate ever opens it, so whoever does is flagged and blocked.
const crypto = require('node:crypto');
route('GET', '/api/canaries', 'user', async (req, res, ctx) => send(res, 200, db.prepare('SELECT id,token,label,hits,last_hit,created FROM canaries WHERE user_id=? ORDER BY id DESC').all(ctx.user.id)));
route('POST', '/api/canaries', 'user', async (req, res, ctx) => {
  const label = String(ctx.body.label || '').trim().slice(0, 60) || 'Trap link';
  if (db.prepare('SELECT COUNT(*) c FROM canaries WHERE user_id=?').get(ctx.user.id).c >= 20) throw bad('You can have up to 20 traps');
  const token = crypto.randomBytes(9).toString('base64url');
  db.prepare('INSERT INTO canaries(user_id,token,label,created) VALUES(?,?,?,?)').run(ctx.user.id, token, label, now());
  send(res, 201, { token, label });
});
route('DELETE', '/api/canaries/:id', 'user', async (req, res, ctx) => {
  db.prepare('DELETE FROM canaries WHERE id=? AND user_id=?').run(Number(ctx.params.id), ctx.user.id);
  send(res, 200, { ok: true });
});
function triggerCanary(c, ip, ua) {
  const t = now(), u = c.user_id, cfg = getSettings(u);
  db.prepare('UPDATE canaries SET hits=hits+1,last_hit=? WHERE id=?').run(t, c.id);
  const recent = db.prepare("SELECT id FROM alerts WHERE user_id=? AND type='canary' AND src_ip=? AND created>?").get(u, ip, t - 60000);
  if (recent) { db.prepare('UPDATE alerts SET count=count+1, updated=? WHERE id=?').run(t, recent.id); return; }
  const title = `Trap "${c.label}" was opened by ${ip}`;
  const r = db.prepare('INSERT INTO alerts(user_id,device_id,device_name,type,severity,src_ip,title,detail,status,count,created,updated) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)')
    .run(u, null, 'Canary trap', 'canary', 'critical', ip, title.slice(0, 300), JSON.stringify({ trap: c.label, user_agent: String(ua || '').slice(0, 200) }), 'open', 1, t, t);
  const id = Number(r.lastInsertRowid);
  let action = 'Trap triggered. Anyone opening it is probing where they should not be.';
  const why = engine.protectedReason(u, ip);
  if (why) action = `Not blocked: ${why}`;
  else if (cfg.auto_block) { engine.addBlock(u, { ip, reason: title, source: 'auto', scope: 'fleet', alertId: id, ttlMin: cfg.block_ttl_min }); action = `Blocked ${ip} on all your devices`; }
  db.prepare('UPDATE alerts SET action=? WHERE id=?').run(action, id);
  hub.emit(u, 'alert', engine.publicAlert(db.prepare('SELECT * FROM alerts WHERE id=?').get(id)));
  engine.log(u, null, 'CRIT', `${title} | ${action}`);
}

// ------------------------------------------------------------------ simulator
route('POST', '/api/sim/attack', 'user', async (req, res, ctx) => {
  if (!['cyber', 'scan', 'brute', 'spark'].includes(ctx.body.type)) throw bad('Unknown attack type');
  if (!auth.rateLimit('sim:' + ctx.user.id, 20, 60000)) throw bad('Slow down', 429);
  if (!db.prepare('SELECT 1 FROM devices WHERE user_id=? AND virtual=1').get(ctx.user.id)) createDevice(ctx.user.id, 'Demo device (simulated)', 1);
  const r = sim.start(ctx.user.id, ctx.body.type);
  if (!r) throw bad('Demo device missing', 404);
  send(res, 200, { ok: true, listening: hub.listeners(ctx.user.id), attacker_ip: r.ip });
});
route('POST', '/api/sim/reset', 'user', async (req, res, ctx) => { sim.reset(ctx.user.id); send(res, 200, { ok: true }); });

// ------------------------------------------------------------------ agent API (Bearer device key)
route('POST', '/api/agent/telemetry', 'agent', async (req, res, ctx) => {
  if (!auth.rateLimit('tel:' + ctx.device.id, 120, 60000)) throw bad('Too many samples', 429);
  if (ctx.device.virtual) throw bad('Not for the demo device', 400);
  send(res, 200, engine.ingest(ctx.device, ctx.body, ctx.ip));
});
route('POST', '/api/agent/event', 'agent', async (req, res, ctx) => {
  if (!auth.rateLimit('evt:' + ctx.device.id, 60, 60000)) throw bad('Too many events', 429);
  send(res, 200, engine.ingestEvent(ctx.device, ctx.body));
});

route('GET', '/healthz', 'public', async (req, res) => send(res, 200, { ok: true, uptime: Math.round(process.uptime()) }));

// ------------------------------------------------------------------ dispatcher
function serveFile(res, file, headers = {}) {
  fs.readFile(file, (err, buf) => {
    if (err) return send(res, 404, { error: 'Not found' });
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-cache', ...HEADERS, ...headers });
    res.end(buf);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    const ip = clientIp(req);

    // live stream (Server-Sent Events)
    if (req.method === 'GET' && url.pathname === '/api/stream') {
      const user = auth.userFromRequest(req);
      if (!user) return send(res, 401, { error: 'Sign in required' });
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache, no-transform', Connection: 'keep-alive', 'X-Accel-Buffering': 'no', ...HEADERS });
      res.write('retry: 3000\n\n');
      hub.addClient(user.id, res);
      return;
    }

    if (url.pathname.startsWith('/api/') || url.pathname === '/healthz') {
      const r = routes.find((x) => x.method === req.method && x.re.test(url.pathname));
      if (!r) return send(res, 404, { error: 'Not found' });
      const m = r.re.exec(url.pathname);
      const params = Object.fromEntries(r.keys.map((k, i) => [k, decodeURIComponent(m[i + 1])]));
      const ctx = { ip, params, query: url.searchParams, body: {} };
      if (r.mode === 'user') {
        ctx.user = auth.userFromRequest(req);
        if (!ctx.user) throw bad('Sign in required', 401);
        if (req.method !== 'GET' && req.headers['x-requested-with'] !== 'NetGuard') throw bad('Missing CSRF header', 403);
      } else if (r.mode === 'agent') {
        ctx.device = auth.deviceFromRequest(req);
        if (!ctx.device) throw bad('Invalid or missing API key', 401);
      } else if (r.mode === 'public' && req.method !== 'GET' && req.headers['x-requested-with'] !== 'NetGuard') {
        throw bad('Missing CSRF header', 403);
      }
      if (req.method !== 'GET' && req.method !== 'DELETE') ctx.body = await readBody(req);
      return await r.handler(req, res, ctx);
    }

    // canary trap: always answers like an ordinary missing page, so attackers learn nothing
    if (req.method === 'GET' && url.pathname.startsWith('/c/')) {
      const c = db.prepare('SELECT * FROM canaries WHERE token=?').get(url.pathname.slice(3, 40));
      if (c && ip !== 'unknown') { try { triggerCanary(c, ip, req.headers['user-agent']); } catch { /* never break the response */ } }
      return send(res, 404, { error: 'Not found' });
    }

    // downloads + static files
    if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, { error: 'Method not allowed' });
    if (url.pathname === '/install.sh') {
      const proto = TRUST_PROXY ? String(req.headers['x-forwarded-proto'] || 'https').split(',')[0].trim() : 'http';
      const host = String(req.headers.host || '');
      const origin = process.env.PUBLIC_URL || `${proto}://${host}`;
      if (!/^https?:\/\/[A-Za-z0-9.\-]+(:\d+)?$/.test(origin)) return send(res, 400, { error: 'Bad host' });
      return send(res, 200, installScript(origin.replace(/\/$/, '')), { 'Content-Type': 'text/x-shellscript; charset=utf-8' });
    }
    if (url.pathname === '/agent/netguard_agent.py') return serveFile(res, path.join(AGENT_DIR, 'netguard_agent.py'), { 'Content-Disposition': 'attachment; filename="netguard_agent.py"' });
    let rel = decodeURIComponent(url.pathname);
    if (rel === '/') rel = '/index.html';
    const file = path.normalize(path.join(PUBLIC, rel));
    if (!file.startsWith(PUBLIC + path.sep)) return send(res, 403, { error: 'Forbidden' });
    return serveFile(res, file);
  } catch (e) {
    if (e instanceof HttpError) return send(res, e.status, { error: e.message });
    console.error('[error]', e);
    if (!res.headersSent) send(res, 500, { error: 'Server error' });
  }
});

// One-command Linux installer: curl -fsSL https://HOST/install.sh | sudo NETGUARD_KEY=ng_... bash
function installScript(origin) {
  return `#!/usr/bin/env bash
# NetGuard AI agent installer. Installs the agent as a systemd service that starts on boot.
set -euo pipefail
SERVER="${origin}"
KEY="\${NETGUARD_KEY:-}"
[ -n "$KEY" ] || { echo "Missing key. Run: curl -fsSL $SERVER/install.sh | sudo NETGUARD_KEY=ng_xxx bash"; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "Please run as root (use sudo)."; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required."; exit 1; }
command -v systemctl >/dev/null || { echo "systemd not found. Run the agent manually: see $SERVER"; exit 1; }
echo "[1/4] Downloading agent"
mkdir -p /opt/netguard
curl -fsSL "$SERVER/agent/netguard_agent.py" -o /opt/netguard/netguard_agent.py
echo "[2/4] Installing dependency (psutil)"
python3 -c "import psutil" 2>/dev/null || apt-get install -y python3-psutil 2>/dev/null || dnf install -y python3-psutil 2>/dev/null || pip3 install psutil 2>/dev/null || pip3 install --break-system-packages psutil
echo "[3/4] Saving configuration"
umask 077
printf 'NETGUARD_SERVER=%s\nNETGUARD_KEY=%s\n' "$SERVER" "$KEY" > /etc/netguard.env
echo "[4/4] Starting service"
cat > /etc/systemd/system/netguard-agent.service <<'UNIT'
[Unit]
Description=NetGuard AI agent
After=network-online.target
Wants=network-online.target
[Service]
EnvironmentFile=/etc/netguard.env
ExecStart=/usr/bin/env python3 /opt/netguard/netguard_agent.py --enforce --sniff
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now netguard-agent
echo "Done. This machine will appear as online in your NetGuard dashboard within a few seconds."
echo "Check status: systemctl status netguard-agent   |   Uninstall: systemctl disable --now netguard-agent"
`;
}

function lanAddresses() {
  return Object.values(os.networkInterfaces()).flat().filter((i) => i && i.family === 'IPv4' && !i.internal).map((i) => i.address);
}

if (require.main === module) {
  server.listen(PORT, process.env.HOST || '0.0.0.0', () => {
    console.log(`\n  NetGuard AI is running\n  Open:  http://localhost:${PORT}`);
    for (const a of lanAddresses()) console.log(`  LAN:   http://${a}:${PORT}`);
    console.log('\n  Create an account, add a device, then install the agent on it.\n');
  });
  const stop = () => { server.close(); process.exit(0); };
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
}
module.exports = { server };
