'use strict';
// Demo device: generates synthetic telemetry and pushes it through the SAME engine as real agents,
// so detection, alerts and blocking in the demo are the real code paths. Blocks stop simulated attacks.
const { db } = require('./db');
const engine = require('./engine');
const hub = require('./hub');
const { now } = require('./util');

const scenarios = new Map(); // userId -> { type, ip, until, tick }
const rand = (a, b) => Math.floor(Math.random() * (b - a + 1)) + a;

function start(userId, type) {
  const ip = { cyber: '218.92.0.204', scan: '185.220.101.42', brute: '45.155.205.109' }[type] || `10.0.4.${rand(20, 250)}`; // labelled sample attackers (Demo only)
  const dev = db.prepare('SELECT * FROM devices WHERE user_id=? AND virtual=1').get(userId);
  if (!dev) return null;
  if (type === 'spark') {
    scenarios.set(userId, { type, ip: null, until: now() + 7000, tick: 0 });
    engine.ingestEvent(dev, {
      type: 'physical_anomaly', severity: 'critical', sensor: 'PS-14',
      title: 'Physical anomaly: electrical arc detected on Feeder-2 (sensor PS-14)', action: 'shutdown', hold_s: 7,
    });
  } else {
    const dur = { cyber: 8000, scan: 10000, brute: 10000 }[type];
    if (!dur) return null;
    scenarios.set(userId, { type, ip, until: now() + dur, tick: 0 });
    engine.log(userId, dev.id, 'INFO', `Simulator: ${type} attack started from ${ip}`);
  }
  return { ip };
}
function reset(userId) { scenarios.delete(userId); }

function payload(userId, dev) {
  const sc = scenarios.get(userId);
  const blocks = engine.desiredBlocks(userId, dev.id);
  const p = {
    pps: rand(100, 150), hostname: 'plc-gateway-01', os: 'Simulated OT network', agent_version: 'sim', enforce: true,
    interval: 1, own_ips: ['10.0.0.1', '10.0.0.2'], enforced: blocks, power: 'online',
    connections: Array.from({ length: rand(4, 9) }, (_, i) => ({ ip: `10.0.1.${10 + i}`, lport: 502, state: 'ESTABLISHED' })),
    sources: [], auth_failures: {}, listening: [{ port: 502, addr: '10.0.0.2', proc: 'modbus-gw' }],
  };
  if (!sc) return p;
  if (now() > sc.until) { scenarios.delete(userId); return p; }
  sc.tick += 1;
  const blocked = sc.ip && blocks.includes(sc.ip);
  if (sc.type === 'spark') { p.pps = 0; p.power = 'shutdown'; p.connections = []; return p; }
  if (blocked) return p; // attacker cut off by the firewall rule
  if (sc.type === 'cyber') {
    p.pps = 2000;
    p.sources = [{ ip: sc.ip, pkts: 1900, syns: 1500, ports: [502] }];
  } else if (sc.type === 'scan') {
    p.pps += 60;
    p.sources = [{ ip: sc.ip, pkts: 60, syns: 60, ports: Array.from({ length: 12 }, () => rand(1, 10000)) }];
  } else if (sc.type === 'brute') {
    p.auth_failures = { [sc.ip]: rand(3, 5) };
  }
  return p;
}

setInterval(() => {
  const devs = db.prepare('SELECT * FROM devices WHERE virtual=1').all();
  for (const d of devs) {
    if (!hub.listeners(d.user_id) && !scenarios.has(d.user_id)) continue;
    try { engine.ingest(d, payload(d.user_id, d), null); } catch (e) { console.error('sim error', e); }
  }
}, 1000).unref();

module.exports = { start, reset };
