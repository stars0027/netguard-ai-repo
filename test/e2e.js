'use strict';
// End-to-end test: boots the real server on a temp DB and drives it over HTTP like a browser + agent would.
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs');
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-test-'));
process.env.ALLOW_PRIVATE_WEBHOOKS = '1';
const { server } = require('../server/index.js');
const http = require('node:http');

let pass = 0, fail = 0;
const ok = (cond, name) => { cond ? pass++ : fail++; console.log((cond ? '  PASS ' : '  FAIL ') + name); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  let cookie = '';
  const call = async (method, p, body, opts = {}) => {
    const headers = { 'Content-Type': 'application/json', ...(opts.noCsrf ? {} : { 'X-Requested-With': 'NetGuard' }), ...(opts.key ? { Authorization: 'Bearer ' + opts.key } : { Cookie: cookie }) };
    const res = await fetch(base + p, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    const sc = res.headers.get('set-cookie'); if (sc) cookie = sc.split(';')[0];
    let data = {}; try { data = await res.json(); } catch { /* */ }
    return { status: res.status, data, headers: res.headers };
  };

  console.log('auth');
  ok((await call('GET', '/api/me')).status === 401, 'unauthenticated /api/me is 401');
  ok((await call('POST', '/api/auth/signup', { email: 'a@b.co', password: 'short' })).status === 400, 'weak password rejected');
  ok((await call('POST', '/api/auth/signup', { email: 'a@b.co', password: 'correct horse 9', name: 'Ann' })).status === 201, 'signup works');
  ok((await call('GET', '/api/me')).data.email === 'a@b.co', 'session cookie works');
  ok((await call('POST', '/api/settings/test-webhook', {}, { noCsrf: true })).status === 403, 'CSRF header required on writes');
  const csp = (await call('GET', '/api/me')).headers.get('content-security-policy');
  ok(/script-src 'self'/.test(csp), 'CSP header present');

  console.log('devices');
  const devs = (await call('GET', '/api/devices')).data;
  ok(devs.length === 0, 'new accounts start empty (no fake devices)');
  const created = await call('POST', '/api/devices', { name: 'Web server' });
  const key = created.data.api_key;
  ok(/^ng_/.test(key), 'device API key issued');
  ok((await call('POST', '/api/agent/telemetry', { pps: 5 }, { key: 'ng_' + 'x'.repeat(30) })).status === 401, 'bad agent key rejected');

  console.log('detection');
  const tel = (o) => call('POST', '/api/agent/telemetry', { hostname: 'h1', os: 'Linux', enforce: true, interval: 2, own_ips: ['10.0.0.5'], ...o }, { key });
  for (let i = 0; i < 30; i++) await tel({ pps: 100 + (i % 7) * 5 });
  let r = await tel({ pps: 120, sources: [{ ip: '203.0.113.9', pkts: 40, syns: 2, ports: [443] }] });
  ok(r.status === 200 && r.data.blocks.length === 0, 'normal traffic raises nothing and blocks nothing');
  let alerts = (await call('GET', '/api/alerts')).data;
  ok(alerts.length === 0, 'no alerts on normal traffic');

  r = await tel({ pps: 5000, sources: [{ ip: '198.51.100.23', pkts: 4800, syns: 4000, ports: [80] }] });
  ok(r.data.blocks.includes('198.51.100.23'), 'flood from one source -> IP in agent block list immediately');
  alerts = (await call('GET', '/api/alerts')).data;
  ok(alerts.some((a) => a.type === 'flood' && a.src_ip === '198.51.100.23' && /^Blocked/.test(a.action)), 'flood alert created with block action');

  r = await tel({ pps: 130, sources: [{ ip: '192.0.2.77', pkts: 20, syns: 20, ports: Array.from({ length: 20 }, (_, i) => 1000 + i) }] });
  ok(r.data.blocks.includes('192.0.2.77'), 'port scan -> blocked');
  r = await tel({ pps: 130, auth_failures: { '192.0.2.88': 9 } });
  ok(r.data.blocks.includes('192.0.2.88'), 'brute force -> blocked');
  r = await tel({ pps: 130, connections: Array.from({ length: 120 }, () => ({ ip: '192.0.2.99', lport: 443, state: 'ESTABLISHED' })) });
  ok(r.data.blocks.includes('192.0.2.99'), 'connection flood -> blocked');

  console.log('safety');
  r = await tel({ pps: 130, own_ips: ['10.0.0.5', '10.0.0.1'], sources: [{ ip: '10.0.0.1', pkts: 9000, syns: 9000, ports: [] }, { ip: '127.0.0.1', pkts: 9000, syns: 0, ports: [] }] });
  ok(!r.data.blocks.includes('10.0.0.1') && !r.data.blocks.includes('127.0.0.1'), 'gateway / loopback never blocked');
  ok((await call('POST', '/api/blocks', { ip: '10.0.0.5' })).status === 409, 'cannot manually block own device');
  ok((await call('POST', '/api/blocks', { ip: '999.1.1.1' })).status === 400, 'invalid IP rejected');
  ok((await call('POST', '/api/blocks', { ip: '1.1.1.1; rm -rf /' })).status === 400, 'shell-metacharacter IP rejected');
  await call('POST', '/api/allowlist', { ip: '192.0.2.200', note: 'office' });
  r = await tel({ pps: 130, sources: [{ ip: '192.0.2.200', pkts: 9000, syns: 9000, ports: [] }] });
  ok(!r.data.blocks.includes('192.0.2.200'), 'allowlisted IP not blocked');

  console.log('management');
  const blocks = (await call('GET', '/api/blocks')).data.blocks;
  const b = blocks.find((x) => x.ip === '198.51.100.23');
  ok(!!b && b.expires > Date.now(), 'block has a TTL');
  ok((await call('DELETE', `/api/blocks/${b.id}`)).status === 200, 'unblock works');
  r = await tel({ pps: 130 });
  ok(!r.data.blocks.includes('198.51.100.23'), 'unblocked IP removed from agent list');
  await call('PUT', '/api/settings', { auto_block: false });
  r = await tel({ pps: 5000, sources: [{ ip: '198.51.100.50', pkts: 4900, syns: 10, ports: [] }] });
  ok(!r.data.blocks.includes('198.51.100.50'), 'auto-block off -> alert only');
  const manual = (await call('GET', '/api/alerts')).data.find((a) => a.src_ip === '198.51.100.50');
  ok((await call('POST', `/api/alerts/${manual.id}/block`, {})).status === 200, 'manual block from alert works');
  ok((await call('PATCH', `/api/alerts/${manual.id}`, { status: 'resolved' })).status === 200, 'alert status update');
  ok((await call('PUT', '/api/settings', { webhook_url: 'javascript:alert(1)' })).status === 400, 'bad webhook URL rejected');

  console.log('physical event + isolation');
  ok((await call('POST', '/api/agent/event', { type: 'physical_anomaly', severity: 'critical', title: 'Arc on Feeder-2', action: 'shutdown' }, { key })).status === 200, 'sensor event accepted');
  await call('POST', '/api/auth/signup', { email: 'evil@x.co', password: 'another pass 99' }); // second user, new cookie
  ok((await call('GET', '/api/alerts')).data.length === 0, 'other users cannot see my alerts');
  ok((await call('GET', '/api/blocks')).data.blocks.length === 0, 'other users cannot see my blocks');
  ok((await call('DELETE', `/api/devices/${created.data.device.id}`)).status === 404, 'other users cannot delete my device');

  const inst = await fetch(base + '/install.sh').then((r) => r.text());
  ok(inst.startsWith('#!/usr/bin/env bash') && inst.includes('SERVER="http://127.0.0.1'), 'one-command installer is served');
  console.log('simulator');
  const login = await call('POST', '/api/auth/login', { email: 'a@b.co', password: 'correct horse 9' });
  ok(login.status === 200, 'login works');
  await call('PUT', '/api/settings', { auto_block: true }); // was switched off in the management test
  ok((await call('POST', '/api/auth/login', { email: 'a@b.co', password: 'wrong' })).status === 401, 'wrong password rejected');
  const stream = await new Promise((resolve) => {
    const events = [];
    const req = http.get(base + '/api/stream', { headers: { Cookie: cookie } }, (res) => {
      res.on('data', (c) => { for (const m of String(c).matchAll(/event: (\w+)/g)) events.push(m[1]); });
      setTimeout(async () => {
        await call('POST', '/api/sim/attack', { type: 'cyber' });
        setTimeout(() => { req.destroy(); resolve(events); }, 4500);
      }, 2500);
    });
  });
  ok(stream.includes('telemetry'), 'SSE streams live telemetry');
  ok(stream.includes('alert') && stream.includes('block'), 'simulated attack -> alert + block pushed live');
  const simAlerts = (await call('GET', '/api/alerts')).data;
  ok(simAlerts.some((a) => a.type === 'flood' && /^Blocked/.test(a.action)), 'simulator attack was auto-blocked');

  console.log(`\n${pass} passed, ${fail} failed`);
  server.close();
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
