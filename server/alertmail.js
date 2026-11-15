'use strict';
// Real-time e-mail for critical and high alerts on REAL devices (never the sandbox or the demo device).
// At most one e-mail per user and source address every 15 minutes.
const { db } = require('./db');
const { now, json } = require('./util');
const { getSettings } = require('./settings');
const mailer = require('./mailer');
const geo = require('./geo');

const last = new Map(); // "userId|key" -> time
setInterval(() => { const t = now(); for (const [k, v] of last) if (t - v > 3600000) last.delete(k); }, 600000).unref();
const LABEL = { flood: 'Traffic flood', syn_flood: 'SYN flood', port_scan: 'Port scan', brute_force: 'Brute force', conn_flood: 'Connection flood', ot_probe: 'Industrial (OT/PLC) port probe', anomaly: 'Statistical traffic anomaly', heartbeat_lost: 'Agent heartbeat lost', device_offline: 'Device offline', exposure: 'Exposed service', physical: 'Physical event', canary: 'Canary trap hit' };
const clip = (x, n = 120) => String(x == null ? '' : x).replace(/[\r\n]+/g, ' ').slice(0, n);

async function maybeSend(row, device) {
  if (!row || row.demo || (device && device.virtual)) return false;
  if (!['critical', 'high'].includes(row.severity)) return false;
  if (!mailer.mailReady() || mailer.provider() === 'emailjs') return false; // EmailJS can only carry the verification-code template
  const u = db.prepare('SELECT email, email_verified, read_only FROM users WHERE id=?').get(row.user_id);
  if (!u || u.read_only || !u.email_verified || !u.email) return false;
  if (getSettings(row.user_id).email_alerts === false) return false;
  const key = row.user_id + '|' + (row.src_ip || row.type + ':' + row.device_id), t = now();
  if (last.has(key) && t - last.get(key) < 15 * 60000) return false;
  last.set(key, t);

  const d = json(row.detail) || {};
  let g = d.geo || null;
  if (!g && row.src_ip) {
    try {
      const x = await Promise.race([geo.lookup(row.src_ip, false), new Promise((r) => setTimeout(() => r(null), 3500))]);
      if (x && !x.error && !x.private) g = x;
    } catch { /* location is optional */ }
  }
  const fresh = db.prepare('SELECT action FROM alerts WHERE id=?').get(row.id) || row;
  const ports = Array.isArray(d.ports) && d.ports.length ? d.ports.slice(0, 20).join(', ') : d.port ? String(d.port) : d.lport ? String(d.lport) : 'not applicable';
  const where = g ? [g.city, g.country].filter(Boolean).join(', ') + (g.asn || g.isp || g.org ? ` (${[g.asn, g.isp || g.org].filter(Boolean).join(' ')})` : '') : (row.src_ip ? 'location not available' : 'not applicable');
  const text = [
    `NetGuard AI detected a ${row.severity.toUpperCase()} alert.`, '',
    `Device:         ${clip(row.device_name, 60)}`,
    `Attack type:    ${LABEL[row.type] || clip(row.type, 40)}`,
    `Source IP:      ${row.src_ip || 'not applicable'}`,
    `Location / ASN: ${clip(where, 140)}`,
    `Targeted ports: ${ports}`,
    `Firewall:       ${clip(fresh.action || 'No block action', 160)}`,
    `What happened:  ${clip(row.title, 200)}`, '',
    'Open your NetGuard AI dashboard to see the full forensic details.',
    'You get at most one e-mail per source address every 15 minutes. You can turn these e-mails off in Settings.',
  ].join('\n');
  await mailer.send(u.email, `NetGuard AI ${row.severity.toUpperCase()} alert: ${LABEL[row.type] || row.type} on ${clip(row.device_name, 40)}`, text);
  return true;
}
// fire and forget: a mail problem must never slow down or break detection
const notify = (row, device) => { maybeSend(row, device).catch((e) => console.error('alert mail failed:', e.message)); };
module.exports = { notify, maybeSend };
