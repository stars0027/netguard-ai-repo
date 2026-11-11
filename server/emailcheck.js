'use strict';
// Rejects obviously fake e-mail domains and checks that the domain really receives mail (MX record) using the system DNS resolver.
const dns = require('node:dns').promises;
const BLOCKED = new Set(['xyz.com', 'fake.com', 'test.com', 'tempmail.com', 'mailinator.com', 'example.com', 'example.org', 'example.net', 'invalid.com',
  'guerrillamail.com', '10minutemail.com', 'yopmail.com', 'trashmail.com', 'temp-mail.org', 'throwawaymail.com', 'getnada.com', 'sharklasers.com', 'dispostable.com', 'maildrop.cc', 'fakeinbox.com', 'asdf.com', 'abc.com', 'email.com']);
const KNOWN = new Set(['gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'yahoo.com', 'icloud.com', 'proton.me', 'protonmail.com', 'zoho.com']);
const cache = new Map();
async function check(email) {
  const domain = String(email).split('@')[1] || '';
  if (!domain || BLOCKED.has(domain) || /^(localhost|.*\.(test|invalid|example|local))$/.test(domain)) return { ok: false, reason: 'Please use your real e-mail address. This domain is not accepted.' };
  if (process.env.NG_MX_MODE === 'off' || KNOWN.has(domain)) return { ok: true };
  const hit = cache.get(domain); if (hit && hit.exp > Date.now()) return hit.v;
  let v;
  try {
    const mx = await Promise.race([dns.resolveMx(domain), new Promise((_, r) => setTimeout(() => r(Object.assign(new Error('timeout'), { code: 'ETIMEOUT' })), 4000))]);
    v = mx.some((m) => m.exchange && m.exchange !== '.') ? { ok: true } : { ok: false, reason: 'That e-mail domain does not receive e-mail. Check for typos.' };
  } catch (e) {
    if (e.code === 'ENOTFOUND' || e.code === 'ENODATA') v = { ok: false, reason: 'That e-mail domain does not exist or cannot receive e-mail. Check for typos.' };
    else return { ok: true, unchecked: true }; // DNS itself is down: do not lock real people out
  }
  cache.set(domain, { v, exp: Date.now() + 3600000 });
  return v;
}
module.exports = { check };
