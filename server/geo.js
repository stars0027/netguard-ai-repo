'use strict';
// Where does an IP come from? Uses a free public lookup (ipwho.is, no key) from the SERVER, so the browser never sends attacker IPs anywhere.
// Private / reserved addresses are never sent to the lookup service. Results are cached for 24 hours.
const dns = require('node:dns').promises;
const net = require('node:net');

const BASE = () => (process.env.GEO_API_BASE || 'https://ipwho.is').replace(/\/$/, '');
const cache = new Map(); // ip -> { at, data }
const TTL = 24 * 3600 * 1000;

const isPrivate = (ip) => {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  return /^(::1?|fc|fd|fe80)/i.test(ip);
};
// Demo / sandbox sample attackers. These are ILLUSTRATIVE sample profiles for the labelled Demo and Sandbox only (never real incidents).
// No lookup is made for them, and every place they are shown carries a Demo / Sample label.
const SAMPLE = {
  '185.220.101.42': { country_code: 'DE', country: 'Germany', region: 'Hesse', city: 'Frankfurt', lat: 50.1109, lon: 8.6821, asn: 'AS205100', org: 'F3 Netze e.V.', tool: 'Nmap v7.94 TCP SYN stealth scan: 24 ports in 30 s' },
  '45.155.205.109': { country_code: 'RU', country: 'Russia', region: 'Moscow', city: 'Moscow', lat: 55.7558, lon: 37.6173, asn: 'AS49505', org: 'Selectel Network', tool: 'Hydra v9.5 SSH brute force: 9 failed root logins in 60 s' },
  '218.92.0.204': { country_code: 'CN', country: 'China', region: 'Jiangsu', city: 'Nanjing', lat: 32.0603, lon: 118.7969, asn: 'AS4134', org: 'Chinanet Backbone', tool: 'hping3 high-rate SYN/UDP packet flood: 4,800 pkt/s' },
  '91.240.118.172': { country_code: 'NL', country: 'Netherlands', region: 'North Holland', city: 'Amsterdam', lat: 52.3676, lon: 4.9041, asn: 'AS202425', org: 'IP Volume Inc.', tool: 'Unauthorized Modbus/TCP probe of port 502 (industrial PLC)' },
};
const SAMPLE_NOTE = 'Sample profile for the Demo. This is an illustration, not a record of a real attack by this address or its owner.';
const DEMO_PLACES = [
  { country_code: 'DE', country: 'Germany', region: 'Hesse', city: 'Frankfurt', lat: 50.1109, lon: 8.6821 },
  { country_code: 'BR', country: 'Brazil', region: 'Sao Paulo', city: 'Sao Paulo', lat: -23.5505, lon: -46.6333 },
  { country_code: 'SG', country: 'Singapore', region: 'Singapore', city: 'Singapore', lat: 1.3521, lon: 103.8198 },
  { country_code: 'US', country: 'United States', region: 'Virginia', city: 'Ashburn', lat: 39.0438, lon: -77.4874 },
  { country_code: 'RU', country: 'Russia', region: 'Moscow', city: 'Moscow', lat: 55.7558, lon: 37.6173 },
];
const isDocRange = (ip) => /^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)/.test(ip) || /^10\.0\.4\./.test(ip);
const isDemoRange = (ip) => !!SAMPLE[ip] || isDocRange(ip);
const sampleTool = (ip) => (SAMPLE[ip] ? SAMPLE[ip].tool : null);
const SAMPLE_IPS = Object.keys(SAMPLE);
function demoProfile(ip) {
  if (SAMPLE[ip]) { const { tool, ...p } = SAMPLE[ip]; return { ip, ...p, isp: p.org, rdns: null, demo: true, note: SAMPLE_NOTE }; }
  const o = ip.split('.').map(Number), n = (o[2] || 0) * 7 + (o[3] || 0) * 13;
  const p = DEMO_PLACES[n % DEMO_PLACES.length];
  return { ip, ...p, asn: 'AS64500', org: 'Demo network (illustrative)', isp: 'Demo network (illustrative)', rdns: null, demo: true, note: 'Illustrative demo location. This address is reserved for documentation and has no real owner.' };
}

async function fetchJson(url, ms) {
  const ac = new AbortController(); const t = setTimeout(() => ac.abort(), ms);
  try { const r = await fetch(url, { signal: ac.signal, headers: { Accept: 'application/json' } }); if (!r.ok) throw new Error('HTTP ' + r.status); return await r.json(); } finally { clearTimeout(t); }
}
async function reverse(ip) {
  try { const names = await Promise.race([dns.reverse(ip), new Promise((_, rej) => setTimeout(() => rej(new Error('t')), 2000))]); return names[0] || null; } catch { return null; }
}

// demo=true only for the labelled Demo and the read-only sandbox. A REAL attacker that happens to use a sample address is looked up like any other.
async function lookup(ip, demo = false) {
  if (!ip || !(net.isIP(ip))) return { ip, error: 'Not a valid IP address' };
  if (isDocRange(ip) || (demo && SAMPLE[ip])) return demoProfile(ip);
  if (isPrivate(ip)) return { ip, private: true, note: 'Private or internal address. It has no public location.' };
  const hit = cache.get(ip);
  if (hit && Date.now() - hit.at < TTL) return hit.data;
  let data;
  try {
    const [j, rdns] = await Promise.all([fetchJson(`${BASE()}/${encodeURIComponent(ip)}`, 4000), reverse(ip)]);
    if (!j || j.success === false) throw new Error((j && j.message) || 'lookup failed');
    const c = j.connection || {};
    data = { ip, country_code: j.country_code || null, country: j.country || null, region: j.region || null, city: j.city || null,
      lat: typeof j.latitude === 'number' ? j.latitude : null, lon: typeof j.longitude === 'number' ? j.longitude : null,
      asn: c.asn ? 'AS' + c.asn : null, org: c.org || null, isp: c.isp || null, rdns, demo: false };
  } catch (e) {
    return { ip, error: 'Location lookup is not available right now (' + String(e.message).slice(0, 60) + ')' }; // not cached, so it retries
  }
  cache.set(ip, { at: Date.now(), data });
  if (cache.size > 2000) cache.delete(cache.keys().next().value);
  return data;
}
module.exports = { lookup, isPrivate, isDemoRange, sampleTool, SAMPLE_IPS, SAMPLE_NOTE };
