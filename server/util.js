'use strict';
const net = require('node:net');
const crypto = require('node:crypto');

const now = () => Date.now();
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const randToken = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');
const clamp = (v, lo, hi, dflt = lo) => {
  if (v === null || v === undefined || v === '') return dflt; // a missing value must use the default, not become 0
  const n = Number(v);
  return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : dflt;
};

// Normalise "::ffff:1.2.3.4" -> "1.2.3.4" and return null if it is not a literal IP.
function cleanIp(raw) {
  if (typeof raw !== 'string') return null;
  let s = raw.trim().replace(/^::ffff:/i, '');
  if (s.length > 45 || !net.isIP(s)) return null;
  return s.toLowerCase();
}

function isLoopbackOrSpecial(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 127 || a === 0 || a >= 224 || (a === 169 && b === 254);
  }
  return ip === '::1' || ip === '::' || ip.startsWith('fe80:') || ip.startsWith('ff');
}

function isPrivate(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
  }
  return ip.startsWith('fc') || ip.startsWith('fd');
}

const json = (v, fallback = {}) => { try { return JSON.parse(v); } catch { return fallback; } };

module.exports = { now, sha256, randToken, clamp, cleanIp, isLoopbackOrSpecial, isPrivate, json };
