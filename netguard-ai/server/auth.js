'use strict';
const crypto = require('node:crypto');
const { db } = require('./db');
const { now, sha256, randToken, json } = require('./util');

const COOKIE = 'ng_session';
const SESSION_MS = 7 * 24 * 3600 * 1000;

// ---- password hashing: scrypt (built in, memory-hard) ----
function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(pw, salt, 64, { N: 16384, r: 8, p: 1 });
  return `s1$${salt.toString('base64')}$${key.toString('base64')}`;
}
function verifyPassword(pw, stored) {
  const [v, s, k] = String(stored).split('$');
  if (v !== 's1' || !s || !k) return false;
  const expect = Buffer.from(k, 'base64');
  const got = crypto.scryptSync(pw, Buffer.from(s, 'base64'), expect.length, { N: 16384, r: 8, p: 1 });
  return crypto.timingSafeEqual(got, expect);
}

// ---- sessions: random opaque token, only its hash is stored (revocable, no JWT secret to leak) ----
function createSession(userId) {
  const token = randToken(32);
  db.prepare('INSERT INTO sessions(token_hash,user_id,expires) VALUES(?,?,?)').run(sha256(token), userId, now() + SESSION_MS);
  return token;
}
function destroySession(token) { db.prepare('DELETE FROM sessions WHERE token_hash=?').run(sha256(token)); }
function destroyUserSessions(userId) { db.prepare('DELETE FROM sessions WHERE user_id=?').run(userId); }

function parseCookies(header) {
  const out = {};
  for (const part of String(header || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function cookieHeader(token, secure) {
  const attrs = [`${COOKIE}=${token}`, 'Path=/', 'HttpOnly', 'SameSite=Strict', `Max-Age=${Math.floor(SESSION_MS / 1000)}`];
  if (secure) attrs.push('Secure');
  return attrs.join('; ');
}
const clearCookieHeader = () => `${COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`;

function userFromRequest(req) {
  const token = parseCookies(req.headers.cookie)[COOKIE];
  if (!token) return null;
  const row = db.prepare(`SELECT u.id,u.email,u.name,u.settings,u.read_only,s.expires FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?`).get(sha256(token));
  if (!row || row.expires < now()) return null;
  return { id: row.id, email: row.email, name: row.name, settings: json(row.settings), read_only: !!row.read_only, token };
}

// ---- device API keys: "ng_<random>", only sha256 stored ----
function newApiKey() {
  const key = 'ng_' + randToken(24);
  return { key, hash: sha256(key), prefix: key.slice(0, 9) };
}
function deviceFromRequest(req) {
  const m = /^Bearer\s+(ng_[A-Za-z0-9_-]{20,80})$/.exec(req.headers.authorization || '');
  if (!m) return null;
  return db.prepare('SELECT * FROM devices WHERE key_hash=?').get(sha256(m[1])) || null;
}

// ---- tiny in-memory rate limiter ----
const buckets = new Map();
function rateLimit(key, max, windowMs) {
  const t = now();
  const b = buckets.get(key);
  if (!b || b.reset < t) { buckets.set(key, { n: 1, reset: t + windowMs }); return true; }
  b.n += 1;
  return b.n <= max;
}
setInterval(() => { const t = now(); for (const [k, b] of buckets) if (b.reset < t) buckets.delete(k); }, 60000).unref();

setInterval(() => db.prepare('DELETE FROM sessions WHERE expires<?').run(now()), 3600000).unref();

module.exports = {
  hashPassword, verifyPassword, createSession, destroySession, destroyUserSessions,
  cookieHeader, clearCookieHeader, userFromRequest, deviceFromRequest, newApiKey, rateLimit,
};
