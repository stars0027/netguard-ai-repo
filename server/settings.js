'use strict';
const { db } = require('./db');
const { json, clamp } = require('./util');

const DEFAULTS = {
  auto_block: true,          // block attackers automatically when confidence is high
  block_scope: 'fleet',      // 'fleet' = block on all your devices, 'device' = only the one attacked
  block_ttl_min: 60,         // auto-unblock after N minutes (0 = permanent)
  sensitivity: 'medium',     // low | medium | high -> how far from baseline counts as an anomaly
  learn_samples: 30,         // telemetry samples used to learn "normal"
  src_pps_limit: 500,        // packets/s from ONE source that is always a flood
  conn_limit: 100,           // simultaneous connections from ONE source
  port_scan_ports: 15,       // distinct ports touched by ONE source
  brute_force_attempts: 8,   // failed logins from ONE source within 60 s
  webhook_url: '',           // Slack / Discord / generic JSON webhook
};

const cache = new Map(); // userId -> { at, value }  (settings are read on every telemetry sample)
function getSettings(userId) {
  const c = cache.get(userId);
  if (c && Date.now() - c.at < 5000) return c.value;
  const row = db.prepare('SELECT settings FROM users WHERE id=?').get(userId);
  const value = { ...DEFAULTS, ...json(row && row.settings) };
  cache.set(userId, { at: Date.now(), value });
  return value;
}

function sanitize(input) {
  const s = {};
  if ('auto_block' in input) s.auto_block = !!input.auto_block;
  if (['fleet', 'device'].includes(input.block_scope)) s.block_scope = input.block_scope;
  if ('block_ttl_min' in input) s.block_ttl_min = clamp(input.block_ttl_min, 0, 60 * 24 * 30, 60);
  if (['low', 'medium', 'high'].includes(input.sensitivity)) s.sensitivity = input.sensitivity;
  if ('learn_samples' in input) s.learn_samples = clamp(input.learn_samples, 10, 600, 30);
  if ('src_pps_limit' in input) s.src_pps_limit = clamp(input.src_pps_limit, 10, 1e7, 500);
  if ('conn_limit' in input) s.conn_limit = clamp(input.conn_limit, 5, 1e6, 100);
  if ('port_scan_ports' in input) s.port_scan_ports = clamp(input.port_scan_ports, 3, 65535, 15);
  if ('brute_force_attempts' in input) s.brute_force_attempts = clamp(input.brute_force_attempts, 2, 1000, 8);
  if ('webhook_url' in input) {
    const u = String(input.webhook_url || '').trim().slice(0, 500);
    if (u && !/^https?:\/\/[^\s]+$/i.test(u)) throw new Error('Webhook URL must start with http:// or https://');
    s.webhook_url = u;
  }
  return s;
}

function saveSettings(userId, patch) {
  const merged = { ...getSettings(userId), ...sanitize(patch) };
  db.prepare('UPDATE users SET settings=? WHERE id=?').run(JSON.stringify(merged), userId);
  cache.delete(userId);
  return merged;
}

module.exports = { DEFAULTS, getSettings, saveSettings };
