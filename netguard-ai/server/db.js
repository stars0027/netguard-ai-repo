'use strict';
// SQLite via Node's built-in node:sqlite (Node >= 22.13). No native modules, no npm install.
const { DatabaseSync } = require('node:sqlite');
const fs = require('node:fs');
const path = require('node:path');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new DatabaseSync(path.join(DATA_DIR, process.env.DB_FILE || 'netguard.db'));

db.exec(`
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  pass_hash TEXT NOT NULL,
  settings TEXT NOT NULL DEFAULT '{}',
  created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  key_prefix TEXT NOT NULL,
  virtual INTEGER NOT NULL DEFAULT 0,
  hostname TEXT, os TEXT, agent_version TEXT,
  enforce INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending',
  last_seen INTEGER,
  created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
  device_name TEXT,
  type TEXT NOT NULL,
  severity TEXT NOT NULL,
  src_ip TEXT,
  title TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '{}',
  action TEXT,
  status TEXT NOT NULL DEFAULT 'open',
  count INTEGER NOT NULL DEFAULT 1,
  created INTEGER NOT NULL,
  updated INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS alerts_user ON alerts(user_id, created DESC);
CREATE TABLE IF NOT EXISTS blocks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id INTEGER REFERENCES devices(id) ON DELETE CASCADE,
  ip TEXT NOT NULL,
  reason TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'auto',
  scope TEXT NOT NULL DEFAULT 'fleet',
  alert_id INTEGER,
  active INTEGER NOT NULL DEFAULT 1,
  created INTEGER NOT NULL,
  expires INTEGER
);
CREATE INDEX IF NOT EXISTS blocks_user ON blocks(user_id, active);
CREATE TABLE IF NOT EXISTS allowlist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ip TEXT NOT NULL,
  note TEXT,
  UNIQUE(user_id, ip)
);
CREATE TABLE IF NOT EXISTS metrics (
  device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  ts INTEGER NOT NULL,
  pps REAL NOT NULL,
  conns INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS metrics_dev ON metrics(device_id, ts);
CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id INTEGER,
  ts INTEGER NOT NULL,
  level TEXT NOT NULL,
  msg TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS logs_user ON logs(user_id, id DESC);
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS resets (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS canaries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token TEXT NOT NULL UNIQUE,
  label TEXT NOT NULL,
  hits INTEGER NOT NULL DEFAULT 0,
  last_hit INTEGER,
  created INTEGER NOT NULL
);
`);

// ---- migrations (safe to run on every start) ----
const addCol = (sql) => { try { db.exec(sql); } catch { /* column already exists */ } };
addCol('ALTER TABLE alerts ADD COLUMN demo INTEGER NOT NULL DEFAULT 0');
addCol('ALTER TABLE blocks ADD COLUMN demo INTEGER NOT NULL DEFAULT 0');
addCol('ALTER TABLE logs ADD COLUMN demo INTEGER NOT NULL DEFAULT 0');
// Per-device protection mode. Devices that already exist keep working exactly as before ('live');
// devices created from now on start in 'monitor' (dry run) until the owner switches them on.
addCol("ALTER TABLE devices ADD COLUMN mode TEXT NOT NULL DEFAULT 'live'");
// Simulator rows created by older versions: tag them so they stop mixing with real data.
try {
  db.exec(`UPDATE alerts SET demo=1 WHERE demo=0 AND device_id IN (SELECT id FROM devices WHERE virtual=1);
           UPDATE logs   SET demo=1 WHERE demo=0 AND device_id IN (SELECT id FROM devices WHERE virtual=1);
           UPDATE blocks SET demo=1, scope='device' WHERE demo=0 AND device_id IN (SELECT id FROM devices WHERE virtual=1);`);
} catch { /* ignore */ }

// ---- account security columns ----
addCol('ALTER TABLE users ADD COLUMN pin_hash TEXT');
addCol('ALTER TABLE users ADD COLUMN totp_secret TEXT');
addCol('ALTER TABLE users ADD COLUMN totp_on INTEGER NOT NULL DEFAULT 0');
addCol('ALTER TABLE users ADD COLUMN email_otp INTEGER NOT NULL DEFAULT 0');
addCol('ALTER TABLE users ADD COLUMN read_only INTEGER NOT NULL DEFAULT 0'); // sandbox demo account: can look, cannot change anything

module.exports = { db, DATA_DIR };
