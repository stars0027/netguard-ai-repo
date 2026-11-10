'use strict';
// Server-Sent Events hub: pushes live telemetry/alerts to each user's open dashboards.
const clients = new Map(); // userId -> Set<res>

function addClient(userId, res) {
  if (!clients.has(userId)) clients.set(userId, new Set());
  clients.get(userId).add(res);
  res.on('close', () => { const s = clients.get(userId); if (s) { s.delete(res); if (!s.size) clients.delete(userId); } });
}
function emit(userId, event, data) {
  const set = clients.get(userId);
  if (!set) return;
  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of set) res.write(msg);
}
const listeners = (userId) => (clients.get(userId) || new Set()).size;
setInterval(() => { for (const set of clients.values()) for (const res of set) res.write(': keepalive\n\n'); }, 20000).unref();

module.exports = { addClient, emit, listeners };
