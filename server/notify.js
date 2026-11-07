'use strict';
// Outbound webhook notifications (Slack / Discord / any JSON endpoint) with SSRF protection.
const dns = require('node:dns').promises;
const net = require('node:net');
const { isLoopbackOrSpecial, isPrivate } = require('./util');

async function assertPublicUrl(urlStr) {
  const u = new URL(urlStr);
  if (!/^https?:$/.test(u.protocol)) throw new Error('Only http(s) webhooks are allowed');
  if (process.env.ALLOW_PRIVATE_WEBHOOKS === '1') return u;
  const host = u.hostname.replace(/^\[|\]$/g, '');
  const addrs = net.isIP(host) ? [{ address: host }] : await dns.lookup(host, { all: true });
  for (const a of addrs) {
    if (isLoopbackOrSpecial(a.address) || isPrivate(a.address)) throw new Error('Webhook host resolves to a private address');
  }
  return u;
}

async function sendWebhook(url, payload) {
  const u = await assertPublicUrl(url);
  const text = payload.text || 'NetGuard AI alert';
  const res = await fetch(u, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text, content: text, ...payload }),
    redirect: 'error',
    signal: AbortSignal.timeout(5000),
  });
  if (!res.ok) throw new Error('Webhook responded ' + res.status);
}

module.exports = { sendWebhook };
