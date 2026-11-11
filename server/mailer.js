'use strict';
// Sending e-mail: HTTPS APIs work on Render's free plan (SMTP ports are blocked there), so they are tried first.
//   RESEND_API_KEY  (+ MAIL_FROM)   https://resend.com   free tier
//   BREVO_API_KEY   (+ MAIL_FROM)   https://brevo.com    free tier
//   SMTP_EMAIL + SMTP_PASSWORD      Gmail app password (works on your own PC / VPS)
const fs = require('node:fs');
const path = require('node:path');
const twofa = require('./twofa');

const provider = () => (process.env.NG_MAIL_STUB ? 'stub' : process.env.RESEND_API_KEY ? 'resend' : process.env.BREVO_API_KEY ? 'brevo' : twofa.smtpReady() ? 'smtp' : null);
const mailReady = () => !!provider();
const from = () => process.env.MAIL_FROM || process.env.SMTP_EMAIL || 'onboarding@resend.dev';

async function postJson(url, headers, body) {
  const ac = new AbortController(); const t = setTimeout(() => ac.abort(), 12000);
  try {
    const r = await fetch(url, { method: 'POST', signal: ac.signal, headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });
    if (!r.ok) throw new Error('Mail service said HTTP ' + r.status);
  } finally { clearTimeout(t); }
}
async function send(to, subject, text) {
  if (/[\r\n]/.test(to + subject)) throw new Error('bad header');
  switch (provider()) {
    case 'stub': { // tests only: write to a file instead of sending
      const f = path.join(process.env.DATA_DIR || '.', 'mail-outbox.json');
      let a = []; try { a = JSON.parse(fs.readFileSync(f, 'utf8')); } catch { /* new */ }
      a.push({ to, subject, text }); fs.writeFileSync(f, JSON.stringify(a)); return;
    }
    case 'resend': return postJson('https://api.resend.com/emails', { Authorization: 'Bearer ' + process.env.RESEND_API_KEY }, { from: `NetGuard AI <${from()}>`, to: [to], subject, text });
    case 'brevo': return postJson('https://api.brevo.com/v3/smtp/email', { 'api-key': process.env.BREVO_API_KEY }, { sender: { name: 'NetGuard AI', email: from() }, to: [{ email: to }], subject, textContent: text });
    case 'smtp': return twofa.sendMail(to, subject, text);
    default: throw new Error('No mail service is configured');
  }
}
module.exports = { send, mailReady, provider };
