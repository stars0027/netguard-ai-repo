'use strict';
// Sending e-mail: HTTPS APIs work on Render's free plan (SMTP ports are blocked there), so they are tried first.
//   RESEND_API_KEY  (+ MAIL_FROM)   https://resend.com   free tier
//   BREVO_API_KEY   (+ MAIL_FROM)   https://brevo.com    free tier
//   SMTP_EMAIL + SMTP_PASSWORD      Gmail app password (works on your own PC / VPS)
const fs = require('node:fs');
const path = require('node:path');
const twofa = require('./twofa');

const emailjsReady = () => !!(process.env.EMAILJS_SERVICE_ID && process.env.EMAILJS_TEMPLATE_ID && process.env.EMAILJS_PUBLIC_KEY);
const provider = () => (process.env.NG_MAIL_STUB ? 'stub' : process.env.BREVO_API_KEY && (process.env.SENDER_EMAIL || process.env.MAIL_FROM) ? 'brevo' : process.env.RESEND_API_KEY ? 'resend' : emailjsReady() ? 'emailjs' : twofa.smtpReady() ? 'smtp' : null);
const mailReady = () => !!provider();
const from = () => process.env.SENDER_EMAIL || process.env.MAIL_FROM || process.env.SMTP_EMAIL || 'onboarding@resend.dev';

async function postJson(url, headers, body) {
  const ac = new AbortController(); const t = setTimeout(() => ac.abort(), 12000);
  try {
    const r = await fetch(url, { method: 'POST', signal: ac.signal, headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });
    if (!r.ok) throw new Error('Mail service said HTTP ' + r.status);
  } finally { clearTimeout(t); }
}
const esc = (x) => String(x).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
// dark-themed HTML body that shows the 6-digit code in large bold text
const codeHtml = (code) => `<div style="background:#171717;padding:32px;font-family:Arial,sans-serif;color:#f2f2f2"><div style="max-width:420px;margin:auto;border:1px solid #3a3a3a;border-radius:12px;padding:28px;background:#1f1f1f;text-align:center"><div style="font-size:13px;letter-spacing:3px;color:#FFF21A">NETGUARD AI</div><p style="color:#cfcfcf">Your 6-digit verification code is</p><div style="font-size:40px;font-weight:700;letter-spacing:10px;color:#FFF21A;margin:14px 0">${esc(code)}</div><p style="color:#9a9a9a;font-size:13px">It expires in 10 minutes. If you did not create this account, ignore this e-mail.</p></div></div>`;
async function sendCode(to, code) {
  const subject = 'NetGuard AI — Your 6-Digit Verification Code';
  const text = `Your NetGuard AI verification code is ${code}. It expires in 10 minutes. If you did not create this account, ignore this e-mail.`;
  if (provider() === 'brevo') return postJson('https://api.brevo.com/v3/smtp/email', { 'api-key': process.env.BREVO_API_KEY }, { sender: { name: 'NetGuard AI', email: from() }, to: [{ email: to }], subject, textContent: text, htmlContent: codeHtml(code) });
  if (provider() === 'resend') return postJson('https://api.resend.com/emails', { Authorization: 'Bearer ' + process.env.RESEND_API_KEY }, { from: `NetGuard AI <${from()}>`, to: [to], subject, text, html: codeHtml(code) });
  if (provider() === 'emailjs') return postJson('https://api.emailjs.com/api/v1.0/email/send', {}, { service_id: process.env.EMAILJS_SERVICE_ID, template_id: process.env.EMAILJS_TEMPLATE_ID, user_id: process.env.EMAILJS_PUBLIC_KEY, ...(process.env.EMAILJS_PRIVATE_KEY ? { accessToken: process.env.EMAILJS_PRIVATE_KEY } : {}), template_params: { to_email: to, email: to, code, verification_code: code, subject, message: text } });
  return send(to, subject, text);
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
    case 'emailjs': throw new Error('EmailJS is only used for verification codes');
    case 'smtp': return twofa.sendMail(to, subject, text);
    default: throw new Error('No mail service is configured');
  }
}
module.exports = { send, sendCode, mailReady, provider };
