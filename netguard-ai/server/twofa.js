'use strict';
// Zero-dependency second factor helpers: TOTP (RFC 6238, works with Google Authenticator / Authy / Microsoft Authenticator),
// a 4-digit security PIN (stored as a scrypt hash like a password), and an optional e-mail one-time code over SMTP.
const crypto = require('node:crypto');
const tls = require('node:tls');

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32encode(buf) {
  let bits = '', out = '';
  for (const b of buf) bits += b.toString(2).padStart(8, '0');
  for (let i = 0; i < bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)];
  return out;
}
function b32decode(s) {
  let bits = '';
  for (const ch of String(s).replace(/=+$/, '').toUpperCase()) { const i = B32.indexOf(ch); if (i < 0) continue; bits += i.toString(2).padStart(5, '0'); }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}
const newSecret = () => b32encode(crypto.randomBytes(20));
function hotp(secret, counter) {
  const msg = Buffer.alloc(8); msg.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', b32decode(secret)).update(msg).digest();
  const o = h[19] & 15;
  const n = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(n % 1e6).padStart(6, '0');
}
function verifyTotp(secret, code, t = Date.now()) {
  code = String(code || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(code) || !secret) return false;
  const c = Math.floor(t / 30000);
  for (const d of [-1, 0, 1]) {
    const a = Buffer.from(hotp(secret, c + d)), b = Buffer.from(code);
    if (crypto.timingSafeEqual(a, b)) return true;
  }
  return false;
}
const otpauthUri = (secret, email) => `otpauth://totp/NetGuard%20AI:${encodeURIComponent(email)}?secret=${secret}&issuer=NetGuard%20AI&algorithm=SHA1&digits=6&period=30`;

// ---- e-mail OTP (only when SMTP_EMAIL + SMTP_PASSWORD are set; Gmail needs an "app password") ----
const smtpReady = () => !!(process.env.SMTP_EMAIL && process.env.SMTP_PASSWORD);
function sendMail(to, subject, text) {
  return new Promise((resolve, reject) => {
    const host = process.env.SMTP_HOST || 'smtp.gmail.com', port = Number(process.env.SMTP_PORT || 465);
    const user = process.env.SMTP_EMAIL, pass = process.env.SMTP_PASSWORD;
    if (/[\r\n]/.test(to + subject)) return reject(new Error('bad header'));
    const sock = tls.connect({ host, port, servername: host }, () => {});
    sock.setTimeout(15000, () => { sock.destroy(); reject(new Error('SMTP timeout')); });
    const steps = [
      [null, 220], ['EHLO netguard', 250], ['AUTH LOGIN', 334], [Buffer.from(user).toString('base64'), 334], [Buffer.from(pass).toString('base64'), 235],
      [`MAIL FROM:<${user}>`, 250], [`RCPT TO:<${to}>`, 250], ['DATA', 354],
      [`From: NetGuard AI <${user}>\r\nTo: ${to}\r\nSubject: ${subject}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n${text.replace(/\n\./g, '\n..')}\r\n.`, 250], ['QUIT', 221],
    ];
    let i = 0, buf = '';
    sock.on('data', (d) => {
      buf += d.toString();
      if (!/\r?\n$/.test(buf) || /^\d{3}-/m.test(buf.split(/\r?\n/).filter(Boolean).pop() || '')) return;
      const code = Number(buf.slice(0, 3)); buf = '';
      if (code !== steps[i][1]) { sock.destroy(); return reject(new Error('SMTP error ' + code)); }
      i += 1;
      if (i >= steps.length) { sock.end(); return resolve(); }
      sock.write(steps[i][0] + '\r\n');
    });
    sock.on('error', reject);
  });
}
module.exports = { newSecret, verifyTotp, otpauthUri, smtpReady, sendMail, hotp };
