# NetGuard AI

A multi-user network defense platform. Users sign up, install a small **agent** on the machines they
want to protect, and NetGuard **learns normal traffic, detects attacks, blocks the attacker in the OS
firewall, and alerts them** on a live dashboard and by webhook.

It started as a hackathon demo and is now a real tool: it only shows data from real agents and canary traps.

```
 your servers / PCs / gateways            NetGuard server (this repo)             your browser
┌────────────────────────────┐  telemetry ┌───────────────────────────┐  SSE   ┌──────────────┐
│ agent: traffic, connections│ ─────────▶ │ detection engine + SQLite │ ─────▶ │ live dashboard│
│ sniffer, SSH log, firewall │ ◀───────── │ accounts, alerts, blocks  │        │ alerts, blocks│
└────────────────────────────┘ block list └───────────────────────────┘        └──────────────┘
```

## What it detects

| Detection | How |
|---|---|
| Traffic flood / DoS | per-device baseline learned from its own traffic (adaptive mean + variance; frozen during attacks so they can't "teach" it) plus a per-source packets/s limit |
| Port scan | one source touching N distinct ports in 30 s |
| Connection flood | one source holding N simultaneous connections |
| Brute force | N failed SSH/login attempts from one source in 60 s (reads `/var/log/auth.log` or `/var/log/secure`) |
| Traffic drop | sudden fall to ~0 (cable cut, crash, emergency shutdown) |
| Exposed services | Telnet, RDP, VNC, SMB, Redis, MongoDB, Modbus, DNP3, S7... listening on all interfaces |
| Device offline | agent stops reporting |
| Physical events | sensors/PLC gateways `POST /api/agent/event` (e.g. arc detected -> emergency shutdown) |

Response: de-duplicated alert, automatic block (all devices or just one, with auto-expiry), webhook
(Slack/Discord/any JSON endpoint), live push to the dashboard.

## Run the server

Needs **Node 22.13+**. No `npm install`: the server has zero dependencies.

```
node server/index.js          # or: npm start
```

Open http://localhost:3000 and create an account. New accounts start empty: add a device and install the agent on it.

Docker: `docker compose up -d`. Run tests: `npm test`.

Environment variables: `PORT`, `DATA_DIR` (database location), `ALLOW_SIGNUP=0` (close registration),
`TRUST_PROXY=1` (behind a reverse proxy), `COOKIE_SECURE=1` (set automatically when `NODE_ENV=production`).

## Protect a real machine

0. **Easiest (Linux):** Devices -> Add a device shows a one-line installer that sets the agent up as a systemd service:
   `curl -fsSL https://YOUR-SERVER/install.sh | sudo NETGUARD_KEY=ng_... bash`
1. **Devices -> Add a device** also gives you the API key and manual commands.
2. Manual install on the machine (Python 3.8+):
   ```
   pip install psutil
   sudo python3 netguard_agent.py --server https://YOUR-SERVER --key ng_... --enforce --sniff
   ```
   * Without `--enforce` the agent only monitors; it never touches your firewall.
   * `--enforce` blocks attacker IPs (Linux iptables/ip6tables, Windows Firewall). Needs root/Administrator.
   * `--sniff` adds a packet sniffer (Linux, root) for per-source rates and port-scan detection.
   * The agent never blocks its own addresses, your gateway, DNS servers, loopback, the NetGuard server or
     anything on your allowlist. Rules are removed on exit unless you pass `--keep-rules`.
3. Run it as a service (systemd example):
   ```
   [Service]
   ExecStart=/usr/bin/python3 /opt/netguard/netguard_agent.py --server https://YOUR-SERVER --key ng_... --enforce --sniff
   Restart=always
   ```

## Going public (so other people can use it)

* Put it behind HTTPS (Caddy, nginx, Cloudflare). Agents send API keys; never use plain http across the internet.
* Deploy anywhere that runs Node 22 or Docker (Render, Railway, Fly.io, a VPS). Mount a persistent volume for `DATA_DIR`.
* Security built in: scrypt password hashing, revocable server-side sessions, `HttpOnly`+`SameSite=Strict` cookies,
  CSRF header on every write, strict CSP, login/sign-up rate limits, hashed API keys, strict IP validation
  (no shell injection into firewall commands), SSRF-safe webhooks, per-user data isolation.

## Honest limits

* NetGuard protects machines that **run the agent**. A website alone cannot see or stop traffic on someone's network.
* It detects and blocks **single-source** attacks well. A large distributed DDoS needs upstream protection
  (Cloudflare, your ISP); NetGuard will alert and tell you so instead of pretending to block it.
* Statistical anomaly detection (not a trained ML model). It is explainable and needs no training data, but
  tune thresholds in Settings if you see false positives; the allowlist is there for trusted hosts.
* Baselines re-learn (about a minute) after a server restart. Agents on macOS are monitor-only.

## Layout

```
server/   index.js (HTTP+API) engine.js (detection) db.js auth.js hub.js (SSE) notify.js settings.js
public/   index.html styles.css app.js   (no build step)
agent/    netguard_agent.py
test/     e2e.js                          (37 checks against a live server)
```


## v2 additions
- Security score (0-100) with the exact fixes that raise it
- 24-hour alert timeline, attack-type breakdown, top attackers with one-click block
- Alarm sound and browser notification for serious alerts (toggle in the header)
- Alerts export as CSV (`/api/alerts.csv`)
- New lemon / charcoal / lavender / amber look

## Real AI for the Copilot (optional, free tier available)
Set one environment variable on the server and the Copilot becomes a real AI that you can type to or talk to, in English and Tamil:
- `GEMINI_API_KEY` (free key from https://aistudio.google.com/apikey), optional `GEMINI_MODEL`
- or `ANTHROPIC_API_KEY`, optional `ANTHROPIC_MODEL`
- `AI_DAILY_LIMIT` caps questions per user per day (default 150).
Only a summary of your alerts, devices and attacker IPs is sent to the AI. Passwords, emails and API keys are never sent.
Without a key the built-in rule-based assistant is used.


## v13 notes
- Optional Render environment variables: `GEMINI_API_KEY` (real AI Copilot, server-side only), `ADMIN_EMAIL` + `ADMIN_PASSWORD` (+ optional `ADMIN_PIN`) to create your owner account on every start, `SMTP_EMAIL` + `SMTP_PASSWORD` (Gmail app password) to enable e-mail sign-in codes.
- Sandbox login: demo@netguard.ai / NetGuardDemo2026! (read-only, sample data, or use the "Try the sandbox" button).

## v14 notes
- Optional environment variables for sign-up e-mail codes (use ONE): `RESEND_API_KEY` or `BREVO_API_KEY` (+ `MAIL_FROM`), or `SMTP_EMAIL` + `SMTP_PASSWORD`. If none is set, sign-ups work without a code.
- The threat map uses Esri World Dark Gray base + reference tiles (no API key; OpenStreetMap tiles are not used because they return 403), darkened to a pitch-black SOC look with CSS, over a built-in continent layer so it is never blank. Attacker locations come from the free ipwho.is service, called from the server only (cached 24 h).

## v17 notes
- **Sign-up needs a mail service.** Set ONE of: `BREVO_API_KEY` + `SENDER_EMAIL`, `RESEND_API_KEY` (+ `MAIL_FROM`), `EMAILJS_SERVICE_ID/TEMPLATE_ID/PUBLIC_KEY`, or SMTP. Without one, sign-up says the mail service is not ready (the sandbox button and the `ADMIN_EMAIL`/`ADMIN_PASSWORD` owner login still work). The 6-digit Verification Code is always required; the 4-digit PIN is only the screen lock.
- Fake/disposable domains are rejected (blocklist + server-side MX lookup).
- **Agent engine:** trusted addresses (this host, loopback, gateway, DNS 8.8.8.8/1.1.1.1) and your own outbound ESTABLISHED web traffic (ports 80/443) are ignored. SYN flood = `SYN_RECV` per remote IP; port scan = distinct local ports probed in 30 s (`--scan-ports`, default 15) with the exact port list; failed logins from auth.log/secure, `journalctl -u ssh`, or Windows Event 4625 (run as Administrator).
- Real alerts get country, city, lat/lon, ISP and ASN attached by the server (ipwho.is, cached).
- Copilot: set `GEMINI_API_KEY` (model `gemini-2.5-flash`) on Render.

## v20 notes
- **Screen lock is server-side.** `POST /api/auth/lock` marks the session locked; every other API call returns 423 until `POST /api/auth/unlock` (account password or PIN). F5 or clearing browser storage does not bypass it.
- **Forgot password:** 6-digit email code (`/api/auth/forgot`, `/api/auth/reset`), 10-minute expiry, 5 tries, resets sign out all sessions. Needs a working mail provider.
- **Alert emails:** critical/high alerts email the device owner (device, attack type, source IP, country/city/ASN, ports, firewall status), max 1 per source IP per 15 minutes. Toggle: Settings > `email_alerts`. Works with Brevo, Resend or SMTP (not EmailJS, which only carries the code template).
- **Agent 2.1:** EMA + Z-score anomaly detection, OT ports 502/102/20000/4840, never blocks private (RFC-1918) addresses unless `--allow-lan-block`, `--install-service` (systemd or Windows scheduled task). The server raises a high alert if an agent is silent for more than 3 minutes.
- **Proxy / limits:** `TRUST_PROXY=1`, `TRUST_PROXY_HOPS` (default 1) and `CLIENT_IP_HEADER` pick the real client IP. Rate limits cover failed agent keys, verification/reset codes and per-email login lockout.
- **Copilot:** accepts Gemini keys starting `AIza` or `AQ.`, with a smarter local fallback.
- Tests: `node test/e2e.js` and `python3 test/agent_test.py`.

## v21 notes
- 2-step sign-in by e-mail code now works through the mail service (Brevo/Resend/EmailJS/SMTP); raw `SMTP_EMAIL` is no longer required.
- Canary Trap hits are located with the geo lookup (shown on the World Map) and e-mail the owner right away (Brevo/Resend/SMTP).

## v22 notes
- **Tamil voice without a Tamil voice installed:** Copilot "Read answers aloud" checks the computer for a `ta` voice. If none exists, Tamil text is split into chunks of at most 180 characters and played from `GET /api/tts` (server fetches the MP3 from Google Translate TTS, 90 requests/min per user, cached). The text of the spoken answer is sent to Google for this. `TTS_BASE` overrides the host. Unchecking "Read answers aloud" or pressing Stop ends the audio.
- **`AQ.` Gemini keys:** tried on the Vertex AI Express endpoint first (`VERTEX_BASE` overrides), then the Generative Language endpoint (`?key=` + Bearer, then `x-goog-api-key`). `GET /api/copilot/status` now also returns `ai_error` (last Google status/message, key removed).

## v23 notes
- The traffic-spike threshold never goes below `max(src_pps_limit, 500)` pkt/s, so a quiet laptop (baseline ~20 pkt/s) no longer alarms at 60-120 pkt/s.
- A "from many sources" flood alert needs an identifiable source or real half-open (SYN_RECV) connections. Your own outbound browsing/video no longer counts.
- No more "traffic dropped" alerts, and Windows SMB (445/139) no longer raises an exposure warning on its own.
- One-time clean-up on first start: old non-demo `flood` alerts with no source and all `traffic_drop` alerts are deleted.

## v24: autonomous engine
Detection no longer uses editable thresholds (warm-up 15 samples, 4 sigma above the learned mean, 500 pkt/s floor, instant at 1500, 15-port scan, 6 failed logins). Settings shows live engine stats (`GET /api/ai-engine/status`) and `POST /api/ai-engine/recalibrate` resets the learned baseline.
