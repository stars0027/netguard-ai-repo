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
