'use strict';
(() => {
  // ------------------------------------------------------------------ helpers
  const $app = document.getElementById('app');
  const el = (tag, props, ...kids) => {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (v == null || v === false) continue;
      if (k === 'class') n.className = v;
      else if (k === 'text') n.textContent = v;
      else if (k === 'style') n.style.cssText = v; // CSSOM is allowed by our CSP, style attributes are not
      else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
      else if (k === 'value') n.value = v;
      else if (k === 'checked') n.checked = !!v;
      else if (k === 'disabled') n.disabled = !!v;
      else n.setAttribute(k, v === true ? '' : v);
    }
    for (const kid of kids.flat()) if (kid != null && kid !== false) n.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    return n;
  };
  const svg = (d, size = 22, fill = 'none') => {
    const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    s.setAttribute('viewBox', '0 0 24 24'); s.setAttribute('width', size); s.setAttribute('height', size);
    s.setAttribute('fill', fill); s.setAttribute('stroke', 'currentColor'); s.setAttribute('stroke-width', '1.8');
    s.setAttribute('stroke-linecap', 'round'); s.setAttribute('stroke-linejoin', 'round'); s.setAttribute('aria-hidden', 'true');
    for (const p of [].concat(d)) { const path = document.createElementNS(s.namespaceURI, 'path'); path.setAttribute('d', p); s.append(path); }
    return s;
  };
  const SHIELD = ['M12 3l7 3v5c0 4.5-3 8.3-7 10-4-1.7-7-5.5-7-10V6l7-3z', 'M9 12l2 2 4-4'];
  const WARN = ['M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z', 'M12 9v4M12 17h.01'];

  const fmtTime = (ts) => new Date(ts).toLocaleTimeString([], { hour12: false });
  const fmtDT = (ts) => new Date(ts).toLocaleString([], { hour12: false, month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const ago = (ts) => { if (!ts) return 'never'; const s = Math.round((Date.now() - ts) / 1000); return s < 5 ? 'just now' : s < 60 ? s + ' s ago' : s < 3600 ? Math.round(s / 60) + ' min ago' : s < 86400 ? Math.round(s / 3600) + ' h ago' : Math.round(s / 86400) + ' d ago'; };
  const left = (ts) => { if (!ts) return 'permanent'; const m = Math.round((ts - Date.now()) / 60000); return m <= 0 ? 'expiring' : m < 90 ? m + ' min' : Math.round(m / 60) + ' h'; };

  let toastTimer;
  function toast(msg, bad) {
    const t = document.getElementById('toast');
    t.textContent = msg; t.className = 'on' + (bad ? ' bad' : '');
    clearTimeout(toastTimer); toastTimer = setTimeout(() => { t.className = ''; }, 3500);
  }

  async function api(method, path, body) {
    const res = await fetch(path, {
      method, credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'NetGuard' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    let data = {}; try { data = await res.json(); } catch { /* empty */ }
    if (res.status === 401 && path !== '/api/auth/login') { if (S.me) { S.me = null; closeStream(); route(); } }
    if (!res.ok) throw new Error(data.error || 'Request failed (' + res.status + ')');
    return data;
  }

  // ------------------------------------------------------------------ state
  const S = {
    me: null, devices: [], alerts: [], logs: [], stats: null, statsErr: false, alertsState: 'loading', demoAlerts: [], demoLogs: [], sel: null, series: [], live: {}, banner: null, bannerTimer: null,
    openAlert: null, stream: null, linked: false, ins: null,
  };
  let current = { refresh: null };

  // ---- shared UI pieces: loading / empty / error boxes, Demo tag, one-line number formatting
  const stateBox = (kind, msg, retry) => el('div', { class: 'state ' + kind, role: kind === 'error' ? 'alert' : 'status' },
    kind === 'loading' ? el('i', { class: 'spin', 'aria-hidden': 'true' }) : null, el('span', {}, msg),
    retry ? el('button', { class: 'btn sm', type: 'button', onclick: retry }, 'Try again') : null);
  const demoTag = (txt) => el('span', { class: 'demo-tag', title: 'Simulated data. It is separate from your real devices.' }, txt || 'Demo');
  // copy-to-clipboard code block, used for every install command
  const codeBlock = (text) => {
    const b = el('button', { class: 'btn sm copybtn', type: 'button', onclick: async () => {
      try { await navigator.clipboard.writeText(text); b.textContent = 'Copied'; } catch { b.textContent = 'Select + Ctrl+C'; }
      setTimeout(() => { b.textContent = 'Copy'; }, 1800);
    } }, 'Copy');
    return el('div', { class: 'codewrap' }, el('div', { class: 'codeblock' }, text), b);
  };
  // IP checks run in the browser first for a clear message; the server checks again (never trust the browser)
  function ipProblem(v) {
    v = String(v || '').trim();
    if (!v) return 'Enter an IP address.';
    if (/\/\d+$/.test(v)) return 'Ranges (CIDR like 10.0.0.0/24) are not accepted, because one typo could block a whole network. Enter a single IP.';
    const v4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(v);
    const v6 = /^[0-9a-f:]+$/i.test(v) && v.includes(':') && v.length <= 45;
    if (!v4 && !v6) return 'That is not a valid IPv4 or IPv6 address.';
    if (/^127\./.test(v) || v === '::1' || /^0\.0\.0\.0$/.test(v)) return v + ' is this computer (loopback). Blocking or inspecting it would only lock you out, so it is not allowed.';
    return null;
  }
  const num = (k) => (S.stats && S.stats[k] != null ? S.stats[k] : '—'); // "—" = not loaded yet, never a misleading 0
  const realDevices = () => S.devices.filter((d) => !d.virtual);

  // ------------------------------------------------------------------ realtime
  function closeStream() { if (S.stream) { S.stream.close(); S.stream = null; } }
  function openStream() {
    closeStream();
    const es = new EventSource('/api/stream');
    S.stream = es;
    es.onopen = () => { S.linked = true; updateLink(); };
    es.onerror = () => { S.linked = false; updateLink(); };
    es.addEventListener('telemetry', (e) => {
      const d = JSON.parse(e.data);
      S.live[d.device_id] = d;
      const dev = S.devices.find((x) => x.id === d.device_id);
      if (dev) { dev.status = 'online'; dev.last_seen = d.ts; dev.enforce = d.enforce; }
      if (d.device_id === S.sel) {
        S.series.push({ ts: d.ts, pps: d.pps });
        if (S.series.length > 300) S.series.shift();
      }
      if (current.tick) current.tick();
    });
    es.addEventListener('telemetry_state', (e) => { const d = JSON.parse(e.data); if (S.live[d.device_id]) S.live[d.device_id].status = d.status; if (current.tick) current.tick(); });
    es.addEventListener('log', (e) => {
      const l = JSON.parse(e.data), box = l.demo ? S.demoLogs : S.logs;
      box.push(l); if (box.length > 80) box.shift();
      if (current.logTick) current.logTick();
    });
    es.addEventListener('alert', (e) => {
      const a = JSON.parse(e.data);
      (a.demo ? S.demoAlerts : S.alerts).unshift(a);
      refreshStats(); loadInsights();
      if (['critical', 'high'].includes(a.severity)) {
        alarmSound(a);
        const blocked = /^(\[Demo\] )?Blocked/.test(a.action || '');
        S.banner = {
          title: (a.demo ? 'DEMO · ' : '') + (a.type === 'physical_anomaly' ? 'Emergency power shutdown' : blocked ? 'Attack blocked' : 'Attack detected'),
          sub: a.title + (a.action ? ' — ' + a.action : ''), good: blocked,
        };
        clearTimeout(S.bannerTimer);
        S.bannerTimer = setTimeout(() => { S.banner = null; if (current.tick) current.tick(); }, 9000);
      }
      if (current.tick) current.tick();
      if (current.refresh) current.refresh();
      updateNavBadge();
    });
    for (const ev of ['alert_update', 'alert_status', 'block', 'unblock', 'device']) {
      es.addEventListener(ev, () => { if (ev.startsWith('alert')) { loadAlerts().then(() => { current.refresh && current.refresh(); }); refreshStats(); } else { if (ev === 'device') loadDevices(); refreshStats(); loadInsights(); current.refresh && current.refresh(); } });
    }
  }
  async function refreshStats() { try { S.stats = await api('GET', '/api/stats'); S.statsErr = false; } catch { S.statsErr = true; } updateNavBadge(); if (current.tick) current.tick(); }
  async function loadDevices() { S.devices = (await api('GET', '/api/devices')); if (!S.sel || !realDevices().find((d) => d.id === S.sel)) S.sel = realDevices()[0] ? realDevices()[0].id : null; }
  async function loadAlerts() { try { S.alerts = await api('GET', '/api/alerts?limit=200'); S.alertsState = 'ok'; } catch { S.alertsState = 'error'; } }
  async function loadDemo() { try { [S.demoAlerts, S.demoLogs] = await Promise.all([api('GET', '/api/alerts?demo=1&limit=30'), api('GET', '/api/logs?demo=1&limit=40')]); } catch { /* demo panel just stays empty */ } }
  async function loadInsights() { try { S.ins = await api('GET', '/api/insights'); if (current.insights) current.insights(); } catch { /* ignore */ } }
  const TYPE_LABEL = { flood: 'Traffic flood', port_scan: 'Port scan', brute_force: 'Brute force', conn_flood: 'Connection flood', exposed_port: 'Exposed service', physical_anomaly: 'Physical event', traffic_drop: 'Traffic drop', device_offline: 'Device offline', canary: 'Canary trap' };
  const typeLabel = (t) => TYPE_LABEL[t] || String(t).replace(/_/g, ' ');
  // sound + browser notification when something serious happens (opt-in, remembered per browser)
  const soundOn = () => { try { return localStorage.getItem('ng_sound') === '1'; } catch { return false; } };
  let audioCtx;
  function alarmSound(a) {
    if (!soundOn()) return;
    try {
      audioCtx = audioCtx || new (window.AudioContext || window.webkitAudioContext)();
      const t0 = audioCtx.currentTime, tones = a.severity === 'critical' ? [880, 660, 880, 660] : [740, 740];
      tones.forEach((f, i) => { const o = audioCtx.createOscillator(), g = audioCtx.createGain(); o.type = 'square'; o.frequency.value = f; g.gain.setValueAtTime(0.0001, t0 + i * 0.18); g.gain.exponentialRampToValueAtTime(0.12, t0 + i * 0.18 + 0.02); g.gain.exponentialRampToValueAtTime(0.0001, t0 + i * 0.18 + 0.16); o.connect(g); g.connect(audioCtx.destination); o.start(t0 + i * 0.18); o.stop(t0 + i * 0.18 + 0.17); });
    } catch { /* audio not available */ }
    speakAlert(a);
    try { if (document.hidden && 'Notification' in window && Notification.permission === 'granted') new Notification('NetGuard AI: ' + a.title, { body: a.action || a.severity }); } catch { /* ignore */ }
  }
  // spoken alerts in English and Tamil (uses the voices installed on the device; Tamil needs a Tamil voice)
  const TA_ALERT = { flood: 'போக்குவரத்து வெள்ளம்', port_scan: 'போர்ட் ஸ்கேன்', brute_force: 'கடவுச்சொல் ஊகித்தல்', conn_flood: 'இணைப்பு வெள்ளம்', exposed_port: 'திறந்த சேவை', physical_anomaly: 'உடல் சார்ந்த நிகழ்வு', traffic_drop: 'போக்குவரத்து வீழ்ச்சி', device_offline: 'சாதனம் ஆஃப்லைன்', canary: 'கேனரி பொறி திறக்கப்பட்டது' };
  const voiceMode = () => { try { return localStorage.getItem('ng_voice') || 'both'; } catch { return 'both'; } };
  function sayLine(text, lang) {
    const u = new SpeechSynthesisUtterance(text); u.lang = lang; u.rate = 1; u.volume = 0.9;
    const v = speechSynthesis.getVoices().find((x) => x.lang && x.lang.toLowerCase().startsWith(lang.slice(0, 2).toLowerCase())); if (v) u.voice = v;
    speechSynthesis.speak(u);
  }
  function speakAlert(a) {
    try {
      if (!('speechSynthesis' in window) || !a.type) return;
      const m = voiceMode(), blocked = /^Blocked/.test(a.action || '');
      const en = (a.severity === 'critical' ? 'Critical alert. ' : 'Warning. ') + typeLabel(a.type) + ' detected' + (a.src_ip ? ' from ' + a.src_ip.split('').join(' ').replace(/ \. /g, ' dot ') : '') + '.' + (blocked ? ' Attacker blocked.' : '');
      const ta = (a.severity === 'critical' ? 'முக்கிய எச்சரிக்கை. ' : 'எச்சரிக்கை. ') + (TA_ALERT[a.type] || typeLabel(a.type)) + ' கண்டறியப்பட்டது.' + (a.src_ip ? ' ' + a.src_ip + ' இலிருந்து.' : '') + (blocked ? ' தாக்குபவர் தடுக்கப்பட்டார்.' : '');
      speechSynthesis.cancel();
      if (m === 'both' || m === 'en') sayLine(en, 'en-IN');
      if (m === 'both' || m === 'ta') sayLine(ta, 'ta-IN');
    } catch { /* ignore */ }
  }
  function toggleSound(btn) {
    const on = !soundOn();
    try { localStorage.setItem('ng_sound', on ? '1' : '0'); } catch { /* ignore */ }
    if (on) { try { if ('Notification' in window && Notification.permission === 'default') Notification.requestPermission(); } catch { /* ignore */ } alarmSound({ severity: 'high', type: 'port_scan', src_ip: '203.0.113.5', action: 'Blocked' }); }
    btn.textContent = on ? 'Sound on' : 'Sound off'; btn.setAttribute('aria-pressed', String(on));
  }
  // The badge reads the SAME number as the dashboard, War Room and Report (S.stats.open_alerts, real alerts only).
  function updateNavBadge() { const b = document.getElementById('navBadge'); if (b) { const n = S.stats ? S.stats.open_alerts : 0; b.textContent = n > 99 ? '99+' : n; b.hidden = !n; } }
  function updateLink() {
    const l = document.getElementById('linkLed'), t = document.getElementById('linkText');
    if (!l) return;
    l.className = 'led ' + (S.linked ? 'on' : 'wait');
    const real = realDevices(), on = real.filter((d) => d.status === 'online').length;
    t.textContent = S.linked ? `Live · ${on} of ${real.length} devices online` : 'Reconnecting…';
  }

  // ------------------------------------------------------------------ auth screen
  // password field with a show/hide eye button
  function pwField(label, props) {
    const input = el('input', { type: 'password', required: true, ...props });
    const eye = el('button', { class: 'eye', type: 'button', 'aria-label': 'Show password', title: 'Show / hide password', onclick: () => {
      const show = input.type === 'password'; input.type = show ? 'text' : 'password'; eye.textContent = show ? '🙈' : '👁'; eye.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
    } }, '👁');
    const lbl = el('label', {}, el('span', { class: 'lbltxt' }, label), el('span', { class: 'pwbox' }, input, eye));
    return { input, lbl, setLabel: (t) => { lbl.querySelector('.lbltxt').textContent = t; } };
  }

  function authView() {
    let mode = 'login', ticket = null;
    const err = el('p', { class: 'err', role: 'alert' });
    const name = el('input', { type: 'text', autocomplete: 'name', maxlength: 60 });
    const email = el('input', { type: 'email', autocomplete: 'email', required: true });
    const pwf = pwField('Password', { autocomplete: 'current-password', minlength: 1 }), pw = pwf.input;
    const pin = el('input', { type: 'password', inputmode: 'numeric', pattern: '\\d{4}', maxlength: 4, autocomplete: 'off', placeholder: 'optional, 4 digits' });
    const pinLbl = el('label', {}, '4-digit security PIN (extra protection, recommended)', pin);
    const invite = el('input', { type: 'text', autocomplete: 'off', maxlength: 40 });
    const inviteLbl = el('label', {}, 'Invite code (ask the owner)', invite); inviteLbl.hidden = true;
    let signupMode = 'open';
    const nameLbl = el('label', {}, 'Name', name);
    const submit = el('button', { class: 'btn primary', type: 'submit' }, 'Sign in');
    const switcher = el('button', { class: 'btn', type: 'button' }, 'Create an account');
    const sandbox = el('button', { class: 'btn sandbox', type: 'button', onclick: async () => {
      sandbox.disabled = true; err.textContent = '';
      try { await api('POST', '/api/auth/sandbox', {}); await boot(); location.hash = '#/dashboard'; } catch (x) { err.textContent = x.message; } finally { sandbox.disabled = false; }
    } }, '⚡ Try the sandbox demo (read-only, sample data)');
    const title = el('h2', {}, 'Sign in');
    const code = el('input', { type: 'text', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: 6, required: true });
    const codeLbl = el('label', {}, 'Security PIN (4 digits) or authenticator / e-mail code (6 digits)', code);
    const step1 = el('div', { class: 'form' }), step2 = el('div', { class: 'form' }); step2.hidden = true;
    function setMode(m) {
      mode = m; nameLbl.hidden = m === 'login'; pinLbl.hidden = m === 'login'; inviteLbl.hidden = !(m === 'signup' && signupMode === 'invite');
      title.textContent = m === 'login' ? 'Sign in' : 'Create your account';
      submit.textContent = m === 'login' ? 'Sign in' : 'Create account';
      switcher.textContent = m === 'login' ? 'Create an account' : 'I already have an account';
      pwf.setLabel(m === 'login' ? 'Password' : 'Password (8+ characters)');
      pw.autocomplete = m === 'login' ? 'current-password' : 'new-password'; err.textContent = '';
    }
    switcher.onclick = () => setMode(mode === 'login' ? 'signup' : 'login');
    const form = el('form', { class: 'form panel pad', onsubmit: async (e) => {
      e.preventDefault(); err.textContent = ''; submit.disabled = true;
      try {
        if (ticket) {
          await api('POST', '/api/auth/verify', { ticket, code: code.value });
        } else {
          const r = await api('POST', mode === 'login' ? '/api/auth/login' : '/api/auth/signup', { email: email.value.trim().toLowerCase(), password: pw.value, name: name.value, invite: invite.value, pin: pin.value });
          if (r.step2) { ticket = r.ticket; step1.hidden = true; step2.hidden = false; title.textContent = 'Second step'; submit.textContent = 'Verify'; switcher.hidden = true; code.focus(); return; }
        }
        await boot(); location.hash = '#/dashboard';
      } catch (x) { err.textContent = x.message; } finally { submit.disabled = false; }
    } }, title,
      step1, step2, err, el('div', { class: 'inline' }, submit, switcher),
      el('div', { class: 'or' }, 'or'), sandbox,
      el('p', { class: 'foot', style: 'margin-top:12px' }, el('a', { href: '/privacy.html' }, 'Privacy'), ' · ', el('a', { href: '#support', onclick: (e) => { e.preventDefault(); const t = document.getElementById('pubInfo'); if (t) t.scrollIntoView({ behavior: 'smooth' }); } }, 'Support')));
    step1.append(nameLbl, el('label', {}, 'Email', email), pwf.lbl, pinLbl, inviteLbl);
    step2.append(el('p', { class: 'muted' }, 'Enter the code from your security PIN, authenticator app, or e-mail to finish signing in.'), codeLbl);
    code.required = false; email.required = true;
    setMode('login');
    api('GET', '/api/public-config').then((c) => { signupMode = c.signup; if (c.signup === 'closed') { switcher.disabled = true; switcher.textContent = 'Sign-ups are closed'; } setMode(mode); }).catch(() => {});
    const card = (h, ...kids) => el('div', { class: 'pubcard' }, el('h3', {}, h), ...kids);
    return el('div', { class: 'wrap' },
      el('div', { class: 'auth' },
        el('div', {},
          el('div', { class: 'brand' }, el('span', { class: 'mark' }, svg(SHIELD)), el('div', {}, el('h1', {}, 'NetGuard ', el('span', {}, 'AI')), el('p', { class: 'tag' }, 'Network & industrial anomaly defense'))),
          el('div', { class: 'scene', 'aria-hidden': 'true' }, el('div', { class: 'shield3d' }, [0, 1, 2, 3, 4, 5].map((i) => el('div', { class: 'layer l' + i })))),
          el('h2', { class: 'big-h', style: 'margin-top:28px;text-transform:none;letter-spacing:.02em' }, 'Detect attacks on your network and block them automatically.'),
          el('ul', {},
            el('li', {}, 'Install the agent on any server, PC or gateway'),
            el('li', {}, 'It learns normal traffic, then catches floods, port scans and brute-force logins'),
            el('li', {}, 'Starts in monitor-only mode: you see what it WOULD block before it blocks anything'),
            el('li', {}, 'Live dashboard, alert history and webhook notifications'))),
        form),
      el('div', { class: 'pubinfo', id: 'pubInfo' },
        card('Try it without installing anything', el('p', {}, 'The sandbox is a read-only copy with sample devices and alerts, so you can click around safely. Inside your own account, the Attack Simulator runs a clearly labelled Demo device that never touches a real device or firewall.')),
        card('Supported systems', el('ul', {}, el('li', {}, el('b', {}, 'Linux'), ' (Debian, Ubuntu, Fedora, Raspberry Pi OS): full support, firewall blocking with iptables, optional packet sniffer'), el('li', {}, el('b', {}, 'Windows 10 / 11 / Server'), ': monitoring and blocking with Windows Firewall (run as Administrator)'), el('li', {}, el('b', {}, 'macOS'), ': monitoring only for now'), el('li', {}, 'Needs Python 3.8+ and the psutil package'))),
        card('How installation works', el('ol', {}, el('li', {}, 'Create an account, then open Devices and add a device'), el('li', {}, 'Copy the one-line install command and run it on that machine'), el('li', {}, 'It appears online and learns normal traffic (about a minute)'), el('li', {}, 'Keep it in monitor-only (dry run) until you trust the alerts, then enable live blocking'))),
        card('Privacy & support', el('p', {}, 'Your devices, alerts and API keys are visible only to your account. API keys and passwords are stored hashed. You can delete your account and all its data at any time. ', el('a', { href: '/privacy.html' }, 'Read the privacy page'), '.'), el('p', {}, 'Support: open an issue at ', el('a', { href: 'https://github.com/stars0027/netguard-ai-repo/issues', target: '_blank', rel: 'noopener' }, 'github.com/stars0027/netguard-ai-repo'), '.'))));
  }

  // ------------------------------------------------------------------ shell: collapsible left sidebar + slim header
  const NAV_GROUPS = [
    ['Operations (SOC)', [['dashboard', 'Dashboard', 'M3 12l9-8 9 8M5 10v10h14V10'], ['warroom', 'War Room', 'M12 2a10 10 0 100 20 10 10 0 000-20zM12 12l6-4'], ['alerts', 'Alerts', 'M12 3l9 16H3L12 3zM12 10v4M12 17h.01'], ['blocks', 'Blocklist', 'M12 2a10 10 0 100 20 10 10 0 000-20zM5 5l14 14']]],
    ['Defense & fleet', [['devices', 'Devices', 'M4 5h16v10H4zM8 19h8M12 15v4'], ['copilot', 'Copilot AI', 'M4 5h16v11H9l-5 4V5z'], ['tools', 'Security Tools', 'M14 6l4 4-9 9H5v-4l9-9z'], ['report', 'Incident Report', 'M6 3h9l4 4v14H6zM9 12h7M9 16h7']]],
    ['Simulation & system', [['simulator', 'Attack Simulator (Demo)', 'M5 3l14 9-14 9V3z'], ['settings', 'Settings', 'M12 8a4 4 0 100 8 4 4 0 000-8zM12 2v3M12 19v3M2 12h3M19 12h3']]],
  ];
  const navItems = () => NAV_GROUPS.flatMap(([, items]) => items.map(([k, l]) => [k, l]));
  const sideCollapsed = () => { try { return localStorage.getItem('ng_side') === '1'; } catch { return false; } };

  // ---- privacy shield: lock screen (manual button + 10 minutes without activity)
  let lockTimer = null, lockEl = null;
  const IDLE_MS = 10 * 60 * 1000;
  const isLocked = () => { try { return sessionStorage.getItem('ng_locked') === '1'; } catch { return false; } };
  function armIdle() {
    clearTimeout(lockTimer);
    if (S.me && !S.me.sandbox && !isLocked()) lockTimer = setTimeout(lockScreen, IDLE_MS);
  }
  ['mousemove', 'keydown', 'click', 'touchstart'].forEach((ev) => document.addEventListener(ev, () => { if (!lockEl) armIdle(); }, { passive: true }));
  function lockScreen() {
    if (lockEl || !S.me) return;
    try { sessionStorage.setItem('ng_locked', '1'); } catch { /* ignore */ }
    const secret = el('input', { type: 'password', autocomplete: 'current-password', placeholder: 'Password or 4-digit PIN', 'aria-label': 'Password or PIN' });
    const msg = el('p', { class: 'err', role: 'alert' });
    const go = async (e) => {
      e.preventDefault(); msg.textContent = '';
      try { await api('POST', '/api/auth/unlock', { secret: secret.value }); unlockScreen(); } catch (x) { msg.textContent = x.message; secret.value = ''; }
    };
    lockEl = el('div', { class: 'lockshield', role: 'dialog', 'aria-modal': 'true', 'aria-label': 'Screen locked' },
      el('form', { class: 'lockbox', onsubmit: go }, svg(SHIELD, 44), el('h2', {}, 'Screen locked'), el('p', { class: 'muted' }, 'Live data is hidden. Enter your password or PIN to continue.'), secret, msg, el('button', { class: 'btn primary', type: 'submit' }, 'Unlock'),
        el('button', { class: 'btn sm', type: 'button', onclick: async () => { await api('POST', '/api/auth/logout', {}).catch(() => {}); unlockScreen(); closeStream(); S.me = null; route(); } }, 'Sign out instead')));
    document.body.append(lockEl); $app.classList.add('blurred'); secret.focus();
  }
  function unlockScreen() {
    try { sessionStorage.removeItem('ng_locked'); } catch { /* ignore */ }
    if (lockEl) { lockEl.remove(); lockEl = null; } $app.classList.remove('blurred'); armIdle();
  }

  function shell(view, active) {
    const badge = el('span', { class: 'badge', id: 'navBadge', hidden: true });
    const body = el('div', { class: 'wrap shell' + (sideCollapsed() ? ' collapsed' : '') });
    const toggle = () => {
      if (window.innerWidth < 1024) body.classList.toggle('drawer'); else { body.classList.toggle('collapsed'); try { localStorage.setItem('ng_side', body.classList.contains('collapsed') ? '1' : '0'); } catch { /* ignore */ } }
    };
    const search = el('input', { type: 'search', class: 'navsearch', placeholder: '🔍 Search modules…  (Ctrl+K)', 'aria-label': 'Search modules', oninput: () => {
      const q = search.value.trim().toLowerCase();
      for (const a of side.querySelectorAll('a.navlink')) a.hidden = !!q && !a.textContent.toLowerCase().includes(q);
      for (const g of side.querySelectorAll('.navgroup')) g.hidden = !g.querySelector('a.navlink:not([hidden])');
    } });
    const side = el('aside', { class: 'side', 'aria-label': 'Main menu' },
      el('div', { class: 'brand' }, el('span', { class: 'mark' }, svg(SHIELD)), el('div', { class: 'brandtxt' }, el('h1', {}, 'NetGuard ', el('span', {}, 'AI')), el('p', { class: 'tag' }, 'Network & industrial anomaly defense'))),
      search,
      NAV_GROUPS.map(([g, items]) => el('div', { class: 'navgroup' }, el('p', { class: 'navhead' }, g),
        items.map(([k, label, icon]) => el('a', { class: 'navlink', href: '#/' + k, title: label, 'aria-current': k === active ? 'page' : null, onclick: () => body.classList.remove('drawer') }, svg(icon, 18), el('span', { class: 'navtxt' }, label), k === 'alerts' ? badge : null)))));
    const title = (navItems().find(([k]) => k === active) || ['', 'NetGuard'])[1];
    const header = el('header', { class: 'top2' },
      el('button', { class: 'btn sm', type: 'button', 'aria-label': 'Toggle menu', onclick: toggle }, '☰'),
      el('h2', { class: 'pagetitle' }, title),
      el('div', { class: 'hdr-right' },
        el('span', { class: 'link' }, el('i', { class: 'led wait', id: 'linkLed' }), el('span', { id: 'linkText' }, 'Connecting…')),
        el('button', { class: 'btn sm', type: 'button', 'aria-pressed': String(soundOn()), title: 'Alarm sound and notification for serious alerts', onclick: (e) => toggleSound(e.currentTarget) }, soundOn() ? 'Sound on' : 'Sound off'),
        S.me.sandbox ? null : el('button', { class: 'btn sm', type: 'button', title: 'Hide the screen until you enter your password or PIN', onclick: lockScreen }, '🔒 Lock'),
        el('button', { class: 'btn sm kbd', type: 'button', title: 'Command palette', onclick: openPalette }, 'Ctrl+K'),
        el('span', { class: 'userbadge', title: S.me.email }, (S.me.name || S.me.email).slice(0, 18)),
        el('button', { class: 'btn sm', type: 'button', onclick: async () => { await api('POST', '/api/auth/logout', {}); closeStream(); S.me = null; route(); } }, 'Sign out')));
    body.append(side, el('div', { class: 'scrim', onclick: () => body.classList.remove('drawer') }),
      el('div', { class: 'main' }, header, S.me.sandbox ? el('div', { class: 'demo-banner', role: 'note' }, demoTag('SANDBOX'), el('span', {}, 'You are in the read-only sandbox. Everything here is sample data and nothing can be changed. Sign out and create an account to protect your own devices.')) : null, view));
    return body;
  }

  // ------------------------------------------------------------------ alert forensics window
  function openForensics(a, after) {
    const d = a.detail || {};
    const ports = d.ports || (d.top_source && d.top_source.ports) || (d.port ? [d.port] : []);
    const peak = d.pps || d.pkts_per_s || d.peak_pps || null;
    const ipKind = !a.src_ip ? '—' : /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|fc|fd|fe80)/i.test(a.src_ip) ? 'Private / internal address' : 'Public internet address (no location database is bundled, so no country is shown)';
    const ro = !!(S.me && S.me.sandbox);
    const close = () => { m.remove(); document.removeEventListener('keydown', esc, true); };
    const esc = (e) => { if (e.key === 'Escape') close(); };
    const act = (fn, okMsg) => async () => { try { await fn(); toast(okMsg); close(); if (after) await after(); } catch (e) { toast(e.message, true); } };
    const row = (k, v) => el('div', { class: 'frow' }, el('span', { class: 'k' }, k), el('span', { class: 'v' }, v == null || v === '' ? '—' : v));
    const m = el('div', { class: 'palette', role: 'dialog', 'aria-modal': 'true', 'aria-label': 'Alert details', onclick: (e) => { if (e.target === m) close(); } },
      el('div', { class: 'palette-box forensic' },
        el('div', { class: 'head' }, el('h2', {}, el('span', { class: 'sev ' + a.severity }, a.severity), ' ' + typeLabel(a.type)), el('button', { class: 'btn sm', onclick: close }, 'Close')),
        el('p', {}, a.title),
        row('Time', fmtDT(a.created)), row('Attack type', typeLabel(a.type)), row('Source IP', a.src_ip), row('Origin', ipKind),
        row('Target device', a.device_name), row('Targeted ports', ports.length ? ports.join(', ') : null), row('Peak packet rate', peak != null ? Number(peak).toLocaleString() + ' pkt/s' : null),
        row('Status', a.status), row('What NetGuard did', a.action),
        el('p', { class: 'k', style: 'margin-top:10px' }, 'Raw telemetry'), el('pre', {}, JSON.stringify(d, null, 2)),
        ro ? el('p', { class: 'muted' }, 'Sandbox is read-only: actions are turned off.') : null,
        el('div', { class: 'inline', style: 'margin-top:12px' },
          a.src_ip ? el('button', { class: 'btn danger', disabled: ro || /^(\[Demo\] )?Blocked/.test(a.action || ''), onclick: act(() => api('POST', `/api/alerts/${a.id}/block`, {}), 'Blocked ' + a.src_ip) }, 'Block IP now') : null,
          a.src_ip ? el('button', { class: 'btn', disabled: ro, onclick: act(() => api('POST', '/api/allowlist', { ip: a.src_ip, note: 'Added from alert' }), a.src_ip + ' added to the allowlist') }, 'Add IP to allowlist') : null,
          el('button', { class: 'btn', onclick: () => { S.copilotSeed = `Investigate the ${typeLabel(a.type)} alert${a.src_ip ? ' from ' + a.src_ip : ''} on ${a.device_name || 'my device'}. Is it dangerous and what should I do?`; close(); location.hash = '#/copilot'; } }, 'Investigate in Copilot'),
          a.status === 'open' ? el('button', { class: 'btn', disabled: ro, onclick: act(() => api('PATCH', `/api/alerts/${a.id}`, { status: 'ack' }), 'Acknowledged') }, 'Acknowledge') : null,
          a.status !== 'resolved' ? el('button', { class: 'btn', disabled: ro, onclick: act(() => api('PATCH', `/api/alerts/${a.id}`, { status: 'resolved' }), 'Resolved') }, 'Resolve') : null)));
    document.body.append(m); document.addEventListener('keydown', esc, true);
  }

  // ------------------------------------------------------------------ protection status strip
  // One clear answer to "will NetGuard block anything right now?" plus the three things people look for: allowlist, expiry, undo.
  function protectionBar() {
    const box = el('section', { class: 'panel pad protbar', 'aria-label': 'Protection status' });
    function paint() {
      const p = S.stats && S.stats.protection;
      if (!p) { box.replaceChildren(S.statsErr ? stateBox('error', 'Could not load protection status.', refreshStats) : stateBox('loading', 'Checking protection status…')); return; }
      const r = S.stats.real, mins = p.block_ttl_min;
      const modeTxt = p.effective === 'off' ? 'Automatic blocking is OFF. NetGuard only raises alerts.'
        : p.effective === 'dry-run' ? 'Automatic blocking is ON, but every device is monitor-only (dry run). Nothing is blocked yet; alerts show what would be blocked.'
        : `Automatic blocking is ON for ${r.live_devices} live device${r.live_devices === 1 ? '' : 's'}` + (r.dry_run_devices ? ` (${r.dry_run_devices} more in dry run)` : '') + '.';
      box.dataset.mode = p.effective;
      box.replaceChildren(
        el('div', { class: 'pb-row' },
          el('span', { class: 'pb-pill', 'data-on': String(p.auto_block) }, 'Auto-block: ' + (p.auto_block ? 'ON' : 'OFF')),
          el('span', { class: 'pb-pill', 'data-on': String(p.lockdown) }, 'Lockdown: ' + (p.lockdown ? 'ON' : 'OFF')),
          el('span', { class: 'pb-pill' }, 'Scope: ' + (p.block_scope === 'fleet' ? 'all devices' : 'attacked device only')),
          el('span', { class: 'pb-pill' }, 'Blocks expire: ' + (mins ? mins + ' min' : 'never'))),
        el('p', { class: 'pb-msg' }, modeTxt),
        el('p', { class: 'pb-help' }, 'Safety tools: ', el('a', { href: '#/blocks' }, 'Allowlist (IPs never blocked)'), ' · ', el('a', { href: '#/blocks' }, 'Unblock / roll back'), ' · ', el('a', { href: '#/settings' }, 'Change expiry or turn off')));
    }
    paint();
    const prev = current.tick; // repaint whenever the shared stats refresh
    return { node: box, paint };
  }

  // ------------------------------------------------------------------ chart (hand drawn, no library)
  function drawChart(canvas, pts, baseline, thr, hot) {
    const dpr = window.devicePixelRatio || 1, w = canvas.clientWidth, h = canvas.clientHeight;
    if (!w || !h) return;
    if (canvas.width !== w * dpr || canvas.height !== h * dpr) { canvas.width = w * dpr; canvas.height = h * dpr; }
    const c = canvas.getContext('2d'); c.setTransform(dpr, 0, 0, dpr, 0, 0); c.clearRect(0, 0, w, h);
    const L = 44, R = 8, T = 8, B = 22, pw = w - L - R, ph = h - T - B;
    const max = Math.max(200, ...pts.map((p) => p.pps), thr || 0) * 1.12;
    const y = (v) => T + ph - (v / max) * ph;
    c.font = '11px IBM Plex Mono, monospace'; c.textBaseline = 'middle';
    for (let i = 0; i <= 4; i++) {
      const v = (max / 4) * i, yy = y(v);
      c.strokeStyle = 'rgba(255,255,255,.07)'; c.beginPath(); c.moveTo(L, yy); c.lineTo(w - R, yy); c.stroke();
      c.fillStyle = '#a8a8a0'; c.textAlign = 'right'; c.fillText(Math.round(v).toLocaleString(), L - 6, yy);
    }
    if (!pts.length) { c.fillStyle = '#8a9ead'; c.textAlign = 'center'; c.fillText('Waiting for telemetry…', w / 2, h / 2); return; }
    const t1 = pts[pts.length - 1].ts, span = 120000, t0 = t1 - span, x = (t) => L + ((t - t0) / span) * pw;
    c.textAlign = 'center'; c.fillStyle = '#8a9ead';
    for (let i = 0; i <= 4; i++) { const t = t0 + (span / 4) * i; c.fillText(fmtTime(t), Math.min(w - 24, Math.max(L + 22, x(t))), h - 8); }
    if (thr) { c.setLineDash([6, 6]); c.strokeStyle = 'rgba(200,121,44,.95)'; c.beginPath(); c.moveTo(L, y(thr)); c.lineTo(w - R, y(thr)); c.stroke(); c.setLineDash([]); }
    const col = hot ? '#ff5557' : '#FFF21A';
    const vis = pts.filter((p) => p.ts >= t0);
    if (!vis.length) return;
    c.beginPath(); vis.forEach((p, i) => (i ? c.lineTo(x(p.ts), y(p.pps)) : c.moveTo(x(p.ts), y(p.pps))));
    c.lineWidth = 2.5; c.strokeStyle = col; c.stroke();
    c.lineTo(x(vis[vis.length - 1].ts), y(0)); c.lineTo(x(vis[0].ts), y(0)); c.closePath();
    const gr = c.createLinearGradient(0, T, 0, T + ph); gr.addColorStop(0, hot ? 'rgba(255,85,87,.35)' : 'rgba(255,242,26,.28)'); gr.addColorStop(1, 'rgba(255,242,26,0)'); c.fillStyle = gr; c.fill();
  }

  // ------------------------------------------------------------------ dashboard
  function dashboardView() {
    const banner = el('div', { class: 'banner', role: 'alert', hidden: true }, svg(WARN, 40), el('div', {}, el('p', { class: 't', id: 'bT' }), el('p', { class: 's', id: 'bS' })));
    const kv = (id, label, small) => el('div', { class: 'kpi' }, el('span', { class: 'k' }, label), el('span', { class: 'v' + (small ? '' : ' st'), id }));
    const kpis = el('div', { class: 'panel kpis' }, kv('kPps', 'Live traffic', true), kv('kStatus', 'System status'), kv('kBlocked', 'Threats blocked', true), kv('kOpen', 'Open alerts', true));
    const canvas = el('canvas', { role: 'img', 'aria-label': 'Live network traffic in packets per second' });
    const chartPanel = el('section', { class: 'panel pad' });
    const devSel = el('select', { 'aria-label': 'Device', onchange: async (e) => { S.sel = Number(e.target.value); await loadSeries(); current.tick(); } });
    const logs = el('div', { class: 'logs', id: 'logs' });
    const statsNote = el('div', {}), prot = protectionBar();
    chartPanel.append(el('div', { class: 'head' }, el('h2', {}, 'Network traffic'), el('span', { class: 'meta' }, devSel, 'packets/s')), el('div', { class: 'chartbox' }, canvas));

    async function loadSeries() {
      if (!S.sel) { S.series = []; return; }
      try { S.series = await api('GET', `/api/metrics/${S.sel}?minutes=3`); } catch { S.series = []; }
    }
    function paintLogs() {
      logs.replaceChildren(...S.logs.slice().reverse().map((l) => el('div', { class: 'row ' + l.level }, el('span', { class: 't' }, fmtTime(l.ts)), el('span', { class: 'l' }, l.level), el('span', { class: 'm' }, l.msg))));
    }
    function tick() {
      const live = S.live[S.sel], dev = S.devices.find((d) => d.id === S.sel);
      const set = (id, text, tone) => { const n = document.getElementById(id); if (n) { n.textContent = text; if (tone) n.dataset.tone = tone; } };
      const status = live ? live.status : dev && dev.status === 'online' ? 'nominal' : 'offline';
      const label = { nominal: 'Nominal', under_attack: 'Under attack', safe_mode: 'Safe mode', learning: 'Learning', offline: 'No data' }[status] || status;
      const hot = status === 'under_attack' || status === 'safe_mode';
      set('kPps', live ? live.pps.toLocaleString() : '—', hot ? 'crit' : 'accent');
      set('kStatus', status === 'learning' && live ? `Learning ${Math.round(live.learning * 100)}%` : label, hot ? 'crit' : status === 'nominal' ? 'ok' : 'warn');
      set('kBlocked', String(num('blocked_total')), 'accent');
      set('kOpen', String(num('open_alerts')), S.stats && S.stats.open_alerts > 0 ? 'warn' : 'ok');
      statsNote.replaceChildren(...(S.statsErr ? [stateBox('error', 'Live counts could not be refreshed. The numbers shown may be out of date.', refreshStats)] : []));
      prot.paint();
      banner.hidden = !S.banner; banner.className = 'banner' + (S.banner && S.banner.good ? ' good' : '');
      if (S.banner) { document.getElementById('bT').textContent = S.banner.title; document.getElementById('bS').textContent = S.banner.sub; }
      document.getElementById('glow').className = S.banner && !S.banner.good ? 'on' : '';
      chartPanel.classList.toggle('alarm', hot);
      drawChart(canvas, S.series, live && live.baseline, live && live.threshold, hot);
      updateLink();
    }
    current = { tick, logTick: paintLogs, refresh: null, cleanup: () => { document.getElementById('glow').className = ''; } };
    (async () => {
      await Promise.all([loadDevices(), loadAlerts(), refreshStats()]);
      loaded = true;
      devSel.replaceChildren(...realDevices().map((d) => el('option', { value: d.id, selected: d.id === S.sel }, d.name)));
      if (!S.logs.length) S.logs = await api('GET', '/api/logs?limit=60');
      await loadSeries(); paintLogs(); current.tick();
    })();
    window.addEventListener('resize', tick);
    const prevCleanup = current.cleanup; current.cleanup = () => { prevCleanup(); window.removeEventListener('resize', tick); };
    let loaded = false; const loadingBox = stateBox('loading', 'Loading your devices and live counts…');
    const empty = el('div', { class: 'panel pad', hidden: true, id: 'emptyState' },
      el('h2', {}, 'Protect your first device'),
      el('p', { class: 'muted', style: 'margin:8px 0 14px;max-width:70ch' }, 'NetGuard protects machines that run its small agent. Add a server, PC or gateway, run one command on it, and it starts learning its normal traffic, detecting attacks and blocking attackers automatically.'),
      el('ol', { class: 'muted', style: 'margin:0 0 16px;padding-left:20px;display:grid;gap:4px' }, el('li', {}, 'Click Add device and give it a name'), el('li', {}, 'Copy the install command and run it on that machine'), el('li', {}, 'Watch it appear here within seconds')),
      el('div', { class: 'inline' }, el('a', { class: 'btn primary', href: '#/devices', style: 'text-decoration:none;display:inline-flex;align-items:center' }, 'Add your first device'), el('a', { class: 'btn', href: '#/simulator', style: 'text-decoration:none;display:inline-flex;align-items:center' }, 'Try the Demo (no real device)')));
    const showEmpty = () => { const n = realDevices().length; empty.hidden = n > 0 || !loaded; kpis.hidden = chartRow.hidden = n === 0; loadingBox.hidden = loaded; };
    const prevTick = tick; current.tick = () => { showEmpty(); prevTick(); };
    const chartRow = el('div', { class: 'split' }, chartPanel, el('section', { class: 'panel pad' }, el('div', { class: 'head' }, el('h2', {}, 'Live logs'), el('span', { class: 'meta' }, el('i', { class: 'led on' }), 'streaming')), logs));
    // ---- next-level insights: security score, 24h timeline, attack types, top attackers
    const SVGNS = 'http://www.w3.org/2000/svg', R = 52, CIRC = 2 * Math.PI * R;
    const ringArc = document.createElementNS(SVGNS, 'circle');
    for (const [k, v] of Object.entries({ cx: 70, cy: 70, r: R, fill: 'none', 'stroke-width': 12, 'stroke-linecap': 'round', transform: 'rotate(-90 70 70)', 'stroke-dasharray': `0 ${CIRC}`, class: 'ring-arc' })) ringArc.setAttribute(k, v);
    const ringBg = document.createElementNS(SVGNS, 'circle');
    for (const [k, v] of Object.entries({ cx: 70, cy: 70, r: R, fill: 'none', 'stroke-width': 12, class: 'ring-bg' })) ringBg.setAttribute(k, v);
    const ring = document.createElementNS(SVGNS, 'svg'); ring.setAttribute('viewBox', '0 0 140 140'); ring.setAttribute('class', 'ring'); ring.setAttribute('role', 'img'); ring.setAttribute('aria-label', 'Security score'); ring.append(ringBg, ringArc);
    const scoreNum = el('div', { class: 'score-num' }, '—'), scoreLbl = el('div', { class: 'score-lbl' }, 'Security score');
    const factorsBox = el('ul', { class: 'factors' });
    const tl = el('canvas', { role: 'img', 'aria-label': 'Alerts per hour over the last 24 hours' });
    const typesBox = el('div', { class: 'bars' }), atkBox = el('div', { class: 'atk' });
    function paintTimeline() {
      const c = tl, dpr = window.devicePixelRatio || 1, w = c.clientWidth, h = c.clientHeight; if (!w || !h) return;
      if (c.width !== w * dpr || c.height !== h * dpr) { c.width = w * dpr; c.height = h * dpr; }
      const g = c.getContext('2d'); g.setTransform(dpr, 0, 0, dpr, 0, 0); g.clearRect(0, 0, w, h);
      const data = (S.ins && S.ins.timeline) || [], max = Math.max(3, ...data.map((b) => b.critical + b.high + b.other)), bw = (w - 8) / 24, base = h - 20;
      g.font = '10px IBM Plex Mono, monospace'; g.fillStyle = '#a8a8a0'; g.textAlign = 'center';
      data.forEach((b, i) => {
        const x = 4 + i * bw + bw * 0.14, ww = bw * 0.72; let y = base;
        for (const [n, col] of [[b.other, '#A66BFF'], [b.high, '#C8792C'], [b.critical, '#ff5557']]) { const hh = (n / max) * (base - 6); if (hh) { g.fillStyle = col; g.fillRect(x, y - hh, ww, hh); y -= hh; } }
        if (!(b.critical + b.high + b.other)) { g.fillStyle = 'rgba(255,255,255,.08)'; g.fillRect(x, base - 2, ww, 2); }
        if (i % 6 === 0 || i === 23) { g.fillStyle = '#a8a8a0'; g.fillText(new Date(b.start).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false }), Math.min(w - 16, Math.max(16, x + ww / 2)), h - 5); }
      });
    }
    function paintInsights() {
      const I = S.ins; if (!I) return;
      const sc = I.score;
      scoreNum.textContent = sc == null ? '—' : String(sc);
      const tone = sc == null ? 'idle' : sc >= 85 ? 'good' : sc >= 60 ? 'mid' : 'bad';
      ring.dataset.tone = tone; scoreNum.dataset.tone = tone;
      ringArc.setAttribute('stroke-dasharray', `${((sc || 0) / 100) * CIRC} ${CIRC}`);
      scoreLbl.textContent = sc == null ? 'Add a device to get a score' : sc >= 85 ? 'Well protected' : sc >= 60 ? 'Needs attention' : 'At risk';
      factorsBox.replaceChildren(...(I.factors.length ? I.factors.map((f) => el('li', {}, el('strong', {}, '−' + f.points + ' '), f.label, el('span', { class: 'muted' }, ' — ' + f.fix))) : [el('li', { class: 'muted' }, sc == null ? 'Protect a device to see how safe you are.' : 'Nothing to fix. Everything looks healthy.')]));
      const mx = Math.max(1, ...I.by_type.map((t) => t.c));
      typesBox.replaceChildren(...(I.by_type.length ? I.by_type.map((t) => el('div', { class: 'bar' }, el('span', { class: 'bl' }, typeLabel(t.type)), el('span', { class: 'bt' }, el('i', { style: `width:${Math.max(4, (t.c / mx) * 100)}%` })), el('span', { class: 'bn' }, t.c))) : [el('p', { class: 'empty' }, 'No attacks in the last 7 days.')]));
      atkBox.replaceChildren(...(I.attackers.length ? I.attackers.map((a) => el('div', { class: 'atk-row' },
        el('div', {}, el('div', { class: 'mono ip' }, a.ip), el('div', { class: 'muted small' }, a.types.map(typeLabel).join(', ') + ' · ' + a.alerts + ' alert' + (a.alerts === 1 ? '' : 's') + ' · ' + ago(a.last))),
        a.blocked ? el('span', { class: 'pill ok' }, 'Blocked') : el('button', { class: 'btn sm danger', onclick: async () => { try { await api('POST', '/api/blocks', { ip: a.ip, reason: 'Blocked from top attackers' }); toast('Blocked ' + a.ip); loadInsights(); } catch (e) { toast(e.message, true); } } }, 'Block'))) : [el('p', { class: 'empty' }, 'No attackers seen yet. That is good news.')]));
      paintTimeline();
    }
    current.insights = paintInsights;
    const prevCl = current.cleanup; current.cleanup = () => { prevCl(); window.removeEventListener('resize', paintTimeline); }; window.addEventListener('resize', paintTimeline);
    loadInsights();
    // ---- live threat radar: every attacker seen this week is a blip; blocked ones are neutralised
    const radar = el('canvas', { role: 'img', 'aria-label': 'Radar showing attackers around your network' });
    let alive = true, t0 = performance.now();
    const hashN = (str, salt) => { let h = 2166136261 ^ salt; for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 16777619); } return ((h >>> 0) % 10000) / 10000; };
    const reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    function drawRadar(now) {
      if (!alive) return;
      const dpr = window.devicePixelRatio || 1, w = radar.clientWidth, h = radar.clientHeight;
      if (w && h) {
        if (radar.width !== w * dpr || radar.height !== h * dpr) { radar.width = w * dpr; radar.height = h * dpr; }
        const g = radar.getContext('2d'); g.setTransform(dpr, 0, 0, dpr, 0, 0); g.clearRect(0, 0, w, h);
        const cx = w / 2, cy = h / 2, R = Math.min(w, h) / 2 - 8, ang = reduce ? 0 : ((now - t0) / 4200) * Math.PI * 2;
        g.strokeStyle = 'rgba(166,107,255,.35)'; g.lineWidth = 1;
        for (let i = 1; i <= 4; i++) { g.beginPath(); g.arc(cx, cy, (R / 4) * i, 0, 7); g.stroke(); }
        g.beginPath(); g.moveTo(cx - R, cy); g.lineTo(cx + R, cy); g.moveTo(cx, cy - R); g.lineTo(cx, cy + R); g.stroke();
        if (!reduce) { const gr = g.createConicGradient ? g.createConicGradient(ang - 1.1, cx, cy) : null; if (gr) { gr.addColorStop(0, 'rgba(255,242,26,0)'); gr.addColorStop(0.17, 'rgba(255,242,26,.38)'); gr.addColorStop(0.1750, 'rgba(255,242,26,0)'); g.fillStyle = gr; g.beginPath(); g.arc(cx, cy, R, 0, 7); g.fill(); } g.strokeStyle = 'rgba(255,242,26,.9)'; g.lineWidth = 2; g.beginPath(); g.moveTo(cx, cy); g.lineTo(cx + Math.cos(ang) * R, cy + Math.sin(ang) * R); g.stroke(); }
        g.fillStyle = '#FFF21A'; g.beginPath(); g.arc(cx, cy, 6, 0, 7); g.fill(); g.strokeStyle = 'rgba(255,242,26,.5)'; g.lineWidth = 2; g.beginPath(); g.arc(cx, cy, 10 + (reduce ? 0 : (Math.sin(now / 400) + 1) * 3), 0, 7); g.stroke();
        const A = (S.ins && S.ins.attackers) || [];
        for (const a of A) {
          const th = hashN(a.ip, 1) * Math.PI * 2, rr = (0.3 + hashN(a.ip, 2) * 0.62) * R, x = cx + Math.cos(th) * rr, y = cy + Math.sin(th) * rr;
          const lit = reduce ? 1 : Math.max(0.35, 1 - ((((ang - th) % (Math.PI * 2)) + Math.PI * 2) % (Math.PI * 2)) / (Math.PI * 2));
          if (a.blocked) { g.strokeStyle = '#FFF21A'; g.lineWidth = 2; g.beginPath(); g.moveTo(x - 6, y - 6); g.lineTo(x + 6, y + 6); g.moveTo(x + 6, y - 6); g.lineTo(x - 6, y + 6); g.stroke(); g.fillStyle = 'rgba(255,242,26,.85)'; g.font = '10px IBM Plex Mono, monospace'; g.textAlign = 'center'; g.fillText(a.ip, x, y + 20); }
          else { g.fillStyle = `rgba(255,85,87,${lit})`; g.beginPath(); g.arc(x, y, 6 + (reduce ? 0 : Math.sin(now / 200) * 1.5), 0, 7); g.fill(); g.fillStyle = '#ffd0d0'; g.font = '10px IBM Plex Mono, monospace'; g.textAlign = 'center'; g.fillText(a.ip, x, y + 20); }
        }
      }
      requestAnimationFrame(drawRadar);
    }
    requestAnimationFrame(drawRadar);
    const prevCl2 = current.cleanup; current.cleanup = () => { alive = false; prevCl2(); };
    const lockBtn = el('button', { class: 'btn lock', type: 'button', 'aria-pressed': 'false' }, 'Lockdown: …');
    const paintLock = async () => { const on = await getLockdown(); lockBtn.setAttribute('aria-pressed', String(on)); lockBtn.textContent = on ? 'Lockdown: ON' : 'Lockdown: OFF'; };
    lockBtn.onclick = async () => { lockBtn.disabled = true; try { await setLockdown(lockBtn.getAttribute('aria-pressed') !== 'true'); } catch (e) { toast(e.message, true); } lockBtn.disabled = false; paintLock(); };
    paintLock();
    const radarRow = el('section', { class: 'panel pad radar-panel' },
      el('div', { class: 'head' }, el('h2', {}, 'Threat radar'), el('span', { class: 'meta' }, lockBtn)),
      el('div', { class: 'radarbox' }, radar),
      el('p', { class: 'foot', style: 'margin-top:8px' }, 'Red = active attacker · Lemon X = neutralised · Lockdown = max sensitivity + auto-block · Press Ctrl+K for commands'));
    const insightsRow = el('div', { class: 'insights' },
      el('section', { class: 'panel pad score' }, el('div', { class: 'head' }, el('h2', {}, 'Security score')),
        el('div', { class: 'score-wrap' }, el('div', { class: 'ring-box' }, ring, el('div', { class: 'ring-in' }, scoreNum, scoreLbl)), factorsBox)),
      el('section', { class: 'panel pad' }, el('div', { class: 'head' }, el('h2', {}, 'Last 24 hours'), el('span', { class: 'meta legend' }, el('i', { class: 'sw crit' }), 'critical', el('i', { class: 'sw amb' }), 'high', el('i', { class: 'sw lav' }), 'other')), el('div', { class: 'tlbox' }, tl),
        el('div', { class: 'head', style: 'margin-top:14px' }, el('h2', {}, 'Attack types · 7 days')), typesBox),
      el('section', { class: 'panel pad' }, el('div', { class: 'head' }, el('h2', {}, 'Top attackers'), el('span', { class: 'meta' }, '7 days')), atkBox));
    return el('section', { class: 'view grid' },
      loadingBox, prot.node, statsNote, empty, banner, kpis,
      chartRow, radarRow, insightsRow,
      el('p', { class: 'foot' }, 'Dashed line = anomaly threshold learned from this device\'s own normal traffic'));
  }

  // ------------------------------------------------------------------ devices
  function devicesView() {
    const list = el('div', {});
    const keyArea = el('div', {});
    const nameIn = el('input', { type: 'text', maxlength: 60, placeholder: 'e.g. Web server, Plant gateway' });
    const origin = location.origin;
    function installBox(key, isNew = true) {
      const k = key || 'YOUR_API_KEY';
      const cmd = (extra) => `curl -fsSL ${origin}/agent/netguard_agent.py -o netguard_agent.py\npip install psutil\n${extra}`;
      const shown = el('div', { class: 'codeblock', id: 'keyShown' }, key ? key.slice(0, 6) + '•'.repeat(24) + key.slice(-3) : 'Keys are stored hashed, so an old key cannot be shown again. Use "New key" to make one.');
      let vis = false;
      const reveal = key ? el('button', { class: 'btn sm', type: 'button', onclick: (e) => { vis = !vis; shown.textContent = vis ? key : key.slice(0, 6) + '•'.repeat(24) + key.slice(-3); e.currentTarget.textContent = vis ? 'Hide key' : 'Reveal key'; } }, 'Reveal key') : null;
      const copyKey = key ? codeBlock(key).querySelector('button') : null;
      if (copyKey) copyKey.onclick = async () => { try { await navigator.clipboard.writeText(key); copyKey.textContent = 'Copied'; } catch { copyKey.textContent = 'Reveal then copy'; } setTimeout(() => { copyKey.textContent = 'Copy key'; }, 1800); };
      if (copyKey) copyKey.textContent = 'Copy key';
      return el('div', { class: 'keybox' },
        el('strong', {}, key && isNew ? 'Copy your API key now. It is hidden by default and shown only once.' : 'Install commands (replace YOUR_API_KEY with the key you saved, or press "New key")'),
        el('div', { class: 'codewrap' }, shown, el('div', { class: 'inline' }, reveal, copyKey)),
        el('p', { class: 'muted', 'data-tone': 'ok' }, 'New devices start in monitor-only (dry run) mode: NetGuard reports what it WOULD block but blocks nothing. Switch the device to live blocking on this page when you are ready.'),
        el('p', {}, el('strong', {}, 'Linux server or PC (easiest): one command.'), ' It installs the agent as a service that starts on boot.'),
        codeBlock(`curl -fsSL ${origin}/install.sh | sudo NETGUARD_KEY=${k} bash`),
        el('p', { class: 'muted' }, 'Linux / macOS by hand. Add --enforce to let NetGuard block attackers in the firewall (needs root); --sniff enables the packet sniffer (Linux, root).'),
        codeBlock(cmd(`sudo python3 netguard_agent.py --server ${origin} --key ${k} --enforce --sniff`)),
        el('p', { class: 'muted' }, 'Windows (PowerShell as Administrator):'),
        codeBlock(`Invoke-WebRequest ${origin}/agent/netguard_agent.py -OutFile netguard_agent.py\npip install psutil\npython netguard_agent.py --server ${origin} --key ${k} --enforce`),
        origin.startsWith('http://') && !/localhost|127\.0\.0\.1/.test(origin) ? el('p', { class: 'muted', 'data-tone': 'warn' }, 'This server is on plain http. Put it behind https before using it on the internet.') : null);
    }
    function paint() {
      if (!S.devices.length) { list.replaceChildren(stateBox('empty', 'No devices yet. Add one above.')); return; }
      list.replaceChildren(...S.devices.map((d) => {
        const live = S.live[d.id] || {};
        return el('div', { class: 'devrow' },
          el('div', {}, el('div', { class: 'n' }, el('i', { class: 'led ' + (d.status === 'online' ? 'on' : d.status === 'offline' ? 'off' : 'wait') }), d.name, d.virtual ? demoTag('Demo · simulated') : null),
            el('div', { class: 'muted mono' }, `${d.hostname || 'waiting for agent'} · ${d.os || ''}`)),
          el('div', {}, el('div', { class: 'k' }, 'Status'), d.status + (d.virtual ? '' : d.mode === 'monitor' ? ' · monitor-only (dry run)' : d.enforce ? ' · live blocking' : d.status === 'online' ? ' · agent monitor-only' : '')),
          el('div', {}, el('div', { class: 'k' }, 'Traffic'), live.pps != null ? live.pps.toLocaleString() + ' pkt/s' : '—'),
          el('div', {}, el('div', { class: 'k' }, 'Last seen'), ago(d.last_seen)),
          el('div', { class: 'inline' }, [
            d.virtual ? null : el('button', { class: 'btn sm' + (d.mode === 'monitor' ? ' primary' : ''), onclick: async () => {
              const toLive = d.mode === 'monitor';
              if (toLive && !confirm(`Turn on LIVE blocking for ${d.name}?\n\nNetGuard will block attacker IPs in this device's firewall (only if its agent runs with --enforce). Your own devices, gateway and allowlist are never blocked. You can switch back any time.`)) return;
              try { await api('PATCH', `/api/devices/${d.id}/mode`, toLive ? { mode: 'live', confirm: true } : { mode: 'monitor' }); await loadDevices(); await refreshStats(); paint(); toast(toLive ? 'Live blocking on' : 'Back to monitor-only'); } catch (e) { toast(e.message, true); }
            } }, d.mode === 'monitor' ? 'Enable live blocking' : 'Back to monitor-only'),
            d.virtual ? null : el('button', { class: 'btn sm', onclick: () => keyArea.replaceChildren(installBox(null, false)) }, 'Install commands'),
            d.virtual ? null : el('button', { class: 'btn sm', onclick: async () => { const n = prompt('New name for this device', d.name); if (n == null || !n.trim()) return; try { await api('PATCH', `/api/devices/${d.id}`, { name: n }); await loadDevices(); paint(); toast('Renamed'); } catch (e) { toast(e.message, true); } } }, 'Rename'),
            el('button', { class: 'btn sm', onclick: async () => { if (!confirm('Rotate the API key? The agent stops working until you update it.')) return; const r = await api('POST', `/api/devices/${d.id}/rotate-key`, {}); keyArea.replaceChildren(installBox(r.api_key)); } }, 'New key'),
            el('button', { class: 'btn sm danger', onclick: async () => { if (!confirm(`Delete ${d.name}? Its history stays in alerts, but the agent will stop being accepted.`)) return; await api('DELETE', `/api/devices/${d.id}`); await loadDevices(); paint(); } }, 'Delete')]));
      }));
    }
    current = { refresh: paint, tick: paint };
    loadDevices().then(paint);
    return el('section', { class: 'view grid' },
      el('div', { class: 'panel pad' }, el('div', { class: 'head' }, el('h2', {}, 'Add a device')),
        el('div', { class: 'inline' }, el('label', {}, 'Device name', nameIn),
          el('button', { class: 'btn primary', onclick: async () => {
            try { const r = await api('POST', '/api/devices', { name: nameIn.value }); nameIn.value = ''; keyArea.replaceChildren(installBox(r.api_key)); await loadDevices(); paint(); } catch (e) { toast(e.message, true); }
          } }, 'Create + get install command')), keyArea),
      el('div', { class: 'panel pad' }, el('div', { class: 'head' }, el('h2', {}, 'Your devices')), list));
  }

  // ------------------------------------------------------------------ alerts
  function alertsView() {
    const body = el('tbody', {});
    let filter = 'all';
    const sel = el('select', { 'aria-label': 'Filter', onchange: (e) => { filter = e.target.value; paint(); } },
      ['all', 'open', 'ack', 'resolved'].map((v) => el('option', { value: v }, v === 'all' ? 'All alerts' : v === 'ack' ? 'Acknowledged' : v[0].toUpperCase() + v.slice(1))));
    const act = async (fn) => { try { await fn(); await loadAlerts(); await refreshStats(); paint(); } catch (e) { toast(e.message, true); } };
    function paint() {
      const cell = (node) => { body.replaceChildren(el('tr', {}, el('td', { colspan: 7 }, node))); };
      if (S.alertsState === 'loading') return cell(stateBox('loading', 'Loading alerts…'));
      if (S.alertsState === 'error') return cell(stateBox('error', 'Could not load alerts.', () => { S.alertsState = 'loading'; paint(); loadAlerts().then(paint); }));
      const rows = S.alerts.filter((a) => filter === 'all' || a.status === filter);
      if (!rows.length) return cell(stateBox('empty', S.alerts.length ? 'No alerts match this filter.' : 'No real alerts. Nothing suspicious has been seen on your devices. (Simulator alerts are on the Demo page, not here.)'));
      body.replaceChildren(...rows.flatMap((a) => {
        const tr = el('tr', { style: 'cursor:pointer', title: 'Click for full details', onclick: (e) => { if (e.target.closest('button')) return; openForensics(a, async () => { await loadAlerts(); await refreshStats(); paint(); }); } },
          el('td', { class: 'mono' }, fmtDT(a.created)), el('td', {}, el('span', { class: 'sev ' + a.severity }, a.severity)),
          el('td', {}, a.title, a.count > 1 ? el('span', { class: 'pill', style: 'margin-left:8px' }, '×' + a.count) : null, a.action ? el('div', { class: 'muted' }, a.action) : null),
          el('td', { class: 'mono' }, a.src_ip || '—'), el('td', {}, a.device_name || '—'), el('td', {}, a.status),
          el('td', {}, el('div', { class: 'inline' },
            a.status === 'open' ? el('button', { class: 'btn sm', onclick: () => act(() => api('PATCH', `/api/alerts/${a.id}`, { status: 'ack' })) }, 'Ack') : null,
            a.status !== 'resolved' ? el('button', { class: 'btn sm', onclick: () => act(() => api('PATCH', `/api/alerts/${a.id}`, { status: 'resolved' })) }, 'Resolve') : null,
            a.src_ip && !/^(\[Demo\] )?Blocked/.test(a.action || '') ? el('button', { class: 'btn sm danger', onclick: () => act(async () => { await api('POST', `/api/alerts/${a.id}/block`, {}); toast('Blocked ' + a.src_ip); }) }, 'Block IP') : null)));
        const out = [tr];
        return out;
      }));
    }
    current = { refresh: paint, tick: null };
    S.alertsState = 'loading'; paint(); loadAlerts().then(paint);
    return el('section', { class: 'view panel pad' },
      el('div', { class: 'head' }, el('h2', {}, 'Alerts'), el('span', { class: 'meta' }, el('a', { class: 'btn sm', href: '/api/alerts.csv', download: 'netguard-alerts.csv', style: 'text-decoration:none;display:inline-flex;align-items:center' }, 'Export CSV'), sel)),
      el('div', { class: 'tablewrap' }, el('table', {}, el('thead', {}, el('tr', {}, ['Time', 'Severity', 'What happened', 'Source', 'Device', 'Status', ''].map((h) => el('th', {}, h)))), body)));
  }

  // ------------------------------------------------------------------ blocklist
  function blocksView() {
    const blocksBody = el('tbody', {}), allowBody = el('tbody', {}), info = el('p', { class: 'muted' });
    const ip = el('input', { type: 'text', placeholder: '203.0.113.50', inputmode: 'text' });
    const reason = el('input', { type: 'text', placeholder: 'Reason (optional)', maxlength: 200 });
    const aip = el('input', { type: 'text', placeholder: '198.51.100.7' }), anote = el('input', { type: 'text', placeholder: 'Note (optional)', maxlength: 100 });
    async function paint() {
      const [b, a] = await Promise.all([api('GET', '/api/blocks'), api('GET', '/api/allowlist')]);
      info.textContent = `${b.enforcing_devices} device${b.enforcing_devices === 1 ? '' : 's'} currently enforcing blocks in their firewall. Devices in monitor-only (dry run) mode raise alerts but do not block. This list shows real blocks only.`;
      blocksBody.replaceChildren(...(b.blocks.length ? b.blocks.map((x) => el('tr', {},
        el('td', { class: 'mono' }, x.ip), el('td', {}, x.reason), el('td', {}, x.source), el('td', {}, x.applied + ' / ' + b.enforcing_devices),
        el('td', {}, fmtDT(x.created)), el('td', {}, left(x.expires)),
        el('td', {}, el('button', { class: 'btn sm', onclick: async () => { await api('DELETE', `/api/blocks/${x.id}`); paint(); } }, 'Unblock')))) : [el('tr', {}, el('td', { colspan: 7, class: 'empty' }, 'Nothing blocked right now.'))]));
      allowBody.replaceChildren(...(a.length ? a.map((x) => el('tr', {}, el('td', { class: 'mono' }, x.ip), el('td', {}, x.note || ''),
        el('td', {}, el('button', { class: 'btn sm', onclick: async () => { await api('DELETE', `/api/allowlist/${x.id}`); paint(); } }, 'Remove')))) : [el('tr', {}, el('td', { colspan: 3, class: 'empty' }, 'Allowlist is empty.'))]));
    }
    current = { refresh: paint, tick: null };
    paint();
    const add = (path, body, clear) => async () => { try { const b = body(); const pr = b.ip !== undefined ? ipProblem(b.ip) : null; if (pr) { toast(pr, true); return; } await api('POST', path, b); clear.forEach((i) => { i.value = ''; }); paint(); } catch (e) { toast(e.message, true); } };
    return el('section', { class: 'view grid' },
      el('div', { class: 'panel pad rollback' }, el('div', { class: 'head' }, el('h2', {}, 'Made a mistake? How to undo')),
        el('ol', { class: 'muted', style: 'margin:0;padding-left:20px;display:grid;gap:4px' },
          el('li', {}, 'Click Unblock next to the IP below. It leaves the firewall of every device within seconds.'),
          el('li', {}, 'Add the IP to the Allowlist so it can never be blocked or flagged again.'),
          el('li', {}, 'Blocks expire on their own (see the Expires column). Change the time in Settings.'),
          el('li', {}, 'To stop all automatic blocking: Settings, untick "Block attackers automatically", Save. Or stop the agent on the device.'))),
      el('div', { class: 'panel pad' }, el('div', { class: 'head' }, el('h2', {}, 'Active blocks')), info,
        el('div', { class: 'inline', style: 'margin:12px 0' }, el('label', {}, 'IP address', ip), el('label', {}, 'Reason', reason),
          el('button', { class: 'btn primary', onclick: add('/api/blocks', () => ({ ip: ip.value, reason: reason.value }), [ip, reason]) }, 'Block IP')),
        el('div', { class: 'tablewrap' }, el('table', {}, el('thead', {}, el('tr', {}, ['IP', 'Reason', 'Source', 'Enforced on', 'Since', 'Expires', ''].map((h) => el('th', {}, h)))), blocksBody))),
      el('div', { class: 'panel pad' }, el('div', { class: 'head' }, el('h2', {}, 'Allowlist (never blocked or flagged)')),
        el('div', { class: 'inline', style: 'margin-bottom:12px' }, el('label', {}, 'IP address', aip), el('label', {}, 'Note', anote),
          el('button', { class: 'btn', onclick: add('/api/allowlist', () => ({ ip: aip.value, note: anote.value }), [aip, anote]) }, 'Add to allowlist')),
        el('div', { class: 'tablewrap' }, el('table', {}, el('thead', {}, el('tr', {}, ['IP', 'Note', ''].map((h) => el('th', {}, h)))), allowBody))));
  }

  // ------------------------------------------------------------------ settings
  function settingsView() {
    const f = el('form', { class: 'form' }), msg = el('p', { class: 'err' });
    const pwForm = el('form', { class: 'form' }), pmsg = el('p', { class: 'err' });
    (async () => {
      const s = await api('GET', '/api/settings');
      const num = (k, label, hint) => el('label', {}, label + (hint ? ` (${hint})` : ''), el('input', { type: 'number', name: k, value: s[k], min: 0 }));
      f.append(
        el('label', { class: 'check' }, el('input', { type: 'checkbox', name: 'auto_block', checked: s.auto_block }), 'Block attackers automatically'),
        el('p', { class: 'muted small' }, 'Off by default for new accounts. Turning it on asks you to confirm. New devices stay in monitor-only (dry run) mode until you enable live blocking on the Devices page.'),
        el('label', {}, 'Block scope', el('select', { name: 'block_scope' }, [['fleet', 'All my devices'], ['device', 'Only the attacked device']].map(([v, t]) => el('option', { value: v, selected: s.block_scope === v }, t)))),
        num('block_ttl_min', 'Unblock after', 'minutes, 0 = never'),
        el('label', {}, 'Sensitivity', el('select', { name: 'sensitivity' }, [['low', 'Low (fewer alerts)'], ['medium', 'Medium'], ['high', 'High (more alerts)']].map(([v, t]) => el('option', { value: v, selected: s.sensitivity === v }, t)))),
        num('learn_samples', 'Learning samples', '~2 s each'),
        num('src_pps_limit', 'Flood limit per source', 'packets/s'), num('conn_limit', 'Connection limit per source'),
        num('port_scan_ports', 'Port-scan threshold', 'distinct ports in 30 s'), num('brute_force_attempts', 'Brute-force threshold', 'failed logins in 60 s'),
        el('label', {}, 'Alert webhook URL (Slack, Discord or any JSON endpoint)', el('input', { type: 'url', name: 'webhook_url', value: s.webhook_url, placeholder: 'https://hooks.slack.com/services/…' })),
        msg,
        el('div', { class: 'inline' },
          el('button', { class: 'btn primary', type: 'submit' }, 'Save settings'),
          el('button', { class: 'btn', type: 'button', onclick: async () => { try { await api('POST', '/api/settings/test-webhook', {}); toast('Test sent'); } catch (e) { toast(e.message, true); } } }, 'Send test notification')));
    })();
    f.onsubmit = async (e) => {
      e.preventDefault(); msg.textContent = '';
      const fd = new FormData(f), body = {};
      for (const [k, v] of fd.entries()) body[k] = ['webhook_url', 'block_scope', 'sensitivity'].includes(k) ? v : Number(v);
      body.auto_block = f.elements.auto_block.checked;
      try {
        try { await api('PUT', '/api/settings', body); }
        catch (x) {
          if (!/^Confirmation needed/.test(x.message)) throw x;
          const lock = body.auto_block && body.sensitivity === 'high';
          if (!confirm((lock ? 'LOCKDOWN: maximum sensitivity with automatic blocking.\n\n' : 'Turn on automatic blocking' + (body.block_scope === 'fleet' ? ' on ALL your devices' : '') + '?\n\n') +
            'NetGuard will block attacker IPs by itself, for ' + (body.block_ttl_min ? body.block_ttl_min + ' minutes' : 'ever') + ' each. A wrong block can cut off a real visitor. Your own devices, gateway and allowlist are never blocked, and you can undo any block on the Blocklist page.\n\nDevices still in monitor-only (dry run) mode will not block until you switch them to live.')) { msg.textContent = 'Not saved. Automatic blocking stays as it was.'; return; }
          await api('PUT', '/api/settings', { ...body, confirm_broad: true });
        }
        toast('Settings saved'); refreshStats();
      } catch (x) { msg.textContent = x.message; }
    };
    const cur = el('input', { type: 'password', autocomplete: 'current-password' }), nw = el('input', { type: 'password', autocomplete: 'new-password', minlength: 8 });
    pwForm.append(el('label', {}, 'Current password', cur), el('label', {}, 'New password', nw), pmsg, el('button', { class: 'btn', type: 'submit' }, 'Change password'));
    pwForm.onsubmit = async (e) => { e.preventDefault(); pmsg.textContent = ''; try { await api('POST', '/api/auth/password', { current: cur.value, password: nw.value }); cur.value = nw.value = ''; toast('Password changed'); } catch (x) { pmsg.textContent = x.message; } };
    current = { refresh: null, tick: null };
    return el('section', { class: 'view grid' },
      el('div', { class: 'panel pad' }, el('div', { class: 'head' }, el('h2', {}, 'Detection & response')), f),
      el('div', { class: 'panel pad' }, el('div', { class: 'head' }, el('h2', {}, 'Account · ' + S.me.email)), pwForm));
  }

  // ------------------------------------------------------------------ lockdown mode + command palette
  async function getLockdown() { try { const c = await api('GET', '/api/settings'); return !!c.auto_block && c.sensitivity === 'high'; } catch { return false; } }
  async function setLockdown(on) {
    const cur = await api('GET', '/api/settings');
    if (on) {
      if (!confirm('Turn on LOCKDOWN?\n\nMaximum sensitivity plus automatic blocking' + (cur.block_scope === 'fleet' ? ' on all your devices' : '') + '. It may block legitimate visitors. Allowlisted IPs and your own devices are never blocked. You can turn it off any time, and every block can be undone on the Blocklist page.')) return;
      try { localStorage.setItem('ng_prev_sens', cur.sensitivity); } catch { /* ignore */ } await api('PUT', '/api/settings', { auto_block: true, sensitivity: 'high', confirm_broad: true }); toast('Lockdown ON: maximum sensitivity, automatic blocking'); }
    else { let prev = 'medium'; try { prev = localStorage.getItem('ng_prev_sens') || 'medium'; } catch { /* ignore */ } await api('PUT', '/api/settings', { sensitivity: prev === 'high' ? 'medium' : prev }); toast('Lockdown off: sensitivity restored'); }
    loadInsights(); refreshStats();
  }
  const THEMES = { lemon: ['#FFF21A', 'rgba(255,242,26,.13)', '#171717'], lavender: ['#A66BFF', 'rgba(166,107,255,.18)', '#171717'], amber: ['#C8792C', 'rgba(200,121,44,.2)', '#171717'], ice: ['#5ee7ff', 'rgba(94,231,255,.14)', '#04141c'] };
  function applyTheme(name) {
    const t = THEMES[name] || THEMES.lemon, r = document.documentElement.style;
    r.setProperty('--accent', t[0]); r.setProperty('--accent-fill', t[1]);
    try { localStorage.setItem('ng_theme', name); } catch { /* ignore */ }
  }
  try { applyTheme(localStorage.getItem('ng_theme') || 'lemon'); } catch { /* ignore */ }
  let palette = null;
  function openPalette() {
    if (palette || !S.me) return;
    const input = el('input', { type: 'text', placeholder: 'Type a command or page…', 'aria-label': 'Command' });
    const list = el('div', { class: 'cmd-list', role: 'listbox' });
    const go = (h) => () => { location.hash = h; };
    const cmds = [
      ...navItems().map(([k, l]) => ({ t: 'Go to ' + l, run: go('#/' + k) })),
      ...Object.keys(THEMES).map((k) => ({ t: 'Theme: ' + k[0].toUpperCase() + k.slice(1), run: () => { applyTheme(k); toast('Theme: ' + k); } })),
      { t: 'Turn lockdown mode on', run: () => setLockdown(true) }, { t: 'Turn lockdown mode off', run: () => setLockdown(false) },
      ...[['both', 'English + தமிழ்'], ['en', 'English only'], ['ta', 'தமிழ் only']].map(([k, l]) => ({ t: 'Alert voice: ' + l, run: () => { try { localStorage.setItem('ng_voice', k); } catch { /* ignore */ } speakAlert({ severity: 'high', type: 'port_scan', src_ip: '203.0.113.5', action: 'Blocked' }); toast('Alert voice: ' + l); } })),
      { t: 'Toggle alarm sound', run: () => { try { localStorage.setItem('ng_sound', soundOn() ? '0' : '1'); } catch { /* ignore */ } toast('Sound ' + (soundOn() ? 'on' : 'off')); route(); } },
      { t: 'Print incident report', run: () => { location.hash = '#/report'; setTimeout(() => window.print(), 600); } },
      { t: 'Sign out', run: async () => { await api('POST', '/api/auth/logout', {}); closeStream(); S.me = null; route(); } },
    ];
    let shown = cmds, idx = 0;
    const close = () => { palette.remove(); palette = null; document.removeEventListener('keydown', onKey, true); };
    const paint = () => list.replaceChildren(...(shown.length ? shown.map((c, i) => el('button', { type: 'button', class: 'cmd' + (i === idx ? ' on' : ''), role: 'option', onclick: () => { close(); c.run(); } }, c.t)) : [el('p', { class: 'empty' }, 'No match')]));
    function onKey(e) {
      if (e.key === 'Escape') { close(); } else if (e.key === 'ArrowDown') { e.preventDefault(); idx = Math.min(shown.length - 1, idx + 1); paint(); } else if (e.key === 'ArrowUp') { e.preventDefault(); idx = Math.max(0, idx - 1); paint(); }
      else if (e.key === 'Enter' && shown[idx]) { e.preventDefault(); const c = shown[idx]; close(); c.run(); }
    }
    input.addEventListener('input', () => { const q = input.value.toLowerCase(); shown = cmds.filter((c) => c.t.toLowerCase().includes(q)); idx = 0; paint(); });
    palette = el('div', { class: 'palette', onclick: (e) => { if (e.target === palette) close(); } }, el('div', { class: 'palette-box' }, input, list, el('p', { class: 'muted small' }, 'Enter to run · Esc to close')));
    document.body.append(palette); document.addEventListener('keydown', onKey, true); paint(); input.focus();
  }
  document.addEventListener('keydown', (e) => { if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); palette ? palette.querySelector('input').blur() : openPalette(); } });

  // ------------------------------------------------------------------ copilot (rule-based assistant, answers from your own data)
  function copilotView() {
    const getLang = () => { try { return localStorage.getItem('ng_lang') || 'both'; } catch { return 'both'; } };
    const UI = {
      en: { hello: 'Hi, I am NetGuard Copilot. Ask me anything about your security, by typing or by pressing Talk. I can explain attacks, check an IP, and block it or turn on lockdown when you confirm.', ph: 'Ask anything: "Is my network safe?", "What is a port scan?", "block 203.0.113.5"…', ask: 'Ask', you: 'You', bot: 'NetGuard Copilot', label: 'Your question', chips: ['Am I safe?', 'What happened today?', 'Who is attacking me?', 'What should I do?', 'What is a port scan?', 'How do I add a device?', 'lockdown on'], read: 'Read answers aloud', talk: 'Talk', stop: 'Stop talking' },
      ta: { hello: 'வணக்கம்! நான் NetGuard Copilot. உங்கள் பாதுகாப்பு பற்றி எதையும் கேளுங்கள், தட்டச்சு செய்தோ "பேசு" பொத்தானை அழுத்தியோ. தாக்குதல்களை விளக்குவேன், IP-ஐச் சரிபார்ப்பேன், நீங்கள் உறுதிப்படுத்தினால் தடுக்கவோ lockdown இயக்கவோ செய்வேன்.', ph: 'எதையும் கேளுங்கள்: "என் நெட்வொர்க் பாதுகாப்பாக உள்ளதா?", "போர்ட் ஸ்கேன் என்றால் என்ன?"…', ask: 'கேள்', you: 'நீங்கள்', bot: 'NetGuard Copilot', label: 'உங்கள் கேள்வி', chips: ['நான் பாதுகாப்பாக இருக்கிறேனா?', 'இன்று என்ன நடந்தது?', 'என்னை யார் தாக்குகிறார்கள்?', 'நான் என்ன செய்ய வேண்டும்?', 'போர்ட் ஸ்கேன் என்றால் என்ன?', 'சாதனத்தை எப்படிச் சேர்ப்பது?', 'lockdown on'], read: 'பதில்களை உரக்கப் படி', talk: 'பேசு', stop: 'பேசுவதை நிறுத்து' },
    };
    const ui = () => UI[getLang() === 'ta' ? 'ta' : 'en'];
    const log = el('div', { class: 'chat', 'aria-live': 'polite' });
    const input = el('input', { type: 'text', maxlength: 400, 'aria-label': 'Ask Copilot' });
    if (S.copilotSeed) { input.value = S.copilotSeed; S.copilotSeed = null; }
    const chipsBox = el('div', { class: 'chips' }), askBtn = el('button', { class: 'btn primary', type: 'submit' }), labelTxt = el('span', {});
    const badge = el('span', { class: 'aibadge' }, '…');
    const basicCard = el('div', { class: 'basic-card', hidden: true, role: 'note' },
      el('strong', {}, 'Copilot is in Basic mode'),
      el('p', {}, 'The full AI is switched off because the server has no AI key (GEMINI_API_KEY) yet. Basic mode still works, using your own live data and fixed rules.'),
      el('div', { class: 'two' },
        el('div', {}, el('b', {}, 'Works now'), el('ul', {}, ['Security score and what is hurting it', 'Open alerts, top attackers, blocked IPs', 'Explaining attack types in plain words', 'IP checks, English and Tamil, voice in and out', 'Block an IP or lockdown (you confirm first)'].map((t) => el('li', {}, t)))),
        el('div', {}, el('b', {}, 'Needs the key'), el('ul', {}, ['Free-form questions outside the built-in topics', 'Follow-up questions that remember the conversation', 'Detailed step-by-step fixes for your setup'].map((t) => el('li', {}, t))))),
      el('p', { class: 'muted small' }, 'The key lives only on the server (a Render environment variable). It is never sent to your browser.'));
    const history = []; let readAloud = true, convo = false, rec = null, busy = false;
    api('GET', '/api/copilot/status').then((r) => { badge.textContent = r.ai ? 'AI: ' + (r.ai === 'gemini' ? 'Gemini' : 'Claude') : 'Basic mode'; badge.dataset.ai = r.ai ? '1' : '0'; badge.title = r.ai ? 'Real AI is on' : 'Add GEMINI_API_KEY on the server to turn on the full AI'; basicCard.hidden = !!r.ai; }).catch(() => { badge.textContent = 'Status unknown'; });
    // speak() resolves when the voice finishes, so the hands-free loop knows when to listen again
    const speak = (text, lang) => new Promise((resolve) => {
      try {
        if (!readAloud || !('speechSynthesis' in window)) return resolve();
        speechSynthesis.cancel();
        const parts = lang === 'both' ? text.split('\n\n') : [text], voices = speechSynthesis.getVoices();
        parts.forEach((t, i) => {
          const l = lang === 'both' ? (i === 0 ? 'en' : 'ta') : (lang === 'ta' || /[஀-௿]/.test(t) ? 'ta' : 'en');
          const u = new SpeechSynthesisUtterance(t); u.lang = l === 'ta' ? 'ta-IN' : 'en-IN';
          const v = voices.find((x) => x.lang && x.lang.toLowerCase().startsWith(l)); if (v) u.voice = v;
          if (i === parts.length - 1) { u.onend = resolve; u.onerror = resolve; }
          speechSynthesis.speak(u);
        });
        setTimeout(resolve, 45000);
      } catch { resolve(); }
    });
    const runAction = async (ac, btn) => {
      btn.disabled = true;
      try {
        if (ac.kind === 'block') { await api('POST', '/api/blocks', { ip: ac.ip, reason: 'Blocked from Copilot' }); toast('Blocked ' + ac.ip); }
        else if (ac.kind === 'trust') { await api('POST', '/api/allowlist', { ip: ac.ip, note: 'Added from Copilot' }); toast('Trusted ' + ac.ip); }
        else if (ac.kind === 'lockdown') { await setLockdown(ac.on); }
        btn.textContent = '✓ ' + btn.textContent; loadInsights();
      } catch (e) { toast(e.message, true); btn.disabled = false; }
    };
    const add = (who, text, extra = {}) => new Promise((done) => {
      const u = ui(), bubble = el('div', { class: 'msg ' + who }, el('span', { class: 'who' }, who === 'me' ? u.you : u.bot + (extra.ai ? ' · AI' : '')), el('p', {}, ''));
      log.append(bubble); log.scrollTop = log.scrollHeight;
      const p = bubble.querySelector('p');
      if (who === 'me') { p.textContent = text; return done(); }
      let i = 0; const step = Math.max(1, Math.round(text.length / 60));
      const iv = setInterval(() => {
        i += step; p.textContent = text.slice(0, i); log.scrollTop = log.scrollHeight;
        if (i >= text.length) {
          clearInterval(iv);
          (extra.actions || []).forEach((ac) => { const b = el('button', { class: 'btn sm ' + (ac.kind === 'block' || (ac.kind === 'lockdown' && ac.on) ? 'danger' : ''), type: 'button', style: 'margin:8px 8px 0 0' }, ac.label); b.onclick = () => runAction(ac, b); bubble.append(b); });
          (extra.links || []).forEach((l) => bubble.append(el('a', { class: 'btn sm', href: l.href, style: 'text-decoration:none;display:inline-flex;margin:8px 8px 0 0' }, l.label)));
          log.scrollTop = log.scrollHeight;
          speak(text, extra.lang).then(done);
        }
      }, 18);
    });
    async function ask(q) {
      q = q.trim(); if (!q || busy) return; busy = true; add('me', q); input.value = '';
      const thinking = el('div', { class: 'msg bot thinking' }, el('span', { class: 'dots' }, '● ● ●')); log.append(thinking); log.scrollTop = log.scrollHeight;
      try {
        const r = await api('POST', '/api/copilot', { question: q, lang: getLang(), history: history.slice(-6) });
        thinking.remove(); history.push({ role: 'user', text: q }, { role: 'bot', text: r.answer });
        if (r.ai) { badge.textContent = 'AI: ' + (r.ai === 'gemini' ? 'Gemini' : 'Claude'); badge.dataset.ai = '1'; }
        await add('bot', r.answer, r);
      } catch (e) { thinking.remove(); await add('bot', 'Sorry: ' + e.message); }
      busy = false;
      if (convo) listen();
    }
    function paintUi(first) {
      const u = ui(); input.placeholder = u.ph; askBtn.textContent = u.ask; labelTxt.textContent = u.label; talkBtn.textContent = convo ? '⏹ ' + u.stop : '🎙 ' + u.talk;
      chipsBox.replaceChildren(...(getLang() === 'both' ? [...UI.en.chips, ...UI.ta.chips.slice(0, 6)] : u.chips).map((q) => el('button', { class: 'chip', type: 'button', onclick: () => ask(q) }, q)));
      if (first) add('bot', getLang() === 'both' ? UI.en.hello + '\n\n' + UI.ta.hello : u.hello, { lang: getLang() });
    }
    // hands-free voice conversation: listen -> think -> speak -> listen again
    const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
    function listen() {
      if (!SR || !convo) return;
      try {
        rec = new SR(); const l = getLang();
        rec.lang = l === 'ta' ? 'ta-IN' : l === 'en' ? 'en-IN' : 'ta-IN'; // 'ta-IN' recognises Tamil and usually English words too
        rec.interimResults = false; rec.maxAlternatives = 1;
        talkBtn.classList.add('live');
        rec.onresult = (e) => { const t = e.results[0][0].transcript; input.value = t; ask(t); };
        rec.onerror = (e) => { talkBtn.classList.remove('live'); if (e.error === 'not-allowed' || e.error === 'service-not-allowed') { convo = false; paintUi(false); toast('Allow the microphone to talk to Copilot', true); } else if (convo && !busy) setTimeout(listen, 800); };
        rec.onend = () => { talkBtn.classList.remove('live'); if (convo && !busy && !speechSynthesis.speaking) setTimeout(listen, 500); };
        rec.start();
      } catch { convo = false; paintUi(false); }
    }
    const talkBtn = el('button', { class: 'btn talk', type: 'button', 'aria-label': 'Talk to Copilot' });
    talkBtn.onclick = () => {
      if (!SR) { toast('Voice input needs Chrome or Edge', true); return; }
      convo = !convo; if (!convo) { try { rec && rec.abort(); } catch { /* ignore */ } try { speechSynthesis.cancel(); } catch { /* ignore */ } talkBtn.classList.remove('live'); } else { readAloud = true; readChk.checked = true; listen(); }
      paintUi(false);
    };
    const langSel = el('select', { 'aria-label': 'Language', onchange: (e) => { try { localStorage.setItem('ng_lang', e.target.value); } catch { /* ignore */ } paintUi(false); } },
      el('option', { value: 'both' }, 'English + தமிழ்'), el('option', { value: 'auto' }, 'Auto'), el('option', { value: 'en' }, 'English'), el('option', { value: 'ta' }, 'தமிழ்'));
    langSel.value = getLang();
    const readChk = el('input', { type: 'checkbox', checked: true, onchange: (e) => { readAloud = e.target.checked; if (!readAloud && 'speechSynthesis' in window) speechSynthesis.cancel(); } });
    current = { cleanup: () => { convo = false; try { rec && rec.abort(); } catch { /* ignore */ } try { speechSynthesis.cancel(); } catch { /* ignore */ } } };
    paintUi(true);
    return el('section', { class: 'view grid' }, el('div', { class: 'panel pad copilot' },
      el('div', { class: 'head' }, el('h2', {}, 'AI Copilot'), el('span', { class: 'meta' }, badge, el('label', { class: 'check', style: 'margin:0 10px' }, readChk, ui().read), el('span', { style: 'margin-right:6px' }, 'Language'), langSel)),
      log, chipsBox,
      el('form', { class: 'inline', onsubmit: (e) => { e.preventDefault(); ask(input.value); } }, el('label', {}, labelTxt, input), talkBtn, askBtn)));
  }

  // ------------------------------------------------------------------ tools: IP inspector + threat hunt
  function toolsView() {
    const out = el('div', {}), hout = el('div', {});
    const ipIn = el('input', { type: 'text', placeholder: '203.0.113.50', 'aria-label': 'IP address' });
    const qIn = el('input', { type: 'text', placeholder: 'e.g. 10.0.4.23, brute, flood, blocked', 'aria-label': 'Search' });
    async function inspect(ip) {
      const pr = ipProblem(ip); if (pr) { out.replaceChildren(el('p', { class: 'err' }, pr)); return; }
      out.replaceChildren(el('p', { class: 'muted' }, 'Checking…'));
      try {
        const r = await api('GET', '/api/ip/' + encodeURIComponent(ip.trim()));
        const tone = r.blocked ? 'crit' : r.allowlisted ? 'ok' : r.alerts.length ? 'warn' : 'accent';
        out.replaceChildren(el('div', { class: 'verdict', 'data-tone': tone }, el('div', { class: 'mono ip' }, r.ip), el('p', {}, r.verdict)),
          el('div', { class: 'inline', style: 'margin:10px 0' },
            !r.blocked && !r.protected && !r.allowlisted ? el('button', { class: 'btn danger', onclick: async () => { try { await api('POST', '/api/blocks', { ip: r.ip, reason: 'Blocked from IP Inspector' }); toast('Blocked ' + r.ip); inspect(r.ip); } catch (e) { toast(e.message, true); } } }, 'Block this IP') : null,
            !r.allowlisted && !r.protected ? el('button', { class: 'btn', onclick: async () => { try { await api('POST', '/api/allowlist', { ip: r.ip, note: 'Added from IP Inspector' }); toast('Allowlisted'); inspect(r.ip); } catch (e) { toast(e.message, true); } } }, 'Trust this IP') : null),
          r.alerts.length ? el('div', { class: 'tablewrap' }, el('table', {}, el('thead', {}, el('tr', {}, ['When', 'Severity', 'What happened', 'Action'].map((h) => el('th', {}, h)))), el('tbody', {}, r.alerts.map((a) => el('tr', {}, el('td', { class: 'mono' }, fmtDT(a.created)), el('td', {}, el('span', { class: 'sev ' + a.severity }, a.severity)), el('td', {}, a.title), el('td', {}, a.action || '—')))))) : el('p', { class: 'muted' }, 'No history for this address.'));
      } catch (e) { out.replaceChildren(el('p', { class: 'err' }, e.message)); }
    }
    async function hunt(q) {
      hout.replaceChildren(el('p', { class: 'muted' }, 'Searching…'));
      try {
        const r = await api('GET', '/api/hunt?q=' + encodeURIComponent(q));
        hout.replaceChildren(
          el('h3', { class: 'sub' }, `Alerts (${r.alerts.length})`),
          r.alerts.length ? el('div', { class: 'tablewrap' }, el('table', {}, el('tbody', {}, r.alerts.map((a) => el('tr', {}, el('td', { class: 'mono' }, fmtDT(a.created)), el('td', {}, el('span', { class: 'sev ' + a.severity }, a.severity)), el('td', {}, a.title), el('td', { class: 'mono' }, a.src_ip || '—')))))) : el('p', { class: 'muted' }, 'No matching alerts.'),
          el('h3', { class: 'sub' }, `Log lines (${r.logs.length})`),
          r.logs.length ? el('div', { class: 'logs', style: 'height:auto;max-height:280px' }, r.logs.map((l) => el('div', { class: 'row ' + l.level }, el('span', { class: 't' }, fmtTime(l.ts)), el('span', { class: 'l' }, l.level), el('span', { class: 'm' }, l.msg)))) : el('p', { class: 'muted' }, 'No matching log lines.'));
      } catch (e) { hout.replaceChildren(el('p', { class: 'err' }, e.message)); }
    }
    const pre = (location.hash.match(/[?&]ip=([\w.:]+)/) || [])[1];
    if (pre) { ipIn.value = pre; setTimeout(() => inspect(pre), 0); }
    current = {};
    return el('section', { class: 'view grid' },
      el('div', { class: 'panel pad' }, el('div', { class: 'head' }, el('h2', {}, 'IP inspector')), el('p', { class: 'muted', style: 'margin-bottom:10px' }, 'Check any address against everything NetGuard has seen, then block or trust it in one click.'),
        el('form', { class: 'inline', onsubmit: (e) => { e.preventDefault(); inspect(ipIn.value); } }, el('label', {}, 'IP address', ipIn), el('button', { class: 'btn primary', type: 'submit' }, 'Inspect')), out),
      canaryPanel(), toolkitPanel(),
      el('div', { class: 'panel pad' }, el('div', { class: 'head' }, el('h2', {}, 'Threat hunt')), el('p', { class: 'muted', style: 'margin-bottom:10px' }, 'Search all alerts and logs by IP, attack type, device or any word.'),
        el('form', { class: 'inline', onsubmit: (e) => { e.preventDefault(); hunt(qIn.value); } }, el('label', {}, 'Search', qIn), el('button', { class: 'btn primary', type: 'submit' }, 'Hunt')), hout));
  }

  // ------------------------------------------------------------------ incident report (print to PDF)
  function reportView() {
    const body = el('div', { class: 'report-body' });
    current = {};
    const draw = () => {
      const I = S.ins;
      if (S.alertsState === 'error' || !I || !S.stats) {
        body.replaceChildren(stateBox('error', 'The report could not be built because live data failed to load.', load)); return;
      }
      const R = S.stats.real, total = I.timeline.reduce((a, b) => a + b.critical + b.high + b.other, 0);
      if (!R.devices && !R.alerts_total) {
        body.replaceChildren(stateBox('empty', 'Nothing to report yet. Add a real device on the Devices page. The report fills in as soon as your device sends data. Demo and simulator activity is never included here.'),
          el('a', { class: 'btn primary noprint', href: '#/devices', style: 'text-decoration:none;display:inline-flex;margin-top:12px' }, 'Add a device')); return;
      }
      const mx = Math.max(1, ...I.timeline.map((b) => b.critical + b.high + b.other));
      body.replaceChildren(
        el('p', { class: 'muted' }, `Real data only. ${R.devices} device${R.devices === 1 ? '' : 's'} (${R.online} online), ${R.alerts_total} alert${R.alerts_total === 1 ? '' : 's'} on record.`),
        el('div', { class: 'rep-grid' },
          el('div', { class: 'rep-stat' }, el('span', { class: 'k' }, 'Security score'), el('b', {}, I.score == null ? '—' : I.score + '/100')),
          el('div', { class: 'rep-stat' }, el('span', { class: 'k' }, 'Alerts, 24 h'), el('b', {}, R.alerts_24h)),
          el('div', { class: 'rep-stat' }, el('span', { class: 'k' }, 'Open alerts'), el('b', {}, R.open_alerts)),
          el('div', { class: 'rep-stat' }, el('span', { class: 'k' }, 'Currently blocked'), el('b', {}, R.active_blocks))),
        el('h3', { class: 'sub' }, 'Alerts per hour, last 24 hours'),
        total ? el('div', { class: 'rep-bars' }, I.timeline.map((b) => { const n = b.critical + b.high + b.other; return el('i', { style: `height:${Math.max(3, (n / mx) * 100)}%`, title: n + ' alerts', class: b.critical ? 'c' : b.high ? 'h' : '' }); })) : stateBox('empty', 'No alerts in the last 24 hours.'),
        el('h3', { class: 'sub' }, 'Top attackers'),
        I.attackers.length ? el('table', {}, el('thead', {}, el('tr', {}, ['IP', 'Attack types', 'Alerts', 'Last seen', 'Status'].map((h) => el('th', {}, h)))), el('tbody', {}, I.attackers.map((a) => el('tr', {}, el('td', { class: 'mono' }, a.ip), el('td', {}, a.types.map(typeLabel).join(', ')), el('td', {}, a.alerts), el('td', {}, ago(a.last)), el('td', {}, a.blocked ? 'Blocked' : 'Not blocked'))))) : stateBox('empty', 'No attackers seen in the last 7 days.'),
        el('h3', { class: 'sub' }, 'Recent alerts'),
        S.alerts.length ? el('table', {}, el('thead', {}, el('tr', {}, ['Time', 'Severity', 'What happened', 'Source', 'Action'].map((h) => el('th', {}, h)))), el('tbody', {}, S.alerts.slice(0, 20).map((a) => el('tr', {}, el('td', { class: 'mono' }, fmtDT(a.created)), el('td', {}, a.severity), el('td', {}, a.title), el('td', { class: 'mono' }, a.src_ip || '—'), el('td', {}, a.action || '—'))))) : stateBox('empty', 'No alerts recorded.'),
        el('h3', { class: 'sub' }, 'Recommendations'),
        el('ul', { class: 'recs' }, (I.factors.length ? I.factors : [{ fix: 'No action needed. Keep reviewing alerts weekly.' }]).map((f) => el('li', {}, f.fix))));
    };
    function load() {
      body.replaceChildren(stateBox('loading', 'Building your report…'));
      Promise.all([loadAlerts(), refreshStats(), api('GET', '/api/insights').then((i) => { S.ins = i; }).catch(() => { S.ins = null; })]).then(draw);
    }
    load();
    return el('section', { class: 'view panel pad report' },
      el('div', { class: 'head' }, el('h2', {}, 'Incident report'), el('span', { class: 'meta noprint' }, el('button', { class: 'btn primary sm', type: 'button', onclick: () => window.print() }, 'Print / save as PDF'))),
      el('p', { class: 'muted', style: 'margin-bottom:14px' }, 'Generated ' + new Date().toLocaleString() + ' for ' + S.me.email), body);
  }

  // ------------------------------------------------------------------ war room (full-screen mission control for the projector)
  function warRoomView() {
    const radar = el('canvas', { role: 'img', 'aria-label': 'Threat radar' }), feed = el('div', { class: 'wr-feed' });
    const big = (id, k) => el('div', { class: 'wr-k' }, el('span', { class: 'k' }, k), el('b', { id }, '—'));
    const clock = el('div', { class: 'wr-clock mono' });
    let alive = true; const t0 = performance.now();
    const hashN = (str, salt) => { let h = 2166136261 ^ salt; for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 16777619); } return ((h >>> 0) % 10000) / 10000; };
    function draw(now) {
      if (!alive) return;
      const dpr = window.devicePixelRatio || 1, w = radar.clientWidth, h = radar.clientHeight;
      if (w && h) {
        if (radar.width !== w * dpr || radar.height !== h * dpr) { radar.width = w * dpr; radar.height = h * dpr; }
        const g = radar.getContext('2d'); g.setTransform(dpr, 0, 0, dpr, 0, 0); g.clearRect(0, 0, w, h);
        const cx = w / 2, cy = h / 2, R = Math.min(w, h) / 2 - 12, ang = ((now - t0) / 3600) * Math.PI * 2;
        g.lineWidth = 1; g.strokeStyle = 'rgba(166,107,255,.45)';
        for (let i = 1; i <= 5; i++) { g.beginPath(); g.arc(cx, cy, (R / 5) * i, 0, 7); g.stroke(); }
        for (let i = 0; i < 12; i++) { g.beginPath(); g.moveTo(cx, cy); g.lineTo(cx + Math.cos(i * Math.PI / 6) * R, cy + Math.sin(i * Math.PI / 6) * R); g.stroke(); }
        if (g.createConicGradient) { const gr = g.createConicGradient(ang - 1.2, cx, cy); gr.addColorStop(0, 'rgba(255,242,26,0)'); gr.addColorStop(0.19, 'rgba(255,242,26,.42)'); gr.addColorStop(0.191, 'rgba(255,242,26,0)'); g.fillStyle = gr; g.beginPath(); g.arc(cx, cy, R, 0, 7); g.fill(); }
        g.strokeStyle = '#FFF21A'; g.lineWidth = 2.5; g.beginPath(); g.moveTo(cx, cy); g.lineTo(cx + Math.cos(ang) * R, cy + Math.sin(ang) * R); g.stroke();
        g.fillStyle = '#FFF21A'; g.beginPath(); g.arc(cx, cy, 8, 0, 7); g.fill();
        for (const a of (S.ins && S.ins.attackers) || []) {
          const th = hashN(a.ip, 1) * Math.PI * 2, rr = (0.25 + hashN(a.ip, 2) * 0.68) * R, x = cx + Math.cos(th) * rr, y = cy + Math.sin(th) * rr;
          g.font = '12px IBM Plex Mono, monospace'; g.textAlign = 'center';
          if (a.blocked) { g.strokeStyle = '#FFF21A'; g.lineWidth = 3; g.beginPath(); g.moveTo(x - 8, y - 8); g.lineTo(x + 8, y + 8); g.moveTo(x + 8, y - 8); g.lineTo(x - 8, y + 8); g.stroke(); g.fillStyle = '#FFF21A'; }
          else { const p = (Math.sin(now / 180) + 1) / 2; g.fillStyle = 'rgba(255,85,87,.35)'; g.beginPath(); g.arc(x, y, 12 + p * 10, 0, 7); g.fill(); g.fillStyle = '#ff5557'; g.beginPath(); g.arc(x, y, 8, 0, 7); g.fill(); g.fillStyle = '#ffd0d0'; }
          g.fillText(a.ip, x, y + 26);
        }
      }
      requestAnimationFrame(draw);
    }
    requestAnimationFrame(draw);
    function paint() {
      const set = (id, v) => { const n = document.getElementById(id); if (n) n.textContent = v; };
      const I = S.ins; set('wScore', I && I.score != null ? I.score : '—'); set('wBlocked', num('active_blocks')); set('wOpen', num('open_alerts'));
      set('wAtk', I ? I.attackers.filter((a) => !a.blocked).length : '—');
      clock.textContent = new Date().toLocaleTimeString([], { hour12: false });
      feed.replaceChildren(...S.logs.slice(-14).reverse().map((l) => el('div', { class: 'row ' + l.level }, el('span', { class: 't' }, fmtTime(l.ts)), el('span', { class: 'l' }, l.level), el('span', { class: 'm' }, l.msg))));
      document.getElementById('glow').className = S.banner && !S.banner.good ? 'on' : '';
    }
    const iv = setInterval(paint, 1000); const iv2 = setInterval(loadInsights, 8000);
    current = { tick: paint, logTick: paint, refresh: paint, cleanup: () => { alive = false; clearInterval(iv); clearInterval(iv2); document.getElementById('glow').className = ''; } };
    (async () => { await Promise.all([loadAlerts(), refreshStats(), loadInsights()]); if (!S.logs.length) S.logs = await api('GET', '/api/logs?limit=30'); paint(); })();
    const fs = el('button', { class: 'btn sm', type: 'button', onclick: () => { document.fullscreenElement ? document.exitFullscreen() : document.documentElement.requestFullscreen && document.documentElement.requestFullscreen(); } }, 'Full screen');
    return el('section', { class: 'view wr' },
      el('div', { class: 'wr-top' }, el('h2', {}, 'NetGuard war room ', el('small', { class: 'muted' }, 'real data only')), el('span', { class: 'meta' }, clock, fs)),
      el('div', { class: 'wr-main' }, el('div', { class: 'panel wr-radar' }, radar), el('div', { class: 'wr-side' }, big('wScore', 'Security score'), big('wAtk', 'Active attackers'), big('wBlocked', 'Blocked now'), big('wOpen', 'Open alerts'))),
      el('div', { class: 'panel pad' }, el('div', { class: 'head' }, el('h2', {}, 'Live feed'), el('span', { class: 'meta' }, el('i', { class: 'led on' }), 'streaming')), feed));
  }

  // ------------------------------------------------------------------ canary traps + security toolkit (used by the Tools page)
  function canaryPanel() {
    const list = el('div', {}), label = el('input', { type: 'text', maxlength: 60, placeholder: 'e.g. Fake admin panel', 'aria-label': 'Trap name' });
    async function paint() {
      const rows = await api('GET', '/api/canaries');
      list.replaceChildren(...(rows.length ? rows.map((c) => { const url = location.origin + '/c/' + c.token; return el('div', { class: 'trap' },
        el('div', {}, el('strong', {}, c.label), el('div', { class: 'muted small' }, c.hits ? `Triggered ${c.hits} time${c.hits === 1 ? '' : 's'}, last ${ago(c.last_hit)}` : 'Not triggered yet')),
        el('div', { class: 'codeblock', style: 'user-select:all;margin:6px 0' }, url),
        el('div', { class: 'inline' }, el('button', { class: 'btn sm', onclick: async () => { try { await navigator.clipboard.writeText(url); toast('Link copied'); } catch { toast('Select the link and copy it', true); } } }, 'Copy link'), el('button', { class: 'btn sm', onclick: () => window.open('/c/' + c.token, '_blank', 'noopener') }, 'Test it'), el('button', { class: 'btn sm danger', onclick: async () => { await api('DELETE', '/api/canaries/' + c.id); paint(); } }, 'Delete'))); }) : [el('p', { class: 'empty' }, 'No traps yet.')]));
    }
    paint();
    return el('div', { class: 'panel pad' }, el('div', { class: 'head' }, el('h2', {}, 'Canary traps')),
      el('p', { class: 'muted', style: 'margin-bottom:10px;max-width:75ch' }, 'A trap is a link no real person should ever open. Hide it in a fake admin page, a robots.txt entry or a decoy file. The moment someone opens it, NetGuard raises a critical alert and blocks their IP. The link always looks like an ordinary missing page, so attackers learn nothing.'),
      el('form', { class: 'inline', onsubmit: async (e) => { e.preventDefault(); try { await api('POST', '/api/canaries', { label: label.value }); label.value = ''; paint(); } catch (x) { toast(x.message, true); } } }, el('label', {}, 'Trap name', label), el('button', { class: 'btn primary', type: 'submit' }, 'Create trap')), list);
  }
  function toolkitPanel() {
    // password lab
    const pw = el('input', { type: 'text', autocomplete: 'off', spellcheck: 'false', placeholder: 'Type a password to test (stays in your browser)', 'aria-label': 'Password to test' });
    const meter = el('div', { class: 'meter' }, el('i', {})), verdict = el('p', { class: 'muted' }, 'Nothing is sent anywhere. The test runs entirely in this page.');
    pw.addEventListener('input', () => {
      const v = pw.value; if (!v) { meter.firstChild.style.cssText = 'width:0'; verdict.textContent = 'Nothing is sent anywhere. The test runs entirely in this page.'; return; }
      let pool = 0; if (/[a-z]/.test(v)) pool += 26; if (/[A-Z]/.test(v)) pool += 26; if (/\d/.test(v)) pool += 10; if (/[^\w]/.test(v)) pool += 33;
      let bits = v.length * Math.log2(Math.max(pool, 2));
      const common = /(password|qwerty|letmein|admin|welcome|iloveyou|123456|abc123|111111)/i.test(v); if (common) bits = Math.min(bits, 24);
      if (/(.)\1{2,}/.test(v)) bits -= 8; if (/^(?:19|20)\d\d$/.test(v) || /^\d+$/.test(v)) bits = Math.min(bits, 28);
      bits = Math.max(0, bits);
      const secs = Math.pow(2, bits) / 2 / 1e10, human = secs < 1 ? 'instantly' : secs < 60 ? Math.round(secs) + ' seconds' : secs < 3600 ? Math.round(secs / 60) + ' minutes' : secs < 86400 ? Math.round(secs / 3600) + ' hours' : secs < 3.15e7 ? Math.round(secs / 86400) + ' days' : secs < 3.15e9 ? Math.round(secs / 3.15e7) + ' years' : 'centuries';
      const pct = Math.min(100, Math.round((bits / 80) * 100)), lvl = bits < 36 ? 'Weak' : bits < 60 ? 'Okay' : 'Strong';
      meter.firstChild.style.cssText = `width:${pct}%;background:${bits < 36 ? '#ff5557' : bits < 60 ? '#C8792C' : '#FFF21A'}`;
      verdict.textContent = `${lvl}. About ${Math.round(bits)} bits. A fast attacker could crack it in ${human}.` + (common ? ' It contains a very common word or pattern.' : '') + (v.length < 12 ? ' Use at least 12 characters.' : '');
    });
    // hash
    const hin = el('input', { type: 'text', placeholder: 'Text to hash', 'aria-label': 'Text to hash' }), hout = el('div', { class: 'codeblock', style: 'white-space:pre-wrap;word-break:break-all' }, '');
    const doHash = async () => { try { const buf = new TextEncoder().encode(hin.value); const lines = []; for (const alg of ['SHA-256', 'SHA-512']) { const d = await crypto.subtle.digest(alg, buf); lines.push(alg + '\n' + [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('')); } hout.textContent = lines.join('\n\n'); } catch { hout.textContent = 'Hashing needs a secure (https) page.'; } };
    hin.addEventListener('input', doHash);
    // base64 / jwt
    const din = el('input', { type: 'text', placeholder: 'Paste Base64 text or a JWT token', 'aria-label': 'Base64 or JWT' }), dout = el('div', { class: 'codeblock', style: 'white-space:pre-wrap;word-break:break-all' }, '');
    const b64 = (x) => decodeURIComponent(escape(atob(x.replace(/-/g, '+').replace(/_/g, '/'))));
    din.addEventListener('input', () => {
      const v = din.value.trim(); if (!v) { dout.textContent = ''; return; }
      try {
        const parts = v.split('.');
        if (parts.length === 3) dout.textContent = 'JWT header\n' + JSON.stringify(JSON.parse(b64(parts[0])), null, 2) + '\n\nJWT payload\n' + JSON.stringify(JSON.parse(b64(parts[1])), null, 2) + '\n\n(The signature is not verified here.)';
        else dout.textContent = 'Decoded\n' + b64(v);
      } catch { dout.textContent = 'Not valid Base64 or JWT.'; }
    });
    return el('div', { class: 'panel pad' }, el('div', { class: 'head' }, el('h2', {}, 'Security toolkit')),
      el('div', { class: 'toolkit' },
        el('div', {}, el('h3', { class: 'sub' }, 'Password lab'), el('label', {}, 'Password', pw), meter, verdict),
        el('div', {}, el('h3', { class: 'sub' }, 'Hash generator'), el('label', {}, 'Text', hin), hout),
        el('div', {}, el('h3', { class: 'sub' }, 'Base64 and JWT decoder'), el('label', {}, 'Input', din), dout)));
  }

  // ------------------------------------------------------------------ simulator
  function simulatorView() {
    const status = el('p', { class: 'mono muted', 'aria-live': 'polite' }, 'No command sent yet.');
    const fire = (type, label) => async () => {
      try {
        const r = await api('POST', '/api/sim/attack', { type });
        status.textContent = `${fmtTime(Date.now())} ${label}${r.attacker_ip ? ' from ' + r.attacker_ip : ''}. ${r.listening} dashboard${r.listening === 1 ? '' : 's'} listening. Results appear below (Demo only).`;
        try { navigator.vibrate && navigator.vibrate(type === 'cyber' ? [60, 40, 60] : 140); } catch { /* ignore */ }
      } catch (e) { toast(e.message, true); }
    };
    const btn = (cls, title, sub, type, label) => el('button', { class: 'big ' + cls, type: 'button', onclick: fire(type, label) }, el('span', { class: 'lbl' }, title), el('span', { class: 'sub' }, sub));
    const feed = el('div', { class: 'logs' }), dAlerts = el('div', {});
    function paintDemo() {
      dAlerts.replaceChildren(...(S.demoAlerts.length ? S.demoAlerts.slice(0, 6).map((a) => el('div', { class: 'row' }, el('span', { class: 't' }, fmtTime(a.created)), el('span', { class: 'sev ' + a.severity }, a.severity), el('span', { class: 'm' }, demoTag(), ' ', a.title, a.action ? ' | ' + a.action : ''))) : [stateBox('empty', 'No demo alerts yet. Press one of the buttons above.')]));
      feed.replaceChildren(...S.demoLogs.slice(-12).reverse().map((l) => el('div', { class: 'row ' + l.level }, el('span', { class: 't' }, fmtTime(l.ts)), el('span', { class: 'l' }, l.level), el('span', { class: 'm' }, l.msg))));
    }
    current = { tick: paintDemo, refresh: paintDemo, logTick: paintDemo };
    loadDemo().then(paintDemo);
    return el('section', { class: 'view grid' },
      el('div', { class: 'demo-banner', role: 'note' }, demoTag('DEMO MODE'), el('span', {}, 'Everything on this page is simulated. It runs on a separate Demo device with fake traffic. It never reaches your real devices, your real alerts, or any firewall. Demo results are kept out of your dashboard counts and report.')),
      el('div', {}, el('h2', {}, 'Attack simulator ', demoTag()),
        el('p', { class: 'muted', style: 'max-width:70ch;margin-top:6px' }, 'Sends synthetic traffic from a fake attacker into the demo device. It goes through the exact same detection engine, alerting and auto-block logic as a real agent. Open the Dashboard on another screen to watch, or use this page on your phone.')),
      el('div', { class: 'remote' },
        btn('red', 'Launch cyber attack', 'Floods the demo network with 2,000 packets per second', 'cyber', 'Flood attack launched'),
        btn('amber', 'Inject physical spark', 'Electrical arc sensor event triggers an emergency shutdown', 'spark', 'Physical spark injected'),
        btn('blue', 'Port scan', 'One host probes dozens of ports', 'scan', 'Port scan launched'),
        btn('violet', 'Login brute force', 'Repeated failed logins from one address', 'brute', 'Brute force launched')),
      el('div', { class: 'panel pad' }, status,
        el('p', { class: 'muted', style: 'margin-top:8px' }, 'The Demo device always blocks its fake attacker on its own, so you can see the full flow. This never changes your Settings and never blocks anything on a real device.'),
        el('button', { class: 'btn sm', style: 'margin-top:10px', onclick: async () => { await api('POST', '/api/sim/reset', {}); toast('Simulation stopped'); } }, 'Stop simulation')),
      el('div', { class: 'panel pad' }, el('div', { class: 'head' }, el('h2', {}, 'Demo alerts '), demoTag()), dAlerts, el('div', { class: 'head', style: 'margin-top:14px' }, el('h2', {}, 'Demo log '), demoTag()), feed));
  }

  // ------------------------------------------------------------------ my account: delete everything
  // ---- 2-step verification settings: security PIN, authenticator app, e-mail code
  function securityPanel() {
    const box = el('div', { class: 'panel pad' }), msg = el('p', { class: 'err', role: 'alert' });
    const pw = el('input', { type: 'password', autocomplete: 'current-password', 'aria-label': 'Your password' });
    const pin = el('input', { type: 'password', inputmode: 'numeric', maxlength: 4, 'aria-label': 'New 4-digit PIN', placeholder: '4 digits' });
    const secretBox = el('div', {});
    async function paint() {
      let st; try { st = await api('GET', '/api/security'); } catch { box.replaceChildren(stateBox('error', 'Could not load security settings.', paint)); return; }
      const run = (fn, ok) => async () => { msg.textContent = ''; try { await fn(); toast(ok); await paint(); } catch (x) { msg.textContent = x.message; } };
      box.replaceChildren(el('div', { class: 'head' }, el('h2', {}, 'Privacy & 2-step verification')),
        el('p', { class: 'muted' }, 'After your password, NetGuard can ask for a second step. Turn on at least one. The same PIN also unlocks the screen after inactivity.'),
        el('label', {}, 'Your password (needed for every change below)', pw),
        el('div', { class: 'secrow' }, el('b', {}, '4-digit security PIN: ' + (st.pin ? 'ON' : 'off')),
          el('div', { class: 'inline' }, pin, el('button', { class: 'btn sm primary', onclick: run(() => api('POST', '/api/security/pin', { password: pw.value, pin: pin.value }), 'PIN saved') }, st.pin ? 'Change PIN' : 'Set PIN'),
            st.pin ? el('button', { class: 'btn sm danger', onclick: run(() => api('DELETE', '/api/security/pin', { password: pw.value }), 'PIN removed') }, 'Remove') : null)),
        el('div', { class: 'secrow' }, el('b', {}, 'Authenticator app (6-digit code): ' + (st.totp ? 'ON' : 'off')),
          el('div', { class: 'inline' },
            el('button', { class: 'btn sm primary', onclick: async () => {
              msg.textContent = '';
              try {
                const r = await api('POST', '/api/security/totp/setup', { password: pw.value });
                const c = el('input', { type: 'text', inputmode: 'numeric', maxlength: 6, placeholder: '6-digit code', 'aria-label': 'Code from your authenticator' });
                secretBox.replaceChildren(el('p', { class: 'muted' }, 'In Google Authenticator, Microsoft Authenticator or Authy choose "Enter a setup key" and type this key (account: NetGuard AI, time-based):'), codeBlock(r.secret.replace(/(.{4})/g, '$1 ').trim()),
                  el('p', { class: 'muted' }, 'On a phone you can also tap: ', el('a', { href: r.uri }, 'open in authenticator app'), '. Then type the code it shows to finish.'),
                  el('div', { class: 'inline' }, c, el('button', { class: 'btn sm primary', onclick: run(() => api('POST', '/api/security/totp/enable', { code: c.value }), 'Authenticator turned on') }, 'Confirm')));
              } catch (x) { msg.textContent = x.message; }
            } }, st.totp ? 'Set up again' : 'Set up'),
            st.totp ? el('button', { class: 'btn sm danger', onclick: run(() => api('DELETE', '/api/security/totp', { password: pw.value }), 'Authenticator removed') }, 'Remove') : null), secretBox),
        el('div', { class: 'secrow' }, el('b', {}, 'E-mail code: ' + (st.email ? 'ON' : 'off')),
          st.email_available ? el('button', { class: 'btn sm', onclick: run(() => api('POST', '/api/security/email', { password: pw.value, on: !st.email }), st.email ? 'E-mail code off' : 'E-mail code on') }, st.email ? 'Turn off' : 'Turn on')
            : el('span', { class: 'muted' }, 'Not available: the site owner has not set SMTP_EMAIL and SMTP_PASSWORD on the server.')),
        msg);
    }
    box.replaceChildren(stateBox('loading', 'Loading security settings…')); paint();
    return box;
  }
  function accountPanel() {
    const pw = el('input', { type: 'password', autocomplete: 'current-password', 'aria-label': 'Your password' }), err = el('p', { class: 'err', role: 'alert' });
    return el('div', { class: 'panel pad' }, el('div', { class: 'head' }, el('h2', {}, 'My account')),
      el('p', { class: 'muted', style: 'margin-bottom:10px' }, 'Deleting your account permanently removes your devices, alerts, blocks and logs. This cannot be undone. ', el('a', { href: '/privacy.html' }, 'Privacy')),
      el('form', { class: 'inline', onsubmit: async (e) => {
        e.preventDefault(); err.textContent = '';
        if (!confirm('Delete your account and ALL its data forever?')) return;
        try { await api('DELETE', '/api/me', { password: pw.value }); closeStream(); S.me = null; location.hash = ''; route(); toast('Account deleted'); } catch (x) { err.textContent = x.message; }
      } }, el('label', {}, 'Type your password to confirm', pw), el('button', { class: 'btn danger', type: 'submit' }, 'Delete my account')), err);
  }

  // ------------------------------------------------------------------ router
  function withProtection(v) { const pb = protectionBar(); v.prepend(pb.node); const t = current.tick; current.tick = () => { pb.paint(); if (t) t(); }; return v; }
  const VIEWS = { warroom: warRoomView, copilot: copilotView, tools: toolsView, report: reportView, dashboard: dashboardView, devices: devicesView, alerts: alertsView, blocks: () => withProtection(blocksView()), simulator: simulatorView, settings: () => { const v = withProtection(settingsView()); v.append(securityPanel()); if (!S.me.sandbox) v.append(accountPanel()); return v; } };
  function route() {
    if (current.cleanup) { current.cleanup(); }
    current = { refresh: null };
    if (!S.me) { $app.replaceChildren(authView()); return; }
    const key = (location.hash.match(/^#\/(\w+)/) || [])[1];
    const name = VIEWS[key] ? key : 'dashboard';
    $app.replaceChildren(shell(VIEWS[name](), name));
    updateNavBadge(); updateLink();
  }
  async function boot() {
    try { S.me = await api('GET', '/api/me'); } catch { S.me = null; }
    if (S.me) {
      if (isLocked()) setTimeout(lockScreen, 0); else armIdle();
      await Promise.all([loadDevices(), loadAlerts(), refreshStats()]);
      S.logs = []; openStream();
    }
    route();
  }
  window.addEventListener('hashchange', route);
  setInterval(() => { if (current.tick && S.me) current.tick(); }, 5000);
  setInterval(() => { if (current.insights && S.me) loadInsights(); }, 15000);
  boot();
})();
