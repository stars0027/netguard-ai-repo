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
    me: null, devices: [], alerts: [], logs: [], stats: {}, sel: null, series: [], live: {}, banner: null, bannerTimer: null,
    openAlert: null, stream: null, linked: false, ins: null,
  };
  let current = { refresh: null };

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
      S.logs.push(JSON.parse(e.data)); if (S.logs.length > 80) S.logs.shift();
      if (current.logTick) current.logTick();
    });
    es.addEventListener('alert', (e) => {
      const a = JSON.parse(e.data);
      S.alerts.unshift(a);
      refreshStats(); loadInsights();
      if (['critical', 'high'].includes(a.severity)) {
        alarmSound(a);
        const blocked = /^Blocked/.test(a.action || '');
        S.banner = {
          title: a.type === 'physical_anomaly' ? 'Emergency power shutdown' : blocked ? 'Attack blocked' : 'Attack detected',
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
      es.addEventListener(ev, () => { if (ev.startsWith('alert')) loadAlerts().then(() => { current.refresh && current.refresh(); updateNavBadge(); }); else { if (ev === 'device') loadDevices(); refreshStats(); loadInsights(); current.refresh && current.refresh(); } });
    }
  }
  async function refreshStats() { try { S.stats = await api('GET', '/api/stats'); updateNavBadge(); if (current.tick) current.tick(); } catch { /* ignore */ } }
  async function loadDevices() { S.devices = (await api('GET', '/api/devices')).filter((d) => !d.virtual || demoOn()); if (!S.sel || !S.devices.find((d) => d.id === S.sel)) S.sel = S.devices[0] && S.devices[0].id; }
  async function loadAlerts() { S.alerts = await api('GET', '/api/alerts?limit=200'); }
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
    try { if (a.title && 'speechSynthesis' in window) { const u = new SpeechSynthesisUtterance((a.severity === 'critical' ? 'Critical alert. ' : 'Warning. ') + a.title.replace(/[^\w .,:-]/g, ' ').slice(0, 120)); u.rate = 1.05; u.volume = 0.8; speechSynthesis.speak(u); } } catch { /* ignore */ }
    try { if (document.hidden && 'Notification' in window && Notification.permission === 'granted') new Notification('NetGuard AI: ' + a.title, { body: a.action || a.severity }); } catch { /* ignore */ }
  }
  function toggleSound(btn) {
    const on = !soundOn();
    try { localStorage.setItem('ng_sound', on ? '1' : '0'); } catch { /* ignore */ }
    if (on) { try { if ('Notification' in window && Notification.permission === 'default') Notification.requestPermission(); } catch { /* ignore */ } alarmSound({ severity: 'high' }); }
    btn.textContent = on ? 'Sound on' : 'Sound off'; btn.setAttribute('aria-pressed', String(on));
  }
  function updateNavBadge() { const b = document.getElementById('navBadge'); if (b) { const n = S.alerts.filter((a) => a.status === 'open').length; b.textContent = n > 99 ? '99+' : n; b.hidden = !n; } }
  function updateLink() {
    const l = document.getElementById('linkLed'), t = document.getElementById('linkText');
    if (!l) return;
    l.className = 'led ' + (S.linked ? 'on' : 'wait');
    const on = S.devices.filter((d) => d.status === 'online').length;
    t.textContent = S.linked ? `Live · ${on} of ${S.devices.length} devices online` : 'Reconnecting…';
  }

  // ------------------------------------------------------------------ auth screen
  function authView() {
    let mode = 'login';
    const err = el('p', { class: 'err', role: 'alert' });
    const name = el('input', { type: 'text', autocomplete: 'name', maxlength: 60 });
    const email = el('input', { type: 'email', autocomplete: 'email', required: true });
    const pw = el('input', { type: 'password', autocomplete: 'current-password', required: true, minlength: 8 });
    const nameLbl = el('label', {}, 'Name', name);
    const submit = el('button', { class: 'btn primary', type: 'submit' }, 'Sign in');
    const switcher = el('button', { class: 'btn', type: 'button' }, 'Create an account');
    const title = el('h2', {}, 'Sign in');
    function setMode(m) {
      mode = m; nameLbl.hidden = m === 'login';
      title.textContent = m === 'login' ? 'Sign in' : 'Create your account';
      submit.textContent = m === 'login' ? 'Sign in' : 'Create account';
      switcher.textContent = m === 'login' ? 'Create an account' : 'I already have an account';
      pw.autocomplete = m === 'login' ? 'current-password' : 'new-password'; err.textContent = '';
    }
    switcher.onclick = () => setMode(mode === 'login' ? 'signup' : 'login');
    const form = el('form', { class: 'form panel pad', onsubmit: async (e) => {
      e.preventDefault(); err.textContent = ''; submit.disabled = true;
      try {
        await api('POST', mode === 'login' ? '/api/auth/login' : '/api/auth/signup', { email: email.value, password: pw.value, name: name.value });
        await boot(); location.hash = '#/dashboard';
      } catch (x) { err.textContent = x.message; } finally { submit.disabled = false; }
    } }, title, nameLbl, el('label', {}, 'Email', email), el('label', {}, 'Password (8+ characters)', pw), err, el('div', { class: 'inline' }, submit, switcher));
    setMode('login');
    return el('div', { class: 'wrap' },
      el('div', { class: 'auth' },
        el('div', {},
          el('div', { class: 'brand' }, el('span', { class: 'mark' }, svg(SHIELD)), el('div', {}, el('h1', {}, 'NetGuard ', el('span', {}, 'AI')), el('p', { class: 'tag' }, 'Network & industrial anomaly defense'))),
          el('div', { class: 'scene', 'aria-hidden': 'true' }, el('div', { class: 'shield3d' }, [0, 1, 2, 3, 4, 5].map((i) => el('div', { class: 'layer l' + i })))),
          el('h2', { class: 'big-h', style: 'margin-top:28px;text-transform:none;letter-spacing:.02em' }, 'Detect attacks on your network and block them automatically.'),
          el('ul', {},
            el('li', {}, 'Install the agent on any server, PC or gateway'),
            el('li', {}, 'It learns normal traffic, then catches floods, port scans and brute-force logins'),
            el('li', {}, 'Attacker IPs are blocked in the OS firewall, on all your devices'),
            el('li', {}, 'Live dashboard, alert history and webhook notifications'))),
        form));
  }

  // ------------------------------------------------------------------ shell
  const demoOn = () => { try { return localStorage.getItem('ng_demo') === '1'; } catch { return false; } };
  const navItems = () => [['dashboard', 'Dashboard'], ['copilot', 'Copilot'], ['devices', 'Devices'], ['alerts', 'Alerts'], ['blocks', 'Blocklist'], ['tools', 'Tools'], ['warroom', 'War Room'], ['report', 'Report'], demoOn() ? ['simulator', 'Demo'] : null, ['settings', 'Settings']].filter(Boolean);
  function shell(view, active) {
    const badge = el('span', { class: 'badge', id: 'navBadge', hidden: true });
    return el('div', { class: 'wrap' },
      el('header', { class: 'top' },
        el('div', { class: 'brand' }, el('span', { class: 'mark' }, svg(SHIELD)), el('div', {}, el('h1', {}, 'NetGuard ', el('span', {}, 'AI')), el('p', { class: 'tag' }, 'Network & industrial anomaly defense'))),
        el('nav', { class: 'nav' },
          el('div', { class: 'tabs' }, navItems().map(([k, label]) => el('a', { href: '#/' + k, 'aria-current': k === active ? 'page' : null }, label, k === 'alerts' ? badge : null))),
          el('button', { class: 'btn sm', type: 'button', 'aria-pressed': String(soundOn()), title: 'Play an alarm sound and show a notification for serious alerts', onclick: (e) => toggleSound(e.currentTarget) }, soundOn() ? 'Sound on' : 'Sound off'),
          el('span', { class: 'link' }, el('i', { class: 'led wait', id: 'linkLed' }), el('span', { id: 'linkText' }, 'Connecting…')),
          el('button', { class: 'btn sm', type: 'button', title: S.me.email, onclick: async () => { await api('POST', '/api/auth/logout', {}); closeStream(); S.me = null; route(); } }, 'Sign out'))),
      view);
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
      set('kBlocked', String(S.stats.blocked_total ?? 0), 'accent');
      set('kOpen', String(S.stats.open_alerts ?? 0), (S.stats.open_alerts || 0) > 0 ? 'warn' : 'ok');
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
      devSel.replaceChildren(...S.devices.map((d) => el('option', { value: d.id, selected: d.id === S.sel }, d.name)));
      if (!S.logs.length) S.logs = await api('GET', '/api/logs?limit=60');
      await loadSeries(); paintLogs(); tick();
    })();
    window.addEventListener('resize', tick);
    const prevCleanup = current.cleanup; current.cleanup = () => { prevCleanup(); window.removeEventListener('resize', tick); };
    const empty = el('div', { class: 'panel pad', hidden: true, id: 'emptyState' },
      el('h2', {}, 'Protect your first device'),
      el('p', { class: 'muted', style: 'margin:8px 0 14px;max-width:70ch' }, 'NetGuard protects machines that run its small agent. Add a server, PC or gateway, run one command on it, and it starts learning its normal traffic, detecting attacks and blocking attackers automatically.'),
      el('ol', { class: 'muted', style: 'margin:0 0 16px;padding-left:20px;display:grid;gap:4px' }, el('li', {}, 'Click Add device and give it a name'), el('li', {}, 'Copy the install command and run it on that machine'), el('li', {}, 'Watch it appear here within seconds')),
      el('a', { class: 'btn primary', href: '#/devices', style: 'text-decoration:none;display:inline-flex;align-items:center' }, 'Add your first device'));
    const showEmpty = () => { empty.hidden = S.devices.length > 0; kpis.hidden = chartRow.hidden = S.devices.length === 0; };
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
      empty, banner, kpis,
      chartRow, radarRow, insightsRow,
      el('p', { class: 'foot' }, 'Dashed line = anomaly threshold learned from this device\'s own normal traffic'));
  }

  // ------------------------------------------------------------------ devices
  function devicesView() {
    const list = el('div', {});
    const keyArea = el('div', {});
    const nameIn = el('input', { type: 'text', maxlength: 60, placeholder: 'e.g. Web server, Plant gateway' });
    const origin = location.origin;
    function installBox(key) {
      const cmd = (extra) => `curl -fsSL ${origin}/agent/netguard_agent.py -o netguard_agent.py\npip install psutil\n${extra}`;
      return el('div', { class: 'keybox' },
        el('strong', {}, 'Copy your API key now. It is shown only once.'),
        el('div', { class: 'codeblock' }, key),
        el('p', {}, el('strong', {}, 'Easiest (Linux server or PC): one command.'), ' It installs the agent as a service that starts on boot and blocks attackers automatically.'),
        el('div', { class: 'codeblock' }, `curl -fsSL ${origin}/install.sh | sudo NETGUARD_KEY=${key} bash`),
        el('p', { class: 'muted' }, 'Or install by hand. Linux / macOS. Run on the machine you want to protect. Add --enforce to let NetGuard block attackers in the firewall (needs root); --sniff enables the packet sniffer (Linux, root).'),
        el('div', { class: 'codeblock' }, cmd(`sudo python3 netguard_agent.py --server ${origin} --key ${key} --enforce --sniff`)),
        el('p', { class: 'muted' }, 'Windows (PowerShell as Administrator):'),
        el('div', { class: 'codeblock' }, `Invoke-WebRequest ${origin}/agent/netguard_agent.py -OutFile netguard_agent.py\npip install psutil\npython netguard_agent.py --server ${origin} --key ${key} --enforce`),
        origin.startsWith('http://') && !/localhost|127\.0\.0\.1/.test(origin) ? el('p', { class: 'muted', 'data-tone': 'warn' }, 'This server is on plain http. Put it behind https before using it on the internet.') : null);
    }
    function paint() {
      if (!S.devices.length) { list.replaceChildren(el('p', { class: 'empty' }, 'No devices yet.')); return; }
      list.replaceChildren(...S.devices.map((d) => {
        const live = S.live[d.id] || {};
        return el('div', { class: 'devrow' },
          el('div', {}, el('div', { class: 'n' }, el('i', { class: 'led ' + (d.status === 'online' ? 'on' : d.status === 'offline' ? 'off' : 'wait') }), d.name, d.virtual ? el('span', { class: 'pill' }, 'simulated') : null),
            el('div', { class: 'muted mono' }, d.virtual ? 'Used by the Simulator' : `${d.hostname || 'waiting for agent'} · ${d.os || ''}`)),
          el('div', {}, el('div', { class: 'k' }, 'Status'), d.status + (d.enforce ? ' · enforcing' : d.status === 'online' ? ' · monitor-only' : '')),
          el('div', {}, el('div', { class: 'k' }, 'Traffic'), live.pps != null ? live.pps.toLocaleString() + ' pkt/s' : '—'),
          el('div', {}, el('div', { class: 'k' }, 'Last seen'), ago(d.last_seen)),
          el('div', { class: 'inline' }, d.virtual ? null : [
            el('button', { class: 'btn sm', onclick: async () => { if (!confirm('Rotate the API key? The agent stops working until you update it.')) return; const r = await api('POST', `/api/devices/${d.id}/rotate-key`, {}); keyArea.replaceChildren(installBox(r.api_key)); } }, 'New key'),
            el('button', { class: 'btn sm danger', onclick: async () => { if (!confirm(`Remove ${d.name}?`)) return; await api('DELETE', `/api/devices/${d.id}`); await loadDevices(); paint(); } }, 'Remove')]));
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
      const rows = S.alerts.filter((a) => filter === 'all' || a.status === filter);
      if (!rows.length) { body.replaceChildren(el('tr', {}, el('td', { colspan: 7, class: 'empty' }, 'No alerts. That means nothing suspicious has been seen.'))); return; }
      body.replaceChildren(...rows.flatMap((a) => {
        const tr = el('tr', { style: 'cursor:pointer', onclick: (e) => { if (e.target.closest('button')) return; S.openAlert = S.openAlert === a.id ? null : a.id; paint(); } },
          el('td', { class: 'mono' }, fmtDT(a.created)), el('td', {}, el('span', { class: 'sev ' + a.severity }, a.severity)),
          el('td', {}, a.title, a.count > 1 ? el('span', { class: 'pill', style: 'margin-left:8px' }, '×' + a.count) : null, a.action ? el('div', { class: 'muted' }, a.action) : null),
          el('td', { class: 'mono' }, a.src_ip || '—'), el('td', {}, a.device_name || '—'), el('td', {}, a.status),
          el('td', {}, el('div', { class: 'inline' },
            a.status === 'open' ? el('button', { class: 'btn sm', onclick: () => act(() => api('PATCH', `/api/alerts/${a.id}`, { status: 'ack' })) }, 'Ack') : null,
            a.status !== 'resolved' ? el('button', { class: 'btn sm', onclick: () => act(() => api('PATCH', `/api/alerts/${a.id}`, { status: 'resolved' })) }, 'Resolve') : null,
            a.src_ip && !/^Blocked/.test(a.action || '') ? el('button', { class: 'btn sm danger', onclick: () => act(async () => { await api('POST', `/api/alerts/${a.id}/block`, {}); toast('Blocked ' + a.src_ip); }) }, 'Block IP') : null)));
        const out = [tr];
        if (S.openAlert === a.id) out.push(el('tr', { class: 'open-detail' }, el('td', { colspan: 7 }, el('pre', {}, `type: ${a.type}\n` + JSON.stringify(a.detail, null, 2)))));
        return out;
      }));
    }
    current = { refresh: paint, tick: null };
    loadAlerts().then(paint);
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
      info.textContent = `${b.enforcing_devices} device${b.enforcing_devices === 1 ? '' : 's'} currently enforcing blocks in their firewall. Devices in monitor-only mode raise alerts but do not block.`;
      blocksBody.replaceChildren(...(b.blocks.length ? b.blocks.map((x) => el('tr', {},
        el('td', { class: 'mono' }, x.ip), el('td', {}, x.reason), el('td', {}, x.source), el('td', {}, x.applied + ' / ' + b.enforcing_devices),
        el('td', {}, fmtDT(x.created)), el('td', {}, left(x.expires)),
        el('td', {}, el('button', { class: 'btn sm', onclick: async () => { await api('DELETE', `/api/blocks/${x.id}`); paint(); } }, 'Unblock')))) : [el('tr', {}, el('td', { colspan: 7, class: 'empty' }, 'Nothing blocked right now.'))]));
      allowBody.replaceChildren(...(a.length ? a.map((x) => el('tr', {}, el('td', { class: 'mono' }, x.ip), el('td', {}, x.note || ''),
        el('td', {}, el('button', { class: 'btn sm', onclick: async () => { await api('DELETE', `/api/allowlist/${x.id}`); paint(); } }, 'Remove')))) : [el('tr', {}, el('td', { colspan: 3, class: 'empty' }, 'Allowlist is empty.'))]));
    }
    current = { refresh: paint, tick: null };
    paint();
    const add = (path, body, clear) => async () => { try { await api('POST', path, body()); clear.forEach((i) => { i.value = ''; }); paint(); } catch (e) { toast(e.message, true); } };
    return el('section', { class: 'view grid' },
      el('div', { class: 'panel pad' }, el('div', { class: 'head' }, el('h2', {}, 'Active blocks')), info,
        el('div', { class: 'inline', style: 'margin:12px 0' }, el('label', {}, 'IP address', ip), el('label', {}, 'Reason', reason),
          el('button', { class: 'btn primary', onclick: add('/api/blocks', () => ({ ip: ip.value, reason: reason.value }), [ip, reason]) }, 'Block IP')),
        el('div', { class: 'tablewrap' }, el('table', {}, el('thead', {}, el('tr', {}, ['IP', 'Reason', 'Source', 'Enforced on', 'Since', 'Expires', ''].map((h) => el('th', {}, h)))), blocksBody))),
      el('div', { class: 'panel pad' }, el('div', { class: 'head' }, el('h2', {}, 'Allowlist (never blocked or flagged)')),
        el('div', { class: 'inline', style: 'margin-bottom:12px' }, el('label', {}, 'IP address', aip), el('label', {}, 'Note', anote),
          el('button', { class: 'btn', onclick: add('/api/allowlist', () => ({ ip: aip.value, note: anote.value }), [aip, anote]) }, 'Add to allowlist')),
        el('div', { class: 'tablewrap' }, el('table', {}, el('thead', {}, el('tr', {}, ['IP', 'Note', ''].map((h) => el('th', {}, h)))), allowBody))));
  }

  // ------------------------------------------------------------------ simulator
  function simulatorView() {
    const status = el('p', { class: 'mono muted', 'aria-live': 'polite' }, 'No command sent yet.');
    const fire = (type, label) => async () => {
      try {
        const r = await api('POST', '/api/sim/attack', { type });
        status.textContent = `${fmtTime(Date.now())} ${label}${r.attacker_ip ? ' from ' + r.attacker_ip : ''}. ${r.listening} dashboard${r.listening === 1 ? '' : 's'} listening. Watch the Dashboard.`;
        try { navigator.vibrate && navigator.vibrate(type === 'cyber' ? [60, 40, 60] : 140); } catch { /* ignore */ }
      } catch (e) { toast(e.message, true); }
    };
    const btn = (cls, title, sub, type, label) => el('button', { class: 'big ' + cls, type: 'button', onclick: fire(type, label) }, el('span', { class: 'lbl' }, title), el('span', { class: 'sub' }, sub));
    return el('section', { class: 'view grid' },
      el('div', {}, el('h2', {}, 'Attack simulator'),
        el('p', { class: 'muted', style: 'max-width:70ch;margin-top:6px' }, 'Sends synthetic traffic from a fake attacker into the demo device. It goes through the exact same detection engine, alerting and auto-block logic as a real agent. Open the Dashboard on another screen to watch, or use this page on your phone.')),
      el('div', { class: 'remote' },
        btn('red', 'Launch cyber attack', 'Floods the demo network with 2,000 packets per second', 'cyber', 'Flood attack launched'),
        btn('amber', 'Inject physical spark', 'Electrical arc sensor event triggers an emergency shutdown', 'spark', 'Physical spark injected'),
        btn('blue', 'Port scan', 'One host probes dozens of ports', 'scan', 'Port scan launched'),
        btn('violet', 'Login brute force', 'Repeated failed logins from one address', 'brute', 'Brute force launched')),
      el('div', { class: 'panel pad' }, status,
        el('p', { class: 'muted', style: 'margin-top:8px' }, 'If auto-block is on (Settings), the attacker is blocked within seconds and the simulated attack stops, like it would on a real machine.'),
        el('button', { class: 'btn sm', style: 'margin-top:10px', onclick: async () => { await api('POST', '/api/sim/reset', {}); toast('Simulation stopped'); } }, 'Stop simulation')));
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
      try { await api('PUT', '/api/settings', body); toast('Settings saved'); } catch (x) { msg.textContent = x.message; }
    };
    const cur = el('input', { type: 'password', autocomplete: 'current-password' }), nw = el('input', { type: 'password', autocomplete: 'new-password', minlength: 8 });
    pwForm.append(el('label', {}, 'Current password', cur), el('label', {}, 'New password', nw), pmsg, el('button', { class: 'btn', type: 'submit' }, 'Change password'));
    pwForm.onsubmit = async (e) => { e.preventDefault(); pmsg.textContent = ''; try { await api('POST', '/api/auth/password', { current: cur.value, password: nw.value }); cur.value = nw.value = ''; toast('Password changed'); } catch (x) { pmsg.textContent = x.message; } };
    current = { refresh: null, tick: null };
    return el('section', { class: 'view grid' },
      el('div', { class: 'panel pad' }, el('div', { class: 'head' }, el('h2', {}, 'Detection & response')), f),
      el('div', { class: 'panel pad' }, el('div', { class: 'head' }, el('h2', {}, 'Demo tools')),
        el('label', { class: 'check' }, el('input', { type: 'checkbox', checked: demoOn(), onchange: (e) => { try { localStorage.setItem('ng_demo', e.target.checked ? '1' : '0'); } catch { /* ignore */ } loadDevices().then(route); } }), 'Show the attack simulator (for presentations only)')),
      el('div', { class: 'panel pad' }, el('div', { class: 'head' }, el('h2', {}, 'Account · ' + S.me.email)), pwForm));
  }

  // ------------------------------------------------------------------ lockdown mode + command palette
  async function getLockdown() { try { const c = await api('GET', '/api/settings'); return !!c.auto_block && c.sensitivity === 'high'; } catch { return false; } }
  async function setLockdown(on) {
    const cur = await api('GET', '/api/settings');
    if (on) { try { localStorage.setItem('ng_prev_sens', cur.sensitivity); } catch { /* ignore */ } await api('PUT', '/api/settings', { auto_block: true, sensitivity: 'high' }); toast('Lockdown ON: maximum sensitivity, automatic blocking'); }
    else { let prev = 'medium'; try { prev = localStorage.getItem('ng_prev_sens') || 'medium'; } catch { /* ignore */ } await api('PUT', '/api/settings', { sensitivity: prev === 'high' ? 'medium' : prev }); toast('Lockdown off: sensitivity restored'); }
    loadInsights();
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
    const log = el('div', { class: 'chat', 'aria-live': 'polite' });
    const input = el('input', { type: 'text', maxlength: 300, placeholder: 'Ask: "Am I safe?", "Who is attacking me?", or paste an IP…', 'aria-label': 'Ask Copilot' });
    const add = (who, text, links) => {
      const bubble = el('div', { class: 'msg ' + who }, el('span', { class: 'who' }, who === 'me' ? 'You' : 'NetGuard Copilot'), el('p', {}, ''));
      log.append(bubble); log.scrollTop = log.scrollHeight;
      const p = bubble.querySelector('p');
      if (who === 'me') { p.textContent = text; return; }
      let i = 0; const step = Math.max(1, Math.round(text.length / 70));
      const iv = setInterval(() => { i += step; p.textContent = text.slice(0, i); log.scrollTop = log.scrollHeight; if (i >= text.length) { clearInterval(iv); (links || []).forEach((l) => bubble.append(el('a', { class: 'btn sm', href: l.href, style: 'text-decoration:none;display:inline-flex;margin:8px 8px 0 0' }, l.label))); } }, 18);
    };
    async function ask(q) {
      q = q.trim(); if (!q) return; add('me', q); input.value = '';
      try { const r = await api('POST', '/api/copilot', { question: q }); add('bot', r.answer, r.links); } catch (e) { add('bot', 'Sorry, I could not answer: ' + e.message); }
    }
    const chips = ['Am I safe?', 'What happened today?', 'Who is attacking me?', 'What should I do?', 'Which devices are online?'].map((q) => el('button', { class: 'chip', type: 'button', onclick: () => ask(q) }, q));
    add('bot', 'Hi, I am NetGuard Copilot. I read your alerts, blocks and devices and explain them in plain words. I do not use any outside AI service, so your data never leaves your server.');
    current = {};
    return el('section', { class: 'view grid' }, el('div', { class: 'panel pad copilot' },
      el('div', { class: 'head' }, el('h2', {}, 'AI Copilot'), el('span', { class: 'meta' }, el('i', { class: 'led on' }), 'online')),
      log, el('div', { class: 'chips' }, chips),
      el('form', { class: 'inline', onsubmit: (e) => { e.preventDefault(); ask(input.value); } }, el('label', {}, 'Your question', input), el('button', { class: 'btn primary', type: 'submit' }, 'Ask'))));
  }

  // ------------------------------------------------------------------ tools: IP inspector + threat hunt
  function toolsView() {
    const out = el('div', {}), hout = el('div', {});
    const ipIn = el('input', { type: 'text', placeholder: '203.0.113.50', 'aria-label': 'IP address' });
    const qIn = el('input', { type: 'text', placeholder: 'e.g. 10.0.4.23, brute, flood, blocked', 'aria-label': 'Search' });
    async function inspect(ip) {
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
    (async () => {
      await Promise.all([loadAlerts(), loadInsights()]);
      const I = S.ins || { timeline: [], attackers: [], by_type: [], factors: [] }, total = I.timeline.reduce((a, b) => a + b.critical + b.high + b.other, 0);
      const mx = Math.max(1, ...I.timeline.map((b) => b.critical + b.high + b.other));
      body.replaceChildren(
        el('div', { class: 'rep-grid' },
          el('div', { class: 'rep-stat' }, el('span', { class: 'k' }, 'Security score'), el('b', {}, I.score == null ? '—' : I.score + '/100')),
          el('div', { class: 'rep-stat' }, el('span', { class: 'k' }, 'Alerts, 24 h'), el('b', {}, total)),
          el('div', { class: 'rep-stat' }, el('span', { class: 'k' }, 'Attackers, 7 d'), el('b', {}, I.attackers.length)),
          el('div', { class: 'rep-stat' }, el('span', { class: 'k' }, 'Currently blocked'), el('b', {}, S.stats.active_blocks ?? 0))),
        el('h3', { class: 'sub' }, 'Alerts per hour, last 24 hours'),
        el('div', { class: 'rep-bars' }, I.timeline.map((b) => { const n = b.critical + b.high + b.other; return el('i', { style: `height:${Math.max(3, (n / mx) * 100)}%`, title: n + ' alerts', class: b.critical ? 'c' : b.high ? 'h' : '' }); })),
        el('h3', { class: 'sub' }, 'Top attackers'),
        I.attackers.length ? el('table', {}, el('thead', {}, el('tr', {}, ['IP', 'Attack types', 'Alerts', 'Last seen', 'Status'].map((h) => el('th', {}, h)))), el('tbody', {}, I.attackers.map((a) => el('tr', {}, el('td', { class: 'mono' }, a.ip), el('td', {}, a.types.map(typeLabel).join(', ')), el('td', {}, a.alerts), el('td', {}, ago(a.last)), el('td', {}, a.blocked ? 'Blocked' : 'Not blocked'))))) : el('p', { class: 'muted' }, 'No attackers in the last 7 days.'),
        el('h3', { class: 'sub' }, 'Recent alerts'),
        S.alerts.length ? el('table', {}, el('thead', {}, el('tr', {}, ['Time', 'Severity', 'What happened', 'Source', 'Action'].map((h) => el('th', {}, h)))), el('tbody', {}, S.alerts.slice(0, 20).map((a) => el('tr', {}, el('td', { class: 'mono' }, fmtDT(a.created)), el('td', {}, a.severity), el('td', {}, a.title), el('td', { class: 'mono' }, a.src_ip || '—'), el('td', {}, a.action || '—'))))) : el('p', { class: 'muted' }, 'No alerts recorded.'),
        el('h3', { class: 'sub' }, 'Recommendations'),
        el('ul', { class: 'recs' }, (I.factors.length ? I.factors : [{ fix: 'No action needed. Keep reviewing alerts weekly.' }]).map((f) => el('li', {}, f.fix))));
    })();
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
      const I = S.ins; set('wScore', I && I.score != null ? I.score : '—'); set('wBlocked', S.stats.active_blocks ?? 0); set('wOpen', S.stats.open_alerts ?? 0);
      set('wAtk', I ? I.attackers.filter((a) => !a.blocked).length : 0);
      clock.textContent = new Date().toLocaleTimeString([], { hour12: false });
      feed.replaceChildren(...S.logs.slice(-14).reverse().map((l) => el('div', { class: 'row ' + l.level }, el('span', { class: 't' }, fmtTime(l.ts)), el('span', { class: 'l' }, l.level), el('span', { class: 'm' }, l.msg))));
      document.getElementById('glow').className = S.banner && !S.banner.good ? 'on' : '';
    }
    const iv = setInterval(paint, 1000); const iv2 = setInterval(loadInsights, 8000);
    current = { tick: paint, logTick: paint, refresh: paint, cleanup: () => { alive = false; clearInterval(iv); clearInterval(iv2); document.getElementById('glow').className = ''; } };
    (async () => { await Promise.all([loadAlerts(), refreshStats(), loadInsights()]); if (!S.logs.length) S.logs = await api('GET', '/api/logs?limit=30'); paint(); })();
    const fs = el('button', { class: 'btn sm', type: 'button', onclick: () => { document.fullscreenElement ? document.exitFullscreen() : document.documentElement.requestFullscreen && document.documentElement.requestFullscreen(); } }, 'Full screen');
    return el('section', { class: 'view wr' },
      el('div', { class: 'wr-top' }, el('h2', {}, 'NetGuard war room'), el('span', { class: 'meta' }, clock, fs)),
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

  // ------------------------------------------------------------------ router
  const VIEWS = { warroom: warRoomView, copilot: copilotView, tools: toolsView, report: reportView, dashboard: dashboardView, devices: devicesView, alerts: alertsView, blocks: blocksView, simulator: simulatorView, settings: settingsView };
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
