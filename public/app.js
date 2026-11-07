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
    openAlert: null, stream: null, linked: false,
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
      refreshStats();
      if (['critical', 'high'].includes(a.severity)) {
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
      es.addEventListener(ev, () => { if (ev.startsWith('alert')) loadAlerts().then(() => { current.refresh && current.refresh(); updateNavBadge(); }); else { if (ev === 'device') loadDevices(); refreshStats(); current.refresh && current.refresh(); } });
    }
  }
  async function refreshStats() { try { S.stats = await api('GET', '/api/stats'); updateNavBadge(); if (current.tick) current.tick(); } catch { /* ignore */ } }
  async function loadDevices() { S.devices = (await api('GET', '/api/devices')).filter((d) => !d.virtual || demoOn()); if (!S.sel || !S.devices.find((d) => d.id === S.sel)) S.sel = S.devices[0] && S.devices[0].id; }
  async function loadAlerts() { S.alerts = await api('GET', '/api/alerts?limit=200'); }
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
  const navItems = () => [['dashboard', 'Dashboard'], ['devices', 'Devices'], ['alerts', 'Alerts'], ['blocks', 'Blocklist'], demoOn() ? ['simulator', 'Demo'] : null, ['settings', 'Settings']].filter(Boolean);
  function shell(view, active) {
    const badge = el('span', { class: 'badge', id: 'navBadge', hidden: true });
    return el('div', { class: 'wrap' },
      el('header', { class: 'top' },
        el('div', { class: 'brand' }, el('span', { class: 'mark' }, svg(SHIELD)), el('div', {}, el('h1', {}, 'NetGuard ', el('span', {}, 'AI')), el('p', { class: 'tag' }, 'Network & industrial anomaly defense'))),
        el('nav', { class: 'nav' },
          el('div', { class: 'tabs' }, navItems().map(([k, label]) => el('a', { href: '#/' + k, 'aria-current': k === active ? 'page' : null }, label, k === 'alerts' ? badge : null))),
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
      c.strokeStyle = 'rgba(138,158,173,.1)'; c.beginPath(); c.moveTo(L, yy); c.lineTo(w - R, yy); c.stroke();
      c.fillStyle = '#8a9ead'; c.textAlign = 'right'; c.fillText(Math.round(v).toLocaleString(), L - 6, yy);
    }
    if (!pts.length) { c.fillStyle = '#8a9ead'; c.textAlign = 'center'; c.fillText('Waiting for telemetry…', w / 2, h / 2); return; }
    const t1 = pts[pts.length - 1].ts, span = 120000, t0 = t1 - span, x = (t) => L + ((t - t0) / span) * pw;
    c.textAlign = 'center'; c.fillStyle = '#8a9ead';
    for (let i = 0; i <= 4; i++) { const t = t0 + (span / 4) * i; c.fillText(fmtTime(t), Math.min(w - 24, Math.max(L + 22, x(t))), h - 8); }
    if (thr) { c.setLineDash([6, 6]); c.strokeStyle = 'rgba(245,181,61,.7)'; c.beginPath(); c.moveTo(L, y(thr)); c.lineTo(w - R, y(thr)); c.stroke(); c.setLineDash([]); }
    const col = hot ? '#ff5557' : '#2dd4c0';
    const vis = pts.filter((p) => p.ts >= t0);
    if (!vis.length) return;
    c.beginPath(); vis.forEach((p, i) => (i ? c.lineTo(x(p.ts), y(p.pps)) : c.moveTo(x(p.ts), y(p.pps))));
    c.lineWidth = 2.5; c.strokeStyle = col; c.stroke();
    c.lineTo(x(vis[vis.length - 1].ts), y(0)); c.lineTo(x(vis[0].ts), y(0)); c.closePath();
    c.fillStyle = hot ? 'rgba(255,85,87,.2)' : 'rgba(45,212,192,.14)'; c.fill();
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
    return el('section', { class: 'view grid' },
      empty, banner, kpis,
      chartRow,
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
      if (!rows.length) { body.replaceChildren(el('tr', {}, el('td', { colspan: 7, class: 'empty' }, 'No alerts. Try the Simulator to see one.'))); return; }
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
      el('div', { class: 'head' }, el('h2', {}, 'Alerts'), el('span', { class: 'meta' }, sel)),
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

  // ------------------------------------------------------------------ router
  const VIEWS = { dashboard: dashboardView, devices: devicesView, alerts: alertsView, blocks: blocksView, simulator: simulatorView, settings: settingsView };
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
  boot();
})();
