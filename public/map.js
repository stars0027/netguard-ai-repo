'use strict';
// NetGuard world map: a small self-hosted slippy map (Web Mercator) that draws dark-styled tiles
// from OpenStreetMap (no API key); if those fail it switches to Esri World Dark Gray. Pan / zoom / flyTo and attack markers. No third-party script is loaded.
(function () {
  const TILE = 256, MAXZ = 12, MINZ = 1.2;
  const clamp = (v, a, b) => Math.min(b, Math.max(a, v));
  const W = (z) => TILE * Math.pow(2, z);
  const px = (lon, z) => ((lon + 180) / 360) * W(z);
  const py = (lat, z) => { const r = (clamp(lat, -85, 85) * Math.PI) / 180; return ((1 - Math.log(Math.tan(r) + 1 / Math.cos(r)) / Math.PI) / 2) * W(z); };
  const unLon = (x, z) => (x / W(z)) * 360 - 180;
  const unLat = (y, z) => { const n = Math.PI - (2 * Math.PI * y) / W(z); return (180 / Math.PI) * Math.atan(0.5 * (Math.exp(n) - Math.exp(-n))); };
  const NS = 'http://www.w3.org/2000/svg';
  const sv = (tag, attrs) => { const e = document.createElementNS(NS, tag); for (const k in attrs) e.setAttribute(k, attrs[k]); return e; };
  const COLORS = { critical: '#ff5557', high: '#ff5557', medium: '#C8792C', low: '#FFF21A', demo: '#A66BFF', site: '#FFF21A', blocked: '#FFF21A' };

  // Coarse built-in continents [lon,lat]. Drawn under the tiles so the map is never blank, even if every tile fails.
  const LAND = [
    [[-168,66],[-162,70],[-141,70],[-125,70],[-110,73],[-95,72],[-82,69],[-80,63],[-94,59],[-93,50],[-82,46],[-67,45],[-60,48],[-56,52],[-64,60],[-78,62],[-82,56],[-76,52],[-66,45],[-70,42],[-76,35],[-81,31],[-80,25],[-83,29],[-90,30],[-97,27],[-97,21],[-90,21],[-87,21],[-88,16],[-83,10],[-78,8],[-85,10],[-92,15],[-105,20],[-110,24],[-115,30],[-118,34],[-124,40],[-124,48],[-135,58],[-150,60],[-165,60],[-168,66]],
    [[-80,8],[-72,12],[-62,10],[-52,5],[-50,0],[-35,-6],[-40,-20],[-48,-27],[-58,-38],[-65,-42],[-68,-52],[-72,-52],[-74,-40],[-71,-20],[-76,-14],[-81,-5],[-78,2],[-80,8]],
    [[-10,36],[-9,43],[-2,44],[-4,48],[2,51],[8,54],[10,57],[12,56],[20,55],[24,60],[22,66],[28,70],[40,68],[60,69],[70,73],[100,77],[140,72],[170,70],[180,68],[180,65],[160,60],[142,54],[135,44],[128,40],[122,38],[122,30],[120,22],[108,20],[106,10],[100,13],[100,3],[104,1],[98,8],[93,18],[88,22],[80,14],[77,8],[72,20],[67,25],[57,25],[56,27],[50,30],[48,29],[56,18],[44,13],[36,28],[34,31],[28,37],[26,40],[20,40],[16,38],[12,44],[6,43],[-1,38],[-10,36]],
    [[-17,21],[-10,30],[-5,36],[10,37],[20,33],[32,31],[35,28],[43,12],[51,12],[40,-3],[40,-15],[35,-24],[27,-34],[18,-34],[12,-18],[13,-6],[9,4],[-8,4],[-15,11],[-17,21]],
    [[113,-22],[122,-18],[130,-12],[137,-12],[142,-11],[146,-19],[153,-26],[150,-37],[141,-38],[130,-32],[115,-34],[113,-22]],
    [[-55,60],[-45,60],[-20,70],[-20,82],[-60,82],[-72,78],[-55,60]],
    [[-6,50],[2,52],[-2,58],[-6,56],[-6,50]],
    [[130,31],[141,41],[145,44],[140,36],[130,31]],
  ];

  function create(opts = {}) {
    const root = document.createElement('div'); root.className = 'ngmap'; root.setAttribute('role', 'application'); root.setAttribute('aria-label', 'World map of attack origins. Drag to pan, scroll or use the buttons to zoom.');
    const landSvg = sv('svg', { class: 'ngm-land' }); const landPath = sv('path', { class: 'ngm-landp' }); landSvg.append(landPath);
    const tiles = document.createElement('div'); tiles.className = 'ngm-tiles';
    const svg = sv('svg', { class: 'ngm-svg' });
    const ctl = document.createElement('div'); ctl.className = 'ngm-ctl';
    const card = document.createElement('div'); card.className = 'ngm-card'; card.hidden = true;
    const attr = document.createElement('div'); attr.className = 'ngm-attr'; attr.textContent = 'Tiles © Esri, HERE, Garmin, OpenStreetMap contributors';
    const note = document.createElement('div'); note.className = 'ngm-note'; note.hidden = true; note.textContent = 'Detailed map tiles could not be loaded. The simplified world outline and markers are still accurate.';
    root.append(landSvg, tiles, svg, ctl, card, attr, note);
    const mkBtn = (label, title, fn) => { const b = document.createElement('button'); b.type = 'button'; b.className = 'btn sm'; b.textContent = label; b.title = title; b.setAttribute('aria-label', title); b.onclick = fn; ctl.append(b); return b; };

    let lat = 20, lon = 0, z = 2, w = 600, h = 340, markers = [], site = null, selected = null, anim = 0, tileErrors = 0, raf = 0;
    const pool = new Map();

    function size() { w = root.clientWidth || 600; h = root.clientHeight || 340; svg.setAttribute('viewBox', `0 0 ${w} ${h}`); }
    const toScreen = (la, lo) => { const cx = px(lon, z), cy = py(lat, z); let dx = px(lo, z) - cx; const full = W(z); if (dx > full / 2) dx -= full; if (dx < -full / 2) dx += full; return [w / 2 + dx, h / 2 + (py(la, z) - cy)]; };

    function drawTiles() {
      const Z = clamp(Math.round(z), 1, MAXZ), scale = Math.pow(2, z - Z), ts = TILE * scale, n = Math.pow(2, Z);
      const cx = px(lon, Z) , cy = py(lat, Z);
      const x0 = Math.floor((cx - w / 2 / scale) / TILE), x1 = Math.floor((cx + w / 2 / scale) / TILE), y0 = Math.floor((cy - h / 2 / scale) / TILE), y1 = Math.floor((cy + h / 2 / scale) / TILE);
      const keep = new Set();
      const LAYERS = [
        { id: 'base', cls: 'base', url: (Z, x, y) => `https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/${Z}/${y}/${x}` },
        { id: 'ref', cls: 'ref', url: (Z, x, y) => `https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Reference/MapServer/tile/${Z}/${y}/${x}` },
      ]; // Esri tile order is {z}/{y}/{x}
      for (const L of LAYERS) for (let ty = Math.max(0, y0); ty <= Math.min(n - 1, y1); ty++) for (let tx = x0; tx <= x1; tx++) {
        const wx = ((tx % n) + n) % n, key = `${L.id}/${Z}/${tx}/${ty}`; keep.add(key);
        let im = pool.get(key);
        if (!im) {
          im = new Image(); im.className = 'ngm-tile ' + L.cls; im.alt = ''; im.draggable = false; im.decoding = 'async';
          im.onerror = () => { im.hidden = true; if (L.id === 'base' && ++tileErrors > 3) note.hidden = false; };
          im.onload = () => { if (L.id === 'base') { tileErrors = 0; note.hidden = true; } };
          im.src = L.url(Z, wx, ty);
          tiles.append(im); pool.set(key, im);
        }
        im.style.left = Math.round(w / 2 + (tx * TILE - cx) * scale) + 'px'; im.style.top = Math.round(h / 2 + (ty * TILE - cy) * scale) + 'px'; im.style.width = im.style.height = Math.ceil(ts) + 1 + 'px';
      }
      for (const [k, im] of pool) if (!keep.has(k)) { im.remove(); pool.delete(k); }
    }

    function greatCircle(a, b, steps = 40) {
      const r = Math.PI / 180, [la1, lo1, la2, lo2] = [a[0] * r, a[1] * r, b[0] * r, b[1] * r];
      const d = 2 * Math.asin(Math.sqrt(Math.sin((la2 - la1) / 2) ** 2 + Math.cos(la1) * Math.cos(la2) * Math.sin((lo2 - lo1) / 2) ** 2));
      if (!d) return [a, b];
      const pts = [];
      for (let i = 0; i <= steps; i++) {
        const f = i / steps, A = Math.sin((1 - f) * d) / Math.sin(d), B = Math.sin(f * d) / Math.sin(d);
        const x = A * Math.cos(la1) * Math.cos(lo1) + B * Math.cos(la2) * Math.cos(lo2), y = A * Math.cos(la1) * Math.sin(lo1) + B * Math.cos(la2) * Math.sin(lo2), zz = A * Math.sin(la1) + B * Math.sin(la2);
        pts.push([Math.atan2(zz, Math.sqrt(x * x + y * y)) / r, Math.atan2(y, x) / r]);
      }
      return pts;
    }

    function drawMarkers() {
      svg.replaceChildren();
      if (site) {
        for (const m of markers) if (m.id === selected || markers.length <= 12) {
          const pts = greatCircle([m.lat, m.lon], [site.lat, site.lon]).map((p) => toScreen(p[0], p[1]));
          // split the polyline where it wraps around the date line
          let d = '', prev = null;
          for (const p of pts) { d += (prev && Math.abs(p[0] - prev[0]) > w / 2 ? 'M' : prev ? 'L' : 'M') + p[0].toFixed(1) + ' ' + p[1].toFixed(1) + ' '; prev = p; }
          svg.append(sv('path', { d, fill: 'none', stroke: m.demo ? COLORS.demo : COLORS[m.severity] || COLORS.high, 'stroke-width': m.id === selected ? 2 : 1, 'stroke-dasharray': '5 4', opacity: m.id === selected ? 0.95 : 0.45 }));
        }
        const [sx, sy] = toScreen(site.lat, site.lon);
        svg.append(sv('rect', { x: sx - 6, y: sy - 6, width: 12, height: 12, fill: COLORS.site, stroke: '#171717', 'stroke-width': 2, transform: `rotate(45 ${sx} ${sy})` }));
        const t = sv('text', { x: sx + 11, y: sy + 4, fill: '#FFF21A', 'font-size': 11, 'font-family': 'IBM Plex Mono, monospace' }); t.textContent = 'Your network' + (site.demo ? ' (sample)' : ''); svg.append(t);
      }
      for (const m of markers) {
        const [x, y] = toScreen(m.lat, m.lon), col = m.demo ? COLORS.demo : m.blocked ? COLORS.blocked : COLORS[m.severity] || COLORS.high, sel = m.id === selected;
        const g = sv('g', { class: 'ngm-mark', tabindex: 0, role: 'button', 'aria-label': `${m.demo ? 'Demo ' : ''}attacker ${m.label || m.id}`, transform: `translate(${x.toFixed(1)} ${y.toFixed(1)})` });
        if (sel) g.append(sv('circle', { r: 16, fill: 'none', stroke: col, 'stroke-width': 1.5, opacity: 0.6 }));
        g.append(sv('circle', { r: sel ? 8 : 6, fill: col, 'fill-opacity': 0.9, stroke: '#171717', 'stroke-width': 2 }));
        g.append(sv('circle', { r: 14, fill: 'transparent' }));
        const act = () => api.select(m.id, true); g.onclick = act; g.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); act(); } };
        svg.append(g);
      }
    }
    function drawLand() {
      landSvg.setAttribute('viewBox', `0 0 ${w} ${h}`);
      const full = W(z); let d = '';
      for (const poly of LAND) for (const off of [-full, 0, full]) {
        d += poly.map(([lo, la], i) => { const x = w / 2 + px(lo, z) - px(lon, z), y = h / 2 + py(la, z) - py(lat, z); return (i ? 'L' : 'M') + (x + off).toFixed(1) + ' ' + y.toFixed(1); }).join('') + 'Z';
      }
      landPath.setAttribute('d', d);
    }
    function render() { cancelAnimationFrame(raf); raf = requestAnimationFrame(() => { size(); drawLand(); drawTiles(); drawMarkers(); }); }

    // ---- interaction
    let drag = null;
    root.addEventListener('pointerdown', (e) => { if (e.target.closest('.ngm-ctl,.ngm-card,.ngm-mark')) return; drag = { x: e.clientX, y: e.clientY, lat, lon }; root.setPointerCapture(e.pointerId); root.classList.add('grab'); anim++; });
    root.addEventListener('pointermove', (e) => { if (!drag) return; const cx = px(drag.lon, z) - (e.clientX - drag.x), cy = py(drag.lat, z) - (e.clientY - drag.y); lon = ((unLon(cx, z) + 540) % 360) - 180; lat = clamp(unLat(cy, z), -80, 80); render(); });
    const end = () => { drag = null; root.classList.remove('grab'); };
    root.addEventListener('pointerup', end); root.addEventListener('pointercancel', end);
    root.addEventListener('wheel', (e) => { e.preventDefault(); anim++; z = clamp(z - Math.sign(e.deltaY) * 0.5, MINZ, MAXZ); render(); }, { passive: false });
    root.tabIndex = 0;
    root.addEventListener('keydown', (e) => { if (e.key === '+' || e.key === '=') { z = clamp(z + 1, MINZ, MAXZ); render(); } if (e.key === '-') { z = clamp(z - 1, MINZ, MAXZ); render(); } });
    mkBtn('+', 'Zoom in', () => { anim++; z = clamp(Math.round(z) + 1, MINZ, MAXZ); render(); });
    mkBtn('-', 'Zoom out', () => { anim++; z = clamp(Math.round(z) - 1, MINZ, MAXZ); render(); });
    mkBtn('Reset world view', 'Reset world view', () => { api.flyTo(20, 0, 2); });
    if (typeof ResizeObserver !== 'undefined') new ResizeObserver(render).observe(root);

    const reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const api = {
      el: root,
      flyTo(toLat, toLon, toZ = 6, dur = 1.4) {
        const my = ++anim, a = { lat, lon, z }; let dLon = toLon - lon; if (dLon > 180) dLon -= 360; if (dLon < -180) dLon += 360;
        const dz = Math.abs(toZ - z), bump = Math.min(2.2, 0.6 + dz * 0.35);
        if (reduce || !dur) { lat = toLat; lon = toLon; z = toZ; render(); return; }
        const t0 = performance.now();
        const step = (t) => {
          if (my !== anim) return;
          const f = clamp((t - t0) / (dur * 1000), 0, 1), e = f < 0.5 ? 2 * f * f : 1 - Math.pow(-2 * f + 2, 2) / 2;
          lat = a.lat + (toLat - a.lat) * e; lon = ((a.lon + dLon * e + 540) % 360) - 180; z = clamp(a.z + (toZ - a.z) * e - Math.sin(Math.PI * f) * bump, MINZ, MAXZ);
          size(); drawTiles(); drawMarkers();
          if (f < 1) requestAnimationFrame(step);
        };
        requestAnimationFrame(step);
      },
      setMarkers(list) { markers = list.filter((m) => typeof m.lat === 'number' && typeof m.lon === 'number'); if (selected && !markers.find((m) => m.id === selected)) { selected = null; card.hidden = true; } render(); },
      setSite(s) { site = s && typeof s.lat === 'number' ? s : null; render(); },
      select(id, fly) {
        selected = id; const m = markers.find((x) => x.id === id);
        if (!m) { card.hidden = true; render(); return; }
        if (fly) api.flyTo(m.lat, m.lon, 6, 1.4);
        if (opts.renderCard) { card.replaceChildren(opts.renderCard(m, () => { selected = null; card.hidden = true; render(); })); card.hidden = false; }
        render();
      },
      resetView() { api.flyTo(20, 0, 2); },
      get view() { return { lat, lon, z }; },
      destroy() { cancelAnimationFrame(raf); anim++; pool.clear(); },
    };
    setTimeout(render, 0);
    return api;
  }
  window.NgMap = { create };
})();
