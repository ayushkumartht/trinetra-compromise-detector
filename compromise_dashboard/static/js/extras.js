"use strict";
/* Console extras: story mode, live attack lab, what-if lab, ATT&CK map, attack timeline, toasts + sound,
   command palette, theme / language / presenter toggles, map zoom-pan-drag-minimap, upload, mobile menu.
   Shares globals with console.js (R, T, times, renderAll, openDrawer, ...). */

window.viewRenderers = window.viewRenderers || {};
window.onRendered = window.onRendered || [];
const TACTIC_ABBR = { "Execution": "EXE", "Persistence": "PER", "Defense Evasion": "DEF", "Credential Access": "CRED", "Discovery": "DISC",
  "Lateral Movement": "LAT", "Collection": "COL", "Command and Control": "C2", "Exfiltration": "EXF", "Impact": "IMP" };

/* =================================================================== toasts + sound */
let soundOn = localStorage.getItem("trinetra-sound") === "1";
let lastToastT = null, storyActive = false, liveMode = false;
function beep() {
  try {
    const a = new (window.AudioContext || window.webkitAudioContext)(), o = a.createOscillator(), g = a.createGain();
    o.type = "sine"; o.frequency.value = 880;
    g.gain.setValueAtTime(0.0001, a.currentTime); g.gain.exponentialRampToValueAtTime(0.2, a.currentTime + 0.02);
    g.gain.exponentialRampToValueAtTime(0.0001, a.currentTime + 0.35);
    o.connect(g).connect(a.destination); o.start(); o.stop(a.currentTime + 0.4);
  } catch (_) { /* audio not available */ }
}
function toast(kind, title, body, dev) {
  const box = $("#toasts"), n = document.createElement("div");
  const ic = kind === "bad" ? "i-shield-alert" : kind === "warn" ? "i-triangle-alert" : kind === "good" ? "i-circle-check" : "i-bell-ring";
  n.className = `toast ${kind}`;
  n.innerHTML = `<span class="t-ico">${icon(ic)}</span><div class="t-body"><b>${esc(title)}</b>${body ? `<span>${esc(body)}</span>` : ""}</div><button class="t-x" aria-label="Dismiss">${icon("i-x")}</button>`;
  n.onclick = (e) => { if (!e.target.closest(".t-x") && dev) openDrawer(dev); n.remove(); };
  box.prepend(n);
  setTimeout(() => n.classList.add("out"), 5200);
  setTimeout(() => n.remove(), 5800);
  while (box.children.length > 4) box.lastChild.remove();
  if (soundOn && kind === "bad") beep();
}
onRendered.push(() => {
  if (lastToastT !== null && T > lastToastT && T - lastToastT <= 8 * 900 && !storyActive) {
    sortedEvents.filter((e) => e.ts > lastToastT && e.ts <= T).slice(-3).forEach((e) => {
      const key = e.to === "COMPROMISED" ? "toast.comp" : e.to === "SUSPICIOUS" ? "toast.sus" : "toast.clean";
      toast(STATUS[e.to].k, tr(key, { d: e.device }), e.reason, e.device);
    });
  }
  lastToastT = T;
  updateBanner();
});

/* =================================================================== theme / language / presenter / menu */
function syncThemeIcon() { $("#theme-ic").setAttribute("href", `${SPRITE}#${document.documentElement.dataset.theme === "dark" ? "i-sun" : "i-moon"}`); }
function syncLang() { $("#lang-lbl").textContent = LANG === "en" ? "हि" : "EN"; }
$("#btn-theme").onclick = () => toggleTheme();
$("#btn-lang").onclick = () => setLang(LANG === "en" ? "hi" : "en");
addEventListener("themechange", () => { syncThemeIcon(); mapSig = ""; if (R) { renderAll(); rerenderOpenView(); } });
addEventListener("langchange", () => { syncLang(); mapSig = ""; if (R) { renderAll(); renderEvaluation(); rerenderOpenView(); } if (storyActive) { storySteps = buildStory(); storyShow(); } });
syncThemeIcon(); syncLang();
function rerenderOpenView() { if (["attack", "timeline"].includes(view)) viewRenderers[view]("open"); }
function togglePresenter() { document.body.classList.toggle("presenter"); mapSig = ""; mapState.vb = null; if (R) renderAll(); }
$("#btn-present").onclick = togglePresenter;
$("#btn-menu").onclick = () => $("#side").classList.toggle("open");
$$(".sn").forEach((b) => b.addEventListener("click", () => $("#side").classList.remove("open")));

addEventListener("keydown", (e) => {
  const typing = /INPUT|TEXTAREA|SELECT/.test(document.activeElement?.tagName || "");
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); openPalette(); return; }
  if (typing || !$("#palette").hidden) return;
  if (storyActive) {
    if (e.key === "ArrowRight") { e.preventDefault(); storyGo(1); }
    if (e.key === "ArrowLeft") { e.preventDefault(); storyGo(-1); }
    if (e.key === "Escape") storyStop();
    return;
  }
  const k = e.key.toLowerCase();
  if (k === "p") togglePresenter();
  if (k === "s") storyStart();
  if (k === "d") toggleTheme();
  if (k === "l") setLang(LANG === "en" ? "hi" : "en");
});

/* =================================================================== command palette */
let palItems = [], palSel = 0;
function paletteItems() {
  const views = [["overview", "nav.overview", "i-gauge"], ["matrix", "nav.matrix", "i-layers"], ["attack", "nav.attack", "i-crosshair"],
    ["timeline", "nav.timeline", "i-route"], ["devices", "nav.devices", "i-server"], ["incidents", "nav.incidents", "i-siren"],
    ["live", "nav.live", "i-zap"], ["whatif", "nav.whatif", "i-flask-conical"], ["evaluation", "nav.evaluation", "i-target"]]
    .map(([v, k, ic]) => ({ ic, label: tr(k), hint: "view", run: () => switchView(v) }));
  const acts = [
    { ic: "i-play", label: tr("btn.story"), hint: "S", run: storyStart },
    { ic: "i-zap", label: "Launch a live attack", hint: "lab", run: () => switchView("live") },
    { ic: "i-printer", label: tr("side.report"), hint: "PDF", run: () => open("/report?print=1", "_blank") },
    { ic: "i-database", label: tr("side.upload"), hint: "upload", run: openUpload },
    { ic: "i-moon", label: "Toggle dark / light theme", hint: "D", run: toggleTheme },
    { ic: "i-globe", label: LANG === "en" ? "हिंदी में बदलें" : "Switch to English", hint: "L", run: () => setLang(LANG === "en" ? "hi" : "en") },
    { ic: "i-maximize", label: "Presenter mode", hint: "P", run: togglePresenter },
    { ic: "i-bell-ring", label: soundOn ? "Turn alert sound off" : "Turn alert sound on", hint: "sound",
      run: () => { soundOn = !soundOn; localStorage.setItem("trinetra-sound", soundOn ? "1" : "0"); toast("info", soundOn ? "Alert sound on" : "Alert sound off", ""); } },
    { ic: "i-repeat", label: "Reset network map layout", hint: "map", run: resetLayout },
    { ic: "i-timer", label: "Jump to now", hint: "time", run: () => { stop(); setT(times.at(-1)); } },
    { ic: "i-hourglass", label: "Jump to the start of the test period", hint: "time", run: () => { stop(); setT(times[0]); } },
  ];
  const devs = (R?.devices || []).map((d) => ({ ic: devIcon(d), label: d.id, hint: vLabel(verdictAt(d.id).v), run: () => openDrawer(d.id), dev: d }));
  return [...acts, ...views, ...devs];
}
function openPalette() { $("#palette").hidden = false; $("#pal-q").value = ""; palSel = 0; renderPalette(); setTimeout(() => $("#pal-q").focus(), 10); }
function closePalette() { $("#palette").hidden = true; }
function renderPalette() {
  const q = $("#pal-q").value.toLowerCase().trim();
  palItems = paletteItems().filter((i) => !q || i.label.toLowerCase().includes(q) || (i.dev && i.dev.ip.includes(q))).slice(0, 12);
  palSel = Math.max(0, Math.min(palSel, palItems.length - 1));
  $("#pal-list").innerHTML = palItems.map((i, n) => `<li class="${n === palSel ? "sel" : ""}" data-n="${n}">${icon(i.ic)}<span>${esc(i.label)}</span><small>${esc(i.hint)}</small></li>`).join("")
    || `<li class="empty">No match</li>`;
  $$("#pal-list li[data-n]").forEach((li) => (li.onclick = () => { const it = palItems[+li.dataset.n]; closePalette(); it.run(); }));
}
$("#pal-q").addEventListener("input", () => { palSel = 0; renderPalette(); });
$("#pal-q").addEventListener("keydown", (e) => {
  if (e.key === "ArrowDown") { palSel = Math.min(palItems.length - 1, palSel + 1); renderPalette(); e.preventDefault(); }
  if (e.key === "ArrowUp") { palSel = Math.max(0, palSel - 1); renderPalette(); e.preventDefault(); }
  if (e.key === "Enter" && palItems[palSel]) { const it = palItems[palSel]; closePalette(); it.run(); }
  if (e.key === "Escape") closePalette();
});
$("#palette").addEventListener("click", (e) => { if (e.target.id === "palette") closePalette(); });
$("#btn-palette").onclick = openPalette;

/* =================================================================== map: zoom, pan, drag, minimap */
const mapState = { pos: null, width: 0, height: 0, W: 150, H: 52, vb: null };
const curSvg = () => $("#topology svg");
function setVB(svg, vb) { mapState.vb = vb; svg.setAttribute("viewBox", `${vb.x} ${vb.y} ${vb.w} ${vb.h}`); drawMinimap(); }
function fullVB() { return { x: 0, y: 0, w: mapState.width, h: mapState.height }; }
function svgPoint(svg, cx, cy) { const p = svg.createSVGPoint(); p.x = cx; p.y = cy; return p.matrixTransform(svg.getScreenCTM().inverse()); }
window.mapAfterRender = (svg, pos, width, height, W, H) => {
  Object.assign(mapState, { pos, width, height, W, H });
  setVB(svg, mapState.vb || fullVB());
  bindMap(svg);
};
function zoomBy(f, cx, cy) {
  const svg = curSvg(); if (!svg) return;
  const vb = { ...(mapState.vb || fullVB()) };
  const nw = Math.min(mapState.width * 1.3, Math.max(mapState.width * 0.22, vb.w * f)), k = nw / vb.w;
  cx = cx ?? vb.x + vb.w / 2; cy = cy ?? vb.y + vb.h / 2;
  setVB(svg, { x: cx - (cx - vb.x) * k, y: cy - (cy - vb.y) * k, w: nw, h: vb.h * k });
}
function animateVB(to) {
  const from = { ...(mapState.vb || fullVB()) }, t0 = performance.now();
  const step = (now) => {
    const k = Math.min(1, (now - t0) / 650), e = 1 - Math.pow(1 - k, 3), s = curSvg();
    if (s) setVB(s, { x: from.x + (to.x - from.x) * e, y: from.y + (to.y - from.y) * e, w: from.w + (to.w - from.w) * e, h: from.h + (to.h - from.h) * e });
    if (k < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}
function zoomTo(id) {
  const p = mapState.pos?.[id]; if (!p) return;
  const w = mapState.width * 0.6, h = mapState.height * 0.6;
  animateVB({ x: p.x + mapState.W / 2 - w / 2, y: p.y + mapState.H / 2 - h / 2, w, h });
}
function fitMap() { animateVB(fullVB()); }
function resetLayout() { window.mapCustomPos = {}; localStorage.removeItem("trinetra-map-pos"); mapState.vb = null; mapSig = ""; renderTopology(); }
function bindMap(svg) {
  svg.addEventListener("wheel", (e) => { e.preventDefault(); const p = svgPoint(svg, e.clientX, e.clientY); zoomBy(e.deltaY > 0 ? 1.12 : 0.89, p.x, p.y); }, { passive: false });
  svg.addEventListener("mousedown", (e) => {
    if (e.button !== 0) return;
    const node = e.target.closest(".node[data-id]");
    if (node) {                                       // drag a device
      const id = node.dataset.id, start = svgPoint(svg, e.clientX, e.clientY), p0 = { x: mapState.pos[id].x, y: mapState.pos[id].y };
      let moved = false;
      const mv = (ev) => {
        const s = curSvg(), q = svgPoint(s, ev.clientX, ev.clientY), dx = q.x - start.x, dy = q.y - start.y;
        if (!moved && Math.hypot(dx, dy) < 5) return;
        moved = true; hideTip();
        window.mapCustomPos[id] = { x: Math.round(p0.x + dx), y: Math.round(p0.y + dy) };
        mapSig = ""; renderTopology(); focusNode(id);
      };
      const up = () => { removeEventListener("mousemove", mv); removeEventListener("mouseup", up); if (moved) localStorage.setItem("trinetra-map-pos", JSON.stringify(window.mapCustomPos)); };
      addEventListener("mousemove", mv); addEventListener("mouseup", up);
      return;
    }
    const vb0 = { ...(mapState.vb || fullVB()) }, c0 = { x: e.clientX, y: e.clientY }, scale = vb0.w / svg.getBoundingClientRect().width;
    svg.classList.add("panning");
    const mv = (ev) => { const s = curSvg(); if (s) setVB(s, { ...vb0, x: vb0.x - (ev.clientX - c0.x) * scale, y: vb0.y - (ev.clientY - c0.y) * scale }); };
    const up = () => { removeEventListener("mousemove", mv); removeEventListener("mouseup", up); curSvg()?.classList.remove("panning"); };
    addEventListener("mousemove", mv); addEventListener("mouseup", up);
  });
}
function drawMinimap() {
  const mm = $("#minimap"); if (!mm || !mapState.pos) return;
  const { width, height, W, H } = mapState, vb = mapState.vb || fullVB();
  const zoomed = vb.w < width * 0.97 || vb.x > 2 || vb.y > 2 || vb.x < -2 || vb.y < -2;
  mm.classList.toggle("show", zoomed);
  if (!zoomed) return;
  let s = `<svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="xMidYMid meet">`;
  for (const [id, p] of Object.entries(mapState.pos)) {
    const v = id === "INTERNET" ? "CLEAN" : verdictAt(id).v;
    s += `<rect x="${p.x}" y="${p.y}" width="${p.w || W}" height="${H}" rx="12" fill="${v === "CLEAN" ? "#9fb7d6" : STATUS[v].color}"/>`;
  }
  mm.innerHTML = s + `<rect class="mm-vp" x="${vb.x}" y="${vb.y}" width="${vb.w}" height="${vb.h}" rx="10"/></svg>`;
}
$("#minimap").addEventListener("click", (e) => {
  const r = e.currentTarget.getBoundingClientRect(), vb = { ...(mapState.vb || fullVB()) };
  vb.x = ((e.clientX - r.left) / r.width) * mapState.width - vb.w / 2; vb.y = ((e.clientY - r.top) / r.height) * mapState.height - vb.h / 2;
  const s = curSvg(); if (s) setVB(s, vb);
});
$("#z-in").onclick = () => zoomBy(0.8);
$("#z-out").onclick = () => zoomBy(1.25);
$("#z-fit").onclick = fitMap;
$("#z-reset").onclick = resetLayout;

/* =================================================================== story mode */
let storySteps = [], storyIdx = 0, storyTimer = null;
function buildStory() {
  const hi = LANG === "hi", ev = R.evaluation;
  const steps = [{ ts: times[0], dev: null, title: hi ? "परीक्षण सप्ताह शुरू" : "The test week begins",
    text: hi ? `TRINETRA ने ${R.devices.length} डिवाइस का सामान्य व्यवहार 4 दिन में सीखा, बिना किसी हमले के उदाहरण के। अब अगले 3 दिन हर डिवाइस हर 15 मिनट पर जाँचा जाएगा।`
      : `TRINETRA learned the normal behaviour of ${R.devices.length} devices over 4 days, without a single attack example. Now every device is scored every 15 minutes for the next 3 days.` }];
  for (const e of sortedEvents.filter((x) => x.to !== "CLEAN"))
    steps.push({ ts: e.ts, dev: e.device, to: e.to, title: `${e.device} → ${vLabel(e.to)}`, text: storyCaption(R, e, LANG) });
  const c = R.devices.filter((d) => d.verdict === "COMPROMISED").length;
  steps.push({ ts: times.at(-1), dev: null, title: hi ? "नतीजा" : "The outcome",
    text: ev ? (hi ? `${ev.n_attacked} में से ${ev.tp} हैक हुए डिवाइस पकड़े गए और ${ev.n_clean} साफ़ डिवाइस में से ${ev.fp} को गलती से हैक घोषित किया गया। Patch rollout और planned change जैसे जाल पर कोई गलत फ़ैसला नहीं हुआ।`
      : `${ev.tp} of ${ev.n_attacked} attacked devices were caught and ${ev.fp} of ${ev.n_clean} clean devices were wrongly convicted. Benign traps such as the fleet-wide patch rollout and the planned router change did not fool the engine.`)
      : (hi ? `${c} डिवाइस हैक घोषित हुए।` : `${c} devices were convicted.`) });
  return steps;
}
function storyStart() {
  if (!R) return;
  stop(); closeDrawer(); switchView("overview");
  storySteps = buildStory(); storyIdx = 0; storyActive = true;
  $("#story").hidden = false; document.body.classList.add("story-on");
  storyShow();
}
function storyShow() {
  const s = storySteps[storyIdx];
  setT(s.ts);
  $("#story-step").textContent = `${storyIdx + 1} / ${storySteps.length}`;
  $("#story-time").textContent = fmt(s.ts) + " UTC";
  $("#story-title").innerHTML = s.to ? `${esc(s.dev)} ${badge(s.to)}` : esc(s.title);
  $("#story-text").textContent = s.text;
  $("#story-prog").style.width = `${((storyIdx + 1) / storySteps.length) * 100}%`;
  $("#story-open").hidden = !s.dev;
  $("#story-prev").disabled = storyIdx === 0;
  $("#story").classList.remove("pop"); void $("#story").offsetWidth; $("#story").classList.add("pop");
  requestAnimationFrame(() => {
    if (s.dev) { focusNode(s.dev); zoomTo(s.dev); } else { applyMapFilter(); fitMap(); }
  });
}
function storyGo(d) {
  const n = storyIdx + d;
  if (n >= storySteps.length) { storyStop(); return; }
  storyIdx = Math.max(0, n); storyShow();
}
function storyAutoToggle() {
  if (storyTimer) { clearInterval(storyTimer); storyTimer = null; $("#story-auto-ic").setAttribute("href", `${SPRITE}#i-play`); return; }
  $("#story-auto-ic").setAttribute("href", `${SPRITE}#i-pause`);
  storyTimer = setInterval(() => { if (storyIdx >= storySteps.length - 1) { storyAutoToggle(); return; } storyGo(1); }, 7000);
}
function storyStop() {
  storyActive = false; if (storyTimer) storyAutoToggle();
  $("#story").hidden = true; document.body.classList.remove("story-on");
  applyMapFilter(); fitMap();
}
$("#btn-story").onclick = storyStart;
$("#story-next").onclick = () => storyGo(1);
$("#story-prev").onclick = () => storyGo(-1);
$("#story-x").onclick = storyStop;
$("#story-auto").onclick = storyAutoToggle;
$("#story-open").onclick = () => { const s = storySteps[storyIdx]; if (s.dev) openDrawer(s.dev); };

/* =================================================================== ATT&CK heat-map */
viewRenderers.attack = () => {
  if (!R) return;
  const cells = {};
  for (const d of R.devices) for (const ev of R.evidence[d.id] || []) {
    if (ev.ts > T) continue;
    for (const [ta, techs] of Object.entries(ev.tactics)) for (const te of techs) {
      const c = ((cells[ta] ||= {})[te] ||= { devices: new Set(), first: ev.ts });
      c.devices.add(d.id); c.first = Math.min(c.first, ev.ts);
    }
  }
  const maxN = Math.max(1, ...Object.values(cells).flatMap((t) => Object.values(t).map((c) => c.devices.size)));
  const hit = STAGES.filter((s) => cells[s]).length;
  const nTech = Object.values(cells).reduce((a, t) => a + Object.keys(t).length, 0);
  $("#attack-view").innerHTML = `<div class="panel"><div class="ph"><div class="ph-l"><span class="ph-ico red">${icon("i-crosshair")}</span><div><h2>MITRE ATT&amp;CK coverage</h2>
    <p>Up to ${fmt(T)} · ${hit} of ${STAGES.length} tactics · ${nTech} techniques · darker cell = more devices</p></div></div>
    <a class="btn sm" href="https://attack.mitre.org/" target="_blank" rel="noopener">${icon("i-external-link")}attack.mitre.org</a></div>
    <div class="attck">${STAGES.map((s) => {
      const techs = Object.entries(cells[s] || {}).sort((a, b) => b[1].devices.size - a[1].devices.size);
      return `<div class="attck-col ${techs.length ? "on" : ""}"><div class="attck-h"><b>${esc(s)}</b><small>${techs.length} technique${techs.length === 1 ? "" : "s"}</small></div>
        ${techs.length ? techs.map(([te, c]) => {
          const a = 0.18 + 0.82 * (c.devices.size / maxN), dark = a > 0.55;
          return `<button class="attck-cell" style="background:rgba(208,59,59,${a.toFixed(2)});color:${dark ? "#fff" : "var(--ink)"}" data-devs="${esc([...c.devices].join(","))}" data-first="${c.first}" data-te="${esc(te)}">
            <span class="te-id">${esc(te.split(" ")[0])}</span><span class="te-n">${esc(te.split(" ").slice(1).join(" "))}</span><span class="te-d">${c.devices.size} device${c.devices.size > 1 ? "s" : ""}</span></button>`;
        }).join("") : `<div class="attck-empty">not observed</div>`}</div>`;
    }).join("")}</div>
    <p class="small dim" style="margin:14px 0 0">Every cell is a technique that TRINETRA attributed from behaviour (no signature). Hover for devices and first sighting; click to open the first device.</p></div>`;
  $$(".attck-cell").forEach((b) => {
    b.onmousemove = (e) => showTip(`<div class="tt-t">first seen ${fmt(+b.dataset.first)}</div><b>${esc(b.dataset.te)}</b><div style="margin-top:6px">${b.dataset.devs.split(",").map((x) => `<span class="chip">${esc(x)}</span>`).join("")}</div>`, e.clientX, e.clientY);
    b.onmouseleave = hideTip;
    b.onclick = () => openDrawer(b.dataset.devs.split(",")[0]);
  });
};

/* =================================================================== attack timeline (swimlanes) */
viewRenderers.timeline = () => {
  if (!R) return;
  const first = (d) => Math.min(...(R.evidence[d.id] || []).map((e) => e.ts), ...(eventsByDev[d.id] || []).map((e) => e.ts), 1e18);
  const rows = R.devices.filter((d) => (R.evidence[d.id] || []).some((e) => Object.keys(e.tactics).length) || (eventsByDev[d.id] || []).length)
    .sort((a, b) => first(a) - first(b));
  const box = $("#timeline-view");
  const W = Math.max(960, (box.clientWidth || 1100) - 46), LW = 168, RH = 54, TOP = 34, H = TOP + rows.length * RH + 10;
  const t0 = times[0], t1 = times.at(-1), x = (t) => LW + ((t - t0) / Math.max(1, t1 - t0)) * (W - LW - 24);
  let s = `<svg viewBox="0 0 ${W} ${H}" class="swim" role="img" aria-label="Attack timeline per device">`;
  for (let t = Math.ceil(t0 / 86400) * 86400; t <= t1; t += 86400)
    s += `<line x1="${x(t)}" x2="${x(t)}" y1="${TOP - 10}" y2="${H}" class="sw-day"/><text x="${x(t) + 6}" y="18" class="sw-dlbl">${DAYS[new Date(t * 1000).getUTCDay()]} 00:00</text>`;
  rows.forEach((d, r) => {
    const y = TOP + r * RH, v = verdictAt(d.id).v;
    s += `<rect x="0" y="${y + 4}" width="${W}" height="${RH - 8}" rx="12" class="sw-lane ${r % 2 ? "alt" : ""}"/>`;
    s += `<circle cx="16" cy="${y + RH / 2}" r="5" fill="${STATUS[v].color}"/><text x="30" y="${y + RH / 2 + 4}" class="sw-lbl" data-dev="${esc(d.id)}">${esc(d.id)}</text>`;
    s += `<line x1="${LW}" x2="${W - 20}" y1="${y + RH / 2}" y2="${y + RH / 2}" class="sw-axis"/>`;
    let lastLx = -99;
    for (const ev of (R.evidence[d.id] || []).filter((e) => e.ts <= T)) {
      const tac = Object.keys(ev.tactics), cx = x(ev.ts), rr = 3.5 + Math.min(6, ev.score / 2);
      const col = tac.length ? "#d03b3b" : ev.alarm ? "#e7a400" : "#8fb0d8";
      s += `<circle cx="${cx}" cy="${y + RH / 2}" r="${rr}" fill="${col}" fill-opacity="${tac.length ? 0.9 : 0.55}" stroke="var(--card)" stroke-width="1.5" class="sw-ev" data-dev="${esc(d.id)}" data-ts="${ev.ts}"/>`;
      if (tac.length && cx - lastLx > 46) { s += `<text x="${cx}" y="${y + RH / 2 - rr - 5}" class="sw-tac" text-anchor="middle">${tac.map((t) => TACTIC_ABBR[t] || t).slice(0, 3).join("·")}</text>`; lastLx = cx; }
    }
    for (const e of (eventsByDev[d.id] || []).filter((e) => e.ts <= T)) {
      const cx = x(e.ts), c = STATUS[e.to].color;
      s += `<g class="sw-flag" data-dev="${esc(d.id)}"><line x1="${cx}" x2="${cx}" y1="${y + 8}" y2="${y + RH - 8}" stroke="${c}" stroke-width="2"/><path d="M${cx} ${y + 8} h12 l-4 5 l4 5 h-12z" fill="${c}"/></g>`;
    }
  });
  if (T < t1) s += `<rect x="${x(T)}" y="${TOP - 6}" width="${x(t1) - x(T) + 4}" height="${H - TOP + 6}" style="fill:var(--card)" opacity=".7"/><line x1="${x(T)}" x2="${x(T)}" y1="${TOP - 10}" y2="${H}" stroke="#2a78d6" stroke-width="2"/>`;
  s += `</svg>`;
  box.innerHTML = `<div class="panel"><div class="ph"><div class="ph-l"><span class="ph-ico">${icon("i-route")}</span><div><h2>Attack timeline</h2>
    <p>One lane per device that showed evidence · dot size = evidence · red = mapped to an ATT&amp;CK stage · flag = verdict change</p></div></div></div>
    <div class="swim-wrap">${s}</div>
    <div class="legend">${Object.entries(TACTIC_ABBR).map(([k, a]) => `<span class="lg"><b class="mono">${a}</b> ${esc(k)}</span>`).join("")}</div></div>`;
  $$("#timeline-view .sw-ev").forEach((c) => {
    const ev = (R.evidence[c.dataset.dev] || []).find((e) => e.ts === +c.dataset.ts);
    c.onmousemove = (e) => showTip(`<div class="tt-t">${fmt(ev.ts)} UTC · evidence ${ev.score.toFixed(1)}</div><b class="mono">${esc(c.dataset.dev)}</b>
      <div style="margin-top:6px">${Object.entries(ev.tactics).map(([t, te]) => `<div><span class="chip red">${esc(t)}</span><span class="small dim">${esc(te[0])}</span></div>`).join("") || '<span class="small dim">no ATT&CK stage, anomaly only</span>'}</div>`, e.clientX, e.clientY);
    c.onmouseleave = hideTip;
    c.onclick = () => openDrawer(c.dataset.dev);
  });
  $$("#timeline-view .sw-lbl").forEach((t) => (t.onclick = () => openDrawer(t.dataset.dev)));
};

/* =================================================================== what-if lab */
const WI_DETS = ["zscore", "iforest", "autoenc", "sequence", "beacon", "graph", "config"];
const WI_DEFAULT = { k: 2, h: 4, consensus: true, corroboration: true, cusum: true, detectors: [...WI_DETS] };
let wi = JSON.parse(JSON.stringify(WI_DEFAULT)), wiBase = null, wiLast = null, wiTimer = null, wiSeq = 0;
viewRenderers.whatif = (why) => {
  if (why === "tick") return;
  const box = $("#whatif-view");
  if (box.dataset.built) return;
  box.dataset.built = "1";
  const det = R.meta.detectors;
  box.innerHTML = `<div class="wi-grid">
    <div class="panel wi-ctl"><div class="ph"><div class="ph-l"><span class="ph-ico">${icon("i-flask-conical")}</span><div><h2>What-if lab</h2><p>Change a knob, the whole benchmark week is re-scored</p></div></div></div>
      <div class="wi-slider"><label>CUSUM reference <b class="mono">k</b> <span class="mono" id="wi-k-v"></span></label><input type="range" id="wi-k" min="1" max="4" step="0.5"><small>Evidence below k per window is ignored. Lower = more sensitive.</small></div>
      <div class="wi-slider"><label>Alarm threshold <b class="mono">h</b> <span class="mono" id="wi-h-v"></span></label><input type="range" id="wi-h" min="1" max="10" step="1"><small>Accumulated evidence needed to raise an alarm.</small></div>
      <h3>False-alarm layers</h3>
      ${[["consensus", "Fleet consensus", "Patch rollouts on many peers are treated as normal"], ["corroboration", "Kill-chain corroboration", "Compromised needs ≥ 2 ATT&CK stages"], ["cusum", "CUSUM persistence", "Evidence must persist over windows"]]
        .map(([k, l, d]) => `<label class="switch"><input type="checkbox" data-wi="${k}"><span class="sw"></span><div><b>${l}</b><small>${d}</small></div></label>`).join("")}
      <h3>Detectors</h3><div class="wi-dets">${WI_DETS.map((d) => `<label class="chk"><input type="checkbox" data-det="${d}"><span>${esc(det[d])}</span></label>`).join("")}</div>
      <div class="wi-btns"><button class="btn sm" id="wi-reset">${icon("i-repeat")}Default settings</button><button class="btn primary sm" id="wi-run">${icon("i-play")}Re-score</button></div>
    </div>
    <div class="panel wi-out"><div id="wi-out"></div></div></div>`;
  const sync = () => {
    $("#wi-k").value = wi.k; $("#wi-h").value = wi.h; $("#wi-k-v").textContent = `= ${wi.k}`; $("#wi-h-v").textContent = `= ${wi.h}`;
    $$("[data-wi]").forEach((c) => (c.checked = wi[c.dataset.wi]));
    $$("[data-det]").forEach((c) => (c.checked = wi.detectors.includes(c.dataset.det)));
  };
  const changed = () => { clearTimeout(wiTimer); wiTimer = setTimeout(runWhatif, 500); };
  $("#wi-k").oninput = (e) => { wi.k = +e.target.value; $("#wi-k-v").textContent = `= ${wi.k}`; changed(); };
  $("#wi-h").oninput = (e) => { wi.h = +e.target.value; $("#wi-h-v").textContent = `= ${wi.h}`; changed(); };
  $$("[data-wi]").forEach((c) => (c.onchange = () => { wi[c.dataset.wi] = c.checked; changed(); }));
  $$("[data-det]").forEach((c) => (c.onchange = () => {
    wi.detectors = $$("[data-det]").filter((x) => x.checked).map((x) => x.dataset.det);
    if (!wi.detectors.length) { c.checked = true; wi.detectors = [c.dataset.det]; }
    changed();
  }));
  $("#wi-reset").onclick = () => { wi = JSON.parse(JSON.stringify(WI_DEFAULT)); sync(); runWhatif(); };
  $("#wi-run").onclick = runWhatif;
  sync(); runWhatif();
};
async function runWhatif() {
  const seq = ++wiSeq, out = $("#wi-out");
  out.innerHTML = `<div class="wi-loading"><span class="ov-ico">${icon("i-radar")}</span><b>Re-scoring 3 days × 22 devices…</b><span class="dim small">The first run also trains the engine (about 30 s). Later runs take a few seconds.</span></div>`;
  try {
    const r = await fetch("/api/whatif", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(wi) });
    const res = await r.json();
    if (seq !== wiSeq) return;
    const isDefault = JSON.stringify({ ...wi, detectors: [...wi.detectors].sort() }) === JSON.stringify({ ...WI_DEFAULT, detectors: [...WI_DEFAULT.detectors].sort() });
    if (isDefault) wiBase = res;
    if (!wiBase) {
      const rb = await fetch("/api/whatif", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(WI_DEFAULT) });
      wiBase = await rb.json();
    }
    wiLast = res;
    renderWhatifOut();
  } catch (e) { out.innerHTML = `<div class="empty">What-if failed: ${esc(e.message)}</div>`; }
}
function renderWhatifOut() {
  const r = wiLast.evaluation, b = wiBase.evaluation, pct = (v) => Math.round(v * 100) + "%";
  const metric = (label, val, base, fmtv, higherBetter, ic) => {
    const d = val - base, same = Math.abs(d) < 1e-9, good = higherBetter ? d > 0 : d < 0;
    return `<div class="metric"><div class="label">${icon(ic)}${label}</div><div class="value">${fmtv(val)}</div>
      <div class="delta ${same ? "" : good ? "up" : "down"}">${same ? "same as default" : `${d > 0 ? "▲" : "▼"} ${fmtv(Math.abs(d))} vs default`}</div></div>`;
  };
  const att = wiLast.devices.filter((d) => d.truth === "attacked"), clean = wiLast.devices.filter((d) => d.truth === "clean" && d.verdict !== "CLEAN");
  $("#wi-out").innerHTML = `<div class="ph"><div class="ph-l"><span class="ph-ico">${icon("i-target")}</span><div><h2>Result</h2><p>Benchmark seed ${wiLast.seed} · re-scored in ${wiLast.runtime_s}s</p></div></div></div>
    <div class="metric-grid wi-m">
      ${metric("Recall", r.recall, b.recall, pct, true, "i-target")}${metric("Precision", r.precision, b.precision, pct, true, "i-badge-check")}
      ${metric("Wrongly convicted", r.fp, b.fp, (v) => String(Math.round(v)), false, "i-shield-x")}${metric("Clean devices alarmed", r.clean_devices_with_any_alarm, b.clean_devices_with_any_alarm, (v) => String(Math.round(v)), false, "i-bell-ring")}
      ${metric("Alarm windows / device-day", r.false_alarm_windows_per_device_day, b.false_alarm_windows_per_device_day, (v) => v.toFixed(2), false, "i-activity")}
      ${metric("Median time to detect", r.median_ttd_min ?? 0, b.median_ttd_min ?? 0, (v) => `${Math.round(v)} min`, false, "i-timer")}</div>
    <h3>Attacked devices</h3><div class="wi-devs">${att.map((d) => `<span class="wi-dev ${d.verdict === "COMPROMISED" ? "ok" : "miss"}">${icon(d.verdict === "COMPROMISED" ? "i-check" : "i-x")}<b class="mono">${esc(d.device)}</b><small>${d.verdict === "COMPROMISED" ? `caught · ${d.ttd_min} min` : "missed"}</small></span>`).join("")}</div>
    <h3>Clean devices that raised an alarm</h3><div class="wi-devs">${clean.length ? clean.map((d) => `<span class="wi-dev ${d.verdict === "COMPROMISED" ? "miss" : "warn"}">${icon(d.verdict === "COMPROMISED" ? "i-shield-x" : "i-triangle-alert")}<b class="mono">${esc(d.device)}</b><small>${vLabel(d.verdict)}</small></span>`).join("") : `<span class="dim">None. ${icon("i-circle-check")}</span>`}</div>`;
}

/* =================================================================== live attack lab */
let liveSeq = -1, livePoll = null, scenarios = null;
viewRenderers.live = async (why) => {
  if (why === "tick") return;
  if (!scenarios) scenarios = await (await fetch("/api/scenarios")).json();
  renderLiveView();
};
const SC_ICON = { A1: "i-laptop", A2: "i-router", A3: "i-brick-wall", A4: "i-globe" };
function renderLiveView(state) {
  const box = $("#live-view"), running = state?.running;
  box.innerHTML = `<div class="panel live-hero"><div class="ph"><div class="ph-l"><span class="ph-ico red">${icon("i-zap")}</span><div><h2>Live attack lab</h2>
      <p>Pick an attack. A fresh enterprise week is generated, the engine learns 4 normal days, then the attack is replayed live, window by window. Nothing is pre-computed.</p></div></div>
      ${liveMode ? `<button class="btn sm" id="live-back">${icon("i-repeat")}Back to benchmark</button>` : ""}</div>
    ${running || state ? `<div class="live-status"><div class="ls-top"><span class="live-dot ${running ? "on" : ""}"></span><b>${esc(state.phase || "")}</b><span class="mono">${Math.round((state.progress || 0) * 100)}%</span>
      ${running ? `<button class="btn sm" id="live-stop">${icon("i-x")}Stop</button>` : ""}</div><div class="progress"><div style="width:${Math.round((state.progress || 0) * 100)}%"></div></div>
      ${state.error ? `<div class="up-err">${esc(state.error)}</div>` : ""}</div>` : ""}
    <div class="sc-grid">${(scenarios || []).map((s) => `<article class="sc"><span class="sc-ico">${icon(SC_ICON[s.id])}</span><div class="sc-id mono">${s.id}</div><h3>${esc(s.title)}</h3><p>${esc(s.story)}</p>
      <button class="btn primary sm" data-sc="${s.id}" ${running ? "disabled" : ""}>${icon("i-zap")}Launch this attack</button></article>`).join("")}</div></div>`;
  $$("[data-sc]").forEach((b) => (b.onclick = () => startLive(b.dataset.sc)));
  $("#live-stop") && ($("#live-stop").onclick = () => fetch("/api/live/stop", { method: "POST" }));
  $("#live-back") && ($("#live-back").onclick = backToBenchmark);
}
async function startLive(id) {
  const r = await fetch("/api/live/start", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ scenario: id }) });
  if (r.status === 409) { toast("warn", "A live run is already in progress", ""); return; }
  liveMode = true; liveSeq = -1; lastToastT = null;
  toast("info", `Live attack ${id} launched`, "The engine is learning the baseline first (about 25 s), then the attack streams in.");
  pollLive();
}
async function pollLive() {
  clearTimeout(livePoll);
  const s = await (await fetch(`/api/live/state?since=${liveSeq}`)).json();
  if (s.data) {
    liveSeq = s.seq;
    const first = !R || R.meta?.source !== "live";
    R = s.data; T = 0; prepare(); renderAll();
    if (first && view === "live") switchView("overview");
  }
  window._liveState = s;
  if (view === "live") renderLiveView(s);
  updateBanner();
  if (s.running) livePoll = setTimeout(pollLive, 700);
  else if (s.data?.evaluation) toast(s.data.evaluation.recall === 1 ? "good" : "warn", "Live run finished",
    `${s.data.evaluation.tp}/${s.data.evaluation.n_attacked} attacked devices caught · ${s.data.evaluation.fp} false convictions`);
}
async function backToBenchmark() {
  liveMode = false; clearTimeout(livePoll);
  R = await (await fetch("/api/results")).json(); T = 0; lastToastT = null; prepare(); renderAll();
  if (view === "live") renderLiveView();
}
function updateBanner() {
  const b = $("#data-banner"); if (!R) return;
  const src = R.meta?.source;
  if (src === "live") {
    const s = window._liveState || {};
    b.hidden = false; b.className = "data-banner live";
    b.innerHTML = `<span class="live-dot ${s.running ? "on" : ""}"></span><b>LIVE</b> attack ${esc(R.meta.scenario || "")} · ${esc(s.phase || "")} · ${Math.round((s.progress || 0) * 100)}%
      <span class="grow"></span>${s.running ? `<button class="btn sm" id="bn-stop">Stop</button>` : ""}<button class="btn sm" id="bn-back">Back to benchmark</button>`;
    $("#bn-back").onclick = backToBenchmark;
    $("#bn-stop") && ($("#bn-stop").onclick = () => fetch("/api/live/stop", { method: "POST" }));
  } else if (src === "real") {
    b.hidden = false; b.className = "data-banner real";
    b.innerHTML = `${icon("i-database")}<b>Your data</b> · ${(R.meta.uploaded || []).map(esc).join(", ")} · ${R.meta.n_events.toLocaleString()} events<span class="grow"></span><button class="btn sm" id="bn-demo">Back to benchmark</button>`;
    $("#bn-demo").onclick = async () => { await fetch("/api/restore_demo", { method: "POST" }); backToBenchmark(); };
  } else { b.hidden = true; }
}

/* =================================================================== upload */
let upFiles = [];
const KINDS = [["ubt", "UBT events (.jsonl)"], ["inventory", "Inventory (.json)"], ["zeek", "Zeek conn / dns log"], ["slips", "Slips alerts.json"], ["syslog", "Syslog (router / firewall / host)"], ["config", "Config backup"]];
function guessKind(name) {
  const n = name.toLowerCase();
  if (n === "inventory.json") return "inventory";
  if (n.endsWith(".jsonl")) return "ubt";
  if (n.includes("alerts") && n.endsWith(".json")) return "slips";
  if ((n.includes("conn") || n.includes("dns")) && (n.endsWith(".log") || n.endsWith(".json"))) return "zeek";
  if (n.endsWith(".cfg") || n.endsWith(".conf") || n.includes("config")) return "config";
  return "syslog";
}
function openUpload() { $("#upload").hidden = false; }
function addFiles(list) {
  for (const f of list) upFiles.push({ file: f, kind: guessKind(f.name), device: "", dtype: "router" });
  renderUpList();
}
function renderUpList() {
  $("#up-list").innerHTML = upFiles.map((u, i) => `<li><span class="up-ico">${icon(u.kind === "ubt" || u.kind === "inventory" ? "i-database" : u.kind === "zeek" || u.kind === "slips" ? "i-network" : u.kind === "config" ? "i-file-cog" : "i-scroll-text")}</span>
    <div class="up-name"><b>${esc(u.file.name)}</b><small>${(u.file.size / 1024 / 1024).toFixed(2)} MB</small></div>
    <select data-i="${i}" data-f="kind">${KINDS.map(([k, l]) => `<option value="${k}" ${u.kind === k ? "selected" : ""}>${l}</option>`).join("")}</select>
    ${u.kind === "syslog" || u.kind === "config" ? `<input data-i="${i}" data-f="device" placeholder="Device name, e.g. RTR-EDGE" value="${esc(u.device)}">
      <select data-i="${i}" data-f="dtype">${["router", "firewall", "host"].map((t) => `<option ${u.dtype === t ? "selected" : ""}>${t}</option>`).join("")}</select>` : ""}
    <button class="btn icon sm" data-rm="${i}" aria-label="Remove">${icon("i-x")}</button></li>`).join("");
  $$("#up-list [data-f]").forEach((el_) => (el_.oninput = () => { upFiles[+el_.dataset.i][el_.dataset.f] = el_.value; if (el_.dataset.f === "kind") renderUpList(); }));
  $$("#up-list [data-rm]").forEach((b) => (b.onclick = () => { upFiles.splice(+b.dataset.rm, 1); renderUpList(); }));
  $("#up-go").disabled = !upFiles.length;
}
const drop = $("#drop");
drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
drop.addEventListener("dragleave", () => drop.classList.remove("over"));
drop.addEventListener("drop", (e) => { e.preventDefault(); drop.classList.remove("over"); addFiles(e.dataTransfer.files); });
$("#up-files").addEventListener("change", (e) => { addFiles(e.target.files); e.target.value = ""; });
$("#up-frac").oninput = (e) => ($("#frac-v").textContent = e.target.value + "%");
$("#btn-upload").onclick = openUpload;
$("#up-x").onclick = () => ($("#upload").hidden = true);
$("#upload").addEventListener("click", (e) => { if (e.target.id === "upload") $("#upload").hidden = true; });
$("#up-go").onclick = async () => {
  const fd = new FormData();
  fd.append("meta", JSON.stringify(upFiles.map((u) => ({ kind: u.kind, device: u.device, dtype: u.dtype }))));
  fd.append("train_frac", $("#up-frac").value / 100);
  upFiles.forEach((u, i) => fd.append(`file${i}`, u.file));
  $("#up-go").disabled = true; $("#up-err").hidden = true;
  const r = await fetch("/api/upload", { method: "POST", body: fd });
  const j = await r.json().catch(() => ({}));
  if (r.status !== 202) { $("#up-err").hidden = false; $("#up-err").textContent = j.error || "Upload failed"; $("#up-go").disabled = false; return; }
  $("#upload").hidden = true; upFiles = []; renderUpList();
  liveMode = false; T = 0; showOverlay(); poll();
};

/* close the progress overlay when an analysis failed */
$("#overlay").addEventListener("click", () => { if (/^Error/.test($("#progress-msg").textContent)) $("#overlay").classList.remove("show"); });
