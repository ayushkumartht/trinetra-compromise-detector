"use strict";
/* TRINETRA console · light theme · vanilla JS, no dependencies, works offline. */

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const SPRITE = "/static/img/icons.svg";
const icon = (id, cls = "ic") => `<svg class="${cls}" aria-hidden="true"><use href="${SPRITE}#${id}"/></svg>`;
const SVGNS = "http://www.w3.org/2000/svg";

const STATUS = {
  COMPROMISED: { cls: "v-bad", k: "bad", ic: "i-shield-alert", label: "Compromised", color: "#d03b3b", ink: "#a32020", soft: "#fdecec", rank: 2 },
  SUSPICIOUS: { cls: "v-warn", k: "warn", ic: "i-triangle-alert", label: "Suspicious", color: "#fab219", ink: "#7a5300", soft: "#fff4d6", rank: 1 },
  CLEAN: { cls: "v-good", k: "good", ic: "i-circle-check", label: "Clean", color: "#0ca30c", ink: "#066d06", soft: "#e5f6e5", rank: 0 },
};
const TYPE_LABEL = { host: "System", firewall: "Firewall", router: "Router", network: "Network sensor" };
const TYPE_ORDER = { firewall: 0, router: 1, network: 2, host: 3 };
const STAGES = ["Execution", "Persistence", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
  "Collection", "Command and Control", "Exfiltration", "Impact"];
const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const devIcon = (d) => d.type === "firewall" ? "i-brick-wall" : d.type === "router" ? "i-router" : d.type === "network" ? "i-radio-tower"
  : d.role === "server" ? "i-server" : "i-laptop";

let R = null, T = 0, times = [], playTimer = null, openDevice = null, view = "overview", mapFilter = "all", mapSig = "";
let devById = {}, eventsByDev = {}, sortedEvents = [];

/* ------------------------------------------------------------------ helpers */
const p2 = (n) => String(n).padStart(2, "0");
function fmt(ts, day = true) {
  const d = new Date(ts * 1000), hm = `${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}`;
  return day ? `${DAYS[d.getUTCDay()]} ${p2(d.getUTCDate())}, ${hm}` : hm;
}
const vLabel = (v) => (typeof tr === "function" ? tr(`v.${v}`) : STATUS[v].label);
const badge = (v) => `<span class="v ${STATUS[v].cls}">${icon(STATUS[v].ic)}${vLabel(v)}</span>`;
window.mapCustomPos = JSON.parse(localStorage.getItem("trinetra-map-pos") || "{}");
function verdictAt(id, at = T) {
  let v = "CLEAN", reason = "Behaviour within the learned baseline", ts = null;
  for (const e of eventsByDev[id] || []) { if (e.ts > at) break; v = e.to; reason = e.reason; ts = e.ts; }
  return { v, reason, ts };
}
function tacticsAt(id) {
  const s = new Set();
  for (const ev of R.evidence[id] || []) if (ev.ts <= T) Object.keys(ev.tactics).forEach((t) => s.add(t));
  return [...s];
}
const tip = $("#tooltip");
function showTip(html, x, y) {
  tip.innerHTML = html; tip.classList.add("show");
  const w = tip.offsetWidth, h = tip.offsetHeight;
  tip.style.left = Math.min(x + 16, innerWidth - w - 10) + "px";
  tip.style.top = (y - h - 14 < 8 ? y + 18 : y - h - 14) + "px";
}
const hideTip = () => tip.classList.remove("show");
function el(tag, attrs = {}, parent) {
  const n = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  if (parent) parent.appendChild(n);
  return n;
}
const txt = (parent, x, y, s, attrs = {}) => { const t = el("text", { x, y, ...attrs }, parent); t.textContent = s; return t; };
function svgIcon(parent, id, x, y, size, color) {
  const s = el("svg", { x, y, width: size, height: size, class: "nico", stroke: color }, parent);
  el("use", { href: `${SPRITE}#${id}` }, s);
  return s;
}

/* ------------------------------------------------------------------ load */
async function load() {
  if (typeof applyI18n === "function") applyI18n();
  const r = await fetch("/api/results");
  if (r.status === 404) { showOverlay(); poll(); return; }
  R = await r.json();
  prepare();
  renderAll();
  const h = new URLSearchParams(location.hash.slice(1));
  if (h.get("view")) switchView(h.get("view"));
  if (h.get("t") === "start") setT(times[0]);
  if (h.get("device") && devById[h.get("device")]) openDrawer(h.get("device"));
}
function prepare() {
  devById = Object.fromEntries(R.devices.map((d) => [d.id, d]));
  sortedEvents = [...R.verdict_events].sort((a, b) => a.ts - b.ts);
  eventsByDev = {};
  for (const e of sortedEvents) (eventsByDev[e.device] ||= []).push(e);
  times = (R.timeline[R.devices[0].id] || []).map((x) => x[0]);
  $("#slider").max = Math.max(0, times.length - 1);
  if (!T || T > times.at(-1) || T < times[0]) T = times.at(-1);
  $("#slider").value = idxOf(T);
  const m = R.meta;
  $("#engine-meta").innerHTML = `<b>${m.n_events.toLocaleString()}</b> events · ${R.devices.length} devices<br>${m.source}${m.seed ? " · seed " + m.seed : ""} · ${m.runtime_s}s`;
  mapSig = "";
  renderTimelineTicks();
  renderEvaluation();
}
const idxOf = (ts) => Math.max(0, times.findIndex((t) => t >= ts));
function showOverlay() { $("#overlay").classList.add("show"); }
async function poll() {
  const s = await (await fetch("/api/status")).json();
  $("#progress-bar").style.width = Math.round(s.progress * 100) + "%";
  $("#progress-pct").textContent = Math.round(s.progress * 100) + "%";
  $("#progress-msg").textContent = s.error ? "Error: " + s.error : s.message || "";
  if (s.running || (!s.has_results && !s.error)) { setTimeout(poll, 700); return; }
  if (!s.error) { $("#overlay").classList.remove("show"); load(); }
}

/* ------------------------------------------------------------------ timeline bar */
function renderTimelineTicks() {
  const t0 = times[0], t1 = times.at(-1), pct = (t) => ((t - t0) / Math.max(1, t1 - t0)) * 100;
  $("#tl-ticks").innerHTML = sortedEvents.map((e) => `<span class="tl-tick ${e.to === "COMPROMISED" ? "c" : e.to === "SUSPICIOUS" ? "s" : "b"}"
    style="left:${pct(e.ts)}%" data-ts="${e.ts}" data-dev="${esc(e.device)}" data-to="${e.to}"></span>`).join("");
  $$("#tl-ticks .tl-tick").forEach((t) => {
    t.addEventListener("click", () => { stop(); setT(+t.dataset.ts); });
    t.addEventListener("mousemove", (e) => showTip(`<div class="tt-t">${fmt(+t.dataset.ts)} UTC</div><b class="mono">${esc(t.dataset.dev)}</b> → ${badge(t.dataset.to)}`, e.clientX, e.clientY));
    t.addEventListener("mouseleave", hideTip);
  });
  let days = "";
  for (let t = Math.ceil(t0 / 86400) * 86400; t <= t1; t += 86400)
    days += `<span style="left:${pct(t)}%;${pct(t) < 4 ? "transform:none" : ""}">${DAYS[new Date(t * 1000).getUTCDay()]} 00:00</span>`;
  $("#tl-days").innerHTML = days;
}
function setT(ts) { T = times[idxOf(ts)]; $("#slider").value = idxOf(ts); renderAll(); }

/* ------------------------------------------------------------------ render */
function renderAll() {
  const i = idxOf(T), n = Math.max(1, times.length - 1);
  $("#slider").style.setProperty("--p", `${(i / n) * 100}%`);
  $("#clock").textContent = fmt(T) + " UTC";
  renderStatus(); renderKpis(); renderTopology(); renderFeed(); renderIncidentSummary();
  if (view === "devices") renderDeviceTable();
  if (view === "incidents") renderIncidents();
  if (view === "matrix") renderMatrix();
  window.viewRenderers?.[view]?.("tick");
  if (openDevice) renderDrawer();
  (window.onRendered || []).forEach((f) => f());
}
function counts() {
  const c = { COMPROMISED: [], SUSPICIOUS: [], CLEAN: [] };
  R.devices.forEach((d) => c[verdictAt(d.id).v].push(d.id));
  return c;
}
function renderStatus() {
  const c = counts(), s = $("#status");
  let cls = "", ic = "i-shield-check", t, sub;
  if (c.COMPROMISED.length) {
    cls = "compromised"; ic = "i-siren";
    t = tr("status.comp", { n: c.COMPROMISED.length });
    sub = tr("status.sub.comp", { list: c.COMPROMISED.join(", ") }) + (c.SUSPICIOUS.length ? tr("status.sub.review", { list: c.SUSPICIOUS.join(", ") }) : "");
  } else if (c.SUSPICIOUS.length) {
    cls = "suspicious"; ic = "i-triangle-alert"; t = tr("status.sus"); sub = tr("status.sub.sus", { list: c.SUSPICIOUS.join(", ") });
  } else { t = tr("status.clean"); sub = tr("status.sub.clean", { n: R.devices.length }); }
  const last = sortedEvents.filter((e) => e.ts <= T).at(-1);
  s.className = "status " + cls;
  s.innerHTML = `<span class="s-ico">${icon(ic)}</span><div><div class="t">${esc(t)}</div><div class="s">${esc(sub)}</div></div>
    <div class="when">${tr("status.last")}<b>${last ? fmt(last.ts) : "–"}</b></div>`;
  const openCrit = R.incidents.filter((i) => i.severity === "critical" && i.devices.some((d) => verdictAt(d).v === "COMPROMISED")).length;
  $("#inc-n").textContent = openCrit || "";
}
function renderKpis() {
  const c = counts(), byType = {};
  R.devices.forEach((d) => (byType[d.type] = (byType[d.type] || 0) + 1));
  const typeTxt = ["host", "firewall", "router", "network"].filter((t) => byType[t]).map((t) => `${byType[t]} ${t === "host" ? "systems" : t === "network" ? "sensor" : t + "s"}`).join(" · ");
  const openInc = R.incidents.filter((i) => i.devices.some((d) => verdictAt(d).v !== "CLEAN")).length;
  const k = (ic, cls, label, value, detail) => `<div class="kpi"><span class="k-ico ${cls}">${icon(ic)}</span><div><div class="label">${label}</div><div class="value">${value}</div><div class="detail">${detail}</div></div></div>`;
  $("#kpis").innerHTML = k("i-network", "", tr("kpi.monitored"), R.devices.length, typeTxt) +
    k("i-shield-alert", "bad", tr("kpi.compromised"), c.COMPROMISED.length, tr("kpi.d.comp")) +
    k("i-triangle-alert", "warn", tr("kpi.suspicious"), c.SUSPICIOUS.length, tr("kpi.d.sus")) +
    k("i-circle-check", "good", tr("kpi.clean"), c.CLEAN.length, tr("kpi.d.clean")) +
    k("i-siren", "", tr("kpi.incidents"), openInc, `${(R.meta.n_events / 1000).toFixed(0)}k events · 8 detectors`);
}

/* ------------------------------------------------------------------ topology (interactive) */
function attackPaths() {
  const out = [];
  for (const inc of R.incidents.filter((i) => i.severity === "critical")) {
    const seq = inc.devices.filter((d) => devById[d].type !== "network" && verdictAt(d).v === "COMPROMISED")
      .sort((a, b) => (devById[a].compromised_at || 0) - (devById[b].compromised_at || 0));
    if (seq.length && ["firewall", "router"].includes(devById[seq[0]].type)) out.push(["INTERNET", seq[0]]);
    for (let i = 1; i < seq.length; i++) out.push([seq[i - 1], seq[i]]);
  }
  return out;
}
function renderTopology() {
  const sig = R.devices.map((d) => verdictAt(d.id).v[0]).join("") + attackPaths().map((p) => p.join(">")).join("|");
  if (sig === mapSig && $("#topology svg")) return;          // unchanged: keep animations running smoothly
  mapSig = sig;
  const W = 150, H = 52, GAP = 12, COLS = 4, hx = 640;
  const groups = { firewall: [], router: [], network: [], host: [] };
  R.devices.forEach((d) => groups[d.type].push(d));
  groups.host.sort((a, b) => (a.role === b.role ? a.id.localeCompare(b.id) : a.role === "server" ? -1 : 1));
  const hostRows = Math.ceil(groups.host.length / COLS), hostH = hostRows * (H + GAP) - GAP;
  const height = Math.max(hostH + 120, 4 * (H + GAP) + 100, 330), width = hx + COLS * (W + GAP) + 10;
  const svg = el("svg", { viewBox: `0 0 ${width} ${height}`, role: "img", "aria-label": "Interactive network map" });
  const pos = {};
  const column = (list, x) => { const tot = list.length * (H + GAP) - GAP; list.forEach((d, i) => (pos[d.id] = { x, y: (height - tot) / 2 + 14 + i * (H + GAP) })); };
  column(groups.firewall, 150); column(groups.router, 320); column(groups.network, 490);
  const hy = (height - hostH) / 2 + 22;
  groups.host.forEach((d, i) => (pos[d.id] = { x: hx + (i % COLS) * (W + GAP), y: hy + Math.floor(i / COLS) * (H + GAP) }));
  pos.INTERNET = { x: 16, y: height / 2 - H / 2 + 14, w: 108 };
  for (const [id, p] of Object.entries(window.mapCustomPos || {})) if (pos[id]) { pos[id].x = p.x; pos[id].y = p.y; }   // user-dragged layout

  const links = el("g", {}, svg);
  const R_ = (id) => ({ x: pos[id].x + (pos[id].w || W), y: pos[id].y + H / 2 }), L_ = (id) => ({ x: pos[id].x, y: pos[id].y + H / 2 });
  const curve = (a, b, ids, extraCls = "") => {
    const p = el("path", { d: `M${a.x},${a.y} C${(a.x + b.x) / 2},${a.y} ${(a.x + b.x) / 2},${b.y} ${b.x},${b.y}`, class: "link " + extraCls, "data-ids": ids.join(" ") }, links);
    const dot = el("circle", { r: 2.6, fill: "#2a78d6", opacity: .7, class: "pkt", "data-ids": ids.join(" ") }, links);
    el("animateMotion", { dur: `${(2.4 + Math.random() * 1.6).toFixed(2)}s`, begin: `-${(Math.random() * 2).toFixed(2)}s`, repeatCount: "indefinite", path: p.getAttribute("d") }, dot);
  };
  (groups.firewall.length ? groups.firewall : groups.router).forEach((d) => curve(R_("INTERNET"), L_(d.id), ["INTERNET", d.id]));
  groups.firewall.forEach((f) => groups.router.forEach((r) => curve(R_(f.id), L_(r.id), [f.id, r.id])));
  groups.router.forEach((r) => groups.network.forEach((n) => curve(R_(r.id), L_(n.id), [r.id, n.id])));
  const panel = { x: hx - 14, y: hy - 32, w: COLS * (W + GAP) + 16, h: hostH + 46 };
  (groups.network.length ? groups.network : groups.router).forEach((n) => curve(R_(n.id), { x: panel.x, y: panel.y + panel.h / 2 }, [n.id, ...groups.host.map((h) => h.id)]));
  el("rect", { x: panel.x, y: panel.y, width: panel.w, height: panel.h, rx: 18, class: "panel-rect", "stroke-dasharray": "5 5" }, svg);
  const grpLabel = (x, y, ic, label) => { svgIcon(svg, ic, x, y - 11, 14, "#898781"); txt(svg, x + 19, y, label, { fill: "#898781", "font-size": 11, "font-weight": 700, "letter-spacing": 1 }); };
  grpLabel(panel.x + 14, panel.y + 19, "i-laptop", `SYSTEMS · ${groups.host.length}`);
  if (groups.firewall.length) grpLabel(150, 26, "i-brick-wall", "FIREWALLS");
  if (groups.router.length) grpLabel(320, 26, "i-router", "ROUTERS");
  if (groups.network.length) grpLabel(490, 26, "i-radio-tower", "SENSORS");

  // Internet node
  const ig = el("g", { class: "node", "data-id": "INTERNET" }, svg);
  el("rect", { x: pos.INTERNET.x, y: pos.INTERNET.y, width: 108, height: H, rx: 26, class: "box clean", filter: "url(#f-node)" }, ig);
  svgIcon(ig, "i-globe", pos.INTERNET.x + 14, pos.INTERNET.y + 15, 22, "#2a78d6");
  txt(ig, pos.INTERNET.x + 44, pos.INTERNET.y + 31, "Internet", { class: "t-main", "font-size": 13, "font-weight": 700 });

  // attack paths
  const atk = el("g", {}, svg);
  for (const [a, b] of attackPaths()) {
    let d;
    if (a === "INTERNET") d = `M${R_("INTERNET").x},${R_("INTERNET").y} L${L_(b).x},${L_(b).y}`;
    else { const pa = pos[a], pb = pos[b], ax = pa.x + W / 2, bx = pb.x + W / 2; d = `M${ax},${pa.y} C${ax},6 ${bx},6 ${bx},${pb.y}`; }
    el("path", { d, class: "attack-link", "data-ids": `${a} ${b}` }, atk);
    for (const delay of [0, 1.1]) {
      const dot = el("circle", { r: 3.6, fill: "#d03b3b", class: "pkt-atk", "data-ids": `${a} ${b}` }, atk);
      el("animateMotion", { dur: "2.2s", begin: `-${delay}s`, repeatCount: "indefinite", path: d }, dot);
    }
  }
  // device nodes
  for (const d of R.devices) {
    const p = pos[d.id], v = verdictAt(d.id).v, S = STATUS[v], bad = v === "COMPROMISED", sus = v === "SUSPICIOUS";
    const g = el("g", { class: "node", tabindex: 0, role: "button", "aria-label": `${d.id} ${S.label}`, "data-id": d.id, "data-v": v }, svg);
    if (bad) el("rect", { x: p.x - 5, y: p.y - 5, width: W + 10, height: H + 10, rx: 16, fill: "none", stroke: S.color, class: "ring" }, g);
    el("rect", { x: p.x, y: p.y, width: W, height: H, rx: 13, class: "box" + (bad || sus ? "" : " clean"), filter: "url(#f-node)",
      stroke: bad ? S.color : "#e7b43c", "stroke-width": bad || sus ? 1.6 : 1 }, g);
    el("rect", { x: p.x + 9, y: p.y + 10, width: 32, height: 32, rx: 10, class: "chip-bg " + S.k }, g);
    svgIcon(g, devIcon(d), p.x + 16, p.y + 17, 18, bad ? "#d03b3b" : sus ? "#b37800" : "#2a78d6");
    txt(g, p.x + 50, p.y + 23, d.id.length > 13 ? d.id.slice(0, 12) + "…" : d.id, { class: "t-main", "font-size": 12.5, "font-weight": 700 });
    txt(g, p.x + 50, p.y + 39, v === "CLEAN" ? (d.role === "server" ? "Server" : TYPE_LABEL[d.type]) : vLabel(v), { class: "t-sub " + S.k, "font-size": 11, "font-weight": v === "CLEAN" ? 500 : 700 });
    if (bad || sus) { el("circle", { cx: p.x + W - 12, cy: p.y + 12, r: 5, fill: S.color, stroke: "#fff", "stroke-width": 2 }, g); }
    g.addEventListener("click", () => openDrawer(d.id));
    g.addEventListener("keydown", (e) => e.key === "Enter" && openDrawer(d.id));
    g.addEventListener("mouseenter", () => focusNode(d.id));
    g.addEventListener("mouseleave", () => { applyMapFilter(); hideTip(); });
    g.addEventListener("mousemove", (e) => showTip(`<div class="tt-t">${esc(TYPE_LABEL[d.type])} · ${esc(d.ip)}</div><b class="mono">${esc(d.id)}</b> ${badge(v)}
      <div style="margin-top:6px;color:#52514e">${esc(verdictAt(d.id).reason)}</div><div class="tt-t" style="margin-top:6px">Click for the forensic report</div>`, e.clientX, e.clientY));
  }
  $("#topology").replaceChildren(svg);
  window.mapAfterRender?.(svg, pos, width, height, W, H);
  $("#map-legend").innerHTML = `${badge("CLEAN")}${badge("SUSPICIOUS")}${badge("COMPROMISED")}<span class="lg"><i class="sw-atk"></i>attack path, in order of compromise</span><span class="lg">${icon("i-circle-dot")}moving dots = live traffic</span>`;
  applyMapFilter();
}
function focusNode(id) {
  const svg = $("#topology svg");
  const connected = new Set([id]);
  $$("[data-ids]", svg).forEach((n) => { const ids = n.dataset.ids.split(" "); if (ids.includes(id)) ids.forEach((x) => connected.add(x)); });
  $$(".node", svg).forEach((n) => n.classList.toggle("dim-out", !connected.has(n.dataset.id)));
  $$("[data-ids]", svg).forEach((n) => {
    const on = n.dataset.ids.split(" ").includes(id);
    n.classList.toggle("dim-out", !on);
    if (n.classList.contains("link")) n.classList.toggle("hot", on);
  });
}
function applyMapFilter() {
  const svg = $("#topology svg");
  if (!svg) return;
  $$(".link", svg).forEach((n) => n.classList.remove("hot"));
  const atkIds = new Set(attackPaths().flat());
  $$(".node", svg).forEach((n) => {
    const id = n.dataset.id, v = n.dataset.v;
    const keep = mapFilter === "all" || (mapFilter === "attack" ? atkIds.has(id) : v === mapFilter);
    n.classList.toggle("dim-out", !keep);
  });
  $$("[data-ids]", svg).forEach((n) => {
    const isAtk = n.classList.contains("attack-link") || n.classList.contains("pkt-atk");
    n.classList.toggle("dim-out", mapFilter !== "all" && !(mapFilter === "attack" && isAtk) && !(mapFilter !== "attack" && isAtk));
  });
}
$$("#map-filter button").forEach((b) => b.addEventListener("click", () => {
  mapFilter = b.dataset.f;
  $$("#map-filter button").forEach((x) => x.classList.toggle("active", x === b));
  applyMapFilter();
}));

/* ------------------------------------------------------------------ feed + incidents */
function renderFeed() {
  const evs = sortedEvents.filter((e) => e.ts <= T).reverse();
  $("#feed-count").textContent = `${evs.length} verdict change${evs.length === 1 ? "" : "s"} so far`;
  $("#feed").innerHTML = evs.length ? evs.map((e) => {
    const S = STATUS[e.to];
    return `<li data-dev="${esc(e.device)}"><span class="dot ${S.k}">${icon(e.to === "COMPROMISED" ? "i-x" : e.to === "SUSPICIOUS" ? "i-triangle-alert" : "i-check")}</span>
      <div class="body"><span class="when">${fmt(e.ts)}</span><div class="what"><b>${esc(e.device)}</b>${badge(e.to)}</div><div class="why">${esc(e.reason)}</div></div></li>`;
  }).join("") : `<li class="empty" style="display:block">No verdict changes yet: every device matches its baseline.</li>`;
  $$("#feed li[data-dev]").forEach((li) => li.addEventListener("click", () => openDrawer(li.dataset.dev)));
}
const activeIncidents = () => R.incidents.filter((i) => i.devices.some((d) => verdictAt(d).v !== "CLEAN"));
const worstOf = (devs) => devs.map((d) => verdictAt(d).v).sort((a, b) => STATUS[b].rank - STATUS[a].rank)[0];
function renderIncidentSummary() {
  const inc = activeIncidents();
  $("#incident-summary").innerHTML = inc.length ? inc.map((i) => {
    const tac = new Set(i.kill_chain.filter((c) => c.ts <= T).map((c) => c.tactic));
    return `<div class="inc" data-inc="${i.id}"><div class="head"><b>${i.id}</b>${badge(worstOf(i.devices))}</div>
      <div>${i.devices.map((d) => `<span class="chip">${icon(devIcon(devById[d]))}${esc(d)}</span>`).join("")}</div>
      <div class="meta">${icon("i-list-checks")}${tac.size} attack stage${tac.size === 1 ? "" : "s"} · since ${fmt(i.start)}</div></div>`;
  }).join("") : `<div class="empty">No open incidents.</div>`;
  $$("#incident-summary .inc").forEach((c) => c.addEventListener("click", () => {
    switchView("incidents");
    setTimeout(() => document.getElementById("inc-" + c.dataset.inc)?.scrollIntoView({ behavior: "smooth", block: "start" }), 60);
  }));
}
function renderIncidents() {
  const inc = activeIncidents();
  $("#incidents").innerHTML = inc.length ? inc.map((i) => {
    const chain = i.kill_chain.filter((c) => c.ts <= T), hit = new Set(chain.map((c) => c.tactic));
    return `<div class="panel" id="inc-${i.id}">
      <div class="ph"><div class="ph-l"><span class="ph-ico ${i.severity === "critical" ? "red" : ""}">${icon("i-siren")}</span><div><h2 class="mono">${i.id} &nbsp;${badge(worstOf(i.devices))}</h2><p>First alarm ${fmt(i.start)} · ${hit.size} of 10 ATT&amp;CK stages observed</p></div></div>
        <div>${i.devices.map((d) => `<span class="chip on" style="cursor:pointer" data-dev="${esc(d)}">${icon(devIcon(devById[d]))}${esc(d)}</span>`).join("")}</div></div>
      <div class="stages">${STAGES.map((s) => `<div class="stage ${hit.has(s) ? "hit" : ""}">${s}</div>`).join("")}</div>
      <table class="chain"><tbody>${chain.length ? chain.map((c) => `<tr><td class="t">${fmt(c.ts)}</td><td class="d">${esc(c.device)}</td>
        <td><span class="chip red">${esc(c.tactic)}</span></td><td class="te">${esc(c.technique)}</td></tr>`).join("")
        : `<tr><td class="te">Persistent anomaly without a mapped attack stage. Review the device evidence.</td></tr>`}</tbody></table></div>`;
  }).join("") : `<div class="panel empty">No open incidents at ${fmt(T)}.</div>`;
  $$("#incidents [data-dev]").forEach((c) => c.addEventListener("click", () => openDrawer(c.dataset.dev)));
}

/* ------------------------------------------------------------------ evidence matrix */
const RAMP = [[0, [244, 247, 251]], [.12, [205, 226, 251]], [.3, [158, 197, 244]], [.45, [109, 167, 236]], [.6, [57, 135, 229]],
  [.75, [37, 106, 191]], [.88, [24, 79, 149]], [1, [13, 54, 107]]];
const RAMP_DARK = [[0, [31, 35, 43]], [.15, [24, 52, 92]], [.35, [28, 92, 171]], [.55, [42, 120, 214]], [.75, [109, 167, 236]], [1, [205, 226, 251]]];
function evColor(s) {
  const t = Math.min(1, Math.max(0, s / 8)), ramp = document.documentElement.dataset.theme === "dark" ? RAMP_DARK : RAMP;
  for (let i = 1; i < ramp.length; i++) if (t <= ramp[i][0]) {
    const [a, ca] = ramp[i - 1], [b, cb] = ramp[i], k = (t - a) / (b - a);
    return `rgb(${ca.map((c, j) => Math.round(c + (cb[j] - c) * k)).join(",")})`;
  }
  return `rgb(${ramp.at(-1)[1].join(",")})`;
}
const matrixRows = () => [...R.devices].sort((a, b) => TYPE_ORDER[a.type] - TYPE_ORDER[b.type] || a.id.localeCompare(b.id));
function renderMatrix() {
  const cv = $("#matrix"), wrap = cv.parentElement;
  const rows = matrixRows(), n = times.length, LW = 150, RH = 24, TOP = 26;
  const cw = Math.max(2, Math.floor((wrap.clientWidth - LW - 6) / n));
  const Wc = LW + cw * n + 4, Hc = TOP + rows.length * RH + 6, dpr = Math.min(devicePixelRatio || 1, 2);
  cv.width = Wc * dpr; cv.height = Hc * dpr; cv.style.width = Wc + "px"; cv.style.height = Hc + "px";
  const ctx = cv.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  const cv_ = (n) => cssVar(n);
  ctx.fillStyle = cv_("--card"); ctx.fillRect(0, 0, Wc, Hc);
  const h = R.params.h;
  rows.forEach((d, r) => {
    const y = TOP + r * RH, tl = R.timeline[d.id] || [], v = verdictAt(d.id).v;
    if (r % 2) { ctx.fillStyle = cv_("--stripe"); ctx.fillRect(0, y, Wc, RH); }
    ctx.fillStyle = STATUS[v].color; ctx.beginPath(); ctx.arc(14, y + RH / 2, 4.5, 0, 7); ctx.fill();
    ctx.font = `${v === "CLEAN" ? 500 : 700} 12px ui-monospace, Consolas, monospace`;
    ctx.fillStyle = v === "CLEAN" ? cv_("--ink-2") : cv_("--ink");
    ctx.fillText(d.id, 26, y + RH / 2 + 4);
    for (let i = 0; i < tl.length; i++) {
      ctx.fillStyle = evColor(tl[i][1]);
      ctx.fillRect(LW + i * cw, y + 3, cw - (cw > 3 ? 1 : 0), RH - 9);
      if (tl[i][2] > h) {
        const comp = verdictAt(d.id, tl[i][0]).v === "COMPROMISED";
        ctx.fillStyle = comp ? "#d03b3b" : "#fab219";
        if (comp || i % 2 === 0) ctx.fillRect(LW + i * cw, y + RH - 5, cw, 3);
      }
    }
  });
  ctx.font = "600 11px system-ui, Segoe UI, sans-serif";
  for (let i = 0; i < n; i++) if (times[i] % 86400 === 0) {
    ctx.fillStyle = cv_("--axis"); ctx.fillRect(LW + i * cw, TOP - 4, 1, Hc - TOP);
    ctx.fillStyle = "#898781"; ctx.fillText(`${DAYS[new Date(times[i] * 1000).getUTCDay()]} 00:00`, LW + i * cw + 5, 15);
  }
  const ti = idxOf(T);
  if (ti < n - 1) {
    ctx.fillStyle = cv_("--veil"); ctx.fillRect(LW + (ti + 1) * cw, TOP - 2, (n - ti - 1) * cw + 4, Hc - TOP + 2);
    ctx.fillStyle = "#2a78d6"; ctx.fillRect(LW + (ti + 1) * cw, TOP - 8, 2, Hc - TOP + 8);
  }
  let hl = wrap.querySelector(".mx-hl");
  if (!hl) { hl = document.createElement("div"); hl.className = "mx-hl"; hl.style.cssText = "position:absolute;pointer-events:none;border:2px solid #2a78d6;border-radius:6px;display:none"; wrap.style.position = "relative"; wrap.appendChild(hl); }
  cv.onmousemove = (e) => {
    const r = cv.getBoundingClientRect(), x = e.clientX - r.left, y = e.clientY - r.top;
    const i = Math.floor((x - LW) / cw), ri = Math.floor((y - TOP) / RH);
    if (ri < 0 || ri >= rows.length) { hl.style.display = "none"; return hideTip(); }
    hl.style.display = "block"; hl.style.left = "2px"; hl.style.top = TOP + ri * RH + "px"; hl.style.width = Wc - 4 + "px"; hl.style.height = RH + "px";
    if (i < 0 || i >= n) return hideTip();
    const d = rows[ri], p = R.timeline[d.id][i];
    showTip(`<div class="tt-t">${fmt(p[0])} UTC</div><b class="mono">${esc(d.id)}</b> ${badge(verdictAt(d.id, p[0]).v)}
      <div style="margin-top:6px">Fused evidence <b class="mono">${p[1].toFixed(2)}</b> · accumulated <b class="mono">${p[2].toFixed(1)}</b>${p[2] > h ? " · <b style='color:#a32020'>alarm</b>" : ""}</div>`, e.clientX, e.clientY);
  };
  cv.onmouseleave = () => { hl.style.display = "none"; hideTip(); };
  cv.onclick = (e) => { const r = cv.getBoundingClientRect(), ri = Math.floor((e.clientY - r.top - TOP) / RH); if (rows[ri]) openDrawer(rows[ri].id); };
}

/* ------------------------------------------------------------------ devices table */
function sparkline(id) {
  const tl = R.timeline[id] || [], w = 150, hh = 28, n = tl.length;
  if (!n) return "";
  const pts = tl.map((p, i) => `${((i / (n - 1)) * w).toFixed(1)},${(hh - 2 - Math.min(1, p[1] / 8) * (hh - 5)).toFixed(1)}`);
  const ti = idxOf(T), v = verdictAt(id).v, c = v === "COMPROMISED" ? "#d03b3b" : v === "SUSPICIOUS" ? "#d89a00" : "#2a78d6";
  return `<svg width="${w}" height="${hh}" viewBox="0 0 ${w} ${hh}" aria-hidden="true"><path d="M0,${hh} L${pts.join(" L")} L${w},${hh}Z" fill="${c}" opacity=".1"/>
    <polyline points="${pts.join(" ")}" fill="none" stroke="${c}" stroke-width="1.4"/>${ti < n - 1 ? `<rect x="${(ti / (n - 1)) * w}" y="0" width="${w}" height="${hh}" style="fill:var(--card)" opacity=".8"/>` : ""}</svg>`;
}
function renderDeviceTable() {
  const q = $("#f-search").value.toLowerCase(), ft = $("#f-type").value, fv = $("#f-verdict").value;
  const rows = R.devices.map((d) => ({ d, v: verdictAt(d.id) }))
    .filter(({ d, v }) => (!q || d.id.toLowerCase().includes(q) || d.ip.includes(q)) && (!ft || d.type === ft) && (!fv || v.v === fv))
    .sort((a, b) => STATUS[b.v.v].rank - STATUS[a.v.v].rank || a.d.id.localeCompare(b.d.id));
  $("#device-table tbody").innerHTML = rows.map(({ d, v }) => {
    const peak = Math.max(0, ...(R.timeline[d.id] || []).filter((x) => x[0] <= T).map((x) => x[1]));
    const k = STATUS[v.v].k;
    return `<tr class="click" data-dev="${esc(d.id)}"><td><div class="dev-cell"><span class="di ${k === "good" ? "" : k}">${icon(devIcon(d))}</span><div><b>${esc(d.id)}</b><small>${esc(d.role)}</small></div></div></td>
      <td>${esc(TYPE_LABEL[d.type])}</td><td class="mono small">${esc(d.ip || "–")}</td><td>${badge(v.v)}</td><td>${sparkline(d.id)}</td>
      <td class="num">${peak.toFixed(1)}</td><td>${tacticsAt(d.id).map((t) => `<span class="chip red">${esc(t)}</span>`).join("") || '<span class="dim">–</span>'}</td></tr>`;
  }).join("");
  $$("#device-table tbody tr").forEach((tr) => tr.addEventListener("click", () => openDrawer(tr.dataset.dev)));
}

/* ------------------------------------------------------------------ drawer */
function openDrawer(id) { openDevice = id; renderDrawer(); $("#drawer").classList.add("open"); $("#scrim").classList.add("open"); $("#drawer").scrollTop = 0; }
function closeDrawer() { openDevice = null; $("#drawer").classList.remove("open"); $("#scrim").classList.remove("open"); }
function renderDrawer() {
  const d = devById[openDevice], v = verdictAt(d.id), S = STATUS[v.v];
  const evs = (R.evidence[d.id] || []).filter((e) => e.ts <= T).sort((a, b) => b.score - a.score).slice(0, 6).sort((a, b) => a.ts - b.ts);
  const det = R.meta.detectors;
  $("#drawer-body").innerHTML = `
    <div class="d-top"><div class="d-id"><span class="d-ico ${S.k === "good" ? "" : S.k}">${icon(devIcon(d))}</span><div>
      <div class="d-title">${esc(d.id)} ${badge(v.v)}</div>
      <div class="d-meta">${esc(TYPE_LABEL[d.type])} · ${esc(d.ip || "no address")} · ${esc(d.role)} · watched by ${d.coverage.length} of 8 detectors</div></div></div>
      <div class="d-actions no-print">${v.v !== "CLEAN" ? `<button class="btn sm" id="btn-benign">${icon("i-check")}Mark benign</button>` : ""}
        <button class="btn sm" onclick="window.print()">${icon("i-printer")}Print</button><button class="btn sm icon" id="btn-close" aria-label="Close">${icon("i-x")}</button></div></div>
    <div class="d-card d-reason ${v.v.toLowerCase()}">${icon(S.ic)}<div><b>Verdict.</b> ${esc(v.reason)} ${v.ts ? `<span class="mono small">· ${fmt(v.ts)}</span>` : ""}
      <div style="margin-top:8px">${tacticsAt(d.id).map((t) => `<span class="chip red">${esc(t)}</span>`).join("") || '<span class="small">No attack stage observed.</span>'}</div></div></div>
    ${(() => { const x = window.explainDevice ? explainDevice(R, d.id, LANG, T) : null; return x ? `<div class="d-card why">
      <div class="why-h"><span class="why-ico">${icon("i-sparkles")}</span><div><h3>${tr("why.title")}</h3><small>${esc(x.headline)}</small></div>
      <div class="seg mini"><button class="${LANG === "en" ? "active" : ""}" data-lang="en">EN</button><button class="${LANG === "hi" ? "active" : ""}" data-lang="hi">हि</button></div></div>
      ${x.paragraphs.map((p) => `<p>${esc(p)}</p>`).join("")}</div>` : ""; })()}
    <div class="d-card"><h3 style="margin-top:0">Anomaly evidence over time</h3><div class="chart" id="chart"></div>
      <div class="chart-legend"><span><i style="background:#2a78d6;height:3px"></i>fused evidence per 15 min (−log₁₀ p)</span><span><i style="border-top:2px dashed #898781;height:0"></i>significance p = 0.01</span>
      <span><i style="background:repeating-linear-gradient(45deg,rgba(208,59,59,.3) 0 2px,rgba(208,59,59,.06) 2px 6px)"></i>alarm active</span><span><i style="background:#d03b3b;border-radius:50%;width:10px"></i>verdict change</span></div></div>
    <div class="d-card"><h3 style="margin-top:0">Detector coverage</h3>${Object.keys(det).map((k) => `<span class="chip ${d.coverage.includes(k) ? "on" : ""}">${d.coverage.includes(k) ? icon("i-check") : icon("i-x")}${esc(det[k])}</span>`).join("")}</div>
    <h3>Strongest evidence${evs.length ? ` · ${evs.length} windows` : ""}</h3>
    ${evs.length ? evs.map(evidenceCard).join("") : `<div class="d-card empty">No significant evidence up to ${fmt(T)}.</div>`}
    <div class="d-card"><h3 style="margin-top:0">Recommended forensic actions</h3>
    ${v.v === "CLEAN" ? `<div class="dim">No action needed.</div>` : `<ol class="actions-list">${(R.actions[d.type] || []).map((a) => `<li>${esc(a)}</li>`).join("")}</ol>`}</div>`;
  $("#btn-close").onclick = closeDrawer;
  $$(".why [data-lang]").forEach((b) => (b.onclick = () => setLang(b.dataset.lang)));
  const bb = $("#btn-benign");
  if (bb) bb.onclick = async () => {
    bb.disabled = true;
    await fetch("/api/mark_benign", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ device: d.id }) });
    R = await (await fetch("/api/results")).json();
    T = 0; prepare(); renderAll();
  };
  renderChart($("#chart"), d.id);
}
function evidenceCard(e) {
  const det = Object.entries(e.detectors).sort((a, b) => b[1] - a[1]), max = Math.max(6, ...det.map((x) => x[1]));
  const tac = Object.entries(e.tactics).map(([t, techs]) => `<span class="chip red" title="${esc(techs.join("; "))}">${esc(t)}</span>`).join("");
  const list = (ic, title, arr) => arr && arr.length ? `<div class="sub-h">${icon(ic)}${title}</div><ul class="list">${arr.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : "";
  const cfg = (e.config || []).map((c) => `<div class="sub-h">${icon("i-file-cog")}Configuration change by ${esc(c.actor)}</div>
      <div class="small">${c.maintenance_window ? "inside" : "<b>outside</b>"} the maintenance window · ${c.known_admin ? "known admin" : "<b>unknown actor</b>"} · risk <b class="mono">${c.score}</b></div>
      <div style="margin-top:6px">${c.risks.map((r) => `<span class="chip red" title="${esc(r.technique)}">${esc(r.risk)}</span>`).join("")}</div>
      <div class="diff">${c.added.map((l) => `<div class="add">${esc(l)}</div>`).join("")}${c.removed.map((l) => `<div class="del">${esc(l)}</div>`).join("")}</div>`).join("");
  const b = e.beacon ? `<div class="sub-h">${icon("i-radio-tower")}Periodic beacon</div><div class="mono small">${esc(e.beacon.src)} → ${esc(e.beacon.dst)} · every ${e.beacon.period_s}s · jitter ${e.beacon.jitter_pct}% · ${e.beacon.contacts} contacts in 3 h</div>` : "";
  return `<div class="ev"><div class="ev-head"><b>${fmt(e.ts)}</b><span class="small dim">fused evidence <b class="mono">${e.score.toFixed(1)}</b>${e.alarm ? " · alarm" : ""}</span></div>
    <div class="ev-body">${tac ? `<div style="margin-bottom:12px">${tac}</div>` : ""}
    <div class="ev-grid"><div><h4>Detectors (−log₁₀ p)</h4>${det.map(([k, v]) => `<div class="det-row"><span class="lbl" title="${esc(R.meta.detectors[k])}">${esc(R.meta.detectors[k])}</span>
        <span class="trk"><span class="fil" style="width:${Math.min(100, (v / max) * 100)}%"></span></span><span class="val">${v.toFixed(1)}</span></div>`).join("")}</div>
      <div><h4>What changed vs normal</h4>${e.top_features.length ? `<table class="kv"><tr><td>Behaviour</td><td class="num">Now</td><td class="num">Normal</td></tr>
        ${e.top_features.map((f) => `<tr><td>${esc(f.feature)}</td><td class="num"><b>${f.value.toLocaleString()}</b></td><td class="num">${f.normal.toLocaleString()}</td></tr>`).join("")}</table>`
        : `<div class="dim small">Volumes look normal: the evidence comes from the sequence, configuration or periodicity detectors.</div>`}</div></div>
    ${cfg}${b}${list("i-binary", "Never-seen process chains", e.new_processes)}${list("i-key-round", "New logins (user@source)", e.new_logins)}
    ${list("i-waypoints", `New internal connections${e.n_new_internal > 8 ? ` (${e.n_new_internal} total)` : ""}`, e.new_internal)}
    ${list("i-globe", "Never-seen Internet destinations", e.new_external)}${list("i-link", "Never-seen domains", e.new_domains)}
    ${list("i-scroll-text", "Unusual log sequences", e.odd_logs)}${list("i-scan-eye", "Slips evidence", e.slips)}</div></div>`;
}

/* ------------------------------------------------------------------ chart */
function renderChart(box, id) {
  const data = R.timeline[id] || [];
  if (!data.length) { box.innerHTML = `<div class="empty">No data.</div>`; return; }
  const W = box.clientWidth || 820, H = 220, m = { l: 32, r: 10, t: 16, b: 26 }, iw = W - m.l - m.r, ih = H - m.t - m.b;
  const t0 = data[0][0], t1 = data.at(-1)[0], ymax = Math.max(6, Math.ceil(Math.max(...data.map((x) => x[1])) + 1));
  const x = (t) => m.l + ((t - t0) / Math.max(1, t1 - t0)) * iw, y = (v) => m.t + ih - (Math.min(v, ymax) / ymax) * ih;
  const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, height: H, role: "img", "aria-label": `Anomaly evidence over time for ${id}` });
  const step = ymax > 16 ? 5 : 2;
  for (let v = 0; v <= ymax; v += step) { el("line", { x1: m.l, x2: W - m.r, y1: y(v), y2: y(v), class: v ? "gridline" : "axis" }, svg); txt(svg, m.l - 8, y(v) + 4, v, { "text-anchor": "end" }); }
  for (let t = Math.ceil(t0 / 86400) * 86400; t <= t1; t += 86400) { el("line", { x1: x(t), x2: x(t), y1: m.t, y2: m.t + ih, class: "gridline" }, svg); txt(svg, x(t) + 5, H - 7, `${DAYS[new Date(t * 1000).getUTCDay()]} 00:00`); }
  const h = R.params.h, dt = R.meta.window_s;
  let st = null;
  data.forEach((p, i) => {
    const on = p[2] > h;
    if (on && st === null) st = p[0];
    if ((!on || i === data.length - 1) && st !== null) { const end = on ? p[0] + dt : p[0]; el("rect", { x: x(st), y: m.t, width: Math.max(1.5, x(end) - x(st)), height: ih, fill: "url(#hatch-red)" }, svg); st = null; }
  });
  el("line", { x1: m.l, x2: W - m.r, y1: y(2), y2: y(2), class: "ref" }, svg);
  const pts = data.map((p) => `${x(p[0]).toFixed(1)},${y(p[1]).toFixed(1)}`);
  el("path", { d: `M${m.l},${y(0)} L${pts.join(" L")} L${x(t1)},${y(0)} Z`, fill: "url(#g-area)" }, svg);
  el("path", { d: "M" + pts.join(" L"), class: "series" }, svg);
  for (const e of eventsByDev[id] || []) if (e.ts >= t0) el("circle", { cx: x(e.ts), cy: m.t + 2, r: 6, fill: STATUS[e.to].color, stroke: "#fff", "stroke-width": 2.5 }, svg);
  if (T < t1) { el("rect", { x: x(T), y: m.t, width: x(t1) - x(T), height: ih, style: "fill:var(--card)", opacity: .75 }, svg); el("line", { x1: x(T), x2: x(T), y1: m.t, y2: m.t + ih, class: "now" }, svg); }
  const cross = el("line", { y1: m.t, y2: m.t + ih, class: "cross", visibility: "hidden" }, svg);
  const dot = el("circle", { r: 5, fill: "#2a78d6", stroke: "#fff", "stroke-width": 2.5, visibility: "hidden" }, svg);
  const hit = el("rect", { x: m.l, y: 0, width: iw, height: H, class: "hit" }, svg);
  hit.addEventListener("mousemove", (ev) => {
    const r = svg.getBoundingClientRect(), px = ((ev.clientX - r.left) / r.width) * W;
    const i = Math.max(0, Math.min(data.length - 1, Math.round(((px - m.l) / iw) * (data.length - 1)))), p = data[i];
    cross.setAttribute("x1", x(p[0])); cross.setAttribute("x2", x(p[0])); cross.setAttribute("visibility", "visible");
    dot.setAttribute("cx", x(p[0])); dot.setAttribute("cy", y(p[1])); dot.setAttribute("visibility", "visible");
    showTip(`<div class="tt-t">${fmt(p[0])} UTC</div>Fused evidence <b class="mono">${p[1].toFixed(2)}</b> (p ≈ 10<sup>−${p[1].toFixed(1)}</sup>)<br>
      Accumulated <b class="mono">${p[2].toFixed(1)}</b> ${p[2] > h ? "· <b style='color:#a32020'>alarm</b>" : `of threshold ${h}`}`, ev.clientX, ev.clientY);
  });
  hit.addEventListener("mouseleave", () => { cross.setAttribute("visibility", "hidden"); dot.setAttribute("visibility", "hidden"); hideTip(); });
  box.replaceChildren(svg);
}

/* ------------------------------------------------------------------ evaluation */
function renderEvaluation() {
  const box = $("#evaluation"), ev = R.evaluation;
  if (!ev) { box.innerHTML = `<div class="panel empty">This analysis ran on real telemetry, so there is no ground truth. Evaluation is shown for the simulated benchmark.</div>`; return; }
  const k = (label, value, detail) => `<div class="metric"><div class="label">${label}</div><div class="value">${value}</div><div class="detail">${detail}</div></div>`;
  const pct = (v) => Math.round(v * 100) + "%";
  const final = Object.fromEntries(ev.devices.map((d) => [d.device, d]));
  const scen = (R.truth?.scenarios || []).map((s) => {
    let out;
    if (s.devices[0] === "all hosts") {
      const other = new Set(R.truth.scenarios.filter((x) => x !== s).flatMap((x) => x.devices));
      const own = R.devices.filter((d) => d.type === "host" && !other.has(d.id)), n = own.filter((d) => final[d.id].verdict === "CLEAN").length;
      out = `<span>${n}/${own.length} uninvolved hosts ${badge(n === own.length ? "CLEAN" : "SUSPICIOUS")}</span>`;
    } else out = s.devices.map((d) => `<span>${esc(d)} ${badge(devById[d].verdict)}</span>`).join("");
    return `<div class="scen"><span class="id ${s.kind === "attack" ? "atk" : "ben"}">${s.id}</span><div><b>${esc(s.title)}</b> <span class="chip">${s.kind === "attack" ? "attack" : "benign trap"}</span>
      <div class="story">${esc(s.story)}</div></div><div class="out">${out}</div></div>`;
  }).join("");
  const abl = (R.ablation || []).map((a, i) => `<tr class="${i === 0 ? "best" : ""}"><td>${esc(a.variant)}</td>
      <td class="num">${a.tp}</td><td class="num">${a.fp}</td><td class="num">${a.fn}</td><td class="num">${pct(a.precision)}</td><td class="num">${pct(a.recall)}</td>
      <td><span class="hbar" style="width:${Math.max(3, a.f1 * 110)}px"></span><span class="mono">${a.f1.toFixed(2)}</span></td>
      <td class="num">${a.clean_devices_with_any_alarm}</td><td class="num">${a.false_alarm_windows_per_device_day}</td><td class="num">${a.median_ttd_min ?? "–"}</td></tr>`).join("");
  box.innerHTML = `
    <div class="panel"><div class="ph"><div class="ph-l"><span class="ph-ico">${icon("i-target")}</span><div><h2>Device-level detection performance</h2><p>Simulated 22-device enterprise · 4-day baseline + ${ev.test_days}-day test · ${R.meta.n_events.toLocaleString()} events · seed ${R.meta.seed}</p></div></div></div>
      <div class="metric-grid">${k("Precision", pct(ev.precision), `${ev.fp} wrongly convicted`)}${k("Recall", pct(ev.recall), `${ev.tp} of ${ev.n_attacked} attacked caught`)}
        ${k("F1 score", ev.f1.toFixed(2), "device verdicts")}${k("False positives", ev.fp, `of ${ev.n_clean} clean devices`)}
        ${k("Median time to detect", (ev.median_ttd_min ?? "–") + " min", "from first attacker action")}${k("Alarm windows", ev.false_alarm_windows_per_device_day, "per clean device-day")}</div></div>
    <div class="panel"><div class="ph"><div class="ph-l"><span class="ph-ico">${icon("i-list-checks")}</span><div><h2>Scenario outcomes</h2><p>Attacks must be convicted; benign traps must not</p></div></div></div>${scen}</div>
    <div class="panel"><div class="ph"><div class="ph-l"><span class="ph-ico">${icon("i-git-compare")}</span><div><h2>Ablation study</h2><p>Same data and baseline, one component removed or used alone</p></div></div></div>
      <table class="table"><thead><tr><th>Variant</th><th class="num">TP</th><th class="num">FP</th><th class="num">FN</th><th class="num">Precision</th><th class="num">Recall</th><th>F1</th>
      <th class="num">Clean alarmed</th><th class="num">Alarm windows / device-day</th><th class="num">TTD (min)</th></tr></thead><tbody>${abl}</tbody></table></div>
    <div class="panel"><div class="ph"><div class="ph-l"><span class="ph-ico">${icon("i-badge-check")}</span><div><h2>Ground truth vs verdict</h2><p>Per device</p></div></div></div>
      <table class="table"><thead><tr><th>Device</th><th>Truth</th><th>Verdict</th><th class="num">Alarm windows</th><th class="num">TTD (min)</th></tr></thead>
      <tbody>${ev.devices.map((d) => `<tr><td><div class="dev-cell"><span class="di">${icon(devIcon(devById[d.device]))}</span><b>${esc(d.device)}</b></div></td>
        <td>${d.truth === "attacked" ? '<span class="chip red">attacked</span>' : '<span class="chip">clean</span>'}</td><td>${badge(d.verdict)}</td>
        <td class="num">${d.alarm_windows}</td><td class="num">${d.ttd_min ?? "–"}</td></tr>`).join("")}</tbody></table></div>`;
}

/* ------------------------------------------------------------------ controls */
function switchView(v) {
  view = v;
  $$(".sn").forEach((t) => t.classList.toggle("active", t.dataset.view === v));
  $$(".view").forEach((s) => s.classList.toggle("active", s.id === "view-" + v));
  if (v === "devices") renderDeviceTable();
  if (v === "incidents") renderIncidents();
  if (v === "matrix") renderMatrix();
  window.viewRenderers?.[v]?.("open");
}
$$(".sn").forEach((t) => t.addEventListener("click", () => switchView(t.dataset.view)));
$("#scrim").addEventListener("click", closeDrawer);
addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeDrawer();
  if (e.key === " " && e.target === document.body) { e.preventDefault(); $("#btn-play").click(); }
});
["#f-search", "#f-type", "#f-verdict"].forEach((s) => $(s).addEventListener("input", renderDeviceTable));
$("#slider").addEventListener("input", (e) => { T = times[+e.target.value]; renderAll(); });
$("#btn-end").addEventListener("click", () => { stop(); setT(times.at(-1)); });
const setPlayIcon = (id) => $("#play-ic use").setAttribute("href", `${SPRITE}#${id}`);
function stop() { clearInterval(playTimer); playTimer = null; setPlayIcon("i-play"); }
$("#btn-play").addEventListener("click", () => {
  if (playTimer) return stop();
  let i = +$("#slider").value;
  if (i >= times.length - 1) i = 0;
  setPlayIcon("i-pause");
  playTimer = setInterval(() => {
    i = Math.min(times.length - 1, i + 1);
    $("#slider").value = i; T = times[i]; renderAll();
    if (i >= times.length - 1) stop();
  }, 80);
});
$("#btn-rerun").addEventListener("click", async () => {
  const r = await fetch("/api/run", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ seed: 1 + Math.floor(Math.random() * 999), ablations: true }) });
  if (r.status !== 409) { T = 0; showOverlay(); poll(); }
});
addEventListener("resize", () => { if (openDevice) renderChart($("#chart"), openDevice); if (view === "matrix") renderMatrix(); });
load();
