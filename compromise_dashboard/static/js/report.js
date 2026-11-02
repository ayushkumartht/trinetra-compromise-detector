"use strict";
/* Executive compromise-assessment report (print / Save as PDF). */
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const icon = (id) => `<svg class="ic" aria-hidden="true"><use href="/static/img/icons.svg#${id}"/></svg>`;
const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const p2 = (n) => String(n).padStart(2, "0");
const fmt = (ts) => { const d = new Date(ts * 1000); return `${DAYS[d.getUTCDay()]} ${p2(d.getUTCDate())}-${p2(d.getUTCMonth() + 1)}-${d.getUTCFullYear()} ${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())} UTC`; };
const STAGES = ["Execution", "Persistence", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"];
const V = { COMPROMISED: ["v-bad", "i-shield-alert", "Compromised"], SUSPICIOUS: ["v-warn", "i-triangle-alert", "Suspicious"], CLEAN: ["v-good", "i-circle-check", "Clean"] };
const badge = (v) => `<span class="v ${V[v][0]}">${icon(V[v][1])}${V[v][2]}</span>`;
let LANG = localStorage.getItem("trinetra-lang") || "en", R = null;

async function main() {
  R = await (await fetch("/api/results")).json();
  render();
  if (new URLSearchParams(location.search).get("print") === "1") setTimeout(() => window.print(), 900);
}
function render() {
  const devs = R.devices, comp = devs.filter((d) => d.verdict === "COMPROMISED"), sus = devs.filter((d) => d.verdict === "SUSPICIOUS");
  const m = R.meta, ev = R.evaluation;
  const vk = comp.length ? "bad" : sus.length ? "warn" : "good";
  const vt = comp.length ? `Network compromised: ${comp.length} device${comp.length > 1 ? "s" : ""} require incident response`
    : sus.length ? `${sus.length} device(s) show suspicious behaviour and need review` : "No compromise detected";
  const byType = {};
  devs.forEach((d) => (byType[d.type] = (byType[d.type] || 0) + 1));
  const crit = R.incidents.filter((i) => i.severity === "critical");
  const cover = `<div class="page cover">
    <div><div class="c-top"><div class="brand"><span class="brand-mark"><svg viewBox="0 0 32 32"><path d="M16 2.5 4.5 7v8.2c0 7.1 4.9 12.4 11.5 14.3 6.6-1.9 11.5-7.2 11.5-14.3V7z" fill="currentColor"/><path d="M8.6 16c2-3.3 4.5-5 7.4-5s5.4 1.7 7.4 5c-2 3.3-4.5 5-7.4 5s-5.4-1.7-7.4-5z" fill="#fff"/><circle cx="16" cy="16" r="2.6" fill="currentColor"/></svg></span><span class="brand-name">TRINETRA</span></div>
      <span class="muted mono" style="font-size:11px">CONFIDENTIAL · INCIDENT RESPONSE</span></div>
      <div class="c-title"><div class="k">Compromise assessment report</div><h1>Is the network already breached?</h1>
        <p>Behaviour-based (IoC-free) assessment of ${devs.length} devices: ${Object.entries(byType).map(([t, n]) => `${n} ${t === "host" ? "systems" : t === "network" ? "network sensor(s)" : t + "s"}`).join(", ")}.</p></div>
      <div class="verdict ${vk}">${icon(comp.length ? "i-siren" : sus.length ? "i-triangle-alert" : "i-shield-check")}<div><b>${esc(vt)}</b>
        <span>${comp.length ? `Compromised: ${comp.map((d) => d.id).join(", ")}` : ""}${sus.length ? `${comp.length ? " · " : ""}Under review: ${sus.map((d) => d.id).join(", ")}` : ""}</span></div></div></div>
    <div class="c-meta"><div>Data source<b>${esc(m.source === "simulation" ? "Simulated benchmark" : m.source === "live" ? "Live attack lab" : "Uploaded telemetry")}</b></div>
      <div>Period analysed<b>${fmt(m.t_train_end)}<br>→ ${fmt(m.t_end)}</b></div><div>Events analysed<b>${m.n_events.toLocaleString()}</b></div><div>Report generated<b>${new Date().toUTCString().slice(5, 22)} UTC</b></div></div></div>`;

  const summary = `<div class="page">
    <section><h2><span class="n">1</span>Executive summary</h2>
      <p>${esc(vt)}. TRINETRA learned how every device normally behaves and scored it every 15 minutes with eight independent detectors (statistics, machine learning, log grammar, beaconing, graph rarity, configuration semantics, Slips evidence). A device is declared <b>compromised</b> only when its anomaly persists <b>and</b> spans at least two MITRE ATT&amp;CK attack stages, or when it received a new connection from an already compromised device.</p>
      <div class="kpis"><div class="kpi"><b>${devs.length}</b><span>devices monitored</span></div><div class="kpi"><b style="color:#d03b3b">${comp.length}</b><span>compromised</span></div>
        <div class="kpi"><b style="color:#b37800">${sus.length}</b><span>suspicious</span></div><div class="kpi"><b style="color:#0ca30c">${devs.length - comp.length - sus.length}</b><span>clean</span></div>
        <div class="kpi"><b>${crit.length}</b><span>critical incidents</span></div></div>
      <h3>Immediate priorities</h3><ol class="acts">${comp.slice(0, 6).map((d) => `<li><b class="mono">${esc(d.id)}</b>: ${esc((R.actions[d.type] || [])[0] || "Investigate")}</li>`).join("") || "<li>No compromised devices. Review suspicious devices within the shift.</li>"}</ol></section>
    <section><h2><span class="n">2</span>Incidents</h2>
      ${R.incidents.length ? R.incidents.map((i) => { const hit = new Set(i.tactics);
        return `<div class="inc"><div class="dev-h"><b class="mono">${i.id}</b>${badge(i.severity === "critical" ? "COMPROMISED" : "SUSPICIOUS")}</div>
          <p style="margin:6px 0">Devices: <b>${i.devices.map(esc).join(", ")}</b> · first alarm ${fmt(i.start)}</p>
          <div class="stages">${STAGES.map((s) => `<div class="stage ${hit.has(s) ? "hit" : ""}">${s}</div>`).join("")}</div>
          ${i.kill_chain.length ? `<table><tr><th>Time</th><th>Device</th><th>Tactic</th><th>Technique</th></tr>${i.kill_chain.slice(0, 10).map((c) => `<tr><td class="mono">${fmt(c.ts).slice(0, 16)}</td><td class="mono">${esc(c.device)}</td><td>${esc(c.tactic)}</td><td class="muted">${esc(c.technique)}</td></tr>`).join("")}</table>` : `<p class="muted">Persistent anomaly without a mapped attack stage.</p>`}</div>`; }).join("") : "<p>No incidents.</p>"}</section></div>`;

  const detail = [...comp, ...sus].map((d) => {
    const x = window.explainDevice(R, d.id, LANG);
    return `<div class="dev"><div class="dev-h"><b>${esc(d.id)}</b><span class="muted">${esc(d.type)} · ${esc(d.ip)} · ${esc(d.role)}</span>${badge(d.verdict)}</div>
      ${x.paragraphs.map((p) => `<p>${esc(p)}</p>`).join("")}
      ${d.verdict === "COMPROMISED" ? `<h3>Recommended forensic actions</h3><ol class="acts">${(R.actions[d.type] || []).map((a) => `<li>${esc(a)}</li>`).join("")}</ol>` : ""}</div>`;
  }).join("");
  const devPage = `<div class="page"><section><h2><span class="n">3</span>${LANG === "hi" ? "हर प्रभावित डिवाइस: क्यों और क्या करें" : "Affected devices: why, and what to do"}</h2>${detail || "<p>No affected devices.</p>"}</section></div>`;

  const allTable = `<div class="page"><section><h2><span class="n">4</span>All devices</h2><table><tr><th>Device</th><th>Type</th><th>Address</th><th>Verdict</th><th>Attack stages</th><th>Peak evidence</th></tr>
    ${devs.map((d) => `<tr><td class="mono">${esc(d.id)}</td><td>${esc(d.type)}</td><td class="mono">${esc(d.ip)}</td><td>${badge(d.verdict)}</td><td>${esc(d.tactics.join(", ")) || "–"}</td><td class="mono">${d.max_score}</td></tr>`).join("")}</table></section>
    ${ev ? `<section><h2><span class="n">5</span>Detection quality (benchmark ground truth)</h2>
      <div class="kpis"><div class="kpi"><b>${Math.round(ev.precision * 100)}%</b><span>precision</span></div><div class="kpi"><b>${Math.round(ev.recall * 100)}%</b><span>recall</span></div>
      <div class="kpi"><b>${ev.fp}</b><span>false convictions</span></div><div class="kpi"><b>${ev.median_ttd_min ?? "–"} min</b><span>median time to detect</span></div><div class="kpi"><b>${ev.false_alarm_windows_per_device_day}</b><span>alarm windows / clean device-day</span></div></div>
      ${(R.ablation || []).length ? `<table><tr><th>Variant</th><th>Caught</th><th>False convictions</th><th>Clean devices alarmed</th><th>F1</th></tr>${R.ablation.slice(0, 4).map((a) => `<tr><td>${esc(a.variant)}</td><td>${a.tp}/${a.tp + a.fn}</td><td>${a.fp}</td><td>${a.clean_devices_with_any_alarm}</td><td>${a.f1.toFixed(2)}</td></tr>`).join("")}</table>` : ""}</section>` : ""}
    <section><h2><span class="n">${ev ? 6 : 5}</span>Methodology</h2><ul>
      <li><b>No IoCs required.</b> Each device's normal behaviour is learned from its own history and its peers; no hashes, IPs or signatures are used.</li>
      <li><b>Eight detectors</b> per 15-minute window: robust deviation, Isolation Forest, autoencoder, DeepLog-style log grammar, C2 beaconing, rare internal edges, configuration semantic drift, Slips evidence.</li>
      <li><b>Calibration and fusion.</b> Scores become conformal p-values with extreme-value tails, fused with the Cauchy combination test and accumulated with CUSUM.</li>
      <li><b>Low false alarms.</b> Fleet consensus, maintenance-window context, kill-chain corroboration (≥ 2 ATT&amp;CK stages) and gated learning.</li></ul>
      <div class="foot">Generated by TRINETRA (extension of Stratosphere Slips, GPL-2.0). Times in UTC. This report reflects behavioural evidence and should be confirmed with forensic acquisition (memory, disk, device configuration and image integrity).</div></section></div>`;
  $("#report").innerHTML = cover + summary + devPage + allTable;
  $("#lang-t").textContent = LANG === "hi" ? "English" : "हिंदी";
}
$("#lang").onclick = () => { LANG = LANG === "hi" ? "en" : "hi"; render(); };
main();
