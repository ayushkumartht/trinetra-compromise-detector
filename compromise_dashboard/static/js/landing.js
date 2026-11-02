"use strict";
/* TRINETRA landing (light): reveals, count-ups, live numbers from /api/results, research library. */

const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const icon = (id, cls = "ic") => `<svg class="${cls}" aria-hidden="true"><use href="/static/img/icons.svg#${id}"/></svg>`;

/* ------------------------------------------------------------ static content */
const LOGOS = [
  ["b-linux", "Linux", "#0b0b0b"], ["b-redhat", "Red Hat", "#ee0000"], ["b-ubuntu", "Ubuntu", "#e95420"],
  ["b-debian", "Debian", "#a81d33"], ["b-fedora", "Fedora", "#51a2da"], ["b-kalilinux", "Kali Linux", "#557c94"],
  ["b-rockylinux", "Rocky Linux", "#10b981"], ["b-archlinux", "Arch Linux", "#1793d1"], ["b-docker", "Docker", "#2496ed"],
  ["b-python", "Python", "#3776ab"], ["b-scikitlearn", "scikit-learn", "#f7931e"], ["b-numpy", "NumPy", "#013243"],
  ["b-scipy", "SciPy", "#8caae6"], ["b-flask", "Flask", "#0b0b0b"], ["b-wireshark", "Wireshark (pcap)", "#1679a7"],
  ["b-elastic", "Elastic (CEF)", "#005571"], ["b-splunk", "Splunk (CEF)", "#0b0b0b"], ["b-git", "Git", "#f05032"],
];
const TIMELINE = [
  ["2015", "SYNful Knock", "Cisco IOS router image implant", "i-router"],
  ["2018", "VPNFilter", "≈500k SOHO routers & NAS", "i-router"],
  ["2023", "Jaguar Tooth", "Cisco IOS via SNMP", "i-router"],
  ["2023", "IOS XE implant", "public IoC check evaded", "i-bug"],
  ["2024", "Volt Typhoon", "living off the land", "i-ghost"],
  ["2024", "COATHANGER", "FortiGate RAT survives upgrades", "i-brick-wall"],
  ["2024", "ArcaneDoor", "memory-resident ASA implant", "i-brick-wall"],
  ["2024", "Salt Typhoon", "telecom core routers", "i-radio-tower"],
  ["2025", "CISA ED 25-03", "core dumps to hunt implants", "i-landmark"],
];
const DETECTORS = [
  ["D1", "i-activity", "Robust deviation", "How far is this window from the device's own normal?", "statistics"],
  ["D2", "i-target", "Isolation Forest", "Is this behaviour easy to isolate from its peers?", "machine learning"],
  ["D3", "i-brain-circuit", "Autoencoder", "A neural net that can only rebuild normal behaviour.", "neural network"],
  ["D4", "i-scroll-text", "Log grammar", "DeepLog-style surprise over syslog message order.", "sequence model"],
  ["D5", "i-radio-tower", "Beaconing", "Clock-like calls to a never-seen external server.", "periodicity"],
  ["D6", "i-waypoints", "Graph rarity", "New internal paths to services nobody used.", "graph"],
  ["D7", "i-file-cog", "Config semantics", "What changed in a router or firewall config, who, when, from where.", "expert rules"],
  ["D8", "i-scan-eye", "Slips evidence", "Stratosphere Slips' behavioural IPS detections as a vote.", "base IPS"],
];
const PAPERS = [
  ["network", "NDSS 2018", "Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection", "Mirsky, Doitshman, Elovici, Shabtai",
    "Autoencoder detector: unsupervised learning of normal traffic", "https://arxiv.org/pdf/1802.09089"],
  ["logs", "ACM CCS 2017", "DeepLog: Anomaly Detection and Diagnosis from System Logs through Deep Learning", "Du, Li, Zheng, Srikumar",
    "Log-grammar detector for router / firewall / host syslog", "https://users.cs.utah.edu/~lifeifei/papers/deeplog.pdf"],
  ["stats", "Annals of Statistics 2023", "Testing for Outliers with Conformal p-values", "Bates, Candès, Lei, Romano, Sesia",
    "Calibration: every detector score becomes a p-value", "https://arxiv.org/pdf/2104.08279"],
  ["stats", "KDD 2017", "Anomaly Detection in Streams with Extreme Value Theory (SPOT)", "Siffer, Fouque, Termier, Largouët",
    "Extreme-value tails for very rare scores", "https://www.eecs.yorku.ca/course_archive/2017-18/F/6412/reading/kdd17p1067.pdf"],
  ["stats", "JASA 2020", "Cauchy Combination Test under Arbitrary Dependency Structures", "Liu, Xie",
    "Fusing 8 correlated detectors into one calibrated verdict", "https://arxiv.org/abs/1808.09011v1"],
  ["network", "NDSS 2023", "HyperVision: Unknown Encrypted Malicious Traffic via Flow Interaction Graphs", "Fu, Li, Xu",
    "Graph view of traffic behind the graph-rarity detector", "https://arxiv.org/pdf/2301.13686"],
  ["network", "Open source", "RITA: Real Intelligence Threat Analytics", "Active Countermeasures",
    "Beaconing (C2 periodicity) detection idea", "https://github.com/activecm/rita"],
  ["network", "Open source · CTU Prague", "Slips: Stratosphere Linux IPS", "Stratosphere Laboratory",
    "Base project, network sensor and detector D8", "https://github.com/stratosphereips/StratosphereLinuxIPS"],
  ["host", "IEEE S&P 2024", "KAIROS: Practical Intrusion Detection and Investigation using Whole-system Provenance", "Cheng et al.",
    "Related work: provenance-graph host detection", "https://arxiv.org/pdf/2308.05034"],
  ["host", "USENIX Security 2025", "TAPAS: Online APT Detection with Task-guided Provenance Graph Segmentation", "Zhang et al.",
    "Related work: scalable online APT detection", "https://www.usenix.org/conference/usenixsecurity25/presentation/zhang-bo-tapas"],
  ["host", "ACM CCS 2025", "Slot: Provenance-Driven APT Detection through Graph Reinforcement Learning", "",
    "Related work: graph reinforcement learning", "https://arxiv.org/html/2410.17910v4"],
  ["guidance", "IEEE S&P 2010", "Outside the Closed World: On Using Machine Learning for Network Intrusion Detection", "Sommer, Paxson",
    "Why false alarms sink anomaly IDS: our 8 false-alarm layers", "https://ieeexplore.ieee.org/document/5504793"],
  ["guidance", "USENIX Security 2022", "Dos and Don'ts of Machine Learning in Computer Security", "Arp et al.",
    "Evaluation hygiene: time-ordered split, base rates, ablation", "https://arxiv.org/abs/2010.09470"],
  ["guidance", "MITRE", "MITRE ATT&CK Enterprise Matrix", "",
    "Kill-chain stages and technique IDs in every verdict", "https://attack.mitre.org/"],
  ["gov", "CISA · Feb 2025", "Joint guidance on securing network edge devices", "CISA, ASD's ACSC, NCSC-UK and partners",
    "Why routers, firewalls and VPNs need dedicated detection", "https://cisa.gov/news-events/alerts/2025/02/04/cisa-partners-asds-acsc-cccs-ncsc-uk-and-other-international-and-us-organizations-release-guidance"],
  ["gov", "CISA · Sep 2025", "Emergency Directive 25-03: compromised Cisco devices", "CISA",
    "Edge-device implants that evade logs and IoCs", "https://cisa.gov/news-events/directives/ed-25-03-identify-and-mitigate-potential-compromise-cisco-devices"],
  ["gov", "ASD's ACSC · 2025", "Forensic visibility specifications for network devices", "Australian Cyber Security Centre",
    "Which logs edge devices should expose for forensics", "https://www.cyber.gov.au/business-government/protecting-devices-systems/hardening-systems-applications/network-hardening/securing-edge-devices/guidance-on-digital-forensics-and-protective-monitoring-specifications-for-producers-of-network-devices-and-appliances"],
];
const CAT_ICON = { network: "i-network", logs: "i-scroll-text", stats: "i-chart-line", host: "i-cpu", guidance: "i-badge-check", gov: "i-landmark" };
const DOCS = [
  ["00-overview", "i-eye", "Overview", "The 60-second version and key numbers"],
  ["03-architecture", "i-workflow", "Architecture", "Context, components, life of a window"],
  ["04-repository", "i-git-branch", "Repository tour", "Every file and what it does"],
  ["08-detectors", "i-scan-eye", "The eight detectors", "Intuition, maths and examples"],
  ["09-fusion-and-verdict", "i-git-compare", "Fusion & verdict", "Calibration, Cauchy, CUSUM, kill chain"],
  ["12-evaluation", "i-target", "Evaluation", "Scenarios, results, ablation, limits"],
  ["15-presentation-guide", "i-play", "Presentation guide", "Demo script and judge Q&A"],
  ["17-basics-se-samjho", "i-graduation-cap", "Basics se samjho", "Hinglish guide from absolute zero"],
  ["18-research-survey", "i-library", "Research survey", "Worldwide literature and GitHub projects"],
];

// real photographs (Wikimedia Commons, credits loaded from photos/credits.json)
const PHOTOS = [
  ["router.jpg", "w2 h2", "i-router", "Router", "Edge routers",
    "<b>Watches:</b> config drift, new tunnels and traffic mirroring, logging switched off, unusual syslog grammar, router-originated C2.",
    ["bad", "RTR-EDGE · compromised", 47, 48]],
  ["firewall.jpg", "w2", "i-brick-wall", "Firewall", "Perimeter firewalls",
    "<b>Watches:</b> any → internal rules, rogue admin accounts, exposed management, firewall-originated beacons.",
    ["warn", "FW-DC · under review", 70, 40]],
  ["switches.jpg", "", "i-network", "Switch", "Access switches", "<b>Watches:</b> rare internal edges, sudden fan-out, scans."],
  ["rack.jpg", "h2", "i-server", "Server", "Servers",
    "<b>Watches:</b> never-seen process chains, new user@source logins, exfiltration volume.", ["bad", "SRV-DB · compromised", 45, 30]],
  ["soc.jpg", "w2", "i-monitor", "SOC", "The analysts", "<b>Gets:</b> a calibrated verdict with a plain-language reason, not ten thousand raw alerts."],
  ["ports.jpg", "", "i-link", "Ports", "Every port is a path", "<b>Watches:</b> new destination ports, port entropy, failed connections."],
  ["datacenter.jpg", "w2", "i-database", "Data centre", "The whole fleet",
    "<b>Fleet consensus:</b> the same change on many peers at once is IT work, not an intrusion."],
  ["fiber.jpg", "", "i-zap", "Backbone", "Network sensors", "<b>Watches:</b> volume asymmetry, DNS tunnelling and beacons via Slips and Zeek."],
  ["cables.jpg", "", "i-waypoints", "Wiring", "Lateral movement", "<b>Graph rarity:</b> new internal paths to services nobody used before."],
];
const SHOTS = [
  ["overview", "i-map", "Overview", "/console", "Network map", "Seven compromised devices; dashed lines show the attack path in order of compromise."],
  ["matrix", "i-layers", "Evidence matrix", "/console#view=matrix", "Every device × every 15 minutes", "Attack campaigns light up as streaks; benign traps only flicker."],
  ["attack", "i-target", "ATT&CK map", "/console#view=attack", "MITRE ATT&CK coverage", "Techniques attributed from behaviour, without a single signature."],
  ["timeline", "i-clock", "Attack timeline", "/console#view=timeline", "One swim-lane per device", "Evidence dots, ATT&CK stages and verdict flags across the week."],
  ["device", "i-file-search", "Forensic report", "/console#device=RTR-EDGE", "Why RTR-EDGE was convicted", "Plain-language reason, evidence chart, detector coverage and playbook."],
  ["report", "i-printer", "Executive report", "/report", "Printable assessment", "One click from the console to a PDF for management."],
  ["dark", "i-moon", "Dark mode", "/console?theme=dark", "Night-shift ready", "Every screen in light and dark, English and हिंदी."],
];
const FEED_UI = {
  remcos: { icon: "i-laptop", flag: "MALICIOUS",
    note: "No IoC needed: a <b>never-seen Internet destination</b> is contacted 719 times like a metronome (2 % jitter) and <b>722 connections fail</b> in one window, far outside any workstation's baseline. The 0.5 s retry rhythm is faster than the beacon detector's 3-hour view, so the deviation detectors carry this one." },
  mozi: { icon: "i-router", flag: "PAYLOAD",
    note: "Mozi is an IoT botnet that infects <b>routers</b>. The device pulls <b>/Mozi.m</b> and <b>/bin.sh</b> from raw IP addresses. A hash list knows this only after Mozi is catalogued; a router suddenly downloading executables from never-seen hosts is abnormal on day one." },
  portscan: { icon: "i-radar", flag: "REJECTED",
    note: "<b>44 ports in one window, 86 % rejected.</b> Destination ports, port entropy and failed connections jump together, which TRINETRA maps to <b>Discovery (T1046)</b>, whoever the scanner is." },
  telnet: { icon: "i-satellite-dish", flag: "SCAN",
    note: "Sweeps of telnet <b>23 / 2323</b> and <b>8080</b> are how Mirai- and Mozi-style botnets find routers to infect. For TRINETRA these are fan-out and failed-connection features on the network sensor." },
  suricata: { icon: "i-brick-wall", flag: "IOC MATCH",
    note: "<b>73 % of these 745 alerts</b> come from IP reputation lists. Useful, but a fresh attacker IP produces none of them. That's why TRINETRA counts Slips/Suricata as <b>one vote out of eight</b>, not the verdict." },
};

/* ------------------------------------------------------------ render static */
$("#logo-track").innerHTML = [...LOGOS, ...LOGOS].map(([id, name, c]) =>
  `<span class="logo" style="--c:${c}">${icon(id, "ic b")}${esc(name)}</span>`).join("");
$("#timeline").innerHTML = TIMELINE.map(([y, n, d, ic], i) =>
  `<div class="tl ${i >= 4 ? "recent" : ""}"><div class="tl-dot">${icon(ic)}</div><div class="tl-y">${y}</div><div class="tl-n">${esc(n)}</div><div class="tl-d">${esc(d)}</div></div>`).join("");
$("#det-grid").innerHTML = DETECTORS.map(([n, ic, t, p, k]) =>
  `<article class="det reveal"><div class="top"><span class="ico-badge sm">${icon(ic)}</span><span class="dn">${n}</span></div>
   <h3>${esc(t)}</h3><p>${esc(p)}</p><span class="kind">${esc(k)}</span></article>`).join("");
$("#papers").innerHTML = PAPERS.map(([cat, venue, title, au, use, url]) =>
  `<article class="paper reveal" data-cat="${cat}"><div class="ptop"><span class="venue">${icon(CAT_ICON[cat])}${esc(venue)}</span></div>
   <h3>${esc(title)}</h3>${au ? `<p class="au">${esc(au)}</p>` : `<p class="au">&nbsp;</p>`}
   <div class="use"><b>Used for:</b> ${esc(use)}</div>
   <a class="lnk" href="${esc(url)}" target="_blank" rel="noopener">Open source ${icon("i-external-link")}</a></article>`).join("");
$("#doc-grid").innerHTML = DOCS.map(([slug, ic, t, d]) =>
  `<a class="doc reveal" href="/docs#/${slug}"><span class="ico-badge sm">${icon(ic)}</span><div><b>${esc(t)}</b><span>${esc(d)}</span></div>${icon("i-arrow-right", "ic go")}</a>`).join("");

/* research filter */
document.querySelectorAll("#paper-filter .chip").forEach((b) => b.addEventListener("click", () => {
  document.querySelectorAll("#paper-filter .chip").forEach((x) => x.classList.toggle("active", x === b));
  document.querySelectorAll(".paper").forEach((p) => p.classList.toggle("hide", b.dataset.f !== "all" && p.dataset.cat !== b.dataset.f));
}));

/* terminal tabs + copy */
document.querySelectorAll(".tt").forEach((t) => t.addEventListener("click", () => {
  document.querySelectorAll(".tt").forEach((x) => x.classList.toggle("active", x === t));
  $("#term-demo").hidden = t.dataset.t !== "demo";
  $("#term-linux").hidden = t.dataset.t !== "linux";
}));
$("#copy").addEventListener("click", () => {
  const pre = $("#term-demo").hidden ? $("#term-linux") : $("#term-demo");
  const text = [...pre.childNodes].filter((n) => !(n.classList && n.classList.contains("c"))).map((n) => n.textContent).join("")
    .split("\n").map((l) => l.trimEnd()).filter(Boolean).join("\n");
  navigator.clipboard?.writeText(text);
  $("#copy span").textContent = "Copied";
  setTimeout(() => ($("#copy span").textContent = "Copy"), 1400);
});

/* ------------------------------------------------------------ photo bento */
const STILL = location.hash === "#still";
if (STILL) document.documentElement.classList.add("still");
const photoCredit = {};
$("#bento").innerHTML = PHOTOS.map(([f, cls, ic, chip, title, more, hot]) => `
  <figure class="tile reveal ${cls}" data-f="${f}" tabindex="0">
    <img src="/static/img/photos/${f}" alt="${esc(title)}" loading="lazy">
    <div class="grid-ov"></div><div class="scan"></div>
    ${hot ? `<span class="hot ${hot[0]}" style="left:${hot[2]}%;top:${hot[3]}%"><i></i><b>${esc(hot[1])}</b></span>` : ""}
    <button class="cr" aria-label="Photo credit">i</button>
    <figcaption><span class="tchip">${icon(ic)}${esc(chip)}</span><h3>${esc(title)}</h3><p class="more">${more}</p></figcaption>
  </figure>`).join("");
document.querySelectorAll(".tile").forEach((t) => {
  t.addEventListener("pointermove", (e) => {
    const r = t.getBoundingClientRect(), x = (e.clientX - r.left) / r.width - 0.5, y = (e.clientY - r.top) / r.height - 0.5;
    t.style.setProperty("--ty", `${x * 7}deg`); t.style.setProperty("--tx", `${-y * 7}deg`);
    t.style.setProperty("--px", `${-x * 18}px`); t.style.setProperty("--py", `${-y * 18}px`);
  });
  t.addEventListener("pointerleave", () => ["--tx", "--ty", "--px", "--py"].forEach((p) => t.style.removeProperty(p)));
  const open = () => {
    const c = photoCredit[t.dataset.f];
    lightbox(`/static/img/photos/${t.dataset.f}`, t.querySelector("h3").textContent,
      c ? `${esc(c.title)} · ${esc(c.artist || "unknown author")} · ${esc(c.license)} · <a href="${esc(c.source)}" target="_blank" rel="noopener">source</a>` : "");
  };
  t.addEventListener("click", open);
  t.addEventListener("keydown", (e) => { if (e.key === "Enter") open(); });
});
fetch("/static/img/photos/credits.json").then((r) => r.json()).then((list) => {
  list.forEach((c) => {
    c.artist = (c.artist || "").replace(/<[^>]*>/g, "").trim();
    photoCredit[c.file] = c;
    const b = document.querySelector(`.tile[data-f="${c.file}"] .cr`);
    if (b) b.title = `${c.title} · ${c.artist || "unknown author"} · ${c.license}`;
  });
  $("#photo-credits").innerHTML = list.map((c) =>
    `<li><a href="${esc(c.source)}" target="_blank" rel="noopener">${esc(c.title)}</a> · ${esc(c.artist || "unknown author")} · ${esc(c.license)}</li>`).join("");
}).catch(() => {});

/* lightbox */
function lightbox(src, title, cap) {
  $("#lb-img").src = src; $("#lb-img").alt = title;
  $("#lb-cap").innerHTML = `<b>${esc(title)}</b>${cap ? " · " + cap : ""}`;
  $("#lightbox").hidden = false;
  $("#lb-x").focus();
}
const closeLb = () => { $("#lightbox").hidden = true; };
$("#lb-x").addEventListener("click", closeLb);
$("#lightbox").addEventListener("click", (e) => { if (e.target.id === "lightbox") closeLb(); });
addEventListener("keydown", (e) => { if (e.key === "Escape") closeLb(); });

/* ------------------------------------------------------------ real logs: ticker + viewer */
const FEED_ICON = (f) => FEED_UI[f.id]?.icon || "i-file-text";
let FEEDS = [], cur = 0, lineIdx = 0, streamT = null, paused = false, evVisible = STILL, nextT = null;
fetch("/static/data/real_logs.json").then((r) => r.json()).then((d) => {
  FEEDS = d.feeds;
  // hero ticker: interleave a few lines from every capture
  const items = [];
  for (let i = 0; i < 6; i++) FEEDS.forEach((f) => { const l = f.lines[i]; if (l) items.push([f, l]); });
  const html = items.map(([f, l]) => `<span class="${l.bad ? "bad" : ""}"><b>${esc(f.kind.split(" (")[0])}</b>${esc(l.text)}</span>`).join("");
  $("#tk-track").innerHTML = html + html;
  $("#ev-tabs").innerHTML = FEEDS.map((f, i) => `<button class="evt" role="tab" data-i="${i}"><span class="ei">${icon(FEED_ICON(f))}</span>
    <span>${esc(f.title)}<small>${esc(f.kind)}</small></span></button>`).join("");
  document.querySelectorAll(".evt").forEach((b) => b.addEventListener("click", () => selectFeed(+b.dataset.i, true)));
  $("#data-credits").innerHTML = FEEDS.map((f) => `<li><b>${esc(f.title)}</b> · ${esc(f.origin)} · <code>${esc(f.source)}</code></li>`).join("");
  selectFeed(0, false);
}).catch(() => {});

function selectFeed(i, user) {
  cur = i; lineIdx = 0; clearTimeout(streamT); clearTimeout(nextT);
  const f = FEEDS[i], ui = FEED_UI[f.id] || {};
  document.querySelectorAll(".evt").forEach((b) => { b.classList.toggle("active", +b.dataset.i === i); b.setAttribute("aria-selected", +b.dataset.i === i); });
  $("#lw-title").textContent = `${f.kind} · ${f.title}`;
  $("#lw-src").textContent = `${f.source} · ${f.origin}`;
  $("#lw-body").innerHTML = "";
  $("#ev-signals").innerHTML = f.signals.map(([k, v], j) => `<dt>${esc(k)}</dt><dd style="animation-delay:${j * 80}ms">${esc(v)}</dd>`).join("");
  $("#ev-note").innerHTML = ui.note || "";
  $("#ev-pulse-card").hidden = !f.pulses;
  if (f.pulses) drawPulses(f.pulses, f.id === "remcos" ? "C2 contact" : "probe");
  $("#ev-feat-card").hidden = !f.engine;
  if (f.engine) {
    $("#ev-feat-sub").textContent = `${f.engine.host} · busiest 15-min window`;
    const scale = (ft) => ft.feature === "ext_frac" ? ft.value : ft.feature === "dport_entropy" ? ft.value / 6 : Math.log1p(ft.value) / Math.log1p(1000);
    $("#ev-feats").innerHTML = f.engine.features.map((ft) => `<div class="ft ${ft.tactic && ft.value > 2 ? "al" : ""}">
      <span class="fl">${esc(ft.label)}${ft.tactic && ft.value > 2 ? `<small>→ ${esc(ft.tactic)}</small>` : ""}</span>
      <span class="tr"><i data-w="${Math.min(100, Math.max(2, scale(ft) * 100)).toFixed(1)}"></i></span><span class="fv">${ft.value}</span></div>`).join("");
    requestAnimationFrame(() => requestAnimationFrame(() => document.querySelectorAll("#ev-feats i").forEach((n) => (n.style.width = n.dataset.w + "%"))));
  }
  paused = false; setPauseIcon();
  if (user) evVisible = true;
  stream();
}
function lineHtml(f, l, n) {
  const flag = l.bad ? `<span class="flag">${esc(FEED_UI[f.id]?.flag || "ALERT")}</span>` : "";
  return `<div class="ll ${l.bad ? "bad" : ""}"><span class="no">${n}</span><span class="tx">${esc(l.text)}${flag}</span><span class="raw">${esc(l.raw)}</span></div>`;
}
function stream() {
  clearTimeout(streamT);
  const f = FEEDS[cur], body = $("#lw-body");
  if (!f) return;
  if (STILL) { body.innerHTML = f.lines.map((l, j) => lineHtml(f, l, j + 1)).join(""); lineIdx = f.lines.length; updCount(); return; }
  if (paused || !evVisible) return;
  if (lineIdx >= f.lines.length) {
    body.querySelector(".caret")?.remove();
    body.insertAdjacentHTML("beforeend", `<div><span class="caret"></span></div>`);
    nextT = setTimeout(() => { if (!paused && evVisible) selectFeed((cur + 1) % FEEDS.length, false); }, 6500);
    return;
  }
  body.insertAdjacentHTML("beforeend", lineHtml(f, f.lines[lineIdx], lineIdx + 1));
  lineIdx++; updCount();
  body.scrollTop = body.scrollHeight;
  streamT = setTimeout(stream, f.lines[lineIdx - 1].bad ? 650 : 380);
}
const updCount = () => {
  const f = FEEDS[cur];
  $("#lw-count").textContent = `${lineIdx}/${f.lines.length} lines · ${f.lines.slice(0, lineIdx).filter((l) => l.bad).length} flagged`;
};
const setPauseIcon = () => {
  $("#lw-pause").innerHTML = icon(paused ? "i-play" : "i-pause");
  $("#lw-pause").setAttribute("aria-label", paused ? "Resume stream" : "Pause stream");
};
$("#lw-pause").addEventListener("click", () => { paused = !paused; setPauseIcon(); clearTimeout(nextT); if (!paused) stream(); });
$("#lw-replay").addEventListener("click", () => selectFeed(cur, true));
$("#lw-body").addEventListener("click", (e) => { const l = e.target.closest(".ll"); if (l) l.classList.toggle("open"); });
new IntersectionObserver((es) => es.forEach((e) => {
  evVisible = e.isIntersecting;
  if (evVisible && FEEDS.length && lineIdx === 0) stream();
  else if (evVisible && FEEDS.length && lineIdx < FEEDS[cur].lines.length) stream();
}), { threshold: 0.25 }).observe($("#evidence"));

function drawPulses(ts, what) {
  const cv = $("#ev-pulse"), dpr = devicePixelRatio || 1, W = cv.clientWidth || 380, H = 70;
  cv.width = W * dpr; cv.height = H * dpr;
  const g = cv.getContext("2d"); g.setTransform(dpr, 0, 0, dpr, 0, 0);
  const span = ts[ts.length - 1] || 1, x = (t) => 8 + (t / span) * (W - 16);
  const iat = ts.slice(1).map((t, i) => t - ts[i]).sort((a, b) => a - b), med = iat[Math.floor(iat.length / 2)] || 0;
  const t0 = performance.now(), dur = STILL ? 0 : 1400, red = getComputedStyle(document.body).getPropertyValue("--bad").trim() || "#d03b3b";
  const frame = (now) => {
    const k = dur ? Math.min(1, (now - t0) / dur) : 1;
    g.clearRect(0, 0, W, H);
    g.strokeStyle = "rgba(11,11,11,.14)"; g.lineWidth = 1; g.beginPath(); g.moveTo(8, 44.5); g.lineTo(W - 8, 44.5); g.stroke();
    g.strokeStyle = red; g.lineWidth = 2; g.lineCap = "round";
    ts.forEach((t, i) => { if (i / ts.length <= k) { g.beginPath(); g.moveTo(x(t), 44); g.lineTo(x(t), 18); g.stroke(); } });
    g.fillStyle = "#52514e"; g.font = "600 11px Inter, system-ui, sans-serif";
    g.fillText(`${ts.length} × ${what} in ${span.toFixed(1)} s · median gap ${med.toFixed(2)} s`, 8, 62);
    if (k < 1) requestAnimationFrame(frame);
  };
  requestAnimationFrame(frame);
}

/* ------------------------------------------------------------ console showcase */
let shot = 0, shotT = null, scVisible = false;
$("#sc-tabs").innerHTML = SHOTS.map(([, ic, label], i) =>
  `<button class="sct" role="tab" data-i="${i}">${icon(ic)}${esc(label)}<span class="bar"></span></button>`).join("");
$("#br-view").innerHTML = SHOTS.map(([f, , label]) => `<img src="/static/img/shots/${f}.jpg" alt="TRINETRA console: ${esc(label)}" loading="lazy">`).join("")
  + `<div class="cap" id="sc-cap"></div>`;
function showShot(i) {
  shot = i; clearTimeout(shotT);
  const [, , , path, t, d] = SHOTS[i];
  document.querySelectorAll("#br-view img").forEach((im, j) => im.classList.toggle("on", j === i));
  document.querySelectorAll(".sct").forEach((b, j) => { b.classList.toggle("active", j === i); b.setAttribute("aria-selected", j === i); });
  $("#br-path").textContent = path;
  const cap = $("#sc-cap"); cap.outerHTML = `<div class="cap" id="sc-cap"><b>${esc(t)}</b>${esc(d)}</div>`;
  if (!STILL && scVisible && !$("#showcase").classList.contains("paused")) shotT = setTimeout(() => showShot((shot + 1) % SHOTS.length), 6000);
}
document.querySelectorAll(".sct").forEach((b) => b.addEventListener("click", () => showShot(+b.dataset.i)));
$("#br-view").addEventListener("click", () => lightbox(`/static/img/shots/${SHOTS[shot][0]}.jpg`, SHOTS[shot][4], esc(SHOTS[shot][5])));
$("#showcase").addEventListener("pointerenter", () => { $("#showcase").classList.add("paused"); clearTimeout(shotT); });
$("#showcase").addEventListener("pointerleave", () => { $("#showcase").classList.remove("paused"); showShot(shot); });
showShot(0);
new IntersectionObserver((es) => es.forEach((e) => {
  const was = scVisible; scVisible = e.isIntersecting;
  if (scVisible && !was) showShot(shot);
  if (!scVisible) clearTimeout(shotT);
}), { threshold: 0.3 }).observe($("#showcase"));

/* ------------------------------------------------------------ hero motion */
const ROTOR = ["router", "firewall", "server", "laptop", "network"];
let rot = 0;
if (!STILL) setInterval(() => { rot = (rot + 1) % ROTOR.length; $("#rotor").innerHTML = `<b>${ROTOR[rot]}</b>`; }, 2200);
const hero = $("#hero"), art = document.querySelector(".hero-art");
hero.addEventListener("pointermove", (e) => {
  const r = hero.getBoundingClientRect(), x = (e.clientX - r.left) / r.width, y = (e.clientY - r.top) / r.height;
  hero.style.setProperty("--gx", `${x * 100}%`); hero.style.setProperty("--gy", `${y * 100}%`);
  art.style.setProperty("--ry", `${(x - 0.5) * 5}deg`); art.style.setProperty("--rx", `${(0.5 - y) * 4}deg`);
});
hero.addEventListener("pointerleave", () => { art.style.removeProperty("--rx"); art.style.removeProperty("--ry"); });

/* split headings into words for a staggered reveal */
document.querySelectorAll(".split-words").forEach((h) => {
  let n = 0;
  [...h.childNodes].forEach((node) => {
    if (node.nodeType !== 3) return;
    const frag = document.createDocumentFragment();
    node.textContent.split(/(\s+)/).forEach((w) => {
      if (!w.trim()) { frag.append(w); return; }
      const s = document.createElement("span"); s.className = "w"; s.textContent = w; s.style.transitionDelay = `${120 + n++ * 70}ms`; frag.append(s);
    });
    node.replaceWith(frag);
  });
});

/* cursor spotlight on cards + magnetic primary buttons + scroll progress */
document.querySelectorAll(".card, .det, .dev, .paper, .doc, .ev-card, .numbers > div, .scn").forEach((el) => el.classList.add("spot"));
document.addEventListener("pointermove", (e) => {
  const el = e.target.closest?.(".spot");
  if (!el) return;
  const r = el.getBoundingClientRect();
  el.style.setProperty("--mx", `${e.clientX - r.left}px`); el.style.setProperty("--my", `${e.clientY - r.top}px`);
}, { passive: true });
document.querySelectorAll(".btn-primary").forEach((b) => {
  b.addEventListener("pointermove", (e) => {
    const r = b.getBoundingClientRect();
    b.style.transform = `translate(${(e.clientX - r.left - r.width / 2) * 0.18}px, ${(e.clientY - r.top - r.height / 2) * 0.3}px)`;
  });
  b.addEventListener("pointerleave", () => (b.style.transform = ""));
});
const onScroll = () => {
  const max = document.documentElement.scrollHeight - innerHeight;
  $("#progress").style.setProperty("--p", max > 0 ? scrollY / max : 0);
  const r = $("#showcase").getBoundingClientRect();
  const p = STILL ? 1 : Math.min(1, Math.max(0, (innerHeight - r.top) / (innerHeight * 0.75)));
  const br = document.querySelector(".browser");
  br.style.setProperty("--tilt", `${(1 - p) * 16}deg`); br.style.setProperty("--sc", (0.93 + 0.07 * p).toFixed(3));
};
addEventListener("scroll", onScroll, { passive: true });
onScroll();

/* ------------------------------------------------------------ reveal + count-up */
const countUp = (el) => {
  // reads the target every frame, so live numbers arriving mid-animation still land correctly
  if (location.hash === "#still") { el.textContent = el.dataset.count; return; }
  const dur = 1200, t0 = performance.now();
  const step = (now) => {
    const k = Math.min(1, (now - t0) / dur), e = 1 - Math.pow(1 - k, 3);
    el.textContent = Math.round(+el.dataset.count * e);
    if (k < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
};
const io = new IntersectionObserver((entries) => entries.forEach((e) => {
  if (!e.isIntersecting) return;
  e.target.classList.add("in");
  e.target.querySelectorAll?.("[data-count]").forEach(countUp);
  io.unobserve(e.target);
}), { threshold: 0.15 });
const watch = () => document.querySelectorAll(".reveal:not(.in), #steps, .proof").forEach((el, i) => {
  if (el.classList.contains("reveal")) el.style.transitionDelay = `${(i % 4) * 60}ms`;
  io.observe(el);
});
watch();
const still = location.hash === "#still";
const revealAll = (all = false) => document.querySelectorAll(".reveal:not(.in), #steps:not(.in), .proof:not(.in)").forEach((el) => {
  if (all || el.getBoundingClientRect().top < innerHeight) { el.classList.add("in"); el.querySelectorAll("[data-count]").forEach(countUp); }
});
if (still) revealAll(true);
addEventListener("load", () => setTimeout(() => revealAll(still), 300));
addEventListener("beforeprint", () => revealAll(true));
addEventListener("scroll", () => $("#nav").style.boxShadow = scrollY > 20 ? "0 10px 30px -14px rgba(16,36,64,.35)" : "", { passive: true });

/* ------------------------------------------------------------ live data */
fetch("/api/results").then((r) => (r.ok ? r.json() : null)).then((R) => {
  if (!R) return;
  const ev = R.evaluation;
  const setCount = (k, v) => document.querySelectorAll(`[data-k="${k}"]`).forEach((n) => {
    if (n.dataset.count !== undefined) n.dataset.count = v;
    n.textContent = v;
  });
  if (ev) {
    setCount("tp", ev.tp); setCount("n_attacked", ev.n_attacked); setCount("fp", ev.fp);
    setCount("ttd", ev.median_ttd_min ?? 0); setCount("ttd2", ev.median_ttd_min ?? 0);
    setCount("precision", Math.round(ev.precision * 100)); setCount("recall", Math.round(ev.recall * 100)); setCount("fp2", ev.fp);
  }
  // ablation bars (clean devices raising any alarm)
  const ab = R.ablation || [];
  const pick = (s) => ab.find((a) => a.variant.startsWith(s));
  const rows = [["Full system", pick("Full")], ["Without fleet consensus", pick("Without fleet")],
    ["Without kill-chain corroboration", pick("Without kill")], ["Graph rarity alone", pick("Single detector: Rare")],
    ["Autoencoder alone", pick("Single detector: Autoencoder")]].filter((r) => r[1]);
  if (rows.length) {
    const max = Math.max(1, ...rows.map((r) => r[1].clean_devices_with_any_alarm));
    $("#bars").innerHTML = rows.map(([l, a], i) => `<div class="bar-row ${i === 0 ? "best" : ""}"><span class="lbl">${esc(l)}</span>
      <span class="trk"><span class="fil" style="--w:${Math.max(3, (a.clean_devices_with_any_alarm / max) * 100)}%"></span></span>
      <span class="n">${a.clean_devices_with_any_alarm}</span></div>`).join("");
    const f = pick("Full");
    $("#bars-note").textContent = `Full system: ${f.fp} clean devices wrongly convicted, ${f.tp}/${f.tp + f.fn} attacked devices caught.`;
  }
  // scenarios
  const final = Object.fromEntries(R.devices.map((d) => [d.id, d.verdict]));
  const pill = (v) => v === "COMPROMISED" ? `<span class="status s-bad">${icon("i-shield-alert")}Caught</span>`
    : v === "SUSPICIOUS" ? `<span class="status s-warn">${icon("i-triangle-alert")}Under review</span>`
      : `<span class="status s-good">${icon("i-circle-check")}Stayed clean</span>`;
  $("#scenarios").innerHTML = (R.truth?.scenarios || []).map((s) => {
    let v;
    if (s.devices[0] === "all hosts") {
      const other = new Set(R.truth.scenarios.filter((x) => x !== s).flatMap((x) => x.devices));
      const own = R.devices.filter((d) => d.type === "host" && !other.has(d.id));
      v = own.every((d) => d.verdict === "CLEAN") ? "CLEAN" : "SUSPICIOUS";
    } else if (s.kind === "attack") v = s.devices.every((d) => final[d] === "COMPROMISED") ? "COMPROMISED" : "SUSPICIOUS";
    else v = s.devices.some((d) => final[d] === "COMPROMISED") ? "COMPROMISED" : s.devices.some((d) => final[d] === "SUSPICIOUS") ? "SUSPICIOUS" : "CLEAN";
    return `<div class="scn reveal"><span class="sid ${s.kind === "attack" ? "atk" : "ben"}">${s.id}</span>
      <div class="st"><b>${esc(s.title)}</b><small>${s.kind === "attack" ? "attack" : "benign trap"} · ${esc(s.devices.join(", "))}</small></div>${pill(v)}</div>`;
  }).join("");
  watch();
  if (still) revealAll(true);
}).catch(() => {});
