"use strict";
/* Docs site: renders trinetra_docs/*.md (the same files GitHub renders) with marked + mermaid, offline. */

const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const slugify = (s) => s.toLowerCase().replace(/<[^>]+>/g, "").replace(/[^\w\s-]/g, "").trim().replace(/\s+/g, "-");

mermaid.initialize({
  startOnLoad: false, securityLevel: "strict", theme: "base",
  fontFamily: '"Inter", system-ui, "Segoe UI", sans-serif',
  themeVariables: {
    darkMode: false, background: "#ffffff", fontSize: "14px",
    primaryColor: "#eef4fc", primaryTextColor: "#0b0b0b", primaryBorderColor: "#2a78d6",
    secondaryColor: "#e8f7f0", secondaryTextColor: "#0b0b0b", secondaryBorderColor: "#1baf7a",
    tertiaryColor: "#f7f8fa", tertiaryTextColor: "#0b0b0b", tertiaryBorderColor: "#c3c2b7",
    lineColor: "#6d8fb8", textColor: "#2c2b29", mainBkg: "#eef4fc", nodeBorder: "#2a78d6",
    clusterBkg: "#f7f9fc", clusterBorder: "#cde2fb", titleColor: "#1c5cab", edgeLabelBackground: "#ffffff",
    noteBkgColor: "#fff4d6", noteTextColor: "#0b0b0b", noteBorderColor: "#fab219",
    actorBkg: "#eef4fc", actorBorder: "#2a78d6", actorTextColor: "#0b0b0b", actorLineColor: "#9fb7d6",
    signalColor: "#52514e", signalTextColor: "#0b0b0b", labelBoxBkgColor: "#eef4fc", labelBoxBorderColor: "#2a78d6",
    labelTextColor: "#0b0b0b", loopTextColor: "#0b0b0b", activationBkgColor: "#cde2fb", activationBorderColor: "#2a78d6",
    sequenceNumberColor: "#ffffff",
    taskBkgColor: "#cde2fb", taskTextColor: "#0b0b0b", taskTextLightColor: "#0b0b0b", taskTextOutsideColor: "#0b0b0b",
    taskBorderColor: "#2a78d6", activeTaskBkgColor: "#9ec5f4", activeTaskBorderColor: "#1c5cab",
    critBkgColor: "#fdecec", critBorderColor: "#d03b3b", doneTaskBkgColor: "#e1e0d9", doneTaskBorderColor: "#c3c2b7",
    gridColor: "#e1e0d9", sectionBkgColor: "#f7f9fc", altSectionBkgColor: "#ffffff", sectionBkgColor2: "#eef4fc",
    todayLineColor: "#d03b3b",
    stateBkg: "#eef4fc", stateLabelColor: "#0b0b0b", compositeBackground: "#f7f9fc", altBackground: "#ffffff",
    classText: "#0b0b0b", fillType0: "#eef4fc", fillType1: "#e8f7f0",
    cScale0: "#2a78d6", cScale1: "#1baf7a", cScale2: "#6250d6", cScale3: "#eb6834", cScale4: "#e87ba4",
  },
  flowchart: { curve: "basis", padding: 14, htmlLabels: true }, sequence: { mirrorActors: false }, gantt: { barHeight: 18, fontSize: 11 },
});

let PAGES = [], renderSeq = 0;
async function init() {
  PAGES = await (await fetch("/api/docs")).json();
  renderNav();
  addEventListener("hashchange", route);
  route();
}
function renderNav(filter = "") {
  const f = filter.toLowerCase(), groups = {};
  PAGES.filter((p) => !f || p.title.toLowerCase().includes(f) || p.group.toLowerCase().includes(f) || (p.text || "").includes(f))
    .forEach((p) => (groups[p.group] ||= []).push(p));
  $("#toc-nav").innerHTML = Object.entries(groups).map(([g, ps]) => `<div class="grp"><div class="grp-t">${esc(g)}</div>
    ${ps.map((p) => `<a href="#/${p.slug}" data-slug="${p.slug}"><span class="n">${p.n}</span><span>${esc(p.title)}</span></a>`).join("")}</div>`).join("")
    || `<div class="dim small">No match.</div>`;
  markActive();
}
function markActive() {
  const cur = current();
  document.querySelectorAll("#toc-nav a").forEach((a) => a.classList.toggle("active", a.dataset.slug === cur));
}
const current = () => (location.hash.replace(/^#\/?/, "").split("#")[0] || PAGES[0]?.slug);

async function route() {
  const slug = current(), i = PAGES.findIndex((p) => p.slug === slug);
  if (i < 0) { location.hash = "#/" + PAGES[0].slug; return; }
  markActive();
  const md = await (await fetch(`/docs/raw/${slug}`)).text();
  const art = $("#doc");
  art.innerHTML = marked.parse(md, { gfm: true });
  // mermaid blocks - rendered one by one with unique ids (mermaid.run can reuse a timestamp id
  // for several diagrams on one page, which draws them into the same SVG)
  const blocks = [...art.querySelectorAll("pre code.language-mermaid")];
  for (const [k, c] of blocks.entries()) {
    const div = document.createElement("div");
    div.className = "mermaid";
    c.parentElement.replaceWith(div);
    try {
      const { svg, bindFunctions } = await mermaid.render(`mmd-${slug}-${k}-${renderSeq++}`, c.textContent);
      div.innerHTML = svg;
      bindFunctions?.(div);
    } catch (e) {
      div.innerHTML = `<pre class="mono dim">diagram error: ${esc(e.message || e)}</pre>`;
    }
  }
  // copy buttons
  art.querySelectorAll("pre").forEach((pre) => {
    const b = document.createElement("button");
    b.className = "copy"; b.textContent = "Copy";
    b.onclick = () => { navigator.clipboard?.writeText(pre.querySelector("code")?.textContent || ""); b.textContent = "Copied"; setTimeout(() => (b.textContent = "Copy"), 1200); };
    pre.appendChild(b);
  });
  // internal .md links -> doc routes
  art.querySelectorAll('a[href$=".md"], a[href*=".md#"]').forEach((a) => {
    const m = a.getAttribute("href").match(/([\w-]+)\.md(#.*)?$/);
    if (m && PAGES.some((p) => p.slug === m[1])) a.setAttribute("href", `#/${m[1]}`);
  });
  // headings + on-this-page
  const heads = [...art.querySelectorAll("h2, h3")];
  heads.forEach((h) => (h.id = slugify(h.textContent)));
  $("#onpage").innerHTML = heads.map((h) => `<a class="${h.tagName.toLowerCase()}" href="#/${slug}#${h.id}" data-id="${h.id}">${esc(h.textContent)}</a>`).join("");
  document.querySelectorAll("#onpage a").forEach((a) => a.addEventListener("click", (e) => {
    e.preventDefault(); document.getElementById(a.dataset.id)?.scrollIntoView({ behavior: "smooth" });
  }));
  const prev = PAGES[i - 1], next = PAGES[i + 1];
  $("#pager").innerHTML = (prev ? `<a href="#/${prev.slug}"><small>← Previous</small><b>${esc(prev.title)}</b></a>` : "<span></span>") +
    (next ? `<a class="next" href="#/${next.slug}"><small>Next →</small><b>${esc(next.title)}</b></a>` : "");
  document.title = `${PAGES[i].title} · TRINETRA Docs`;
  const anchor = location.hash.split("#")[2];
  if (anchor) document.getElementById(anchor)?.scrollIntoView(); else scrollTo(0, 0);
}
// scroll spy
addEventListener("scroll", () => {
  const heads = [...document.querySelectorAll("#doc h2, #doc h3")];
  let cur = heads[0]?.id;
  for (const h of heads) if (h.getBoundingClientRect().top < 120) cur = h.id;
  document.querySelectorAll("#onpage a").forEach((a) => a.classList.toggle("active", a.dataset.id === cur));
}, { passive: true });
$("#q").addEventListener("input", (e) => renderNav(e.target.value));
init();
