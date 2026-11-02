"use strict";
/* Plain-language explanation of a device verdict (template-based, deterministic, no AI).
   Used by the console drawer, story mode and the executive report. */
(function () {
  const D = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  const pad = (n) => String(n).padStart(2, "0");
  const when = (ts) => { const d = new Date(ts * 1000); return `${D[d.getUTCDay()]} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`; };
  const list = (a, lang) => a.length <= 1 ? (a[0] || "") : a.slice(0, -1).join(", ") + (lang === "hi" ? " और " : " and ") + a.at(-1);

  function verdictAt(R, id, T) {
    let v = "CLEAN", reason = "", ts = null;
    for (const e of [...R.verdict_events].sort((a, b) => a.ts - b.ts)) if (e.device === id && e.ts <= T) { v = e.to; reason = e.reason; ts = e.ts; }
    return { v, reason, ts };
  }

  function facts(R, id, T) {
    const evs = (R.evidence[id] || []).filter((e) => e.ts <= T).sort((a, b) => a.ts - b.ts);
    const tactics = [...new Set(evs.flatMap((e) => Object.keys(e.tactics)))];
    const feats = [], seen = new Set();
    for (const e of [...evs].sort((a, b) => b.score - a.score)) for (const f of e.top_features) if (!seen.has(f.key) && feats.length < 3) { seen.add(f.key); feats.push(f); }
    const cfg = evs.flatMap((e) => e.config || [])[0];
    const beacon = evs.map((e) => e.beacon).find(Boolean);
    const logins = [...new Set(evs.flatMap((e) => e.new_logins || []))].slice(0, 2);
    const procs = [...new Set(evs.flatMap((e) => e.new_processes || []))].slice(0, 2);
    const internal = evs.reduce((m, e) => Math.max(m, e.n_new_internal || 0), 0);
    return { evs, tactics, feats, cfg, beacon, logins, procs, internal, first: evs[0] };
  }

  function explainDevice(R, id, lang = "en", T = Infinity) {
    const d = R.devices.find((x) => x.id === id);
    const v = verdictAt(R, id, T), f = facts(R, id, T), hi = lang === "hi";
    const P = [];
    if (!f.evs.length && v.v === "CLEAN") {
      P.push(hi ? `${id} ने पूरे समय अपने सीखे हुए सामान्य व्यवहार जैसा ही काम किया। किसी भी detector ने महत्वपूर्ण सबूत नहीं दिया।`
        : `${id} behaved like its learned baseline the whole time. No detector produced significant evidence.`);
      return { headline: hi ? "सब सामान्य" : "Nothing unusual", paragraphs: P };
    }
    if (f.first) P.push(hi ? `पहला असामान्य संकेत ${when(f.first.ts)} पर मिला।` : `The first unusual window was ${when(f.first.ts)}.`);
    const sig = [];
    if (f.cfg) {
      const risks = f.cfg.risks.map((r) => r.risk.toLowerCase());
      sig.push(hi ? `कॉन्फ़िगरेशन बदला गया (${list(risks, lang)}), ${f.cfg.known_admin ? "जाने-पहचाने admin" : "अनजान व्यक्ति"} द्वारा, ${f.cfg.maintenance_window ? "maintenance समय में" : "maintenance समय के बाहर"} (${f.cfg.actor})`
        : `its configuration was changed (${list(risks, lang)}) by ${f.cfg.known_admin ? "a known admin" : "an unknown actor"} ${f.cfg.maintenance_window ? "inside" : "outside"} the maintenance window (${f.cfg.actor})`);
    }
    if (f.beacon) sig.push(hi ? `यह हर ${f.beacon.period_s} सेकंड पर ${f.beacon.dst} को घड़ी की तरह कॉल कर रहा था (beaconing)`
      : `it called ${f.beacon.dst} like clockwork every ${f.beacon.period_s} s (beaconing)`);
    if (f.procs.length) sig.push(hi ? `पहली बार ये प्रोग्राम-चेन चलीं: ${list(f.procs, lang)}` : `never-seen process chains ran: ${list(f.procs, lang)}`);
    if (f.logins.length) sig.push(hi ? `नए लॉगिन दिखे: ${list(f.logins, lang)}` : `new logins appeared: ${list(f.logins, lang)}`);
    if (f.internal >= 10) sig.push(hi ? `एक ही 15 मिनट में ${f.internal} नए अंदरूनी कनेक्शन (scanning)` : `${f.internal} new internal connections in one window (scanning)`);
    for (const ft of f.feats) if (sig.length < 5) sig.push(hi ? `"${ft.feature}" ${ft.value} था जबकि सामान्य ${ft.normal}` : `"${ft.feature}" was ${ft.value} against a normal of ${ft.normal}`);
    if (sig.length) P.push((hi ? "मुख्य सबूत: " : "Key evidence: ") + sig.join("; ") + ".");
    if (v.v === "COMPROMISED") {
      const prop = /received a new connection/.test(v.reason);
      P.push(hi ? `${when(v.ts)} पर इसे "हैक हुआ" घोषित किया गया क्योंकि ${prop ? "यह पहले से संदिग्ध था और एक हैक हुए डिवाइस से इसे नया कनेक्शन मिला (lateral movement)" : `गड़बड़ी लगातार बनी रही और ${f.tactics.length} अलग हमले के चरण दिखे: ${list(f.tactics, lang)}`}।`
        : `TRINETRA convicted it at ${when(v.ts)} because ${prop ? "it was already suspicious and received a new connection from a compromised device (lateral movement)" : `the anomaly persisted and spanned ${f.tactics.length} independent attack stages: ${list(f.tactics, lang)}`}.`);
      const act = (R.actions || {})[d.type]?.[0];
      if (act) P.push((hi ? "सबसे पहला कदम: " : "First response step: ") + act + ".");
    } else if (v.v === "SUSPICIOUS") {
      P.push(hi ? `यह गड़बड़ी लगातार है लेकिन ${f.tactics.length ? `सिर्फ़ एक चरण (${f.tactics[0]})` : "कोई हमले का चरण"} दिखा, इसलिए इसे "संदिग्ध" रखा गया है, हैक नहीं। Analyst इसे जाँच कर "Mark benign" कर सकता है।`
        : `The anomaly is persistent but shows ${f.tactics.length ? `only one attack stage (${f.tactics[0]})` : "no attack stage"}, so it stays SUSPICIOUS rather than compromised. An analyst can review it and mark it benign.`);
    } else {
      P.push(hi ? "कुछ असामान्य window थीं, लेकिन सबूत इतना लगातार नहीं था कि alarm बजे।" : "There were some unusual windows, but the evidence never persisted long enough to raise an alarm.");
    }
    const headline = v.v === "COMPROMISED" ? (hi ? "हैक होने के पक्के सबूत" : "Multi-stage compromise") : v.v === "SUSPICIOUS" ? (hi ? "जाँच ज़रूरी" : "Needs review") : (hi ? "सामान्य" : "Within baseline");
    return { headline, paragraphs: P };
  }

  function storyCaption(R, e, lang = "en") {
    const x = explainDevice(R, e.device, lang, e.ts);
    return x.paragraphs.slice(1, 3).join(" ") || x.paragraphs[0];
  }

  window.explainDevice = explainDevice;
  window.storyCaption = storyCaption;
})();
