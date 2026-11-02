"use strict";
/* English / हिंदी interface strings. tr(key, {vars}) falls back to English, then to the key. */
const I18N = {
  en: {
    "nav.overview": "Overview", "nav.matrix": "Evidence matrix", "nav.devices": "Devices", "nav.incidents": "Incidents",
    "nav.attack": "ATT&CK map", "nav.timeline": "Attack timeline", "nav.whatif": "What-if lab", "nav.live": "Live attack lab",
    "nav.evaluation": "Evaluation", "side.export": "Export", "side.cef": "CEF for SIEM", "side.json": "JSON report",
    "side.report": "Executive report (PDF)", "side.learn": "Learn", "side.docs": "Documentation", "side.home": "Project home",
    "side.upload": "Upload your data", "btn.rerun": "Re-run analysis", "btn.now": "Now", "btn.story": "Story mode",
    "bar.time": "Analysis time", "v.COMPROMISED": "Compromised", "v.SUSPICIOUS": "Suspicious", "v.CLEAN": "Clean",
    "kpi.monitored": "Monitored", "kpi.compromised": "Compromised", "kpi.suspicious": "Suspicious", "kpi.clean": "Clean",
    "kpi.incidents": "Open incidents", "kpi.d.comp": "≥ 2 attack stages", "kpi.d.sus": "persistent, single stage",
    "kpi.d.clean": "within baseline", "status.comp": "Network compromised: {n} device(s) need response",
    "status.sus": "Suspicious behaviour under review", "status.clean": "No compromise detected",
    "status.sub.comp": "Compromised: {list}", "status.sub.review": " · Under review: {list}",
    "status.sub.sus": "Single-stage anomalies on {list}", "status.sub.clean": "All {n} devices behave like their learned baseline",
    "status.last": "Last verdict change", "map.title": "Network map",
    "map.sub": "Hover to trace connections · drag to rearrange · scroll to zoom · click for the report",
    "map.all": "All", "map.comp": "Compromised", "map.sus": "Suspicious", "map.attack": "Attack paths",
    "inc.title": "Open incidents", "inc.sub": "Linked by connections, logins or shared attacker infrastructure",
    "feed.title": "Verdict feed", "feed.count": "{n} verdict change(s) so far", "matrix.title": "Evidence matrix",
    "matrix.sub": "Every device × every 15 minutes · darker = more unusual for that device", "why.title": "Why this verdict?",
    "toast.comp": "{d} is now COMPROMISED", "toast.sus": "{d} is now SUSPICIOUS", "toast.clean": "{d} is clean again",
    "palette.ph": "Type a command or a device name…", "story.next": "Next", "story.prev": "Back", "story.auto": "Auto-play",
    "story.exit": "Exit", "story.open": "Open report",
  },
  hi: {
    "nav.overview": "अवलोकन", "nav.matrix": "सबूत मैट्रिक्स", "nav.devices": "डिवाइस", "nav.incidents": "घटनाएँ",
    "nav.attack": "ATT&CK नक्शा", "nav.timeline": "हमले की टाइमलाइन", "nav.whatif": "क्या-अगर लैब", "nav.live": "लाइव हमला लैब",
    "nav.evaluation": "मूल्यांकन", "side.export": "निर्यात", "side.cef": "SIEM के लिए CEF", "side.json": "JSON रिपोर्ट",
    "side.report": "रिपोर्ट (PDF)", "side.learn": "सीखें", "side.docs": "दस्तावेज़", "side.home": "होम पेज",
    "side.upload": "अपना डेटा अपलोड करें", "btn.rerun": "फिर से विश्लेषण", "btn.now": "अभी", "btn.story": "कहानी मोड",
    "bar.time": "विश्लेषण समय", "v.COMPROMISED": "हैक हुआ", "v.SUSPICIOUS": "संदिग्ध", "v.CLEAN": "सुरक्षित",
    "kpi.monitored": "निगरानी में", "kpi.compromised": "हैक हुए", "kpi.suspicious": "संदिग्ध", "kpi.clean": "सुरक्षित",
    "kpi.incidents": "खुली घटनाएँ", "kpi.d.comp": "≥ 2 हमले के चरण", "kpi.d.sus": "लगातार, एक चरण", "kpi.d.clean": "सामान्य व्यवहार",
    "status.comp": "नेटवर्क हैक हुआ: {n} डिवाइस पर तुरंत कार्रवाई चाहिए", "status.sus": "संदिग्ध व्यवहार की जाँच जारी",
    "status.clean": "कोई हैक नहीं मिला", "status.sub.comp": "हैक हुए: {list}", "status.sub.review": " · जाँच में: {list}",
    "status.sub.sus": "एक-चरण वाली गड़बड़ी: {list}", "status.sub.clean": "सभी {n} डिवाइस अपने सामान्य व्यवहार में हैं",
    "status.last": "आख़िरी बदलाव", "map.title": "नेटवर्क नक्शा",
    "map.sub": "माउस ले जाएँ: कनेक्शन देखें · खींचें: जगह बदलें · स्क्रॉल: ज़ूम · क्लिक: रिपोर्ट",
    "map.all": "सभी", "map.comp": "हैक हुए", "map.sus": "संदिग्ध", "map.attack": "हमले का रास्ता",
    "inc.title": "खुली घटनाएँ", "inc.sub": "कनेक्शन, लॉगिन या एक ही हमलावर से जुड़े डिवाइस",
    "feed.title": "फ़ैसलों की सूची", "feed.count": "अब तक {n} बदलाव", "matrix.title": "सबूत मैट्रिक्स",
    "matrix.sub": "हर डिवाइस × हर 15 मिनट · जितना गहरा, उतना असामान्य", "why.title": "यह फ़ैसला क्यों?",
    "toast.comp": "{d} अब हैक घोषित", "toast.sus": "{d} अब संदिग्ध", "toast.clean": "{d} फिर से सुरक्षित",
    "palette.ph": "कमांड या डिवाइस का नाम लिखें…", "story.next": "आगे", "story.prev": "पीछे", "story.auto": "अपने-आप चलाएँ",
    "story.exit": "बंद करें", "story.open": "रिपोर्ट खोलें",
  },
};
let LANG = localStorage.getItem("trinetra-lang") || "en";
function tr(key, vars) {
  let s = (I18N[LANG] && I18N[LANG][key]) ?? I18N.en[key] ?? key;
  if (vars) for (const [a, b] of Object.entries(vars)) s = s.split(`{${a}}`).join(b);
  return s;
}
function applyI18n() {
  document.querySelectorAll("[data-i18n]").forEach((el) => (el.textContent = tr(el.dataset.i18n)));
  document.querySelectorAll("[data-i18n-ph]").forEach((el) => (el.placeholder = tr(el.dataset.i18nPh)));
  document.documentElement.lang = LANG === "hi" ? "hi" : "en";
}
function setLang(l) {
  LANG = l;
  localStorage.setItem("trinetra-lang", l);
  applyI18n();
  window.dispatchEvent(new Event("langchange"));
}
