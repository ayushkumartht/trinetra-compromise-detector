/* Theme bootstrap: load in <head> so the page never flashes the wrong theme. */
(function () {
  const q = new URLSearchParams(location.search).get("theme");          // ?theme=dark|light (demo links)
  if (q === "dark" || q === "light") localStorage.setItem("trinetra-theme", q);
  const t = localStorage.getItem("trinetra-theme") || "light";
  document.documentElement.dataset.theme = t;
})();
window.toggleTheme = function () {
  const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  localStorage.setItem("trinetra-theme", next);
  window.dispatchEvent(new Event("themechange"));
};
window.cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
