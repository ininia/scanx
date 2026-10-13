// scanX UI helpers (no inline scripts: CSP script-src 'self').
// Copy buttons: <button data-copy="text">.
document.addEventListener("click", function (e) {
  var btn = e.target.closest("[data-copy]");
  if (!btn) return;
  e.preventDefault();
  var text = btn.getAttribute("data-copy");
  var done = function () {
    var old = btn.textContent;
    btn.textContent = "✓";
    btn.classList.add("copied");
    setTimeout(function () { btn.textContent = old; btn.classList.remove("copied"); }, 1500);
  };
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(done, function () {});
    return;
  }
  // Fallback for http:// or self-signed contexts without the async API.
  var ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("readonly", "");
  ta.className = "sr-only";
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand("copy"); done(); } catch (err) { /* ignore */ }
  document.body.removeChild(ta);
});

// Theme switch: <button data-theme-toggle>. Toggles between dark and light
// starting from the theme currently shown (explicit choice or OS setting).
document.addEventListener("click", function (e) {
  if (!e.target.closest("[data-theme-toggle]")) return;
  var root = document.documentElement;
  var current = root.getAttribute("data-theme");
  if (current !== "light" && current !== "dark") {
    current = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }
  var next = current === "light" ? "dark" : "light";
  root.setAttribute("data-theme", next);
  try { localStorage.setItem("scanx-theme", next); } catch (err) { /* not persisted */ }
});

// Sidebar collapse: <button data-sidebar-toggle>; remembered per browser.
document.addEventListener("click", function (e) {
  if (!e.target.closest("[data-sidebar-toggle]")) return;
  var root = document.documentElement;
  var on = !root.classList.contains("sidebar-collapsed");
  root.classList.toggle("sidebar-collapsed", on);
  try { localStorage.setItem("scanx-sidebar", on ? "collapsed" : "open"); } catch (err) { /* not persisted */ }
});

// Cmd/Ctrl+K focuses the top search box.
document.addEventListener("keydown", function (e) {
  if ((e.metaKey || e.ctrlKey) && (e.key === "k" || e.key === "K")) {
    var box = document.querySelector("[data-search-input]");
    if (box) { e.preventDefault(); box.focus(); box.select(); }
  }
});

// Client-side table filter: <input data-filter-input="id">, <select
// data-filter-status="id"> and <table data-filter-table="id"> whose rows
// carry data-filter-row and data-status.
function scanxFilter(id) {
  var table = document.querySelector('[data-filter-table="' + id + '"]');
  if (!table) return;
  var text = document.querySelector('[data-filter-input="' + id + '"]');
  var status = document.querySelector('[data-filter-status="' + id + '"]');
  var q = text ? text.value.trim().toLowerCase() : "";
  var st = status ? status.value : "";
  table.querySelectorAll("[data-filter-row]").forEach(function (row) {
    var ok = (!q || row.textContent.toLowerCase().indexOf(q) >= 0) && (!st || row.getAttribute("data-status") === st);
    row.hidden = !ok;
  });
}
document.addEventListener("input", function (e) {
  var id = e.target.getAttribute && (e.target.getAttribute("data-filter-input") || e.target.getAttribute("data-filter-status"));
  if (id) scanxFilter(id);
});
document.addEventListener("change", function (e) {
  var id = e.target.getAttribute && e.target.getAttribute("data-filter-status");
  if (id) scanxFilter(id);
});
