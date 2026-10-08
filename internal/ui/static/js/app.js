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
