// Applies the saved theme and sidebar state before first paint (loaded synchronously in
// <head>; inline scripts are not allowed by the CSP).
(function () {
  try {
    var t = localStorage.getItem("scanx-theme");
    if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t);
    if (localStorage.getItem("scanx-sidebar") === "collapsed") document.documentElement.classList.add("sidebar-collapsed");
  } catch (e) { /* storage unavailable: follow the OS setting */ }
})();
