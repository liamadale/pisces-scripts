/**
 * PISCES Theme Toggle — shared across all web apps.
 *
 * Usage:
 *   <head>: <script src="/shared/static/theme.js"></script>
 *   (the IIFE at the top applies the saved theme before CSS loads)
 *
 *   Settings page: <select onchange="setTheme(this.value)">
 */

/* Flash-prevention: apply saved theme immediately */
(function () {
  var MIGRATE = { 'dark': 'pisces-dark', 'light': 'pisces-light' };
  var t = localStorage.getItem('pisces-theme') || 'pisces-dark';
  if (MIGRATE[t]) { t = MIGRATE[t]; localStorage.setItem('pisces-theme', t); }
  document.documentElement.setAttribute('data-theme', t);
})();

/* Set a specific theme by name */
window.setTheme = function (theme) {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('pisces-theme', theme);
};
