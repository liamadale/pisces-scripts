/**
 * PISCES Theme Toggle — shared across all web apps.
 *
 * Usage:
 *   <head>: <script src="/shared/static/theme.js"></script>
 *   (the IIFE at the top applies the saved theme before CSS loads)
 *
 *   <body>: <button onclick="toggleTheme()">…</button>
 */

/* Flash-prevention: apply saved theme immediately */
(function () {
  var t = localStorage.getItem('pisces-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', t);
})();

/* Toggle between dark and light */
window.toggleTheme = function () {
  var html = document.documentElement;
  var next = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  html.setAttribute('data-theme', next);
  localStorage.setItem('pisces-theme', next);
  updateThemeIcon(next);
};

/* Sync the icon to match the current theme */
function updateThemeIcon(theme) {
  var icon = document.getElementById('theme-icon');
  if (!icon) return;
  icon.className = theme === 'dark' ? 'fa-solid fa-moon' : 'fa-solid fa-sun';
}

/* Set the correct icon on first load */
updateThemeIcon(document.documentElement.getAttribute('data-theme') || 'dark');
