// ── Theme: apply saved preference before first paint ─────────────────────────
(function () {
  var t = localStorage.getItem('bliztech-theme');
  if (t === 'light') document.documentElement.setAttribute('data-theme', 'light');
})();

document.addEventListener('DOMContentLoaded', function () {

  // ── Mobile nav ─────────────────────────────────────────────────────────────
  var btn   = document.getElementById('nav-btn');
  var panel = document.getElementById('nav-panel');

  if (btn && panel) {
    function openMenu() {
      panel.classList.add('open');
      btn.setAttribute('aria-expanded', 'true');
    }

    function closeMenu() {
      panel.classList.remove('open');
      btn.setAttribute('aria-expanded', 'false');
    }

    function toggleMenu() {
      if (panel.classList.contains('open')) {
        closeMenu();
      } else {
        openMenu();
      }
    }

    btn.addEventListener('click', function (e) {
      e.stopPropagation();
      toggleMenu();
    });

    panel.addEventListener('click', function (e) {
      e.stopPropagation();
    });

    document.addEventListener('click', function () {
      closeMenu();
    });

    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') closeMenu();
    });

    panel.querySelectorAll('a').forEach(function (link) {
      link.addEventListener('click', function () {
        closeMenu();
      });
    });
  }

  // ── Theme toggle ───────────────────────────────────────────────────────────
  var themeBtn = document.getElementById('theme-toggle');
  if (!themeBtn) return;

  themeBtn.addEventListener('click', function () {
    var html    = document.documentElement;
    var isLight = html.getAttribute('data-theme') === 'light';
    if (isLight) {
      html.removeAttribute('data-theme');
      localStorage.setItem('bliztech-theme', 'dark');
    } else {
      html.setAttribute('data-theme', 'light');
      localStorage.setItem('bliztech-theme', 'light');
    }
  });

});