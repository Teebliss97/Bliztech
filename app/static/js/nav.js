document.addEventListener('DOMContentLoaded', function () {
  var btn = document.getElementById('nav-btn');
  var panel = document.getElementById('nav-panel');

  if (!btn || !panel) return;

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
    if (e.key === 'Escape') {
      closeMenu();
    }
  });

  var links = panel.querySelectorAll('a');
  links.forEach(function (link) {
    link.addEventListener('click', function () {
      closeMenu();
    });
  });
});