document.addEventListener('DOMContentLoaded', function() {
  var btn = document.getElementById('nav-btn');
  var panel = document.getElementById('nav-panel');
  if (btn && panel) {
    btn.addEventListener('click', function() {
      panel.classList.toggle('open');
    });
  }
});