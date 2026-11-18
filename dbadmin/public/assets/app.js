// Conferma prima delle azioni distruttive (niente JS inline: compatibile con la CSP)
document.addEventListener('click', function (e) {
  var b = e.target.closest('.js-confirm');
  if (b && !window.confirm(b.dataset.confirm || 'Confermi?')) {
    e.preventDefault();
  }
});
