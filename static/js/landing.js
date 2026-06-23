// Landing page — animações de scroll com IntersectionObserver nativo (sem libs
// pesadas) + count-up das estatísticas. Foco em performance: rAF, observers que
// se desligam após disparar, respeito a prefers-reduced-motion.
(function () {
  var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // --- Reveal ao entrar na viewport ---
  var els = document.querySelectorAll('[data-reveal]');
  els.forEach(function (el) {
    var d = parseInt(el.getAttribute('data-delay') || '0', 10);
    if (d) el.style.transitionDelay = (d * 80) + 'ms';
  });

  if (reduce || !('IntersectionObserver' in window)) {
    els.forEach(function (el) { el.classList.add('is-visible'); });
  } else {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) {
          e.target.classList.add('is-visible');
          io.unobserve(e.target);
        }
      });
    }, { threshold: 0.12, rootMargin: '0px 0px -8% 0px' });
    els.forEach(function (el) { io.observe(el); });
  }

  // --- Count-up das estatísticas ---
  var nums = document.querySelectorAll('[data-count]');
  function fmt(n) { return Math.round(n).toLocaleString('pt-BR'); }
  function animateCount(el) {
    var target = parseInt(el.getAttribute('data-count') || '0', 10);
    if (!target || target <= 0) { el.textContent = '0'; return; }
    if (reduce) { el.textContent = fmt(target); return; }
    var dur = 1500, start = null;
    function step(ts) {
      if (!start) start = ts;
      var p = Math.min((ts - start) / dur, 1);
      var eased = 1 - Math.pow(1 - p, 3);
      el.textContent = fmt(eased * target);
      if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  if ('IntersectionObserver' in window) {
    var io2 = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) { animateCount(e.target); io2.unobserve(e.target); }
      });
    }, { threshold: 0.5 });
    nums.forEach(function (el) { io2.observe(el); });
  } else {
    nums.forEach(function (el) { el.textContent = fmt(parseInt(el.getAttribute('data-count') || '0', 10)); });
  }
})();
