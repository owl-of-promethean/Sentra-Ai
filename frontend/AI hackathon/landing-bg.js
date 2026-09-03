// =====================================================================
//  SENTRA AI — landing-bg.js (performance-tuned rewrite)
//
//  Motion model:
//   · All continuous background motion lives in CSS keyframes on a
//     handful of grouped layers (transform / opacity / dash-offset
//     only) — defined in the ".sentra-animated-bg" block in
//     style.css. No Anime.js, no per-shape tweens, no timers.
//   · This file only handles: depth parallax (transform-only,
//     rAF-throttled, desktop only), scene awareness via
//     IntersectionObserver, and pausing all motion while the tab is
//     hidden or the user prefers reduced motion.
//
//  Remove this file + the .sentra-animated-bg markup in index.html
//  + the "SENTRA ANIMATED SVG BACKGROUND" block in style.css to
//  disable the layer entirely.
// =====================================================================
(function () {
  'use strict';

  var bgRoot = document.querySelector('.sentra-animated-bg');
  if (!bgRoot) return;

  var reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
  var smallScreen  = window.matchMedia('(max-width: 768px)');
  var layers = Array.prototype.slice.call(bgRoot.querySelectorAll('.sb-layer'));

  // ── 1 · Depth parallax — grouped layers, transform-only ─────────
  // One rAF-throttled handler writes translate3d to 4 layer groups.
  var layerData = layers.map(function (l) {
    return { el: l, depth: parseFloat(l.getAttribute('data-sb-depth')) || 0, last: '' };
  });
  var parallaxTicking = false;

  function parallaxEnabled() {
    return !reduceMotion.matches && !smallScreen.matches && !document.hidden;
  }

  function updateParallax() {
    parallaxTicking = false;
    if (!parallaxEnabled()) return;
    var max = document.documentElement.scrollHeight - window.innerHeight;
    var p = max > 0 ? window.scrollY / max : 0;
    for (var i = 0; i < layerData.length; i++) {
      var d = layerData[i];
      var t = 'translate3d(0,' + (-(p * d.depth * 300)).toFixed(1) + 'px,0)';
      if (t !== d.last) { d.last = t; d.el.style.transform = t; }
    }
  }

  function requestParallax() {
    if (parallaxTicking || !parallaxEnabled()) return;
    parallaxTicking = true;
    requestAnimationFrame(updateParallax);
  }

  window.addEventListener('scroll', requestParallax, { passive: true });
  window.addEventListener('resize', requestParallax, { passive: true });

  // ── 2 · Scene awareness — cheap attribute/class toggles only ─────
  if ('IntersectionObserver' in window) {
    var sceneIO = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (en.isIntersecting) {
          bgRoot.setAttribute('data-sb-scene', en.target.getAttribute('data-sb-index'));
        }
      });
    }, { rootMargin: '-42% 0px -42% 0px', threshold: 0 });

    Array.prototype.forEach.call(document.querySelectorAll('.scene'), function (scene, i) {
      scene.setAttribute('data-sb-index', i);
      sceneIO.observe(scene);
    });
    var s6 = document.getElementById('s6-section');
    if (s6) { s6.setAttribute('data-sb-index', '6'); sceneIO.observe(s6); }

    // Advanced AI [BETA] — reveal the sandbox cluster while in view
    var scene5 = document.getElementById('scene-5');
    if (scene5) {
      var aiIO = new IntersectionObserver(function (entries) {
        entries.forEach(function (en) {
          bgRoot.classList.toggle('scene-ai-active', en.isIntersecting);
        });
      }, { threshold: 0.12 });
      aiIO.observe(scene5);
    }
  } else {
    bgRoot.classList.add('scene-ai-active');
  }

  // ── 3 · Pause every CSS animation while the tab is hidden ────────
  document.addEventListener('visibilitychange', function () {
    bgRoot.classList.toggle('sb-paused', document.hidden);
    if (!document.hidden) requestParallax();
  });

  // ── 4 · React live to reduced-motion preference changes ──────────
  function onMotionPrefChange() {
    if (reduceMotion.matches) {
      layerData.forEach(function (d) { d.el.style.transform = ''; d.last = ''; });
    } else {
      requestParallax();
    }
  }
  if (typeof reduceMotion.addEventListener === 'function') {
    reduceMotion.addEventListener('change', onMotionPrefChange);
  }

  // ── Boot ──
  updateParallax();
}());
