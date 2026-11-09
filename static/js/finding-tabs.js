/**
 * Tabbladen in het bevinding-formulier (modal + volledige pagina).
 * Alle velden blijven in de DOM, dus formulier-indiening werkt ongeacht de
 * actieve tab. CSP-veilig (extern, nonce'd) en idempotent (ook na AJAX-injectie).
 */
(function () {
  'use strict';

  function initOne(root) {
    if (root._ftabInit) return;
    root._ftabInit = true;

    var btns = Array.prototype.slice.call(root.querySelectorAll('[data-ftab]'));
    var panels = Array.prototype.slice.call(root.querySelectorAll('[data-ftab-panel]'));
    if (!btns.length) return;

    function activate(key) {
      btns.forEach(function (b) {
        b.classList.toggle('is-active', b.getAttribute('data-ftab') === key);
      });
      panels.forEach(function (p) {
        p.classList.toggle('is-active', p.getAttribute('data-ftab-panel') === key);
      });
    }

    btns.forEach(function (b) {
      b.addEventListener('click', function () {
        activate(b.getAttribute('data-ftab'));
      });
    });
  }

  function initAll() {
    document.querySelectorAll('[data-finding-tabs]').forEach(initOne);
  }

  window.initFindingTabs = initAll;
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initAll);
  else initAll();
})();
