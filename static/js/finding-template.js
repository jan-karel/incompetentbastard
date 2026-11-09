/**
 * Koppelen van standaardbevindingen (templates) aan een bevinding + per-bevinding
 * overrides. Doorzoekbare kiezer, auto-suggesties op basis van de naam, en een
 * read-only voorbeeld van de template-tekst die in het rapport komt.
 * CSP-veilig (extern, nonce'd) en idempotent (werkt ook na AJAX-injectie).
 */
(function () {
  'use strict';

  var _templatesPromise = null;
  function loadTemplates() {
    if (_templatesPromise) return _templatesPromise;
    _templatesPromise = fetch('/api/findings/templates', { credentials: 'same-origin' })
      .then(function (r) { return r.json(); })
      .then(function (d) { return d.templates || []; })
      .catch(function () { return []; });
    return _templatesPromise;
  }

  function esc(s) { var d = document.createElement('div'); d.textContent = s == null ? '' : s; return d.innerHTML; }

  function matches(t, q) {
    q = q.toLowerCase();
    var hay = [t.titel, t.cwe, t.owasp_2025, t.ncsc, t.bevtype].join(' ').toLowerCase();
    return hay.indexOf(q) !== -1;
  }

  function label(t) {
    var meta = [];
    if (t.cwe) meta.push('CWE-' + t.cwe);
    if (t.bevtype) meta.push(t.bevtype);
    return { main: t.titel || ('#' + t.id), meta: meta.join(' · ') };
  }

  function initOne(root) {
    if (root._tplInit) return;
    root._tplInit = true;

    var form = root.closest ? root.closest('form') : null;
    function q1(sel) { return (form || document).querySelector(sel); }
    var refInput = q1('[name="ref"]');
    var naamInput = q1('[name="naam"]');
    var current = root.querySelector('[data-tpl-current]');
    var unlinkBtn = root.querySelector('[data-tpl-unlink]');
    var search = root.querySelector('[data-tpl-search]');
    var results = root.querySelector('[data-tpl-results]');
    var help = root.querySelector('[data-tpl-help]');

    // Override-velden (kunnen buiten `root`, maar binnen hetzelfde formulier staan).
    var scope = form || document;
    var EMPTY_PH = 'Leeg = standaardtekst van de template';
    var ovFields = [];
    scope.querySelectorAll('[data-ov]').forEach(function (wrap) {
      if (wrap._ovInit) return;
      wrap._ovInit = true;
      var key = wrap.getAttribute('data-ov-key');
      var ta = scope.querySelector('[name="' + wrap.getAttribute('data-ov') + '"]');
      if (!ta) return;
      var badge = wrap.querySelector('[data-ov-badge]');
      var fillBtn = wrap.querySelector('[data-ov-fill]');
      var resetBtn = wrap.querySelector('[data-ov-reset]');
      var rec = { key: key, ta: ta, badge: badge, fillBtn: fillBtn, resetBtn: resetBtn, tpl: '' };

      function syncBadge() {
        var filled = (ta.value || '').trim().length > 0;
        if (badge) {
          badge.textContent = filled ? 'Aangepast' : 'Standaard';
          badge.classList.toggle('is-aangepast', filled);
        }
        if (resetBtn) resetBtn.hidden = !filled;
      }
      ta.addEventListener('input', syncBadge);
      if (fillBtn) fillBtn.addEventListener('click', function () {
        ta.value = rec.tpl || '';
        ta.dispatchEvent(new Event('input', { bubbles: true }));
        ta.focus();
      });
      if (resetBtn) resetBtn.addEventListener('click', function () {
        ta.value = '';
        ta.dispatchEvent(new Event('input', { bubbles: true }));
      });
      rec.sync = syncBadge;
      ovFields.push(rec);
      syncBadge();
    });

    function applyTemplateText(d) {
      if (help) help.hidden = !d;
      ovFields.forEach(function (rec) {
        rec.tpl = d ? (d[rec.key] || '') : '';
        if (rec.ta) rec.ta.placeholder = rec.tpl ? rec.tpl : (d ? 'Geen standaardtekst — leeg laat dit weg' : EMPTY_PH);
        if (rec.fillBtn) rec.fillBtn.hidden = !(d && rec.tpl);
        if (rec.sync) rec.sync();
      });
    }

    function setLinked(t) {
      if (!t) {
        if (refInput) refInput.value = '';
        if (current) current.textContent = 'Geen standaardbevinding gekoppeld';
        if (unlinkBtn) unlinkBtn.hidden = true;
        applyTemplateText(null);
        return;
      }
      if (refInput) refInput.value = String(t.id);
      var l = label(t);
      if (current) current.textContent = l.main + (l.meta ? (' — ' + l.meta) : '');
      if (unlinkBtn) unlinkBtn.hidden = false;
      fetch('/api/findings/templates/' + t.id + '/detail', { credentials: 'same-origin' })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(applyTemplateText).catch(function () { applyTemplateText(null); });
    }

    function render(items, heading) {
      if (!results) return;
      if (!items.length) { results.hidden = true; results.innerHTML = ''; return; }
      var html = heading ? '<div class="tpl-results-head">' + esc(heading) + '</div>' : '';
      html += items.slice(0, 8).map(function (t) {
        var l = label(t);
        return '<button type="button" class="tpl-result" data-id="' + t.id + '">' +
          '<span class="tpl-result-main">' + esc(l.main) + '</span>' +
          (l.meta ? '<span class="tpl-result-meta">' + esc(l.meta) + '</span>' : '') +
          '</button>';
      }).join('');
      results.innerHTML = html;
      results.hidden = false;
    }

    if (results) results.addEventListener('click', function (e) {
      var btn = e.target.closest ? e.target.closest('.tpl-result') : null;
      if (!btn) return;
      var id = btn.getAttribute('data-id');
      loadTemplates().then(function (list) {
        var t = list.filter(function (x) { return String(x.id) === String(id); })[0];
        if (t) { setLinked(t); results.hidden = true; if (search) search.value = ''; }
      });
    });

    if (search) search.addEventListener('input', function () {
      var qv = search.value.trim();
      if (!qv) { if (results) results.hidden = true; return; }
      loadTemplates().then(function (list) {
        render(list.filter(function (t) { return matches(t, qv); }), null);
      });
    });

    if (unlinkBtn) unlinkBtn.addEventListener('click', function () { setLinked(null); });

    // Auto-suggesties op basis van de naam (zolang het zoekveld leeg is).
    var timer = null;
    if (naamInput) naamInput.addEventListener('input', function () {
      if (search && search.value.trim()) return;
      if (refInput && refInput.value) return; // al gekoppeld
      if (timer) clearTimeout(timer);
      timer = setTimeout(function () {
        var qv = naamInput.value.trim();
        if (qv.length < 3) { if (results) results.hidden = true; return; }
        loadTemplates().then(function (list) {
          var m = list.filter(function (t) { return matches(t, qv); });
          render(m, m.length ? 'Suggesties op basis van de naam' : null);
        });
      }, 300);
    });

    // Init: toon de reeds gekoppelde template (bij bewerken).
    if (refInput && refInput.value) {
      loadTemplates().then(function (list) {
        var t = list.filter(function (x) { return String(x.id) === String(refInput.value); })[0];
        setLinked(t || { id: refInput.value, titel: 'Template #' + refInput.value });
      });
    }
  }

  function initAll() {
    document.querySelectorAll('[data-template-link]').forEach(initOne);
  }

  window.initFindingTemplate = initAll;
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initAll);
  else initAll();
})();
