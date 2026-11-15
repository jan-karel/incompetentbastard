// Lak-galerij voor het rapportdashboard: loopt alle in de opdracht gebruikte
// \plaatje{}-afbeeldingen langs, toont de lak-status, en opent per afbeelding een
// canvas-lak-editor (zwarte vlakken -> raw/screenshots/lakken/<naam>). De gelakte
// rapportbuild laadt die kopie i.p.v. het origineel.
(function () {
  'use strict';

  function csrf() {
    var m = document.querySelector('meta[name="csrf-token"]');
    if (m && m.getAttribute('content')) return m.getAttribute('content');
    var i = document.querySelector('input[name="csrf_token"]');
    return i ? i.value : '';
  }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  function init(root) {
    var grid = root.querySelector('[data-lak-grid]');
    var statusEl = root.querySelector('[data-lak-status]');
    var filterSel = root.querySelector('[data-lak-filter]');
    var refreshBtn = root.querySelector('[data-lak-refresh]');
    if (!grid) return;

    var items = [];
    var currentShown = [];

    function counts() {
      var gelakt = 0, gecontroleerd = 0, todo = 0, ont = 0;
      items.forEach(function (i) {
        if (!i.exists) ont++;
        if (i.has_lakken) gelakt++;
        else if (i.gecontroleerd) gecontroleerd++;
        else todo++;
      });
      return { totaal: items.length, gelakt: gelakt, gecontroleerd: gecontroleerd,
               todo: todo, ontbreekt: ont };
    }

    function setStatus() {
      if (!statusEl) return;
      var c = counts();
      statusEl.textContent = c.totaal + ' afbeeldingen · ' + c.gelakt + ' gelakt · ' +
        c.gecontroleerd + ' gecontroleerd · ' + c.todo + ' te controleren' +
        (c.ontbreekt ? ' · ' + c.ontbreekt + ' ontbreekt' : '');
    }

    function render() {
      var filter = filterSel ? filterSel.value : 'alle';
      grid.textContent = '';
      var shown = items.filter(function (it) {
        if (filter === 'gelakt') return it.has_lakken;
        if (filter === 'niet') return !it.has_lakken;
        if (filter === 'gecontroleerd') return it.gecontroleerd && !it.has_lakken;
        if (filter === 'todo') return !it.has_lakken && !it.gecontroleerd;
        return true;
      });
      if (!shown.length) {
        grid.appendChild(el('p', 'lak-empty',
          'Geen afbeeldingen in deze weergave. Afbeeldingen verschijnen hier zodra ze via \\plaatje{} in een bevinding of notitie van de opdracht gebruikt worden.'));
        return;
      }
      currentShown = shown;
      shown.forEach(function (it) { grid.appendChild(tile(it)); });
    }

    function tile(it) {
      var t = el('figure', 'lak-tile');
      t.classList.toggle('is-gelakt', !!it.has_lakken);
      t.classList.toggle('is-gecontroleerd', !it.has_lakken && !!it.gecontroleerd);
      if (!it.exists) t.classList.add('is-missing');

      var thumbWrap = el('div', 'lak-thumb');
      if (it.exists) {
        var img = el('img');
        img.loading = 'lazy';
        img.alt = it.name;
        img.src = it.url;
        thumbWrap.appendChild(img);
        // Klik op de thumbnail -> groot in beeld (lightbox) om snel te inspecteren.
        thumbWrap.classList.add('is-clickable');
        thumbWrap.title = 'Klik om groot te bekijken';
        thumbWrap.addEventListener('click', function () {
          openLightbox(currentShown, it, {
            lak: function (item, after) { openRedactor(item, function (name, has) { applyUpdate(name, has); if (after) after(); }); },
            review: function (item, reviewed, after) { setReviewed(item, reviewed, after); }
          });
        });
      } else {
        thumbWrap.appendChild(el('div', 'lak-missing', 'bestand ontbreekt'));
      }
      var badgeText = it.has_lakken ? 'GELAKT'
        : (it.gecontroleerd ? 'gecontroleerd' : 'te controleren');
      thumbWrap.appendChild(el('span', 'lak-badge', badgeText));
      t.appendChild(thumbWrap);

      var cap = el('figcaption', 'lak-cap');
      cap.appendChild(el('div', 'lak-name', it.name));
      if (it.used_in && it.used_in.length) {
        cap.appendChild(el('div', 'lak-used', it.used_in.join(' · ')));
      }
      t.appendChild(cap);

      var actions = el('div', 'lak-actions');
      var btn = el('button', 'btn btn-sm', it.has_lakken ? 'Lak bewerken' : 'Lakken');
      btn.type = 'button';
      if (it.has_lakken) btn.classList.add('btn-primary');
      btn.disabled = !it.redactable;
      if (!it.redactable && it.exists) btn.title = 'Dit formaat (bv. SVG) kan niet gelakt worden';
      btn.addEventListener('click', function () { openRedactor(it, applyUpdate); });
      actions.appendChild(btn);

      // Toggle "gecontroleerd (geen lak nodig)".
      var chk = el('button', 'btn btn-sm lak-check-btn',
        it.gecontroleerd ? '✓ Gecontroleerd' : 'Gecontroleerd');
      chk.type = 'button';
      chk.classList.toggle('is-on', !!it.gecontroleerd);
      chk.title = 'Markeer als beoordeeld: geen lak nodig';
      chk.addEventListener('click', function () {
        chk.disabled = true;
        setReviewed(it, !it.gecontroleerd, function () { chk.disabled = false; });
      });
      actions.appendChild(chk);
      t.appendChild(actions);
      return t;
    }

    function applyUpdate(name, hasLakken) {
      items.forEach(function (i) { if (i.name === name) i.has_lakken = hasLakken; });
      setStatus();
      render();
    }

    function setReviewed(it, reviewed, done) {
      fetch('/dashboard/report/images/' + encodeURIComponent(it.name) + '/reviewed', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf() },
        body: JSON.stringify({ reviewed: reviewed })
      })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          if (d && d.ok) { it.gecontroleerd = reviewed; setStatus(); render(); }
          if (done) done();
        })
        .catch(function () { if (done) done(); });
    }

    function load() {
      if (statusEl) statusEl.textContent = 'Laden…';
      fetch('/dashboard/report/images', { credentials: 'same-origin' })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          items = (d && d.images) || [];
          setStatus();
          render();
        })
        .catch(function () { if (statusEl) statusEl.textContent = 'Laden mislukt.'; });
    }

    if (filterSel) filterSel.addEventListener('change', render);
    if (refreshBtn) refreshBtn.addEventListener('click', load);
    // Laad wanneer de sectie voor het eerst zichtbaar/geopend wordt, of meteen.
    load();
    root._lakReload = load;
    // Open de lak-editor voor een specifieke afbeelding (vanuit tabblad Bewerken).
    root._openLakByName = function (name) {
      var it = items.filter(function (i) { return i.name === name; })[0];
      if (it) { openRedactor(it, applyUpdate); return true; }
      return false;
    };
  }

  // Globaal: open een afbeelding op naam in de lak-editor (herlaadt zo nodig).
  window.rbOpenLakImage = function (name) {
    var root = document.querySelector('[data-lak-galerij]');
    if (!root || !root._openLakByName) return;
    if (!root._openLakByName(name) && root._lakReload) {
      root._lakReload();
      setTimeout(function () { root._openLakByName(name); }, 700);
    }
  };

  // --- Canvas-lak-editor (zelfstandig, hergebruikt de bestaande endpoints) ---
  function openRedactor(item, onDone) {
    var name = item.name, url = item.url;
    var endpoint = '/api/screenshots/' + encodeURIComponent(name) + '/redact';
    // Reeds gelakt? Dan de bestaande gelakte versie als basis laden (cache-buster),
    // zodat je erop kunt BIJlakken i.p.v. alle vlakken opnieuw te trekken.
    var lakUrl = '/dashboard/raw/screenshots/lakken/' + encodeURIComponent(name);
    var vanafOrigineel = false;

    var overlay = el('div', 'latex-redact-overlay');
    var modal = el('div', 'latex-redact-modal');
    overlay.appendChild(modal);

    var head = el('div', 'latex-redact-head');
    head.appendChild(el('h3', null, 'Lakken — ' + name));
    var closeX = el('button', 'btn btn-sm', 'Sluiten'); closeX.type = 'button';
    head.appendChild(closeX);
    modal.appendChild(head);

    var cwrap = el('div', 'latex-redact-canvas-wrap');
    var canvas = el('canvas', 'latex-redact-canvas');
    cwrap.appendChild(canvas);
    modal.appendChild(cwrap);
    var ctx = canvas.getContext('2d');

    var tb = el('div', 'latex-redact-toolbar');
    var hint = el('span', 'latex-redact-hint',
      'Sleep rechthoeken over wat weg moet; in de gelakte rapportversie wordt dit zwart.');
    var undoBtn = el('button', 'btn btn-sm', 'Laatste ongedaan'); undoBtn.type = 'button';
    var clearBtn = el('button', 'btn btn-sm', 'Wis alles'); clearBtn.type = 'button';
    // "Vanaf origineel": bij een reeds gelakte afbeelding opnieuw beginnen vanaf
    // het ongelakte origineel (voor een volledige herlak i.p.v. bijlakken).
    var origBtn = item.has_lakken ? el('button', 'btn btn-sm', 'Vanaf origineel') : null;
    if (origBtn) origBtn.type = 'button';
    var delBtn = item.has_lakken ? el('button', 'btn btn-sm', 'Lak verwijderen') : null;
    if (delBtn) delBtn.type = 'button';
    var saveBtn = el('button', 'btn btn-sm btn-primary', 'Opslaan'); saveBtn.type = 'button';
    tb.appendChild(hint); tb.appendChild(undoBtn); tb.appendChild(clearBtn);
    if (origBtn) tb.appendChild(origBtn);
    if (delBtn) tb.appendChild(delBtn);
    tb.appendChild(saveBtn);
    modal.appendChild(tb);

    var rects = [];
    var imgEl = new Image();
    imgEl.crossOrigin = 'anonymous';
    imgEl.onload = function () {
      var maxW = 1600;
      var scale = imgEl.naturalWidth > maxW ? maxW / imgEl.naturalWidth : 1;
      canvas.width = Math.max(1, Math.round(imgEl.naturalWidth * scale));
      canvas.height = Math.max(1, Math.round(imgEl.naturalHeight * scale));
      redraw();
    };
    imgEl.onerror = function () { hint.textContent = 'Kon de afbeelding niet laden.'; };

    function loadBase() {
      rects = [];
      var useLak = item.has_lakken && !vanafOrigineel;
      imgEl.src = useLak ? (lakUrl + '?t=' + Date.now()) : url;
      hint.textContent = useLak
        ? 'Bestaande lak als basis — trek extra vlakken om bíj te lakken (of "Vanaf origineel" voor opnieuw).'
        : 'Sleep rechthoeken over wat weg moet; in de gelakte rapportversie wordt dit zwart.';
    }
    loadBase();

    function redraw(cur) {
      if (!canvas.width) return;
      ctx.drawImage(imgEl, 0, 0, canvas.width, canvas.height);
      ctx.fillStyle = '#000';
      rects.forEach(function (r) { ctx.fillRect(r.x, r.y, r.w, r.h); });
      if (cur) ctx.fillRect(cur.x, cur.y, cur.w, cur.h);
    }
    function norm(a, b) {
      return { x: Math.min(a.x, b.x), y: Math.min(a.y, b.y),
               w: Math.abs(a.x - b.x), h: Math.abs(a.y - b.y) };
    }
    function pos(e) {
      var r = canvas.getBoundingClientRect();
      return { x: (e.clientX - r.left) * (canvas.width / r.width),
               y: (e.clientY - r.top) * (canvas.height / r.height) };
    }
    var drawing = false, start = null;
    canvas.addEventListener('pointerdown', function (e) {
      drawing = true; start = pos(e);
      try { canvas.setPointerCapture(e.pointerId); } catch (err) {}
    });
    canvas.addEventListener('pointermove', function (e) {
      if (drawing) redraw(norm(start, pos(e)));
    });
    canvas.addEventListener('pointerup', function (e) {
      if (!drawing) return;
      drawing = false;
      var r = norm(start, pos(e));
      if (r.w > 3 && r.h > 3) rects.push(r);
      redraw();
    });

    function close() { overlay.remove(); document.removeEventListener('keydown', onKey); }
    function onKey(e) { if (e.key === 'Escape') close(); }
    document.addEventListener('keydown', onKey);
    closeX.addEventListener('click', close);
    overlay.addEventListener('click', function (e) { if (e.target === overlay) close(); });
    undoBtn.addEventListener('click', function () { rects.pop(); redraw(); });
    clearBtn.addEventListener('click', function () { rects = []; redraw(); });
    if (origBtn) origBtn.addEventListener('click', function () {
      vanafOrigineel = !vanafOrigineel;
      origBtn.classList.toggle('is-on', vanafOrigineel);
      origBtn.textContent = vanafOrigineel ? 'Terug naar gelakt' : 'Vanaf origineel';
      loadBase();
    });

    if (delBtn) delBtn.addEventListener('click', function () {
      delBtn.disabled = true;
      fetch(endpoint, { method: 'DELETE', credentials: 'same-origin',
                        headers: { 'X-CSRFToken': csrf() } })
        .then(function (r) { return r.json(); })
        .then(function () { item.has_lakken = false; onDone(name, false); close(); })
        .catch(function () { delBtn.disabled = false; hint.textContent = 'Verwijderen mislukt.'; });
    });

    saveBtn.addEventListener('click', function () {
      if (!canvas.width) return;
      if (!rects.length) { hint.textContent = 'Trek eerst minstens één vlak over wat weg moet.'; return; }
      saveBtn.disabled = true; saveBtn.textContent = 'Opslaan…';
      var dataUrl;
      try { dataUrl = canvas.toDataURL('image/png'); }
      catch (err) { hint.textContent = 'Kon de afbeelding niet exporteren.'; saveBtn.disabled = false; saveBtn.textContent = 'Opslaan'; return; }
      fetch(endpoint, {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf() },
        body: JSON.stringify({ image: dataUrl })
      })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          if (d && d.error) { hint.textContent = d.error; saveBtn.disabled = false; saveBtn.textContent = 'Opslaan'; return; }
          item.has_lakken = true; onDone(name, true); close();
        })
        .catch(function () { hint.textContent = 'Opslaan mislukt.'; saveBtn.disabled = false; saveBtn.textContent = 'Opslaan'; });
    });

    document.body.appendChild(overlay);
  }

  // Lightbox: toon een afbeelding groot in beeld, met vorige/volgende-navigatie
  // (pijltjestoetsen of knoppen) door alle getoonde afbeeldingen.
  function openLightbox(list, startItem, api) {
    api = api || {};
    // Alleen bestaande afbeeldingen zijn navigeerbaar.
    var nav = (list || []).filter(function (i) { return i.exists; });
    if (!nav.length) nav = [startItem];
    var idx = nav.indexOf(startItem);
    if (idx < 0) idx = 0;

    var overlay = el('div', 'lak-lightbox-overlay');
    var fig = el('figure', 'lak-lightbox-fig');
    var img = el('img', 'lak-lightbox-img');
    var cap = el('figcaption', 'lak-lightbox-cap');
    var closeX = el('button', 'lak-lightbox-close', '✕');
    closeX.type = 'button'; closeX.setAttribute('aria-label', 'Sluiten');
    var prev = el('button', 'lak-lightbox-nav lak-lightbox-prev', '‹');
    prev.type = 'button'; prev.setAttribute('aria-label', 'Vorige');
    var next = el('button', 'lak-lightbox-nav lak-lightbox-next', '›');
    next.type = 'button'; next.setAttribute('aria-label', 'Volgende');

    // Actiebalk: lakken + gecontroleerd, direct vanuit de lightbox.
    var tools = el('div', 'lak-lightbox-tools');
    var lakBtn = el('button', 'btn btn-sm', 'Lakken');
    lakBtn.type = 'button';
    var chkBtn = el('button', 'btn btn-sm lak-check-btn', 'Gecontroleerd');
    chkBtn.type = 'button';
    tools.appendChild(lakBtn);
    tools.appendChild(chkBtn);

    fig.appendChild(closeX);
    fig.appendChild(img);
    fig.appendChild(cap);
    fig.appendChild(tools);
    overlay.appendChild(prev);
    overlay.appendChild(fig);
    overlay.appendChild(next);

    function show() {
      var it = nav[idx];
      img.src = it.url;
      img.alt = it.name;
      var status = it.has_lakken ? ' · GELAKT' : (it.gecontroleerd ? ' · gecontroleerd' : '');
      cap.textContent = (idx + 1) + ' / ' + nav.length + ' — ' + it.name + status;
      var multi = nav.length > 1;
      prev.style.display = multi ? '' : 'none';
      next.style.display = multi ? '' : 'none';
      lakBtn.textContent = it.has_lakken ? 'Lak bewerken' : 'Lakken';
      lakBtn.classList.toggle('btn-primary', !!it.has_lakken);
      lakBtn.disabled = !it.redactable || !api.lak;
      chkBtn.textContent = it.gecontroleerd ? '✓ Gecontroleerd' : 'Gecontroleerd';
      chkBtn.classList.toggle('is-on', !!it.gecontroleerd);
      chkBtn.disabled = !api.review;
    }
    function go(delta) { idx = (idx + delta + nav.length) % nav.length; show(); }
    function cur() { return nav[idx]; }

    function doLak() {
      if (!api.lak || !cur().redactable) return;
      api.lak(cur(), show);
    }
    function doReview() {
      if (!api.review) return;
      chkBtn.disabled = true;
      api.review(cur(), !cur().gecontroleerd, function () { chkBtn.disabled = false; show(); });
    }

    function close() { overlay.remove(); document.removeEventListener('keydown', onKey); }
    function onKey(e) {
      // Niet reageren terwijl de lak-editor (eigen modal) openstaat.
      if (document.querySelector('.latex-redact-overlay')) return;
      if (e.key === 'Escape') close();
      else if (e.key === 'ArrowLeft') { e.preventDefault(); go(-1); }
      else if (e.key === 'ArrowRight') { e.preventDefault(); go(1); }
      else if (e.key === 'l' || e.key === 'L') { e.preventDefault(); doLak(); }
      else if (e.key === 'g' || e.key === 'G') { e.preventDefault(); doReview(); }
    }
    document.addEventListener('keydown', onKey);
    overlay.addEventListener('click', function (e) {
      if (fig.contains(e.target) || e.target === prev || e.target === next) return;
      close();
    });
    closeX.addEventListener('click', close);
    prev.addEventListener('click', function () { go(-1); });
    next.addEventListener('click', function () { go(1); });
    lakBtn.addEventListener('click', doLak);
    chkBtn.addEventListener('click', doReview);
    document.body.appendChild(overlay);
    show();
  }

  document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('[data-lak-galerij]').forEach(init);
  });
})();
