/* Herbruikbare capture-dialoog: voorbeeld + scope-keuze + titel + bestemming.
   Gebruik: CaptureDialog.open({ title, previewUrl, submitUrl, onDone }).
   previewUrl → {volledig, laatste, commando, segments:[{cmd,tekst}]}.
   submitUrl  ← POST {doel, opdracht_id, titel, inhoud}. */
(function () {
  'use strict';
  var modal, els = {}, st = {};

  function el(tag, cls, txt) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (txt != null) e.textContent = txt;
    return e;
  }

  function segSet(seg, val) {
    var bs = seg.querySelectorAll('button');
    for (var i = 0; i < bs.length; i++) bs[i].classList.toggle('active', bs[i].dataset.v === val);
  }

  var DEFAULT_DEST = [['notitie', '📝 Notitie'], ['bevinding', '🐞 Bevinding'], ['bijlage', '📎 Bijlage']];

  function fillDoel(opts) {
    els.doelSeg.innerHTML = '';
    opts.forEach(function (o, i) {
      var b = el('button', i === 0 ? 'active' : null, o[1]);
      b.type = 'button';
      b.dataset.v = o[0];
      b.addEventListener('click', function () { st.dest = o[0]; segSet(els.doelSeg, o[0]); });
      els.doelSeg.appendChild(b);
    });
  }

  function rowSeg(label, key, opts) {
    var r = el('div', 'capd-row');
    r.appendChild(el('label', null, label));
    var seg = el('div', 'capd-seg');
    els[key + 'Seg'] = seg;
    opts.forEach(function (o, i) {
      var b = el('button', i === 0 ? 'active' : null, o[1]);
      b.type = 'button';
      b.dataset.v = o[0];
      b.addEventListener('click', function () {
        if (b.disabled) return;
        st[key] = o[0];
        segSet(seg, o[0]);
        if (key === 'scope') {
          els.segRow.hidden = (o[0] !== 'segment');
          updatePreview();
        }
      });
      seg.appendChild(b);
    });
    r.appendChild(seg);
    return r;
  }

  function build() {
    if (modal) return;
    modal = el('div', 'capd-modal');
    modal.hidden = true;
    var box = el('div', 'capd-box');

    var head = el('div', 'capd-head');
    els.title = el('h3', null, 'Vastleggen');
    var x = el('button', 'capd-x', '×');
    x.type = 'button';
    x.addEventListener('click', close);
    head.appendChild(els.title);
    head.appendChild(x);

    var body = el('div', 'capd-body');

    var dr = el('div', 'capd-row');
    dr.appendChild(el('label', null, 'Bestemming'));
    els.doelSeg = el('div', 'capd-seg');
    dr.appendChild(els.doelSeg);
    body.appendChild(dr);

    els.opdrachtRow = el('div', 'capd-row');
    els.opdrachtRow.appendChild(el('label', null, 'Opdracht'));
    els.opdracht = el('select', 'input');
    els.opdrachtRow.appendChild(els.opdracht);
    body.appendChild(els.opdrachtRow);

    body.appendChild(rowSeg('Vastleggen', 'scope',
      [['volledig', 'Volledige opname'], ['laatste', 'Laatste opdracht'], ['segment', 'Specifiek commando']]));

    els.segRow = el('div', 'capd-row');
    els.segRow.hidden = true;
    els.segRow.appendChild(el('label', null, 'Commando'));
    els.segment = el('select', 'input');
    els.segment.addEventListener('change', function () {
      st.seg = parseInt(els.segment.value, 10) || 0;
      updatePreview();
    });
    els.segRow.appendChild(els.segment);
    body.appendChild(els.segRow);

    var tr = el('div', 'capd-row');
    tr.appendChild(el('label', null, 'Titel'));
    els.titel = el('input', 'input');
    els.titel.type = 'text';
    els.titel.placeholder = 'Titel (leeg = gedetecteerd commando)';
    els.titel.addEventListener('input', function () { st.titelDirty = true; });
    tr.appendChild(els.titel);
    body.appendChild(tr);

    var pr = el('div', 'capd-row');
    var pl = el('label', null, 'Voorbeeld ');
    els.prevMeta = el('span', 'capd-prevmeta');
    pl.appendChild(els.prevMeta);
    pr.appendChild(pl);
    els.preview = el('pre', 'capd-preview');
    pr.appendChild(els.preview);
    body.appendChild(pr);

    var foot = el('div', 'capd-foot');
    els.status = el('span', 'capd-status');
    var cancel = el('button', 'btn', 'Annuleren');
    cancel.type = 'button';
    cancel.addEventListener('click', close);
    els.confirm = el('button', 'btn btn-primary', 'Vastleggen');
    els.confirm.type = 'button';
    els.confirm.addEventListener('click', submit);
    foot.appendChild(els.status);
    foot.appendChild(cancel);
    foot.appendChild(els.confirm);

    box.appendChild(head);
    box.appendChild(body);
    box.appendChild(foot);
    modal.appendChild(box);
    modal.addEventListener('click', function (e) { if (e.target === modal) close(); });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && !modal.hidden) close(); });
    document.body.appendChild(modal);
  }

  function chosenText() {
    if (!st.data) return '';
    if (st.scope === 'laatste') return st.data.laatste || '';
    if (st.scope === 'segment') {
      var s = (st.data.segments || [])[st.seg];
      return s ? s.tekst : '';
    }
    return st.data.volledig || '';
  }

  function suggestTitle() {
    if (!st.data) return '';
    var segs = st.data.segments || [];
    if (st.scope === 'segment' && segs[st.seg]) return segs[st.seg].cmd;
    if (st.scope === 'laatste') return (segs.length ? segs[segs.length - 1].cmd : st.data.commando) || '';
    return st.data.commando || '';
  }

  function updatePreview() {
    var t = chosenText();
    els.preview.textContent = t;
    els.prevMeta.textContent = '(' + t.length + ' tekens)';
    if (!st.titelDirty) els.titel.value = suggestTitle();
  }

  function loadOpdrachten() {
    els.opdracht.innerHTML = '';
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/api/opdrachten/active');
    xhr.onload = function () {
      if (xhr.status !== 200) return;
      var d;
      try { d = JSON.parse(xhr.responseText); } catch (e) { return; }
      (d.opdrachten || []).forEach(function (o) {
        var op = document.createElement('option');
        op.value = o.id;
        op.textContent = o.naam + (o.klant ? ' · ' + o.klant : '');
        if (o.id === d.active_id) op.selected = true;
        els.opdracht.appendChild(op);
      });
    };
    xhr.send();
  }

  function close() { if (modal) modal.hidden = true; }

  function submit() {
    if (!st.data) return;
    var t = chosenText();
    if (!t.trim()) { els.status.textContent = 'Geen inhoud in deze selectie'; return; }
    els.confirm.disabled = true;
    els.status.textContent = 'Bezig…';
    var xhr = new XMLHttpRequest();
    xhr.open('POST', st.submitUrl);
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.onload = function () {
      els.confirm.disabled = false;
      var d;
      try { d = JSON.parse(xhr.responseText); } catch (e) { d = {}; }
      if (xhr.status === 200 && d.ok) {
        close();
        if (typeof st.onDone === 'function') st.onDone(d);
      } else {
        els.status.textContent = d.error || 'Vastleggen mislukt';
      }
    };
    xhr.onerror = function () { els.confirm.disabled = false; els.status.textContent = 'Verbindingsfout'; };
    var sel = { dest: st.dest, opdrachtId: els.opdracht.value, titel: els.titel.value, inhoud: t };
    var payload = st.buildPayload
      ? st.buildPayload(sel)
      : { doel: sel.dest, opdracht_id: sel.opdrachtId, titel: sel.titel, inhoud: sel.inhoud };
    xhr.send(JSON.stringify(payload));
  }

  function open(opts) {
    build();
    var dests = opts.destinations || DEFAULT_DEST;
    st = {
      previewUrl: opts.previewUrl, submitUrl: opts.submitUrl, onDone: opts.onDone,
      buildPayload: opts.buildPayload,
      data: null, dest: dests[0][0], scope: 'volledig', seg: 0, titelDirty: false
    };
    els.title.textContent = 'Vastleggen — ' + (opts.title || '');
    fillDoel(dests);
    segSet(els.scopeSeg, 'volledig');
    els.segRow.hidden = true;
    els.titel.value = '';
    els.status.textContent = '';
    els.confirm.disabled = true;
    els.preview.textContent = 'Laden…';
    els.prevMeta.textContent = '';
    var segBtn = els.scopeSeg.querySelector('[data-v="segment"]');
    if (segBtn) segBtn.disabled = false;
    els.opdrachtRow.hidden = (opts.showOpdracht === false);
    if (opts.showOpdracht !== false) loadOpdrachten();
    modal.hidden = false;

    var xhr = new XMLHttpRequest();
    xhr.open('GET', opts.previewUrl);
    xhr.onload = function () {
      var d;
      try { d = JSON.parse(xhr.responseText); } catch (e) { d = {}; }
      if (xhr.status !== 200 || d.error) {
        els.preview.textContent = d.error || 'Kan voorbeeld niet laden';
        return;
      }
      st.data = d;
      els.segment.innerHTML = '';
      (d.segments || []).forEach(function (s, i) {
        var op = document.createElement('option');
        op.value = i;
        op.textContent = (i + 1) + '. ' + (s.cmd.length > 60 ? s.cmd.slice(0, 60) + '…' : s.cmd);
        els.segment.appendChild(op);
      });
      if (!(d.segments || []).length && segBtn) segBtn.disabled = true;
      els.confirm.disabled = false;
      updatePreview();
    };
    xhr.onerror = function () { els.preview.textContent = 'Verbindingsfout'; };
    xhr.send();
  }

  window.CaptureDialog = { open: open };
})();
