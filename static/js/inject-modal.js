// Copyright (C) 2021 Jan-Karel Visser info@jan-karel.nl
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * inject-modal.js
 * Bevestigingsmodal voor command file injectie.
 * Eigen find/replace, per-regel injectie, en inject alles.
 *
 * Gebruik:
 *   window.openInjectModal({
 *     commandName: "kerb_kerberoast",
 *     content: "# Comment\ncommand here",   // RAUWE content
 *     mode: "screen" | "agent",
 *     // initieel overnemen van pagina:
 *     initialFind: "10.10.10.1",
 *     initialReplace: "192.168.1.1",
 *     initialHttps: false,
 *     // screen mode:
 *     screenName: "my-screen",
 *     onSuccess: function() { ... },
 *     // agent mode:
 *     onConfirm: function(lines) { ... }
 *   });
 */

(function () {
  'use strict';

  var overlay = document.getElementById('inject-modal');
  var titleEl = document.getElementById('inject-modal-title');
  var bodyEl = document.getElementById('inject-modal-body');
  var statusEl = document.getElementById('inject-modal-status');
  var closeBtn = document.getElementById('btn-inject-close');
  var cancelBtn = document.getElementById('btn-inject-cancel');
  var confirmBtn = document.getElementById('btn-inject-confirm');
  var findInput = document.getElementById('inject-find');
  var replaceInput = document.getElementById('inject-replace');
  var httpsCheckbox = document.getElementById('inject-https');

  if (!overlay) return;

  var currentOpts = null;
  var rawContent = '';    // ongewijzigde content van disk

  function setStatus(text, cls) {
    statusEl.textContent = text;
    statusEl.className = 'status' + (cls ? ' ' + cls : '');
  }

  function btnFeedback(btn, msg, cls) {
    var orig = btn.textContent;
    btn.textContent = msg;
    if (cls) btn.classList.add(cls);
    btn.disabled = true;
    setTimeout(function () {
      btn.textContent = orig;
      btn.disabled = false;
      if (cls) btn.classList.remove(cls);
    }, 1500);
  }

  // ── Modal find/replace ───────────────────────────────────
  function getModalReplacements() {
    var reps = [];
    if (httpsCheckbox && httpsCheckbox.checked) {
      reps.push({ find: 'http://', replace: 'https://' });
    }
    var f = findInput ? findInput.value : '';
    var r = replaceInput ? replaceInput.value : '';
    if (f) reps.push({ find: f, replace: r });
    return reps;
  }

  function applyModalReplacements(text) {
    var reps = getModalReplacements();
    for (var i = 0; i < reps.length; i++) {
      text = text.split(reps[i].find).join(reps[i].replace);
    }
    return text;
  }

  // ── Eén regel injecteren (screen mode) ───────────────────
  function injectSingleLine(input, btn) {
    var line = input.value.trim();
    if (!line) return;

    btn.disabled = true;

    var payload = {
      screen: currentOpts.screenName,
      command: currentOpts.commandName,
      content: line,
    };
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/commands/inject');
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.onload = function () {
      var data;
      try { data = JSON.parse(xhr.responseText); } catch (e) { data = {}; }
      if (xhr.status === 200 && data.ok) {
        btnFeedback(btn, 'OK', 'sent');
        if (typeof currentOpts.onSuccess === 'function') {
          currentOpts.onSuccess();
        }
      } else {
        setStatus(data.error || 'Inject mislukt', 'fail');
        btn.disabled = false;
      }
    };
    xhr.onerror = function () {
      setStatus('Verbindingsfout', 'fail');
      btn.disabled = false;
    };
    xhr.send(JSON.stringify(payload));
  }

  // ── Eén regel injecteren (agent mode) ────────────────────
  function injectSingleAgent(input, btn) {
    var line = input.value.trim();
    if (!line) return;
    if (typeof currentOpts.onConfirm === 'function') {
      currentOpts.onConfirm([line]);
    }
    btnFeedback(btn, 'OK', 'sent');
  }

  // ── Content renderen ─────────────────────────────────────
  function renderContent() {
    bodyEl.innerHTML = '';
    var content = applyModalReplacements(rawContent);
    var lines = content.split('\n');
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      var trimmed = line.trim();

      if (trimmed === '') {
        var spacer = document.createElement('div');
        spacer.className = 'inject-spacer';
        bodyEl.appendChild(spacer);
      } else if (trimmed.charAt(0) === '#') {
        var label = document.createElement('p');
        label.className = 'inject-label';
        label.textContent = trimmed.substring(1).trim();
        bodyEl.appendChild(label);
      } else {
        var row = document.createElement('div');
        row.className = 'inject-cmd-row';

        var input = document.createElement('input');
        input.type = 'text';
        input.className = 'inject-cmd-input';
        input.value = trimmed;

        var lineBtn = document.createElement('button');
        lineBtn.type = 'button';
        lineBtn.className = 'inject-line-btn';
        lineBtn.textContent = 'Inject';

        (function (inp, lb) {
          lb.addEventListener('click', function () {
            if (currentOpts.mode === 'agent') {
              injectSingleAgent(inp, lb);
            } else {
              injectSingleLine(inp, lb);
            }
          });
        })(input, lineBtn);

        row.appendChild(input);
        row.appendChild(lineBtn);
        bodyEl.appendChild(row);
      }
    }
  }

  // ── Content uitlezen (voor inject alles) ─────────────────
  function collectContent() {
    var parts = [];
    var children = bodyEl.children;
    for (var i = 0; i < children.length; i++) {
      var el = children[i];
      if (el.classList.contains('inject-label')) {
        parts.push('# ' + el.textContent);
      } else if (el.classList.contains('inject-spacer')) {
        parts.push('');
      } else if (el.classList.contains('inject-cmd-row')) {
        var inp = el.querySelector('.inject-cmd-input');
        if (inp) parts.push(inp.value);
      }
    }
    return parts.join('\n');
  }

  function collectCommandLines() {
    var lines = [];
    var inputs = bodyEl.querySelectorAll('.inject-cmd-input');
    for (var i = 0; i < inputs.length; i++) {
      var val = inputs[i].value.trim();
      if (val) lines.push(val);
    }
    return lines;
  }

  // ── Modal openen/sluiten ─────────────────────────────────
  function openModal(opts) {
    currentOpts = opts;
    rawContent = opts.content || '';

    titleEl.textContent = opts.commandName
      ? 'Inject: ' + opts.commandName
      : 'Commando injecteren';

    // Vul find/replace voor vanuit pagina-waarden
    if (findInput) findInput.value = opts.initialFind || '';
    if (replaceInput) replaceInput.value = opts.initialReplace || '';
    if (httpsCheckbox) httpsCheckbox.checked = !!opts.initialHttps;

    renderContent();
    setStatus('', '');
    confirmBtn.disabled = false;
    overlay.classList.remove('d-none');

    // Focus eerste input
    setTimeout(function () {
      var first = bodyEl.querySelector('.inject-cmd-input');
      if (first) first.focus();
    }, 50);
  }

  function closeModal() {
    overlay.classList.add('d-none');
    bodyEl.innerHTML = '';
    currentOpts = null;
    rawContent = '';
    setStatus('', '');
  }

  // ── Inject alles handler ─────────────────────────────────
  function onConfirmAll() {
    if (!currentOpts) return;
    confirmBtn.disabled = true;

    if (currentOpts.mode === 'agent') {
      var lines = collectCommandLines();
      if (!lines.length) {
        setStatus('Geen commando\'s om te injecteren', 'fail');
        confirmBtn.disabled = false;
        return;
      }
      if (typeof currentOpts.onConfirm === 'function') {
        currentOpts.onConfirm(lines);
      }
      closeModal();
      return;
    }

    // Screen mode: POST alles naar backend
    var content = collectContent();
    if (!content.trim()) {
      setStatus('Geen content om te injecteren', 'fail');
      confirmBtn.disabled = false;
      return;
    }

    setStatus('Injecteren...', '');

    var payload = {
      screen: currentOpts.screenName,
      command: currentOpts.commandName,
      content: content,
    };
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/commands/inject');
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.onload = function () {
      var data;
      try { data = JSON.parse(xhr.responseText); } catch (e) { data = {}; }
      if (xhr.status === 200 && data.ok) {
        setStatus('Alles geinjected in ' + currentOpts.screenName, 'ok');
        if (typeof currentOpts.onSuccess === 'function') {
          currentOpts.onSuccess();
        }
        setTimeout(closeModal, 800);
      } else {
        setStatus(data.error || 'Inject mislukt', 'fail');
        confirmBtn.disabled = false;
      }
    };
    xhr.onerror = function () {
      setStatus('Verbindingsfout', 'fail');
      confirmBtn.disabled = false;
    };
    xhr.send(JSON.stringify(payload));
  }

  // ── Find/replace live update ─────────────────────────────
  var renderDebounce = null;
  function onReplaceChange() {
    clearTimeout(renderDebounce);
    renderDebounce = setTimeout(renderContent, 150);
  }

  if (findInput) findInput.addEventListener('input', onReplaceChange);
  if (replaceInput) replaceInput.addEventListener('input', onReplaceChange);
  if (httpsCheckbox) httpsCheckbox.addEventListener('change', onReplaceChange);

  // ── Event listeners ──────────────────────────────────────
  closeBtn.addEventListener('click', closeModal);
  cancelBtn.addEventListener('click', closeModal);
  confirmBtn.addEventListener('click', onConfirmAll);

  overlay.addEventListener('click', function (e) {
    if (e.target === overlay) closeModal();
  });

  // Escape toets (capture zodat global-tools.js niet interfereert)
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && !overlay.classList.contains('d-none')) {
      e.stopImmediatePropagation();
      closeModal();
    }
  }, true);

  // Publieke API
  window.openInjectModal = openModal;
})();
