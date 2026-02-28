// Copyright (C) 2021 Jan-Karel Visser info@jan-karel.nl
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Generator
 * Output van opdrachten (live) bekijken in HTML
 */

(function () {
  'use strict';

  var form = document.getElementById('gen-form');
  if (!form) return;

  var apiUrl = form.getAttribute('data-api');
  var btn = document.getElementById('gen-btn');
  var statusEl = document.getElementById('gen-status');
  var outputEl = document.getElementById('gen-output');
  var dlSection = document.getElementById('gen-download');
  var dlLink = document.getElementById('gen-dl-link');

  var currentRunId = null;
  var pollTimer = null;

  // Dynamisch formulier — agentgen specifiek
  var languageSelect = document.getElementById('language');
  var amsiCheckbox = document.getElementById('amsi');
  var persistSelect = document.getElementById('persist');
  var previewSection = document.getElementById('gen-preview-section');
  var previewEl = document.getElementById('gen-preview');

  // Persist opties per taal
  var persistValid = {
    bash: ['crontab'],
    powershell: ['registry', 'schtasks'],
    python: ['crontab', 'registry', 'schtasks'],
    csharp: ['registry', 'schtasks'],
    go: ['crontab', 'schtasks'],
    rust: ['crontab'],
    ruby: ['crontab']
  };

  function updateFormForLanguage() {
    if (!languageSelect) return;
    var lang = languageSelect.value;

    // AMSI: alleen voor powershell
    if (amsiCheckbox) {
      if (lang !== 'powershell') {
        amsiCheckbox.checked = false;
        amsiCheckbox.disabled = true;
        amsiCheckbox.closest('label').style.opacity = '0.45';
      } else {
        amsiCheckbox.disabled = false;
        amsiCheckbox.closest('label').style.opacity = '1';
      }
    }

    // Persist: verberg ongeldige opties
    if (persistSelect) {
      var valid = persistValid[lang] || [];
      var options = persistSelect.querySelectorAll('option');
      for (var i = 0; i < options.length; i++) {
        var opt = options[i];
        if (opt.value === '') {
          opt.style.display = '';
          continue;
        }
        if (valid.indexOf(opt.value) >= 0) {
          opt.style.display = '';
        } else {
          opt.style.display = 'none';
          if (opt.selected) {
            persistSelect.value = '';
          }
        }
      }
    }
  }

  if (languageSelect) {
    languageSelect.addEventListener('change', updateFormForLanguage);
    updateFormForLanguage();
  }

  function setStatus(text, cls) {
    statusEl.textContent = text;
    statusEl.className = 'status' + (cls ? ' ' + cls : '');
  }

  function escapeHtml(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function ansiToHtml(text) {
    // ANSI SGR codes naar HTML spans
    var COLORS = {
      '30': '#4b5563', '31': '#ef4444', '32': '#22c55e', '33': '#eab308',
      '34': '#3b82f6', '35': '#a855f7', '36': '#06b6d4', '37': '#e2e8f0',
      '90': '#6b7280', '91': '#f87171', '92': '#4ade80', '93': '#facc15',
      '94': '#60a5fa', '95': '#c084fc', '96': '#22d3ee', '97': '#f8fafc'
    };
    var result = '';
    var open = 0;
    var re = /\x1b\[([0-9;]*)m/g;
    var last = 0;
    var m;
    while ((m = re.exec(text)) !== null) {
      result += escapeHtml(text.substring(last, m.index));
      last = m.index + m[0].length;
      var codes = m[1] ? m[1].split(';') : ['0'];
      for (var i = 0; i < codes.length; i++) {
        var c = codes[i];
        if (c === '0' || c === '') {
          while (open > 0) { result += '</span>'; open--; }
        } else if (c === '1') {
          result += '<span style="font-weight:700">'; open++;
        } else if (COLORS[c]) {
          result += '<span style="color:' + COLORS[c] + '">'; open++;
        }
      }
    }
    result += escapeHtml(text.substring(last));
    while (open > 0) { result += '</span>'; open--; }
    return result;
  }

  function setOutput(lines) {
    outputEl.innerHTML = ansiToHtml(lines.join('\n'));
    outputEl.scrollTop = outputEl.scrollHeight;
  }

  function showDownload(url) {
    dlLink.href = url;
    dlSection.classList.add('show');
  }

  function hideDownload() {
    dlSection.classList.remove('show');
  }

  function hidePreview() {
    if (previewSection) previewSection.style.display = 'none';
  }

  function showPreview(url) {
    if (!previewSection || !previewEl || !url) return;
    var xhr = new XMLHttpRequest();
    xhr.open('GET', url);
    xhr.onload = function () {
      if (xhr.status === 200) {
        previewEl.textContent = xhr.responseText;
        previewSection.style.display = '';
      }
    };
    xhr.send();
  }

  function pollRun() {
    if (!currentRunId) return;

    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/api/generate/status/' + currentRunId);
    xhr.onload = function () {
      if (xhr.status !== 200) {
        setStatus('Fout bij ophalen status', 'fail');
        btn.disabled = false;
        return;
      }

      var data = JSON.parse(xhr.responseText);
      setOutput(data.output || []);

      if (data.status === 'running') {
        setStatus('Bezig met genereren...', '');
        pollTimer = setTimeout(pollRun, 1000);
      } else if (data.status === 'success') {
        setStatus('Gereed!', 'ok');
        btn.disabled = false;
        if (data.has_download && data.download_url) {
          showDownload(data.download_url);
          showPreview(data.download_url);
        }
        try {
          form.dispatchEvent(new CustomEvent('generator:done', {
            bubbles: true,
            detail: { download_url: data.download_url || null, run_id: currentRunId }
          }));
        } catch (ignored) {}
      } else {
        setStatus('Mislukt (rc=' + data.return_code + ')', 'fail');
        btn.disabled = false;
      }
    };
    xhr.onerror = function () {
      setStatus('Verbindingsfout', 'fail');
      btn.disabled = false;
    };
    xhr.send();
  }

  form.addEventListener('submit', function (e) {
    e.preventDefault();

    if (pollTimer) {
      clearTimeout(pollTimer);
      pollTimer = null;
    }

    hideDownload();
    hidePreview();
    setOutput([]);
    setStatus('Starten...', '');
    btn.disabled = true;

    var formData = new FormData(form);
    var xhr = new XMLHttpRequest();
    xhr.open('POST', apiUrl);
    xhr.onload = function () {
      var data;
      try {
        data = JSON.parse(xhr.responseText);
      } catch (ex) {
        setStatus('Ongeldig antwoord van server', 'fail');
        btn.disabled = false;
        return;
      }

      if (xhr.status !== 200) {
        setStatus('Fout: ' + (data.error || 'onbekend'), 'fail');
        btn.disabled = false;
        return;
      }

      currentRunId = data.run_id;
      setStatus('Run gestart...', '');
      pollRun();
    };
    xhr.onerror = function () {
      setStatus('Verbindingsfout', 'fail');
      btn.disabled = false;
    };
    xhr.send(formData);
  });
})();
