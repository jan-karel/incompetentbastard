// Copyright (C) 2021 Jan-Karel Visser info@jan-karel.nl
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * HTML terminal
 * Zodat je ook kunt klootviolen vanaf je iPad
 */

(function () {
  'use strict';

  var newSessionName = document.getElementById('new-session-name');
  var newSessionShell = document.getElementById('new-session-shell');
  var createBtn = document.getElementById('create-session');
  var createStatus = document.getElementById('create-status');
  var screenSelect = document.getElementById('screen-select');
  var screenCustom = document.getElementById('screen-custom');
  var refreshBtn = document.getElementById('refresh-screens');
  var startBtn = document.getElementById('start-polling');
  var stopBtn = document.getElementById('stop-polling');
  var detachBtn = document.getElementById('detach-session');
  var statusEl = document.getElementById('screen-status');
  var outputEl = document.getElementById('screen-output');
  var cmdInput = document.getElementById('screen-cmd');
  var sendBtn = document.getElementById('send-cmd');
  var recordingLink = document.getElementById('recording-link');

  if (!outputEl) return;

  var pollTimer = null;

  function updateRecordingLink() {
    if (!recordingLink) return;
    var name = getScreenName();
    if (name) {
      recordingLink.href = '/dashboard/recordings/' + encodeURIComponent(name) + '.rec';
      recordingLink.style.display = '';
    } else {
      recordingLink.style.display = 'none';
    }
  }
  var polling = false;

  function escapeHtml(s) {
    var d = document.createElement('div');
    d.appendChild(document.createTextNode(s));
    return d.innerHTML;
  }

  function setStatus(text, cls) {
    statusEl.textContent = text;
    statusEl.className = 'status' + (cls ? ' ' + cls : '');
  }

  function setCreateStatus(text, cls) {
    createStatus.textContent = text;
    createStatus.className = 'status' + (cls ? ' ' + cls : '');
    if (cls === 'ok') {
      setTimeout(function () { createStatus.textContent = ''; }, 4000);
    }
  }

  function getScreenName() {
    var custom = (screenCustom.value || '').trim();
    if (custom) return custom;
    return (screenSelect.value || '').trim();
  }

  // -----------------------------------------------------------------------
  // Screen sessions laden
  // -----------------------------------------------------------------------

  function loadScreens(selectName) {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/api/commands/screens');
    xhr.onload = function () {
      if (xhr.status !== 200) return;
      var data = JSON.parse(xhr.responseText);
      var screens = data.screens || [];

      screenSelect.innerHTML = '';
      if (!screens.length) {
        var opt = document.createElement('option');
        opt.value = '';
        opt.textContent = '-- geen sessies gevonden --';
        screenSelect.appendChild(opt);
        return;
      }

      for (var i = 0; i < screens.length; i++) {
        var opt = document.createElement('option');
        opt.value = screens[i].name;
        opt.textContent = screens[i].name + ' (' + screens[i].status + ')';
        screenSelect.appendChild(opt);
      }

      // Selecteer een specifieke sessie als opgegeven
      if (selectName) {
        screenSelect.value = selectName;
      }
    };
    xhr.send();
  }

  // -----------------------------------------------------------------------
  // Nieuwe sessie aanmaken
  // -----------------------------------------------------------------------

  function createSession() {
    var name = (newSessionName.value || '').trim();
    if (!name) {
      setCreateStatus('Vul een sessie naam in', 'fail');
      return;
    }

    createBtn.disabled = true;
    setCreateStatus('Sessie starten...', '');

    var payload = { name: name };
    var shell = (newSessionShell.value || '').trim();
    if (shell) { payload.shell = shell; }
    var body = JSON.stringify(payload);
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/screen/start');
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.onload = function () {
      createBtn.disabled = false;
      var data;
      try { data = JSON.parse(xhr.responseText); } catch (e) { data = {}; }

      if (xhr.status === 200 && data.ok) {
        setCreateStatus('Sessie "' + name + '" gestart (recording: ' + data.recording + ')', 'ok');
        newSessionName.value = '';
        // Vernieuw sessie lijst en selecteer de nieuwe sessie
        setTimeout(function () { loadScreens(name); }, 500);
      } else {
        setCreateStatus(data.error || 'Starten mislukt', 'fail');
      }
    };
    xhr.onerror = function () {
      createBtn.disabled = false;
      setCreateStatus('Verbindingsfout', 'fail');
    };
    xhr.send(body);
  }

  // -----------------------------------------------------------------------
  // Sessie detachen
  // -----------------------------------------------------------------------

  function detachSession() {
    var name = getScreenName();
    if (!name) {
      setStatus('Selecteer eerst een sessie', 'fail');
      return;
    }

    detachBtn.disabled = true;

    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/screen/' + encodeURIComponent(name) + '/detach');
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.onload = function () {
      detachBtn.disabled = false;
      if (xhr.status === 200) {
        if (polling) { stopPolling(); }
        setStatus('Sessie "' + name + '" detached', 'ok');
        setTimeout(function () {
          loadScreens();
          setStatus('', '');
        }, 1500);
      } else {
        var err;
        try { err = JSON.parse(xhr.responseText).error; } catch (e) { err = 'Detach mislukt'; }
        setStatus(err, 'fail');
      }
    };
    xhr.onerror = function () {
      detachBtn.disabled = false;
      setStatus('Verbindingsfout', 'fail');
    };
    xhr.send();
  }

  // -----------------------------------------------------------------------
  // Screen content ophalen
  // -----------------------------------------------------------------------

  function fetchContent() {
    var name = getScreenName();
    if (!name) return;

    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/api/screen/' + encodeURIComponent(name) + '/content');
    xhr.onload = function () {
      if (xhr.status === 200) {
        var data = JSON.parse(xhr.responseText);
        var wasAtBottom = outputEl.scrollHeight - outputEl.scrollTop - outputEl.clientHeight < 30;
        outputEl.innerHTML = escapeHtml(data.content || '');
        if (wasAtBottom) {
          outputEl.scrollTop = outputEl.scrollHeight;
        }
      } else {
        var err;
        try { err = JSON.parse(xhr.responseText).error; } catch (e) { err = 'Fout bij ophalen'; }
        setStatus(err, 'fail');
      }
    };
    xhr.onerror = function () {
      setStatus('Verbindingsfout', 'fail');
    };
    xhr.send();
  }

  // -----------------------------------------------------------------------
  // Polling start/stop
  // -----------------------------------------------------------------------

  function startPolling() {
    var name = getScreenName();
    if (!name) {
      setStatus('Selecteer eerst een sessie', 'fail');
      return;
    }

    polling = true;
    startBtn.disabled = true;
    stopBtn.disabled = false;
    cmdInput.disabled = false;
    sendBtn.disabled = false;
    screenSelect.disabled = true;
    screenCustom.disabled = true;
    setStatus('Polling actief', 'polling');
    updateRecordingLink();

    fetchContent();
    pollTimer = setInterval(fetchContent, 1000);
  }

  function stopPolling() {
    polling = false;
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
    startBtn.disabled = false;
    stopBtn.disabled = true;
    cmdInput.disabled = true;
    sendBtn.disabled = true;
    screenSelect.disabled = false;
    screenCustom.disabled = false;
    setStatus('Gestopt', '');
  }

  // -----------------------------------------------------------------------
  // Commando versturen
  // -----------------------------------------------------------------------

  function sendCommand() {
    var name = getScreenName();
    var cmd = cmdInput.value;
    if (!name || !cmd) return;

    sendBtn.disabled = true;
    var body = JSON.stringify({ command: cmd });
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/screen/' + encodeURIComponent(name) + '/input');
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.onload = function () {
      sendBtn.disabled = false;
      if (xhr.status === 200) {
        cmdInput.value = '';
        cmdInput.focus();
        // Direct content vernieuwen na commando
        setTimeout(fetchContent, 300);
      } else {
        var err;
        try { err = JSON.parse(xhr.responseText).error; } catch (e) { err = 'Versturen mislukt'; }
        setStatus(err, 'fail');
      }
    };
    xhr.onerror = function () {
      sendBtn.disabled = false;
      setStatus('Verbindingsfout', 'fail');
    };
    xhr.send(body);
  }

  // -----------------------------------------------------------------------
  // Events
  // -----------------------------------------------------------------------

  createBtn.addEventListener('click', createSession);
  newSessionName.addEventListener('keydown', function (e) {
    if (e.key === 'Enter') { e.preventDefault(); createSession(); }
  });

  refreshBtn.addEventListener('click', function () { loadScreens(); });
  startBtn.addEventListener('click', startPolling);
  stopBtn.addEventListener('click', stopPolling);
  detachBtn.addEventListener('click', detachSession);
  sendBtn.addEventListener('click', sendCommand);
  screenSelect.addEventListener('change', updateRecordingLink);
  screenCustom.addEventListener('input', updateRecordingLink);

  cmdInput.addEventListener('keydown', function (e) {
    if (e.key === 'Enter') {
      e.preventDefault();
      sendCommand();
    }
  });

  // -----------------------------------------------------------------------
  // Command Library (inline)
  // -----------------------------------------------------------------------

  var cmdList = document.getElementById('cmd-list');
  var cmdFilter = document.getElementById('cmd-filter');
  var replaceFindInput = document.getElementById('replace-find');
  var replaceWithInput = document.getElementById('replace-with');
  var replaceHttpsCheckbox = document.getElementById('replace-https');
  var allCommands = [];

  function getReplacements() {
    var reps = [];
    if (replaceHttpsCheckbox && replaceHttpsCheckbox.checked) {
      reps.push({ find: 'http://', replace: 'https://' });
    }
    if (replaceFindInput) {
      var find = replaceFindInput.value;
      var replace = replaceWithInput ? replaceWithInput.value : '';
      if (find) reps.push({ find: find, replace: replace });
    }
    return reps;
  }

  function applyReplacements(text) {
    var reps = getReplacements();
    for (var i = 0; i < reps.length; i++) {
      text = text.split(reps[i].find).join(reps[i].replace);
    }
    return text;
  }

  function highlightReplacements(text) {
    var reps = getReplacements();
    var escaped = escapeHtml(text);
    for (var i = 0; i < reps.length; i++) {
      var needle = escapeHtml(reps[i].replace);
      if (needle) {
        escaped = escaped.split(needle).join('<mark style="background:#2d5a2d;color:#4caf50;padding:0 2px;border-radius:2px">' + needle + '</mark>');
      }
    }
    return escaped;
  }

  function copyToClipboard(text, btn) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { showCmdFeedback(btn, 'Gekopieerd!'); });
    } else {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      showCmdFeedback(btn, 'Gekopieerd!');
    }
  }

  function showCmdFeedback(btn, msg) {
    var orig = btn.textContent;
    btn.textContent = msg;
    btn.classList.add('copied');
    setTimeout(function () {
      btn.textContent = orig;
      btn.classList.remove('copied');
    }, 1200);
  }

  function injectLibraryCommand(cmdName, btn) {
    var screen = getScreenName();
    if (!screen) {
      setStatus('Selecteer eerst een screen sessie', 'fail');
      return;
    }

    btn.disabled = true;
    var payload = { screen: screen, command: cmdName };
    var reps = getReplacements();
    if (reps.length) payload.replacements = reps;
    var body = JSON.stringify(payload);
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/commands/inject');
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.onload = function () {
      btn.disabled = false;
      var data;
      try { data = JSON.parse(xhr.responseText); } catch (e) { data = {}; }
      if (xhr.status === 200 && data.ok) {
        setStatus('Command geinjected', 'ok');
        showCmdFeedback(btn, 'Verstuurd!');
        setTimeout(fetchContent, 300);
      } else {
        setStatus(data.error || 'Inject mislukt', 'fail');
      }
    };
    xhr.onerror = function () {
      btn.disabled = false;
      setStatus('Verbindingsfout', 'fail');
    };
    xhr.send(body);
  }

  // -----------------------------------------------------------------------
  // Category mapping
  // -----------------------------------------------------------------------

  var CATEGORY_PREFIXES = [
    { prefix: 'amsi_',      label: 'AMSI Bypass' },
    { prefix: 'av_',        label: 'AV Bypass' },
    { prefix: 'adcs_',      label: 'AD CS Attacks' },
    { prefix: 'ad_',        label: 'Active Directory' },
    { prefix: 'applocker_', label: 'AppLocker Bypass' },
    { prefix: 'cred_',      label: 'Credential Dumping' },
    { prefix: 'enum_',      label: 'Enumeratie' },
    { prefix: 'exploit_',   label: 'Exploits' },
    { prefix: 'get_',       label: 'Tool Downloads' },
    { prefix: 'inject_',    label: 'Process Injection' },
    { prefix: 'kerb_',      label: 'Kerberos' },
    { prefix: 'lateral_',   label: 'Lateral Movement (Windows)' },
    { prefix: 'linux_',     label: 'Linux Post-Exploitation' },
    { prefix: 'mssql_',     label: 'MSSQL Attacks' },
    { prefix: 'net_',       label: 'Network Evasion' },
    { prefix: 'passwd_',    label: 'Password Attacks' },
    { prefix: 'persist_',   label: 'Persistence' },
    { prefix: 'privesc_',   label: 'Privilege Escalation' },
    { prefix: 'ps_cradle_', label: 'PowerShell Cradles' },
    { prefix: 'ps',         label: 'PowerShell Payloads' },
    { prefix: 'msf',        label: 'Metasploit' },
    { prefix: 'proof_',     label: 'Proof / Flags' },
    { prefix: 'recon_',     label: 'Reconnaissance' },
    { prefix: 'shell_',     label: 'Reverse Shells' },
    { prefix: 'tunnel_',    label: 'Tunneling / Pivoting' },
    { prefix: 'web_ssti_',  label: 'Web: SSTI' },
    { prefix: 'web_sqli_',  label: 'Web: SQL Injection' },
    { prefix: 'web_cmdi_',  label: 'Web: Command Injection' },
    { prefix: 'web_xss_',   label: 'Web: XSS' },
    { prefix: 'web_xxe_',   label: 'Web: XXE' },
    { prefix: 'web_ssrf_',  label: 'Web: SSRF' },
    { prefix: 'web_lfi_',   label: 'Web: LFI / Traversal' },
    { prefix: 'web_deser_', label: 'Web: Deserialization' },
    { prefix: 'web_',       label: 'Web: Overig' }
  ];

  function getCategoryKey(name) {
    for (var i = 0; i < CATEGORY_PREFIXES.length; i++) {
      if (name.indexOf(CATEGORY_PREFIXES[i].prefix) === 0) {
        return CATEGORY_PREFIXES[i].prefix;
      }
    }
    return '_other';
  }

  function getCategoryLabel(key) {
    for (var i = 0; i < CATEGORY_PREFIXES.length; i++) {
      if (CATEGORY_PREFIXES[i].prefix === key) return CATEGORY_PREFIXES[i].label;
    }
    return 'Overig';
  }

  var collapsedCategories = {};

  function buildCmdCard(cmd) {
    var card = document.createElement('div');
    card.className = 'cmd-item';

    var header = document.createElement('div');
    header.className = 'cmd-header';

    var name = document.createElement('span');
    name.className = 'cmd-name';
    name.textContent = cmd.name;

    var actions = document.createElement('span');
    actions.className = 'cmd-actions';

    var copyBtn = document.createElement('button');
    copyBtn.className = 'btn-copy';
    copyBtn.textContent = 'Kopieer';
    copyBtn.setAttribute('type', 'button');
    (function (content, b) {
      b.addEventListener('click', function () { copyToClipboard(applyReplacements(content), b); });
    })(cmd.content, copyBtn);

    var injectBtn = document.createElement('button');
    injectBtn.className = 'btn-copy btn-inject';
    injectBtn.textContent = 'Inject';
    injectBtn.setAttribute('type', 'button');
    (function (cmdName, b) {
      b.addEventListener('click', function () { injectLibraryCommand(cmdName, b); });
    })(cmd.name, injectBtn);

    actions.appendChild(copyBtn);
    actions.appendChild(injectBtn);
    header.appendChild(name);
    header.appendChild(actions);

    var code = document.createElement('pre');
    code.className = 'cmd-code';
    var replaced = applyReplacements(cmd.content);
    if (replaced !== cmd.content) {
      code.innerHTML = highlightReplacements(replaced);
    } else {
      code.textContent = cmd.content;
    }

    card.appendChild(header);
    card.appendChild(code);
    return card;
  }

  function renderLibraryCommands(filter) {
    if (!cmdList) return;
    cmdList.innerHTML = '';
    var term = (filter || '').toLowerCase();

    // Filter commands
    var filtered = [];
    for (var i = 0; i < allCommands.length; i++) {
      var cmd = allCommands[i];
      if (term && cmd.name.toLowerCase().indexOf(term) === -1 && cmd.content.toLowerCase().indexOf(term) === -1) {
        continue;
      }
      filtered.push(cmd);
    }

    if (filtered.length === 0) {
      cmdList.innerHTML = '<p style="color:var(--muted)">Geen commands gevonden' + (term ? ' voor "' + escapeHtml(term) + '"' : '') + '.</p>';
      return;
    }

    // Group by category
    var groups = {};
    var groupOrder = [];
    for (var i = 0; i < filtered.length; i++) {
      var key = getCategoryKey(filtered[i].name);
      if (!groups[key]) {
        groups[key] = [];
        groupOrder.push(key);
      }
      groups[key].push(filtered[i]);
    }

    for (var g = 0; g < groupOrder.length; g++) {
      var key = groupOrder[g];
      var cmds = groups[key];
      var label = getCategoryLabel(key);
      var collapsed = !!collapsedCategories[key];

      var section = document.createElement('div');
      section.className = 'cmd-category';

      var catHeader = document.createElement('div');
      catHeader.className = 'cmd-category-header' + (collapsed ? ' collapsed' : '');
      catHeader.innerHTML = '<span class="cmd-category-chevron"></span>' +
        '<span class="cmd-category-label">' + escapeHtml(label) + '</span>' +
        '<span class="cmd-category-count">' + cmds.length + '</span>';
      (function (k, ch) {
        ch.addEventListener('click', function () {
          collapsedCategories[k] = !collapsedCategories[k];
          renderLibraryCommands(cmdFilter ? cmdFilter.value : '');
        });
      })(key, catHeader);

      section.appendChild(catHeader);

      if (!collapsed) {
        var body = document.createElement('div');
        body.className = 'cmd-category-body';
        for (var c = 0; c < cmds.length; c++) {
          body.appendChild(buildCmdCard(cmds[c]));
        }
        section.appendChild(body);
      }

      cmdList.appendChild(section);
    }
  }

  function loadLibraryCommands() {
    if (!cmdList) return;
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/api/commands');
    xhr.onload = function () {
      if (xhr.status === 200) {
        var data = JSON.parse(xhr.responseText);
        allCommands = data.commands || [];
        renderLibraryCommands('');
      }
    };
    xhr.send();
  }

  var cmdDebounce = null;
  function rerenderLibrary() {
    clearTimeout(cmdDebounce);
    cmdDebounce = setTimeout(function () {
      renderLibraryCommands(cmdFilter ? cmdFilter.value : '');
    }, 150);
  }

  if (cmdFilter) {
    cmdFilter.addEventListener('input', rerenderLibrary);
  }
  if (replaceFindInput) {
    replaceFindInput.addEventListener('input', rerenderLibrary);
  }
  if (replaceWithInput) {
    replaceWithInput.addEventListener('input', rerenderLibrary);
  }
  if (replaceHttpsCheckbox) {
    replaceHttpsCheckbox.addEventListener('change', rerenderLibrary);
  }

  // -----------------------------------------------------------------------
  // Sidebar toggle
  // -----------------------------------------------------------------------

  var cmdSidebar = document.getElementById('cmd-sidebar');
  var toggleSidebarBtn = document.getElementById('toggle-cmd-sidebar');
  var closeSidebarBtn = document.getElementById('close-cmd-sidebar');

  function setSidebarOpen(open) {
    if (!cmdSidebar) return;
    if (open) {
      cmdSidebar.classList.add('open');
      if (toggleSidebarBtn) toggleSidebarBtn.innerHTML = 'Commands &#9664;';
    } else {
      cmdSidebar.classList.remove('open');
      if (toggleSidebarBtn) toggleSidebarBtn.innerHTML = 'Commands &#9654;';
    }
  }

  if (toggleSidebarBtn) {
    toggleSidebarBtn.addEventListener('click', function () {
      setSidebarOpen(!cmdSidebar.classList.contains('open'));
    });
  }
  if (closeSidebarBtn) {
    closeSidebarBtn.addEventListener('click', function () {
      setSidebarOpen(false);
    });
  }

  // -----------------------------------------------------------------------
  // Fullscreen
  // -----------------------------------------------------------------------

  var workspace = document.getElementById('terminal-workspace');
  var fsBtn = document.getElementById('btn-fullscreen');

  if (fsBtn && workspace) {
    fsBtn.addEventListener('click', function () {
      if (document.fullscreenElement || document.webkitFullscreenElement) {
        (document.exitFullscreen || document.webkitExitFullscreen).call(document);
      } else {
        (workspace.requestFullscreen || workspace.webkitRequestFullscreen).call(workspace);
      }
    });

    function onFsChange() {
      var isFs = !!(document.fullscreenElement || document.webkitFullscreenElement);
      fsBtn.innerHTML = isFs ? '&#x2716; Exit fullscreen' : '&#x26F6; Fullscreen';
    }
    document.addEventListener('fullscreenchange', onFsChange);
    document.addEventListener('webkitfullscreenchange', onFsChange);
  }

  // Init
  loadScreens();
  loadLibraryCommands();
})();
