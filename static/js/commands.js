// Copyright (C) 2021 Jan-Karel Visser info@jan-karel.nl
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * commands.js
 * Extra functionaliteit voor de flask app.
 */


(function () {
  'use strict';

  var screenSelect = document.getElementById('screen-select');
  var screenCustom = document.getElementById('screen-custom');
  var refreshBtn = document.getElementById('refresh-screens');
  var statusEl = document.getElementById('inject-status');
  var filterInput = document.getElementById('cmd-filter');
  var cmdList = document.getElementById('cmd-list');
  var replaceFindInput = document.getElementById('replace-find');
  var replaceWithInput = document.getElementById('replace-with');
  var replaceHttpsCheckbox = document.getElementById('replace-https');

  if (!cmdList) return;

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

  function setStatus(text, cls) {
    statusEl.textContent = text;
    statusEl.className = 'status' + (cls ? ' ' + cls : '');
    if (cls === 'ok') {
      setTimeout(function () { statusEl.textContent = ''; }, 3000);
    }
  }

  function escapeHtml(s) {
    var d = document.createElement('div');
    d.appendChild(document.createTextNode(s));
    return d.innerHTML;
  }

  function copyToClipboard(text, btn) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { showFeedback(btn, 'Gekopieerd!'); });
    } else {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      showFeedback(btn, 'Gekopieerd!');
    }
  }

  function showFeedback(btn, msg) {
    var orig = btn.textContent;
    btn.textContent = msg;
    btn.classList.add('copied');
    setTimeout(function () {
      btn.textContent = orig;
      btn.classList.remove('copied');
    }, 1200);
  }

  function getScreenName() {
    var custom = screenCustom.value.trim();
    if (custom) return custom;
    return screenSelect.value;
  }

  // -----------------------------------------------------------------------
  // Screen sessions
  // -----------------------------------------------------------------------

  function loadScreens() {
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
    };
    xhr.send();
  }

  // -----------------------------------------------------------------------
  // Inject command
  // -----------------------------------------------------------------------

  function findCommandContent(cmdName) {
    for (var i = 0; i < allCommands.length; i++) {
      if (allCommands[i].name === cmdName) return allCommands[i].content;
    }
    return '';
  }

  function injectCommand(cmdName, btn) {
    var screen = getScreenName();
    if (!screen) {
      setStatus('Selecteer eerst een screen sessie', 'fail');
      return;
    }

    var raw = findCommandContent(cmdName);

    window.openInjectModal({
      commandName: cmdName,
      content: raw,
      mode: 'screen',
      screenName: screen,
      initialFind: replaceFindInput ? replaceFindInput.value : '',
      initialReplace: replaceWithInput ? replaceWithInput.value : '',
      initialHttps: replaceHttpsCheckbox ? replaceHttpsCheckbox.checked : false,
      onSuccess: function () {
        setStatus('Geinjected in ' + screen, 'ok');
        showFeedback(btn, 'Verstuurd!');
      },
    });
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

  // -----------------------------------------------------------------------
  // Command list rendering
  // -----------------------------------------------------------------------

  function buildCmdCard(cmd, injectFn) {
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
      b.addEventListener('click', function () { injectFn(cmdName, b); });
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

  function renderCommands(filter) {
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
          renderCommands(filterInput ? filterInput.value : '');
        });
      })(key, catHeader);

      section.appendChild(catHeader);

      if (!collapsed) {
        var body = document.createElement('div');
        body.className = 'cmd-category-body';
        for (var c = 0; c < cmds.length; c++) {
          body.appendChild(buildCmdCard(cmds[c], injectCommand));
        }
        section.appendChild(body);
      }

      cmdList.appendChild(section);
    }
  }

  function loadCommands() {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/api/commands');
    xhr.onload = function () {
      if (xhr.status === 200) {
        var data = JSON.parse(xhr.responseText);
        allCommands = data.commands || [];
        renderCommands('');
      }
    };
    xhr.send();
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

  // -----------------------------------------------------------------------
  // Events
  // -----------------------------------------------------------------------

  if (refreshBtn) {
    refreshBtn.addEventListener('click', loadScreens);
  }

  var filterDebounce = null;
  function rerender() {
    clearTimeout(filterDebounce);
    filterDebounce = setTimeout(function () {
      renderCommands(filterInput ? filterInput.value : '');
    }, 150);
  }

  if (filterInput) {
    filterInput.addEventListener('input', rerender);
  }
  if (replaceFindInput) {
    replaceFindInput.addEventListener('input', rerender);
  }
  if (replaceWithInput) {
    replaceWithInput.addEventListener('input', rerender);
  }
  if (replaceHttpsCheckbox) {
    replaceHttpsCheckbox.addEventListener('change', rerender);
  }

  // Init
  loadScreens();
  loadCommands();
})();
