// Copyright (C) 2021 Jan-Karel Visser info@jan-karel.nl
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * ./agents
 * Extra functionaliteit voor de flask app.
 */

(function () {
  'use strict';

  var agentListEl = document.getElementById('agent-list');
  var shellCard = document.getElementById('shell-card');
  var shellTitle = document.getElementById('shell-title');
  var shellOutput = document.getElementById('shell-output');
  var shellCmd = document.getElementById('shell-cmd');
  var sendBtn = document.getElementById('send-cmd');
  var clearBtn = document.getElementById('clear-shell');
  var deleteBtn = document.getElementById('delete-agent');
  var recordingLink = document.getElementById('recording-link');
  var kpiActive = document.getElementById('kpi-active');
  var kpiTotal = document.getElementById('kpi-total');
  var kpiDead = document.getElementById('kpi-dead');

  // Command Library sidebar elements
  var workspace = document.getElementById('agent-workspace');
  var cmdSidebar = document.getElementById('cmd-sidebar');
  var toggleSidebarBtn = document.getElementById('toggle-cmd-sidebar');
  var closeSidebarBtn = document.getElementById('close-cmd-sidebar');
  var cmdList = document.getElementById('cmd-list');
  var cmdFilter = document.getElementById('cmd-filter');
  var replaceFindInput = document.getElementById('replace-find');
  var replaceWithInput = document.getElementById('replace-with');
  var replaceHttpsCheckbox = document.getElementById('replace-https');

  if (!agentListEl) return;

  var selectedAgent = null;
  var agentPollTimer = null;
  var historyPollTimer = null;
  var lastHistoryLen = 0;
  var allCommands = [];
  var collapsedCategories = {};

  function escapeHtml(s) {
    var d = document.createElement('div');
    d.appendChild(document.createTextNode(s));
    return d.innerHTML;
  }

  function timeDelta(seconds) {
    if (seconds < 60) return seconds + 's geleden';
    if (seconds < 3600) return Math.floor(seconds / 60) + 'm geleden';
    if (seconds < 86400) return Math.floor(seconds / 3600) + 'u geleden';
    return Math.floor(seconds / 86400) + 'd geleden';
  }

  // ── Agent list polling ──────────────────────────────────────
  function fetchAgents() {
    fetch('/api/agents')
      .then(function (r) { return r.json(); })
      .then(function (agents) {
        var active = 0, dead = 0;
        agents.forEach(function (a) {
          if (a.status === 'active') active++;
          if (a.status === 'dead') dead++;
        });
        kpiActive.textContent = active;
        kpiTotal.textContent = agents.length;
        kpiDead.textContent = dead;

        agentListEl.innerHTML = '';
        if (agents.length === 0) {
          agentListEl.innerHTML = '<p class="help">Geen agenten verbonden.</p>';
          return;
        }
        agents.forEach(function (a) {
          var item = document.createElement('div');
          item.className = 'agent-item' + (selectedAgent === a.agent_id ? ' selected' : '');
          item.dataset.agentId = a.agent_id;
          item.innerHTML =
            '<span class="agent-dot ' + escapeHtml(a.status) + '"></span>' +
            '<div class="agent-meta">' +
              '<div class="agent-name">' + escapeHtml(a.hostname) + ' (' + escapeHtml(a.username) + ')</div>' +
              '<div class="agent-info">' + escapeHtml(a.ip) + ' &middot; ' + escapeHtml(a.os_info || '') + ' &middot; ' + escapeHtml(a.script || '') + '</div>' +
            '</div>' +
            '<span class="agent-time">' + timeDelta(a.delta) + '</span>';
          item.addEventListener('click', function () { selectAgent(a.agent_id, a); });
          agentListEl.appendChild(item);
        });
      })
      .catch(function () {});
  }

  // ── Select agent ────────────────────────────────────────────
  function selectAgent(agentId, agentData) {
    selectedAgent = agentId;
    lastHistoryLen = 0;
    shellOutput.innerHTML = '';
    shellCard.style.display = '';
    shellTitle.textContent = 'Shell: ' + (agentData.hostname || agentId) + ' (' + (agentData.ip || '') + ')';
    shellCmd.focus();

    // Recording link
    if (recordingLink) {
      if (agentData.recording) {
        recordingLink.href = '/dashboard/recordings/' + encodeURIComponent(agentData.recording);
        recordingLink.style.display = '';
      } else {
        recordingLink.style.display = 'none';
      }
    }

    var items = agentListEl.querySelectorAll('.agent-item');
    items.forEach(function (el) {
      el.classList.toggle('selected', el.dataset.agentId === agentId);
    });

    if (historyPollTimer) clearInterval(historyPollTimer);
    fetchHistory();
    historyPollTimer = setInterval(fetchHistory, 2000);
  }

  // ── Command history ─────────────────────────────────────────
  function fetchHistory() {
    if (!selectedAgent) return;
    fetch('/api/agents/' + selectedAgent + '/history')
      .then(function (r) { return r.json(); })
      .then(function (cmds) {
        if (cmds.length === lastHistoryLen) return;
        lastHistoryLen = cmds.length;
        renderHistory(cmds);
      })
      .catch(function () {});
  }

  function renderHistory(cmds) {
    var html = '';
    cmds.forEach(function (c) {
      html += '<div class="cmd-line">$ ' + escapeHtml(c.command) + '</div>';
      if (c.status === 'done' && c.response !== null) {
        html += '<div class="cmd-output">' + escapeHtml(c.response) + '</div>';
      } else if (c.status === 'sent') {
        html += '<div class="cmd-pending">[wacht op resultaat...]</div>';
      } else {
        html += '<div class="cmd-pending">[in wachtrij]</div>';
      }
    });
    shellOutput.innerHTML = html;
    shellOutput.scrollTop = shellOutput.scrollHeight;
  }

  // ── Send command (text) ─────────────────────────────────────
  function queueCommand(cmdText) {
    if (!selectedAgent || !cmdText) return;
    fetch('/api/agents/' + selectedAgent + '/command', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ command: cmdText })
    }).then(function () {
      shellOutput.innerHTML += '<div class="cmd-line">$ ' + escapeHtml(cmdText) + '</div>' +
                               '<div class="cmd-pending">[in wachtrij]</div>';
      shellOutput.scrollTop = shellOutput.scrollHeight;
      lastHistoryLen = 0;
    }).catch(function () {});
  }

  function sendCommand() {
    var cmd = shellCmd.value.trim();
    if (!cmd) return;
    shellCmd.value = '';
    queueCommand(cmd);
  }

  sendBtn.addEventListener('click', sendCommand);
  shellCmd.addEventListener('keydown', function (e) {
    if (e.key === 'Enter') { e.preventDefault(); sendCommand(); }
  });

  // ── Clear shell ─────────────────────────────────────────────
  clearBtn.addEventListener('click', function () {
    shellOutput.innerHTML = '';
  });

  // ── Delete agent ────────────────────────────────────────────
  deleteBtn.addEventListener('click', function () {
    if (!selectedAgent) return;
    if (!confirm('Agent verwijderen? Alle commando geschiedenis wordt gewist.')) return;
    fetch('/api/agents/' + selectedAgent, { method: 'DELETE' })
      .then(function () {
        selectedAgent = null;
        shellCard.style.display = 'none';
        if (historyPollTimer) clearInterval(historyPollTimer);
        fetchAgents();
      })
      .catch(function () {});
  });

  // ═══════════════════════════════════════════════════════════
  // Command Library (reuse screen-terminal patterns)
  // ═══════════════════════════════════════════════════════════

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
      navigator.clipboard.writeText(text).then(function () { showBtnFeedback(btn, 'Gekopieerd!'); });
    } else {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      showBtnFeedback(btn, 'Gekopieerd!');
    }
  }

  function showBtnFeedback(btn, msg) {
    var orig = btn.textContent;
    btn.textContent = msg;
    btn.classList.add('copied');
    setTimeout(function () {
      btn.textContent = orig;
      btn.classList.remove('copied');
    }, 1200);
  }

  // Inject: open modal, queue na bevestiging
  function injectCommand(content, btn, cmdName) {
    if (!selectedAgent) {
      showBtnFeedback(btn, 'Geen agent!');
      return;
    }

    window.openInjectModal({
      commandName: cmdName || '',
      content: content,
      mode: 'agent',
      initialFind: replaceFindInput ? replaceFindInput.value : '',
      initialReplace: replaceWithInput ? replaceWithInput.value : '',
      initialHttps: replaceHttpsCheckbox ? replaceHttpsCheckbox.checked : false,
      onConfirm: function (lines) {
        for (var i = 0; i < lines.length; i++) {
          queueCommand(lines[i]);
        }
        showBtnFeedback(btn, 'Verstuurd!');
      },
    });
  }

  // ── Category mapping ────────────────────────────────────────

  var CATEGORY_PREFIXES = [
    { prefix: 'amsi_',      label: 'AMSI Bypass' },
    { prefix: 'av_',        label: 'AV Bypass' },
    { prefix: 'adcs_',      label: 'AD CS aanvallen' },
    { prefix: 'ad_',        label: 'Active Directory' },
    { prefix: 'applocker_', label: 'AppLocker Bypass' },
    { prefix: 'cred_',      label: 'Credential dumping' },
    { prefix: 'enum_',      label: 'Enumeratie' },
    { prefix: 'exploit_',   label: 'Exploits' },
    { prefix: 'get_',       label: 'Tool downloads' },
    { prefix: 'inject_',    label: 'Process Injection' },
    { prefix: 'kerb_',      label: 'Kerberos' },
    { prefix: 'lateral_',   label: 'Laterale beweging (Windows)' },
    { prefix: 'linux_',     label: 'Linux post-exploitatie' },
    { prefix: 'mssql_',     label: 'MSSQL aanvallen' },
    { prefix: 'net_',       label: 'Netwerk evasie' },
    { prefix: 'passwd_',    label: 'Wachtwoord aanvallen' },
    { prefix: 'persist_',   label: 'Persistentie' },
    { prefix: 'privesc_',   label: 'Privilege escalatie' },
    { prefix: 'ps_cradle_', label: 'PowerShell Cradles' },
    { prefix: 'ps',         label: 'PowerShell Payloads' },
    { prefix: 'msf',        label: 'Metasploit' },
    { prefix: 'proof_',     label: 'Bewijs / Flags' },
    { prefix: 'recon_',     label: 'Verkenning' },
    { prefix: 'shell_',     label: 'Reverse shells' },
    { prefix: 'tunnel_',    label: 'Tunneling / pivoting' },
    { prefix: 'web_ssti_',  label: 'Web: SSTI' },
    { prefix: 'web_sqli_',  label: 'Web: SQL Injection' },
    { prefix: 'web_cmdi_',  label: 'Web: Command Injection' },
    { prefix: 'web_xss_',   label: 'Web: XSS' },
    { prefix: 'web_xxe_',   label: 'Web: XXE' },
    { prefix: 'web_ssrf_',  label: 'Web: SSRF' },
    { prefix: 'web_lfi_',   label: 'Web: LFI / Traversal' },
    { prefix: 'web_deser_', label: 'Web: Deserialisatie' },
    { prefix: 'web_',       label: 'Web: Overig' }
  ];

  function getCategoryKey(name) {
    for (var i = 0; i < CATEGORY_PREFIXES.length; i++) {
      if (name.indexOf(CATEGORY_PREFIXES[i].prefix) === 0) return CATEGORY_PREFIXES[i].prefix;
    }
    return '_other';
  }

  function getCategoryLabel(key) {
    for (var i = 0; i < CATEGORY_PREFIXES.length; i++) {
      if (CATEGORY_PREFIXES[i].prefix === key) return CATEGORY_PREFIXES[i].label;
    }
    return 'Overig';
  }

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
    copyBtn.textContent = 'kopieer';
    copyBtn.setAttribute('type', 'button');
    (function (content, b) {
      b.addEventListener('click', function () { copyToClipboard(applyReplacements(content), b); });
    })(cmd.content, copyBtn);

    var injectBtn = document.createElement('button');
    injectBtn.className = 'btn-copy btn-inject';
    injectBtn.textContent = 'Inject';
    injectBtn.setAttribute('type', 'button');
    (function (content, b, name) {
      b.addEventListener('click', function () { injectCommand(content, b, name); });
    })(cmd.content, injectBtn, cmd.name);

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

    var filtered = [];
    for (var i = 0; i < allCommands.length; i++) {
      var cmd = allCommands[i];
      if (term && cmd.name.toLowerCase().indexOf(term) === -1 && cmd.content.toLowerCase().indexOf(term) === -1) continue;
      filtered.push(cmd);
    }

    if (filtered.length === 0) {
      cmdList.innerHTML = '<p style="color:var(--muted)">Geen commando\'s gevonden' + (term ? ' voor "' + escapeHtml(term) + '"' : '') + '.</p>';
      return;
    }

    var groups = {};
    var groupOrder = [];
    for (var i = 0; i < filtered.length; i++) {
      var key = getCategoryKey(filtered[i].name);
      if (!groups[key]) { groups[key] = []; groupOrder.push(key); }
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
    fetch('/api/commands')
      .then(function (r) { return r.json(); })
      .then(function (data) {
        allCommands = data.commands || [];
        renderLibraryCommands('');
      })
      .catch(function () {});
  }

  var cmdDebounce = null;
  function rerenderLibrary() {
    clearTimeout(cmdDebounce);
    cmdDebounce = setTimeout(function () {
      renderLibraryCommands(cmdFilter ? cmdFilter.value : '');
    }, 150);
  }

  if (cmdFilter) cmdFilter.addEventListener('input', rerenderLibrary);
  if (replaceFindInput) replaceFindInput.addEventListener('input', rerenderLibrary);
  if (replaceWithInput) replaceWithInput.addEventListener('input', rerenderLibrary);
  if (replaceHttpsCheckbox) replaceHttpsCheckbox.addEventListener('change', rerenderLibrary);

  // ── Sidebar toggle ──────────────────────────────────────────

  function setSidebarOpen(open) {
    if (!cmdSidebar || !workspace) return;
    if (open) {
      cmdSidebar.classList.add('open');
      workspace.classList.add('sidebar-open');
      if (toggleSidebarBtn) toggleSidebarBtn.innerHTML = 'Commando\'s &#9664;';
    } else {
      cmdSidebar.classList.remove('open');
      workspace.classList.remove('sidebar-open');
      if (toggleSidebarBtn) toggleSidebarBtn.innerHTML = 'Commando\'s &#9654;';
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

  // ── Init ────────────────────────────────────────────────────
  fetchAgents();
  agentPollTimer = setInterval(fetchAgents, 5000);
  loadLibraryCommands();
})();
