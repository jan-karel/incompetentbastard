// Copyright (C) 2021 Jan-Karel Visser info@jan-karel.nl
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Scripts aftrappen
 */

(function () {
  'use strict';

  var currentRunId = null;
  var pollTimer = null;
  var taskDefs = {};

  var statusEl = document.getElementById('status');
  var outputEl = document.getElementById('output');
  var groupSelect = document.getElementById('task-group-select');
  var taskSelect = document.getElementById('task-select');
  var runBtn = document.getElementById('run-btn');
  var descEl = document.getElementById('task-desc');
  var argsEl = document.getElementById('task-args');

  if (!statusEl || !outputEl || !taskSelect || !runBtn) return;

  function setStatus(text, cls) {
    statusEl.textContent = text;
    statusEl.className = 'task-status' + (cls ? ' ' + cls : '');
  }

  function escapeHtml(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function ansiToHtml(text) {
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
    outputEl.innerHTML = ansiToHtml((lines || []).join('\n'));
    outputEl.scrollTop = outputEl.scrollHeight;
  }

  // Filter task options op basis van geselecteerde groep
  function filterTasks() {
    var group = groupSelect.value;
    var options = taskSelect.options;
    var firstVisible = null;
    for (var i = 0; i < options.length; i++) {
      var opt = options[i];
      var show = opt.getAttribute('data-group') === group;
      opt.style.display = show ? '' : 'none';
      opt.disabled = !show;
      if (show && firstVisible === null) firstVisible = i;
    }
    if (firstVisible !== null) {
      taskSelect.selectedIndex = firstVisible;
    }
    updateTaskUI();
  }

  // Toon beschrijving en argument velden voor geselecteerde taak
  function updateTaskUI() {
    var taskName = taskSelect.value;
    var def = taskDefs[taskName];

    // Beschrijving
    if (def && def.desc) {
      descEl.textContent = def.desc;
      descEl.style.display = 'block';
    } else {
      descEl.style.display = 'none';
    }

    // Argument velden
    argsEl.innerHTML = '';
    if (!def || !def.args || !def.args.length) return;

    for (var i = 0; i < def.args.length; i++) {
      var arg = def.args[i];

      var wrapper = document.createElement('div');
      wrapper.className = 'arg-field';

      var label = document.createElement('label');
      label.setAttribute('for', 'arg-' + arg.name);
      label.textContent = arg.label;
      if (arg.required) {
        var req = document.createElement('span');
        req.className = 'required';
        req.textContent = ' *';
        label.appendChild(req);
      }

      var input = document.createElement('input');
      input.type = arg.type === 'password' ? 'password' : 'text';
      input.id = 'arg-' + arg.name;
      input.name = arg.name;
      input.className = 'form-control';
      input.placeholder = arg.placeholder || '';
      if (arg.required) input.required = true;
      if (arg.type === 'password') input.autocomplete = 'off';

      wrapper.appendChild(label);
      wrapper.appendChild(input);
      argsEl.appendChild(wrapper);
    }
  }

  // Haal task definities op van de API
  function loadTaskDefs() {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/api/tasks');
    xhr.onload = function () {
      if (xhr.status === 200) {
        var data = JSON.parse(xhr.responseText);
        taskDefs = data.tasks || {};
        filterTasks();
      }
    };
    xhr.send();
  }

  function pollRun() {
    if (!currentRunId) return;

    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/api/tasks/runs/' + currentRunId);
    xhr.onload = function () {
      if (xhr.status !== 200) {
        setStatus('Status: fout bij ophalen', 'fail');
        runBtn.disabled = false;
        return;
      }

      var data = JSON.parse(xhr.responseText);
      setOutput(data.output || []);

      if (data.status === 'running') {
        setStatus('Status: bezig...', '');
        pollTimer = setTimeout(pollRun, 1000);
      } else if (data.status === 'success') {
        setStatus('Status: gereed (rc=0)', 'ok');
        runBtn.disabled = false;
      } else {
        setStatus('Status: mislukt (rc=' + data.return_code + ')', 'fail');
        runBtn.disabled = false;
      }
    };
    xhr.onerror = function () {
      setStatus('Status: verbindingsfout', 'fail');
      runBtn.disabled = false;
    };
    xhr.send();
  }

  function startTask() {
    if (pollTimer) {
      clearTimeout(pollTimer);
      pollTimer = null;
    }

    var taskName = taskSelect.value;
    var def = taskDefs[taskName];

    // Verzamel argumenten
    var args = {};
    if (def && def.args) {
      for (var i = 0; i < def.args.length; i++) {
        var arg = def.args[i];
        var input = document.getElementById('arg-' + arg.name);
        if (input) {
          var val = input.value.trim();
          if (arg.required && !val) {
            setStatus('Status: ' + arg.label + ' is verplicht', 'fail');
            input.focus();
            return;
          }
          if (val) args[arg.name] = val;
        }
      }
    }

    setStatus('Status: starten...', '');
    setOutput([]);
    runBtn.disabled = true;

    var body = JSON.stringify({ task: taskName, args: args });
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/tasks/run');
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.onload = function () {
      var data;
      try {
        data = JSON.parse(xhr.responseText);
      } catch (e) {
        setStatus('Status: ongeldig antwoord', 'fail');
        runBtn.disabled = false;
        return;
      }

      if (xhr.status !== 200) {
        setStatus('Status: ' + (data.error || 'fout'), 'fail');
        runBtn.disabled = false;
        return;
      }

      currentRunId = data.run_id;
      setStatus('Status: run gestart', '');
      pollRun();
    };
    xhr.onerror = function () {
      setStatus('Status: verbindingsfout', 'fail');
      runBtn.disabled = false;
    };
    xhr.send(body);
  }

  groupSelect.addEventListener('change', filterTasks);
  taskSelect.addEventListener('change', updateTaskUI);
  runBtn.addEventListener('click', startTask);

  loadTaskDefs();
})();
