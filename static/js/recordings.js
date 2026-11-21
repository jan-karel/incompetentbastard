(function () {
  'use strict';

  var listEl = document.getElementById('rec-list');
  var playerEl = document.getElementById('player-container');
  var titleEl = document.getElementById('player-title');
  var playerCard = document.getElementById('player-card');
  var refreshBtn = document.getElementById('refresh-btn');
  var fullscreenBtn = document.getElementById('fullscreen-btn');
  var filterInput = document.getElementById('rec-filter');
  var opdrachtSel = document.getElementById('rec-opdracht');
  var filtersEl = document.getElementById('rec-filters');
  var currentFile = playerEl.dataset.initialFile || null;
  var isFullscreen = false;
  var allRecordings = [];
  var activeFilter = 'alle';

  var FILTERS = [
    ['alle', 'Alle'],
    ['opdracht', 'Deze opdracht'],
    ['agents', 'Agents'],
    ['ongekoppeld', 'Niet gekoppeld']
  ];

  // ── Formatters ────────────────────────────────────────────
  function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
  }

  function formatDate(ts) {
    var d = new Date(ts * 1000);
    return d.toLocaleDateString('nl-NL') + ' ' + d.toLocaleTimeString('nl-NL', { hour: '2-digit', minute: '2-digit' });
  }

  function formatDur(sec) {
    if (sec === null || sec === undefined) return '';
    sec = Math.round(sec);
    var m = Math.floor(sec / 60), s = sec % 60;
    if (m >= 60) { var h = Math.floor(m / 60); return h + 'u ' + (m % 60) + 'm'; }
    return m ? (m + 'm ' + s + 's') : (s + 's');
  }

  function bucketOf(ts) {
    var d = new Date(ts * 1000), now = new Date();
    var startToday = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
    var t = d.getTime();
    if (t >= startToday) return 'Vandaag';
    if (t >= startToday - 86400000) return 'Gisteren';
    if (t >= startToday - 6 * 86400000) return 'Deze week';
    if (d.getFullYear() === now.getFullYear() && d.getMonth() === now.getMonth()) return 'Deze maand';
    return 'Ouder';
  }

  // ── Vastleggen (herbruikbare dialoog) ─────────────────────
  function maakCaptureKnop(name) {
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'btn btn-sm rec-cap-btn';
    btn.textContent = 'Vastleggen…';
    btn.title = 'Kies scope, titel en bestemming, met voorbeeld';
    btn.addEventListener('click', function (e) {
      e.stopPropagation();
      if (!window.CaptureDialog) { alert('Capture-dialoog niet geladen'); return; }
      window.CaptureDialog.open({
        title: name,
        previewUrl: '/api/recordings/' + encodeURIComponent(name) + '/preview',
        submitUrl: '/api/recordings/' + encodeURIComponent(name) + '/to-note',
        onDone: loadRecordings
      });
    });
    return btn;
  }

  // ── Opdracht-kiezer ───────────────────────────────────────
  function loadOpdrachten() {
    if (!opdrachtSel) return;
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/api/opdrachten/active');
    xhr.onload = function () {
      if (xhr.status !== 200) return;
      var d;
      try { d = JSON.parse(xhr.responseText); } catch (e) { return; }
      var ops = d.opdrachten || [];
      opdrachtSel.innerHTML = '';
      ops.forEach(function (o) {
        var opt = document.createElement('option');
        opt.value = o.id;
        opt.textContent = o.naam + (o.klant ? ' · ' + o.klant : '');
        if (o.id === d.active_id) opt.selected = true;
        opdrachtSel.appendChild(opt);
      });
    };
    xhr.send();
  }

  // ── Filters ───────────────────────────────────────────────
  function telFilter(key) {
    var oid = opdrachtSel ? parseInt(opdrachtSel.value, 10) : NaN;
    var n = 0;
    for (var i = 0; i < allRecordings.length; i++) {
      var r = allRecordings[i];
      if (key === 'alle') { n++; }
      else if (key === 'agents') { if (r.agent) n++; }
      else if (key === 'ongekoppeld') { if (!(r.opdrachten && r.opdrachten.length)) n++; }
      else if (key === 'opdracht') {
        if ((r.opdrachten || []).some(function (o) { return o.id === oid; })) n++;
      }
    }
    return n;
  }

  function buildFilters() {
    if (!filtersEl) return;
    filtersEl.innerHTML = '';
    FILTERS.forEach(function (f) {
      var chip = document.createElement('button');
      chip.type = 'button';
      chip.className = 'rec-fchip' + (activeFilter === f[0] ? ' active' : '');
      chip.dataset.filter = f[0];
      var cnt = telFilter(f[0]);
      chip.innerHTML = f[1] + ' <span class="rec-fcount">' + cnt + '</span>';
      chip.addEventListener('click', function () {
        activeFilter = f[0];
        buildFilters();
        render();
      });
      filtersEl.appendChild(chip);
    });
  }

  function passFilter(rec, term) {
    if (term && rec.name.toLowerCase().indexOf(term) === -1) return false;
    if (activeFilter === 'agents') return !!rec.agent;
    if (activeFilter === 'ongekoppeld') return !(rec.opdrachten && rec.opdrachten.length);
    if (activeFilter === 'opdracht') {
      var oid = parseInt(opdrachtSel.value, 10);
      return (rec.opdrachten || []).some(function (o) { return o.id === oid; });
    }
    return true;
  }

  // ── Rij ───────────────────────────────────────────────────
  function maakRij(rec) {
    var item = document.createElement('div');
    item.className = 'rec-item' + (rec.name === currentFile ? ' active' : '');

    var ico = document.createElement('span');
    ico.className = 'rec-ico ' + (rec.agent ? 'agent' : 'screen');
    ico.textContent = rec.agent ? '⬢' : '▸';
    ico.title = rec.agent ? 'Agent-opname' : 'Screen-sessie';

    var info = document.createElement('div');
    info.className = 'rec-info';

    var nameEl = document.createElement('span');
    nameEl.className = 'rec-name';
    nameEl.textContent = rec.name;
    info.appendChild(nameEl);

    var sub = document.createElement('span');
    sub.className = 'rec-sub';
    var metaTxt = formatDate(rec.mtime);
    if (rec.duration) metaTxt += '  ·  ⏱ ' + formatDur(rec.duration);
    metaTxt += '  ·  ' + formatSize(rec.size);
    var metaSpan = document.createElement('span');
    metaSpan.className = 'rec-meta';
    metaSpan.textContent = metaTxt;
    sub.appendChild(metaSpan);
    (rec.opdrachten || []).forEach(function (o) {
      var chip = document.createElement('span');
      chip.className = 'rec-chip';
      chip.textContent = '→ ' + o.naam;
      chip.title = 'Gekoppeld aan opdracht: ' + o.naam;
      sub.appendChild(chip);
    });
    info.appendChild(sub);

    var actions = document.createElement('div');
    actions.className = 'rec-actions';
    var playBtn = document.createElement('button');
    playBtn.className = 'btn btn-sm rec-play';
    playBtn.type = 'button';
    playBtn.textContent = '▶ Afspelen';
    var capMenu = maakCaptureKnop(rec.name);

    (function (name) {
      item.addEventListener('click', function () { playRecording(name); });
      playBtn.addEventListener('click', function (e) { e.stopPropagation(); playRecording(name); });
    })(rec.name);

    actions.appendChild(playBtn);
    actions.appendChild(capMenu);

    item.appendChild(ico);
    item.appendChild(info);
    item.appendChild(actions);
    return item;
  }

  function render() {
    var term = (filterInput ? filterInput.value : '').toLowerCase();
    listEl.innerHTML = '';
    var huidigeBucket = null, count = 0;

    for (var i = 0; i < allRecordings.length; i++) {
      var rec = allRecordings[i];
      if (!passFilter(rec, term)) continue;
      count++;
      var bucket = bucketOf(rec.mtime);
      if (bucket !== huidigeBucket) {
        huidigeBucket = bucket;
        var h = document.createElement('div');
        h.className = 'rec-group';
        h.textContent = bucket;
        listEl.appendChild(h);
      }
      listEl.appendChild(maakRij(rec));
    }

    if (count === 0) {
      var p = document.createElement('p');
      p.className = 'rec-empty';
      p.textContent = term
        ? 'Geen opnames gevonden voor "' + term + '".'
        : (allRecordings.length ? 'Geen opnames in deze weergave.' : 'Nog geen opnames in meuk/logs/.');
      listEl.appendChild(p);
    }
  }

  function loadRecordings() {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/api/recordings');
    xhr.onload = function () {
      if (xhr.status !== 200) {
        listEl.innerHTML = '<p class="rec-empty">Kan opnames niet laden.</p>';
        return;
      }
      var data = JSON.parse(xhr.responseText);
      allRecordings = data.recordings || [];
      buildFilters();
      render();
      if (currentFile) playRecording(currentFile);
    };
    xhr.send();
  }

  // ── Speler ────────────────────────────────────────────────
  function playRecording(name, fitMode) {
    currentFile = name;
    titleEl.textContent = 'Speler — ' + name;
    playerEl.innerHTML = '';
    fullscreenBtn.style.display = '';

    var items = listEl.querySelectorAll('.rec-item');
    for (var i = 0; i < items.length; i++) {
      var n = items[i].querySelector('.rec-name');
      items[i].classList.toggle('active', !!(n && n.textContent === name));
    }

    var div = document.createElement('div');
    div.id = 'player-' + Date.now();
    playerEl.appendChild(div);

    AsciinemaPlayer.create(
      '/api/recordings/' + encodeURIComponent(name),
      div,
      {
        cols: 120,
        rows: 30,
        autoPlay: true,
        fit: fitMode || 'width',
        theme: 'monokai',
        terminalFontFamily: 'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace',
        terminalFontSize: '13px'
      }
    );

    if (!isFullscreen) {
      playerEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }

  function toggleFullscreen() {
    isFullscreen = !isFullscreen;
    if (isFullscreen) {
      playerCard.classList.add('fullscreen');
      fullscreenBtn.textContent = 'Sluiten';
      document.body.style.overflow = 'hidden';
    } else {
      playerCard.classList.remove('fullscreen');
      fullscreenBtn.textContent = 'Volledig scherm';
      document.body.style.overflow = '';
    }
    if (currentFile) playRecording(currentFile, isFullscreen ? 'both' : 'width');
  }

  // ── Listeners ─────────────────────────────────────────────
  fullscreenBtn.addEventListener('click', toggleFullscreen);
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && isFullscreen) toggleFullscreen();
  });
  if (refreshBtn) refreshBtn.addEventListener('click', loadRecordings);
  if (filterInput) {
    var debounce = null;
    filterInput.addEventListener('input', function () {
      clearTimeout(debounce);
      debounce = setTimeout(render, 150);
    });
  }
  if (opdrachtSel) opdrachtSel.addEventListener('change', function () {
    buildFilters();                       // 'Deze opdracht'-telling verandert
    if (activeFilter === 'opdracht') render();
  });

  loadOpdrachten();
  loadRecordings();
})();
