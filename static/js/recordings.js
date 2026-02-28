(function () {
  'use strict';

  var listEl = document.getElementById('rec-list');
  var playerEl = document.getElementById('player-container');
  var titleEl = document.getElementById('player-title');
  var playerCard = document.getElementById('player-card');
  var refreshBtn = document.getElementById('refresh-btn');
  var fullscreenBtn = document.getElementById('fullscreen-btn');
  var filterInput = document.getElementById('rec-filter');
  var currentFile = playerEl.dataset.initialFile || null;
  var isFullscreen = false;
  var allRecordings = [];

  function formatSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
  }

  function formatDate(ts) {
    var d = new Date(ts * 1000);
    return d.toLocaleDateString('nl-NL') + ' ' + d.toLocaleTimeString('nl-NL', { hour: '2-digit', minute: '2-digit' });
  }

  function renderRecordings(filter) {
    var term = (filter || '').toLowerCase();
    listEl.innerHTML = '';
    var count = 0;

    for (var i = 0; i < allRecordings.length; i++) {
      var rec = allRecordings[i];
      if (term && rec.name.toLowerCase().indexOf(term) === -1) continue;
      count++;

      var item = document.createElement('div');
      item.className = 'rec-item' + (rec.name === currentFile ? ' active' : '');

      var left = document.createElement('span');
      left.className = 'rec-name';
      left.textContent = rec.name;

      var right = document.createElement('span');
      right.className = 'rec-meta';
      right.textContent = formatSize(rec.size) + '  \u00b7  ' + formatDate(rec.mtime);

      var btn = document.createElement('button');
      btn.className = 'btn';
      btn.textContent = 'Afspelen';
      btn.setAttribute('type', 'button');

      (function (name) {
        item.addEventListener('click', function () { playRecording(name); });
      })(rec.name);

      item.appendChild(left);
      item.appendChild(right);
      item.appendChild(btn);
      listEl.appendChild(item);
    }

    if (count === 0) {
      listEl.innerHTML = '<p style="color:var(--muted)">Geen recordings gevonden' + (term ? ' voor "' + term + '"' : ' in meuk/logs/') + '.</p>';
    }
  }

  function loadRecordings() {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/api/recordings');
    xhr.onload = function () {
      if (xhr.status !== 200) {
        listEl.innerHTML = '<p style="color:var(--muted)">Kan recordings niet laden.</p>';
        return;
      }
      var data = JSON.parse(xhr.responseText);
      allRecordings = data.recordings || [];

      renderRecordings(filterInput ? filterInput.value : '');

      if (currentFile) {
        playRecording(currentFile);
      }
    };
    xhr.send();
  }

  function playRecording(name, fitMode) {
    currentFile = name;
    titleEl.textContent = 'Player \u2014 ' + name;
    playerEl.innerHTML = '';
    fullscreenBtn.style.display = '';

    var items = listEl.querySelectorAll('.rec-item');
    for (var i = 0; i < items.length; i++) {
      var n = items[i].querySelector('.rec-name');
      if (n && n.textContent === name) {
        items[i].classList.add('active');
      } else {
        items[i].classList.remove('active');
      }
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
      fullscreenBtn.textContent = 'Fullscreen';
      document.body.style.overflow = '';
    }
    if (currentFile) {
      playRecording(currentFile, isFullscreen ? 'both' : 'width');
    }
  }

  fullscreenBtn.addEventListener('click', toggleFullscreen);

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && isFullscreen) {
      toggleFullscreen();
    }
  });

  if (refreshBtn) {
    refreshBtn.addEventListener('click', loadRecordings);
  }

  if (filterInput) {
    var debounce = null;
    filterInput.addEventListener('input', function () {
      clearTimeout(debounce);
      debounce = setTimeout(function () {
        renderRecordings(filterInput.value);
      }, 150);
    });
  }

  loadRecordings();
})();
