/* Global search — dropdown resultaten vanuit de header searchBox */
(function () {
  'use strict';

  var searchBox = document.getElementById('searchBox');
  var searchWrap = document.getElementById('searchWrap');
  var searchClear = document.getElementById('searchClear');
  if (!searchBox || !searchWrap) return;

  var dropdown = document.createElement('div');
  dropdown.className = 'search-dropdown';
  dropdown.setAttribute('role', 'listbox');
  dropdown.setAttribute('aria-label', 'Zoekresultaten');
  searchWrap.appendChild(dropdown);

  var debounce = null;
  var activeIdx = -1;
  var currentItems = [];
  var currentXhr = null;

  var catLabels = {
    pages: 'Pagina\'s',
    findings: 'Findings',
    notes: 'Notes',
    commands: 'Commands',
    recordings: 'Recordings',
    loot: 'Loot',
    outputs: 'Outputs'
  };

  var catOrder = ['pages', 'findings', 'notes', 'commands', 'recordings', 'loot', 'outputs'];

  function escapeHtml(s) {
    var d = document.createElement('div');
    d.appendChild(document.createTextNode(s));
    return d.innerHTML;
  }

  function show() { dropdown.classList.add('open'); }
  function hide() { dropdown.classList.remove('open'); activeIdx = -1; }

  function renderResults(results) {
    dropdown.innerHTML = '';
    currentItems = [];
    activeIdx = -1;

    if (!results.length) {
      dropdown.innerHTML = '<div class="search-empty">Geen resultaten</div>';
      show();
      return;
    }

    // Groepeer per categorie
    var grouped = {};
    for (var i = 0; i < results.length; i++) {
      var r = results[i];
      if (!grouped[r.cat]) grouped[r.cat] = [];
      grouped[r.cat].push(r);
    }

    for (var c = 0; c < catOrder.length; c++) {
      var cat = catOrder[c];
      if (!grouped[cat]) continue;

      var label = document.createElement('div');
      label.className = 'search-cat';
      label.textContent = catLabels[cat] || cat;
      dropdown.appendChild(label);

      for (var j = 0; j < grouped[cat].length; j++) {
        var item = grouped[cat][j];
        var el = document.createElement('a');
        el.className = 'search-item';
        el.href = item.url;
        el.setAttribute('role', 'option');
        el.innerHTML =
          '<span class="si-title">' + escapeHtml(item.title) + '</span>' +
          (item.sub ? '<span class="si-sub">' + escapeHtml(item.sub) + '</span>' : '');

        (function (url) {
          el.addEventListener('mousedown', function (e) {
            e.preventDefault();
            window.location.href = url;
          });
        })(item.url);

        dropdown.appendChild(el);
        currentItems.push(el);
      }
    }

    show();
  }

  function doSearch() {
    var q = searchBox.value.trim();
    if (q.length < 2) {
      hide();
      return;
    }

    if (currentXhr) currentXhr.abort();

    var xhr = new XMLHttpRequest();
    currentXhr = xhr;
    xhr.open('GET', '/api/search?q=' + encodeURIComponent(q));
    xhr.onload = function () {
      currentXhr = null;
      if (xhr.status === 200) {
        try {
          var data = JSON.parse(xhr.responseText);
          renderResults(data.results || []);
        } catch (e) {
          hide();
        }
      }
    };
    xhr.onerror = function () { currentXhr = null; };
    xhr.send();
  }

  function setActive(idx) {
    for (var i = 0; i < currentItems.length; i++) {
      currentItems[i].classList.toggle('active', i === idx);
    }
    if (idx >= 0 && idx < currentItems.length) {
      currentItems[idx].scrollIntoView({ block: 'nearest' });
    }
    activeIdx = idx;
  }

  searchBox.addEventListener('input', function () {
    clearTimeout(debounce);
    debounce = setTimeout(doSearch, 200);
  });

  searchBox.addEventListener('focus', function () {
    if (searchBox.value.trim().length >= 2 && currentItems.length) show();
  });

  searchBox.addEventListener('keydown', function (e) {
    if (!dropdown.classList.contains('open')) return;

    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActive(Math.min(activeIdx + 1, currentItems.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActive(Math.max(activeIdx - 1, 0));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (activeIdx >= 0 && activeIdx < currentItems.length) {
        window.location.href = currentItems[activeIdx].href;
      }
    } else if (e.key === 'Escape') {
      hide();
      searchBox.blur();
    }
  });

  document.addEventListener('click', function (e) {
    if (!searchWrap.contains(e.target)) hide();
  });

  if (searchClear) {
    searchClear.addEventListener('click', function () {
      hide();
    });
  }

  // Keyboard shortcut: Ctrl+K of / om search te focussen
  document.addEventListener('keydown', function (e) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
      e.preventDefault();
      searchBox.focus();
      searchBox.select();
    }
    if (e.key === '/' && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA' && !document.activeElement.isContentEditable) {
      e.preventDefault();
      searchBox.focus();
      searchBox.select();
    }
  });
})();
