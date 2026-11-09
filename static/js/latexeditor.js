// Copyright (C) 2021 Jan-Karel Visser info@jan-karel.nl
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * LaTeX Editor Toolbar
 * A clean, CKEditor-style toolbar for inserting LaTeX snippets, images, en other content.
 * Supports multiple modes: document, finding, note
 */
(function() {
  'use strict';

  // Toolbar configurations for different modes
  var TOOLBAR_CONFIGS = {
    // Full document editor (doc_edit.html)
    document: {
      groups: [
        {
          id: 'content',
          label: 'Content',
          items: [
            { id: 'snippet', icon: '{}', label: 'Snippet', type: 'dropdown', dataAttr: 'snippetsUrl' },
            { id: 'note', icon: '\u{1F4DD}', label: 'Notitie', type: 'dropdown', dataAttr: 'notesUrl' },
          ]
        },
        {
          id: 'output',
          label: 'Output',
          items: [
            { id: 'recon', icon: '\u{1F50D}', label: 'Recon', type: 'dropdown', dataAttr: 'reconOutputsUrl' },
            { id: 'scan', icon: '\u{1F4CA}', label: 'Scan', type: 'dropdown', dataAttr: 'scanOutputsUrl' },
          ]
        },
        {
          id: 'media',
          label: 'Media',
          items: [
            { id: 'image', icon: '\u{1F5BC}', label: 'Afbeelding', type: 'dropdown', dataAttr: 'assetsUrl', hasCaption: true },
            { id: 'projectImage', icon: '\u{1F4C1}', label: 'Project afb.', type: 'dropdown', dataAttr: 'projectImagesUrl', hasCaption: true },
          ]
        },
        {
          id: 'extras',
          label: 'Extra',
          items: [
            { id: 'glossary', icon: '\u{1F4D6}', label: 'Glossary', type: 'button' },
            { id: 'gls', icon: '\u{1F4D6}', label: 'Gls', type: 'dropdown', dataAttr: 'glossaryTermsUrl', tooltip: '\\gls{term}' },
            { id: 'glspl', icon: '\u{1F4D6}+', label: 'Gls plural', type: 'dropdown', dataAttr: 'glossaryTermsUrl', tooltip: '\\glspl{term}' },
            { id: 'bibliography', icon: '\u{1F4DA}', label: 'Bibliografie', type: 'button' },
          ]
        }
      ]
    },

    // Finding evidence editor
    finding: {
      groups: [
        {
          id: 'code',
          label: 'Code',
          items: [
            { id: 'lstlisting', icon: '&lt;/&gt;', label: 'Code', type: 'button', tooltip: 'Code block invoegen' },
            { id: 'lstinline', icon: '`c`', label: 'Inline', type: 'button', tooltip: 'Inline code' },
          ]
        },
        {
          id: 'formatting',
          label: 'Opmaak',
          items: [
            { id: 'haakjes', icon: '[ ]', label: 'Haakjes', type: 'button', tooltip: '\\haakjes{}' },
            { id: 'opdracht', icon: '\u{1F4CB}', label: 'Opdracht', type: 'button', tooltip: '\\opdracht{}' },
            { id: 'lakken', icon: '\u{2588}', label: 'Lakken', type: 'button', tooltip: '\\lakken{} - tekst censureren' },
            { id: 'itemize', icon: '\u{2022}', label: 'Lijst', type: 'button', tooltip: 'Bullet list' },
            { id: 'enumerate', icon: '1.', label: 'Genummerd', type: 'button', tooltip: 'Genummerde lijst' },
            { id: 'table', icon: '\u{229E}', label: 'Tabel', type: 'button', tooltip: 'Tabel invoegen' },
          ]
        },
        {
          id: 'references',
          label: 'Referenties',
          items: [
            { id: 'snippet', icon: '{}', label: 'Snippet', type: 'dropdown', dataAttr: 'snippetsUrl' },
            { id: 'gls', icon: '\u{1F4D6}', label: 'Glossary', type: 'dropdown', dataAttr: 'glossaryTermsUrl', tooltip: '\\gls{term}' },
            { id: 'glspl', icon: '\u{1F4D6}+', label: 'Gls plural', type: 'dropdown', dataAttr: 'glossaryTermsUrl', tooltip: '\\glspl{term} (meervoud)' },
          ]
        },
        {
          id: 'media',
          label: 'Media',
          items: [
            { id: 'projectImage', icon: '\u{1F5BC}', label: 'Afbeelding', type: 'dropdown', dataAttr: 'projectImagesUrl', hasCaption: true },
          ]
        }
      ]
    },

    // Project note editor
    note: {
      groups: [
        {
          id: 'code',
          label: 'Code',
          items: [
            { id: 'lstlisting', icon: '&lt;/&gt;', label: 'Code', type: 'button', tooltip: 'Code block invoegen' },
            { id: 'lstinline', icon: '`c`', label: 'Inline', type: 'button', tooltip: 'Inline code' },
          ]
        },
        {
          id: 'formatting',
          label: 'Opmaak',
          items: [
            { id: 'haakjes', icon: '[ ]', label: 'Haakjes', type: 'button', tooltip: '\\haakjes{}' },
            { id: 'opdracht', icon: '\u{1F4CB}', label: 'Opdracht', type: 'button', tooltip: '\\opdracht{}' },
            { id: 'lakken', icon: '\u{2588}', label: 'Lakken', type: 'button', tooltip: '\\lakken{} - tekst censureren' },
          ]
        },
        {
          id: 'references',
          label: 'Referenties',
          items: [
            { id: 'snippet', icon: '{}', label: 'Snippet', type: 'dropdown', dataAttr: 'snippetsUrl' },
            { id: 'gls', icon: '\u{1F4D6}', label: 'Glossary', type: 'dropdown', dataAttr: 'glossaryTermsUrl', tooltip: '\\gls{term}' },
            { id: 'glspl', icon: '\u{1F4D6}+', label: 'Gls plural', type: 'dropdown', dataAttr: 'glossaryTermsUrl', tooltip: '\\glspl{term} (meervoud)' },
          ]
        },
        {
          id: 'media',
          label: 'Media',
          items: [
            { id: 'projectImage', icon: '\u{1F5BC}', label: 'Afbeelding', type: 'dropdown', dataAttr: 'projectImagesUrl', hasCaption: true },
          ]
        },
        {
          id: 'structure',
          label: 'Structuur',
          items: [
            { id: 'section', icon: 'H1', label: 'Sectie', type: 'prompt', tooltip: '\\section{}', promptLabel: 'Sectie titel:' },
            { id: 'subsection', icon: 'H2', label: 'Subsectie', type: 'prompt', tooltip: '\\subsection{}', promptLabel: 'Subsectie titel:' },
            { id: 'itemize', icon: '\u{2022}', label: 'Lijst', type: 'button', tooltip: 'Bullet list' },
            { id: 'enumerate', icon: '1.', label: 'Genummerd', type: 'button', tooltip: 'Genummerde lijst' },
            { id: 'table', icon: '\u{229E}', label: 'Tabel', type: 'button', tooltip: 'Tabel invoegen' },
          ]
        }
      ]
    }
  };

  function LaTeXEditor(container, textareaId) {
    this.container = container;
    this.textarea = document.getElementById(textareaId || 'contentArea');
    if (!this.textarea) return;

    this.mode = container.dataset.mode || 'document';
    this.config = this._parseConfig();
    this.toolbarConfig = TOOLBAR_CONFIGS[this.mode] || TOOLBAR_CONFIGS.document;
    this.dropdownData = {};
    this.activeDropdown = null;
    this.isFullscreen = false;
    this.wrapper = null;

    this._init();
  }

  LaTeXEditor.prototype._parseConfig = function() {
    var cfg = {};
    var el = this.container;
    cfg.snippetsUrl = el.dataset.snippetsUrl || '';
    cfg.notesUrl = el.dataset.notesUrl || '';
    cfg.reconOutputsUrl = el.dataset.reconOutputsUrl || '';
    cfg.scanOutputsUrl = el.dataset.scanOutputsUrl || '';
    cfg.assetsUrl = el.dataset.assetsUrl || '';
    cfg.projectImagesUrl = el.dataset.projectImagesUrl || '';
    cfg.glossaryTermsUrl = el.dataset.glossaryTermsUrl || '';
    return cfg;
  };

  LaTeXEditor.prototype._init = function() {
    this._createWrapper();
    this._render();
    this._loadAllData();
    this._bindEvents();
    this._bindImageDrop();
    this._bindKeys();
    this._bindAutosaveAndLint();
  };

  // Lichte LaTeX-controle: ongebalanceerde accolades en niet-sluitende
  // \begin{}/\end{}-omgevingen. Geeft een korte waarschuwingstekst of ''.
  LaTeXEditor.prototype._lint = function(text) {
    var warns = [];
    // Accolades (escaped \{ \} negeren).
    var depth = 0, bad = false;
    for (var i = 0; i < text.length; i++) {
      var c = text[i];
      if (c === '\\') { i++; continue; }
      if (c === '{') depth++;
      else if (c === '}') { depth--; if (depth < 0) { bad = true; break; } }
    }
    if (bad || depth > 0) warns.push('ongebalanceerde accolades');
    // Omgevingen.
    var stack = [], re = /\\(begin|end)\s*\{([^}]*)\}/g, m, envBad = false;
    while ((m = re.exec(text))) {
      if (m[1] === 'begin') stack.push(m[2]);
      else {
        if (!stack.length || stack.pop() !== m[2]) { envBad = true; break; }
      }
    }
    if (envBad || stack.length) warns.push('niet-sluitende omgeving (\\begin/\\end)');
    return warns.length ? '⚠ ' + warns.join(' · ') : '';
  };

  LaTeXEditor.prototype._bindAutosaveAndLint = function() {
    var self = this;
    var ta = this.textarea;
    if (!ta) return;

    // Conceptsleutel. Optioneel per-record gescope't via data-draft-scope="<sel>"
    // (bv. "#rap-note-id"): de waarde van dat element wordt dynamisch in de
    // sleutel verwerkt, zodat één hergebruikt tekstvak (zoals de notitie-modal)
    // voor elke notitie een eigen concept bijhoudt.
    var base = 'ibdraft:' + location.pathname + '#' + (ta.id || this.mode);
    var scopeSel = this.container ? (this.container.dataset.draftScope || '') : '';
    function scopeVal() {
      if (!scopeSel) return '';
      var el = document.querySelector(scopeSel);
      return el ? (el.value || el.textContent || '') : '';
    }
    function draftKey() { return base + ':' + scopeVal(); }

    function store(v) { try { localStorage.setItem(draftKey(), v); } catch (e) {} }
    function load() { try { return localStorage.getItem(draftKey()); } catch (e) { return null; } }
    function clearDraft() { try { localStorage.removeItem(draftKey()); } catch (e) {} }

    var bar = document.createElement('div');
    bar.className = 'latex-status';
    var lint = document.createElement('span');
    lint.className = 'latex-lint';
    bar.appendChild(lint);
    this.wrapper.appendChild(bar);

    function runLint() {
      var w = self._lint(ta.value);
      lint.textContent = w || '✓ geen LaTeX-waarschuwingen';
      lint.classList.toggle('has-warn', !!w);
    }

    // Toon (of ververs) de herstelbalk voor het concept onder de huidige sleutel.
    function checkDraft() {
      if (self._draftBar) { self._draftBar.remove(); self._draftBar = null; }
      var draft = load();
      if (draft == null || draft === ta.value || draft.trim() === '') return;
      var restore = document.createElement('div');
      restore.className = 'latex-draft-restore';
      var msg = document.createElement('span');
      msg.textContent = '💾 Niet-opgeslagen concept gevonden.';
      var bRestore = document.createElement('button');
      bRestore.type = 'button'; bRestore.className = 'btn btn-sm'; bRestore.textContent = 'Herstellen';
      var bDiscard = document.createElement('button');
      bDiscard.type = 'button'; bDiscard.className = 'btn btn-sm'; bDiscard.textContent = 'Verwerpen';
      bRestore.addEventListener('click', function() {
        ta.value = draft;
        try { ta.dispatchEvent(new Event('input', { bubbles: true })); } catch (e) {}
        restore.remove(); self._draftBar = null;
      });
      bDiscard.addEventListener('click', function() {
        clearDraft(); restore.remove(); self._draftBar = null;
      });
      restore.appendChild(msg); restore.appendChild(bRestore); restore.appendChild(bDiscard);
      self.wrapper.insertBefore(restore, bar);
      self._draftBar = restore;
    }

    var lastScope = scopeVal();
    var t = null;
    ta.addEventListener('input', function() {
      if (t) clearTimeout(t);
      var k = draftKey();  // sleutel vastleggen bij typen (niet bij afvuren)
      t = setTimeout(function() {
        try { localStorage.setItem(k, ta.value); } catch (e) {}
        runLint();
      }, 600);
    });
    // Bij een gescope't tekstvak: wissel van record detecteren (het id wordt
    // programmatisch gezet, zonder event) zodra de gebruiker het veld focust.
    if (scopeSel) {
      ta.addEventListener('focus', function() {
        var sv = scopeVal();
        if (sv !== lastScope) { lastScope = sv; runLint(); checkDraft(); }
      });
    }
    // Concept wissen zodra het formulier daadwerkelijk wordt opgeslagen.
    var form = ta.form || (ta.closest ? ta.closest('form') : null);
    if (form) form.addEventListener('submit', clearDraft);

    runLint();
    checkDraft();
  };

  // Omwikkel de selectie (of plaats de cursor tussen prefix/suffix) met behoud
  // van de undo-stack.
  LaTeXEditor.prototype._wrap = function(prefix, suffix) {
    var sel = this._getSelectedText();
    if (sel) {
      this._insertAtCursor(prefix + sel + suffix);
    } else {
      this._insertAtCursor(prefix + suffix);
      var ta = this.textarea;
      var pos = ta.selectionStart - suffix.length;
      ta.selectionStart = ta.selectionEnd = pos;
    }
  };

  // Sneltoetsen voor opmaak + Tab-inspringen in het tekstvak.
  LaTeXEditor.prototype._bindKeys = function() {
    var self = this;
    var ta = this.textarea;
    if (!ta) return;

    ta.addEventListener('keydown', function(e) {
      var mod = e.ctrlKey || e.metaKey;

      // Tab / Shift+Tab: inspringen i.p.v. focus verliezen.
      if (e.key === 'Tab' && !e.altKey && !e.ctrlKey && !e.metaKey) {
        e.preventDefault();
        var start = ta.selectionStart, end = ta.selectionEnd;
        var val = ta.value;
        var lineStart = val.lastIndexOf('\n', start - 1) + 1;
        var block = val.substring(lineStart, end);
        if (!e.shiftKey && start === end) {
          self._insertAtCursor('  ');
          return;
        }
        var lines = block.split('\n');
        var changed;
        if (e.shiftKey) {
          changed = lines.map(function(l) { return l.replace(/^ {1,2}/, ''); });
        } else {
          changed = lines.map(function(l) { return '  ' + l; });
        }
        var newBlock = changed.join('\n');
        ta.selectionStart = lineStart;
        ta.selectionEnd = end;
        self._insertAtCursor(newBlock);
        ta.selectionStart = lineStart;
        ta.selectionEnd = lineStart + newBlock.length;
        return;
      }

      if (!mod) return;
      var k = e.key.toLowerCase();
      if (k === 'b') { e.preventDefault(); self._wrap('\\textbf{', '}'); }
      else if (k === 'i') { e.preventDefault(); self._wrap('\\emph{', '}'); }
      else if (e.key === '`') { e.preventDefault(); self._wrap('\\texttt{', '}'); }
    });
  };

  // Plakken (Ctrl/Cmd+V) en slepen van afbeeldingen: uploadt direct naar de
  // project-afbeeldingen en voegt een \plaatje{..} op de cursor in. Zo is een
  // screenshot toevoegen aan een notitie/bevinding één handeling.
  LaTeXEditor.prototype._bindImageDrop = function() {
    var self = this;
    var ta = this.textarea;
    var url = this.config.projectImagesUrl;
    if (!ta || !url) return;

    var hint = document.createElement('div');
    hint.className = 'latex-img-hint';
    this._imgHintDefault = '📎 Plak (Ctrl/Cmd+V) of sleep een afbeelding om die direct in te voegen';
    hint.textContent = this._imgHintDefault;
    this._imgHint = hint;
    this.wrapper.appendChild(hint);

    function csrf() {
      var m = document.querySelector('meta[name="csrf-token"]');
      if (m && m.getAttribute('content')) return m.getAttribute('content');
      var i = document.querySelector('input[name="csrf_token"]');
      return i ? i.value : '';
    }

    function setStatus(msg, transient) {
      if (!self._imgHint) return;
      self._imgHint.textContent = msg;
      if (transient) {
        setTimeout(function() {
          if (self._imgHint) self._imgHint.textContent = self._imgHintDefault;
        }, 3000);
      }
    }

    function uploadAndInsert(file) {
      if (!file || (file.type || '').indexOf('image') !== 0) return;
      setStatus('⏳ Uploaden…');
      var fd = new FormData();
      fd.append('file', file, file.name || 'screenshot.png');
      fetch(url, {
        method: 'POST', credentials: 'same-origin',
        headers: { 'X-CSRFToken': csrf() }, body: fd
      })
        .then(function(r) { return r.json(); })
        .then(function(d) {
          if (d && d.ok && d.name) {
            self._insertAtCursor('\\plaatje{' + d.name + '}{Caption}\n', 'Caption');
            if (self.dropdownData.projectImage) {
              self.dropdownData.projectImage.unshift({ value: d.name, label: d.name, url: d.url });
              self._renderDropdownList('projectImage');
            }
            setStatus('✔ Toegevoegd: ' + d.name, true);
          } else {
            setStatus('✖ ' + ((d && d.error) || 'upload mislukt'), true);
          }
        })
        .catch(function() { setStatus('✖ upload mislukt', true); });
    }

    ta.addEventListener('paste', function(e) {
      var items = (e.clipboardData && e.clipboardData.items) || [];
      for (var i = 0; i < items.length; i++) {
        if (items[i].kind === 'file' && (items[i].type || '').indexOf('image') === 0) {
          var file = items[i].getAsFile();
          if (file) { e.preventDefault(); uploadAndInsert(file); return; }
        }
      }
    });

    ta.addEventListener('dragover', function(e) {
      var types = (e.dataTransfer && e.dataTransfer.types) || [];
      if (Array.prototype.indexOf.call(types, 'Files') !== -1) {
        e.preventDefault();
        ta.classList.add('latex-dropping');
      }
    });
    ta.addEventListener('dragleave', function() { ta.classList.remove('latex-dropping'); });
    ta.addEventListener('drop', function(e) {
      var files = (e.dataTransfer && e.dataTransfer.files) || [];
      var imgs = Array.prototype.filter.call(files, function(f) {
        return (f.type || '').indexOf('image') === 0;
      });
      if (imgs.length) {
        e.preventDefault();
        ta.classList.remove('latex-dropping');
        imgs.forEach(uploadAndInsert);
      }
    });
  };

  LaTeXEditor.prototype._createWrapper = function() {
    this.wrapper = document.createElement('div');
    this.wrapper.className = 'latex-editor-wrapper';
    this.container.parentNode.insertBefore(this.wrapper, this.container);
    this.wrapper.appendChild(this.container);
    this.wrapper.appendChild(this.textarea);
  };

  LaTeXEditor.prototype._render = function() {
    var self = this;
    this.container.innerHTML = '';
    this.container.className = 'latex-toolbar';

    this.toolbarConfig.groups.forEach(function(group) {
      var groupEl = document.createElement('div');
      groupEl.className = 'latex-toolbar-group';

      group.items.forEach(function(item) {
        if (item.dataAttr && !self.config[item.dataAttr]) return;

        var wrapper = document.createElement('div');
        wrapper.className = 'latex-toolbar-item';

        if (item.type === 'dropdown') {
          wrapper.innerHTML = self._renderDropdownButton(item);
        } else if (item.type === 'prompt') {
          wrapper.innerHTML = self._renderPromptButton(item);
        } else {
          wrapper.innerHTML = self._renderButton(item);
        }

        groupEl.appendChild(wrapper);
      });

      if (groupEl.children.length > 0) {
        self.container.appendChild(groupEl);
      }
    });

    // Add fullscreen toggle button
    var fullscreenGroup = document.createElement('div');
    fullscreenGroup.className = 'latex-toolbar-group latex-toolbar-right';
    fullscreenGroup.innerHTML =
      '<div class="latex-toolbar-item">' +
        '<button type="button" class="latex-btn" data-preview-toggle title="PDF-voorbeeld van dit fragment">' +
          '<span class="latex-btn-icon">\u{1F441}</span>' +
          '<span class="latex-btn-label">Preview</span>' +
        '</button>' +
      '</div>' +
      '<div class="latex-toolbar-item">' +
        '<button type="button" class="latex-btn latex-btn-fullscreen" data-fullscreen-toggle title="Fullscreen (Esc om te sluiten)">' +
          '<span class="latex-btn-icon latex-icon-expand">\u26F6</span>' +
          '<span class="latex-btn-icon latex-icon-collapse hidden">\u2716</span>' +
          '<span class="latex-btn-label">Fullscreen</span>' +
        '</button>' +
      '</div>';
    this.container.appendChild(fullscreenGroup);
  };

  LaTeXEditor.prototype._renderButton = function(item) {
    return '<button type="button" class="latex-btn" data-action="' + item.id + '" title="' + (item.tooltip || item.label) + '">' +
      '<span class="latex-btn-icon">' + item.icon + '</span>' +
      '<span class="latex-btn-label">' + item.label + '</span>' +
    '</button>';
  };

  LaTeXEditor.prototype._renderPromptButton = function(item) {
    return '<button type="button" class="latex-btn" data-prompt="' + item.id + '" data-prompt-label="' + (item.promptLabel || 'Waarde:') + '" title="' + (item.tooltip || item.label) + '">' +
      '<span class="latex-btn-icon">' + item.icon + '</span>' +
      '<span class="latex-btn-label">' + item.label + '</span>' +
    '</button>';
  };

  LaTeXEditor.prototype._renderDropdownButton = function(item) {
    var html = '<div class="latex-dropdown" data-dropdown="' + item.id + '">' +
      '<button type="button" class="latex-btn latex-btn-dropdown" data-toggle="' + item.id + '" title="' + (item.tooltip || item.label) + '">' +
        '<span class="latex-btn-icon">' + item.icon + '</span>' +
        '<span class="latex-btn-label">' + item.label + '</span>' +
        '<span class="latex-btn-arrow">\u25BC</span>' +
      '</button>' +
      '<div class="latex-dropdown-menu" data-menu="' + item.id + '">' +
        '<div class="latex-dropdown-search">' +
          '<input type="text" placeholder="Zoeken..." data-search="' + item.id + '" />' +
        '</div>' +
        '<div class="latex-dropdown-list" data-list="' + item.id + '">' +
          '<div class="latex-dropdown-loading">Laden...</div>' +
        '</div>';

    if (item.hasCaption) {
      html += '<div class="latex-dropdown-footer">' +
        '<input type="text" placeholder="Caption (optioneel)" data-caption="' + item.id + '" class="latex-caption-input" />' +
      '</div>';
    }

    html += '</div></div>';
    return html;
  };

  LaTeXEditor.prototype._loadAllData = function() {
    var self = this;
    var loaders = [
      { id: 'snippet', url: this.config.snippetsUrl, transform: this._transformSnippet },
      { id: 'note', url: this.config.notesUrl, transform: this._transformNote },
      { id: 'recon', url: this.config.reconOutputsUrl, transform: this._transformOutput },
      { id: 'scan', url: this.config.scanOutputsUrl, transform: this._transformOutput },
      { id: 'image', url: this.config.assetsUrl, transform: this._transformImage },
      { id: 'projectImage', url: this.config.projectImagesUrl, transform: this._transformImage },
      { id: 'gls', url: this.config.glossaryTermsUrl, transform: this._transformGlossaryTerm },
      { id: 'glspl', url: this.config.glossaryTermsUrl, transform: this._transformGlossaryTerm },
    ];

    loaders.forEach(function(loader) {
      if (!loader.url) return;
      fetch(loader.url, { credentials: 'same-origin' })
        .then(function(resp) {
          if (!resp.ok) return;
          return resp.json();
        })
        .then(function(items) {
          if (!items) return;
          self.dropdownData[loader.id] = items.map(loader.transform);
          self._renderDropdownList(loader.id);
        })
        .catch(function(e) {
          console.warn('Failed to load ' + loader.id + ':', e);
        });
    });
  };

  LaTeXEditor.prototype._transformSnippet = function(item) {
    return { value: item.slug, label: item.slug, sublabel: item.title };
  };
  LaTeXEditor.prototype._transformNote = function(item) {
    return { value: item.slug, label: item.slug, sublabel: item.title };
  };
  LaTeXEditor.prototype._transformOutput = function(item) {
    return { value: item.name, label: item.name, sublabel: item.title || '', title: item.title };
  };
  LaTeXEditor.prototype._transformImage = function(item) {
    return { value: item.name, label: item.name, url: item.url };
  };
  LaTeXEditor.prototype._transformGlossaryTerm = function(item) {
    return { value: item.key, label: item.key, sublabel: item.name || '' };
  };

  LaTeXEditor.prototype._renderDropdownList = function(id) {
    var listEl = this.container.querySelector('[data-list="' + id + '"]');
    if (!listEl) return;

    var items = this.dropdownData[id] || [];
    if (items.length === 0) {
      listEl.innerHTML = '<div class="latex-dropdown-empty">Geen items gevonden</div>';
      return;
    }

    listEl.innerHTML = items.map(_dropdownItemHtml).join('');
  };

  LaTeXEditor.prototype._filterDropdownList = function(id, query) {
    var items = this.dropdownData[id] || [];
    var listEl = this.container.querySelector('[data-list="' + id + '"]');
    if (!listEl) return;

    var q = query.toLowerCase();
    var filtered = items.filter(function(item) {
      return item.label.toLowerCase().indexOf(q) !== -1 ||
        (item.sublabel && item.sublabel.toLowerCase().indexOf(q) !== -1);
    });

    if (filtered.length === 0) {
      listEl.innerHTML = '<div class="latex-dropdown-empty">Geen resultaten</div>';
      return;
    }

    listEl.innerHTML = filtered.map(_dropdownItemHtml).join('');
  };

  LaTeXEditor.prototype._bindEvents = function() {
    var self = this;

    this.container.addEventListener('click', function(e) {
      var toggle = e.target.closest('[data-toggle]');
      if (toggle) {
        e.preventDefault();
        self._toggleDropdown(toggle.dataset.toggle);
        return;
      }

      var item = e.target.closest('.latex-dropdown-item');
      if (item) {
        e.preventDefault();
        var dropdown = item.closest('.latex-dropdown');
        var id = dropdown ? dropdown.dataset.dropdown : null;
        self._handleItemSelect(id, item);
        return;
      }

      var actionBtn = e.target.closest('[data-action]');
      if (actionBtn) {
        e.preventDefault();
        self._handleAction(actionBtn.dataset.action);
        return;
      }

      var promptBtn = e.target.closest('[data-prompt]');
      if (promptBtn) {
        e.preventDefault();
        self._handlePrompt(promptBtn.dataset.prompt, promptBtn.dataset.promptLabel);
        return;
      }

      var fullscreenBtn = e.target.closest('[data-fullscreen-toggle]');
      if (fullscreenBtn) {
        e.preventDefault();
        self._toggleFullscreen();
        return;
      }

      var previewBtn = e.target.closest('[data-preview-toggle]');
      if (previewBtn) {
        e.preventDefault();
        self._togglePreview(previewBtn);
        return;
      }
    });

    this.container.addEventListener('input', function(e) {
      var search = e.target.closest('[data-search]');
      if (search) {
        self._filterDropdownList(search.dataset.search, search.value);
      }
    });

    document.addEventListener('click', function(e) {
      if (!e.target.closest('.latex-dropdown') && self.activeDropdown) {
        self._closeDropdown();
      }
    });

    document.addEventListener('keydown', function(e) {
      if (e.key === 'Escape') {
        if (self.isFullscreen) {
          self._toggleFullscreen();
        } else if (self.activeDropdown) {
          self._closeDropdown();
        }
      }
    });
  };

  // Fragment-preview: compileer de huidige inhoud server-side tot een PNG en
  // toon die in een paneel onder/naast de editor.
  LaTeXEditor.prototype._togglePreview = function(btn) {
    var self = this;
    if (!this._previewPanel) {
      var panel = document.createElement('div');
      panel.className = 'latex-preview-panel';
      this.wrapper.appendChild(panel);
      this._previewPanel = panel;
    }
    var panel = this._previewPanel;
    if (panel.classList.contains('is-open')) {
      panel.classList.remove('is-open');
      this.wrapper.classList.remove('has-preview');
      return;
    }
    panel.classList.add('is-open');
    this.wrapper.classList.add('has-preview');
    this._refreshPreview();
  };

  LaTeXEditor.prototype._refreshPreview = function() {
    var self = this;
    var panel = this._previewPanel;
    if (!panel) return;
    panel.innerHTML = '<div class="latex-preview-status">⏳ Preview wordt gecompileerd…</div>';
    var csrf = (document.querySelector('meta[name="csrf-token"]') || {}).getAttribute
      ? (document.querySelector('meta[name="csrf-token"]').getAttribute('content') || '')
      : ((document.querySelector('input[name="csrf_token"]') || {}).value || '');
    fetch('/api/latex/preview', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf },
      body: JSON.stringify({ content: this.textarea.value, mode: this.mode })
    })
      .then(function(r) { return r.json(); })
      .then(function(d) {
        if (d && d.ok && d.image) {
          panel.innerHTML =
            '<div class="latex-preview-bar">' +
              '<span>PDF-voorbeeld</span>' +
              '<button type="button" class="btn btn-sm" data-preview-refresh>Vernieuwen</button>' +
            '</div>' +
            '<div class="latex-preview-img"><img alt="Preview" src="' + d.image + '" /></div>';
          var rb = panel.querySelector('[data-preview-refresh]');
          if (rb) rb.addEventListener('click', function() { self._refreshPreview(); });
        } else {
          panel.innerHTML = '<div class="latex-preview-status is-error">✖ ' +
            _escapeHtml((d && d.error) || 'preview mislukt') +
            '</div><div class="latex-preview-bar"><button type="button" class="btn btn-sm" data-preview-refresh>Opnieuw</button></div>';
          var rb2 = panel.querySelector('[data-preview-refresh]');
          if (rb2) rb2.addEventListener('click', function() { self._refreshPreview(); });
        }
      })
      .catch(function() {
        panel.innerHTML = '<div class="latex-preview-status is-error">✖ preview-verzoek mislukt</div>';
      });
  };

  LaTeXEditor.prototype._toggleFullscreen = function() {
    this.isFullscreen = !this.isFullscreen;
    this.wrapper.classList.toggle('is-fullscreen', this.isFullscreen);
    document.body.classList.toggle('latex-editor-fullscreen-active', this.isFullscreen);

    var expandIcon = this.container.querySelector('.latex-icon-expand');
    var collapseIcon = this.container.querySelector('.latex-icon-collapse');
    var labelEl = this.container.querySelector('[data-fullscreen-toggle] .latex-btn-label');

    if (expandIcon) expandIcon.classList.toggle('hidden', this.isFullscreen);
    if (collapseIcon) collapseIcon.classList.toggle('hidden', !this.isFullscreen);
    if (labelEl) labelEl.textContent = this.isFullscreen ? 'Sluiten' : 'Fullscreen';

    if (this.isFullscreen) {
      this.textarea.focus();
    }
  };

  LaTeXEditor.prototype._toggleDropdown = function(id) {
    var dropdown = this.container.querySelector('[data-dropdown="' + id + '"]');
    if (!dropdown) return;

    if (this.activeDropdown === id) {
      this._closeDropdown();
    } else {
      this._closeDropdown();
      dropdown.classList.add('is-open');
      this.activeDropdown = id;
      var search = dropdown.querySelector('[data-search="' + id + '"]');
      if (search) search.focus();
    }
  };

  LaTeXEditor.prototype._closeDropdown = function() {
    if (!this.activeDropdown) return;
    var dropdown = this.container.querySelector('[data-dropdown="' + this.activeDropdown + '"]');
    if (dropdown) {
      dropdown.classList.remove('is-open');
      var search = dropdown.querySelector('input[data-search]');
      if (search) {
        search.value = '';
        this._filterDropdownList(this.activeDropdown, '');
      }
    }
    this.activeDropdown = null;
  };

  LaTeXEditor.prototype._handleItemSelect = function(id, itemEl) {
    var value = itemEl.dataset.value;
    var title = itemEl.dataset.title || '';
    var dropdown = this.container.querySelector('[data-dropdown="' + id + '"]');
    var captionInput = dropdown ? dropdown.querySelector('[data-caption="' + id + '"]') : null;
    var caption = captionInput ? (captionInput.value || '').trim() : '';

    var latex = '';
    switch (id) {
      case 'snippet':
        latex = '\\input{snippets/' + value + '.tex}\n';
        break;
      case 'note':
        latex = '\\input{notes/' + value + '.tex}\n';
        break;
      case 'recon':
        latex = '\\reconoutput{' + value + '}{' + (_sanitizeTitle(title) || 'Recon output') + '}\n';
        break;
      case 'scan':
        latex = '\\scanoutput{' + value + '}{' + (_sanitizeTitle(title) || 'Scan output') + '}\n';
        break;
      case 'image':
      case 'projectImage':
        latex = '\\plaatje{' + value + '}{' + (caption || 'Caption') + '}\n';
        break;
      case 'gls':
        latex = '\\gls{' + value + '}';
        break;
      case 'glspl':
        latex = '\\glspl{' + value + '}';
        break;
    }

    if (latex) {
      // Bij een afbeelding zonder eigen onderschrift: selecteer "Caption".
      var ph = ((id === 'image' || id === 'projectImage') && !caption) ? 'Caption' : null;
      this._insertAtCursor(latex, ph);
      if (captionInput) captionInput.value = '';
    }

    this._closeDropdown();
  };

  LaTeXEditor.prototype._handleAction = function(action) {
    var selected = this._getSelectedText();
    var latex = '';

    switch (action) {
      case 'glossary':
        latex = '\\input{cyberveilig_woordenboek2024_glossary.tex}\n';
        break;
      case 'bibliography':
        latex = '\\bibliographystyle{acm}\n\\bibliography{opmaak/biblio}\n';
        break;
      case 'lstlisting':
        if (selected) {
          latex = '\\begin{lstlisting}\n' + selected + '\n\\end{lstlisting}\n';
        } else {
          latex = '\\begin{lstlisting}\n% Code hier\n\\end{lstlisting}\n';
        }
        break;
      case 'lstinline':
        if (selected) {
          latex = '\\lstinline|' + selected + '|';
        } else {
          latex = '\\lstinline||';
          this._insertAtCursor(latex);
          this.textarea.selectionStart = this.textarea.selectionEnd - 1;
          return;
        }
        break;
      case 'haakjes':
        if (selected) {
          latex = '\\haakjes{' + selected + '}';
        } else {
          latex = '\\haakjes{}';
          this._insertAtCursor(latex);
          this.textarea.selectionStart = this.textarea.selectionEnd - 1;
          return;
        }
        break;
      case 'opdracht':
        if (selected) {
          latex = '\\opdracht{' + selected + '}';
        } else {
          latex = '\\opdracht{}';
          this._insertAtCursor(latex);
          this.textarea.selectionStart = this.textarea.selectionEnd - 1;
          return;
        }
        break;
      case 'lakken':
        if (selected) {
          latex = '\\lakken{' + selected + '}';
        } else {
          latex = '\\lakken{}';
          this._insertAtCursor(latex);
          this.textarea.selectionStart = this.textarea.selectionEnd - 1;
          return;
        }
        break;
      case 'itemize':
        if (selected) {
          var items = selected.split('\n').filter(function(l) { return l.trim(); }).map(function(l) { return '  \\item ' + l.trim(); }).join('\n');
          latex = '\\begin{itemize}\n' + items + '\n\\end{itemize}\n';
        } else {
          latex = '\\begin{itemize}\n  \\item \n\\end{itemize}\n';
        }
        break;
      case 'enumerate':
        if (selected) {
          var items = selected.split('\n').filter(function(l) { return l.trim(); }).map(function(l) { return '  \\item ' + l.trim(); }).join('\n');
          latex = '\\begin{enumerate}\n' + items + '\n\\end{enumerate}\n';
        } else {
          latex = '\\begin{enumerate}\n  \\item \n\\end{enumerate}\n';
        }
        break;
      case 'table':
        latex = this._buildTable();
        break;
    }

    if (latex) {
      this._insertAtCursor(latex);
    }
  };

  // Bouw een tabular-skelet op basis van gevraagde kolommen/rijen.
  LaTeXEditor.prototype._buildTable = function() {
    var cols = parseInt(window.prompt('Aantal kolommen:', '3'), 10);
    if (!cols || cols < 1) return '';
    cols = Math.min(cols, 12);
    var rows = parseInt(window.prompt('Aantal rijen (excl. koprij):', '2'), 10);
    if (isNaN(rows) || rows < 0) rows = 1;
    rows = Math.min(rows, 50);
    var colspec = '|' + new Array(cols + 1).join('c|');
    function row(cells) { return '  ' + cells.join(' & ') + ' \\\\'; }
    function filled(fn) {
      var c = []; for (var i = 1; i <= cols; i++) { c.push(fn(i)); } return c;
    }
    var out = ['\\begin{tabular}{' + colspec + '}', '  \\hline'];
    out.push(row(filled(function(i) { return '\\textbf{Kop ' + i + '}'; })));
    out.push('  \\hline');
    for (var r = 0; r < rows; r++) {
      out.push(row(filled(function() { return ''; })));
      out.push('  \\hline');
    }
    out.push('\\end{tabular}');
    return out.join('\n') + '\n';
  };

  LaTeXEditor.prototype._handlePrompt = function(action, promptLabel) {
    var selected = this._getSelectedText();
    var value = selected || window.prompt(promptLabel || 'Waarde:', '');
    if (!value) return;

    var latex = '';
    switch (action) {
      case 'gls':
        latex = '\\gls{' + value + '}';
        break;
      case 'glspl':
        latex = '\\glspl{' + value + '}';
        break;
      case 'section':
        latex = '\\section{' + value + '}\n';
        break;
      case 'subsection':
        latex = '\\subsection{' + value + '}\n';
        break;
    }

    if (latex) {
      this._insertAtCursor(latex);
    }
  };

  LaTeXEditor.prototype._getSelectedText = function() {
    var start = this.textarea.selectionStart;
    var end = this.textarea.selectionEnd;
    if (start === end) return '';
    return this.textarea.value.substring(start, end);
  };

  // Voeg tekst in op de cursor. Gebruikt execCommand('insertText') zodat de
  // native undo/redo-stack (Ctrl+Z / Ctrl+Y) intact blijft; valt terug op een
  // directe waarde-set wanneer execCommand niet beschikbaar is. Met
  // selectPlaceholder wordt dat woord binnen de ingevoegde tekst geselecteerd,
  // zodat de gebruiker het meteen kan overtypen (bv. "Caption").
  LaTeXEditor.prototype._insertAtCursor = function(text, selectPlaceholder) {
    var ta = this.textarea;
    ta.focus();
    var start = ta.selectionStart || 0;
    var ok = false;
    try {
      ok = document.execCommand && document.execCommand('insertText', false, text);
    } catch (e) { ok = false; }
    if (!ok) {
      var end = ta.selectionEnd || 0;
      ta.value = ta.value.substring(0, start) + text + ta.value.substring(end);
      ta.selectionStart = ta.selectionEnd = start + text.length;
      try { ta.dispatchEvent(new Event('input', { bubbles: true })); } catch (e2) {}
    }
    if (selectPlaceholder) {
      var caretEnd = ta.selectionStart;
      var insStart = caretEnd - text.length;
      var rel = text.indexOf(selectPlaceholder);
      if (insStart >= 0 && rel !== -1) {
        ta.selectionStart = insStart + rel;
        ta.selectionEnd = insStart + rel + selectPlaceholder.length;
      }
    }
  };

  // Helpers
  function _sanitizeTitle(t) {
    return (t || '').toString().replace(/[{}]/g, '').trim();
  }

  function _escapeHtml(str) {
    var div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  function _escapeAttr(str) {
    return (str || '').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function _isImageUrl(u) {
    return /\.(png|jpe?g|gif|bmp|webp|svg)(\?|#|$)/i.test(u || '');
  }

  // Gedeelde HTML voor één dropdown-item; toont een thumbnail bij een afbeelding.
  function _dropdownItemHtml(item) {
    var thumb = _isImageUrl(item.url)
      ? '<img class="latex-item-thumb" src="' + _escapeAttr(item.url) + '" alt="" loading="lazy" />'
      : '';
    return '<button type="button" class="latex-dropdown-item' + (thumb ? ' has-thumb' : '') +
      '" data-value="' + _escapeAttr(item.value) + '" data-title="' + _escapeAttr(item.title || item.sublabel || '') +
      '" data-url="' + _escapeAttr(item.url || '') + '">' +
      thumb +
      '<span class="latex-item-text">' +
        '<span class="latex-item-label">' + _escapeHtml(item.label) + '</span>' +
        (item.sublabel ? '<span class="latex-item-sublabel">' + _escapeHtml(item.sublabel) + '</span>' : '') +
      '</span>' +
    '</button>';
  }

  // Auto-initialize
  function init() {
    document.querySelectorAll('[data-latex-toolbar]').forEach(function(container) {
      if (container.closest('.latex-editor-wrapper')) return; // already initialized
      var textareaId = container.dataset.latexToolbar || 'contentArea';
      new LaTeXEditor(container, textareaId);
    });

    var legacyContainer = document.getElementById('latexToolbar');
    if (legacyContainer && !legacyContainer.dataset.latexToolbar && !legacyContainer.closest('.latex-editor-wrapper')) {
      new LaTeXEditor(legacyContainer, 'contentArea');
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  window.initLatexToolbar = init;
})();
