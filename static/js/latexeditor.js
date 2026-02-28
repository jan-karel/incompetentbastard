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

    listEl.innerHTML = items.map(function(item) {
      return '<button type="button" class="latex-dropdown-item" data-value="' + _escapeAttr(item.value) + '" data-title="' + _escapeAttr(item.title || item.sublabel || '') + '" data-url="' + _escapeAttr(item.url || '') + '">' +
        '<span class="latex-item-label">' + _escapeHtml(item.label) + '</span>' +
        (item.sublabel ? '<span class="latex-item-sublabel">' + _escapeHtml(item.sublabel) + '</span>' : '') +
      '</button>';
    }).join('');
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

    listEl.innerHTML = filtered.map(function(item) {
      return '<button type="button" class="latex-dropdown-item" data-value="' + _escapeAttr(item.value) + '" data-title="' + _escapeAttr(item.title || item.sublabel || '') + '" data-url="' + _escapeAttr(item.url || '') + '">' +
        '<span class="latex-item-label">' + _escapeHtml(item.label) + '</span>' +
        (item.sublabel ? '<span class="latex-item-sublabel">' + _escapeHtml(item.sublabel) + '</span>' : '') +
      '</button>';
    }).join('');
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
        latex = '\\plaatje{' + value + '}{' + (caption || 'Caption') + '}\n';
        break;
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
      this._insertAtCursor(latex);
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
    }

    if (latex) {
      this._insertAtCursor(latex);
    }
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

  LaTeXEditor.prototype._insertAtCursor = function(text) {
    var ta = this.textarea;
    var start = ta.selectionStart || 0;
    var end = ta.selectionEnd || 0;
    var before = ta.value.substring(0, start);
    var after = ta.value.substring(end);
    ta.value = before + text + after;
    var pos = start + text.length;
    ta.selectionStart = ta.selectionEnd = pos;
    ta.focus();
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
