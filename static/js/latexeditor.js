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
          id: 'kaders',
          label: 'Kaders',
          items: [
            { id: 'kader', icon: '\u{1F516}', label: 'Kader', type: 'button', tooltip: 'Gekleurd kader met eigen titel + inhoud (kies kleur of voorinstelling)' },
          ]
        },
        {
          id: 'technisch',
          label: 'Technisch',
          items: [
            { id: 'pad', icon: '/\u2026', label: 'Pad', type: 'button', tooltip: '\\pad{/etc/shadow} - bestandspad (monospace)' },
            { id: 'host', icon: '\u{1F5A5}', label: 'Host', type: 'button', tooltip: '\\host{10.0.0.5} - host/IP (monospace)' },
            { id: 'route', icon: '\u{1F517}', label: 'Endpoint', type: 'button', tooltip: '\\route{/api/login} - endpoint/URL-pad (monospace)' },
            { id: 'param', icon: '?p', label: 'Param', type: 'button', tooltip: '\\param{redirect} - parameternaam (monospace)' },
            { id: 'port', icon: ':p', label: 'Poort', type: 'button', tooltip: '\\port{445} - poort (monospace)' },
            { id: 'proto', icon: 'prt', label: 'Protocol', type: 'button', tooltip: '\\proto{SMB} - protocol (monospace)' },
            { id: 'request', icon: '\u2192', label: 'Request', type: 'button', tooltip: 'HTTP-request invoegen (modal + highlight)' },
            { id: 'response', icon: '\u2190', label: 'Response', type: 'button', tooltip: 'HTTP-response invoegen (modal + highlight)' },
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
            { id: 'bevinding', icon: '\u{00A7}', label: 'Bevinding', type: 'button', tooltip: '\\bevinding{…} – kies een bevinding (kruisverwijzing)' },
            { id: 'uitwerking', icon: '\u{00A7}+', label: 'Uitwerking', type: 'button', tooltip: '\\uitwerking{…} – kies een bevinding ("verder uitgewerkt in …")' },
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
            { id: 'footnote', icon: 'fn', label: 'Voetnoot', type: 'button', tooltip: '\\footnote{...} - voetnoot' },
            { id: 'kbd', icon: '⌨', label: 'Toets', type: 'button', tooltip: '\\kbd{Ctrl+C} - toetsaanduiding' },
            { id: 'highlight', icon: '\u{1F58D}', label: 'Markeren', type: 'button', tooltip: '\\highlight{...} - tekst markeren' },
            { id: 'opdracht', icon: '\u{1F4CB}', label: 'Opdracht', type: 'button', tooltip: '\\opdracht{}' },
            { id: 'lakken', icon: '\u{2588}', label: 'Lakken', type: 'button', tooltip: '\\lakken{} - tekst censureren' },
            { id: 'deelsgelakt', icon: '\u{2588}½', label: 'Deels lakken', type: 'button', tooltip: '\\deelsgelakt{zichtbaar}{geheim} - deel censureren' },
            { id: 'stap', icon: '①', label: 'Stap', type: 'button', tooltip: '\\stap{...} - reproductiestap' },
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
            { id: 'bevinding', icon: '\u{00A7}', label: 'Bevinding', type: 'button', tooltip: '\\bevinding{…} – kies een bevinding (kruisverwijzing)' },
            { id: 'uitwerking', icon: '\u{00A7}+', label: 'Uitwerking', type: 'button', tooltip: '\\uitwerking{…} – kies een bevinding ("verder uitgewerkt in …")' },
            { id: 'bevindingref', icon: '\u{00A7}→', label: 'Bev.ref', type: 'button', tooltip: '\\bevindingref{…} – kies een bevinding (korte verwijzing, §nr)' },
            { id: 'classificatie', icon: '\u2691', label: 'Classificatie', type: 'button', tooltip: 'CVSS/CWE/CVE/OWASP/MITRE/ISO/BIO/NIST \u2014 modal met slimme invoer' },
            { id: 'url', icon: '\u{1F517}', label: 'URL', type: 'button', tooltip: '\\url{https://…} - klikbare URL' },
            { id: 'link', icon: '\u{1F517}t', label: 'Link', type: 'button', tooltip: '\\link{url}{tekst} - link met eigen tekst' },
          ]
        },
        {
          id: 'kaders',
          label: 'Kaders',
          items: [
            { id: 'kader', icon: '\u{1F516}', label: 'Kader', type: 'button', tooltip: 'Gekleurd kader met eigen titel + inhoud (kies kleur of voorinstelling)' },
          ]
        },
        {
          id: 'technisch',
          label: 'Technisch',
          items: [
            { id: 'pad', icon: '/\u2026', label: 'Pad', type: 'button', tooltip: '\\pad{/etc/shadow} - bestandspad (monospace)' },
            { id: 'host', icon: '\u{1F5A5}', label: 'Host', type: 'button', tooltip: '\\host{10.0.0.5} - host/IP (monospace)' },
            { id: 'route', icon: '\u{1F517}', label: 'Endpoint', type: 'button', tooltip: '\\route{/api/login} - endpoint/URL-pad (monospace)' },
            { id: 'param', icon: '?p', label: 'Param', type: 'button', tooltip: '\\param{redirect} - parameternaam (monospace)' },
            { id: 'port', icon: ':p', label: 'Poort', type: 'button', tooltip: '\\port{445} - poort (monospace)' },
            { id: 'proto', icon: 'prt', label: 'Protocol', type: 'button', tooltip: '\\proto{SMB} - protocol (monospace)' },
            { id: 'request', icon: '\u2192', label: 'Request', type: 'button', tooltip: 'HTTP-request invoegen (modal + highlight)' },
            { id: 'response', icon: '\u2190', label: 'Response', type: 'button', tooltip: 'HTTP-response invoegen (modal + highlight)' },
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
            { id: 'footnote', icon: 'fn', label: 'Voetnoot', type: 'button', tooltip: '\\footnote{...} - voetnoot' },
            { id: 'kbd', icon: '⌨', label: 'Toets', type: 'button', tooltip: '\\kbd{Ctrl+C} - toetsaanduiding' },
            { id: 'highlight', icon: '\u{1F58D}', label: 'Markeren', type: 'button', tooltip: '\\highlight{...} - tekst markeren' },
            { id: 'opdracht', icon: '\u{1F4CB}', label: 'Opdracht', type: 'button', tooltip: '\\opdracht{}' },
            { id: 'lakken', icon: '\u{2588}', label: 'Lakken', type: 'button', tooltip: '\\lakken{} - tekst censureren' },
            { id: 'deelsgelakt', icon: '\u{2588}½', label: 'Deels lakken', type: 'button', tooltip: '\\deelsgelakt{zichtbaar}{geheim} - deel censureren' },
            { id: 'stap', icon: '①', label: 'Stap', type: 'button', tooltip: '\\stap{...} - reproductiestap' },
          ]
        },
        {
          id: 'references',
          label: 'Referenties',
          items: [
            { id: 'snippet', icon: '{}', label: 'Snippet', type: 'dropdown', dataAttr: 'snippetsUrl' },
            { id: 'gls', icon: '\u{1F4D6}', label: 'Glossary', type: 'dropdown', dataAttr: 'glossaryTermsUrl', tooltip: '\\gls{term}' },
            { id: 'glspl', icon: '\u{1F4D6}+', label: 'Gls plural', type: 'dropdown', dataAttr: 'glossaryTermsUrl', tooltip: '\\glspl{term} (meervoud)' },
            { id: 'bevinding', icon: '\u{00A7}', label: 'Bevinding', type: 'button', tooltip: '\\bevinding{…} – kies een bevinding (kruisverwijzing)' },
            { id: 'uitwerking', icon: '\u{00A7}+', label: 'Uitwerking', type: 'button', tooltip: '\\uitwerking{…} – kies een bevinding ("verder uitgewerkt in …")' },
            { id: 'bevindingref', icon: '\u{00A7}→', label: 'Bev.ref', type: 'button', tooltip: '\\bevindingref{…} – kies een bevinding (korte verwijzing, §nr)' },
            { id: 'classificatie', icon: '\u2691', label: 'Classificatie', type: 'button', tooltip: 'CVSS/CWE/CVE/OWASP/MITRE/ISO/BIO/NIST \u2014 modal met slimme invoer' },
            { id: 'url', icon: '\u{1F517}', label: 'URL', type: 'button', tooltip: '\\url{https://…} - klikbare URL' },
            { id: 'link', icon: '\u{1F517}t', label: 'Link', type: 'button', tooltip: '\\link{url}{tekst} - link met eigen tekst' },
          ]
        },
        {
          id: 'kaders',
          label: 'Kaders',
          items: [
            { id: 'kader', icon: '\u{1F516}', label: 'Kader', type: 'button', tooltip: 'Gekleurd kader met eigen titel + inhoud (kies kleur of voorinstelling)' },
          ]
        },
        {
          id: 'technisch',
          label: 'Technisch',
          items: [
            { id: 'pad', icon: '/\u2026', label: 'Pad', type: 'button', tooltip: '\\pad{/etc/shadow} - bestandspad (monospace)' },
            { id: 'host', icon: '\u{1F5A5}', label: 'Host', type: 'button', tooltip: '\\host{10.0.0.5} - host/IP (monospace)' },
            { id: 'route', icon: '\u{1F517}', label: 'Endpoint', type: 'button', tooltip: '\\route{/api/login} - endpoint/URL-pad (monospace)' },
            { id: 'param', icon: '?p', label: 'Param', type: 'button', tooltip: '\\param{redirect} - parameternaam (monospace)' },
            { id: 'port', icon: ':p', label: 'Poort', type: 'button', tooltip: '\\port{445} - poort (monospace)' },
            { id: 'proto', icon: 'prt', label: 'Protocol', type: 'button', tooltip: '\\proto{SMB} - protocol (monospace)' },
            { id: 'request', icon: '\u2192', label: 'Request', type: 'button', tooltip: 'HTTP-request invoegen (modal + highlight)' },
            { id: 'response', icon: '\u2190', label: 'Response', type: 'button', tooltip: 'HTTP-response invoegen (modal + highlight)' },
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
    this._attachEditorHighlight(this.textarea);
    this._render();
    this._loadAllData();
    this._bindEvents();
    this._bindImageDrop();
    this._bindPasteConvert();
    this._bindKeys();
    this._bindFindReplace();
    this._bindAutosaveAndLint();
    this._bindBlockClick();
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
    // Kruisverwijzingen naar bevindingen moeten een numeriek id hebben.
    var refRe = /\\(?:bevinding|uitwerking|bevindingref)\s*\{([^}]*)\}/g, rm;
    while ((rm = refRe.exec(text))) {
      if (!/^\d+$/.test(rm[1].trim())) { warns.push('bevinding-verwijzing zonder geldig id'); break; }
    }
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
    var stat = document.createElement('span');
    stat.className = 'latex-stat';
    bar.appendChild(lint); bar.appendChild(stat);
    this.wrapper.appendChild(bar);

    function updateStat() {
      var v = ta.value, p = ta.selectionStart || 0;
      var before = v.slice(0, p);
      var ln = before.split('\n').length;
      var col = p - before.lastIndexOf('\n');
      var selLen = Math.abs((ta.selectionEnd || 0) - p);
      var words = (v.trim().match(/\S+/g) || []).length;
      stat.textContent = 'Ln ' + ln + ', Kol ' + col
        + (selLen ? '  ·  ' + selLen + ' gesel.' : '')
        + '  ·  ' + v.length + ' tekens  ·  ' + words + ' woorden';
    }
    ['input', 'keyup', 'click', 'select'].forEach(function(ev) { ta.addEventListener(ev, updateStat); });
    updateStat();

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
  // Syntax-highlight-laag: een gekleurde backdrop achter een transparante
  // textarea (de textarea blijft het echte invoerveld, dus undo/plak/selectie/
  // toolbar blijven werken). Metrics worden uit de computed-style gekopieerd,
  // zodat de uitlijning in elke context (ook fullscreen) klopt. CSP-schoon:
  // klassen voor kleuren, CSSOM voor metrics, ge-escapete innerHTML.
  LaTeXEditor.prototype._attachEditorHighlight = function(ta) {
    if (!ta || ta._lxHl) return;
    var wrap = document.createElement('div'); wrap.className = 'lx-ed-wrap';
    var back = document.createElement('div'); back.className = 'lx-ed-backdrop';
    ta.parentNode.insertBefore(wrap, ta);
    wrap.appendChild(back); wrap.appendChild(ta);
    ta.classList.add('lx-ed-area');
    function esc(s) { return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
    function syncMetrics() {
      var cs = getComputedStyle(ta);
      ['fontFamily', 'fontSize', 'fontWeight', 'lineHeight', 'letterSpacing',
       'whiteSpace', 'wordBreak', 'overflowWrap', 'tabSize', 'textAlign',
       'paddingTop', 'paddingRight', 'paddingBottom', 'paddingLeft'].forEach(function(p) {
        try { back.style[p] = cs[p]; } catch (e) {}
      });
      if (back.style.whiteSpace === 'normal') back.style.whiteSpace = 'pre-wrap';
    }
    function hl(v) {
      if (v.length > 50000) return esc(v);  // te groot -> geen tokens (performance)
      return esc(v).replace(/(%[^\n]*)|(\\[a-zA-Z@]+\*?|\\.)|(\$[^$\n]*\$)|([{}])/g,
        function(m, com, cmd, math, brace) {
          if (com) return '<span class="tk-com">' + com + '</span>';
          if (cmd) return '<span class="tk-cmd">' + cmd + '</span>';
          if (math) return '<span class="tk-math">' + math + '</span>';
          if (brace) return '<span class="tk-brace">' + brace + '</span>';
          return m;
        });
    }
    function render() {
      syncMetrics();
      back.innerHTML = hl(ta.value) + '\n';
      back.scrollTop = ta.scrollTop; back.scrollLeft = ta.scrollLeft;
    }
    ta.addEventListener('input', render);
    ta.addEventListener('scroll', function() { back.scrollTop = ta.scrollTop; back.scrollLeft = ta.scrollLeft; });
    window.addEventListener('resize', syncMetrics);
    ta._lxHl = render;
    setTimeout(render, 0);
  };

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

      // Auto-aanvullen van paren: { } [ ] ( ) $ — met wrap om de selectie.
      var pairs = { '{': '}', '[': ']', '(': ')', '$': '$' };
      if (!mod && !e.altKey && pairs[e.key]) {
        var ps = ta.selectionStart, pe = ta.selectionEnd;
        e.preventDefault();
        if (ps !== pe) {
          var selTxt = ta.value.slice(ps, pe);
          self._insertAtCursor(e.key + selTxt + pairs[e.key]);
          ta.selectionStart = ps + 1; ta.selectionEnd = ps + 1 + selTxt.length;
        } else {
          self._insertAtCursor(e.key + pairs[e.key]);
          ta.selectionStart = ta.selectionEnd = ps + 1;
        }
        return;
      }
      // Sluitteken overslaan als het al direct rechts van de cursor staat.
      if (!mod && !e.altKey && '}])'.indexOf(e.key) >= 0
          && ta.selectionStart === ta.selectionEnd && ta.value.charAt(ta.selectionStart) === e.key) {
        e.preventDefault(); ta.selectionStart = ta.selectionEnd = ta.selectionStart + 1; return;
      }
      // Backspace op een leeg paar verwijdert beide tekens.
      if (!mod && !e.altKey && e.key === 'Backspace' && ta.selectionStart === ta.selectionEnd) {
        var bi = ta.selectionStart, L = ta.value.charAt(bi - 1), R = ta.value.charAt(bi);
        if (pairs[L] && pairs[L] === R) {
          e.preventDefault();
          ta.selectionStart = bi - 1; ta.selectionEnd = bi + 1;
          self._insertAtCursor('');
          return;
        }
      }

      if (!mod) return;
      var k = e.key.toLowerCase();
      if (k === 'b') { e.preventDefault(); self._wrap('\\textbf{', '}'); }
      else if (k === 'i') { e.preventDefault(); self._wrap('\\emph{', '}'); }
      else if (e.key === '`') { e.preventDefault(); self._wrap('\\texttt{', '}'); }
      else if (k === 'f') { e.preventDefault(); if (self._toggleFindReplace) self._toggleFindReplace(); }
      else if (k === 'k') { e.preventDefault(); self._handleAction('bevinding'); }
      else if (e.key === 'Enter') {
        e.preventDefault();
        var pb = self.wrapper && self.wrapper.querySelector('[data-preview-toggle]');
        if (pb) pb.click();
      }
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

  // Plakken van Word/HTML of markdown -> LaTeX. Afbeeldingen laat deze met rust
  // (die handelt _bindImageDrop af).
  LaTeXEditor.prototype._bindPasteConvert = function() {
    var self = this;
    var ta = this.textarea;
    if (!ta) return;
    ta.addEventListener('paste', function(e) {
      var cd = e.clipboardData;
      if (!cd) return;
      var items = cd.items || [];
      for (var i = 0; i < items.length; i++) {
        if (items[i].kind === 'file' && (items[i].type || '').indexOf('image') === 0) return;
      }
      var html = cd.getData('text/html');
      var plain = cd.getData('text/plain');
      if (html && /<(p|div|span|b|strong|i|em|u|ul|ol|li|h[1-6]|a|table|br|font)\b/i.test(html)) {
        var tex = _htmlToLatex(html);
        if (tex && tex.trim()) { e.preventDefault(); self._insertAtCursor(tex); return; }
      }
      if (plain && _looksLikeMarkdown(plain)) {
        e.preventDefault();
        self._insertAtCursor(_markdownToLatex(plain));
      }
    });
  };

  // Zoek-en-vervang in het tekstvak (Cmd/Ctrl+F). Behoudt native undo via
  // _insertAtCursor (execCommand). CSP-schoon: klassen, geen inline styles.
  LaTeXEditor.prototype._bindFindReplace = function() {
    var self = this;
    var ta = this.textarea;
    if (!ta) return;
    var panel = document.createElement('div');
    panel.className = 'latex-findbar';
    panel.hidden = true;
    function inp(ph) { var e = document.createElement('input'); e.type = 'text'; e.placeholder = ph; e.className = 'latex-find-input'; return e; }
    function btn(txt) { var b = document.createElement('button'); b.type = 'button'; b.className = 'btn btn-xs'; b.textContent = txt; return b; }
    var fIn = inp('Zoeken…'), rIn = inp('Vervangen door…');
    var bNext = btn('Volgende'), bRepl = btn('Vervang'), bAll = btn('Alles'), bClose = btn('✕');
    var info = document.createElement('span'); info.className = 'latex-find-info';
    [fIn, bNext, rIn, bRepl, bAll, info, bClose].forEach(function(el) { panel.appendChild(el); });
    // De textarea kan in een highlight-wrapper (.lx-ed-wrap) zitten; plaats de
    // zoekbalk vóór het directe kind van de wrapper dat de textarea bevat.
    var ref = ta;
    while (ref.parentNode && ref.parentNode !== this.wrapper) ref = ref.parentNode;
    if (ref.parentNode === this.wrapper) { this.wrapper.insertBefore(panel, ref); }
    else { this.wrapper.appendChild(panel); }

    function count(q) { if (!q) return 0; var c = 0, p = 0, h = ta.value; while ((p = h.indexOf(q, p)) !== -1) { c++; p += q.length; } return c; }
    function findNext() {
      var q = fIn.value; if (!q) { info.textContent = ''; return; }
      var from = ta.selectionEnd || 0;
      var idx = ta.value.indexOf(q, from);
      if (idx === -1) idx = ta.value.indexOf(q, 0);
      if (idx === -1) { info.textContent = 'geen treffer'; return; }
      ta.focus(); ta.setSelectionRange(idx, idx + q.length);
      var n = count(q); info.textContent = n + ' treffer' + (n === 1 ? '' : 's');
    }
    function replaceOne() {
      var q = fIn.value; if (!q) return;
      if (ta.value.substring(ta.selectionStart, ta.selectionEnd) === q) {
        self._insertAtCursor(rIn.value);
      }
      findNext();
    }
    function replaceAll() {
      var q = fIn.value; if (!q) return;
      var parts = ta.value.split(q), n = parts.length - 1;
      if (!n) { info.textContent = 'geen treffer'; return; }
      ta.focus(); ta.select(); self._insertAtCursor(parts.join(rIn.value));
      info.textContent = n + ' vervangen';
    }
    bNext.addEventListener('click', findNext);
    bRepl.addEventListener('click', replaceOne);
    bAll.addEventListener('click', replaceAll);
    bClose.addEventListener('click', function() { panel.hidden = true; ta.focus(); });
    fIn.addEventListener('keydown', function(e) {
      if (e.key === 'Enter') { e.preventDefault(); findNext(); }
      else if (e.key === 'Escape') { panel.hidden = true; ta.focus(); }
    });

    this._toggleFindReplace = function() {
      panel.hidden = !panel.hidden;
      if (!panel.hidden) {
        var sel = self._getSelectedText();
        if (sel && sel.length < 80) fIn.value = sel;
        fIn.focus(); fIn.select();
      }
    };
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

    // Vaste opmaak-groep vooraan: vet / cursief / onderstreept / kleur.
    var fmtGroup = document.createElement('div');
    fmtGroup.className = 'latex-toolbar-group latex-format-group';
    [['bold', 'B', 'Vet (Ctrl/Cmd+B)', 'lx-fmt-b'],
     ['italic', 'I', 'Cursief (Ctrl/Cmd+I)', 'lx-fmt-i'],
     ['underline', 'U', 'Onderstreept', 'lx-fmt-u'],
     ['kleur', 'A', 'Tekstkleur', 'lx-fmt-c']].forEach(function(f) {
      var w = document.createElement('div'); w.className = 'latex-toolbar-item';
      var b = document.createElement('button'); b.type = 'button';
      b.className = 'latex-btn latex-fmt-btn ' + f[3];
      b.setAttribute('data-action', f[0]); b.title = f[2];
      var ic = document.createElement('span'); ic.className = 'latex-btn-icon lx-fmt-ico'; ic.textContent = f[1];
      b.appendChild(ic); w.appendChild(b); fmtGroup.appendChild(w);
    });
    this.container.appendChild(fmtGroup);

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
          '<span class="latex-btn-icon">' + _icon('preview') + '</span>' +
          '<span class="latex-btn-label">Preview</span>' +
        '</button>' +
      '</div>' +
      '<div class="latex-toolbar-item">' +
        '<button type="button" class="latex-btn latex-btn-fullscreen" data-fullscreen-toggle title="Fullscreen (Esc om te sluiten)">' +
          '<span class="latex-btn-icon latex-icon-expand">' + _icon('fs-expand') + '</span>' +
          '<span class="latex-btn-icon latex-icon-collapse hidden">' + _icon('fs-collapse') + '</span>' +
          '<span class="latex-btn-label">Fullscreen</span>' +
        '</button>' +
      '</div>';
    this.container.appendChild(fullscreenGroup);
  };

  // Uniforme inline-SVG icoonset (currentColor -> thema-/hover-bewust, altijd
  // monochroom). Per toolbar-id een line-icon; ontbreekt er een, dan valt de
  // knop terug op het oorspronkelijke tekst-/emoji-icoon.
  var _ICONS = {
    snippet: '<path d="M6 3C4.3 3 4.5 5 4.5 6.3 4.5 7.2 3.8 8 3 8c.8 0 1.5.8 1.5 1.7C4.5 11 4.3 13 6 13"/><path d="M10 3c1.7 0 1.5 2 1.5 3.3 0 .9.7 1.7 1.5 1.7-.8 0-1.5.8-1.5 1.7 0 1.3.2 3.3-1.5 3.3"/>',
    note: '<path d="M4 2h5l3 3v9H4z"/><path d="M9 2v3h3"/><path d="M6 8h4M6 10.5h4"/>',
    recon: '<circle cx="7" cy="7" r="3.5"/><path d="M9.6 9.6L13 13"/>',
    scan: '<path d="M3 13V8.5M6.5 13V5M10 13V9M13.5 13V6.5"/><path d="M2.5 13.5h12"/>',
    kader: '<rect x="2.5" y="3" width="11" height="10" rx="1"/><path d="M2.5 6.2h11"/>',
    pad: '<path d="M2.5 4.5h4l1.3 1.3h5.7v6.7h-11z"/>',
    host: '<rect x="2.5" y="3" width="11" height="4" rx="1"/><rect x="2.5" y="9" width="11" height="4" rx="1"/><path d="M5 5h.01M5 11h.01"/>',
    route: '<circle cx="4" cy="4" r="1.5"/><circle cx="12" cy="12" r="1.5"/><path d="M5.5 4.5h3.5A2 2 0 0 1 11 6.5v4"/>',
    param: '<path d="M6 3c-1.8 0-1.5 2-1.5 5s.3 5-1.5 5M10 3c1.8 0 1.5 2 1.5 5s-.3 5 1.5 5"/><path d="M8 8h.01"/>',
    port: '<path d="M6 2v3M10 2v3"/><rect x="4.5" y="5" width="7" height="4.5" rx="1"/><path d="M8 9.5v2.5A2 2 0 0 1 6 14"/>',
    proto: '<path d="M3 6.2h9.5l-2.2-2.2M13 9.8H3.5l2.2 2.2"/>',
    lstlisting: '<rect x="2.5" y="3.5" width="11" height="9" rx="1"/><path d="M6 7l-1.5 1.5L6 10M10 7l1.5 1.5L10 10"/>',
    lstinline: '<path d="M6 5L3 8l3 3M10 5l3 3-3 3"/>',
    haakjes: '<path d="M6 3H4v10h2M10 3h2v10h-2"/>',
    footnote: '<path d="M4 12V4h3.5M4 8h3"/><circle cx="11.5" cy="5" r="1.1" fill="currentColor" stroke="none"/>',
    kbd: '<rect x="2" y="5" width="12" height="7" rx="1"/><path d="M4.5 8h.01M7 8h.01M9.5 8h.01M12 8h.01M5.5 10.5h5"/>',
    highlight: '<path d="M4 11.5l-1 2.5 2.5-1 6.5-6.5-1.5-1.5z"/><path d="M9.5 4.5l2 2"/>',
    opdracht: '<rect x="3.5" y="3" width="9" height="11" rx="1"/><path d="M6 3V2h4v1"/><path d="M6 7h4M6 10h4"/>',
    lakken: '<rect x="3" y="6.3" width="10" height="3.4" rx=".4" fill="currentColor" stroke="none"/>',
    deelsgelakt: '<path d="M3 8h4"/><rect x="8" y="6.3" width="5" height="3.4" rx=".4" fill="currentColor" stroke="none"/>',
    stap: '<circle cx="8" cy="8" r="5.5"/><path d="M7.3 6.2L8.5 5.6V10.5"/>',
    itemize: '<circle cx="3.3" cy="4.5" r=".9" fill="currentColor" stroke="none"/><circle cx="3.3" cy="8" r=".9" fill="currentColor" stroke="none"/><circle cx="3.3" cy="11.5" r=".9" fill="currentColor" stroke="none"/><path d="M6 4.5h7.5M6 8h7.5M6 11.5h7.5"/>',
    enumerate: '<path d="M6 4.5h7.5M6 8h7.5M6 11.5h7.5"/><path d="M2.2 3.4l1-.5v3M1.9 9.6c0-1 2.1-1 2.1.1 0 .9-2.1 1.2-2.1 2.4h2.2"/>',
    table: '<rect x="2.5" y="3.5" width="11" height="9" rx="1"/><path d="M2.5 6.5h11M2.5 9.5h11M6 3.5v9M10 3.5v9"/>',
    bevinding: '<path d="M9.5 5.2a2.2 2.2 0 0 0-3.1 0L4.9 6.7a2.2 2.2 0 0 0 3.1 3.1"/><path d="M6.5 10.8a2.2 2.2 0 0 0 3.1 0l1.5-1.5a2.2 2.2 0 0 0-3.1-3.1"/>',
    uitwerking: '<path d="M9.5 5.2a2.2 2.2 0 0 0-3.1 0L4.9 6.7a2.2 2.2 0 0 0 3.1 3.1"/><path d="M6.5 10.8a2.2 2.2 0 0 0 3.1 0l1.5-1.5a2.2 2.2 0 0 0-3.1-3.1"/>',
    bevindingref: '<path d="M9.5 5.2a2.2 2.2 0 0 0-3.1 0L4.9 6.7a2.2 2.2 0 0 0 3.1 3.1"/><path d="M6.5 10.8a2.2 2.2 0 0 0 3.1 0l1.5-1.5a2.2 2.2 0 0 0-3.1-3.1"/>',
    classificatie: '<path d="M8 2.3l5 2v3c0 3.2-2.1 5.2-5 6.1-2.9-.9-5-2.9-5-6.1v-3z"/>',
    url: '<circle cx="8" cy="8" r="5.5"/><path d="M2.6 8h10.8M8 2.5c1.9 2 1.9 9 0 11M8 2.5c-1.9 2-1.9 9 0 11"/>',
    link: '<path d="M7 9a2.5 2.5 0 0 0 3.5 0l2-2a2.5 2.5 0 0 0-3.5-3.5l-1 1"/><path d="M9 7a2.5 2.5 0 0 0-3.5 0l-2 2a2.5 2.5 0 0 0 3.5 3.5l1-1"/>',
    image: '<rect x="2.5" y="3.5" width="11" height="9" rx="1"/><circle cx="6" cy="7" r="1.2"/><path d="M3 12l3.5-3 2.5 2 2-2 2.5 3"/>',
    projectImage: '<rect x="2.5" y="3.5" width="11" height="9" rx="1"/><circle cx="6" cy="7" r="1.2"/><path d="M3 12l3.5-3 2.5 2 2-2 2.5 3"/>',
    gls: '<path d="M3 3.5h6.5A1.5 1.5 0 0 1 11 5v8.5H4.5A1.5 1.5 0 0 1 3 12z"/><path d="M11 5h2v8.5H5"/>',
    glspl: '<path d="M3 3.5h6.5A1.5 1.5 0 0 1 11 5v8.5H4.5A1.5 1.5 0 0 1 3 12z"/><path d="M11 5h2v8.5H5"/>',
    request: '<path d="M3 8h9M9 5l3 3-3 3"/>',
    response: '<path d="M13 8H4M7 5L4 8l3 3"/>',
    section: '<path d="M4 3.5v9M10.5 3.5v9M4 8h6.5"/>',
    subsection: '<path d="M3.5 4v7M8.5 4v7M3.5 7.5h5"/><path d="M11 9.3l1.3-.6v4"/>',
    glossary: '<path d="M3 3.5h6.5A1.5 1.5 0 0 1 11 5v8.5H4.5A1.5 1.5 0 0 1 3 12z"/><path d="M11 5h2v8.5H5M5.5 6.5h3.5M5.5 9h3.5"/>',
    bibliography: '<path d="M4 3h6l1.5 1.5V13H4z"/><path d="M4 3L2.5 4.5V14.5H10"/><path d="M6 6.5h3M6 9h3"/>',
    preview: '<path d="M1.6 8S4 3.8 8 3.8 14.4 8 14.4 8 12 12.2 8 12.2 1.6 8 1.6 8z"/><circle cx="8" cy="8" r="2"/>',
    'fs-expand': '<path d="M3 6V3h3M13 6V3h-3M3 10v3h3M13 10v3h-3"/>',
    'fs-collapse': '<path d="M6 3v3H3M10 3v3h3M6 13v-3H3M10 13v-3h3"/>'
  };
  function _svgIcon(inner) {
    return '<svg class="latex-ico" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + inner + '</svg>';
  }
  function _icon(id, fallback) { return _ICONS[id] ? _svgIcon(_ICONS[id]) : (fallback || ''); }

  LaTeXEditor.prototype._renderButton = function(item) {
    return '<button type="button" class="latex-btn" data-action="' + item.id + '" title="' + (item.tooltip || item.label) + '">' +
      '<span class="latex-btn-icon">' + _icon(item.id, item.icon) + '</span>' +
      '<span class="latex-btn-label">' + item.label + '</span>' +
    '</button>';
  };

  LaTeXEditor.prototype._renderPromptButton = function(item) {
    return '<button type="button" class="latex-btn" data-prompt="' + item.id + '" data-prompt-label="' + (item.promptLabel || 'Waarde:') + '" title="' + (item.tooltip || item.label) + '">' +
      '<span class="latex-btn-icon">' + _icon(item.id, item.icon) + '</span>' +
      '<span class="latex-btn-label">' + item.label + '</span>' +
    '</button>';
  };

  LaTeXEditor.prototype._renderDropdownButton = function(item) {
    var html = '<div class="latex-dropdown" data-dropdown="' + item.id + '">' +
      '<button type="button" class="latex-btn latex-btn-dropdown" data-toggle="' + item.id + '" title="' + (item.tooltip || item.label) + '">' +
        '<span class="latex-btn-icon">' + _icon(item.id, item.icon) + '</span>' +
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
    // redactable is alleen true voor projectscreenshots (/api/screenshots); zo
    // verschijnt de lak-knop nooit bij een andere beeldbron.
    return { value: item.name, label: item.name, url: item.url,
             has_lakken: !!item.has_lakken, has_annot: !!item.has_annot,
             redactable: item.redactable === true };
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

  // Canvas-editor voor een projectafbeelding. Twee modi:
  //  - 'lak'   : zwarte vlakken (redactie). De client stuurt alleen de LAAG
  //              (zwarte vlakken op transparant); de server composit die over de
  //              geannoteerde basis -> raw/screenshots/lakken/<naam>, alleen in
  //              de GELAKTE build. Volgorde (eerst lakken/annoteren) maakt niet uit.
  //  - 'annot' : rode aandachtsvormen (kader/pijl/genummerde markering) met
  //              transparante binnenkant -> raw/screenshots/annot/<naam>, in ÁLLE
  //              rapportversies zichtbaar. Gebakken op de afbeelding.
  // Vormen zijn tijdens de sessie te selecteren, verplaatsen en verwijderen.
  LaTeXEditor.prototype._openScreenshotRedactor = function(lakBtn, mode) {
    var self = this;
    var ANNOT = (mode === 'annot');
    var MODE = ANNOT ? {
      title: 'Aandachtspunten', suffix: '/annotate', dir: 'annot',
      stateAttr: 'data-has-annot', stateKey: 'has_annot', on: '⬠ Aandacht ✓', off: '⬠ Aandachtspunt',
      hint: 'Teken rode kaders/pijlen/nummers op aandachtspunten (zichtbaar in álle rapporten).',
      hintBij: 'Bestaande markering als basis — teken extra vormen (of "Vanaf origineel").'
    } : {
      title: 'Lakken', suffix: '/redact', dir: 'lakken',
      stateAttr: 'data-has-lakken', stateKey: 'has_lakken', on: '█ Lak ✓', off: '█ Lakken',
      hint: 'Sleep rechthoeken over wat weg moet; in de gelakte rapportversie wordt dit zwart.',
      hintBij: 'Bestaande lak als basis — sleep extra vlakken (of "Vanaf origineel" voor opnieuw).'
    };
    var name = lakBtn.getAttribute('data-lak-name') || '';
    var url = lakBtn.getAttribute('data-lak-url') || '';
    var hasState = lakBtn.getAttribute(MODE.stateAttr) === '1';
    var hasAnnot = lakBtn.getAttribute('data-has-annot') === '1';
    if (!name || !url) return;
    var endpoint = '/api/screenshots/' + encodeURIComponent(name) + MODE.suffix;
    var annotUrl = '/dashboard/raw/screenshots/annot/' + encodeURIComponent(name);
    var lakkenUrl = '/dashboard/raw/screenshots/lakken/' + encodeURIComponent(name);
    var layerUrl = '/dashboard/raw/screenshots/lakken/_layer/' + encodeURIComponent(name) + '.png';

    function mkbtn(label) {
      var b = document.createElement('button');
      b.type = 'button'; b.className = 'btn btn-sm'; b.textContent = label;
      return b;
    }

    var overlay = document.createElement('div');
    overlay.className = 'latex-redact-overlay';
    var modal = document.createElement('div');
    modal.className = 'latex-redact-modal';
    overlay.appendChild(modal);

    var head = document.createElement('div');
    head.className = 'latex-redact-head';
    var h = document.createElement('h3');
    h.textContent = MODE.title + ' — ' + name;
    var closeX = mkbtn('Sluiten');
    head.appendChild(h); head.appendChild(closeX);
    modal.appendChild(head);

    // Gereedschap (alleen bij annotatie meerdere vormen).
    var tool = 'rect';
    var toolRow = null, toolBtns = {};
    if (ANNOT) {
      toolRow = document.createElement('div'); toolRow.className = 'latex-redact-tools';
      [['rect', '▭ Kader'], ['arrow', '↗ Pijl'], ['num', '① Nummer'], ['select', '➤ Selecteer']]
        .forEach(function(p) {
          var b = mkbtn(p[1]); b.classList.add('lx-tool');
          if (p[0] === tool) b.classList.add('is-on');
          b.addEventListener('click', function() {
            tool = p[0]; selected = -1;
            Object.keys(toolBtns).forEach(function(k) { toolBtns[k].classList.toggle('is-on', k === tool); });
            redraw();
          });
          toolBtns[p[0]] = b; toolRow.appendChild(b);
        });
      modal.appendChild(toolRow);
    }

    var cwrap = document.createElement('div');
    cwrap.className = 'latex-redact-canvas-wrap';
    var canvas = document.createElement('canvas');
    canvas.className = 'latex-redact-canvas';
    cwrap.appendChild(canvas);
    modal.appendChild(cwrap);
    var ctx = canvas.getContext('2d');

    var tb = document.createElement('div');
    tb.className = 'latex-redact-toolbar';
    var hint = document.createElement('span');
    hint.className = 'latex-redact-hint';
    hint.textContent = MODE.hint;
    var undoBtn = mkbtn('Laatste ongedaan');
    var delSelBtn = mkbtn('Verwijder selectie');
    var clearBtn = mkbtn('Wis alles');
    var origBtn = hasState ? mkbtn('Vanaf origineel') : null;
    var delBtn = hasState ? mkbtn(ANNOT ? 'Markering verwijderen' : 'Lak verwijderen') : null;
    var saveBtn = mkbtn('Opslaan'); saveBtn.classList.add('btn-primary');
    tb.appendChild(hint); tb.appendChild(undoBtn); tb.appendChild(delSelBtn); tb.appendChild(clearBtn);
    if (origBtn) tb.appendChild(origBtn);
    if (delBtn) tb.appendChild(delBtn);
    tb.appendChild(saveBtn);
    modal.appendChild(tb);

    var vanafOrigineel = false;
    var shapes = [];
    var selected = -1;
    var existingLayerImg = null;

    // Bij lak-bijlakken: bestaande lak-laag inladen (voor export).
    if (!ANNOT && hasState) {
      var le = new Image();
      le.onload = function() { existingLayerImg = le; };
      le.onerror = function() { existingLayerImg = null; };
      le.src = layerUrl + '?t=' + Date.now();
    }

    var imgEl = new Image();
    imgEl.onload = function() {
      var maxW = 1600;
      var scale = imgEl.naturalWidth > maxW ? maxW / imgEl.naturalWidth : 1;
      canvas.width = Math.max(1, Math.round(imgEl.naturalWidth * scale));
      canvas.height = Math.max(1, Math.round(imgEl.naturalHeight * scale));
      redraw();
    };
    imgEl.onerror = function() { hint.textContent = 'Kon de afbeelding niet laden.'; };
    function loadBase() {
      shapes = []; selected = -1;
      var useState = hasState && !vanafOrigineel;
      var srcUrl;
      if (ANNOT) {
        srcUrl = useState ? (annotUrl + '?t=' + Date.now()) : url;
      } else {
        // Toon de gelakte composiet (incl. annot + oude vlakken) als basis, of
        // anders de annot-kopie / het origineel zodat je de rode kaders ziet.
        srcUrl = useState ? (lakkenUrl + '?t=' + Date.now())
          : (hasAnnot ? (annotUrl + '?t=' + Date.now()) : url);
      }
      imgEl.src = srcUrl;
      hint.textContent = useState ? MODE.hintBij : MODE.hint;
    }
    loadBase();
    if (origBtn) origBtn.addEventListener('click', function() {
      vanafOrigineel = !vanafOrigineel;
      origBtn.classList.toggle('is-on', vanafOrigineel);
      origBtn.textContent = vanafOrigineel ? ('Terug naar ' + (ANNOT ? 'markering' : 'gelakt')) : 'Vanaf origineel';
      loadBase();
    });

    function lw() { return Math.max(3, Math.round(canvas.width / 300)); }
    function numR() { return Math.max(14, lw() * 5); }
    function shapeBBox(s) {
      if (s.t === 'rect') return { x: s.x, y: s.y, w: s.w, h: s.h };
      if (s.t === 'arrow') return { x: Math.min(s.x1, s.x2), y: Math.min(s.y1, s.y2), w: Math.abs(s.x2 - s.x1), h: Math.abs(s.y2 - s.y1) };
      var r = numR(); return { x: s.x - r, y: s.y - r, w: 2 * r, h: 2 * r };
    }
    function hit(s, px, py) {
      var b = shapeBBox(s), t = Math.max(8, lw() * 2);
      return px >= b.x - t && px <= b.x + b.w + t && py >= b.y - t && py <= b.y + b.h + t;
    }
    function drawShape(c, s, num) {
      var color = ANNOT ? '#e4002b' : '#000';
      c.lineWidth = lw(); c.setLineDash([]);
      if (s.t === 'rect') {
        if (ANNOT) { c.strokeStyle = color; c.strokeRect(s.x + lw() / 2, s.y + lw() / 2, Math.max(1, s.w - lw()), Math.max(1, s.h - lw())); }
        else { c.fillStyle = color; c.fillRect(s.x, s.y, s.w, s.h); }
      } else if (s.t === 'arrow') {
        c.strokeStyle = color; c.fillStyle = color; c.lineCap = 'round';
        c.beginPath(); c.moveTo(s.x1, s.y1); c.lineTo(s.x2, s.y2); c.stroke();
        var ang = Math.atan2(s.y2 - s.y1, s.x2 - s.x1), hl = Math.max(14, lw() * 4);
        c.beginPath(); c.moveTo(s.x2, s.y2);
        c.lineTo(s.x2 - hl * Math.cos(ang - 0.45), s.y2 - hl * Math.sin(ang - 0.45));
        c.lineTo(s.x2 - hl * Math.cos(ang + 0.45), s.y2 - hl * Math.sin(ang + 0.45));
        c.closePath(); c.fill();
      } else if (s.t === 'num') {
        var r = numR();
        c.fillStyle = color; c.beginPath(); c.arc(s.x, s.y, r, 0, 2 * Math.PI); c.fill();
        c.fillStyle = '#fff'; c.font = 'bold ' + Math.round(r * 1.25) + 'px sans-serif';
        c.textAlign = 'center'; c.textBaseline = 'middle'; c.fillText(String(num), s.x, s.y + 1);
      }
    }
    function drawAll(c, withSel) {
      var num = 0;
      shapes.forEach(function(s, i) {
        if (s.t === 'num') num++;
        drawShape(c, s, num);
        if (withSel && i === selected) {
          var b = shapeBBox(s); c.strokeStyle = '#1e73be'; c.lineWidth = 2; c.setLineDash([6, 4]);
          c.strokeRect(b.x - 4, b.y - 4, b.w + 8, b.h + 8); c.setLineDash([]);
        }
      });
    }
    function redraw(preview) {
      if (!canvas.width) return;
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(imgEl, 0, 0, canvas.width, canvas.height);
      drawAll(ctx, true);
      if (preview) drawShape(ctx, preview, 0);
    }
    function pos(e) {
      var r = canvas.getBoundingClientRect();
      return { x: (e.clientX - r.left) * (canvas.width / r.width),
               y: (e.clientY - r.top) * (canvas.height / r.height) };
    }

    var drawing = false, start = null, moving = false, moveOff = null;
    canvas.addEventListener('pointerdown', function(e) {
      var p = pos(e);
      try { canvas.setPointerCapture(e.pointerId); } catch (err) {}
      if (ANNOT && tool === 'select') {
        selected = -1;
        for (var i = shapes.length - 1; i >= 0; i--) { if (hit(shapes[i], p.x, p.y)) { selected = i; break; } }
        if (selected >= 0) { moving = true; moveOff = { x: p.x, y: p.y }; }
        redraw(); return;
      }
      if (ANNOT && tool === 'num') { shapes.push({ t: 'num', x: p.x, y: p.y }); selected = shapes.length - 1; redraw(); return; }
      drawing = true; start = p;
    });
    canvas.addEventListener('pointermove', function(e) {
      var p = pos(e);
      if (moving && selected >= 0) {
        var dx = p.x - moveOff.x, dy = p.y - moveOff.y, s = shapes[selected];
        if (s.t === 'rect') { s.x += dx; s.y += dy; }
        else if (s.t === 'arrow') { s.x1 += dx; s.y1 += dy; s.x2 += dx; s.y2 += dy; }
        else { s.x += dx; s.y += dy; }
        moveOff = p; redraw(); return;
      }
      if (!drawing) return;
      var prev = (ANNOT && tool === 'arrow')
        ? { t: 'arrow', x1: start.x, y1: start.y, x2: p.x, y2: p.y }
        : { t: 'rect', x: Math.min(start.x, p.x), y: Math.min(start.y, p.y), w: Math.abs(p.x - start.x), h: Math.abs(p.y - start.y) };
      redraw(prev);
    });
    canvas.addEventListener('pointerup', function(e) {
      if (moving) { moving = false; return; }
      if (!drawing) return;
      drawing = false;
      var p = pos(e);
      if (ANNOT && tool === 'arrow') {
        if (Math.abs(p.x - start.x) > 6 || Math.abs(p.y - start.y) > 6) {
          shapes.push({ t: 'arrow', x1: start.x, y1: start.y, x2: p.x, y2: p.y }); selected = shapes.length - 1;
        }
      } else {
        var r = { t: 'rect', x: Math.min(start.x, p.x), y: Math.min(start.y, p.y), w: Math.abs(p.x - start.x), h: Math.abs(p.y - start.y) };
        if (r.w > 3 && r.h > 3) { shapes.push(r); selected = shapes.length - 1; }
      }
      redraw();
    });

    function close() { overlay.remove(); document.removeEventListener('keydown', onKey); }
    function onKey(e) {
      if ((e.key === 'Delete' || e.key === 'Backspace') && selected >= 0) {
        e.preventDefault(); shapes.splice(selected, 1); selected = -1; redraw();
      }
    }

    function markState(on) {
      ['image', 'projectImage'].forEach(function(did) {
        (self.dropdownData[did] || []).forEach(function(it) {
          if (it.value === name) it[MODE.stateKey] = on;
        });
      });
      lakBtn.setAttribute(MODE.stateAttr, on ? '1' : '0');
      lakBtn.textContent = on ? MODE.on : MODE.off;
      lakBtn.classList.toggle('has-lakken', on);
    }

    closeX.addEventListener('click', close);
    overlay.addEventListener('click', function(e) { if (e.target === overlay) close(); });
    document.addEventListener('keydown', onKey);
    undoBtn.addEventListener('click', function() { shapes.pop(); selected = -1; redraw(); });
    delSelBtn.addEventListener('click', function() { if (selected >= 0) { shapes.splice(selected, 1); selected = -1; redraw(); } });
    clearBtn.addEventListener('click', function() { shapes = []; selected = -1; redraw(); });
    if (delBtn) delBtn.addEventListener('click', function() {
      fetch(endpoint, { method: 'DELETE', credentials: 'same-origin',
                        headers: { 'X-CSRFToken': _csrfToken() } })
        .then(function(r) { return r.json(); })
        .then(function() { markState(false); close(); })
        .catch(function() { close(); });
    });

    function exportDataUrl() {
      var off = document.createElement('canvas'); off.width = canvas.width; off.height = canvas.height;
      var c = off.getContext('2d');
      if (ANNOT) {
        c.drawImage(imgEl, 0, 0, off.width, off.height);
        drawAll(c, false);
      } else {
        if (existingLayerImg && !vanafOrigineel) c.drawImage(existingLayerImg, 0, 0, off.width, off.height);
        drawAll(c, false);  // alleen de zwarte vlakken op transparant
      }
      return off.toDataURL('image/png');
    }
    saveBtn.addEventListener('click', function() {
      var dataUrl;
      try { dataUrl = exportDataUrl(); }
      catch (err) { hint.textContent = 'Opslaan mislukt: kon de afbeelding niet lezen.'; return; }
      saveBtn.disabled = true; saveBtn.textContent = 'Opslaan…';
      fetch(endpoint, {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': _csrfToken() },
        body: JSON.stringify({ image: dataUrl })
      }).then(function(r) { return r.json(); }).then(function(d) {
        if (d && d.ok) { markState(true); close(); }
        else {
          saveBtn.disabled = false; saveBtn.textContent = 'Opslaan';
          hint.textContent = 'Opslaan mislukt: ' + ((d && d.error) || 'onbekende fout');
        }
      }).catch(function() {
        saveBtn.disabled = false; saveBtn.textContent = 'Opslaan';
        hint.textContent = 'Opslaan mislukt (netwerk).';
      });
    });

    document.body.appendChild(overlay);
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

      var lakBtn = e.target.closest('.latex-item-lak');
      if (lakBtn) {
        e.preventDefault();
        self._openScreenshotRedactor(lakBtn);
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
    // Highlight-backdrop opnieuw uitlijnen (fullscreen wijzigt de textarea-stijl).
    if (this.textarea && this.textarea._lxHl) setTimeout(this.textarea._lxHl, 0);
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

  // Eenvoudige één-argument-macro's (id == LaTeX-commando): wikkel de selectie
  // of plaats de cursor tussen de accolades. Alle in rapport.sty gedefinieerd.
  var SIMPLE_MACROS = {
    cvss: 1, severity: 1, cwe: 1, cve: 1, owasp: 1, bevindingref: 1,
    pad: 1, host: 1, route: 1, param: 1, port: 1, proto: 1,
    waarschuwing: 1, tip: 1, opmerking: 1, stap: 1,
    bestuurlijk: 1, principe: 1, letop: 1, praktijk: 1, keten: 1, scenario: 1,
    mitre: 1, url: 1, footnote: 1, kbd: 1, highlight: 1, iso: 1, bio: 1, nist: 1
  };

  var _FP_SEVCOLOR = { critical: '#6b0000', high: '#d4351c', medium: '#f47738', low: '#b58b00', none: '#5a6b7b' };

  // Bevinding-kiezer: haalt de bevindingen van de actieve opdracht op en laat
  // de gebruiker er één kiezen (i.p.v. een id te typen). CSP-schoon (klassen +
  // CSSOM, geen inline style-attributen).
  LaTeXEditor.prototype._openFindingPicker = function(onPick) {
    var old = document.getElementById('lx-finding-picker');
    if (old) old.parentNode.removeChild(old);

    var ov = document.createElement('div');
    ov.id = 'lx-finding-picker';
    ov.className = 'lx-fp-overlay';
    var box = document.createElement('div'); box.className = 'lx-fp-box';
    var head = document.createElement('div'); head.className = 'lx-fp-head';
    var title = document.createElement('span'); title.textContent = 'Bevinding kiezen';
    var closeBtn = document.createElement('button'); closeBtn.type = 'button';
    closeBtn.className = 'lx-fp-close'; closeBtn.innerHTML = '&times;';
    head.appendChild(title); head.appendChild(closeBtn);
    var search = document.createElement('input'); search.type = 'text';
    search.className = 'lx-fp-search'; search.placeholder = 'Zoek op naam, locatie of #id…';
    var list = document.createElement('div'); list.className = 'lx-fp-list';
    var msg = document.createElement('p'); msg.className = 'lx-fp-msg'; msg.textContent = 'Laden…';
    list.appendChild(msg);
    box.appendChild(head); box.appendChild(search); box.appendChild(list);
    ov.appendChild(box); document.body.appendChild(ov);

    function close() { if (ov.parentNode) ov.parentNode.removeChild(ov); document.removeEventListener('keydown', onKey); }
    function onKey(e) { if (e.key === 'Escape') close(); }
    closeBtn.addEventListener('click', close);
    ov.addEventListener('click', function(e) { if (e.target === ov) close(); });
    document.addEventListener('keydown', onKey);

    var all = [];
    function render(filter) {
      var f = (filter || '').toLowerCase().trim();
      var rows = all.filter(function(x) {
        return !f || String(x.id).indexOf(f) >= 0
          || (x.naam || '').toLowerCase().indexOf(f) >= 0
          || (x.locatie || '').toLowerCase().indexOf(f) >= 0;
      });
      list.innerHTML = '';
      if (!rows.length) {
        var m = document.createElement('p'); m.className = 'lx-fp-msg';
        m.textContent = 'Geen bevindingen gevonden.'; list.appendChild(m); return;
      }
      rows.forEach(function(x) {
        var row = document.createElement('button'); row.type = 'button'; row.className = 'lx-fp-row';
        var dot = document.createElement('span'); dot.className = 'lx-fp-dot';
        dot.style.background = _FP_SEVCOLOR[x.severity] || '#999';   // CSSOM: toegestaan onder CSP
        row.appendChild(dot);
        var strong = document.createElement('strong'); strong.textContent = '#' + x.id + ' ';
        row.appendChild(strong);
        row.appendChild(document.createTextNode(x.naam || '(zonder naam)'));
        if (x.locatie) {
          var loc = document.createElement('span'); loc.className = 'lx-fp-loc';
          loc.textContent = ' — ' + x.locatie; row.appendChild(loc);
        }
        row.addEventListener('click', function() { onPick(x.id); close(); });
        list.appendChild(row);
      });
    }
    search.addEventListener('input', function() { render(search.value); });

    fetch('/api/findings', { credentials: 'same-origin' })
      .then(function(r) { return r.json(); })
      .then(function(d) { all = (d && d.findings) || []; render(''); try { search.focus(); } catch (e) {} })
      .catch(function() { list.innerHTML = ''; var m = document.createElement('p');
        m.className = 'lx-fp-msg'; m.textContent = 'Kon bevindingen niet laden.'; list.appendChild(m); });
  };

  var _KADER_PRESETS = [
    { label: 'Eigen', kleur: 'kaderblauw', titel: '' },
    { label: 'Waarschuwing', kleur: 'kaderrood', titel: 'Waarschuwing' },
    { label: 'Tip', kleur: 'kadergroen', titel: 'Tip' },
    { label: 'Opmerking', kleur: 'kaderblauw', titel: 'Opmerking' },
    { label: 'Bestuurlijke kern', kleur: 'kaderblauw', titel: 'Bestuurlijke kern' },
    { label: 'Leidend principe', kleur: 'kadergroen', titel: 'Leidend principe' },
    { label: 'Aandachtspunt', kleur: 'kaderoranje', titel: 'Aandachtspunt' },
    { label: 'Praktische toepassing', kleur: 'kaderblauw', titel: 'Praktische toepassing' },
    { label: 'Ketenperspectief', kleur: 'kaderpaars', titel: 'Ketenperspectief' },
    { label: 'Ketenscenario', kleur: 'kadergrijs', titel: 'Ketenscenario' }
  ];
  var _KADER_KLEUREN = [
    { v: 'kaderblauw', l: 'Blauw' }, { v: 'kadergroen', l: 'Groen' },
    { v: 'kaderoranje', l: 'Oranje' }, { v: 'kaderpaars', l: 'Paars' },
    { v: 'kadergrijs', l: 'Grijs' }, { v: 'kaderrood', l: 'Rood' }
  ];

  LaTeXEditor.prototype._openCalloutDialog = function(preselected, onInsert, prefill) {
    prefill = prefill || {};
    var old = document.getElementById('lx-kader-dialog');
    if (old) old.parentNode.removeChild(old);
    var ov = document.createElement('div'); ov.id = 'lx-kader-dialog'; ov.className = 'lx-fp-overlay';
    var box = document.createElement('div'); box.className = 'lx-fp-box';
    var head = document.createElement('div'); head.className = 'lx-fp-head';
    var ht = document.createElement('span'); ht.textContent = prefill.edit ? 'Kader bewerken' : 'Kader invoegen';
    var hx = document.createElement('button'); hx.type = 'button'; hx.className = 'lx-fp-close'; hx.innerHTML = '&times;';
    head.appendChild(ht); head.appendChild(hx); box.appendChild(head);

    function field(labelText, el) {
      var w = document.createElement('label'); w.className = 'lx-fp-field';
      var s = document.createElement('span'); s.className = 'lx-fp-label'; s.textContent = labelText;
      w.appendChild(s); w.appendChild(el); return w;
    }
    var preset = document.createElement('select'); preset.className = 'lx-fp-search';
    _KADER_PRESETS.forEach(function(p) { var o = document.createElement('option'); o.value = p.label; o.textContent = p.label; preset.appendChild(o); });
    var kleur = document.createElement('select'); kleur.className = 'lx-fp-search';
    _KADER_KLEUREN.forEach(function(c) { var o = document.createElement('option'); o.value = c.v; o.textContent = c.l; kleur.appendChild(o); });
    var titel = document.createElement('input'); titel.type = 'text'; titel.className = 'lx-fp-search'; titel.placeholder = 'Titel van het kader';
    var inhoud = document.createElement('textarea'); inhoud.className = 'lx-fp-search'; inhoud.rows = 5;
    inhoud.placeholder = 'Inhoud…'; inhoud.value = (prefill.inhoud != null ? prefill.inhoud : (preselected || ''));
    if (prefill.kleur) kleur.value = prefill.kleur;
    if (prefill.titel != null) titel.value = prefill.titel;
    box.appendChild(field('Voorinstelling', preset));
    box.appendChild(field('Kleur', kleur));
    box.appendChild(field('Titel', titel));
    box.appendChild(field('Inhoud', inhoud));

    var act = document.createElement('div'); act.className = 'lx-fp-actions';
    var ins = document.createElement('button'); ins.type = 'button'; ins.className = 'btn btn-primary btn-sm'; ins.textContent = prefill.edit ? 'Bijwerken' : 'Invoegen';
    var cancel = document.createElement('button'); cancel.type = 'button'; cancel.className = 'btn btn-sm'; cancel.textContent = 'Annuleren';
    act.appendChild(ins); act.appendChild(cancel); box.appendChild(act);
    ov.appendChild(box); document.body.appendChild(ov);

    function close() { if (ov.parentNode) ov.parentNode.removeChild(ov); document.removeEventListener('keydown', onKey); }
    function onKey(e) { if (e.key === 'Escape') close(); }
    hx.addEventListener('click', close); cancel.addEventListener('click', close);
    ov.addEventListener('click', function(e) { if (e.target === ov) close(); });
    document.addEventListener('keydown', onKey);
    preset.addEventListener('change', function() {
      var p = _KADER_PRESETS.filter(function(z) { return z.label === preset.value; })[0];
      if (p) { kleur.value = p.kleur; if (p.titel) titel.value = p.titel; }
    });
    ins.addEventListener('click', function() {
      onInsert(kleur.value, (titel.value || '').trim() || 'Kader', inhoud.value || '');
      close();
    });
    setTimeout(function() { try { titel.focus(); } catch (e) {} }, 0);
  };

  // --- Hulp voor de blok-modals (HTTP + code) ------------------------------
  // Markeertypes: geel=hl, rood=hlrood, groen=hlgroen, lak=lakken. In de body-
  // textarea staan ze als «inhoud» (geel) of «r:..»/«g:..»/«x:..».
  var _MARK_MACRO = { '': 'hl', r: 'hlrood', g: 'hlgroen', x: 'lakken' };
  var _MACRO_TAG = { hl: '', highlight: '', hlrood: 'r', hlgroen: 'g', lakken: 'x', codelakken: 'x' };
  var _MARK_TYPES = [
    { v: '', l: 'Geel (nadruk)' }, { v: 'r', l: 'Rood (kwetsbaar)' },
    { v: 'g', l: 'Groen (resultaat)' }, { v: 'x', l: 'Lakken (geheim)' }
  ];
  function _markClass(tag) {
    return tag === 'r' ? 'lx-m-rood' : tag === 'g' ? 'lx-m-groen'
      : tag === 'x' ? 'lx-m-lak' : 'lx-m-geel';
  }
  // Keer _escLatex om, zodat een opgeslagen blok leesbaar terug in de modal komt.
  function _unescLatex(s) {
    return (s || '')
      .replace(/\\textbackslash\{\}/g, '\u0001BS\u0001')
      .replace(/\\textasciitilde\{\}/g, '~')
      .replace(/\\textasciicircum\{\}/g, '^')
      .replace(/\\([&%$#_{}])/g, '$1')
      .replace(/\u0001BS\u0001/g, '\\');
  }
  // Lees een gebalanceerde {..}-groep (respecteert \{ en \}); pos wijst op '{'.
  function _readBracedJS(s, pos) {
    if (s.charAt(pos) !== '{') return null;
    var depth = 0, i = pos, n = s.length;
    while (i < n) {
      var c = s.charAt(i);
      if (c === '\\' && i + 1 < n) { i += 2; continue; }
      if (c === '{') { depth++; }
      else if (c === '}') { depth--; if (depth === 0) return { inner: s.slice(pos + 1, i), end: i + 1 }; }
      i++;
    }
    return null;
  }
  // Request/response-body (ge-escaped + mark-macro's) -> rauwe tekst met «»-markers.
  function _httpBodyToMarkers(s) {
    var hre = /\\(hl|highlight|hlrood|hlgroen|lakken|codelakken)\s*\{/g, out = '', last = 0, m;
    while ((m = hre.exec(s))) {
      var br = _readBracedJS(s, m.index + m[0].length - 1);
      if (!br) { hre.lastIndex = m.index + m[0].length; continue; }
      var tag = _MACRO_TAG[m[1]] || '';
      out += _unescLatex(s.slice(last, m.index)) + '«' + (tag ? tag + ':' : '') + _unescLatex(br.inner) + '»';
      last = br.end; hre.lastIndex = last;
    }
    out += _unescLatex(s.slice(last));
    return out;
  }
  // lstlisting-body (verbatim + §\macro{}§) -> rauwe code met «»-markers.
  function _lstBodyToMarkers(code) {
    return (code || '').replace(/§\\(hl|highlight|hlrood|hlgroen|lakken|codelakken)\{([\s\S]*?)\}§/g,
      function(_m, name, inner) {
        var tag = _MACRO_TAG[name] || '';
        return '«' + (tag ? tag + ':' : '') + _unescLatex(inner) + '»';
      });
  }
  // Markers -> LaTeX. mode 'http' => \macro{}, 'code' => §\macro{}§ (+ verbatim).
  function _markersToLatex(raw, mode) {
    return raw.split(/(«(?:[rgx]:)?[\s\S]*?»)/).map(function(seg) {
      var mm = /^«(?:([rgx]):)?([\s\S]*)»$/.exec(seg);
      if (mm) {
        var mac = _MARK_MACRO[mm[1] || ''];
        return mode === 'code' ? ('§\\' + mac + '{' + _escLatex(mm[2]) + '}§')
          : ('\\' + mac + '{' + _escLatex(mm[2]) + '}');
      }
      return mode === 'code' ? seg.replace(/§/g, '?') : _escLatex(seg);
    }).join('');
  }
  // Live-arcering achter de textarea: «..» met kleur per type.
  function _attachHighlighter(ta) {
    var wrap = document.createElement('div'); wrap.className = 'lx-hl-wrap';
    var back = document.createElement('div'); back.className = 'lx-hl-backdrop';
    ta.parentNode.insertBefore(wrap, ta);
    wrap.appendChild(back); wrap.appendChild(ta);
    function esc(s) { return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
    function render() {
      back.innerHTML = esc(ta.value).replace(/«(?:([rgx]):)?([\s\S]*?)»/g, function(_m, tag, inner) {
        return '<mark class="' + _markClass(tag || '') + '">«' + (tag ? tag + ':' : '') + inner + '»</mark>';
      }) + '\n';
      back.scrollTop = ta.scrollTop; back.scrollLeft = ta.scrollLeft;
    }
    ta.addEventListener('input', render);
    ta.addEventListener('scroll', function() { back.scrollTop = ta.scrollTop; back.scrollLeft = ta.scrollLeft; });
    ta._lxRender = render; render();
  }
  // Markeer-knoppen (type-select + markeer + weg).
  function _bindMarkControls(body, sel, markBtn, unmarkBtn) {
    markBtn.addEventListener('click', function() {
      var a = body.selectionStart, b = body.selectionEnd;
      if (a === b) { body.focus(); return; }
      var inner = body.value.slice(a, b).replace(/«(?:[rgx]:)?|»/g, '');
      var tag = sel.value, pre = '«' + (tag ? tag + ':' : '');
      body.value = body.value.slice(0, a) + pre + inner + '»' + body.value.slice(b);
      if (body._lxRender) body._lxRender();
      body.focus(); body.selectionStart = a; body.selectionEnd = a + pre.length + inner.length + 1;
    });
    unmarkBtn.addEventListener('click', function() {
      var a = body.selectionStart, b = body.selectionEnd;
      var strip = function(t) { return t.replace(/«(?:[rgx]:)?|»/g, ''); };
      if (a === b) { body.value = strip(body.value); }
      else { body.value = body.value.slice(0, a) + strip(body.value.slice(a, b)) + body.value.slice(b); }
      if (body._lxRender) body._lxRender();
      body.focus();
    });
  }
  // Sneltoetsen in de body: Tab -> 2 spaties, Cmd/Ctrl+Enter -> submit.
  function _bindAreaKeys(ta, submit) {
    ta.addEventListener('keydown', function(e) {
      if (e.key === 'Tab' && !e.shiftKey && !e.metaKey && !e.ctrlKey && !e.altKey) {
        e.preventDefault();
        var a = ta.selectionStart, b = ta.selectionEnd;
        ta.value = ta.value.slice(0, a) + '  ' + ta.value.slice(b);
        ta.selectionStart = ta.selectionEnd = a + 2;
        if (ta._lxRender) ta._lxRender();
      } else if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
        e.preventDefault(); submit();
      }
    });
  }
  // Auto-caption uit de eerste request-/statusregel.
  function _detectHttpCaption(text, kind) {
    if (kind === 'response') {
      var r = /^HTTP\/\d(?:\.\d)?\s+(\d{3}[^\n]*)/m.exec(text || '');
      return r ? r[1].trim() : '';
    }
    var m = /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s+(\S+)/m.exec(text || '');
    return m ? (m[1] + ' ' + m[2]) : '';
  }
  // Taal raden uit de code-inhoud.
  function _detectLang(code) {
    code = code || '';
    if (/^#!.*\bpython/m.test(code) || /^\s*def\s+\w+\s*\(.*\)\s*:/m.test(code)) return 'Python';
    if (/^#!.*\b(bash|sh|zsh)\b/m.test(code)) return 'bash';
    if (/<\?php/.test(code)) return 'PHP';
    if (/^\s*(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP)\b/im.test(code)) return 'SQL';
    if (/<!DOCTYPE html|<html[\s>]/i.test(code)) return 'HTML';
    if (/^\s*(public|private|protected)\s+(class|static|final)\b/m.test(code)) return 'Java';
    if (/#include\b|\bint\s+main\s*\(/.test(code)) return 'C';
    if (/\b(Get-|Set-|New-|Invoke-)\w+|\$PSItem|\bparam\s*\(/.test(code)) return 'PowerShell';
    if (/\b(function|const|let|=>)\b/.test(code) && /[;{]/.test(code)) return 'JavaScript';
    return '';
  }
  // Markeer vermoedelijke geheimen in een HTTP-body als «x:..» (lak).
  function _autoRedactHttp(text) {
    function wrap(v) { return '«x:' + v + '»'; }
    return (text || '').split('\n').map(function(line) {
      if (line.indexOf('«') >= 0) return line;           // al gemarkeerd
      var m;
      if ((m = /^((?:Proxy-)?Authorization:\s*)(.+)$/i.exec(line))) return m[1] + wrap(m[2].trim());
      if ((m = /^((?:Set-)?Cookie:\s*)(.+)$/i.exec(line))) return m[1] + wrap(m[2].trim());
      line = line.replace(/\b(Bearer|Basic)\s+([A-Za-z0-9+/=._\-]{8,})/g, function(_m, s, t) { return s + ' ' + wrap(t); });
      line = line.replace(/\b(password|passwd|pwd|token|access_token|refresh_token|api[_-]?key|secret|sessionid|session|jsessionid|phpsessid|csrf|authenticity_token)(=|["']?\s*:\s*["']?)([^&;"'\s]+)/gi,
        function(_m, k, sep, v) { return k + sep + wrap(v); });
      return line;
    }).join('\n');
  }
  // Splits een geplakte request+response in twee delen (of null).
  function _splitReqResp(text) {
    var m = /(^|\n)\s*\nHTTP\/\d(?:\.\d)?\s+\d{3}/.exec(text || '');
    if (!m) { var m2 = /\nHTTP\/\d(?:\.\d)?\s+\d{3}/.exec(text || ''); if (!m2 || m2.index < 3) return null; m = m2; }
    var idx = (text.indexOf('HTTP/', m.index));
    if (idx <= 0) return null;
    return { req: text.slice(0, idx).replace(/\s+$/, ''), resp: text.slice(idx).replace(/^\s+/, '') };
  }
  function _miniPreviewPanel() {
    var p = document.createElement('div'); p.className = 'lx-mini-preview'; return p;
  }

  // HTTP-blok (\request/\response): modal met caption, highlight (kleuren + lak),
  // auto-caption, geheimen-lakken, response-splitsen en live-voorbeeld.
  // opts = {kind, caption, body, onInsert, edit}.
  LaTeXEditor.prototype._openHttpDialog = function(opts) {
    opts = opts || {}; var self = this;
    var kind = opts.kind === 'response' ? 'response' : 'request';
    var isReq = (kind === 'request');
    var old = document.getElementById('lx-http-dialog');
    if (old) old.parentNode.removeChild(old);
    var ov = document.createElement('div'); ov.id = 'lx-http-dialog'; ov.className = 'lx-fp-overlay';
    var box = document.createElement('div'); box.className = 'lx-fp-box lx-http-box';
    var head = document.createElement('div'); head.className = 'lx-fp-head';
    var ht = document.createElement('span');
    ht.textContent = (isReq ? 'Request' : 'Response') + (opts.edit ? ' bewerken' : ' invoegen');
    var hx = document.createElement('button'); hx.type = 'button'; hx.className = 'lx-fp-close'; hx.innerHTML = '&times;';
    head.appendChild(ht); head.appendChild(hx); box.appendChild(head);

    function field(labelText, el) {
      var w = document.createElement('label'); w.className = 'lx-fp-field';
      var s = document.createElement('span'); s.className = 'lx-fp-label'; s.textContent = labelText;
      w.appendChild(s); w.appendChild(el); return w;
    }
    var cap = document.createElement('input'); cap.type = 'text'; cap.className = 'lx-fp-search';
    cap.placeholder = isReq ? 'bijv. GET /dashboard/notes/edit/51 (auto)' : 'bijv. 500 Internal Server Error (auto)';
    cap.value = opts.caption || '';
    var body = document.createElement('textarea'); body.className = 'lx-codearea'; body.rows = 12;
    body.placeholder = isReq ? 'Plak hier het volledige HTTP-request…' : 'Plak hier de HTTP-response…';
    body.value = opts.body || '';
    box.appendChild(field('Caption / locatie', cap));
    box.appendChild(field('Inhoud', body));

    // Markeer-rij: type-select + markeer + weg + geheimen lakken.
    var mrow = document.createElement('div'); mrow.className = 'lx-http-tools';
    var sel = document.createElement('select'); sel.className = 'lx-fp-search lx-mark-type';
    _MARK_TYPES.forEach(function(t) { var o = document.createElement('option'); o.value = t.v; o.textContent = t.l; sel.appendChild(o); });
    var markBtn = document.createElement('button'); markBtn.type = 'button'; markBtn.className = 'btn btn-sm lx-http-mark'; markBtn.textContent = 'Markeer selectie';
    var unmarkBtn = document.createElement('button'); unmarkBtn.type = 'button'; unmarkBtn.className = 'btn btn-sm'; unmarkBtn.textContent = 'Markering weg';
    var lakBtn = document.createElement('button'); lakBtn.type = 'button'; lakBtn.className = 'btn btn-sm'; lakBtn.textContent = '🛡 Lak geheimen';
    mrow.appendChild(sel); mrow.appendChild(markBtn); mrow.appendChild(unmarkBtn); mrow.appendChild(lakBtn);
    box.appendChild(mrow);

    // Optie-rij: response splitsen (alleen bij nieuw blok, als gedetecteerd).
    var orow = document.createElement('div'); orow.className = 'lx-http-tools lx-code-numrow';
    var splitChk = document.createElement('input'); splitChk.type = 'checkbox'; splitChk.className = 'lx-code-numchk'; splitChk.id = 'lx-http-split';
    var splitLbl = document.createElement('label'); splitLbl.className = 'lx-http-hint'; splitLbl.setAttribute('for', 'lx-http-split');
    splitLbl.textContent = 'Response apart meesturen (gedetecteerd)';
    orow.appendChild(splitChk); orow.appendChild(splitLbl); box.appendChild(orow);
    orow.classList.add('lx-hidden');
    function refreshSplit() {
      if (opts.edit) { orow.classList.add('lx-hidden'); return; }
      var sp = isReq ? _splitReqResp(body.value) : null;
      if (sp) { orow.classList.remove('lx-hidden'); if (!splitChk._touched) splitChk.checked = true; }
      else { orow.classList.add('lx-hidden'); }
    }
    splitChk.addEventListener('change', function() { splitChk._touched = true; });

    var hint = document.createElement('div'); hint.className = 'lx-http-hint';
    hint.textContent = 'Selecteer tekst en kies een markering; geheimen lakken maskeert ze in het gelakte rapport.';
    box.appendChild(hint);

    var pvBtn = document.createElement('button'); pvBtn.type = 'button'; pvBtn.className = 'btn btn-sm lx-pv-btn'; pvBtn.textContent = '👁 Voorbeeld';
    var pv = _miniPreviewPanel();
    box.appendChild(pvBtn); box.appendChild(pv);

    var act = document.createElement('div'); act.className = 'lx-fp-actions';
    var ins = document.createElement('button'); ins.type = 'button'; ins.className = 'btn btn-primary btn-sm';
    ins.textContent = opts.edit ? 'Bijwerken' : 'Invoegen';
    var cancel = document.createElement('button'); cancel.type = 'button'; cancel.className = 'btn btn-sm'; cancel.textContent = 'Annuleren';
    act.appendChild(ins); act.appendChild(cancel); box.appendChild(act);
    ov.appendChild(box); document.body.appendChild(ov);
    _attachHighlighter(body);

    function close() { if (ov.parentNode) ov.parentNode.removeChild(ov); document.removeEventListener('keydown', onKey); }
    function onKey(e) { if (e.key === 'Escape') close(); }
    hx.addEventListener('click', close); cancel.addEventListener('click', close);
    ov.addEventListener('click', function(e) { if (e.target === ov) close(); });
    document.addEventListener('keydown', onKey);
    _bindMarkControls(body, sel, markBtn, unmarkBtn);
    _bindAreaKeys(body, function() { ins.click(); });

    lakBtn.addEventListener('click', function() {
      body.value = _autoRedactHttp(body.value);
      if (body._lxRender) body._lxRender(); body.focus();
    });
    body.addEventListener('input', function() {
      if (!cap.value.trim()) { var c = _detectHttpCaption(body.value, kind); if (c) cap.value = c; }
      refreshSplit();
    });
    refreshSplit();

    function buildOne(k, rawBody, capText) {
      return '\\' + k + '{' + _escLatex((capText || '').trim()) + '}{' + _markersToLatex(rawBody, 'http') + '}';
    }
    function buildLatex() {
      if (isReq && !opts.edit && splitChk.checked && !orow.classList.contains('lx-hidden')) {
        var sp = _splitReqResp(body.value);
        if (sp) {
          return buildOne('request', sp.req, cap.value || _detectHttpCaption(sp.req, 'request'))
            + '\n\n' + buildOne('response', sp.resp, _detectHttpCaption(sp.resp, 'response'));
        }
      }
      return buildOne(kind, body.value, cap.value);
    }
    pvBtn.addEventListener('click', function() { self._previewInto(buildLatex(), pv); });
    ins.addEventListener('click', function() {
      if (opts.onInsert) opts.onInsert(buildLatex());
      close();
    });
    setTimeout(function() { try { body.focus(); } catch (e) {} }, 0);
  };

  // Code-blok (lstlisting): modal met caption, taal (auto), regelnummers,
  // highlight (kleuren + lak) en live-voorbeeld. opts = {caption, language,
  // body, numbers, firstnumber, onInsert, edit}.
  LaTeXEditor.prototype._openCodeDialog = function(opts) {
    opts = opts || {}; var self = this;
    var old = document.getElementById('lx-code-dialog');
    if (old) old.parentNode.removeChild(old);
    var ov = document.createElement('div'); ov.id = 'lx-code-dialog'; ov.className = 'lx-fp-overlay';
    var box = document.createElement('div'); box.className = 'lx-fp-box lx-http-box';
    var head = document.createElement('div'); head.className = 'lx-fp-head';
    var ht = document.createElement('span'); ht.textContent = 'Code-blok ' + (opts.edit ? 'bewerken' : 'invoegen');
    var hx = document.createElement('button'); hx.type = 'button'; hx.className = 'lx-fp-close'; hx.innerHTML = '&times;';
    head.appendChild(ht); head.appendChild(hx); box.appendChild(head);

    function field(labelText, el) {
      var w = document.createElement('label'); w.className = 'lx-fp-field';
      var s = document.createElement('span'); s.className = 'lx-fp-label'; s.textContent = labelText;
      w.appendChild(s); w.appendChild(el); return w;
    }
    var cap = document.createElement('input'); cap.type = 'text'; cap.className = 'lx-fp-search';
    cap.placeholder = 'bijv. deploy.sh of Listing 1 (optioneel)'; cap.value = opts.caption || '';
    var lang = document.createElement('input'); lang.type = 'text'; lang.className = 'lx-fp-search';
    lang.setAttribute('list', 'lx-code-langs');
    lang.placeholder = 'bijv. bash, Python, SQL (auto)';
    var lastLang = '';
    try { lastLang = window.localStorage.getItem('lx_last_lang') || ''; } catch (e) {}
    lang.value = opts.language || lastLang || '';
    var dl = document.createElement('datalist'); dl.id = 'lx-code-langs';
    ['bash', 'Python', 'SQL', 'PHP', 'JavaScript', 'Java', 'C', 'C++', 'C#',
     'Ruby', 'Go', 'XML', 'HTML', 'PowerShell', 'TeX'].forEach(function(l) {
      var o = document.createElement('option'); o.value = l; dl.appendChild(o);
    });
    lang.appendChild(dl);
    var body = document.createElement('textarea'); body.className = 'lx-codearea'; body.rows = 12;
    body.placeholder = 'Plak of typ hier de code…'; body.value = opts.body || '';
    var lbl = document.createElement('input'); lbl.type = 'text'; lbl.className = 'lx-fp-search';
    lbl.placeholder = 'bijv. lst:deploy — verwijzen met \\ref{lst:deploy} (optioneel)';
    lbl.value = opts.label || '';
    box.appendChild(field('Caption / titel', cap));
    box.appendChild(field('Taal', lang));
    box.appendChild(field('Label (verwijzing)', lbl));
    box.appendChild(field('Code', body));

    // Regelnummers + beginregel.
    var numRow = document.createElement('div'); numRow.className = 'lx-http-tools lx-code-numrow';
    var numChk = document.createElement('input'); numChk.type = 'checkbox'; numChk.className = 'lx-code-numchk';
    numChk.id = 'lx-code-numbers'; numChk.checked = !!opts.numbers;
    var numLbl = document.createElement('label'); numLbl.className = 'lx-http-hint'; numLbl.setAttribute('for', 'lx-code-numbers'); numLbl.textContent = 'Regelnummers';
    var fromLbl = document.createElement('span'); fromLbl.className = 'lx-http-hint'; fromLbl.textContent = 'vanaf regel';
    var fromInp = document.createElement('input'); fromInp.type = 'number'; fromInp.min = '1';
    fromInp.className = 'lx-fp-search lx-code-from'; fromInp.value = opts.firstnumber || '1';
    numRow.appendChild(numChk); numRow.appendChild(numLbl); numRow.appendChild(fromLbl); numRow.appendChild(fromInp);
    box.appendChild(numRow);

    // Markeer-rij: type + markeer + weg.
    var mrow = document.createElement('div'); mrow.className = 'lx-http-tools';
    var sel = document.createElement('select'); sel.className = 'lx-fp-search lx-mark-type';
    _MARK_TYPES.forEach(function(t) { var o = document.createElement('option'); o.value = t.v; o.textContent = t.l; sel.appendChild(o); });
    var markBtn = document.createElement('button'); markBtn.type = 'button'; markBtn.className = 'btn btn-sm lx-http-mark'; markBtn.textContent = 'Markeer selectie';
    var unmarkBtn = document.createElement('button'); unmarkBtn.type = 'button'; unmarkBtn.className = 'btn btn-sm'; unmarkBtn.textContent = 'Markering weg';
    mrow.appendChild(sel); mrow.appendChild(markBtn); mrow.appendChild(unmarkBtn);
    box.appendChild(mrow);

    var pvBtn = document.createElement('button'); pvBtn.type = 'button'; pvBtn.className = 'btn btn-sm lx-pv-btn'; pvBtn.textContent = '👁 Voorbeeld';
    var pv = _miniPreviewPanel();
    box.appendChild(pvBtn); box.appendChild(pv);

    var act = document.createElement('div'); act.className = 'lx-fp-actions';
    var ins = document.createElement('button'); ins.type = 'button'; ins.className = 'btn btn-primary btn-sm';
    ins.textContent = opts.edit ? 'Bijwerken' : 'Invoegen';
    var cancel = document.createElement('button'); cancel.type = 'button'; cancel.className = 'btn btn-sm'; cancel.textContent = 'Annuleren';
    act.appendChild(ins); act.appendChild(cancel); box.appendChild(act);
    ov.appendChild(box); document.body.appendChild(ov);
    _attachHighlighter(body);

    function close() { if (ov.parentNode) ov.parentNode.removeChild(ov); document.removeEventListener('keydown', onKey); }
    function onKey(e) { if (e.key === 'Escape') close(); }
    hx.addEventListener('click', close); cancel.addEventListener('click', close);
    ov.addEventListener('click', function(e) { if (e.target === ov) close(); });
    document.addEventListener('keydown', onKey);
    _bindMarkControls(body, sel, markBtn, unmarkBtn);
    _bindAreaKeys(body, function() { ins.click(); });
    body.addEventListener('input', function() {
      if (!lang.value.trim()) { var l = _detectLang(body.value); if (l) lang.value = l; }
    });

    function buildLatex() {
      var langv = (lang.value || '').trim();
      var code = _markersToLatex(body.value, 'code');
      var lopts = ['escapeinside={§}{§}'];
      if (langv) lopts.push('language=' + langv);
      if (numChk.checked) {
        lopts.push('numbers=left');
        var fn = parseInt(fromInp.value, 10);
        if (fn > 1) lopts.push('firstnumber=' + fn);
      }
      var capv = (cap.value || '').trim();
      if (capv) lopts.push('caption={' + _escLatex(capv) + '}');
      var lblv = (lbl.value || '').trim().replace(/[^\w:.\-]/g, '');
      if (lblv) lopts.push('label={' + lblv + '}');
      return '\\begin{lstlisting}[' + lopts.join(',') + ']\n' + code + '\n\\end{lstlisting}';
    }
    pvBtn.addEventListener('click', function() { self._previewInto(buildLatex(), pv); });
    ins.addEventListener('click', function() {
      try { if (lang.value.trim()) window.localStorage.setItem('lx_last_lang', lang.value.trim()); } catch (e) {}
      if (opts.onInsert) opts.onInsert(buildLatex());
      close();
    });
    setTimeout(function() { try { body.focus(); } catch (e) {} }, 0);
  };

  // Afbeeldings-modal (\plaatje{bestand}{onderschrift}): kies/upload een
  // projectafbeelding, zie een thumbnail, zet het onderschrift, en beheer de
  // lak-/controle-status (zwarte vlakken via de canvas-redactor; "gecontroleerd,
  // geen lak nodig"). Bij klik op een bestaand \plaatje opent de modal voorgevuld.
  // opts = {file, caption, onInsert, edit}.
  LaTeXEditor.prototype._openImageDialog = function(opts) {
    opts = opts || {}; var self = this;
    var old = document.getElementById('lx-img-dialog');
    if (old) old.parentNode.removeChild(old);
    var ov = document.createElement('div'); ov.id = 'lx-img-dialog'; ov.className = 'lx-fp-overlay';
    var box = document.createElement('div'); box.className = 'lx-fp-box lx-img-box';
    var head = document.createElement('div'); head.className = 'lx-fp-head';
    var ht = document.createElement('span'); ht.textContent = 'Afbeelding ' + (opts.edit ? 'bewerken' : 'invoegen');
    var hx = document.createElement('button'); hx.type = 'button'; hx.className = 'lx-fp-close'; hx.innerHTML = '&times;';
    head.appendChild(ht); head.appendChild(hx); box.appendChild(head);

    function field(labelText, el) {
      var w = document.createElement('label'); w.className = 'lx-fp-field';
      var s = document.createElement('span'); s.className = 'lx-fp-label'; s.textContent = labelText;
      w.appendChild(s); w.appendChild(el); return w;
    }
    var items = (self.dropdownData && self.dropdownData.projectImage) || [];
    var status = {};   // naam -> {gecontroleerd, has_lakken, has_annot, redactable, url}
    // Val terug op de lijst-items (die has_lakken/has_annot dragen) voor
    // afbeeldingen die nog niet in het rapport worden gebruikt (en dus niet in
    // /dashboard/report/images staan). report/images voegt alleen 'gecontroleerd' toe.
    function stOf(name) {
      if (status[name]) return status[name];
      var it = items.filter(function(x) { return x.value === name; })[0];
      return it ? { has_lakken: !!it.has_lakken, has_annot: !!it.has_annot,
                    redactable: it.redactable !== false, url: it.url } : {};
    }
    function urlFor(name) {
      if (stOf(name).url) return stOf(name).url;
      var it = items.filter(function(x) { return x.value === name; })[0];
      return it ? it.url : '';
    }

    // Twee kolommen: links kiezen/uploaden, rechts voorbeeld + status + acties.
    var cols = document.createElement('div'); cols.className = 'lx-img-cols';
    var left = document.createElement('div'); left.className = 'lx-img-col';
    var right = document.createElement('div'); right.className = 'lx-img-col';
    cols.appendChild(left); cols.appendChild(right); box.appendChild(cols);

    var fileInp = document.createElement('input'); fileInp.type = 'text'; fileInp.className = 'lx-fp-search';
    fileInp.placeholder = 'bestandsnaam.png'; fileInp.value = opts.file || '';
    left.appendChild(field('Bestand', fileInp));

    var toolRow = document.createElement('div'); toolRow.className = 'lx-http-tools';
    var search = document.createElement('input'); search.type = 'text'; search.className = 'lx-fp-search'; search.placeholder = 'Zoek projectafbeelding…';
    var upBtn = document.createElement('button'); upBtn.type = 'button'; upBtn.className = 'btn btn-sm'; upBtn.textContent = '⬆ Uploaden…';
    var fileHidden = document.createElement('input'); fileHidden.type = 'file'; fileHidden.accept = 'image/*'; fileHidden.className = 'lx-hidden';
    var upStatus = document.createElement('span'); upStatus.className = 'lx-http-hint';
    toolRow.appendChild(search); toolRow.appendChild(upBtn); toolRow.appendChild(fileHidden); toolRow.appendChild(upStatus);
    left.appendChild(toolRow);

    var list = document.createElement('div'); list.className = 'lx-img-list'; left.appendChild(list);

    var cap = document.createElement('input'); cap.type = 'text'; cap.className = 'lx-fp-search';
    cap.placeholder = 'Onderschrift…'; cap.value = (opts.caption || '').replace(/\\([{}])/g, '$1').trim();
    left.appendChild(field('Onderschrift', cap));

    // Voorbeeld-schakelaar: Origineel / ⬠ Aandacht (annot) / █ Gelakt (lakken).
    var viewMode = 'orig', bust = '';
    var viewToggle = document.createElement('div'); viewToggle.className = 'lx-img-viewtoggle lx-hidden';
    var origTab = document.createElement('button'); origTab.type = 'button'; origTab.className = 'btn btn-sm'; origTab.textContent = 'Origineel';
    var annotTab = document.createElement('button'); annotTab.type = 'button'; annotTab.className = 'btn btn-sm'; annotTab.textContent = '⬠ Aandacht';
    var lakTab = document.createElement('button'); lakTab.type = 'button'; lakTab.className = 'btn btn-sm'; lakTab.textContent = '█ Gelakt';
    viewToggle.appendChild(origTab); viewToggle.appendChild(annotTab); viewToggle.appendChild(lakTab);
    right.appendChild(viewToggle);
    origTab.addEventListener('click', function() { viewMode = 'orig'; showPreview(fileInp.value.trim()); });
    annotTab.addEventListener('click', function() { viewMode = 'annot'; showPreview(fileInp.value.trim()); });
    lakTab.addEventListener('click', function() { viewMode = 'lak'; showPreview(fileInp.value.trim()); });

    var preview = document.createElement('div'); preview.className = 'lx-img-preview'; right.appendChild(preview);

    // Lak-/annotatie-/controle-acties.
    var actWrap = document.createElement('div'); actWrap.className = 'lx-img-statusbar';
    var stBadge = document.createElement('span'); stBadge.className = 'lx-img-badge';
    var annotBtn = document.createElement('button'); annotBtn.type = 'button'; annotBtn.className = 'btn btn-sm lx-img-annot'; annotBtn.textContent = '⬠ Aandachtspunt';
    var lakBtn = document.createElement('button'); lakBtn.type = 'button'; lakBtn.className = 'btn btn-sm lx-img-lak'; lakBtn.textContent = '█ Lakken';
    var ctrlBtn = document.createElement('button'); ctrlBtn.type = 'button'; ctrlBtn.className = 'btn btn-sm'; ctrlBtn.textContent = '✓ Gecontroleerd';
    actWrap.appendChild(stBadge); actWrap.appendChild(annotBtn); actWrap.appendChild(lakBtn); actWrap.appendChild(ctrlBtn);
    right.appendChild(actWrap);
    var actHint = document.createElement('div'); actHint.className = 'lx-http-hint';
    actHint.textContent = 'Aandachtspunt = rode kaders (in álle rapporten). Lakken = zwart (alleen gelakt). Gecontroleerd = geen lak nodig.';
    right.appendChild(actHint);

    function showPreview(name) {
      preview.textContent = '';
      var st = stOf(name), hasAnnot = !!st.has_annot, hasLak = !!st.has_lakken;
      viewToggle.classList.toggle('lx-hidden', !(hasAnnot || hasLak));
      annotTab.classList.toggle('lx-hidden', !hasAnnot);
      lakTab.classList.toggle('lx-hidden', !hasLak);
      if (viewMode === 'annot' && !hasAnnot) viewMode = 'orig';
      if (viewMode === 'lak' && !hasLak) viewMode = 'orig';
      origTab.classList.toggle('is-active', viewMode === 'orig');
      annotTab.classList.toggle('is-active', viewMode === 'annot');
      lakTab.classList.toggle('is-active', viewMode === 'lak');
      var base = urlFor(name);
      if (!base) { preview.textContent = name ? ('Geen voorbeeld voor: ' + name) : 'Kies of upload een afbeelding.'; preview.className = 'lx-img-preview is-empty'; return; }
      var u = base;
      if (viewMode === 'lak' && hasLak) u = '/dashboard/raw/screenshots/lakken/' + encodeURIComponent(name) + bust;
      else if (viewMode === 'annot' && hasAnnot) u = '/dashboard/raw/screenshots/annot/' + encodeURIComponent(name) + bust;
      preview.className = 'lx-img-preview';
      var img = document.createElement('img'); img.alt = name; img.src = u;
      img.addEventListener('error', function() { preview.textContent = 'Voorbeeld niet beschikbaar'; preview.className = 'lx-img-preview is-empty'; });
      preview.appendChild(img);
    }
    function updateActions(name) {
      var st = stOf(name);
      var known = !!name && (name in status || items.some(function(x) { return x.value === name; }));
      if (!name) { stBadge.textContent = ''; actWrap.classList.add('lx-hidden'); return; }
      actWrap.classList.remove('lx-hidden');
      stBadge.className = 'lx-img-badge';
      if (st.has_lakken) { stBadge.textContent = '█ Gelakt'; stBadge.classList.add('is-lak'); }
      else if (st.gecontroleerd) { stBadge.textContent = '✓ Gecontroleerd'; stBadge.classList.add('is-ctrl'); }
      else { stBadge.textContent = known ? '• Nog te beoordelen' : '• Onbekende afbeelding'; stBadge.classList.add('is-todo'); }
      if (st.has_annot) stBadge.textContent += ' ⬠';
      var canRedact = st.redactable !== false && known;
      annotBtn.classList.toggle('lx-hidden', !canRedact);
      annotBtn.textContent = st.has_annot ? '⬠ Aandacht bewerken' : '⬠ Aandachtspunt';
      lakBtn.classList.toggle('lx-hidden', !canRedact);
      lakBtn.textContent = st.has_lakken ? '█ Lak bewerken' : '█ Lakken';
      ctrlBtn.classList.toggle('lx-hidden', !known);
      ctrlBtn.textContent = st.gecontroleerd ? '✓ Controle weghalen' : '✓ Gecontroleerd';
    }
    function selectName(name) { fileInp.value = name; showPreview(name); updateActions(name); renderList(); }

    function renderList() {
      var q = (search.value || '').toLowerCase();
      list.textContent = '';
      var shown = items.filter(function(it) { return !q || (it.label || it.value).toLowerCase().indexOf(q) >= 0; });
      if (!shown.length) {
        var e = document.createElement('p'); e.className = 'lx-fp-msg';
        e.textContent = items.length ? 'Geen afbeelding gevonden.' : 'Nog geen projectafbeeldingen (upload er een).';
        list.appendChild(e); return;
      }
      shown.slice(0, 80).forEach(function(it) {
        var row = document.createElement('button'); row.type = 'button'; row.className = 'lx-img-row';
        if (it.value === fileInp.value) row.classList.add('is-active');
        var th = document.createElement('img'); th.className = 'lx-img-thumb'; th.alt = ''; th.loading = 'lazy'; th.src = it.url;
        th.addEventListener('error', function() { th.classList.add('is-broken'); });
        var nm = document.createElement('span'); nm.className = 'lx-img-name'; nm.textContent = it.label || it.value;
        var tag = document.createElement('span'); tag.className = 'lx-img-tag';
        var st = stOf(it.value);
        var marks = (st.has_lakken ? '█' : '') + (st.has_annot ? '⬠' : '');
        tag.textContent = marks || (st.gecontroleerd ? '✓' : '');
        tag.classList.add(st.has_lakken ? 'is-lak' : st.has_annot ? 'is-annot' : st.gecontroleerd ? 'is-ctrl' : 'is-none');
        row.appendChild(th); row.appendChild(nm); row.appendChild(tag);
        row.addEventListener('click', function() { selectName(it.value); });
        list.appendChild(row);
      });
    }
    search.addEventListener('input', renderList);
    fileInp.addEventListener('input', function() { showPreview(fileInp.value.trim()); updateActions(fileInp.value.trim()); renderList(); });

    // Status (gecontroleerd/gelakt) ophalen uit de lak-galerij.
    function refreshStatus(then) {
      fetch('/dashboard/report/images', { credentials: 'same-origin' })
        .then(function(r) { return r.ok ? r.json() : null; })
        .then(function(d) {
          var arr = (d && (d.images || d.items || d)) || [];
          if (Array.isArray(arr)) {
            status = {};
            arr.forEach(function(i) {
              status[i.name] = { gecontroleerd: !!i.gecontroleerd, has_lakken: !!i.has_lakken,
                                 has_annot: !!i.has_annot, redactable: i.redactable !== false, url: i.url };
            });
          }
          if (then) then();
        })
        .catch(function() { if (then) then(); });
    }

    upBtn.addEventListener('click', function() { fileHidden.click(); });
    fileHidden.addEventListener('change', function() {
      var f = fileHidden.files && fileHidden.files[0];
      var url = self.config && self.config.projectImagesUrl;
      if (!f || !url) return;
      upStatus.textContent = '⏳ Uploaden…';
      var fd = new FormData(); fd.append('file', f, f.name || 'screenshot.png');
      fetch(url, { method: 'POST', credentials: 'same-origin', headers: { 'X-CSRFToken': _csrfToken() }, body: fd })
        .then(function(r) { return r.json(); })
        .then(function(d) {
          if (d && d.ok && d.name) {
            items.unshift({ value: d.name, label: d.name, url: d.url, redactable: true });
            if (self.dropdownData && self.dropdownData.projectImage) { self.dropdownData.projectImage = items; self._renderDropdownList('projectImage'); }
            upStatus.textContent = '✔ ' + d.name;
            refreshStatus(function() { selectName(d.name); });
          } else { upStatus.textContent = '✖ ' + ((d && d.error) || 'upload mislukt'); }
        })
        .catch(function() { upStatus.textContent = '✖ upload mislukt'; });
    });

    // Lakken: canvas-redactor openen voor de gekozen afbeelding, daarna status
    // verversen (de redactor werkt dropdownData.has_lakken al bij).
    lakBtn.addEventListener('click', function() {
      var name = fileInp.value.trim(); if (!name) return;
      var st = stOf(name);
      var fake = document.createElement('button');
      fake.setAttribute('data-lak-name', name);
      fake.setAttribute('data-lak-url', st.url || urlFor(name));
      fake.setAttribute('data-has-lakken', st.has_lakken ? '1' : '0');
      fake.setAttribute('data-has-annot', st.has_annot ? '1' : '0');
      self._openScreenshotRedactor(fake, 'lak');
      var poll = setInterval(function() {
        if (!document.querySelector('.latex-redact-overlay')) {
          clearInterval(poll);
          refreshStatus(function() {
            bust = '?t=' + Date.now();
            viewMode = stOf(name).has_lakken ? 'lak' : 'orig';
            showPreview(name); updateActions(name); renderList();
          });
        }
      }, 400);
    });

    // Aandachtspunten: canvas-annotator (rode kaders) openen; in álle rapporten.
    annotBtn.addEventListener('click', function() {
      var name = fileInp.value.trim(); if (!name) return;
      var st = stOf(name);
      var fake = document.createElement('button');
      fake.setAttribute('data-lak-name', name);
      fake.setAttribute('data-lak-url', st.url || urlFor(name));
      fake.setAttribute('data-has-annot', st.has_annot ? '1' : '0');
      self._openScreenshotRedactor(fake, 'annot');
      var poll = setInterval(function() {
        if (!document.querySelector('.latex-redact-overlay')) {
          clearInterval(poll);
          refreshStatus(function() {
            bust = '?t=' + Date.now();
            viewMode = stOf(name).has_annot ? 'annot' : 'orig';
            showPreview(name); updateActions(name); renderList();
          });
        }
      }, 400);
    });

    // Gecontroleerd: markeer/ontmarkeer "geen lak nodig" voor deze opdracht.
    ctrlBtn.addEventListener('click', function() {
      var name = fileInp.value.trim(); if (!name) return;
      var want = !stOf(name).gecontroleerd;
      ctrlBtn.disabled = true;
      fetch('/dashboard/report/images/' + encodeURIComponent(name) + '/reviewed', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': _csrfToken() },
        body: JSON.stringify({ reviewed: want })
      }).then(function(r) { return r.json(); }).then(function(d) {
        ctrlBtn.disabled = false;
        if (d && d.ok) {
          status[name] = status[name] || {}; status[name].gecontroleerd = !!d.gecontroleerd;
          updateActions(name); renderList();
        }
      }).catch(function() { ctrlBtn.disabled = false; });
    });

    var act = document.createElement('div'); act.className = 'lx-fp-actions';
    var ins = document.createElement('button'); ins.type = 'button'; ins.className = 'btn btn-primary btn-sm';
    ins.textContent = opts.edit ? 'Bijwerken' : 'Invoegen';
    var cancel = document.createElement('button'); cancel.type = 'button'; cancel.className = 'btn btn-sm'; cancel.textContent = 'Annuleren';
    act.appendChild(ins); act.appendChild(cancel); box.appendChild(act);
    ov.appendChild(box); document.body.appendChild(ov);

    function close() { if (ov.parentNode) ov.parentNode.removeChild(ov); document.removeEventListener('keydown', onKey); }
    function onKey(e) { if (e.key === 'Escape' && !document.querySelector('.latex-redact-overlay')) close(); }
    hx.addEventListener('click', close); cancel.addEventListener('click', close);
    ov.addEventListener('click', function(e) { if (e.target === ov) close(); });
    document.addEventListener('keydown', onKey);
    ins.addEventListener('click', function() {
      var fn = (fileInp.value || '').trim();
      if (!fn) { fileInp.focus(); return; }
      var capTex = (cap.value || '').trim().replace(/([{}])/g, '\\$1');
      if (opts.onInsert) opts.onInsert('\\plaatje{' + fn + '}{' + capTex + '}');
      close();
    });
    renderList(); showPreview(fileInp.value.trim()); updateActions(fileInp.value.trim());
    refreshStatus(function() { showPreview(fileInp.value.trim()); updateActions(fileInp.value.trim()); renderList(); });
    setTimeout(function() { try { (opts.file ? cap : search).focus(); } catch (e) {} }, 0);
  };

  // Compileer een fragment en toon het als PNG in het paneel (hergebruikt
  // /api/latex/preview, net als de editor-preview).
  LaTeXEditor.prototype._previewInto = function(latex, panel) {
    panel.className = 'lx-mini-preview is-loading';
    panel.textContent = '⏳ Voorbeeld wordt gecompileerd…';
    var mt = document.querySelector('meta[name="csrf-token"]');
    var csrf = mt && mt.getAttribute ? (mt.getAttribute('content') || '')
      : ((document.querySelector('input[name="csrf_token"]') || {}).value || '');
    fetch('/api/latex/preview', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf },
      body: JSON.stringify({ content: latex, mode: this.mode })
    }).then(function(r) { return r.json(); }).then(function(d) {
      if (d && d.ok && d.image) {
        panel.className = 'lx-mini-preview'; panel.textContent = '';
        var img = document.createElement('img'); img.alt = 'Voorbeeld'; img.src = d.image; panel.appendChild(img);
      } else {
        panel.className = 'lx-mini-preview is-error';
        panel.textContent = '✖ ' + ((d && d.error) || 'voorbeeld mislukt');
      }
    }).catch(function() {
      panel.className = 'lx-mini-preview is-error'; panel.textContent = '✖ voorbeeld-verzoek mislukt';
    });
  };

  // Vervang een tekenbereik in de textarea (behoudt undo via execCommand).
  LaTeXEditor.prototype._replaceRange = function(start, end, text) {
    var ta = this.textarea;
    ta.focus();
    ta.selectionStart = start; ta.selectionEnd = end;
    this._insertAtCursor(text);
  };

  // Klik in een bestaand \request/\response/lstlisting-blok -> heropen de modal
  // voorgevuld; bij Bijwerken wordt het blok ter plekke vervangen.
  LaTeXEditor.prototype._editBlockAtCursor = function() {
    if (document.getElementById('lx-http-dialog') || document.getElementById('lx-code-dialog')
        || document.getElementById('lx-img-dialog')) return false;
    var ta = this.textarea;
    if (!ta || ta.selectionStart !== ta.selectionEnd) return false;
    var pos = ta.selectionStart, val = ta.value, self = this, m;

    // \plaatje{bestand}{onderschrift} -> afbeeldings-modal.
    var pre = /\\plaatje\s*\{/g;
    while ((m = pre.exec(val))) {
      var ps = m.index;
      var pb1 = _readBracedJS(val, m.index + m[0].length - 1);
      if (!pb1 || val.charAt(pb1.end) !== '{') { pre.lastIndex = m.index + m[0].length; continue; }
      var pb2 = _readBracedJS(val, pb1.end);
      if (!pb2) { pre.lastIndex = pb1.end; continue; }
      var pe = pb2.end;
      if (pos >= ps && pos <= pe) {
        this._openImageDialog({
          file: pb1.inner.trim(),
          caption: pb2.inner,
          edit: true,
          onInsert: function(tex) { self._replaceRange(ps, pe, tex); }
        });
        return true;
      }
      pre.lastIndex = pe;
    }

    var lre = /\\begin\{lstlisting\}(\[[^\]]*\])?[\s\S]*?\\end\{lstlisting\}/g;
    while ((m = lre.exec(val))) {
      var ls = m.index, le = m.index + m[0].length;
      if (pos >= ls && pos <= le) {
        var o = m[1] || '';
        var capm = (/caption=\{([\s\S]*?)\}/.exec(o) || /caption=([^,\]]+)/.exec(o));
        var langm = /language=([A-Za-z0-9_#+.\-]+)/.exec(o);
        var fnm = /firstnumber=(\d+)/.exec(o);
        var lblm = (/label=\{([^}]*)\}/.exec(o) || /label=([^,\]]+)/.exec(o));
        var bodyCode = m[0].replace(/^\\begin\{lstlisting\}(\[[^\]]*\])?\n?/, '').replace(/\n?\\end\{lstlisting\}$/, '');
        this._openCodeDialog({
          caption: capm ? _unescLatex(capm[1]) : '',
          language: langm ? langm[1] : '',
          numbers: /numbers=left/.test(o),
          firstnumber: fnm ? fnm[1] : '1',
          label: lblm ? lblm[1] : '',
          body: _lstBodyToMarkers(bodyCode),
          edit: true,
          onInsert: function(tex) { self._replaceRange(ls, le, tex); }
        });
        return true;
      }
    }

    var hre = /\\(request|response)\s*\{/g;
    while ((m = hre.exec(val))) {
      var start = m.index, kind = m[1];
      var br1 = _readBracedJS(val, m.index + m[0].length - 1);
      if (!br1) { hre.lastIndex = m.index + m[0].length; continue; }
      var cap = '', bodyRaw = br1.inner, end = br1.end;
      if (val.charAt(br1.end) === '{') {
        var br2 = _readBracedJS(val, br1.end);
        if (br2) { cap = br1.inner; bodyRaw = br2.inner; end = br2.end; }
      }
      if (pos >= start && pos <= end) {
        this._openHttpDialog({
          kind: kind,
          caption: _unescLatex(cap),
          body: _httpBodyToMarkers(bodyRaw),
          edit: true,
          onInsert: function(tex) { self._replaceRange(start, end, tex); }
        });
        return true;
      }
      hre.lastIndex = end;
    }

    // Generiek: zoek een \macro{..}{..} (argc argumenten) waar de cursor in staat.
    function tryMacro(reStr, argc, onHit) {
      var re = new RegExp(reStr, 'g'), mm;
      while ((mm = re.exec(val))) {
        var s0 = mm.index, i = mm.index + mm[0].length - 1, args = [], ok = true;
        for (var a = 0; a < argc; a++) {
          if (val.charAt(i) !== '{') { ok = false; break; }
          var br = _readBracedJS(val, i);
          if (!br) { ok = false; break; }
          args.push(br.inner); i = br.end;
        }
        if (!ok) { re.lastIndex = mm.index + mm[0].length; continue; }
        if (pos >= s0 && pos <= i) { onHit(mm, s0, i, args); return true; }
        re.lastIndex = i;
      }
      return false;
    }

    // \kader<kleur>{titel}{inhoud} -> kader-modal voorgevuld.
    if (tryMacro('\\\\(kaderblauw|kadergroen|kaderoranje|kaderpaars|kadergrijs|kaderrood)\\s*\\{', 2,
      function(mm, s0, e0, args) {
        var kleur = mm[1].replace('kader', '');
        self._openCalloutDialog('', function(kl, ti, inh) {
          self._replaceRange(s0, e0, '\\' + kl + '{' + ti + '}{' + inh + '}');
        }, { kleur: kleur, titel: args[0], inhoud: args[1], edit: true });
      })) return true;

    // \tekstkleur{naam}{inhoud} -> kleurkiezer; houdt de inhoud, wisselt de kleur.
    if (tryMacro('\\\\tekstkleur\\s*\\{', 2, function(mm, s0, e0, args) {
      self._openColorPicker(function(naam) {
        self._replaceRange(s0, e0, '\\tekstkleur{' + naam + '}{' + args[1] + '}');
      });
    })) return true;

    // \cvss/\severity/\cwe/\cve/\owasp/\mitre/\iso/\bio/\nist{...} -> classificatie-modal.
    if (tryMacro('\\\\(cvss|severity|cwe|cve|owasp|mitre|iso|bio|nist)\\s*\\{', 1,
      function(mm, s0, e0, args) {
        self._openRefDialog({
          type: mm[1], value: args[0].trim(),
          onInsert: function(tex) { self._replaceRange(s0, e0, tex); }
        });
      })) return true;

    // \bevinding/\uitwerking/\bevindingref{id} -> bevinding-kiezer.
    if (tryMacro('\\\\(bevinding|uitwerking|bevindingref)\\s*\\{', 1,
      function(mm, s0, e0) {
        var name = mm[1];
        self._openFindingPicker(function(id) {
          self._replaceRange(s0, e0, '\\' + name + '{' + id + '}');
        });
      })) return true;

    // \link{url}{tekst} -> link-dialog.
    if (tryMacro('\\\\link\\s*\\{', 2, function(mm, s0, e0, args) {
      self._openFieldsDialog('Link bewerken',
        [{ label: 'URL', value: args[0], placeholder: 'https://' },
         { label: 'Linktekst', value: args[1] }],
        function(v) { self._replaceRange(s0, e0, '\\link{' + v[0] + '}{' + v[1] + '}'); }, true);
    })) return true;

    // \url{...} -> url-dialog.
    if (tryMacro('\\\\url\\s*\\{', 1, function(mm, s0, e0, args) {
      self._openFieldsDialog('URL bewerken', [{ label: 'URL', value: args[0], placeholder: 'https://' }],
        function(v) { self._replaceRange(s0, e0, '\\url{' + v[0] + '}'); }, true);
    })) return true;

    // \footnote{...} -> voetnoot-dialog.
    if (tryMacro('\\\\footnote\\s*\\{', 1, function(mm, s0, e0, args) {
      self._openFieldsDialog('Voetnoot bewerken', [{ label: 'Voetnoottekst', value: args[0], textarea: true }],
        function(v) { self._replaceRange(s0, e0, '\\footnote{' + v[0] + '}'); }, true);
    })) return true;

    // \hl/\hlrood/\hlgroen{...} -> markeerkleur wisselen, tekst behouden.
    if (tryMacro('\\\\(hlrood|hlgroen|hl)\\s*\\{', 1, function(mm, s0, e0, args) {
      self._openColorPicker(function(name) { self._replaceRange(s0, e0, '\\' + name + '{' + args[0] + '}'); },
        { title: 'Markeerkleur', cols: [['hl', '#ffe14d', 'Geel'], ['hlrood', '#ffb3b3', 'Rood'], ['hlgroen', '#b6e6b6', 'Groen']] });
    })) return true;

    return false;
  };

  // Bind de klik-op-blok (opent de bijbehorende modal).
  LaTeXEditor.prototype._bindBlockClick = function() {
    var self = this, ta = this.textarea;
    if (!ta) return;
    ta.addEventListener('click', function() {
      setTimeout(function() { self._editBlockAtCursor(); }, 0);
    });
  };

  // --- Classificatie-/referentie-modal -------------------------------------
  // Eén knop voor \cvss/\severity/\cwe/\cve/\owasp/\mitre/\iso/\bio/\nist met
  // slimme invoer: CVSS 4.0-calculator (via /api/cvss4/calculate), zoekbare
  // lijsten met namen, CWE->OWASP-suggestie, validatie en live preview.
  var _REF_SEVCOL = { critical: '#6b0000', high: '#d4351c', medium: '#f47738', low: '#b58b00', none: '#5a6b7b' };
  var _REF_SEVNL = { critical: 'Kritiek', high: 'Hoog', medium: 'Midden', low: 'Laag', none: 'Nihil' };
  var _REF_SEV_OPTS = [['kritiek', 'Kritiek'], ['hoog', 'Hoog'], ['midden', 'Midden'], ['laag', 'Laag'], ['nihil', 'Nihil']];
  var _REF_SEV_KEY = { kritiek: 'critical', hoog: 'high', midden: 'medium', laag: 'low', nihil: 'none' };
  var _CVSS4_METRICS = [
    { k: 'AV', l: 'Attack Vector', o: [['N', 'Network'], ['A', 'Adjacent'], ['L', 'Local'], ['P', 'Physical']] },
    { k: 'AC', l: 'Attack Complexity', o: [['L', 'Low'], ['H', 'High']] },
    { k: 'AT', l: 'Attack Requirements', o: [['N', 'None'], ['P', 'Present']] },
    { k: 'PR', l: 'Privileges Required', o: [['N', 'None'], ['L', 'Low'], ['H', 'High']] },
    { k: 'UI', l: 'User Interaction', o: [['N', 'None'], ['P', 'Passive'], ['A', 'Active']] },
    { k: 'VC', l: 'Confidentiality (kwetsbaar)', o: [['H', 'High'], ['L', 'Low'], ['N', 'None']] },
    { k: 'VI', l: 'Integrity (kwetsbaar)', o: [['H', 'High'], ['L', 'Low'], ['N', 'None']] },
    { k: 'VA', l: 'Availability (kwetsbaar)', o: [['H', 'High'], ['L', 'Low'], ['N', 'None']] },
    { k: 'SC', l: 'Confidentiality (vervolg)', o: [['N', 'None'], ['L', 'Low'], ['H', 'High']] },
    { k: 'SI', l: 'Integrity (vervolg)', o: [['N', 'None'], ['L', 'Low'], ['H', 'High']] },
    { k: 'SA', l: 'Availability (vervolg)', o: [['N', 'None'], ['L', 'Low'], ['H', 'High']] }
  ];
  var _REF_OWASP = [
    { id: 'A01:2021', n: 'Broken Access Control' }, { id: 'A02:2021', n: 'Cryptographic Failures' },
    { id: 'A03:2021', n: 'Injection' }, { id: 'A04:2021', n: 'Insecure Design' },
    { id: 'A05:2021', n: 'Security Misconfiguration' }, { id: 'A06:2021', n: 'Vulnerable and Outdated Components' },
    { id: 'A07:2021', n: 'Identification and Authentication Failures' }, { id: 'A08:2021', n: 'Software and Data Integrity Failures' },
    { id: 'A09:2021', n: 'Security Logging and Monitoring Failures' }, { id: 'A10:2021', n: 'Server-Side Request Forgery' },
    { id: 'A01:2025', n: 'Broken Access Control' }, { id: 'A02:2025', n: 'Security Misconfiguration' },
    { id: 'A03:2025', n: 'Software Supply Chain Failures' }, { id: 'A04:2025', n: 'Cryptographic Failures' },
    { id: 'A05:2025', n: 'Injection' }, { id: 'A06:2025', n: 'Insecure Design' },
    { id: 'A07:2025', n: 'Authentication Failures' }, { id: 'A08:2025', n: 'Software or Data Integrity Failures' },
    { id: 'A09:2025', n: 'Security Logging and Alerting Failures' }, { id: 'A10:2025', n: 'Mishandling of Exceptional Conditions' }
  ];
  var _REF_CWE = [
    { id: '79', n: 'Cross-site Scripting (XSS)' }, { id: '89', n: 'SQL Injection' }, { id: '78', n: 'OS Command Injection' },
    { id: '94', n: 'Code Injection' }, { id: '22', n: 'Path Traversal' }, { id: '352', n: 'Cross-Site Request Forgery (CSRF)' },
    { id: '434', n: 'Unrestricted Upload of Dangerous File' }, { id: '611', n: 'XML External Entity (XXE)' },
    { id: '918', n: 'Server-Side Request Forgery (SSRF)' }, { id: '287', n: 'Improper Authentication' },
    { id: '862', n: 'Missing Authorization' }, { id: '863', n: 'Incorrect Authorization' },
    { id: '639', n: 'Authorization Bypass (IDOR)' }, { id: '269', n: 'Improper Privilege Management' },
    { id: '732', n: 'Incorrect Permission Assignment' }, { id: '798', n: 'Use of Hard-coded Credentials' },
    { id: '522', n: 'Insufficiently Protected Credentials' }, { id: '311', n: 'Missing Encryption of Sensitive Data' },
    { id: '319', n: 'Cleartext Transmission of Sensitive Info' }, { id: '327', n: 'Use of Broken/Risky Crypto' },
    { id: '916', n: 'Use of Password Hash With Insufficient Effort' }, { id: '200', n: 'Exposure of Sensitive Information' },
    { id: '209', n: 'Information Exposure Through Error Message' }, { id: '532', n: 'Insertion of Sensitive Info into Log' },
    { id: '601', n: 'Open Redirect' }, { id: '384', n: 'Session Fixation' },
    { id: '614', n: 'Sensitive Cookie Without Secure' }, { id: '1004', n: 'Sensitive Cookie Without HttpOnly' },
    { id: '307', n: 'Improper Restriction of Excessive Auth Attempts' }, { id: '295', n: 'Improper Certificate Validation' },
    { id: '502', n: 'Deserialization of Untrusted Data' }, { id: '915', n: 'Improperly Controlled Modification (Mass Assignment)' },
    { id: '1021', n: 'Improper Restriction of Rendered UI (Clickjacking)' }, { id: '400', n: 'Uncontrolled Resource Consumption' },
    { id: '20', n: 'Improper Input Validation' }, { id: '116', n: 'Improper Encoding/Output Escaping' },
    { id: '306', n: 'Missing Authentication for Critical Function' }, { id: '770', n: 'Allocation Without Limits or Throttling' }
  ];
  var _REF_CWE_OWASP = {
    '79': 'A03:2021', '89': 'A03:2021', '78': 'A03:2021', '94': 'A03:2021', '116': 'A03:2021',
    '22': 'A01:2021', '352': 'A01:2021', '862': 'A01:2021', '863': 'A01:2021', '639': 'A01:2021',
    '269': 'A01:2021', '732': 'A01:2021', '200': 'A01:2021', '601': 'A01:2021',
    '311': 'A02:2021', '319': 'A02:2021', '327': 'A02:2021', '916': 'A02:2021', '522': 'A02:2021', '798': 'A07:2021',
    '434': 'A04:2021', '306': 'A07:2021', '287': 'A07:2021', '384': 'A07:2021', '307': 'A07:2021',
    '611': 'A05:2021', '614': 'A05:2021', '1004': 'A05:2021', '1021': 'A05:2021', '295': 'A07:2021',
    '502': 'A08:2021', '915': 'A08:2021', '532': 'A09:2021', '918': 'A10:2021',
    '209': 'A05:2021', '20': 'A03:2021', '400': 'A04:2021', '770': 'A04:2021'
  };
  var _REF_MITRE = [
    { id: 'T1190', n: 'Exploit Public-Facing Application' }, { id: 'T1133', n: 'External Remote Services' },
    { id: 'T1566', n: 'Phishing' }, { id: 'T1078', n: 'Valid Accounts' }, { id: 'T1110', n: 'Brute Force' },
    { id: 'T1059', n: 'Command and Scripting Interpreter' }, { id: 'T1059.001', n: 'PowerShell' },
    { id: 'T1059.003', n: 'Windows Command Shell' }, { id: 'T1505.003', n: 'Web Shell' },
    { id: 'T1003', n: 'OS Credential Dumping' }, { id: 'T1003.001', n: 'LSASS Memory' },
    { id: 'T1555', n: 'Credentials from Password Stores' }, { id: 'T1552', n: 'Unsecured Credentials' },
    { id: 'T1068', n: 'Exploitation for Privilege Escalation' }, { id: 'T1548', n: 'Abuse Elevation Control Mechanism' },
    { id: 'T1134', n: 'Access Token Manipulation' }, { id: 'T1547', n: 'Boot or Logon Autostart Execution' },
    { id: 'T1053', n: 'Scheduled Task/Job' }, { id: 'T1021', n: 'Remote Services' },
    { id: 'T1021.001', n: 'Remote Desktop Protocol' }, { id: 'T1021.002', n: 'SMB/Windows Admin Shares' },
    { id: 'T1210', n: 'Exploitation of Remote Services' }, { id: 'T1550', n: 'Use Alternate Authentication Material' },
    { id: 'T1557', n: 'Adversary-in-the-Middle' }, { id: 'T1040', n: 'Network Sniffing' },
    { id: 'T1046', n: 'Network Service Discovery' }, { id: 'T1018', n: 'Remote System Discovery' },
    { id: 'T1482', n: 'Domain Trust Discovery' }, { id: 'T1087', n: 'Account Discovery' },
    { id: 'T1098', n: 'Account Manipulation' }, { id: 'T1484', n: 'Domain Policy Modification' },
    { id: 'T1136', n: 'Create Account' }, { id: 'T1562', n: 'Impair Defenses' },
    { id: 'T1070', n: 'Indicator Removal' }, { id: 'T1041', n: 'Exfiltration Over C2 Channel' }
  ];
  var _REF_ISO = [
    { id: 'A.5.7', n: 'Threat intelligence' }, { id: 'A.5.14', n: 'Information transfer' },
    { id: 'A.5.15', n: 'Access control' }, { id: 'A.5.16', n: 'Identity management' },
    { id: 'A.5.17', n: 'Authentication information' }, { id: 'A.5.18', n: 'Access rights' },
    { id: 'A.5.23', n: 'Information security for cloud services' }, { id: 'A.8.1', n: 'User endpoint devices' },
    { id: 'A.8.2', n: 'Privileged access rights' }, { id: 'A.8.3', n: 'Information access restriction' },
    { id: 'A.8.5', n: 'Secure authentication' }, { id: 'A.8.7', n: 'Protection against malware' },
    { id: 'A.8.8', n: 'Management of technical vulnerabilities' }, { id: 'A.8.9', n: 'Configuration management' },
    { id: 'A.8.12', n: 'Data leakage prevention' }, { id: 'A.8.13', n: 'Information backup' },
    { id: 'A.8.15', n: 'Logging' }, { id: 'A.8.16', n: 'Monitoring activities' },
    { id: 'A.8.20', n: 'Networks security' }, { id: 'A.8.21', n: 'Security of network services' },
    { id: 'A.8.23', n: 'Web filtering' }, { id: 'A.8.24', n: 'Use of cryptography' },
    { id: 'A.8.25', n: 'Secure development life cycle' }, { id: 'A.8.26', n: 'Application security requirements' },
    { id: 'A.8.28', n: 'Secure coding' }
  ];
  var _REF_BIO = [
    { id: '9.1.2', n: 'Toegang tot netwerken en netwerkdiensten' }, { id: '9.2.3', n: 'Beheer van speciale toegangsrechten' },
    { id: '9.4.1', n: 'Beperking toegang tot informatie' }, { id: '9.4.2', n: 'Beveiligde inlogprocedures' },
    { id: '10.1.1', n: 'Beleid inzake cryptografie' }, { id: '12.2.1', n: 'Beheersmaatregelen tegen malware' },
    { id: '12.4.1', n: 'Logging van gebeurtenissen' }, { id: '12.4.3', n: 'Logs van beheerders/operators' },
    { id: '12.6.1', n: 'Beheer van technische kwetsbaarheden' }, { id: '13.1.1', n: 'Beheersmaatregelen voor netwerken' },
    { id: '13.1.3', n: 'Scheiding in netwerken' }, { id: '14.1.2', n: 'Toepassingen op openbare netwerken beveiligen' },
    { id: '14.2.1', n: 'Beleid voor veilig ontwikkelen' }, { id: '14.2.5', n: 'Principes voor engineering van veilige systemen' },
    { id: '18.1.3', n: 'Beschermen van registraties' }, { id: '18.2.3', n: 'Beoordeling van technische naleving' }
  ];
  var _REF_NIST = [
    { id: 'AC-2', n: 'Account Management' }, { id: 'AC-3', n: 'Access Enforcement' }, { id: 'AC-6', n: 'Least Privilege' },
    { id: 'AC-17', n: 'Remote Access' }, { id: 'AU-2', n: 'Event Logging' }, { id: 'AU-6', n: 'Audit Record Review' },
    { id: 'CM-6', n: 'Configuration Settings' }, { id: 'CM-7', n: 'Least Functionality' }, { id: 'IA-2', n: 'Identification and Authentication' },
    { id: 'IA-5', n: 'Authenticator Management' }, { id: 'RA-5', n: 'Vulnerability Monitoring and Scanning' },
    { id: 'CA-8', n: 'Penetration Testing' }, { id: 'SC-7', n: 'Boundary Protection' }, { id: 'SC-8', n: 'Transmission Confidentiality and Integrity' },
    { id: 'SC-13', n: 'Cryptographic Protection' }, { id: 'SI-2', n: 'Flaw Remediation' }, { id: 'SI-3', n: 'Malicious Code Protection' },
    { id: 'SI-4', n: 'System Monitoring' }, { id: 'SI-10', n: 'Information Input Validation' }, { id: 'SA-11', n: 'Developer Testing and Evaluation' }
  ];
  var _REF_LISTS = { cwe: _REF_CWE, owasp: _REF_OWASP, mitre: _REF_MITRE, iso: _REF_ISO, bio: _REF_BIO, nist: _REF_NIST };
  var _REF_PREFIX = { iso: 'ISO 27001', bio: 'BIO', nist: 'NIST 800-53' };
  var _REF_TYPES = [
    { v: 'cvss', l: 'CVSS 4.0 (calculator)' }, { v: 'severity', l: 'Severity (ernst)' },
    { v: 'cwe', l: 'CWE' }, { v: 'cve', l: 'CVE' }, { v: 'owasp', l: 'OWASP Top 10' },
    { v: 'mitre', l: 'MITRE ATT&CK' }, { v: 'iso', l: 'ISO 27001' }, { v: 'bio', l: 'BIO' }, { v: 'nist', l: 'NIST 800-53' }
  ];

  // Kleurkiezer: compacte swatch-popover; roept onPick(naam) aan.
  LaTeXEditor.prototype._openColorPicker = function(onPick, opts) {
    opts = opts || {};
    var old = document.getElementById('lx-color-pop'); if (old) old.remove();
    var cols = opts.cols || [['rood', '#D4351C'], ['oranje', '#E17000'], ['groen', '#2A8F2A'],
                ['blauw', '#154273'], ['paars', '#5B3F8C'], ['grijs', '#535353'], ['zwart', '#1A1A1A']];
    var ov = document.createElement('div'); ov.id = 'lx-color-pop'; ov.className = 'lx-fp-overlay';
    var box = document.createElement('div'); box.className = 'lx-color-pop';
    var ttl = document.createElement('div'); ttl.className = 'lx-color-title'; ttl.textContent = opts.title || 'Tekstkleur';
    box.appendChild(ttl);
    var grid = document.createElement('div'); grid.className = 'lx-color-grid';
    cols.forEach(function(c) {
      var b = document.createElement('button'); b.type = 'button'; b.className = 'lx-color-sw'; b.title = c[2] || c[0];
      b.style.background = c[1];
      b.addEventListener('click', function() { onPick(c[0]); close(); });
      grid.appendChild(b);
    });
    box.appendChild(grid);
    ov.appendChild(box); document.body.appendChild(ov);
    function close() { ov.remove(); document.removeEventListener('keydown', onKey); }
    function onKey(e) { if (e.key === 'Escape') close(); }
    ov.addEventListener('click', function(e) { if (e.target === ov) close(); });
    document.addEventListener('keydown', onKey);
  };

  // Generieke invoer-dialog: velden = [{label, value, placeholder, textarea}].
  // onSubmit krijgt een array met de waarden. Voor url/link/footnote.
  LaTeXEditor.prototype._openFieldsDialog = function(title, fields, onSubmit, edit) {
    var old = document.getElementById('lx-fields-dialog'); if (old) old.remove();
    var ov = document.createElement('div'); ov.id = 'lx-fields-dialog'; ov.className = 'lx-fp-overlay';
    var box = document.createElement('div'); box.className = 'lx-fp-box';
    var head = document.createElement('div'); head.className = 'lx-fp-head';
    var ht = document.createElement('span'); ht.textContent = title;
    var hx = document.createElement('button'); hx.type = 'button'; hx.className = 'lx-fp-close'; hx.innerHTML = '&times;';
    head.appendChild(ht); head.appendChild(hx); box.appendChild(head);
    var inputs = [];
    fields.forEach(function(f) {
      var el = f.textarea ? document.createElement('textarea') : document.createElement('input');
      if (!f.textarea) el.type = 'text';
      if (f.textarea) el.rows = 4;
      el.className = 'lx-fp-search'; el.value = f.value || ''; el.placeholder = f.placeholder || '';
      var w = document.createElement('label'); w.className = 'lx-fp-field';
      var s = document.createElement('span'); s.className = 'lx-fp-label'; s.textContent = f.label;
      w.appendChild(s); w.appendChild(el); box.appendChild(w); inputs.push(el);
    });
    var act = document.createElement('div'); act.className = 'lx-fp-actions';
    var ins = document.createElement('button'); ins.type = 'button'; ins.className = 'btn btn-primary btn-sm'; ins.textContent = edit ? 'Bijwerken' : 'Invoegen';
    var cancel = document.createElement('button'); cancel.type = 'button'; cancel.className = 'btn btn-sm'; cancel.textContent = 'Annuleren';
    act.appendChild(ins); act.appendChild(cancel); box.appendChild(act);
    ov.appendChild(box); document.body.appendChild(ov);
    function close() { ov.remove(); document.removeEventListener('keydown', onKey); }
    function onKey(e) { if (e.key === 'Escape') close(); }
    hx.addEventListener('click', close); cancel.addEventListener('click', close);
    ov.addEventListener('click', function(e) { if (e.target === ov) close(); });
    document.addEventListener('keydown', onKey);
    ins.addEventListener('click', function() { onSubmit(inputs.map(function(i) { return i.value; })); close(); });
    setTimeout(function() { try { inputs[0] && inputs[0].focus(); } catch (e) {} }, 0);
  };

  LaTeXEditor.prototype._openRefDialog = function(initialType) {
    var self = this;
    var old = document.getElementById('lx-ref-dialog'); if (old) old.remove();
    var ov = document.createElement('div'); ov.id = 'lx-ref-dialog'; ov.className = 'lx-fp-overlay';
    var box = document.createElement('div'); box.className = 'lx-fp-box lx-ref-box';
    var head = document.createElement('div'); head.className = 'lx-fp-head';
    var ht = document.createElement('span'); ht.textContent = 'Classificatie / referentie invoegen';
    var hx = document.createElement('button'); hx.type = 'button'; hx.className = 'lx-fp-close'; hx.innerHTML = '&times;';
    head.appendChild(ht); head.appendChild(hx); box.appendChild(head);

    function field(labelText, el) {
      var w = document.createElement('label'); w.className = 'lx-fp-field';
      var s = document.createElement('span'); s.className = 'lx-fp-label'; s.textContent = labelText;
      w.appendChild(s); w.appendChild(el); return w;
    }
    var typeSel = document.createElement('select'); typeSel.className = 'lx-fp-search';
    _REF_TYPES.forEach(function(t) { var o = document.createElement('option'); o.value = t.v; o.textContent = t.l; typeSel.appendChild(o); });
    box.appendChild(field('Type', typeSel));

    var formArea = document.createElement('div'); formArea.className = 'lx-ref-form'; box.appendChild(formArea);
    var pv = document.createElement('div'); pv.className = 'lx-ref-preview'; box.appendChild(pv);

    var act = document.createElement('div'); act.className = 'lx-fp-actions';
    var ins = document.createElement('button'); ins.type = 'button'; ins.className = 'btn btn-primary btn-sm'; ins.textContent = 'Invoegen';
    var cancel = document.createElement('button'); cancel.type = 'button'; cancel.className = 'btn btn-sm'; cancel.textContent = 'Annuleren';
    act.appendChild(ins); act.appendChild(cancel); box.appendChild(act);
    ov.appendChild(box); document.body.appendChild(ov);

    var _refOpts = (initialType && typeof initialType === 'object') ? initialType : { type: initialType };
    var _pend = _refOpts.value || '';
    var state = { type: 'cvss', value: '', vector: '', sev: '', withOwasp: false, withVector: false };

    function buildLatex() {
      var t = state.type, v = (state.value || '').trim();
      if (!v) return '';
      if (t === 'cvss') { var s = '\\cvss{' + v + '}'; if (state.withVector && state.vector) s += '\\footnote{' + state.vector + '}'; return s; }
      var out = '\\' + t + '{' + v + '}';
      if (t === 'cwe' && state.withOwasp && _REF_CWE_OWASP[v]) out += ' \\owasp{' + _REF_CWE_OWASP[v] + '}';
      return out;
    }
    function badge(parent) {
      parent.textContent = '';
      var t = state.type, v = (state.value || '').trim();
      if (!v) { parent.textContent = '—'; return; }
      var b = document.createElement('span'); b.className = 'lx-ref-badge';
      if (t === 'cvss' || t === 'severity') {
        var key = t === 'cvss' ? state.sev : _REF_SEV_KEY[v];
        b.style.background = _REF_SEVCOL[key] || '#5a6b7b'; b.style.color = '#fff';
        b.textContent = (t === 'cvss' ? v : '') + (t === 'cvss' ? ' (' + (_REF_SEVNL[key] || '?') + ')' : (_REF_SEVNL[key] || v));
      } else if (t === 'cwe') { b.className = 'lx-ref-badge is-code'; b.textContent = 'CWE-' + v; }
      else if (t === 'cve') { b.className = 'lx-ref-badge is-code'; b.textContent = 'CVE-' + v.replace(/^CVE-/i, ''); }
      else if (t === 'owasp') { var o = _REF_OWASP.filter(function(x) { return x.id === v; })[0]; b.className = 'lx-ref-badge is-code'; b.textContent = v + (o ? ' — ' + o.n : ''); }
      else if (t === 'mitre') { b.className = 'lx-ref-badge is-code'; b.textContent = v; }
      else { b.textContent = (_REF_PREFIX[t] || '') + ' ' + v; }
      parent.appendChild(b);
    }
    function renderPreview() {
      pv.textContent = '';
      var row = document.createElement('div'); row.className = 'lx-ref-pvrow';
      var bwrap = document.createElement('div'); badge(bwrap);
      var code = document.createElement('code'); code.className = 'lx-ref-code'; code.textContent = buildLatex() || '(kies een waarde)';
      row.appendChild(bwrap); row.appendChild(code); pv.appendChild(row);
      ins.disabled = !buildLatex();
    }

    function listPicker(data, withOwaspOption) {
      var search = document.createElement('input'); search.type = 'text'; search.className = 'lx-fp-search'; search.placeholder = 'Zoek op id of naam…';
      var list = document.createElement('div'); list.className = 'lx-ref-list';
      formArea.appendChild(field('Zoeken', search)); formArea.appendChild(list);
      function render() {
        var q = (search.value || '').toLowerCase(); list.textContent = '';
        data.filter(function(it) { return !q || it.id.toLowerCase().indexOf(q) >= 0 || it.n.toLowerCase().indexOf(q) >= 0; })
          .slice(0, 120).forEach(function(it) {
            var row = document.createElement('button'); row.type = 'button'; row.className = 'lx-ref-row';
            if (it.id === state.value) row.classList.add('is-active');
            var id = document.createElement('span'); id.className = 'lx-ref-id'; id.textContent = it.id;
            var nm = document.createElement('span'); nm.className = 'lx-ref-name'; nm.textContent = it.n;
            row.appendChild(id); row.appendChild(nm);
            row.addEventListener('click', function() { state.value = it.id; render(); updateSugg(); renderPreview(); });
            list.appendChild(row);
          });
      }
      var sugg = null;
      function updateSugg() {
        if (!withOwaspOption) return;
        if (sugg) { sugg.remove(); sugg = null; }
        var code = _REF_CWE_OWASP[state.value];
        if (!code) return;
        var o = _REF_OWASP.filter(function(x) { return x.id === code; })[0];
        sugg = document.createElement('label'); sugg.className = 'lx-ref-sugg';
        var cb = document.createElement('input'); cb.type = 'checkbox'; cb.checked = state.withOwasp;
        cb.addEventListener('change', function() { state.withOwasp = cb.checked; renderPreview(); });
        var sp = document.createElement('span'); sp.textContent = ' Ook gerelateerde OWASP toevoegen: ' + code + (o ? ' — ' + o.n : '');
        sugg.appendChild(cb); sugg.appendChild(sp); formArea.appendChild(sugg);
      }
      search.addEventListener('input', render);
      render(); updateSugg();
    }

    function renderForm() {
      formArea.textContent = ''; state.value = _pend; _pend = ''; state.withOwasp = false; state.withVector = false;
      var t = state.type;
      if (t === 'cvss') {
        var grid = document.createElement('div'); grid.className = 'lx-cvss-grid';
        var sels = {};
        _CVSS4_METRICS.forEach(function(m) {
          var s = document.createElement('select'); s.className = 'lx-fp-search';
          m.o.forEach(function(op) { var o = document.createElement('option'); o.value = op[0]; o.textContent = m.k + ': ' + op[1]; s.appendChild(o); });
          s.addEventListener('change', recalc); sels[m.k] = s;
          grid.appendChild(field(m.l, s));
        });
        formArea.appendChild(grid);
        var scoreLine = document.createElement('div'); scoreLine.className = 'lx-cvss-score'; scoreLine.textContent = 'Score: …'; formArea.appendChild(scoreLine);
        var vecLbl = document.createElement('label'); vecLbl.className = 'lx-ref-sugg';
        var vcb = document.createElement('input'); vcb.type = 'checkbox';
        vcb.addEventListener('change', function() { state.withVector = vcb.checked; renderPreview(); });
        var vsp = document.createElement('span'); vsp.textContent = ' Vector als voetnoot meenemen';
        vecLbl.appendChild(vcb); vecLbl.appendChild(vsp); formArea.appendChild(vecLbl);
        var dbt;
        function recalc() {
          var vec = 'CVSS:4.0/' + _CVSS4_METRICS.map(function(m) { return m.k + ':' + sels[m.k].value; }).join('/');
          state.vector = vec; scoreLine.textContent = 'Score: …'; state.value = ''; renderPreview();
          clearTimeout(dbt);
          dbt = setTimeout(function() {
            fetch('/api/cvss4/calculate?vector=' + encodeURIComponent(vec), { credentials: 'same-origin' })
              .then(function(r) { return r.json(); })
              .then(function(d) {
                if (d && d.ok) {
                  state.value = String(d.score); state.sev = d.severity;
                  scoreLine.textContent = 'Score: ' + d.score + ' (' + (_REF_SEVNL[d.severity] || d.severity) + ')  ·  ' + vec;
                } else { scoreLine.textContent = 'Score: ' + ((d && d.error) || 'kon niet berekenen'); }
                renderPreview();
              })
              .catch(function() { scoreLine.textContent = 'Score: netwerkfout'; renderPreview(); });
          }, 250);
        }
        recalc();
      } else if (t === 'severity') {
        var ssel = document.createElement('select'); ssel.className = 'lx-fp-search';
        _REF_SEV_OPTS.forEach(function(op) { var o = document.createElement('option'); o.value = op[0]; o.textContent = op[1]; ssel.appendChild(o); });
        ssel.addEventListener('change', function() { state.value = ssel.value; renderPreview(); });
        formArea.appendChild(field('Ernst', ssel));
        if (state.value) { ssel.value = state.value; } else { state.value = ssel.value; }
        renderPreview();
      } else if (t === 'cve') {
        var inp = document.createElement('input'); inp.type = 'text'; inp.className = 'lx-fp-search'; inp.placeholder = '2024-1234 (of CVE-2024-1234)';
        if (state.value) inp.value = state.value;
        var warn = document.createElement('div'); warn.className = 'lx-http-hint';
        inp.addEventListener('input', function() {
          var v = inp.value.trim().replace(/^CVE-/i, '');
          var ok = /^\d{4}-\d{4,}$/.test(v);
          state.value = ok ? v : ''; warn.textContent = (inp.value && !ok) ? 'Formaat: 2024-1234' : '';
          renderPreview();
        });
        formArea.appendChild(field('CVE-id', inp)); formArea.appendChild(warn); renderPreview();
      } else {
        listPicker(_REF_LISTS[t], t === 'cwe'); renderPreview();
      }
    }

    typeSel.addEventListener('change', function() { state.type = typeSel.value; renderForm(); });
    function close() { ov.remove(); document.removeEventListener('keydown', onKey); }
    function onKey(e) { if (e.key === 'Escape') close(); }
    hx.addEventListener('click', close); cancel.addEventListener('click', close);
    ov.addEventListener('click', function(e) { if (e.target === ov) close(); });
    document.addEventListener('keydown', onKey);
    ins.addEventListener('click', function() {
      var tex = buildLatex();
      if (tex) { if (_refOpts.onInsert) { _refOpts.onInsert(tex); } else { self._insertAtCursor(tex); } close(); }
    });
    if (_refOpts.onInsert) { ht.textContent = 'Classificatie / referentie bewerken'; ins.textContent = 'Bijwerken'; }

    if (_refOpts.type && _REF_TYPES.some(function(t) { return t.v === _refOpts.type; })) { typeSel.value = _refOpts.type; state.type = _refOpts.type; }
    renderForm();
  };

  LaTeXEditor.prototype._handleAction = function(action) {
    var selected = this._getSelectedText();
    var latex = '';

    // Opmaak: vet / cursief / onderstreept / tekstkleur.
    if (action === 'bold') { this._wrap('\\textbf{', '}'); return; }
    if (action === 'italic') { this._wrap('\\textit{', '}'); return; }
    if (action === 'underline') { this._wrap('\\underline{', '}'); return; }
    if (action === 'kleur') {
      var selfClr = this;
      this._openColorPicker(function(naam) {
        var sel = selfClr._getSelectedText();
        selfClr._insertAtCursor('\\tekstkleur{' + naam + '}{' + (sel || 'tekst') + '}', sel ? null : 'tekst');
      });
      return;
    }

    // Classificatie/referentie: één modal voor cvss/cwe/cve/owasp/mitre/iso/bio/nist.
    if (action === 'classificatie') { this._openRefDialog(); return; }

    // Code-blok: open de lstlisting-modal (caption + taal + regelnummers + highlight).
    if (action === 'lstlisting') {
      var selfC = this;
      this._openCodeDialog({ body: selected, onInsert: function(tex) {
        selfC._insertAtCursor('\n' + tex + '\n');
      } });
      return;
    }

    // HTTP-blokken: open de request/response-modal (caption + highlight).
    if (action === 'request' || action === 'response') {
      var selfH = this;
      this._openHttpDialog({ kind: action, body: selected, onInsert: function(tex) {
        selfH._insertAtCursor('\n' + tex + '\n');
      } });
      return;
    }

    // Kruisverwijzingen naar een bevinding: kies de bevinding i.p.v. een id te
    // typen. Als er al een getal geselecteerd is, gebruik dat direct.
    if (action === 'bevinding' || action === 'uitwerking' || action === 'bevindingref') {
      var self = this;
      if (selected && /^\d+$/.test(selected.trim())) {
        this._insertAtCursor('\\' + action + '{' + selected.trim() + '}');
        return;
      }
      this._openFindingPicker(function(id) {
        self._insertAtCursor('\\' + action + '{' + id + '}');
      });
      return;
    }

    // Generiek kader: kies kleur/voorinstelling + titel + inhoud in één dialoog.
    if (action === 'kader') {
      var selfK = this;
      this._openCalloutDialog(selected, function(kleur, titel, inhoud) {
        selfK._insertAtCursor('\\' + kleur + '{' + titel + '}{' + inhoud + '}');
      });
      return;
    }

    if (SIMPLE_MACROS[action]) {
      latex = '\\' + action + '{' + (selected || '') + '}';
      this._insertAtCursor(latex);
      if (!selected) this.textarea.selectionStart = this.textarea.selectionEnd - 1;
      return;
    }
    if (action === 'deelsgelakt') {
      // Twee argumenten: zichtbaar deel + te lakken deel.
      latex = selected ? ('\\deelsgelakt{' + selected + '}{geheim}')
                       : '\\deelsgelakt{zichtbaar}{geheim}';
      this._insertAtCursor(latex);
      return;
    }
    if (action === 'link') {
      // \link{url}{tekst}: geselecteerde tekst wordt de linktekst.
      latex = '\\link{https://}{' + (selected || 'tekst') + '}';
      this._insertAtCursor(latex, selected ? null : 'tekst');
      return;
    }

    switch (action) {
      case 'glossary':
        latex = '\\input{cyberveilig_woordenboek2024_glossary.tex}\n';
        break;
      case 'bibliography':
        latex = '\\bibliographystyle{acm}\n\\bibliography{opmaak/biblio}\n';
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
      case 'bevinding':
        // Kruisverwijzing naar een bevinding; argument is het bevinding-id.
        latex = '\\bevinding{' + (selected || '') + '}';
        this._insertAtCursor(latex);
        if (!selected) this.textarea.selectionStart = this.textarea.selectionEnd - 1;
        return;
      case 'uitwerking':
        latex = '\\uitwerking{' + (selected || '') + '}';
        this._insertAtCursor(latex);
        if (!selected) this.textarea.selectionStart = this.textarea.selectionEnd - 1;
        return;
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

  // ── Markdown/Word → LaTeX conversie (bij plakken) ──────────────────────────
  var _LTX_SPECIAL = { '\\': '\\textbackslash{}', '{': '\\{', '}': '\\}', '$': '\\$',
    '&': '\\&', '#': '\\#', '%': '\\%', '_': '\\_', '^': '\\textasciicircum{}',
    '~': '\\textasciitilde{}' };
  function _escLatex(s) {
    return (s || '').replace(/[\\{}$&#%_^~]/g, function(m) { return _LTX_SPECIAL[m]; });
  }
  // Inline-markdown op één regel -> LaTeX (links/code beschermd tegen escaping).
  function _mdInline(t) {
    var codes = [], links = [];
    t = t.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, function(_m, txt, url) {
      links.push({ txt: txt, url: url }); return '\x00L' + (links.length - 1) + '\x00';
    });
    t = t.replace(/`([^`]+)`/g, function(_m, c) { codes.push(c); return '\x00C' + (codes.length - 1) + '\x00'; });
    t = _escLatex(t);
    t = t.replace(/\*\*([^*]+)\*\*/g, '\\textbf{$1}').replace(/\*([^*]+)\*/g, '\\textit{$1}');
    t = t.replace(/\x00C(\d+)\x00/g, function(_m, n) { return '\\texttt{' + _escLatex(codes[+n]) + '}'; });
    t = t.replace(/\x00L(\d+)\x00/g, function(_m, n) {
      var l = links[+n]; return '\\href{' + l.url + '}{' + _escLatex(l.txt) + '}';
    });
    return t;
  }
  function _looksLikeMarkdown(t) {
    return /(^|\n)\s{0,3}#{1,6}\s/.test(t) || /(^|\n)\s{0,3}[-*+]\s/.test(t) ||
           /(^|\n)\s{0,3}\d+\.\s/.test(t) || /\*\*[^*]+\*\*/.test(t) ||
           /`[^`]+`/.test(t) || /\[[^\]]+\]\([^)\s]+\)/.test(t);
  }
  function _markdownToLatex(md) {
    var lines = (md || '').replace(/\r\n/g, '\n').split('\n');
    var out = [], i = 0;
    while (i < lines.length) {
      var ln = lines[i];
      var h = /^(#{1,6})\s+(.*)$/.exec(ln);
      if (h) {
        var lvl = h[1].length;
        var cmd = lvl <= 1 ? 'section' : lvl === 2 ? 'subsection' : 'subsubsection';
        out.push('\\' + cmd + '{' + _mdInline(h[2].trim()) + '}'); i++; continue;
      }
      if (/^\s{0,3}[-*+]\s+/.test(ln)) {
        var items = [];
        while (i < lines.length && /^\s{0,3}[-*+]\s+/.test(lines[i])) {
          items.push('  \\item ' + _mdInline(lines[i].replace(/^\s{0,3}[-*+]\s+/, ''))); i++;
        }
        out.push('\\begin{itemize}\n' + items.join('\n') + '\n\\end{itemize}'); continue;
      }
      if (/^\s{0,3}\d+\.\s+/.test(ln)) {
        var oitems = [];
        while (i < lines.length && /^\s{0,3}\d+\.\s+/.test(lines[i])) {
          oitems.push('  \\item ' + _mdInline(lines[i].replace(/^\s{0,3}\d+\.\s+/, ''))); i++;
        }
        out.push('\\begin{enumerate}\n' + oitems.join('\n') + '\n\\end{enumerate}'); continue;
      }
      if (ln.trim() === '') { out.push(''); i++; continue; }
      out.push(_mdInline(ln)); i++;
    }
    return out.join('\n');
  }
  // Word/HTML-fragment -> LaTeX (subset: koppen, vet/cursief/code, lijsten, links).
  function _htmlToLatex(html) {
    var doc;
    try { doc = new DOMParser().parseFromString(html, 'text/html'); }
    catch (e) { return null; }
    function walk(node) {
      var out = '';
      node.childNodes.forEach(function(n) {
        if (n.nodeType === 3) { out += _escLatex(n.nodeValue.replace(/\s+/g, ' ')); return; }
        if (n.nodeType !== 1) return;
        var tag = n.tagName.toLowerCase();
        var inner = walk(n);
        if (!inner.trim() && tag !== 'br') { return; }
        switch (tag) {
          case 'b': case 'strong': out += '\\textbf{' + inner + '}'; break;
          case 'i': case 'em': out += '\\textit{' + inner + '}'; break;
          case 'u': out += '\\underline{' + inner + '}'; break;
          case 'code': case 'tt': out += '\\texttt{' + inner + '}'; break;
          case 'h1': out += '\n\n\\section{' + inner + '}\n\n'; break;
          case 'h2': out += '\n\n\\subsection{' + inner + '}\n\n'; break;
          case 'h3': case 'h4': out += '\n\n\\subsubsection{' + inner + '}\n\n'; break;
          case 'p': case 'div': out += '\n\n' + inner + '\n\n'; break;
          case 'br': out += ' \\\\\n'; break;
          case 'ul': out += '\n\\begin{itemize}\n' + inner + '\\end{itemize}\n'; break;
          case 'ol': out += '\n\\begin{enumerate}\n' + inner + '\\end{enumerate}\n'; break;
          case 'li': out += '  \\item ' + inner.trim() + '\n'; break;
          case 'a':
            var href = n.getAttribute('href') || '';
            out += href ? ('\\href{' + href + '}{' + inner + '}') : inner; break;
          case 'blockquote': out += '\n\\begin{quote}\n' + inner + '\n\\end{quote}\n'; break;
          default: out += inner;
        }
      });
      return out;
    }
    var tex = walk(doc.body || doc.documentElement);
    return tex.replace(/\n{3,}/g, '\n\n').trim();
  }

  function _isImageUrl(u) {
    return /\.(png|jpe?g|gif|bmp|webp|svg)(\?|#|$)/i.test(u || '');
  }

  function _csrfToken() {
    var m = document.querySelector('meta[name="csrf-token"]');
    if (m && m.getAttribute('content')) return m.getAttribute('content');
    var i = document.querySelector('input[name="csrf_token"]');
    return i ? i.value : '';
  }

  // Gedeelde HTML voor één dropdown-item; toont een thumbnail bij een afbeelding.
  function _dropdownItemHtml(item) {
    var isImg = _isImageUrl(item.url);
    var thumb = isImg
      ? '<img class="latex-item-thumb" src="' + _escapeAttr(item.url) + '" alt="" loading="lazy" />'
      : '';
    var selectBtn = '<button type="button" class="latex-dropdown-item' + (thumb ? ' has-thumb' : '') +
      '" data-value="' + _escapeAttr(item.value) + '" data-title="' + _escapeAttr(item.title || item.sublabel || '') +
      '" data-url="' + _escapeAttr(item.url || '') + '">' +
      thumb +
      '<span class="latex-item-text">' +
        '<span class="latex-item-label">' + _escapeHtml(item.label) + '</span>' +
        (item.sublabel ? '<span class="latex-item-sublabel">' + _escapeHtml(item.sublabel) + '</span>' : '') +
      '</span>' +
    '</button>';
    // Lak-knop alleen bij redigeerbare projectafbeeldingen: opent de canvas-
    // redactie en bewaart een gelakte kopie voor de gelakte rapportversie.
    if (isImg && item.redactable === true) {
      var lakLabel = item.has_lakken ? '█ Lak ✓' : '█ Lakken';
      var lakCls = 'latex-item-lak' + (item.has_lakken ? ' has-lakken' : '');
      var lakBtn = '<button type="button" class="' + lakCls +
        '" data-lak-name="' + _escapeAttr(item.value) +
        '" data-lak-url="' + _escapeAttr(item.url || '') +
        '" data-has-lakken="' + (item.has_lakken ? '1' : '0') +
        '" data-has-annot="' + (item.has_annot ? '1' : '0') +
        '" title="Zwarte vlakken trekken voor de gelakte rapportversie">' + lakLabel + '</button>';
      return '<div class="latex-dropdown-row">' + selectBtn + lakBtn + '</div>';
    }
    return selectBtn;
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
