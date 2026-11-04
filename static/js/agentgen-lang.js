/**
 * agentgen-lang.js — koppelt taal-dropdown aan PayloadInject defaultFile
 * Geladen als extern script (geen inline nonce nodig).
 */
(function () {
  'use strict';

  var LANG_FILE = {
    bash:       'payloads/agent.sh',
    powershell: 'payloads/agent.ps1',
    python:     'payloads/agent.py',
    csharp:     'payloads/agent.exe',
    go:         'payloads/agent.go',
    rust:       'payloads/agent.rs',
    ruby:       'payloads/agent.rb',
  };

  function init() {
    var langSel = document.getElementById('language');
    if (!langSel) return;

    // PayloadInject is al geïnitialiseerd via auto-init in payload-inject.js.
    // Zoek de gegenereerde inject-wrapper op via data-insert-after.
    // Omdat auto-init de placeholder verwijdert, houden we de referentie via
    // een DOMContentLoaded-volgorde: payload-inject.js draait vóór dit bestand.
    // We binden een MutationObserver op gen-preview-section om de inject-instantie
    // te vinden zodra die is ingevoegd, of we roepen PayloadInject opnieuw aan
    // en slaan de retourwaarde op.

    // Eenvoudiger: sla de retourwaarde op via window.__agentPI na auto-init.
    // payload-inject.js stelt window.__payloadInjectInstances in als Map.
    var instances = window.__payloadInjectInstances;
    if (!instances) return;

    // Zoek de instantie voor gen-form
    var pi = instances.get('gen-form');
    if (!pi) return;

    langSel.addEventListener('change', function () {
      var file = LANG_FILE[langSel.value] || 'payloads/agent.sh';
      pi.setDefaultFile(file);
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
