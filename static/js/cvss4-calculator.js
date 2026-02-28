// Copyright (C) 2021 Jan-Karel Visser info@jan-karel.nl
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * CVSS 4.0 Calculator
 * Implements FIRST CVSS 4.0 specification for base score calculation
 * https://www.first.org/cvss/v4.0/specification-document
 */

(function() {
  'use strict';

  // CVSS 4.0 Base Metrics with their possible values
  const METRICS = {
    // Exploitability Metrics
    AV: { // Attack Vector
      N: { label: 'Network', value: 0.0 },
      A: { label: 'Adjacent', value: 0.1 },
      L: { label: 'Local', value: 0.2 },
      P: { label: 'Physical', value: 0.3 }
    },
    AC: { // Attack Complexity
      L: { label: 'Low', value: 0.0 },
      H: { label: 'High', value: 0.1 }
    },
    AT: { // Attack Requirements
      N: { label: 'None', value: 0.0 },
      P: { label: 'Present', value: 0.1 }
    },
    PR: { // Privileges Required
      N: { label: 'None', value: 0.0 },
      L: { label: 'Low', value: 0.1 },
      H: { label: 'High', value: 0.2 }
    },
    UI: { // User Interaction
      N: { label: 'None', value: 0.0 },
      P: { label: 'Passive', value: 0.1 },
      A: { label: 'Active', value: 0.2 }
    },
    // Vulnerable System Impact
    VC: { // Confidentiality
      H: { label: 'High', value: 0.0 },
      L: { label: 'Low', value: 0.1 },
      N: { label: 'None', value: 0.2 }
    },
    VI: { // Integrity
      H: { label: 'High', value: 0.0 },
      L: { label: 'Low', value: 0.1 },
      N: { label: 'None', value: 0.2 }
    },
    VA: { // Availability
      H: { label: 'High', value: 0.0 },
      L: { label: 'Low', value: 0.1 },
      N: { label: 'None', value: 0.2 }
    },
    // Subsequent System Impact
    SC: { // Confidentiality
      H: { label: 'High', value: 0.0 },
      L: { label: 'Low', value: 0.1 },
      N: { label: 'None', value: 0.2 }
    },
    SI: { // Integrity
      H: { label: 'High', value: 0.0 },
      L: { label: 'Low', value: 0.1 },
      N: { label: 'None', value: 0.2 }
    },
    SA: { // Availability
      H: { label: 'High', value: 0.0 },
      L: { label: 'Low', value: 0.1 },
      N: { label: 'None', value: 0.2 }
    }
  };

  function getCalculatorEndpoint() {
    var body = document.body;
    var fromDataset = body ? (body.dataset.cvss4CalcUrl || '').trim() : '';
    return fromDataset || '/api/cvss4/calculate';
  }

  async function calculateScoreFromServer(vector) {
    var url = getCalculatorEndpoint() + '?vector=' + encodeURIComponent(vector || '');
    var resp = await fetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
      credentials: 'same-origin'
    });
    var payload = null;
    try {
      payload = await resp.json();
    } catch (_) {
      payload = null;
    }
    if (!resp.ok || !payload || payload.ok !== true) {
      throw new Error((payload && payload.error) || 'http_' + resp.status);
    }
    var score = Number(payload.score);
    var severity = String(payload.severity || '').toLowerCase();
    if (!Number.isFinite(score) || !severity) {
      throw new Error('invalid_payload');
    }
    return { score: score, severity: severity };
  }

  /**
   * Generate CVSS 4.0 vector string from metrics
   */
  function generateVector(metrics) {
    var parts = ['CVSS:4.0'];
    var order = ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA'];

    for (var i = 0; i < order.length; i++) {
      var metric = order[i];
      if (metrics[metric]) {
        parts.push(metric + ':' + metrics[metric]);
      }
    }

    return parts.join('/');
  }

  /**
   * Parse CVSS 4.0 vector string to metrics object
   */
  function parseVector(vector) {
    var metrics = {};

    if (!vector || typeof vector !== 'string') {
      return metrics;
    }

    var cleanVector = vector.replace(/^CVSS:4\.0\/?/i, '');

    var parts = cleanVector.split('/');
    for (var i = 0; i < parts.length; i++) {
      var pair = parts[i].split(':');
      var m = pair[0];
      var v = pair[1];
      if (m && v && METRICS[m] && METRICS[m][v]) {
        metrics[m] = v;
      }
    }

    return metrics;
  }

  /**
   * Get severity label from score
   */
  function getSeverity(score) {
    if (score === 0) return 'none';
    if (score < 4.0) return 'low';
    if (score < 7.0) return 'medium';
    if (score < 9.0) return 'high';
    return 'critical';
  }

  /**
   * Initialize CVSS 4.0 calculator on an element
   */
  function initCalculator(container) {
    if (!container) return;

    var form = container.closest('form');
    var searchContext = form || container.parentElement || document;

    var vectorInput = container.querySelector('[data-cvss-vector]') ||
                      searchContext.querySelector('[data-cvss-vector]') ||
                      searchContext.querySelector('input[name="cvss_vector"]');
    var scoreInput = searchContext.querySelector('input[name="cvss_score"]') ||
                     searchContext.querySelector('input[name="basescore"]');
    var scoreDisplay = container.querySelector('[data-cvss-score]');
    var severityDisplay = container.querySelector('[data-cvss-severity]');

    // Build calculator UI
    var calcHtml = buildCalculatorUI();
    var calcPanel = document.createElement('div');
    calcPanel.className = 'cvss4-calculator';
    calcPanel.innerHTML = calcHtml;
    container.appendChild(calcPanel);

    var selects = calcPanel.querySelectorAll('select[data-metric]');

    // Parse existing vector if present
    if (vectorInput && vectorInput.value) {
      var existingMetrics = parseVector(vectorInput.value);
      for (var i = 0; i < selects.length; i++) {
        var metric = selects[i].dataset.metric;
        if (existingMetrics[metric]) {
          selects[i].value = existingMetrics[metric];
        }
      }
    }

    var updateToken = 0;

    function applyCalculatedResult(score, severity) {
      if (scoreInput) scoreInput.value = score.toFixed(1);
      if (scoreDisplay) scoreDisplay.textContent = score.toFixed(1);
      if (severityDisplay) {
        var severityText = severity.charAt(0).toUpperCase() + severity.slice(1);
        severityDisplay.textContent = severityText;
        severityDisplay.className = 'badge sev-' + severity;
      }
    }

    function applyCalculationError() {
      if (scoreInput) scoreInput.value = '';
      if (scoreDisplay) scoreDisplay.textContent = '-';
      if (severityDisplay) {
        severityDisplay.textContent = 'Invalid';
        severityDisplay.className = 'badge';
      }
    }

    async function update() {
      var metrics = {};
      for (var i = 0; i < selects.length; i++) {
        metrics[selects[i].dataset.metric] = selects[i].value;
      }

      var vector = generateVector(metrics);
      if (vectorInput) vectorInput.value = vector;
      var token = ++updateToken;
      try {
        var result = await calculateScoreFromServer(vector);
        if (token !== updateToken) return;
        applyCalculatedResult(result.score, result.severity);
      } catch (_) {
        if (token !== updateToken) return;
        applyCalculationError();
      }
    }

    calcPanel.addEventListener('change', function(e) {
      if (e.target && e.target.matches('select[data-metric]')) {
        update();
      }
    });

    // Initial calculation if we have existing values
    if (vectorInput && vectorInput.value) {
      update();
    }

    // Toggle visibility
    var toggleBtn = container.querySelector('[data-cvss-toggle]');
    if (toggleBtn) {
      toggleBtn.addEventListener('click', function() {
        calcPanel.classList.toggle('hidden');
        this.textContent = calcPanel.classList.contains('hidden') ? 'CVSS 4.0 Calculator' : 'Verberg Calculator';
      });
      calcPanel.classList.add('hidden');
    }

    // Sync calculator when vector input changes manually
    if (vectorInput) {
      vectorInput.addEventListener('change', function() {
        var existingMetrics = parseVector(this.value);
        for (var i = 0; i < selects.length; i++) {
          var metric = selects[i].dataset.metric;
          if (existingMetrics[metric]) {
            selects[i].value = existingMetrics[metric];
          }
        }
        void update();
      });
    }
  }

  /**
   * Build the calculator UI HTML
   */
  function buildCalculatorUI() {
    var sections = [
      {
        title: 'Exploitability',
        metrics: [
          { id: 'AV', name: 'Attack Vector', options: ['N', 'A', 'L', 'P'] },
          { id: 'AC', name: 'Attack Complexity', options: ['L', 'H'] },
          { id: 'AT', name: 'Attack Requirements', options: ['N', 'P'] },
          { id: 'PR', name: 'Privileges Required', options: ['N', 'L', 'H'] },
          { id: 'UI', name: 'User Interaction', options: ['N', 'P', 'A'] }
        ]
      },
      {
        title: 'Vulnerable System Impact',
        metrics: [
          { id: 'VC', name: 'Confidentiality', options: ['N', 'L', 'H'] },
          { id: 'VI', name: 'Integrity', options: ['N', 'L', 'H'] },
          { id: 'VA', name: 'Availability', options: ['N', 'L', 'H'] }
        ]
      },
      {
        title: 'Subsequent System Impact',
        metrics: [
          { id: 'SC', name: 'Confidentiality', options: ['N', 'L', 'H'] },
          { id: 'SI', name: 'Integrity', options: ['N', 'L', 'H'] },
          { id: 'SA', name: 'Availability', options: ['N', 'L', 'H'] }
        ]
      }
    ];

    var html = '<div class="cvss4-sections">';

    for (var s = 0; s < sections.length; s++) {
      var section = sections[s];
      html += '<div class="cvss4-section">' +
        '<div class="cvss4-section-title">' + section.title + '</div>' +
        '<div class="cvss4-metrics">';

      for (var m = 0; m < section.metrics.length; m++) {
        var metric = section.metrics[m];
        html += '<label class="cvss4-metric">' +
          '<span class="cvss4-metric-name">' + metric.name + '</span>' +
          '<select data-metric="' + metric.id + '">';

        for (var o = 0; o < metric.options.length; o++) {
          var opt = metric.options[o];
          var info = METRICS[metric.id][opt];
          html += '<option value="' + opt + '">' + opt + ' - ' + info.label + '</option>';
        }

        html += '</select></label>';
      }

      html += '</div></div>';
    }

    html += '</div>';
    return html;
  }

  // Expose API
  window.CVSS4 = {
    generateVector: generateVector,
    parseVector: parseVector,
    getSeverity: getSeverity,
    init: initCalculator,
    METRICS: METRICS
  };

  // Auto-init on DOM ready
  document.addEventListener('DOMContentLoaded', function() {
    var calculators = document.querySelectorAll('[data-cvss4-calculator]');
    calculators.forEach(function(el) {
      if (el.querySelector('.cvss4-calculator')) return; // already initialized
      initCalculator(el);
    });
  });

})();
