/* ── Global Tools: Field Manual + Settings modal ─────── */
(() => {
  "use strict";

  // ── Helpers ────────────────────────────────────────────
  function escapeHtml(s) {
    const d = document.createElement("div");
    d.appendChild(document.createTextNode(s));
    return d.innerHTML;
  }

  function btnFeedback(btn, text, cls) {
    const old = btn.textContent;
    btn.textContent = text;
    if (cls) btn.classList.add(cls);
    setTimeout(() => {
      btn.textContent = old;
      if (cls) btn.classList.remove(cls);
    }, 1200);
  }

  // ═══════════════════════════════════════════════════════
  // Settings modal
  // ═══════════════════════════════════════════════════════
  const settingsModal = document.getElementById("settings-modal");
  const btnSettingsOpen = document.getElementById("btn-settings");
  const btnSettingsClose = document.getElementById("btn-settings-close");
  const togUpload = document.getElementById("tog-upload");
  const togDownload = document.getElementById("tog-download");
  const togPayloads = document.getElementById("tog-payloads");

  function openSettings() {
    fetch("/api/settings")
      .then(r => r.json())
      .then(d => {
        if (togUpload) togUpload.checked = d.public_upload;
        if (togDownload) togDownload.checked = d.public_downloads;
        if (togPayloads) togPayloads.checked = d.public_payloads;
        if (settingsModal) settingsModal.style.display = "flex";
      });
  }

  function closeSettings() {
    if (settingsModal) settingsModal.style.display = "none";
  }

  function saveSetting(key, val) {
    fetch("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ [key]: val }),
    });
  }

  if (btnSettingsOpen) btnSettingsOpen.addEventListener("click", openSettings);
  if (btnSettingsClose) btnSettingsClose.addEventListener("click", closeSettings);
  if (settingsModal) settingsModal.addEventListener("click", (e) => {
    if (e.target === settingsModal) closeSettings();
  });
  if (togUpload) togUpload.addEventListener("change", () => saveSetting("public_upload", togUpload.checked));
  if (togDownload) togDownload.addEventListener("change", () => saveSetting("public_downloads", togDownload.checked));
  if (togPayloads) togPayloads.addEventListener("change", () => saveSetting("public_payloads", togPayloads.checked));

  // ═══════════════════════════════════════════════════════
  // Field Manual modal
  // ═══════════════════════════════════════════════════════
  const fmModal = document.getElementById("fm-modal");
  const fmContainer = document.getElementById("fm-commands");
  const fmFilterInput = document.getElementById("fm-filter");
  const fmFindInput = document.getElementById("fm-find");
  const fmReplaceInput = document.getElementById("fm-replace");
  const fmHttpsCheckbox = document.getElementById("fm-https");
  const btnFm = document.getElementById("btn-fieldmanual");
  const btnFmClose = document.getElementById("btn-fm-close");

  let fmCommands = null;
  const fmCollapsed = {};

  const FM_CATEGORIES = [
    { prefix: "amsi_",      label: "AMSI Bypass" },
    { prefix: "av_",        label: "AV Bypass" },
    { prefix: "adcs_",      label: "AD CS Attacks" },
    { prefix: "ad_",        label: "Active Directory" },
    { prefix: "applocker_", label: "AppLocker Bypass" },
    { prefix: "cred_",      label: "Credential Dumping" },
    { prefix: "enum_",      label: "Enumeratie" },
    { prefix: "exploit_",   label: "Exploits" },
    { prefix: "get_",       label: "Tool Downloads" },
    { prefix: "inject_",    label: "Process Injection" },
    { prefix: "kerb_",      label: "Kerberos" },
    { prefix: "lateral_",   label: "Lateral Movement (Windows)" },
    { prefix: "linux_",     label: "Linux Post-Exploitation" },
    { prefix: "mssql_",     label: "MSSQL Attacks" },
    { prefix: "net_",       label: "Network Evasion" },
    { prefix: "passwd_",    label: "Password Attacks" },
    { prefix: "persist_",   label: "Persistence" },
    { prefix: "privesc_",   label: "Privilege Escalation" },
    { prefix: "ps_cradle_", label: "PowerShell Cradles" },
    { prefix: "ps",         label: "PowerShell Payloads" },
    { prefix: "msf",        label: "Metasploit" },
    { prefix: "proof_",     label: "Proof / Flags" },
    { prefix: "recon_",     label: "Reconnaissance" },
    { prefix: "shell_",     label: "Reverse Shells" },
    { prefix: "tunnel_",    label: "Tunneling / Pivoting" },
    { prefix: "web_ssti_",  label: "Web: SSTI" },
    { prefix: "web_sqli_",  label: "Web: SQL Injection" },
    { prefix: "web_cmdi_",  label: "Web: Command Injection" },
    { prefix: "web_xss_",   label: "Web: XSS" },
    { prefix: "web_xxe_",   label: "Web: XXE" },
    { prefix: "web_ssrf_",  label: "Web: SSRF" },
    { prefix: "web_lfi_",   label: "Web: LFI / Traversal" },
    { prefix: "web_deser_", label: "Web: Deserialization" },
    { prefix: "web_",       label: "Web: Overig" }
  ];

  function fmCategoryKey(name) {
    for (const cat of FM_CATEGORIES) {
      if (name.indexOf(cat.prefix) === 0) return cat.prefix;
    }
    return "_other";
  }

  function fmCategoryLabel(key) {
    for (const cat of FM_CATEGORIES) {
      if (cat.prefix === key) return cat.label;
    }
    return "Overig";
  }

  function fmGetReplacements() {
    const reps = [];
    if (fmHttpsCheckbox && fmHttpsCheckbox.checked) {
      reps.push({ find: "http://", replace: "https://" });
    }
    const f = fmFindInput ? fmFindInput.value : "";
    const r = fmReplaceInput ? fmReplaceInput.value : "";
    if (f) reps.push({ find: f, replace: r });
    return reps;
  }

  function fmApplyReplacements(text) {
    const reps = fmGetReplacements();
    for (const r of reps) text = text.split(r.find).join(r.replace);
    return text;
  }

  function fmHighlight(text) {
    const reps = fmGetReplacements();
    let html = escapeHtml(text);
    for (const r of reps) {
      const needle = escapeHtml(r.replace);
      if (needle) {
        html = html.split(needle).join('<mark>' + needle + '</mark>');
      }
    }
    return html;
  }

  function fmCopy(content, btn) {
    const text = fmApplyReplacements(content);
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(() => btnFeedback(btn, "Gekopieerd!", "copied"));
    } else {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
      btnFeedback(btn, "Gekopieerd!", "copied");
    }
  }

  function renderFieldManual(filter) {
    if (!fmContainer || !fmCommands) return;
    fmContainer.innerHTML = "";
    const term = (filter || "").toLowerCase();

    const filtered = fmCommands.filter(cmd =>
      !term || cmd.name.toLowerCase().includes(term) || cmd.content.toLowerCase().includes(term)
    );

    if (filtered.length === 0) {
      fmContainer.innerHTML = '<p class="fm-empty">Geen commands gevonden' +
        (term ? ' voor \u201c' + escapeHtml(term) + '\u201d' : '') + '.</p>';
      return;
    }

    const groups = {};
    const order = [];
    for (const cmd of filtered) {
      const key = fmCategoryKey(cmd.name);
      if (!groups[key]) { groups[key] = []; order.push(key); }
      groups[key].push(cmd);
    }

    for (const key of order) {
      const cmds = groups[key];
      const label = fmCategoryLabel(key);
      const collapsed = !!fmCollapsed[key];

      const section = document.createElement("div");
      section.className = "fm-category";

      const header = document.createElement("div");
      header.className = "fm-category-header" + (collapsed ? " collapsed" : "");
      header.innerHTML =
        '<span class="fm-chevron"></span>' +
        '<span class="fm-cat-label">' + escapeHtml(label) + '</span>' +
        '<span class="fm-cat-count">' + cmds.length + '</span>';
      header.addEventListener("click", () => {
        fmCollapsed[key] = !fmCollapsed[key];
        renderFieldManual(fmFilterInput ? fmFilterInput.value : "");
      });
      section.appendChild(header);

      if (!collapsed) {
        const body = document.createElement("div");
        body.className = "fm-category-body";
        for (const cmd of cmds) {
          const item = document.createElement("div");
          item.className = "fm-item";

          const head = document.createElement("div");
          head.className = "fm-item-head";
          const nameEl = document.createElement("span");
          nameEl.className = "fm-item-name";
          nameEl.textContent = cmd.name;
          const copyBtn = document.createElement("button");
          copyBtn.className = "fm-copy-btn";
          copyBtn.textContent = "Kopieer";
          copyBtn.type = "button";
          copyBtn.addEventListener("click", () => fmCopy(cmd.content, copyBtn));
          head.appendChild(nameEl);
          head.appendChild(copyBtn);

          const code = document.createElement("pre");
          code.className = "fm-code";
          const replaced = fmApplyReplacements(cmd.content);
          if (replaced !== cmd.content) {
            code.innerHTML = fmHighlight(replaced);
          } else {
            code.textContent = cmd.content;
          }

          item.appendChild(head);
          item.appendChild(code);
          body.appendChild(item);
        }
        section.appendChild(body);
      }

      fmContainer.appendChild(section);
    }
  }

  function openFieldManual() {
    if (!fmModal) return;
    fmModal.style.display = "flex";
    if (fmFilterInput) { fmFilterInput.value = ""; fmFilterInput.focus(); }
    if (!fmCommands) {
      if (fmContainer) fmContainer.innerHTML = '<p class="fm-empty">Laden...</p>';
      fetch("/api/commands")
        .then(r => r.json())
        .then(data => {
          fmCommands = data.commands || [];
          renderFieldManual("");
        })
        .catch(() => { if (fmContainer) fmContainer.innerHTML = '<p class="fm-empty">Fout bij laden.</p>'; });
    } else {
      renderFieldManual("");
    }
  }

  function closeFieldManual() {
    if (fmModal) fmModal.style.display = "none";
  }

  if (btnFm) btnFm.addEventListener("click", openFieldManual);
  if (btnFmClose) btnFmClose.addEventListener("click", closeFieldManual);
  if (fmModal) fmModal.addEventListener("click", (e) => { if (e.target === fmModal) closeFieldManual(); });

  // Debounced re-render
  let fmDebounce = null;
  function fmRerender() {
    clearTimeout(fmDebounce);
    fmDebounce = setTimeout(() => renderFieldManual(fmFilterInput ? fmFilterInput.value : ""), 150);
  }
  if (fmFilterInput) fmFilterInput.addEventListener("input", fmRerender);
  if (fmFindInput) fmFindInput.addEventListener("input", fmRerender);
  if (fmReplaceInput) fmReplaceInput.addEventListener("input", fmRerender);
  if (fmHttpsCheckbox) fmHttpsCheckbox.addEventListener("change", fmRerender);

  // ═══════════════════════════════════════════════════════
  // Note quick-add modal
  // ═══════════════════════════════════════════════════════
  const noteModal = document.getElementById("note-modal");
  const btnNewNote = document.getElementById("btn-new-note");
  const btnNoteClose = document.getElementById("btn-note-close");
  const btnNoteSave = document.getElementById("btn-note-save");
  const noteNaam = document.getElementById("note-naam");
  const noteUitwerken = document.getElementById("note-uitwerken");
  const noteStatus = document.getElementById("note-status");

  function openNoteModal() {
    if (!noteModal) return;
    noteModal.style.display = "flex";
    if (noteNaam) noteNaam.focus();
  }

  function closeNoteModal() {
    if (!noteModal) return;
    noteModal.style.display = "none";
    if (noteNaam) noteNaam.value = "";
    if (noteUitwerken) noteUitwerken.value = "";
    if (noteStatus) { noteStatus.textContent = ""; noteStatus.style.color = ""; }
  }

  function saveNote() {
    const naam = noteNaam ? noteNaam.value.trim() : "";
    if (!naam) { if (noteStatus) { noteStatus.textContent = "Naam is verplicht"; noteStatus.style.color = "var(--danger, #ef4444)"; } return; }
    const fd = new FormData();
    fd.append("naam", naam);
    fd.append("uitwerken", noteUitwerken ? noteUitwerken.value : "");
    fetch("/dashboard/notes/add", {
      method: "POST",
      headers: { "X-Requested-With": "XMLHttpRequest" },
      body: fd,
    })
      .then(r => r.json())
      .then(d => {
        if (d.ok) {
          if (noteStatus) { noteStatus.textContent = "Opgeslagen!"; noteStatus.style.color = "var(--success, #22c55e)"; }
          setTimeout(closeNoteModal, 800);
        } else {
          if (noteStatus) { noteStatus.textContent = d.error || "Fout"; noteStatus.style.color = "var(--danger, #ef4444)"; }
        }
      })
      .catch(() => { if (noteStatus) { noteStatus.textContent = "Fout"; noteStatus.style.color = "var(--danger, #ef4444)"; } });
  }

  if (btnNewNote) btnNewNote.addEventListener("click", openNoteModal);
  if (btnNoteClose) btnNoteClose.addEventListener("click", closeNoteModal);
  if (noteModal) noteModal.addEventListener("click", (e) => { if (e.target === noteModal) closeNoteModal(); });
  if (btnNoteSave) btnNoteSave.addEventListener("click", saveNote);

  // ═══════════════════════════════════════════════════════
  // Finding quick-add modal
  // ═══════════════════════════════════════════════════════
  const findingModal = document.getElementById("finding-modal");
  const btnNewFinding = document.getElementById("btn-new-finding");
  const btnFindingClose = document.getElementById("btn-finding-close");
  const btnFindingSave = document.getElementById("btn-finding-save");
  const findingCsrf = document.getElementById("finding-csrf");
  const findingTemplate = document.getElementById("finding-template");
  const findingNaam = document.getElementById("finding-naam");
  const findingLocatie = document.getElementById("finding-locatie");
  const findingCvss = document.getElementById("finding-cvss");
  const findingBasescore = document.getElementById("finding-basescore");
  const findingUitwerken = document.getElementById("finding-uitwerken");
  const findingStatus = document.getElementById("finding-status");
  let findingTemplatesLoaded = false;

  function openFindingModal() {
    if (!findingModal) return;
    findingModal.style.display = "flex";
    if (findingNaam) findingNaam.focus();
    if (!findingTemplatesLoaded && findingTemplate) {
      fetch("/api/findings/templates")
        .then(r => r.json())
        .then(d => {
          findingTemplatesLoaded = true;
          const templates = d.templates || [];
          for (const t of templates) {
            const opt = document.createElement("option");
            opt.value = t.id;
            opt.textContent = t.titel + (t.bevtype ? " (" + t.bevtype + ")" : "");
            findingTemplate.appendChild(opt);
          }
        })
        .catch(() => {});
    }
  }

  function closeFindingModal() {
    if (!findingModal) return;
    findingModal.style.display = "none";
    if (findingTemplate) findingTemplate.value = "";
    if (findingNaam) findingNaam.value = "";
    if (findingLocatie) findingLocatie.value = "";
    if (findingCvss) findingCvss.value = "";
    if (findingBasescore) findingBasescore.value = "";
    if (findingUitwerken) findingUitwerken.value = "";
    if (findingStatus) { findingStatus.textContent = ""; findingStatus.style.color = ""; }
  }

  function saveFinding() {
    const naam = findingNaam ? findingNaam.value.trim() : "";
    if (!naam) { if (findingStatus) { findingStatus.textContent = "Naam is verplicht"; findingStatus.style.color = "var(--danger, #ef4444)"; } return; }
    const fd = new FormData();
    if (findingCsrf) fd.append("csrf_token", findingCsrf.value);
    fd.append("naam", naam);
    fd.append("locatie", findingLocatie ? findingLocatie.value : "");
    fd.append("uitwerken", findingUitwerken ? findingUitwerken.value : "");
    fd.append("ref", findingTemplate ? findingTemplate.value : "");
    fd.append("cvss", findingCvss ? findingCvss.value : "");
    fd.append("basescore", findingBasescore ? findingBasescore.value : "");
    fetch("/dashboard/findings/save", {
      method: "POST",
      headers: { "X-Requested-With": "XMLHttpRequest" },
      body: fd,
    })
      .then(r => r.json())
      .then(d => {
        if (d.ok) {
          if (findingStatus) { findingStatus.textContent = "Opgeslagen!"; findingStatus.style.color = "var(--success, #22c55e)"; }
          setTimeout(closeFindingModal, 800);
        } else {
          if (findingStatus) { findingStatus.textContent = d.error || "Fout"; findingStatus.style.color = "var(--danger, #ef4444)"; }
        }
      })
      .catch(() => { if (findingStatus) { findingStatus.textContent = "Fout"; findingStatus.style.color = "var(--danger, #ef4444)"; } });
  }

  if (btnNewFinding) btnNewFinding.addEventListener("click", openFindingModal);
  if (btnFindingClose) btnFindingClose.addEventListener("click", closeFindingModal);
  if (findingModal) findingModal.addEventListener("click", (e) => { if (e.target === findingModal) closeFindingModal(); });
  if (btnFindingSave) btnFindingSave.addEventListener("click", saveFinding);
  if (findingTemplate) findingTemplate.addEventListener("change", () => {
    const sel = findingTemplate.options[findingTemplate.selectedIndex];
    if (sel && sel.value && findingNaam && !findingNaam.value.trim()) {
      findingNaam.value = sel.textContent.replace(/\s*\(.*\)\s*$/, "");
    }
  });

  // ── Keyboard shortcuts ────────────────────────────────
  document.addEventListener("keydown", (e) => {
    // Escape closes any open modal
    if (e.key === "Escape") {
      if (noteModal && noteModal.style.display !== "none") { closeNoteModal(); return; }
      if (findingModal && findingModal.style.display !== "none") { closeFindingModal(); return; }
      if (fmModal && fmModal.style.display !== "none") { closeFieldManual(); return; }
      if (settingsModal && settingsModal.style.display !== "none") { closeSettings(); return; }
    }
    // Ctrl/Cmd+K toggles Field Manual
    if ((e.ctrlKey || e.metaKey) && e.key === "k") {
      e.preventDefault();
      if (fmModal && fmModal.style.display !== "none") {
        closeFieldManual();
      } else {
        openFieldManual();
      }
    }
  });
})();
