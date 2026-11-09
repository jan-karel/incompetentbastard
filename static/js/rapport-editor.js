/* rapport-editor.js — inline editing for findings & notes on the rapport dashboard */
(function () {
  "use strict";

  // ═══════════════════════════════════════════════════
  // 0. Generate report via async API
  // ═══════════════════════════════════════════════════
  var btnGenerate = document.getElementById("btn-generate-report");
  var generateStatus = document.getElementById("generate-status");

  function pollAsyncRun(runId) {
    fetch("/api/report/generate/" + runId)
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (d.status === "running" || d.status === "queued") {
          if (generateStatus) generateStatus.textContent = "Genereren... (" + d.status + ")";
          setTimeout(function () { pollAsyncRun(runId); }, 1500);
        } else if (d.status === "success") {
          if (generateStatus) {
            generateStatus.textContent = "Rapport gegenereerd!";
            generateStatus.style.color = "var(--success, #22c55e)";
          }
          btnGenerate.disabled = false;
          loadVersions();
          setTimeout(function () { if (generateStatus) generateStatus.textContent = ""; }, 3000);
        } else {
          if (generateStatus) {
            generateStatus.textContent = "Fout: " + (d.error || "onbekend");
            generateStatus.style.color = "var(--danger, #ef4444)";
          }
          btnGenerate.disabled = false;
        }
      })
      .catch(function () {
        if (generateStatus) {
          generateStatus.textContent = "Polling fout";
          generateStatus.style.color = "var(--danger, #ef4444)";
        }
        btnGenerate.disabled = false;
      });
  }

  // ── Checklist toggle ──────────────────────────────
  var clToggle = document.getElementById("include-checklists");
  var clWrap = document.getElementById("checklist-select-wrap");
  if (clToggle && clWrap) {
    clToggle.addEventListener("change", function () {
      clWrap.style.display = clToggle.checked ? "block" : "none";
    });
  }

  function collectChecklistIds() {
    if (!clToggle || !clToggle.checked) return "";
    var ids = [];
    document.querySelectorAll(".checklist-cb").forEach(function (cb) {
      if (cb.checked) ids.push(cb.value);
    });
    return ids.join(",");
  }

  if (btnGenerate) {
    btnGenerate.addEventListener("click", function () {
      var draft = document.getElementById("include-draft");
      var includeDraft = draft && draft.checked;
      var checklistIds = collectChecklistIds();

      btnGenerate.disabled = true;
      if (generateStatus) {
        generateStatus.textContent = "Starten...";
        generateStatus.style.color = "";
      }

      fetch("/api/report/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ include_draft: includeDraft, include_checklists: checklistIds })
      })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          if (d.ok && d.run_id) {
            pollAsyncRun(d.run_id);
          } else {
            if (generateStatus) {
              generateStatus.textContent = "Fout bij starten";
              generateStatus.style.color = "var(--danger, #ef4444)";
            }
            btnGenerate.disabled = false;
          }
        })
        .catch(function () {
          if (generateStatus) {
            generateStatus.textContent = "Fout bij starten";
            generateStatus.style.color = "var(--danger, #ef4444)";
          }
          btnGenerate.disabled = false;
        });
    });
  }

  // ═══════════════════════════════════════════════════
  // 0b. Report versions laden
  // ═══════════════════════════════════════════════════
  // Downloads vrijgeven zodra er een gegenereerd rapport is
  function setDownloadsReady(ready, timestamp) {
    var area = document.getElementById("download-area");
    if (!area) return;
    area.classList.toggle("downloads-ready", !!ready);
    area.classList.toggle("downloads-locked", !ready);
    var hint = document.getElementById("download-hint");
    if (hint) {
      hint.textContent = ready
        ? (timestamp ? "Laatst gegenereerd: " + timestamp : "Rapport beschikbaar.")
        : "Genereer eerst een rapport; daarna worden de downloads beschikbaar.";
    }
  }

  function loadVersions() {
    var el = document.getElementById("versions-list");
    fetch("/api/report/versions")
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var items = d.versions || [];
        setDownloadsReady(items.length > 0, items.length ? items[0].timestamp : "");
        if (!el) return;
        if (!items.length) {
          el.innerHTML = "Nog geen versies. Genereer eerst een rapport.";
          return;
        }
        var html = '<table class="table compact"><thead><tr><th>Tijdstempel</th><th>Bestanden</th></tr></thead><tbody>';
        items.forEach(function (v) {
          html += "<tr><td>" + v.timestamp + "</td><td>" + (v.files || []).join(", ") + "</td></tr>";
        });
        html += "</tbody></table>";
        el.innerHTML = html;
      })
      .catch(function () {
        if (el) el.innerHTML = "Kon versies niet laden.";
      });
  }
  loadVersions();

  // ═══════════════════════════════════════════════════
  // 1. Finding status inline change
  // ═══════════════════════════════════════════════════
  document.querySelectorAll(".status-inline").forEach(function (sel) {
    sel.addEventListener("change", function () {
      var id = sel.getAttribute("data-finding-id");
      var status = sel.value;
      var row = sel.closest("tr");

      fetch("/api/findings/" + id + "/status", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: status }),
      })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          if (d.ok) {
            sel.style.borderColor = "var(--success, #22c55e)";
            setTimeout(function () { sel.style.borderColor = ""; }, 1200);

            // Toggle rapport-included class
            if (row) {
              if (status === "final") {
                row.classList.add("rapport-included");
              } else {
                row.classList.remove("rapport-included");
              }
            }

            // Update KPI counter
            updateFindingsCounter();
          }
        });
    });
  });

  function updateFindingsCounter() {
    var finalCount = document.querySelectorAll("tr.rapport-included").length;
    var totalCount = document.querySelectorAll("#rapport-findings-table tbody tr").length;
    var counter = document.getElementById("findings-counter");
    if (counter) {
      counter.textContent = finalCount + " definitief van " + totalCount;
    }
    var kpi = document.getElementById("kpi-final");
    if (kpi) {
      kpi.textContent = finalCount;
    }
  }

  // ═══════════════════════════════════════════════════
  // 2. Finding edit modal  (rap- prefixed IDs)
  // ═══════════════════════════════════════════════════
  var findingModal = document.getElementById("rap-finding-modal");
  var findingModalBody = document.getElementById("rap-finding-body");
  var findingModalClose = document.getElementById("rap-finding-close");

  document.querySelectorAll("[data-edit-finding]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var id = btn.getAttribute("data-edit-finding");
      if (!findingModal || !findingModalBody) return;
      findingModalBody.innerHTML = '<p class="help">Laden...</p>';
      findingModal.style.display = "flex";

      fetch("/dashboard/findings/edit/" + id, {
        headers: { "X-Requested-With": "XMLHttpRequest" },
      })
        .then(function (r) { return r.text(); })
        .then(function (html) {
          findingModalBody.innerHTML = html;

          // Init CVSS calculator if available
          if (window.CVSS4 && typeof window.CVSS4.init === "function") {
            window.CVSS4.init();
          }
          // Init LaTeX toolbar if available
          if (typeof window.initLatexToolbar === "function") {
            window.initLatexToolbar();
          }
          // Init standaardbevinding-koppeling/overrides if available
          if (typeof window.initFindingTemplate === "function") {
            window.initFindingTemplate();
          }
          // Init tabbladen in het bevinding-formulier if available
          if (typeof window.initFindingTabs === "function") {
            window.initFindingTabs();
          }

          // Intercept form submit for AJAX
          var form = findingModalBody.querySelector("form");
          if (form) {
            form.addEventListener("submit", function (e) {
              e.preventDefault();
              var formData = new FormData(form);
              fetch("/dashboard/findings/save", {
                method: "POST",
                headers: { "X-Requested-With": "XMLHttpRequest" },
                body: formData,
              })
                .then(function (r) { return r.json(); })
                .then(function (d) {
                  if (d.ok) {
                    findingModal.style.display = "none";
                    location.reload();
                  }
                });
            });
          }
        });
    });
  });

  if (findingModalClose) {
    findingModalClose.addEventListener("click", function () {
      findingModal.style.display = "none";
      findingModalBody.innerHTML = "";
    });
  }

  if (findingModal) {
    findingModal.addEventListener("click", function (e) {
      if (e.target === findingModal) {
        findingModal.style.display = "none";
        findingModalBody.innerHTML = "";
      }
    });
  }

  // ═══════════════════════════════════════════════════
  // 3. Note edit / add modal  (rap- prefixed IDs)
  // ═══════════════════════════════════════════════════
  var noteModal = document.getElementById("rap-note-modal");
  var noteModalTitle = document.getElementById("rap-note-title");
  var noteEditId = document.getElementById("rap-note-id");
  var noteEditNaam = document.getElementById("rap-note-naam");
  var noteEditUitwerken = document.getElementById("rap-note-uitwerken");
  var noteModalSave = document.getElementById("rap-note-save");
  var noteModalCancel = document.getElementById("rap-note-cancel");
  var noteModalClose = document.getElementById("rap-note-close");

  function openNoteModal(id, naam, uitwerken) {
    if (!noteModal) return;
    noteEditId.value = id || "";
    noteEditNaam.value = naam || "";
    noteEditUitwerken.value = uitwerken || "";
    noteModalTitle.textContent = id ? "Notitie bewerken" : "Notitie toevoegen";
    noteModal.style.display = "flex";
    noteEditNaam.focus();
  }

  function closeNoteModal() {
    if (noteModal) noteModal.style.display = "none";
  }

  // Edit existing note
  document.querySelectorAll("[data-edit-note]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var id = btn.getAttribute("data-edit-note");
      // Fetch note data via API
      fetch("/api/notes")
        .then(function (r) { return r.json(); })
        .then(function (d) {
          var note = null;
          (d.notes || []).forEach(function (n) {
            if (String(n.id) === String(id)) note = n;
          });
          if (note) {
            openNoteModal(note.id, note.naam, note.uitwerken);
          }
        });
    });
  });

  // Add new note
  var btnAddNote = document.getElementById("btn-add-note");
  if (btnAddNote) {
    btnAddNote.addEventListener("click", function () {
      openNoteModal("", "", "");
    });
  }

  // Save note
  if (noteModalSave) {
    noteModalSave.addEventListener("click", function () {
      var id = noteEditId.value;
      var naam = noteEditNaam.value.trim();
      var uitwerken = noteEditUitwerken.value.trim();

      if (!naam) {
        noteEditNaam.style.borderColor = "var(--danger, #ef4444)";
        return;
      }

      if (id) {
        // Update existing note via PUT
        fetch("/api/notes/" + id, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ naam: naam, uitwerken: uitwerken }),
        })
          .then(function (r) { return r.json(); })
          .then(function (d) {
            if (d.ok) {
              closeNoteModal();
              location.reload();
            }
          });
      } else {
        // Add new note via POST
        var formData = new FormData();
        formData.append("naam", naam);
        formData.append("uitwerken", uitwerken);
        fetch("/dashboard/notes/add", {
          method: "POST",
          headers: { "X-Requested-With": "XMLHttpRequest" },
          body: formData,
        })
          .then(function (r) { return r.json(); })
          .then(function (d) {
            if (d.ok) {
              closeNoteModal();
              location.reload();
            }
          });
      }
    });
  }

  if (noteModalCancel) noteModalCancel.addEventListener("click", closeNoteModal);
  if (noteModalClose) noteModalClose.addEventListener("click", closeNoteModal);
  if (noteModal) {
    noteModal.addEventListener("click", function (e) {
      if (e.target === noteModal) closeNoteModal();
    });
  }

  // ═══════════════════════════════════════════════════
  // 4. Notes drag & drop (same pattern as notes.js)
  // ═══════════════════════════════════════════════════
  var list = document.getElementById("rapport-notes-list");
  if (list) {
    var dragItem = null;

    list.addEventListener("dragstart", function (e) {
      var item = e.target.closest(".notes-drag-item");
      if (!item) return;
      dragItem = item;
      item.classList.add("dragging");
      e.dataTransfer.effectAllowed = "move";
      e.dataTransfer.setData("text/plain", item.dataset.id);
    });

    list.addEventListener("dragend", function () {
      if (dragItem) dragItem.classList.remove("dragging");
      dragItem = null;
      list.querySelectorAll(".drag-over").forEach(function (el) {
        el.classList.remove("drag-over");
      });
    });

    list.addEventListener("dragover", function (e) {
      e.preventDefault();
      e.dataTransfer.dropEffect = "move";
      var target = e.target.closest(".notes-drag-item");
      if (!target || target === dragItem) return;
      list.querySelectorAll(".drag-over").forEach(function (el) {
        el.classList.remove("drag-over");
      });
      target.classList.add("drag-over");
    });

    list.addEventListener("drop", function (e) {
      e.preventDefault();
      var target = e.target.closest(".notes-drag-item");
      if (!target || !dragItem || target === dragItem) return;
      target.classList.remove("drag-over");

      var items = Array.from(list.children);
      var dragIdx = items.indexOf(dragItem);
      var targetIdx = items.indexOf(target);
      if (dragIdx < targetIdx) {
        list.insertBefore(dragItem, target.nextSibling);
      } else {
        list.insertBefore(dragItem, target);
      }

      saveOrder();
    });

    function saveOrder() {
      var ids = Array.from(list.querySelectorAll(".notes-drag-item")).map(function (el) {
        return parseInt(el.dataset.id, 10);
      });
      fetch("/api/notes/reorder", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ order: ids }),
      });
    }

    // ═══════════════════════════════════════════════════
    // 5. Notes rapport toggle
    // ═══════════════════════════════════════════════════
    list.addEventListener("change", function (e) {
      var cb = e.target;
      if (!cb.dataset.noteId) return;
      var noteId = cb.dataset.noteId;
      var item = cb.closest(".notes-drag-item");

      fetch("/api/notes/" + noteId + "/toggle-rapport", {
        method: "POST",
      })
        .then(function (r) { return r.json(); })
        .then(function (data) {
          if (data.ok) {
            if (data.rapport) {
              item.classList.add("notes-in-rapport");
            } else {
              item.classList.remove("notes-in-rapport");
            }
            updateNotesCounter();
          }
        });
    });
  }

  function updateNotesCounter() {
    var inRapport = document.querySelectorAll(".notes-drag-item.notes-in-rapport").length;
    var counter = document.getElementById("notes-counter");
    if (counter) {
      counter.textContent = inRapport + " in rapport";
    }
  }

  // ── Escape key closes rapport modals ──────────────
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") {
      if (findingModal && findingModal.style.display === "flex") {
        findingModal.style.display = "none";
        if (findingModalBody) findingModalBody.innerHTML = "";
      }
      if (noteModal && noteModal.style.display === "flex") {
        closeNoteModal();
      }
    }
  });

  // ═══════════════════════════════════════════════════
  // Scan-run importeren als rauwe-LaTeX notitie
  // ═══════════════════════════════════════════════════
  function _escHtml(s) {
    return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
    });
  }

  function renderScanCandidates(cands) {
    var box = document.getElementById("scan-candidates");
    if (!box) return;
    if (!cands || !cands.length) { box.innerHTML = ""; return; }
    window._scanCands = cands;
    var html = '<h3 class="scan-cand-title">Kandidaat-bevindingen &mdash; kies welke je overneemt</h3>';
    html += '<table class="scan-cand-table">';
    html += '<tr><th>Scan-issue</th><th>Ernst</th><th>Standaard-bevinding</th></tr>';
    cands.forEach(function (c, i) {
      var sel;
      if (c.candidates && c.candidates.length) {
        sel = '<select data-cand-idx="' + i + '" class="form-control">';
        sel += '<option value="">&mdash; niet overnemen &mdash;</option>';
        c.candidates.forEach(function (t, j) {
          sel += '<option value="' + t.id + '"' + (j === 0 ? ' selected' : '') + '>'
               + _escHtml(t.titel) + ' [' + _escHtml(t.match) + ']</option>';
        });
        sel += '</select>';
      } else {
        sel = '<span class="help">(geen match)</span>';
      }
      var ncsc = (c.ncsc && c.ncsc.length) ? ' &middot; ' + _escHtml(c.ncsc.join(", ")) : '';
      html += '<tr><td>' + _escHtml(c.title)
            + ' <span class="help">(' + c.count + '&times;' + ncsc + ')</span></td>'
            + '<td>' + _escHtml(c.severity || "") + '</td>'
            + '<td>' + sel + '</td></tr>';
    });
    html += '</table>';
    html += '<button type="button" class="btn btn-primary mt-8" id="btn-scan-create-findings">Maak geselecteerde bevindingen</button>'
          + ' <span id="scan-create-status" class="help ml-8"></span>';
    box.innerHTML = html;
    var btn = document.getElementById("btn-scan-create-findings");
    if (btn) btn.addEventListener("click", createScanFindings);
  }

  function createScanFindings() {
    var cands = window._scanCands || [];
    var items = [];
    document.querySelectorAll("#scan-candidates [data-cand-idx]").forEach(function (sel) {
      if (!sel.value) return;
      var c = cands[parseInt(sel.getAttribute("data-cand-idx"))];
      if (c) items.push({ template_id: sel.value, titel: c.title, severity: c.severity, locatie: c.endpoint || "", evidence_cmd: c.evidence_cmd || "", evidence_resp: c.evidence_resp || "" });
    });
    var st = document.getElementById("scan-create-status");
    if (!items.length) { if (st) { st.textContent = "Niets geselecteerd."; st.style.color = "var(--danger, #ef4444)"; } return; }
    var btn = document.getElementById("btn-scan-create-findings");
    if (btn) btn.disabled = true;
    if (st) { st.textContent = "Bezig..."; st.style.color = ""; }
    fetch("/api/report/scan-create-findings", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ items: items })
    }).then(function (r) { return r.json(); }).then(function (d) {
      if (d.ok) {
        if (st) { st.textContent = d.created + " bevinding(en) aangemaakt (concept) — pagina wordt herladen."; st.style.color = "var(--success, #22c55e)"; }
        setTimeout(function () { location.reload(); }, 1400);
      } else {
        if (st) { st.textContent = "Fout: " + (d.error || "onbekend"); st.style.color = "var(--danger, #ef4444)"; }
        if (btn) btn.disabled = false;
      }
    }).catch(function () {
      if (st) { st.textContent = "Aanmaken mislukt"; st.style.color = "var(--danger, #ef4444)"; }
      if (btn) btn.disabled = false;
    });
  }

  var btnScanImport = document.getElementById("btn-scan-import");
  if (btnScanImport) {
    btnScanImport.addEventListener("click", function () {
      var inp = document.getElementById("scan-run-dir");
      var statusEl = document.getElementById("scan-import-status");
      var runDir = inp ? inp.value.trim() : "";
      if (!runDir) {
        if (statusEl) { statusEl.textContent = "Geef een pad naar de scan-run-map."; statusEl.style.color = "var(--danger, #ef4444)"; }
        return;
      }
      btnScanImport.disabled = true;
      if (statusEl) { statusEl.textContent = "Bezig met importeren..."; statusEl.style.color = ""; }
      fetch("/api/report/scan-import", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ run_dir: runDir })
      })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          if (d.ok) {
            if (statusEl) {
              statusEl.textContent = "Notitie toegevoegd: " + d.naam + ". Kies hieronder welke bevindingen je overneemt.";
              statusEl.style.color = "var(--success, #22c55e)";
            }
            renderScanCandidates(d.candidates || []);
            btnScanImport.disabled = false;
          } else {
            if (statusEl) { statusEl.textContent = "Fout: " + (d.error || "onbekend"); statusEl.style.color = "var(--danger, #ef4444)"; }
            btnScanImport.disabled = false;
          }
        })
        .catch(function () {
          if (statusEl) { statusEl.textContent = "Importeren mislukt"; statusEl.style.color = "var(--danger, #ef4444)"; }
          btnScanImport.disabled = false;
        });
    });
  }

  var btnScanImportZip = document.getElementById("btn-scan-import-zip");
  if (btnScanImportZip) {
    btnScanImportZip.addEventListener("click", function () {
      var fileInp = document.getElementById("scan-zip-file");
      var statusEl = document.getElementById("scan-import-status");
      var file = fileInp && fileInp.files && fileInp.files[0];
      if (!file) {
        if (statusEl) { statusEl.textContent = "Kies eerst een zip-bestand."; statusEl.style.color = "var(--danger, #ef4444)"; }
        return;
      }
      var fd = new FormData();
      fd.append("zip", file);
      btnScanImportZip.disabled = true;
      if (statusEl) { statusEl.textContent = "Uploaden en verwerken..."; statusEl.style.color = ""; }
      fetch("/api/report/scan-import-zip", { method: "POST", body: fd })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          if (d.ok) {
            if (statusEl) {
              statusEl.textContent = "Notitie toegevoegd: " + d.naam + ". Kies hieronder welke bevindingen je overneemt.";
              statusEl.style.color = "var(--success, #22c55e)";
            }
            renderScanCandidates(d.candidates || []);
            btnScanImportZip.disabled = false;
          } else {
            if (statusEl) { statusEl.textContent = "Fout: " + (d.error || "onbekend"); statusEl.style.color = "var(--danger, #ef4444)"; }
            btnScanImportZip.disabled = false;
          }
        })
        .catch(function () {
          if (statusEl) { statusEl.textContent = "Upload mislukt"; statusEl.style.color = "var(--danger, #ef4444)"; }
          btnScanImportZip.disabled = false;
        });
    });
  }
})();
