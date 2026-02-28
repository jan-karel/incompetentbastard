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

  if (btnGenerate) {
    btnGenerate.addEventListener("click", function () {
      var draft = document.getElementById("include-draft");
      var includeDraft = draft && draft.checked;

      btnGenerate.disabled = true;
      if (generateStatus) {
        generateStatus.textContent = "Starten...";
        generateStatus.style.color = "";
      }

      fetch("/api/report/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ include_draft: includeDraft })
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
  function loadVersions() {
    var el = document.getElementById("versions-list");
    if (!el) return;
    fetch("/api/report/versions")
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var items = d.versions || [];
        if (!items.length) {
          el.innerHTML = "Nog geen versies. Genereer eerst een rapport.";
          return;
        }
        var html = '<table class="table compact"><thead><tr><th>Timestamp</th><th>Bestanden</th></tr></thead><tbody>';
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
    noteModalTitle.textContent = id ? "Note bewerken" : "Note toevoegen";
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
})();
