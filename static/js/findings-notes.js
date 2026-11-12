/* Notities-tabblad op dashboard/findings.
   Zelfstandig: praat met de bestaande notes-API (/api/notes ...) en houdt de
   lijst in het tabblad actueel zonder paginavernieuwing. */
(function () {
  "use strict";

  var list = document.getElementById("notes-list");
  if (!list) return; // tabblad niet aanwezig

  var addForm = document.getElementById("fx-note-add-form");
  var addNaam = document.getElementById("fx-note-naam");
  var addUit = document.getElementById("fx-note-uitwerken");
  var addMsg = document.getElementById("fx-note-add-msg");
  var counter = document.getElementById("fx-notes-counter");
  var emptyMsg = document.getElementById("fx-notes-empty");

  var modal = document.getElementById("fx-note-modal");
  var mId = document.getElementById("fx-note-edit-id");
  var mNaam = document.getElementById("fx-note-edit-naam");
  var mUit = document.getElementById("fx-note-edit-uitwerken");

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function itemHtml(n) {
    return '<li class="notes-drag-item' + (n.rapport ? " notes-in-rapport" : "") +
      '" draggable="true" data-id="' + n.id + '">' +
      '<span class="drag-handle" title="Sleep om te herschikken">&#10495;</span>' +
      '<label class="rapport-toggle" title="Opnemen in rapport">' +
      '<input type="checkbox" data-note-id="' + n.id + '"' + (n.rapport ? " checked" : "") + " />" +
      '<span class="rapport-label">Rapport</span></label>' +
      '<span class="note-name">' + esc(n.naam) + "</span>" +
      '<span class="note-actions">' +
      '<button type="button" class="btn btn-sm" data-fx-edit-note="' + n.id + '">bewerken</button>' +
      '<button type="button" class="btn btn-sm" data-fx-del-note="' + n.id +
      '" data-fx-note-naam="' + esc(n.naam) + '">verwijderen</button>' +
      "</span></li>";
  }

  function render(notes) {
    list.innerHTML = notes.map(itemHtml).join("");
    list.classList.toggle("d-none", notes.length === 0);
    if (emptyMsg) emptyMsg.classList.toggle("d-none", notes.length > 0);
    updateCounter();
  }

  function refresh() {
    return fetch("/api/notes")
      .then(function (r) { return r.json(); })
      .then(function (d) { render(d.notes || []); })
      .catch(function () {});
  }

  function updateCounter() {
    if (!counter) return;
    var n = list.querySelectorAll(".notes-drag-item.notes-in-rapport").length;
    counter.textContent = n + " in rapport";
  }

  // ── Toevoegen ───────────────────────────────────────────
  if (addForm) {
    addForm.addEventListener("submit", function (e) {
      e.preventDefault();
      var naam = addNaam ? addNaam.value.trim() : "";
      if (!naam) {
        if (addMsg) { addMsg.textContent = "Naam is verplicht"; addMsg.style.color = "var(--danger, #ef4444)"; }
        return;
      }
      var fd = new FormData();
      fd.append("naam", naam);
      fd.append("uitwerken", addUit ? addUit.value : "");
      fetch("/dashboard/notes/add", {
        method: "POST",
        headers: { "X-Requested-With": "XMLHttpRequest" },
        body: fd,
      })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          if (d.ok) {
            if (addMsg) { addMsg.textContent = "Opgeslagen"; addMsg.style.color = "var(--success, #22c55e)"; }
            if (addNaam) addNaam.value = "";
            if (addUit) addUit.value = "";
            refresh();
            setTimeout(function () { if (addMsg) addMsg.textContent = ""; }, 1500);
          } else if (addMsg) {
            addMsg.textContent = d.error || "Fout"; addMsg.style.color = "var(--danger, #ef4444)";
          }
        })
        .catch(function () { if (addMsg) { addMsg.textContent = "Fout"; addMsg.style.color = "var(--danger, #ef4444)"; } });
    });
  }

  // ── Bewerken (modal) ────────────────────────────────────
  function openModal() { if (modal) modal.style.display = "flex"; }
  function closeModal() { if (modal) modal.style.display = "none"; }

  list.addEventListener("click", function (e) {
    var editBtn = e.target.closest("[data-fx-edit-note]");
    if (editBtn) {
      var id = editBtn.getAttribute("data-fx-edit-note");
      fetch("/api/notes")
        .then(function (r) { return r.json(); })
        .then(function (d) {
          var note = (d.notes || []).filter(function (n) { return String(n.id) === String(id); })[0];
          if (!note) return;
          if (mId) mId.value = note.id;
          if (mNaam) mNaam.value = note.naam || "";
          if (mUit) mUit.value = note.uitwerken || "";
          openModal();
          if (mNaam) mNaam.focus();
        });
      return;
    }
    var delBtn = e.target.closest("[data-fx-del-note]");
    if (delBtn) {
      var delId = delBtn.getAttribute("data-fx-del-note");
      var naam = delBtn.getAttribute("data-fx-note-naam") || "";
      if (!window.confirm("Notitie '" + naam + "' verwijderen?")) return;
      fetch("/dashboard/notes/delete/" + delId, { headers: { "X-Requested-With": "XMLHttpRequest" } })
        .then(function () { refresh(); });
    }
  });

  var mSave = document.getElementById("fx-note-edit-save");
  if (mSave) {
    mSave.addEventListener("click", function () {
      var id = mId ? mId.value : "";
      var naam = mNaam ? mNaam.value.trim() : "";
      if (!id || !naam) return;
      fetch("/api/notes/" + id, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ naam: naam, uitwerken: mUit ? mUit.value : "" }),
      })
        .then(function (r) { return r.json(); })
        .then(function (d) { if (d.ok) { closeModal(); refresh(); } });
    });
  }
  var mCancel = document.getElementById("fx-note-edit-cancel");
  if (mCancel) mCancel.addEventListener("click", closeModal);
  var mClose = document.getElementById("fx-note-modal-close");
  if (mClose) mClose.addEventListener("click", closeModal);
  if (modal) modal.addEventListener("click", function (e) { if (e.target === modal) closeModal(); });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && modal && modal.style.display === "flex") closeModal();
  });

  // ── Rapport-toggle ──────────────────────────────────────
  list.addEventListener("change", function (e) {
    var cb = e.target;
    if (!cb.dataset || !cb.dataset.noteId) return;
    var item = cb.closest(".notes-drag-item");
    fetch("/api/notes/" + cb.dataset.noteId + "/toggle-rapport", { method: "POST" })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (d.ok && item) {
          item.classList.toggle("notes-in-rapport", !!d.rapport);
          updateCounter();
        }
      });
  });

  // ── Slepen om te herschikken ────────────────────────────
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
    list.querySelectorAll(".drag-over").forEach(function (el) { el.classList.remove("drag-over"); });
  });
  list.addEventListener("dragover", function (e) {
    e.preventDefault();
    e.dataTransfer.dropEffect = "move";
    var target = e.target.closest(".notes-drag-item");
    if (!target || target === dragItem) return;
    list.querySelectorAll(".drag-over").forEach(function (el) { el.classList.remove("drag-over"); });
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
    if (dragIdx < targetIdx) list.insertBefore(dragItem, target.nextSibling);
    else list.insertBefore(dragItem, target);
    var ids = Array.from(list.querySelectorAll(".notes-drag-item")).map(function (el) {
      return parseInt(el.dataset.id, 10);
    });
    fetch("/api/notes/reorder", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ order: ids }),
    });
  });
})();
