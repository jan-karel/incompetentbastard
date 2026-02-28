/* Notes drag & drop + rapport toggle */
(function () {
  var list = document.getElementById("notes-list");
  if (!list) return;

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

    // Insert dragItem before or after target
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

  // Rapport toggle
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
        }
      });
  });
})();
