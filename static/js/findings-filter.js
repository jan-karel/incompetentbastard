(function() {
  "use strict";

  // ── Filter functionaliteit ────────────────────────
  var searchInput = document.getElementById("filter-search");
  var sevSelect = document.getElementById("filter-severity");
  var statusSelect = document.getElementById("filter-status");
  var remSelect = document.getElementById("filter-remediation");
  var tableBody = document.querySelector("#findings-table tbody");
  if (!tableBody) return;

  function applyFilters() {
    var q = (searchInput ? searchInput.value : "").toLowerCase();
    var sev = sevSelect ? sevSelect.value : "";
    var status = statusSelect ? statusSelect.value : "";
    var rem = remSelect ? remSelect.value : "";
    var rows = tableBody.querySelectorAll("tr");
    rows.forEach(function(row) {
      var name = (row.getAttribute("data-name") || "").toLowerCase();
      var host = (row.getAttribute("data-host") || "").toLowerCase();
      var rSev = row.getAttribute("data-severity") || "";
      var rStatus = row.getAttribute("data-status") || "";
      var rRem = row.getAttribute("data-remediation") || "";
      var show = true;
      if (q && name.indexOf(q) === -1 && host.indexOf(q) === -1) show = false;
      if (sev && rSev !== sev) show = false;
      if (status && rStatus !== status) show = false;
      if (rem && rRem !== rem) show = false;
      row.style.display = show ? "" : "none";
    });
  }

  [searchInput, sevSelect, statusSelect, remSelect].forEach(function(el) {
    if (el) el.addEventListener("input", applyFilters);
    if (el) el.addEventListener("change", applyFilters);
  });

  // ── Template zoekfilter & categorie toggle ────────────────────
  var tmplSearch = document.getElementById("tmpl-search");
  var tmplCategories = document.querySelectorAll(".tmpl-category");

  function filterTemplates() {
    var q = (tmplSearch ? tmplSearch.value : "").toLowerCase();
    var visible = 0, total = 0;
    tmplCategories.forEach(function(cat) {
      var items = cat.querySelectorAll(".tmpl-item");
      var catVisible = 0;
      items.forEach(function(item) {
        total++;
        var title = item.getAttribute("data-title") || "";
        var bevtype = item.getAttribute("data-bevtype") || "";
        var show = !q || title.indexOf(q) !== -1 || bevtype.indexOf(q) !== -1;
        item.style.display = show ? "" : "none";
        if (show) { catVisible++; visible++; }
      });
      cat.style.display = catVisible ? "" : "none";
      var header = cat.querySelector(".tmpl-category-header");
      if (q && catVisible && header) header.classList.remove("collapsed");
    });
    var counter = document.getElementById("tmpl-count");
    if (counter) counter.textContent = visible + " / " + total;
  }

  if (tmplSearch) tmplSearch.addEventListener("input", filterTemplates);

  document.querySelectorAll(".tmpl-category-header").forEach(function(h) {
    h.addEventListener("click", function() { this.classList.toggle("collapsed"); });
  });

  var tmplExpandAll = document.getElementById("tmpl-expand-all");
  var tmplCollapseAll = document.getElementById("tmpl-collapse-all");
  if (tmplExpandAll) {
    tmplExpandAll.addEventListener("click", function() {
      document.querySelectorAll(".tmpl-category-header").forEach(function(h) {
        h.classList.remove("collapsed");
      });
    });
  }
  if (tmplCollapseAll) {
    tmplCollapseAll.addEventListener("click", function() {
      document.querySelectorAll(".tmpl-category-header").forEach(function(h) {
        h.classList.add("collapsed");
      });
    });
  }

  // ── Batch selectie ────────────────────────
  var checkAll = document.getElementById("batch-check-all");
  var batchAction = document.getElementById("batch-action");
  var batchBtn = document.getElementById("batch-execute");

  if (checkAll) {
    checkAll.addEventListener("change", function() {
      var checks = tableBody.querySelectorAll(".batch-check");
      checks.forEach(function(cb) {
        var row = cb.closest("tr");
        if (row && row.style.display !== "none") {
          cb.checked = checkAll.checked;
        }
      });
    });
  }

  if (batchBtn) {
    batchBtn.addEventListener("click", function() {
      var action = batchAction ? batchAction.value : "";
      if (!action) return;
      var parts = action.split(":");
      var actionType = parts[0];
      var actionValue = parts[1] || "";

      var ids = [];
      tableBody.querySelectorAll(".batch-check:checked").forEach(function(cb) {
        ids.push(parseInt(cb.getAttribute("data-id")));
      });
      if (ids.length === 0) return;

      fetch("/api/findings/batch-action", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ids: ids, action: actionType, value: actionValue})
      })
      .then(function(r) { return r.json(); })
      .then(function(d) {
        if (d.ok) {
          window.location.reload();
        }
      });
    });
  }
})();
