/* ── Files page: tabs, filter, copy URL, preview, loot, upload ── */
(() => {
  "use strict";

  // ── Helpers ───────────────────────────────────────────
  function escapeHtml(s) {
    const d = document.createElement("div");
    d.appendChild(document.createTextNode(s));
    return d.innerHTML;
  }

  function formatSize(bytes) {
    const units = ["B", "KB", "MB", "GB"];
    for (const u of units) {
      if (Math.abs(bytes) < 1024) {
        return u === "B" ? bytes + " B" : bytes.toFixed(1) + " " + u;
      }
      bytes /= 1024;
    }
    return bytes.toFixed(1) + " TB";
  }

  function formatDate(ts) {
    const d = new Date(ts * 1000);
    return d.toISOString().slice(0, 10);
  }

  function btnFeedback(btn, text) {
    const old = btn.innerHTML;
    btn.textContent = text;
    btn.classList.add("copied");
    setTimeout(() => {
      btn.innerHTML = old;
      btn.classList.remove("copied");
    }, 1200);
  }

  // ── Host caching (for copy URL) ──────────────────────
  let cachedHost = "";
  fetch("/api/settings")
    .then(r => r.json())
    .then(d => { cachedHost = d.localhost || ""; })
    .catch(() => {});

  // ── Tab switching ────────────────────────────────────
  const tabs = document.querySelectorAll(".tab");
  const panels = document.querySelectorAll(".tab-panel");
  let lootLoaded = false;

  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      panels.forEach(p => p.classList.remove("active"));
      tab.classList.add("active");
      const target = document.getElementById("panel-" + tab.dataset.tab);
      if (target) target.classList.add("active");

      // Lazy-load loot on first click
      if (tab.dataset.tab === "loot" && !lootLoaded) {
        loadLoot();
        lootLoaded = true;
      }

      // Re-apply filter
      applyFilter();
    });
  });

  // ── Convert epoch timestamps in rendered tables ──────
  document.querySelectorAll(".file-table td:nth-child(3)").forEach(td => {
    const ts = parseInt(td.textContent, 10);
    if (!isNaN(ts) && ts > 1000000000) {
      td.textContent = formatDate(ts);
    }
  });

  // ── Filter ───────────────────────────────────────────
  const filterInput = document.getElementById("file-filter");
  let filterDebounce = null;

  function applyFilter() {
    const term = (filterInput ? filterInput.value : "").toLowerCase();
    const activePanel = document.querySelector(".tab-panel.active");
    if (!activePanel) return;
    activePanel.querySelectorAll(".file-row").forEach(row => {
      const name = row.dataset.name || "";
      row.style.display = name.includes(term) ? "" : "none";
    });
    // Also filter loot groups
    activePanel.querySelectorAll(".loot-group").forEach(group => {
      const rows = group.querySelectorAll(".file-row");
      let anyVisible = false;
      rows.forEach(row => {
        const name = row.dataset.name || "";
        const show = name.includes(term);
        row.style.display = show ? "" : "none";
        if (show) anyVisible = true;
      });
      group.style.display = anyVisible ? "" : "none";
    });
  }

  if (filterInput) {
    filterInput.addEventListener("input", () => {
      clearTimeout(filterDebounce);
      filterDebounce = setTimeout(applyFilter, 150);
    });
  }

  // ── Copy URL ─────────────────────────────────────────
  document.addEventListener("click", (e) => {
    const btn = e.target.closest(".btn-copy-url");
    if (!btn) return;
    e.preventDefault();
    const url = (cachedHost || window.location.origin) + btn.dataset.url;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(url).then(() => btnFeedback(btn, "Copied!"));
    } else {
      const ta = document.createElement("textarea");
      ta.value = url;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
      btnFeedback(btn, "Copied!");
    }
  });

  // ── Preview modal ────────────────────────────────────
  const previewModal = document.getElementById("preview-modal");
  const previewTitle = document.getElementById("preview-title");
  const previewContent = document.getElementById("preview-content");
  const btnPreviewClose = document.getElementById("btn-preview-close");

  function openPreview(category, filename) {
    if (!previewModal) return;
    previewTitle.textContent = filename;
    previewContent.textContent = "Laden...";
    previewModal.style.display = "flex";
    fetch("/api/files/preview/" + encodeURIComponent(category) + "/" + encodeURIComponent(filename))
      .then(r => {
        if (!r.ok) throw new Error("Not found");
        return r.json();
      })
      .then(d => {
        previewContent.textContent = d.content;
      })
      .catch(() => {
        previewContent.textContent = "Kan bestand niet laden.";
      });
  }

  function closePreview() {
    if (previewModal) previewModal.style.display = "none";
  }

  if (btnPreviewClose) btnPreviewClose.addEventListener("click", closePreview);
  if (previewModal) previewModal.addEventListener("click", (e) => {
    if (e.target === previewModal) closePreview();
  });

  document.addEventListener("click", (e) => {
    const btn = e.target.closest(".btn-preview");
    if (!btn) return;
    e.preventDefault();
    openPreview(btn.dataset.cat, btn.dataset.file);
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && previewModal && previewModal.style.display !== "none") {
      closePreview();
    }
  });

  // ── Loot loading ─────────────────────────────────────
  const lootContainer = document.getElementById("loot-container");

  function loadLoot() {
    if (!lootContainer) return;
    lootContainer.innerHTML = '<p class="help">Laden...</p>';
    fetch("/api/files/loot")
      .then(r => r.json())
      .then(data => {
        const ips = Object.keys(data).sort();
        if (ips.length === 0) {
          lootContainer.innerHTML = '<p class="help">Geen loot bestanden gevonden in <code>raw/loot/</code>.</p>';
          return;
        }
        lootContainer.innerHTML = "";
        for (const ip of ips) {
          const files = data[ip];
          const group = document.createElement("div");
          group.className = "loot-group";

          const header = document.createElement("div");
          header.className = "loot-header";
          header.innerHTML =
            '<span class="fm-chevron"></span>' +
            '<span class="loot-ip">' + escapeHtml(ip) + '</span>' +
            '<span class="fm-cat-count">' + files.length + '</span>';
          header.addEventListener("click", () => {
            header.classList.toggle("collapsed");
            const body = group.querySelector(".loot-body");
            if (body) body.style.display = header.classList.contains("collapsed") ? "none" : "";
          });
          group.appendChild(header);

          const body = document.createElement("div");
          body.className = "loot-body";
          const table = document.createElement("table");
          table.className = "file-table";
          table.innerHTML = "<thead><tr><th>Name</th><th>Size</th><th>Modified</th><th>Actions</th></tr></thead>";
          const tbody = document.createElement("tbody");
          for (const f of files) {
            const tr = document.createElement("tr");
            tr.className = "file-row";
            tr.dataset.name = f.name.toLowerCase();
            tr.dataset.url = f.url;
            tr.innerHTML =
              "<td>" + escapeHtml(f.name) + "</td>" +
              "<td>" + formatSize(f.size) + "</td>" +
              "<td>" + formatDate(f.modified) + "</td>" +
              '<td class="file-actions">' +
                '<a class="btn-action" href="' + escapeHtml(f.url) + '" title="Download">&#8595;</a>' +
                '<button class="btn-action btn-copy-url" data-url="' + escapeHtml(f.url) + '" title="Copy URL">&#128203;</button>' +
                (f.previewable
                  ? '<button class="btn-action btn-preview" data-cat="loot" data-file="' + escapeHtml(ip + "/" + f.name) + '" title="Preview">&#128065;</button>'
                  : "") +
              "</td>";
            tbody.appendChild(tr);
          }
          table.appendChild(tbody);
          body.appendChild(table);
          group.appendChild(body);
          lootContainer.appendChild(group);
        }
        applyFilter();
      })
      .catch(() => {
        lootContainer.innerHTML = '<p class="help">Fout bij laden van loot.</p>';
      });
  }

  // ── Upload ───────────────────────────────────────────
  const dropzone = document.getElementById("upload-dropzone");
  const fileInput = document.getElementById("upload-input");
  const uploadList = document.getElementById("upload-list");

  if (dropzone) {
    dropzone.addEventListener("click", () => { if (fileInput) fileInput.click(); });

    dropzone.addEventListener("dragover", (e) => {
      e.preventDefault();
      dropzone.classList.add("dragover");
    });
    dropzone.addEventListener("dragleave", () => {
      dropzone.classList.remove("dragover");
    });
    dropzone.addEventListener("drop", (e) => {
      e.preventDefault();
      dropzone.classList.remove("dragover");
      if (e.dataTransfer && e.dataTransfer.files.length) {
        uploadFiles(e.dataTransfer.files);
      }
    });
  }

  if (fileInput) {
    fileInput.addEventListener("change", () => {
      if (fileInput.files.length) uploadFiles(fileInput.files);
    });
  }

  function uploadFiles(files) {
    for (const file of files) {
      const item = document.createElement("div");
      item.className = "upload-item";
      item.textContent = file.name + "  \u23F3 uploading...";
      if (uploadList) uploadList.appendChild(item);

      const fd = new FormData();
      fd.append("file", file);
      fetch("/upload", { method: "POST", body: fd })
        .then(r => {
          if (r.ok) {
            item.textContent = file.name + "  \u2713 uploaded";
            item.classList.add("success");
          } else {
            return r.text().then(t => {
              item.textContent = file.name + "  \u2717 " + t;
              item.classList.add("error");
            });
          }
        })
        .catch(() => {
          item.textContent = file.name + "  \u2717 upload failed";
          item.classList.add("error");
        });
    }
  }
})();
