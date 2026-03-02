/* Checklists interactie — guided UX + command files + findings integratie */
(function () {
  "use strict";

  var CL_ID = document.body.dataset.checklistId;
  if (!CL_ID) return;

  /* Init progress bar widths from data attributes (CSP safe) */
  document.querySelectorAll("[data-initial-width]").forEach(function (el) {
    el.style.width = el.dataset.initialWidth + "%";
  });

  var STORAGE_KEY = "cl_vars_" + CL_ID;
  var SCREEN_KEY = "cl_screen_" + CL_ID;
  var LEGEND_KEY = "cl_legend_collapsed";
  var STATUS_MAP = ["open", "pass", "fail", "warn", "skip", "na"];
  var allItems = [];    // all .cl-item elements in DOM order
  var focusIdx = -1;    // currently focused item index

  /* ==== Command file cache ==== */
  var commandCache = null;  // { name: content } map, loaded once from /api/commands

  /* ==== Screen session elements ==== */
  var screenSelect = document.getElementById("cl-screen-select");
  var screenNewInput = document.getElementById("cl-screen-new");
  var screenCreateBtn = document.getElementById("cl-screen-create");
  var screenRefreshBtn = document.getElementById("cl-screen-refresh");
  var screenStatus = document.getElementById("cl-screen-status");

  /* ==== Helpers ==== */
  function api(method, url, body) {
    var opts = { method: method, headers: { "Content-Type": "application/json" } };
    if (body) opts.body = JSON.stringify(body);
    return fetch(url, opts).then(function (r) { return r.json(); });
  }

  function toast(msg) {
    var t = document.getElementById("toast");
    if (!t) return;
    t.textContent = msg;
    t.classList.add("show");
    setTimeout(function () { t.classList.remove("show"); }, 2000);
  }

  function isDone(status) {
    return status === "pass" || status === "fail" || status === "warn" || status === "na";
  }

  function isInputFocused() {
    var el = document.activeElement;
    if (!el) return false;
    var tag = el.tagName;
    return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || el.isContentEditable;
  }

  function escapeHtml(str) {
    var div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  /* ==== Collect all items ==== */
  function collectItems() {
    allItems = Array.from(document.querySelectorAll(".cl-item"));
  }
  collectItems();

  /* ==================================================================
     COMMAND FILE CACHE — fetch once, used by previews + inject
     ================================================================== */
  function ensureCommandCache() {
    if (commandCache) return Promise.resolve(commandCache);
    return fetch("/api/commands")
      .then(function (r) { return r.json(); })
      .then(function (d) {
        commandCache = {};
        (d.commands || []).forEach(function (cmd) {
          commandCache[cmd.name] = cmd.content;
        });
        return commandCache;
      })
      .catch(function () {
        commandCache = {};
        return commandCache;
      });
  }

  /* ==================================================================
     SCREEN SESSIONS — load, create, select
     ================================================================== */
  function getScreenName() {
    if (!screenSelect) return "";
    var custom = screenNewInput ? screenNewInput.value.trim() : "";
    if (custom) return custom;
    return screenSelect.value;
  }

  function loadScreens(selectName) {
    if (!screenSelect) return;
    var xhr = new XMLHttpRequest();
    xhr.open("GET", "/api/commands/screens");
    xhr.onload = function () {
      if (xhr.status !== 200) return;
      var data;
      try { data = JSON.parse(xhr.responseText); } catch (e) { return; }
      var screens = data.screens || [];

      screenSelect.innerHTML = "";
      if (!screens.length) {
        var opt = document.createElement("option");
        opt.value = "";
        opt.textContent = "-- geen sessies --";
        screenSelect.appendChild(opt);
        return;
      }

      var saved = selectName || localStorage.getItem(SCREEN_KEY) || "";
      for (var i = 0; i < screens.length; i++) {
        var opt = document.createElement("option");
        opt.value = screens[i].name;
        opt.textContent = screens[i].name + " (" + screens[i].status + ")";
        if (screens[i].name === saved) opt.selected = true;
        screenSelect.appendChild(opt);
      }
    };
    xhr.send();
  }

  function createScreen(name) {
    if (!name) { toast("Geef een sessienaam op"); return; }
    if (screenCreateBtn) { screenCreateBtn.disabled = true; screenCreateBtn.textContent = "..."; }
    if (screenStatus) { screenStatus.textContent = ""; screenStatus.className = "cl-screen-status"; }

    var xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/screen/start");
    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.onload = function () {
      if (screenCreateBtn) { screenCreateBtn.disabled = false; screenCreateBtn.textContent = "Start"; }
      var data;
      try { data = JSON.parse(xhr.responseText); } catch (e) { data = {}; }
      if (xhr.status === 200 && data.ok) {
        if (screenStatus) { screenStatus.textContent = "Gestart"; screenStatus.className = "cl-screen-status status-ok"; }
        if (screenNewInput) screenNewInput.value = "";
        localStorage.setItem(SCREEN_KEY, name);
        loadScreens(name);
        setTimeout(function () { if (screenStatus) screenStatus.textContent = ""; }, 2000);
      } else {
        var msg = data.error || "Kon sessie niet starten";
        if (screenStatus) { screenStatus.textContent = msg; screenStatus.className = "cl-screen-status status-fail"; }
        toast(msg);
      }
    };
    xhr.onerror = function () {
      if (screenCreateBtn) { screenCreateBtn.disabled = false; screenCreateBtn.textContent = "Start"; }
      if (screenStatus) { screenStatus.textContent = "Verbindingsfout"; screenStatus.className = "cl-screen-status status-fail"; }
    };
    xhr.send(JSON.stringify({ name: name }));
  }

  if (screenSelect) {
    screenSelect.addEventListener("change", function () {
      localStorage.setItem(SCREEN_KEY, this.value);
    });
  }
  if (screenCreateBtn) {
    screenCreateBtn.addEventListener("click", function () {
      createScreen((screenNewInput ? screenNewInput.value.trim() : "") || "");
    });
  }
  if (screenRefreshBtn) {
    screenRefreshBtn.addEventListener("click", function () { loadScreens(); });
  }

  loadScreens();

  /* ==================================================================
     STATUS SELECT — update via API
     ================================================================== */
  document.querySelectorAll(".cl-status-select").forEach(function (sel) {
    sel.addEventListener("change", function () {
      var ref = this.dataset.ref;
      var row = this.closest(".cl-item");
      var newStatus = this.value;
      api("POST", "/api/checklists/" + CL_ID + "/items/" + ref + "/status", { status: newStatus })
        .then(function (d) {
          if (d.ok) {
            row.dataset.status = d.status;
            updateProgress();
            updatePhaseNav();
            showContextAdvice(row, d.status);
            toast("Status bijgewerkt");
          }
        });
    });
  });

  /* ==================================================================
     CONTEXT ADVICE — show hint after status change
     ================================================================== */
  function showContextAdvice(item, status) {
    var adv = item.querySelector(".cl-context-advice");
    if (!adv) return;
    adv.className = "cl-context-advice d-none";
    adv.innerHTML = "";

    if (status === "fail") {
      adv.className = "cl-context-advice advice-fail";
      adv.innerHTML = "Kwetsbaarheid gevonden! ";
      var existingBtn = item.querySelector(".cl-item-actions .cl-create-finding");
      if (existingBtn && existingBtn.disabled) {
        adv.innerHTML = "Kwetsbaarheid gevonden &mdash; bevinding al aangemaakt.";
      } else {
        // Check if there are finding templates — load them automatically
        var tplWrap = item.querySelector(".cl-finding-templates");
        if (tplWrap && tplWrap.classList.contains("d-none")) {
          var loadBtn = item.querySelector(".cl-load-templates");
          if (loadBtn) loadBtn.click();
        }
        var btn = document.createElement("button");
        btn.className = "btn cl-create-finding";
        btn.textContent = "Bevinding aanmaken";
        btn.dataset.ref = item.dataset.ref;
        btn.addEventListener("click", handleCreateFinding);
        adv.appendChild(btn);
      }
    } else if (status === "pass") {
      adv.className = "cl-context-advice advice-pass";
      adv.innerHTML = "Geen kwetsbaarheid &mdash; ";
      var noteLink = document.createElement("button");
      noteLink.className = "btn";
      noteLink.textContent = "Evidence noteren";
      noteLink.addEventListener("click", function () {
        var ta = item.querySelector(".cl-inline-note");
        if (ta) { ta.focus(); }
      });
      adv.appendChild(noteLink);
    }
  }

  /* ==================================================================
     EXPAND / COLLAPSE — items
     ================================================================== */
  document.querySelectorAll(".cl-toggle").forEach(function (btn) {
    btn.addEventListener("click", function () {
      toggleItem(this.closest(".cl-item"));
    });
  });

  function toggleItem(item) {
    if (!item) return;
    var detail = item.querySelector(".cl-item-detail");
    if (detail) detail.classList.toggle("d-none");
  }

  function expandItem(item) {
    if (!item) return;
    var detail = item.querySelector(".cl-item-detail");
    if (detail) detail.classList.remove("d-none");
  }

  function collapseItem(item) {
    if (!item) return;
    var detail = item.querySelector(".cl-item-detail");
    if (detail) detail.classList.add("d-none");
  }

  /* EN badge toggle */
  document.querySelectorAll(".cl-toggle-en").forEach(function (badge) {
    badge.addEventListener("click", function (e) {
      e.stopPropagation();
      var enDesc = this.closest(".cl-item").querySelector(".cl-en-desc");
      if (enDesc) enDesc.classList.toggle("d-none");
    });
  });

  /* ==================================================================
     AUTO-EXPAND — first open item
     ================================================================== */
  (function () {
    for (var i = 0; i < allItems.length; i++) {
      if (allItems[i].dataset.status === "open") {
        expandItem(allItems[i]);
        var phase = allItems[i].closest(".checklist-phase");
        if (phase) phase.classList.remove("phase-collapsed");
        break;
      }
    }
  })();

  /* ==================================================================
     NEXT OPEN ITEM — button + function
     ================================================================== */
  document.querySelectorAll(".cl-next-open").forEach(function (btn) {
    btn.addEventListener("click", function () {
      goToNextOpen(this.closest(".cl-item"));
    });
  });

  function goToNextOpen(fromItem) {
    var startIdx = fromItem ? allItems.indexOf(fromItem) : -1;
    for (var i = startIdx + 1; i < allItems.length; i++) {
      if (allItems[i].dataset.status === "open" && allItems[i].style.display !== "none") {
        collapseItem(fromItem);
        setFocus(i);
        expandItem(allItems[i]);
        var phase = allItems[i].closest(".checklist-phase");
        if (phase) phase.classList.remove("phase-collapsed");
        allItems[i].scrollIntoView({ behavior: "smooth", block: "center" });
        return;
      }
    }
    toast("Geen open items meer!");
  }

  /* ==================================================================
     COPY COMMAND — works for inline commands + command file previews
     ================================================================== */
  document.addEventListener("click", function (e) {
    if (!e.target.classList.contains("cmd-copy")) return;
    e.stopPropagation();
    var pre = e.target.closest("pre");
    var line = e.target.closest(".cl-cmdfile-line");
    var text;
    if (line) {
      // Command file preview line — get text from span
      var span = line.querySelector("span");
      text = span ? span.textContent.trim() : "";
    } else if (pre) {
      text = pre.textContent.replace(/kopieer$/, "").trim();
    }
    if (text) {
      navigator.clipboard.writeText(text).then(function () { toast("Gekopieerd"); });
    }
  });

  /* ==================================================================
     COMMAND FILE CARDS — preview + inject
     ================================================================== */

  /* Toggle preview */
  document.querySelectorAll(".cl-cmdfile-toggle").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var card = this.closest(".cl-cmdfile-card");
      var preview = card.querySelector(".cl-cmdfile-preview");
      if (!preview) return;

      if (!preview.classList.contains("d-none")) {
        preview.classList.add("d-none");
        return;
      }

      // Load content if not yet loaded
      if (preview.querySelector(".cl-cmdfile-loading")) {
        var cmdName = card.dataset.cmdRef;
        ensureCommandCache().then(function (cache) {
          var content = cache[cmdName];
          if (!content) {
            preview.innerHTML = '<div class="cl-cmdfile-loading">Command file niet gevonden: ' + escapeHtml(cmdName) + '</div>';
          } else {
            renderCommandPreview(preview, content);
          }
        });
      }
      preview.classList.remove("d-none");
    });
  });

  function renderCommandPreview(container, content) {
    container.innerHTML = "";
    var vars = getVarValues();
    var lines = content.split("\n");
    var preEl = document.createElement("pre");
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      var trimmed = line.trim();
      if (trimmed === "") continue;

      if (trimmed.charAt(0) === "#") {
        // Comment = label
        var label = document.createElement("div");
        label.className = "cl-cmdfile-label";
        label.textContent = trimmed.substring(1).trim();
        preEl.appendChild(label);
      } else {
        // Command line — apply variable replacement
        var replaced = trimmed;
        Object.keys(vars).forEach(function (key) {
          replaced = replaced.split(key).join(vars[key]);
        });
        if (vars.IP) replaced = replaced.split("TARGET").join(vars.IP);

        var lineEl = document.createElement("div");
        lineEl.className = "cl-cmdfile-line";
        var span = document.createElement("span");
        span.textContent = replaced;
        span.className = "cl-cmdfile-line-text";
        var copyBtn = document.createElement("button");
        copyBtn.className = "cmd-copy";
        copyBtn.textContent = "kopieer";
        copyBtn.type = "button";
        lineEl.appendChild(span);
        lineEl.appendChild(copyBtn);
        preEl.appendChild(lineEl);
      }
    }
    container.appendChild(preEl);
  }

  /* Inject button — open inject modal with actual content */
  document.querySelectorAll(".cl-cmdfile-inject").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var screen = getScreenName();
      if (!screen) {
        toast("Selecteer of start eerst een screen sessie");
        return;
      }
      var cmdName = this.dataset.cmdRef;
      var self = this;
      self.disabled = true;
      self.textContent = "Laden...";
      ensureCommandCache().then(function (cache) {
        self.disabled = false;
        self.textContent = "Inject";
        var content = cache[cmdName];
        if (!content) {
          toast("Command file niet gevonden: " + cmdName);
          return;
        }
        if (typeof window.openInjectModal === "function") {
          var vars = getVarValues();
          window.openInjectModal({
            commandName: cmdName,
            content: content,
            mode: "screen",
            screenName: screen,
            initialFind: vars.IP || vars.DOMAIN || "",
            initialReplace: "",
            onSuccess: function () { toast("Geinjected in " + screen); },
          });
        } else {
          toast("Inject modal niet beschikbaar op deze pagina");
        }
      });
    });
  });

  /* ==================================================================
     FINDING TEMPLATES — lazy load + display + create from template
     ================================================================== */

  document.querySelectorAll(".cl-load-templates").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var itemRef = this.dataset.itemRef;
      var wrap = document.querySelector('.cl-finding-templates[data-item-ref="' + itemRef + '"]');
      if (!wrap) return;

      this.disabled = true;
      this.textContent = "Laden...";
      var self = this;

      api("GET", "/api/checklists/" + CL_ID + "/items/" + itemRef + "/matching-templates")
        .then(function (d) {
          self.textContent = "Zoek templates";
          self.disabled = false;
          wrap.classList.remove("d-none");
          wrap.innerHTML = "";

          if (!d.ok || !d.templates || d.templates.length === 0) {
            wrap.innerHTML = '<div class="cl-finding-no-match">Geen matching templates gevonden voor: ' +
              escapeHtml((d.finding_refs || []).join(", ")) + '</div>';
            return;
          }

          d.templates.forEach(function (tmpl) {
            var card = document.createElement("div");
            card.className = "cl-finding-tpl-card";

            // CVSS badge
            var cvssClass = "cvss-info";
            var score = parseFloat(tmpl.basescore);
            if (score >= 9) cvssClass = "cvss-critical";
            else if (score >= 7) cvssClass = "cvss-high";
            else if (score >= 4) cvssClass = "cvss-medium";
            else if (score > 0) cvssClass = "cvss-low";

            var cvssHtml = tmpl.basescore
              ? '<span class="cl-finding-tpl-cvss ' + cvssClass + '">CVSS ' + escapeHtml(tmpl.basescore) + '</span>'
              : '';

            card.innerHTML =
              '<div class="cl-finding-tpl-info">' +
                '<div class="cl-finding-tpl-title">' + escapeHtml(tmpl.titel) + '</div>' +
                '<div class="cl-finding-tpl-meta">' +
                  (tmpl.bevtype ? '<span>' + escapeHtml(tmpl.bevtype) + '</span>' : '') +
                  (tmpl.owasp ? '<span>OWASP: ' + escapeHtml(tmpl.owasp) + '</span>' : '') +
                  '<span>Match: ' + escapeHtml(tmpl.matched_ref) + '</span>' +
                '</div>' +
              '</div>' +
              cvssHtml;

            var useBtn = document.createElement("button");
            useBtn.className = "btn btn-primary";
            useBtn.textContent = "Gebruik template";
            useBtn.dataset.templateId = tmpl.id;
            useBtn.dataset.itemRef = itemRef;
            useBtn.addEventListener("click", function () {
              createFindingFromTemplate(this.dataset.itemRef, parseInt(this.dataset.templateId), this);
            });
            card.appendChild(useBtn);
            wrap.appendChild(card);
          });
        });
    });
  });

  function createFindingFromTemplate(itemRef, templateId, btn) {
    btn.disabled = true;
    btn.textContent = "Aanmaken...";
    api("POST", "/api/checklists/" + CL_ID + "/items/" + itemRef + "/create-finding", { template_id: templateId })
      .then(function (d) {
        if (d.ok) {
          toast("Bevinding aangemaakt: " + d.naam);
          btn.textContent = "Aangemaakt";

          // Add linked finding badge
          var item = document.querySelector('.cl-item[data-ref="' + itemRef + '"]');
          if (item) {
            addFindingBadge(item, d);
            // Disable all create-finding buttons for this item
            item.querySelectorAll(".cl-create-finding").forEach(function (b) { b.disabled = true; });
            // Disable other template buttons
            var tplWrap = item.querySelector(".cl-finding-templates");
            if (tplWrap) tplWrap.querySelectorAll(".btn").forEach(function (b) { b.disabled = true; });
          }
        } else {
          btn.textContent = "Gebruik template";
          btn.disabled = false;
          toast(d.error || "Fout bij aanmaken");
        }
      });
  }

  function addFindingBadge(item, data) {
    var linkedWrap = item.querySelector(".cl-linked-wrap");
    if (!linkedWrap) {
      linkedWrap = item.querySelector(".cl-item-detail");
    }
    if (!linkedWrap) return;

    var badge = document.createElement("span");
    badge.className = "cl-linked cl-finding-link";
    badge.dataset.findingId = data.finding_id;
    var statusClass = "badge-" + (data.status || "draft");
    badge.innerHTML =
      '<a href="/dashboard/findings/edit/' + data.finding_id + '">Bevinding #' + data.finding_id + '</a> ' +
      '<span class="cl-finding-status-badge ' + statusClass + '">' + escapeHtml(data.status || "draft") + '</span>' +
      (data.basescore ? ' <span class="cl-finding-cvss">CVSS ' + escapeHtml(data.basescore) + '</span>' : '') +
      (data.template_used ? ' <span class="cl-finding-tpl-used">(' + escapeHtml(data.template_used) + ')</span>' : '');
    linkedWrap.appendChild(badge);
  }

  /* ==================================================================
     INLINE NOTE SAVE
     ================================================================== */
  document.querySelectorAll(".cl-note-save").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var ref = this.dataset.ref;
      var ta = this.closest(".cl-item-detail").querySelector(".cl-inline-note");
      if (!ta) return;
      api("POST", "/api/checklists/" + CL_ID + "/items/" + ref + "/note", { notitie: ta.value })
        .then(function (d) {
          if (d.ok) toast("Notitie opgeslagen");
        });
    });
  });

  /* ==================================================================
     CREATE NOTE FROM ITEM
     ================================================================== */
  document.querySelectorAll(".cl-create-note").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var ref = this.dataset.ref;
      var self = this;
      api("POST", "/api/checklists/" + CL_ID + "/items/" + ref + "/create-note", {})
        .then(function (d) {
          if (d.ok) {
            toast("Notitie aangemaakt: " + d.naam);
            var linkedWrap = self.closest(".cl-item").querySelector(".cl-linked-wrap") ||
                             self.closest(".cl-item-detail");
            if (linkedWrap) {
              var badge = document.createElement("span");
              badge.className = "cl-linked";
              badge.innerHTML = '<a href="/dashboard/notes/edit/' + d.note_id + '">Notitie #' + d.note_id + "</a>";
              linkedWrap.appendChild(badge);
            }
            self.disabled = true;
          }
        });
    });
  });

  /* ==================================================================
     CREATE FINDING FROM ITEM (direct, without template)
     ================================================================== */
  function handleCreateFinding() {
    var ref = this.dataset.ref;
    var self = this;
    api("POST", "/api/checklists/" + CL_ID + "/items/" + ref + "/create-finding", {})
      .then(function (d) {
        if (d.ok) {
          toast("Bevinding aangemaakt: " + d.naam);
          var item = self.closest(".cl-item");
          if (item) {
            addFindingBadge(item, d);
            // Disable all create-finding buttons for this item
            item.querySelectorAll(".cl-create-finding").forEach(function (b) { b.disabled = true; });
            // Disable template buttons if present
            var tplWrap = item.querySelector(".cl-finding-templates");
            if (tplWrap) tplWrap.querySelectorAll(".btn").forEach(function (b) { b.disabled = true; });
          }
        }
      });
  }

  document.querySelectorAll(".cl-item-actions .cl-create-finding").forEach(function (btn) {
    btn.addEventListener("click", handleCreateFinding);
  });

  /* ==================================================================
     FILTER BAR
     ================================================================== */
  document.querySelectorAll(".cl-filter-btn").forEach(function (btn) {
    btn.addEventListener("click", function () {
      document.querySelectorAll(".cl-filter-btn").forEach(function (b) { b.classList.remove("active"); });
      this.classList.add("active");
      var filter = this.dataset.filter;
      allItems.forEach(function (item) {
        item.style.display = (filter === "all" || item.dataset.status === filter) ? "" : "none";
      });
    });
  });

  /* ==================================================================
     STATUS LEGEND — toggle + localStorage
     ================================================================== */
  (function () {
    var legend = document.getElementById("status-legend");
    var btn = document.getElementById("btn-toggle-legend");
    if (!legend || !btn) return;

    var collapsed = localStorage.getItem(LEGEND_KEY) === "1";
    if (collapsed) legend.classList.add("collapsed");

    btn.addEventListener("click", function () {
      legend.classList.toggle("collapsed");
      localStorage.setItem(LEGEND_KEY, legend.classList.contains("collapsed") ? "1" : "0");
    });
  })();

  /* ==================================================================
     PHASE COLLAPSE / EXPAND
     ================================================================== */
  document.querySelectorAll(".cl-phase-head[data-phase-toggle]").forEach(function (head) {
    head.addEventListener("click", function (e) {
      if (e.target.tagName === "SELECT" || e.target.tagName === "OPTION") return;
      var phase = this.closest(".checklist-phase");
      if (phase) phase.classList.toggle("phase-collapsed");
    });
  });

  /* Auto-collapse completed phases */
  document.querySelectorAll(".checklist-phase.phase-complete").forEach(function (phase) {
    phase.classList.add("phase-collapsed");
  });

  /* ==================================================================
     PHASE NAV — click to scroll + active highlighting
     ================================================================== */
  document.querySelectorAll(".cl-phase-nav-item").forEach(function (link) {
    link.addEventListener("click", function (e) {
      e.preventDefault();
      var target = document.getElementById("phase-" + this.dataset.phase);
      if (target) {
        target.classList.remove("phase-collapsed");
        target.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    });
  });

  function updatePhaseNav() {
    document.querySelectorAll(".cl-phase-nav-item").forEach(function (navItem) {
      var phaseId = navItem.dataset.phase;
      var section = document.getElementById("phase-" + phaseId);
      if (!section) return;

      var items = section.querySelectorAll(".cl-item");
      var done = 0;
      items.forEach(function (i) { if (isDone(i.dataset.status)) done++; });
      var pct = items.length ? Math.round(done / items.length * 100) : 0;

      var pctEl = navItem.querySelector(".cl-phase-nav-pct");
      if (pctEl) pctEl.textContent = pct + "%";

      navItem.classList.remove("nav-done", "nav-active");
      if (done === items.length && items.length > 0) {
        navItem.classList.add("nav-done");
      }
    });

    // Mark first phase with open items as active
    var foundActive = false;
    document.querySelectorAll(".cl-phase-nav-item").forEach(function (navItem) {
      if (foundActive) return;
      var phaseId = navItem.dataset.phase;
      var section = document.getElementById("phase-" + phaseId);
      if (!section) return;
      var hasOpen = section.querySelector('.cl-item[data-status="open"]');
      if (hasOpen && !navItem.classList.contains("nav-done")) {
        navItem.classList.add("nav-active");
        foundActive = true;
      }
    });
  }

  /* Scroll spy */
  if (window.IntersectionObserver) {
    var phaseNavObserver = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          var id = entry.target.dataset.phaseId;
          document.querySelectorAll(".cl-phase-nav-item").forEach(function (n) { n.classList.remove("nav-scroll"); });
          var navItem = document.querySelector('.cl-phase-nav-item[data-phase="' + id + '"]');
          if (navItem) {
            navItem.classList.add("nav-scroll");
            navItem.scrollIntoView({ behavior: "smooth", block: "nearest", inline: "nearest" });
          }
        }
      });
    }, { rootMargin: "-20% 0px -60% 0px" });

    document.querySelectorAll(".checklist-phase").forEach(function (phase) {
      phaseNavObserver.observe(phase);
    });
  }

  /* ==================================================================
     PROGRESS UPDATE
     ================================================================== */
  function updateProgress() {
    document.querySelectorAll(".checklist-phase").forEach(function (phase) {
      var items = phase.querySelectorAll(".cl-item");
      var done = 0;
      items.forEach(function (i) { if (isDone(i.dataset.status)) done++; });
      var pct = items.length ? Math.round(done / items.length * 100) : 0;

      var counter = phase.querySelector(".phase-progress");
      if (counter) counter.textContent = done + "/" + items.length;
      var bar = phase.querySelector(".checklist-progress-fill");
      if (bar) bar.style.width = pct + "%";

      var badge = phase.querySelector(".cl-phase-pct-badge");
      if (badge) {
        badge.textContent = pct + "%";
        badge.classList.toggle("pct-done", done === items.length && items.length > 0);
      }

      phase.classList.toggle("phase-complete", done === items.length && items.length > 0);
    });

    var allDone = 0;
    allItems.forEach(function (i) { if (isDone(i.dataset.status)) allDone++; });
    var overallBar = document.getElementById("overall-progress-fill");
    if (overallBar) overallBar.style.width = (allItems.length ? (allDone / allItems.length * 100) : 0) + "%";
    var overallText = document.getElementById("overall-progress-text");
    if (overallText) overallText.textContent = allDone + "/" + allItems.length + " (" + (allItems.length ? Math.round(allDone / allItems.length * 100) : 0) + "%)";
  }

  updateProgress();
  updatePhaseNav();

  /* ==================================================================
     VARIABLES BAR — live replacement in commands
     ================================================================== */
  var varInputs = document.querySelectorAll(".cl-var-input");
  var cmdElements = document.querySelectorAll(".cl-cmd");

  function loadVars() {
    try {
      var saved = JSON.parse(localStorage.getItem(STORAGE_KEY) || "{}");
      varInputs.forEach(function (input) {
        var key = input.dataset.var;
        if (saved[key]) {
          input.value = saved[key];
          input.classList.add("has-value");
        }
      });
    } catch (e) { /* ignore */ }
  }

  function saveVars() {
    var obj = {};
    varInputs.forEach(function (input) {
      var val = input.value.trim();
      if (val) obj[input.dataset.var] = val;
    });
    localStorage.setItem(STORAGE_KEY, JSON.stringify(obj));
  }

  function getVarValues() {
    var vars = {};
    varInputs.forEach(function (input) {
      var val = input.value.trim();
      if (val) vars[input.dataset.var] = val;
    });
    return vars;
  }

  function applyVarsToCommands() {
    var vars = getVarValues();
    cmdElements.forEach(function (pre) {
      var original = pre.dataset.original;
      if (!original) return;
      var replaced = original;
      var ipVal = vars.IP || "";
      Object.keys(vars).forEach(function (key) {
        replaced = replaced.split(key).join(vars[key]);
      });
      if (ipVal) {
        replaced = replaced.split("TARGET").join(ipVal);
      }
      var copyBtn = pre.querySelector(".cmd-copy");
      pre.textContent = replaced;
      if (copyBtn) pre.appendChild(copyBtn);
    });

    // Also re-render any open command file previews
    document.querySelectorAll(".cl-cmdfile-preview:not(.d-none)").forEach(function (preview) {
      var card = preview.closest(".cl-cmdfile-card");
      if (!card || !commandCache) return;
      var cmdName = card.dataset.cmdRef;
      var content = commandCache[cmdName];
      if (content) renderCommandPreview(preview, content);
    });
  }

  // Pre-fill variables from checklist target + scope targets
  (function () {
    var target = (document.body.dataset.checklistTarget || "").trim();
    if (!target) return;

    // Zoek matching scope target voor type-aware pre-fill
    var scopeTargets = [];
    try { scopeTargets = JSON.parse(document.body.dataset.scopeTargets || "[]"); } catch (e) {}
    var matched = null;
    for (var i = 0; i < scopeTargets.length; i++) {
      if (scopeTargets[i].target === target) { matched = scopeTargets[i]; break; }
    }

    var ipInput = document.querySelector('.cl-var-input[data-var="IP"]');
    var domainInput = document.querySelector('.cl-var-input[data-var="DOMAIN"]');

    function setIfEmpty(input, val) {
      if (input && !input.value && val) {
        input.value = val;
        input.classList.add("has-value");
      }
    }

    if (matched) {
      // Type-aware: host/netwerk -> IP, url/applicatie -> DOMAIN + IP
      var t = matched.type || "host";
      if (t === "url" || t === "applicatie") {
        // Probeer hostname uit URL te halen voor DOMAIN
        var hostname = target;
        try {
          var u = new URL(target.indexOf("://") === -1 ? "https://" + target : target);
          hostname = u.hostname;
        } catch (e) {}
        setIfEmpty(domainInput, hostname);
        setIfEmpty(ipInput, target);
      } else {
        // host of netwerk -> IP
        setIfEmpty(ipInput, target);
      }
    } else {
      // Geen scope match: fallback naar bestaand gedrag (IP)
      setIfEmpty(ipInput, target);
    }
  })();

  loadVars();
  applyVarsToCommands();

  varInputs.forEach(function (input) {
    input.addEventListener("input", function () {
      this.classList.toggle("has-value", !!this.value.trim());
      saveVars();
      applyVarsToCommands();
    });
  });

  /* ==================================================================
     KEYBOARD NAVIGATION
     ================================================================== */
  function setFocus(idx) {
    if (idx < 0 || idx >= allItems.length) return;
    if (focusIdx >= 0 && focusIdx < allItems.length) {
      allItems[focusIdx].classList.remove("cl-focused");
    }
    focusIdx = idx;
    allItems[focusIdx].classList.add("cl-focused");
    allItems[focusIdx].scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  function getNextVisibleIdx(from, direction) {
    var i = from + direction;
    while (i >= 0 && i < allItems.length) {
      if (allItems[i].style.display !== "none") return i;
      i += direction;
    }
    return -1;
  }

  document.addEventListener("keydown", function (e) {
    if (isInputFocused()) return;

    var key = e.key;

    if (key === "?") {
      e.preventDefault();
      var help = document.getElementById("keyboard-help");
      if (help) help.classList.toggle("d-none");
      return;
    }

    if (key === "j" || key === "ArrowDown") {
      e.preventDefault();
      var next = getNextVisibleIdx(focusIdx, 1);
      if (next >= 0) setFocus(next);
      return;
    }

    if (key === "k" || key === "ArrowUp") {
      e.preventDefault();
      var prev = getNextVisibleIdx(focusIdx, -1);
      if (prev >= 0) setFocus(prev);
      return;
    }

    if (key === "Enter" || key === " ") {
      if (focusIdx >= 0 && focusIdx < allItems.length) {
        e.preventDefault();
        toggleItem(allItems[focusIdx]);
      }
      return;
    }

    if (key === "n") {
      e.preventDefault();
      goToNextOpen(focusIdx >= 0 ? allItems[focusIdx] : null);
      return;
    }

    if (key >= "1" && key <= "6") {
      if (focusIdx >= 0 && focusIdx < allItems.length) {
        e.preventDefault();
        var statusIdx = parseInt(key) - 1;
        if (statusIdx < STATUS_MAP.length) {
          var item = allItems[focusIdx];
          var sel = item.querySelector(".cl-status-select");
          if (sel) {
            sel.value = STATUS_MAP[statusIdx];
            sel.dispatchEvent(new Event("change"));
          }
        }
      }
      return;
    }
  });

  /* ==================================================================
     KEYBOARD HELP PANEL
     ================================================================== */
  (function () {
    var helpPanel = document.getElementById("keyboard-help");
    var openBtn = document.getElementById("btn-keyboard-help");
    var closeBtn = document.getElementById("btn-close-help");
    if (!helpPanel) return;

    if (openBtn) {
      openBtn.addEventListener("click", function () { helpPanel.classList.toggle("d-none"); });
    }
    if (closeBtn) {
      closeBtn.addEventListener("click", function () { helpPanel.classList.add("d-none"); });
    }
    helpPanel.addEventListener("click", function (e) {
      if (e.target === helpPanel) helpPanel.classList.add("d-none");
    });
  })();

})();
