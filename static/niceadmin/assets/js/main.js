/* NiceAdmin-inspired dashboard interactions — Vanilla JS */
(() => {
  const $ = (sel, root=document) => root.querySelector(sel);
  const $$ = (sel, root=document) => Array.from(root.querySelectorAll(sel));

  // Toast
  const toastEl = $("#toast");
  const toast = (msg) => {
    if (!toastEl) return;
    toastEl.textContent = msg;
    toastEl.classList.add("show");
    clearTimeout(toast._t);
    toast._t = setTimeout(() => toastEl.classList.remove("show"), 2600);
  };

  // Theme toggle (persist)
  const applyTheme = (theme) => {
    document.body.classList.toggle("theme-dark", theme === "dark");
    localStorage.setItem("na-theme", theme);
  };
  const savedTheme = localStorage.getItem("na-theme");
  if (savedTheme) applyTheme(savedTheme);

  $("#themeToggle")?.addEventListener("click", () => {
    const isDark = document.body.classList.contains("theme-dark");
    applyTheme(isDark ? "light" : "dark");
    toast(isDark ? "Light mode" : "Dark mode");
  });

  // Sidebar toggle
  const overlay = $("#overlay");
  const isMobile = () => window.matchMedia("(max-width: 820px)").matches;

  // Restore collapsed state from localStorage (desktop only)
  if (localStorage.getItem("na-sidebar") === "collapsed" && !isMobile()) {
    document.body.classList.add("sidebar-collapsed");
  }

  const setSidebar = (open) => {
    if (isMobile()) {
      document.body.classList.toggle("sidebar-open", open);
      overlay?.toggleAttribute("hidden", !open);
    } else {
      const collapsed = !document.body.classList.contains("sidebar-collapsed");
      document.body.classList.toggle("sidebar-collapsed", collapsed);
      localStorage.setItem("na-sidebar", collapsed ? "collapsed" : "open");
    }
  };
  $("#sidebarToggle")?.addEventListener("click", () => {
    if (isMobile()) {
      setSidebar(!document.body.classList.contains("sidebar-open"));
    } else {
      setSidebar();
    }
  });
  overlay?.addEventListener("click", () => {
    document.body.classList.remove("sidebar-open");
    overlay?.toggleAttribute("hidden", true);
  });

  // Expandable sidebar groups
  $$("[data-nav-group]").forEach(group => {
    const btn = $("[data-nav-btn]", group);
    btn?.addEventListener("click", () => {
      const open = group.getAttribute("data-open") === "true";
      group.setAttribute("data-open", String(!open));
      btn.setAttribute("aria-expanded", String(!open));
    });
  });

  // Active nav link based on filename
  const path = location.pathname.split("/").pop() || "index.html";
  $$('a[data-page]').forEach(a => a.classList.toggle("active", a.getAttribute("data-page") === path));
  // Auto-open group if active inside
  $$("[data-nav-group]").forEach(g => {
    const activeInside = !!$("a.active", g);
    if (activeInside) g.setAttribute("data-open", "true");
  });

  // Dropdowns
  const closeDropdowns = () => {
    $$("[data-dd]").forEach(dd => dd.removeAttribute("data-open"));
    $$("[data-dd-btn]").forEach(btn => btn.setAttribute("aria-expanded", "false"));
  };

  $$("[data-dd]").forEach(dd => {
    const btn = $("[data-dd-btn]", dd);
    btn?.addEventListener("click", (e) => {
      e.stopPropagation();
      const open = dd.getAttribute("data-open") === "true";
      closeDropdowns();
      dd.setAttribute("data-open", String(!open));
      btn.setAttribute("aria-expanded", String(!open));
    });
  });

  document.addEventListener("click", () => closeDropdowns());
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDropdowns(); });

  // Search clear
  const search = $("#searchBox");
  const clear = $("#searchClear");
  const searchWrap = $("#searchWrap");
  const updateSearchUI = () => {
    const v = (search?.value || "").trim();
    searchWrap?.classList.toggle("has-value", v.length > 0);
  };
  search?.addEventListener("input", updateSearchUI);
  clear?.addEventListener("click", () => {
    if (!search) return;
    search.value = "";
    updateSearchUI();
    search.focus();
  });
  updateSearchUI();

  // Back to top
  const topBtn = $("#toTop");
  const onScroll = () => {
    topBtn?.classList.toggle("show", window.scrollY > 700);
  };
  window.addEventListener("scroll", onScroll, { passive: true });
  onScroll();
  topBtn?.addEventListener("click", () => window.scrollTo({ top: 0, behavior: "smooth" }));

  // Simple table sort (Tables page)
  const table = $("#sortableTable");
  if (table) {
    const ths = $$("th.sortable", table);
    const tbody = $("tbody", table);
    const getCell = (tr, idx) => tr.children[idx]?.textContent?.trim() || "";
    const parseSmart = (v) => {
      const num = Number(v.replace(/[^0-9.\-]/g, ""));
      if (!Number.isNaN(num) && /[0-9]/.test(v)) return num;
      return v.toLowerCase();
    };

    ths.forEach((th, idx) => {
      th.addEventListener("click", () => {
        const dir = th.getAttribute("data-dir") === "asc" ? "desc" : "asc";
        ths.forEach(t => t.removeAttribute("data-dir"));
        th.setAttribute("data-dir", dir);
        const rows = $$("tr", tbody);
        rows.sort((a,b) => {
          const av = parseSmart(getCell(a, idx));
          const bv = parseSmart(getCell(b, idx));
          if (av < bv) return dir === "asc" ? -1 : 1;
          if (av > bv) return dir === "asc" ? 1 : -1;
          return 0;
        });
        rows.forEach(r => tbody.appendChild(r));
      });
    });
  }

  // Forms page demo validation
  const form = $("#demoForm");
  if (form) {
    const showErr = (name, msg) => {
      const el = document.querySelector(`[data-err-for="${name}"]`);
      if (el) el.textContent = msg || "";
    };
    const emailOk = (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v.trim());

    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const data = new FormData(form);
      const name = String(data.get("name") || "");
      const email = String(data.get("email") || "");
      const role = String(data.get("role") || "");
      const msg = String(data.get("message") || "");

      let ok = true;
      showErr("name", ""); showErr("email", ""); showErr("role", ""); showErr("message", "");
      if (name.trim().length < 2) { showErr("name", "Minimaal 2 tekens."); ok = false; }
      if (!emailOk(email)) { showErr("email", "Ongeldig e-mailadres."); ok = false; }
      if (!role) { showErr("role", "Kies een rol."); ok = false; }
      if (msg.trim().length < 10) { showErr("message", "Minimaal 10 tekens."); ok = false; }

      if (!ok) { toast("Check de velden."); return; }
      toast("Formulier verstuurd (demo).");
      form.reset();
    });
  }

  // Charts (Charts page + Dashboard widgets)
  const drawLine = (canvas, points, opts={}) => {
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const { stroke = getComputedStyle(document.body).getPropertyValue("--primary").trim() || "#4154f1" } = opts;

    const w = canvas.width = canvas.clientWidth * devicePixelRatio;
    const h = canvas.height = canvas.clientHeight * devicePixelRatio;
    ctx.clearRect(0,0,w,h);

    const pad = 18 * devicePixelRatio;
    const min = Math.min(...points);
    const max = Math.max(...points);
    const sx = (w - 2*pad) / (points.length - 1);
    const sy = (h - 2*pad) / ((max - min) || 1);

    // grid
    ctx.globalAlpha = 0.18;
    ctx.strokeStyle = getComputedStyle(document.body).getPropertyValue("--border");
    ctx.lineWidth = 1 * devicePixelRatio;
    for (let i=0;i<4;i++){
      const y = pad + i*(h-2*pad)/3;
      ctx.beginPath(); ctx.moveTo(pad, y); ctx.lineTo(w-pad, y); ctx.stroke();
    }
    ctx.globalAlpha = 1;

    // line
    ctx.lineWidth = 2.4 * devicePixelRatio;
    ctx.strokeStyle = stroke;
    ctx.beginPath();
    points.forEach((p, i) => {
      const x = pad + i*sx;
      const y = h - pad - (p - min)*sy;
      if (i === 0) ctx.moveTo(x,y); else ctx.lineTo(x,y);
    });
    ctx.stroke();

    // fill
    const grad = ctx.createLinearGradient(0, pad, 0, h-pad);
    grad.addColorStop(0, `${stroke}33`);
    grad.addColorStop(1, `${stroke}00`);
    ctx.fillStyle = grad;
    ctx.lineTo(w-pad, h-pad);
    ctx.lineTo(pad, h-pad);
    ctx.closePath();
    ctx.fill();
  };

  const drawBars = (canvas, values, opts={}) => {
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const stroke = (opts.stroke || getComputedStyle(document.body).getPropertyValue("--info").trim() || "#0ea5e9");
    const w = canvas.width = canvas.clientWidth * devicePixelRatio;
    const h = canvas.height = canvas.clientHeight * devicePixelRatio;
    ctx.clearRect(0,0,w,h);
    const pad = 18 * devicePixelRatio;
    const max = Math.max(...values) || 1;
    const bw = (w - 2*pad) / values.length;

    ctx.globalAlpha = 0.18;
    ctx.strokeStyle = getComputedStyle(document.body).getPropertyValue("--border");
    ctx.lineWidth = 1 * devicePixelRatio;
    for (let i=0;i<4;i++){
      const y = pad + i*(h-2*pad)/3;
      ctx.beginPath(); ctx.moveTo(pad, y); ctx.lineTo(w-pad, y); ctx.stroke();
    }
    ctx.globalAlpha = 1;

    values.forEach((v, i) => {
      const x = pad + i*bw + bw*0.18;
      const barW = bw*0.64;
      const barH = (h - 2*pad) * (v / max);
      const y = h - pad - barH;
      ctx.fillStyle = `${stroke}33`;
      ctx.strokeStyle = stroke;
      ctx.lineWidth = 2 * devicePixelRatio;
      roundRect(ctx, x, y, barW, barH, 8*devicePixelRatio, true, true);
    });
  };

  function roundRect(ctx, x, y, w, h, r, fill, stroke){
    const rr = Math.min(r, w/2, h/2);
    ctx.beginPath();
    ctx.moveTo(x+rr, y);
    ctx.arcTo(x+w, y, x+w, y+h, rr);
    ctx.arcTo(x+w, y+h, x, y+h, rr);
    ctx.arcTo(x, y+h, x, y, rr);
    ctx.arcTo(x, y, x+w, y, rr);
    ctx.closePath();
    if (fill) ctx.fill();
    if (stroke) ctx.stroke();
  }

  const lineMain = $("#chartLine");
  const barMain = $("#chartBar");
  const spark = $("#sparkline");

  const renderCharts = () => {
    drawLine(lineMain, [12, 19, 15, 26, 22, 34, 30, 38, 31, 46, 41, 50]);
    drawBars(barMain, [8, 12, 10, 16, 14, 18, 17, 22, 19, 25, 23, 28]);
    drawLine(spark, [6, 8, 7, 10, 9, 12, 11, 14, 13, 15, 14, 17], { stroke: getComputedStyle(document.body).getPropertyValue("--success").trim() || "#2eca6a" });
  };

  if (lineMain || barMain || spark) {
    renderCharts();
    window.addEventListener("resize", () => renderCharts(), { passive: true });
    // re-render on theme change (colors)
    const obs = new MutationObserver(() => renderCharts());
    obs.observe(document.body, { attributes: true, attributeFilter: ["class"] });
  }
})();
