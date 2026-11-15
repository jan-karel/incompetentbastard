/* rb-edit-frame.js — draait in de preview-iframe van het tabblad Bewerken.
 * Maakt elk edit-anker ([data-ed-type]) klikbaar en stuurt de klik via
 * postMessage naar het dashboard, dat de juiste editor opent. */
(function () {
  "use strict";
  if (!window.parent || window.parent === window) return;

  function onClick(el, e) {
    e.preventDefault();
    e.stopPropagation();
    window.parent.postMessage({
      source: "rb-edit",
      type: el.getAttribute("data-ed-type") || "",
      key: el.getAttribute("data-ed-key") || ""
    }, "*");
  }

  function injectSectionToggle(sec) {
    if (sec._rbToggle) return;
    sec._rbToggle = true;
    var off = sec.classList.contains("rb-off");
    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "rb-sec-toggle";
    btn.textContent = off ? "⊕ sectie aan" : "⊖ sectie uit";
    btn.title = off ? "Deze sectie inschakelen" : "Deze sectie uitschakelen";
    btn.addEventListener("click", function (e) {
      e.preventDefault();
      e.stopPropagation();
      window.parent.postMessage({ source: "rb-edit", type: "section",
        key: sec.getAttribute("data-ed-key") || "" }, "*");
    });
    sec.insertBefore(btn, sec.firstChild);
  }

  function wire() {
    var nodes = document.querySelectorAll("[data-ed-type]");
    for (var i = 0; i < nodes.length; i++) {
      (function (el) {
        // Secties krijgen een apart toggle-knopje; de inhoud blijft bewerkbaar.
        if (el.getAttribute("data-ed-type") === "section") {
          injectSectionToggle(el);
          return;
        }
        if (el._rbWired) return;
        el._rbWired = true;
        el.addEventListener("click", function (e) {
          // Alleen het binnenste anker reageert (geen dubbele events bij nesting).
          var inner = e.target.closest ? e.target.closest("[data-ed-type]:not([data-ed-type='section'])") : null;
          if (inner && inner !== el) return;
          onClick(el, e);
        });
        // Toegankelijkheid: de ankers zijn focusbaar (tabindex=0); Enter/Space
        // opent dezelfde editor als een klik.
        el.addEventListener("keydown", function (e) {
          if (e.target !== el) return;  // alleen het gefocuste anker zelf
          if (e.key === "Enter" || e.key === " " || e.key === "Spacebar") onClick(el, e);
        });
      })(nodes[i]);
    }
    // Afbeeldingen → lak-galerij (voorrang boven het omliggende tekst-anker).
    var imgs = document.querySelectorAll("img");
    for (var j = 0; j < imgs.length; j++) {
      (function (img) {
        if (img._rbImg) return;
        img._rbImg = true;
        img.style.cursor = "zoom-in";
        img.addEventListener("click", function (e) {
          e.preventDefault();
          e.stopPropagation();
          var fig = img.closest ? img.closest("[data-img-name]") : null;
          var nm = fig ? (fig.getAttribute("data-img-name") || "") : "";
          window.parent.postMessage({ source: "rb-edit", type: "image", key: nm }, "*");
        });
      })(imgs[j]);
    }
  }

  function sendToc() {
    var hs = document.querySelectorAll("h1, h2");
    var items = [];
    for (var i = 0; i < hs.length; i++) {
      var h = hs[i];
      if (!h.id) h.id = "rbh-" + i;
      items.push({ id: h.id, text: (h.textContent || "").trim().slice(0, 80),
                   level: h.tagName === "H1" ? 1 : 2 });
    }
    window.parent.postMessage({ source: "rb-edit", type: "toc", items: items }, "*");
  }

  // Zoek het edit-anker op type + key (met veilige attribuut-escaping).
  function edBy(ref) {
    if (!ref || !ref.type) return null;
    try {
      var sel = '[data-ed-type="' + ref.type + '"][data-ed-key="' +
                String(ref.key).replace(/["\\]/g, "\\$&") + '"]';
      return document.querySelector(sel);
    } catch (err) { return null; }
  }
  function clearHot() {
    var hot = document.querySelectorAll(".rb-hot");
    for (var i = 0; i < hot.length; i++) hot[i].classList.remove("rb-hot");
  }

  // Scroll- en highlight-opdrachten vanuit het dashboard.
  window.addEventListener("message", function (e) {
    var m = e.data;
    if (!m) return;
    if (m.rbScrollTo) {
      var el = document.getElementById(m.rbScrollTo);
      if (el && el.scrollIntoView) el.scrollIntoView({ behavior: "smooth", block: "start" });
      return;
    }
    // Het onderdeel dat nu bewerkt wordt blijvend markeren (of markering wissen).
    if ("rbHighlight" in m) {
      clearHot();
      var h = edBy(m.rbHighlight);
      if (h) {
        h.classList.add("rb-hot");
        if (h.scrollIntoView) h.scrollIntoView({ behavior: "smooth", block: "nearest" });
      }
      return;
    }
    // Na opslaan: terug naar het net bewerkte onderdeel met een korte flash.
    if (m.rbScrollToEd && m.rbScrollToEd.type) {
      var t = edBy(m.rbScrollToEd);
      if (t && t.scrollIntoView) {
        t.scrollIntoView({ behavior: "smooth", block: "center" });
        clearHot();
        t.classList.add("rb-hot");
        setTimeout(function () { t.classList.remove("rb-hot"); }, 1400);
      }
    }
  });

  // Secties met een <!--SEC:key--> marker klikbaar maken (aan/uit via het
  // dashboard). De kop na de marker krijgt een 'section'-anker.
  function markSections() {
    try {
      var walker = document.createTreeWalker(document.body, NodeFilter.SHOW_COMMENT, null);
      var c;
      while ((c = walker.nextNode())) {
        var m = /^\s*SEC:([a-z_]+)\s*$/.exec(c.nodeValue || "");
        if (!m) continue;
        var n = c.nextSibling;
        while (n && n.nodeType !== 1) n = n.nextSibling;
        if (n && !n.hasAttribute("data-ed-type")) {
          n.setAttribute("data-ed-type", "section");
          n.setAttribute("data-ed-key", m[1]);
          n.setAttribute("title", "Klik om deze sectie aan/uit te zetten");
        }
      }
    } catch (e) { /* no-op */ }
  }

  function boot() { markSections(); wire(); sendToc(); }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
