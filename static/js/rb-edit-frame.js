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

  // Scroll-opdrachten vanuit de sectienavigatie in het dashboard.
  window.addEventListener("message", function (e) {
    var m = e.data;
    if (m && m.rbScrollTo) {
      var el = document.getElementById(m.rbScrollTo);
      if (el && el.scrollIntoView) el.scrollIntoView({ behavior: "smooth", block: "start" });
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
