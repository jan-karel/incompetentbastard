(() => {
  const list = document.getElementById("output-list");
  const filter = document.getElementById("output-filter");
  const meta = document.getElementById("output-meta");
  const content = document.getElementById("output-content");
  const copyBtn = document.getElementById("copy-output");

  if (!list || !filter || !meta || !content || !copyBtn) return;

  const items = Array.from(list.querySelectorAll(".output-item"));

  filter.addEventListener("input", () => {
    const q = filter.value.trim().toLowerCase();
    for (const item of items) {
      const hay = item.getAttribute("data-search") || "";
      item.style.display = hay.includes(q) ? "grid" : "none";
    }
  });

  const selectItem = async (item) => {
    items.forEach((x) => x.classList.remove("active"));
    item.classList.add("active");

    const id = item.getAttribute("data-id");
    if (!id) return;

    meta.textContent = "Laden...";
    content.textContent = "";

    const res = await fetch(`/api/outputs/${encodeURIComponent(id)}`);
    const data = await res.json();

    if (!res.ok) {
      meta.textContent = `Fout: ${data.error || "onbekend"}`;
      return;
    }

    meta.textContent = data.path + (data.truncated ? " (truncated)" : "");
    content.textContent = data.content || "";
  };

  items.forEach((item) => {
    item.addEventListener("click", () => {
      selectItem(item);
    });
  });

  copyBtn.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(content.textContent || "");
      const old = copyBtn.textContent;
      copyBtn.textContent = "copied";
      setTimeout(() => {
        copyBtn.textContent = old;
      }, 1000);
    } catch (_err) {
      const old = copyBtn.textContent;
      copyBtn.textContent = "failed";
      setTimeout(() => {
        copyBtn.textContent = old;
      }, 1000);
    }
  });

  if (items.length > 0) {
    selectItem(items[0]);
  }
})();
