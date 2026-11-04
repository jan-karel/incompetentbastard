/* AMSI Bypass Generator */
(function () {
  'use strict';

  // ── DOM referenties ──────────────────────────────────────────────────────
  const archPills      = document.querySelectorAll('.pill-label');
  const amsiMethod     = document.getElementById('amsi-method');
  const clmMethod      = document.getElementById('clm-method');
  const replaceFindEl  = document.getElementById('replace-find');
  const replaceWithEl  = document.getElementById('replace-with');
  const replaceHttps   = document.getElementById('replace-https');
  const btnGenerate    = document.getElementById('btn-generate');
  const genStatus      = document.getElementById('gen-status');
  const output         = document.getElementById('amsi-output');
  const btnCopy        = document.getElementById('btn-copy-output');
  const btnDownload    = document.getElementById('btn-download');
  const btnSavePayload = document.getElementById('btn-save-payload');
  const presetFilter = document.getElementById('preset-filter');
  const presetList   = document.getElementById('preset-list');
  const btnAdd       = document.getElementById('btn-add-preset');

  // Modal
  const modal         = document.getElementById('preset-modal');
  const modalTitle    = document.getElementById('modal-title');
  const modalId       = document.getElementById('modal-preset-id');
  const modalNaam     = document.getElementById('modal-naam');
  const modalCat      = document.getElementById('modal-categorie');
  const modalArch     = document.getElementById('modal-arch');
  const modalMethode  = document.getElementById('modal-methode');
  const modalOms      = document.getElementById('modal-omschrijving');
  const modalCode     = document.getElementById('modal-code');
  const modalVolgorde = document.getElementById('modal-volgorde');
  const modalActief   = document.getElementById('modal-actief');
  const modalSave     = document.getElementById('modal-save');
  const modalCancel   = document.getElementById('modal-cancel');
  const modalClose    = document.getElementById('modal-close');
  const modalStatus   = document.getElementById('modal-status');

  // ── State ────────────────────────────────────────────────────────────────
  let allPresets = [];
  let filterText = '';

  // ── Architectuur pills ───────────────────────────────────────────────────
  archPills.forEach(pill => {
    pill.addEventListener('click', () => {
      archPills.forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
    });
  });

  function getArch() {
    const checked = document.querySelector('input[name="arch"]:checked');
    return checked ? checked.value : 'auto';
  }

  // ── Zoek / vervang (zelfde patroon als commands.js) ─────────────────────
  function applyReplacements(text) {
    if (replaceHttps.checked) {
      text = text.split('http://').join('https://');
    }
    const find = replaceFindEl.value;
    if (find) {
      text = text.split(find).join(replaceWithEl.value);
    }
    return text;
  }

  // Hertoepassen op bestaande output zonder nieuwe API-call
  function reapply() {
    const raw = output.dataset.raw;
    if (raw) output.textContent = applyReplacements(raw);
  }

  replaceFindEl.addEventListener('input', reapply);
  replaceWithEl.addEventListener('input', reapply);
  replaceHttps.addEventListener('change', reapply);

  // ── Genereer ─────────────────────────────────────────────────────────────
  btnGenerate.addEventListener('click', generate);

  async function generate() {
    const arch   = getArch();
    const method = amsiMethod.value;
    const clm    = clmMethod.value;

    btnGenerate.disabled = true;
    genStatus.textContent = 'Genereren...';
    genStatus.className = 'status';

    const params = new URLSearchParams({ arch, method });
    if (clm && clm !== 'none') params.set('clm', clm);

    try {
      const r = await fetch('/api/amsi/generate?' + params);
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const data = await r.json();
      output.dataset.raw = data.code;
      output.textContent = applyReplacements(data.code);
      genStatus.textContent = 'Klaar';
      genStatus.className = 'status ok';

      // Update download-link
      btnDownload.href = '/dashboard/amsi/payload.ps1?' + params;
    } catch (e) {
      genStatus.textContent = 'Fout: ' + e.message;
      genStatus.className = 'status fail';
    } finally {
      btnGenerate.disabled = false;
      setTimeout(() => { genStatus.textContent = ''; genStatus.className = 'status'; }, 3000);
    }
  }

  // ── Opslaan naar http/payloads/amsi-bypass.ps1 ──────────────────────────
  btnSavePayload.addEventListener('click', async () => {
    const text = output.dataset.raw ? output.textContent : null;
    if (!text || !output.dataset.raw) {
      genStatus.textContent = 'Genereer eerst een bypass.';
      genStatus.className = 'status fail';
      setTimeout(() => { genStatus.textContent = ''; genStatus.className = 'status'; }, 3000);
      return;
    }
    btnSavePayload.disabled = true;
    try {
      const r = await fetch('/api/amsi/save-payload', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrf() },
        body: JSON.stringify({ code: text }),
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.error || 'HTTP ' + r.status);
      btnSavePayload.textContent = 'Opgeslagen!';
      setTimeout(() => { btnSavePayload.textContent = 'Opslaan naar schijf'; }, 2500);
    } catch (e) {
      genStatus.textContent = 'Fout bij opslaan: ' + e.message;
      genStatus.className = 'status fail';
      setTimeout(() => { genStatus.textContent = ''; genStatus.className = 'status'; }, 4000);
    } finally {
      btnSavePayload.disabled = false;
    }
  });

  // ── Kopiëren ─────────────────────────────────────────────────────────────
  btnCopy.addEventListener('click', () => {
    const text = output.textContent;
    if (!text || text.startsWith('Klik')) return;
    navigator.clipboard.writeText(text).then(() => {
      btnCopy.textContent = 'Gekopieerd!';
      setTimeout(() => { btnCopy.textContent = 'Kopiëren'; }, 2000);
    });
  });

  // ── Presets laden ────────────────────────────────────────────────────────
  async function loadPresets() {
    try {
      const r = await fetch('/api/amsi/presets');
      allPresets = await r.json();
      renderPresets();
    } catch (e) {
      presetList.innerHTML = '<p class="text-muted">Kon presets niet laden.</p>';
    }
  }

  presetFilter.addEventListener('input', () => {
    filterText = presetFilter.value.toLowerCase();
    renderPresets();
  });

  function renderPresets() {
    const visible = allPresets.filter(p => {
      if (!filterText) return true;
      return (
        p.naam.toLowerCase().includes(filterText) ||
        p.methode.toLowerCase().includes(filterText) ||
        p.architectuur.toLowerCase().includes(filterText) ||
        p.categorie.toLowerCase().includes(filterText) ||
        (p.omschrijving || '').toLowerCase().includes(filterText)
      );
    });

    if (visible.length === 0) {
      presetList.innerHTML = '<p class="preset-empty">Geen presets gevonden.</p>';
      return;
    }

    const tbl = document.createElement('table');
    tbl.className = 'amsi-preset-table';
    tbl.innerHTML = `
      <thead>
        <tr>
          <th>Naam</th>
          <th>Cat.</th>
          <th>Arch.</th>
          <th>Methode</th>
          <th>Code (preview)</th>
          <th>Acties</th>
        </tr>
      </thead>`;

    const tbody = document.createElement('tbody');
    visible.forEach(p => {
      const tr = document.createElement('tr');
      if (!p.actief) tr.classList.add('preset-inactive');
      tr.innerHTML = `
        <td>
          ${escHtml(p.naam)}
          ${p.ingebouwd ? ' <span class="badge badge-builtin">ingebouwd</span>' : ''}
        </td>
        <td><span class="badge badge-${p.categorie}">${p.categorie.toUpperCase()}</span></td>
        <td><span class="badge badge-${p.architectuur}">${p.architectuur}</span></td>
        <td><code>${escHtml(p.methode)}</code></td>
        <td><span class="preset-code-preview" title="${escHtml(p.code)}">${escHtml(p.code)}</span></td>
        <td class="preset-actions">
          <button class="btn btn-sm btn-preset-edit" data-id="${p.id}">Bewerk</button>
          <button class="btn btn-sm btn-preset-toggle" data-id="${p.id}" data-actief="${p.actief}">
            ${p.actief ? 'Deactiveer' : 'Activeer'}
          </button>
          ${!p.ingebouwd
            ? `<button class="btn btn-sm btn-preset-delete" data-id="${p.id}">Verwijder</button>`
            : ''}
        </td>`;
      tbody.appendChild(tr);
    });

    tbl.appendChild(tbody);
    presetList.innerHTML = '';
    presetList.appendChild(tbl);

    // Event listeners op knoppen
    presetList.querySelectorAll('.btn-preset-edit').forEach(btn => {
      btn.addEventListener('click', () => openModal(parseInt(btn.dataset.id)));
    });
    presetList.querySelectorAll('.btn-preset-toggle').forEach(btn => {
      btn.addEventListener('click', () => togglePreset(parseInt(btn.dataset.id), btn.dataset.actief === 'true'));
    });
    presetList.querySelectorAll('.btn-preset-delete').forEach(btn => {
      btn.addEventListener('click', () => deletePreset(parseInt(btn.dataset.id)));
    });
  }

  // ── Preset toggle actief ─────────────────────────────────────────────────
  async function togglePreset(id, huidigActief) {
    try {
      const r = await fetch(`/api/amsi/presets/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrf() },
        body: JSON.stringify({ actief: !huidigActief }),
      });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      await loadPresets();
    } catch (e) {
      alert('Fout bij bijwerken preset: ' + e.message);
    }
  }

  // ── Preset verwijderen ───────────────────────────────────────────────────
  async function deletePreset(id) {
    const preset = allPresets.find(p => p.id === id);
    if (!preset) return;
    if (!confirm(`Weet je zeker dat je "${preset.naam}" wilt verwijderen?`)) return;
    try {
      const r = await fetch(`/api/amsi/presets/${id}`, {
        method: 'DELETE',
        headers: { 'X-CSRFToken': getCsrf() },
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.error || 'HTTP ' + r.status);
      await loadPresets();
    } catch (e) {
      alert('Fout bij verwijderen: ' + e.message);
    }
  }

  // ── Modal open/sluiten ───────────────────────────────────────────────────
  btnAdd.addEventListener('click', () => openModal(null));
  modalClose.addEventListener('click', closeModal);
  modalCancel.addEventListener('click', closeModal);
  modal.addEventListener('click', e => { if (e.target === modal) closeModal(); });

  function openModal(id) {
    modalStatus.textContent = '';
    modalStatus.className = 'status ml-8';

    if (id === null) {
      // Nieuw preset
      modalTitle.textContent = 'Preset toevoegen';
      modalId.value = '';
      modalNaam.value = '';
      modalCat.value = 'amsi';
      modalArch.value = 'any';
      modalMethode.value = '';
      modalOms.value = '';
      modalCode.value = '';
      modalVolgorde.value = '99';
      modalActief.checked = true;
    } else {
      const p = allPresets.find(p => p.id === id);
      if (!p) return;
      modalTitle.textContent = 'Preset bewerken';
      modalId.value = p.id;
      modalNaam.value = p.naam;
      modalCat.value = p.categorie;
      modalArch.value = p.architectuur;
      modalMethode.value = p.methode;
      modalOms.value = p.omschrijving || '';
      modalCode.value = p.code || '';
      modalVolgorde.value = p.volgorde;
      modalActief.checked = p.actief;
    }

    modal.classList.remove('amsi-hidden');
    modalNaam.focus();
  }

  function closeModal() {
    modal.classList.add('amsi-hidden');
  }

  // ── Modal opslaan ────────────────────────────────────────────────────────
  modalSave.addEventListener('click', saveModal);

  async function saveModal() {
    const naam = modalNaam.value.trim();
    if (!naam) {
      modalStatus.textContent = 'Naam is verplicht.';
      modalStatus.className = 'status fail ml-8';
      return;
    }

    const payload = {
      naam,
      categorie:    modalCat.value,
      architectuur: modalArch.value,
      methode:      modalMethode.value.trim(),
      omschrijving: modalOms.value.trim(),
      code:         modalCode.value,
      volgorde:     parseInt(modalVolgorde.value) || 99,
      actief:       modalActief.checked,
    };

    const id = modalId.value;
    const url    = id ? `/api/amsi/presets/${id}` : '/api/amsi/presets';
    const method = id ? 'PUT' : 'POST';

    modalSave.disabled = true;
    try {
      const r = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrf() },
        body: JSON.stringify(payload),
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.error || 'HTTP ' + r.status);
      closeModal();
      await loadPresets();
    } catch (e) {
      modalStatus.textContent = 'Fout: ' + e.message;
      modalStatus.className = 'status fail ml-8';
    } finally {
      modalSave.disabled = false;
    }
  }

  // ── Hulpfuncties ─────────────────────────────────────────────────────────
  function escHtml(str) {
    return String(str || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function getCsrf() {
    // Base template levert een verborgen veld met de token
    const el = document.getElementById('finding-csrf');
    if (el) return el.value;
    const meta = document.querySelector('meta[name="csrf-token"]');
    if (meta) return meta.getAttribute('content');
    return '';
  }

  // ── Init ─────────────────────────────────────────────────────────────────
  loadPresets();
})();
