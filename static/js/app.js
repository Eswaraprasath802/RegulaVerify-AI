document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('[data-toggle-password]').forEach((button) => {
    button.addEventListener('click', () => {
      const field = document.getElementById(button.dataset.togglePassword);
      if (!field) return;
      field.type = field.type === 'password' ? 'text' : 'password';
      button.textContent = field.type === 'password' ? 'Show' : 'Hide';
    });
  });

  const search = document.querySelector('[data-table-search]');
  if (search) {
    const table = document.getElementById(search.dataset.tableSearch);
    search.addEventListener('input', () => {
      const query = search.value.trim().toLocaleLowerCase();
      table?.querySelectorAll('[data-search-row]').forEach((row) => {
        row.hidden = !row.textContent.toLocaleLowerCase().includes(query);
      });
    });
  }

  const filter = document.querySelector('[data-filter-toggle]');
  filter?.addEventListener('click', () => {
    const table = document.getElementById(filter.dataset.filterToggle);
    const rows = [...(table?.querySelectorAll('[data-search-row]') || [])];
    const onlyOpen = filter.dataset.openOnly === 'true';
    rows.forEach((row) => {
      const isOpen = row.textContent.includes('Pending review') || row.textContent.includes('to review');
      row.hidden = !onlyOpen && !isOpen;
    });
    filter.dataset.openOnly = String(!onlyOpen);
    filter.classList.toggle('filter-active', !onlyOpen);
    filter.innerHTML = onlyOpen ? '<span>☷</span> Filter' : '<span>×</span> Open only';
  });

  const uploadList = document.getElementById('upload-list');
  document.getElementById('add-upload')?.addEventListener('click', () => {
    if (!uploadList || uploadList.querySelectorAll('.upload-row').length >= 10) return;
    const row = uploadList.querySelector('.upload-row')?.cloneNode(true);
    if (!row) return;
    row.querySelector('input[type="file"]').value = '';
    row.querySelector('select').selectedIndex = 0;
    row.querySelector('.file-label').innerHTML = '<b>Choose a file</b><small>PDF, PNG or JPG</small>';
    uploadList.appendChild(row);
  });

  uploadList?.addEventListener('click', (event) => {
    const remove = event.target.closest('.remove-upload');
    if (!remove) return;
    const rows = uploadList.querySelectorAll('.upload-row');
    if (rows.length > 1) remove.closest('.upload-row').remove();
  });

  uploadList?.addEventListener('change', (event) => {
    const input = event.target.closest('input[type="file"]');
    if (!input) return;
    const label = input.closest('.file-trigger')?.querySelector('.file-label');
    if (input.files?.[0] && label) {
      const file = input.files[0];
      label.innerHTML = `<b>${escapeHtml(file.name)}</b><small>${(file.size / 1024 / 1024).toFixed(2)} MB · ready</small>`;
      input.closest('.file-drop')?.classList.add('file-selected');
    }
  });

  const note = document.getElementById('note');
  const count = document.querySelector('[data-char-count="note"]');
  const updateCount = () => { if (note && count) count.textContent = `${note.value.length} / 1200`; };
  note?.addEventListener('input', updateCount);
  updateCount();
});

function escapeHtml(value) {
  return value.replace(/[&<>"']/g, (char) => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[char]));
}
