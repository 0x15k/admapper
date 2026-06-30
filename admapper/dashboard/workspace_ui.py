"""Workspace setup modal — create, open, and rename engagements."""

WORKSPACE_UI_CSS = r"""
.workspace-overlay{
  position:fixed;inset:0;z-index:9000;background:rgba(0,0,0,0.72);
  display:flex;align-items:center;justify-content:center;padding:1rem;
}
.workspace-overlay.hidden{display:none;}
.workspace-modal{
  background:var(--panel);border:1px solid var(--border-light);border-radius:10px;
  width:min(420px,100%);padding:1.25rem 1.35rem;box-shadow:0 12px 40px rgba(0,0,0,0.55);
}
.workspace-modal h2{margin:0 0 0.35rem;font-size:0.95rem;color:var(--text);}
.workspace-modal .ws-sub{font-size:0.68rem;color:var(--text-dim);margin-bottom:1rem;line-height:1.4;}
.workspace-modal label{display:block;font-size:0.62rem;color:var(--text-muted);margin:0.55rem 0 0.2rem;}
.workspace-modal input,.workspace-modal select{
  width:100%;box-sizing:border-box;background:var(--bg);border:1px solid var(--border);
  color:var(--text);border-radius:5px;padding:0.45rem 0.55rem;font-size:0.75rem;
}
.workspace-modal .ws-actions{display:flex;gap:0.5rem;margin-top:1rem;flex-wrap:wrap;}
.workspace-modal .ws-actions button{
  flex:1;min-width:7rem;padding:0.45rem 0.65rem;border-radius:5px;border:none;
  font-size:0.72rem;font-weight:600;cursor:pointer;
}
.workspace-modal .ws-primary{background:var(--accent);color:#111;}
.workspace-modal .ws-secondary{background:var(--bg);color:var(--text);border:1px solid var(--border)!important;}
.workspace-modal .ws-error{font-size:0.65rem;color:var(--danger);margin-top:0.5rem;min-height:1rem;}
#h-workspace,#h-dc{cursor:pointer;border-bottom:1px dashed rgba(255,255,255,0.25);}
#h-workspace:hover,#h-dc:hover{color:var(--accent-glow);}
.header-inline-input{
  background:var(--bg-dark);border:1px solid var(--accent);color:var(--text);
  font-size:0.8rem;font-weight:600;padding:0.1rem 0.35rem;border-radius:3px;
  min-width:6rem;max-width:12rem;font-family:inherit;
}
"""

WORKSPACE_MODAL_HTML = r"""
<div class="workspace-overlay hidden" id="workspace-overlay">
  <div class="workspace-modal" role="dialog" aria-labelledby="ws-modal-title">
    <h2 id="ws-modal-title">Workspace</h2>
    <p class="ws-sub" id="ws-modal-sub">Name this engagement (e.g. corp-internal, prod-forest) — not the target IP.</p>
    <label for="ws-name-input">Workspace name</label>
    <input id="ws-name-input" type="text" placeholder="corp-internal" autocomplete="off" spellcheck="false"/>
    <label for="ws-dc-input">Target DC IP (optional)</label>
    <input id="ws-dc-input" type="text" placeholder="192.168.10.10" autocomplete="off"/>
    <div id="ws-open-row" style="display:none;">
      <label for="ws-open-select">Or open existing</label>
      <select id="ws-open-select"><option value="">— select —</option></select>
    </div>
    <div class="ws-error" id="ws-error"></div>
    <div class="ws-actions">
      <button type="button" class="ws-primary" id="ws-create-btn">Create / Open</button>
      <button type="button" class="ws-secondary" id="ws-cancel-btn" style="display:none;">Cancel</button>
    </div>
  </div>
</div>
"""

WORKSPACE_UI_JS = r"""
function showWorkspaceModal(force) {
  const overlay = document.getElementById('workspace-overlay');
  if (!overlay) return;
  const cancel = document.getElementById('ws-cancel-btn');
  const openRow = document.getElementById('ws-open-row');
  const sub = document.getElementById('ws-modal-sub');
  const title = document.getElementById('ws-modal-title');
  if (force) {
    overlay.classList.remove('hidden');
    if (cancel) cancel.style.display = 'none';
    if (openRow) openRow.style.display = '';
    if (title) title.textContent = 'Create or open workspace';
    if (sub) sub.textContent = 'Name this engagement (e.g. corp-internal, prod-forest) — not the target IP.';
    populateWorkspaceSelect(state && state.available_workspaces);
    const dc = (typeof WorkspaceVars !== 'undefined' ? WorkspaceVars.get().DC_IP : '') ||
      (state && state.meta && state.meta.dc_ip) || '';
    const dcInp = document.getElementById('ws-dc-input');
    if (dcInp && dc && !dcInp.value) dcInp.value = dc;
  } else {
    overlay.classList.add('hidden');
  }
}

function showWorkspaceRenameModal() {
  const overlay = document.getElementById('workspace-overlay');
  if (!overlay || !state || state.workspace_required) return;
  overlay.classList.remove('hidden');
  const cancel = document.getElementById('ws-cancel-btn');
  const openRow = document.getElementById('ws-open-row');
  const sub = document.getElementById('ws-modal-sub');
  const title = document.getElementById('ws-modal-title');
  const nameInp = document.getElementById('ws-name-input');
  if (cancel) cancel.style.display = '';
  if (openRow) openRow.style.display = 'none';
  if (title) title.textContent = 'Rename workspace';
  if (sub) sub.textContent = 'Change the engagement folder name on disk.';
  if (nameInp && state.meta && state.meta.workspace) nameInp.value = state.meta.workspace;
  setWorkspaceError('');
}

function populateWorkspaceSelect(names) {
  const sel = document.getElementById('ws-open-select');
  if (!sel) return;
  const current = sel.value;
  sel.innerHTML = '<option value="">— select —</option>';
  (names || []).forEach(function (n) {
    const opt = document.createElement('option');
    opt.value = n;
    opt.textContent = n;
    sel.appendChild(opt);
  });
  if (current) sel.value = current;
}

function setWorkspaceError(msg) {
  const el = document.getElementById('ws-error');
  if (el) el.textContent = msg || '';
}

function submitWorkspaceModal() {
  const nameInp = document.getElementById('ws-name-input');
  const dcInp = document.getElementById('ws-dc-input');
  const sel = document.getElementById('ws-open-select');
  const name = (nameInp && nameInp.value || '').trim();
  const dc = (dcInp && dcInp.value || '').trim();
  const existing = (sel && sel.value || '').trim();
  setWorkspaceError('');

  if (state && !state.workspace_required && document.getElementById('ws-modal-title') &&
      document.getElementById('ws-modal-title').textContent === 'Rename workspace') {
    if (!name) { setWorkspaceError('Enter a workspace name'); return; }
    if (name === (state.meta && state.meta.workspace)) {
      showWorkspaceModal(false);
      return;
    }
    fetch('/api/workspace/rename', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: name })
    }).then(function (r) { return r.json(); }).then(function (data) {
      if (data.error) { setWorkspaceError(data.error); return; }
      showWorkspaceModal(false);
      if (data.state && typeof renderState === 'function') renderState(data.state);
    }).catch(function () { setWorkspaceError('Rename failed'); });
    return;
  }

  if (existing && !name) {
    fetch('/api/workspace/open', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: existing })
    }).then(function (r) { return r.json(); }).then(function (data) {
      if (data.error) { setWorkspaceError(data.error); return; }
      showWorkspaceModal(false);
      if (data.state && typeof renderState === 'function') renderState(data.state);
    }).catch(function () { setWorkspaceError('Open failed'); });
    return;
  }

  if (!name) { setWorkspaceError('Enter a workspace name'); return; }
  const body = { name: name };
  if (dc) body.dc_ip = dc;
  fetch('/api/workspace/create', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  }).then(function (r) { return r.json(); }).then(function (data) {
    if (data.error) { setWorkspaceError(data.error); return; }
    showWorkspaceModal(false);
    if (data.state && typeof renderState === 'function') renderState(data.state);
  }).catch(function () { setWorkspaceError('Create failed'); });
}

function bindWorkspaceModal() {
  const btn = document.getElementById('ws-create-btn');
  const cancel = document.getElementById('ws-cancel-btn');
  if (btn && !btn.dataset.bound) {
    btn.dataset.bound = '1';
    btn.addEventListener('click', submitWorkspaceModal);
  }
  if (cancel && !cancel.dataset.bound) {
    cancel.dataset.bound = '1';
    cancel.addEventListener('click', function () { showWorkspaceModal(false); });
  }
  const nameInp = document.getElementById('ws-name-input');
  if (nameInp && !nameInp.dataset.bound) {
    nameInp.dataset.bound = '1';
    nameInp.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') submitWorkspaceModal();
    });
  }
}
"""
