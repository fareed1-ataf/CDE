/* ═══════════════════════════════════════════════════════════════════ */
/*  CDE v4.0 — Enterprise Application Logic                            */
/*  Full Dynamic UI: Providers CRUD, Pipeline Control, Records Viewer  */
/* ═══════════════════════════════════════════════════════════════════ */

'use strict';

/* ─── STATE ─────────────────────────────────────────────────────────── */
const State = {
  isRunning:     false,
  currentJobId:  null,
  eventSource:   null,
  autoScroll:    true,
  logFilter:     'all',
  jobStartTime:  null,
  timerInterval: null,
  recPage:       1,
  recPageSize:   15,
  recSearch:     '',
  recTask:       '',
};

/* ─── TOAST NOTIFICATION SYSTEM ─────────────────────────────────────── */
function showToast(message, type = 'info', duration = 3500) {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;

  const icon = { success: '✅', error: '❌', warning: '⚠️', info: 'ℹ️' }[type] || 'ℹ️';
  toast.innerHTML = `<span>${icon}</span><span>${message}</span>`;
  container.appendChild(toast);

  const remove = () => {
    toast.classList.add('fade-out');
    setTimeout(() => toast.remove(), 320);
  };
  setTimeout(remove, duration);
}

/* ─── NAVIGATION ─────────────────────────────────────────────────────── */
const breadcrumbs = {
  'page-dash':      'Pipeline Execution',
  'page-records':   'Generated Records',
  'page-providers': 'LLM Provider Management',
  'page-config':    'Configuration',
  'page-export':    'Export Datasets',
};

document.querySelectorAll('.nav-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const target = btn.getAttribute('data-target');
    document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(target).classList.add('active');
    document.getElementById('page-title').textContent =
      btn.querySelector('.nav-label').textContent;
    document.getElementById('page-breadcrumb').textContent =
      breadcrumbs[target] || '';

    if (target === 'page-records') loadRecords();
  });
});

/* ─── GLOBAL STATS ───────────────────────────────────────────────────── */
async function refreshGlobalStats() {
  try {
    const res = await fetch('/api/v1/stats');
    if (!res.ok) return;
    const d = await res.json();
    document.getElementById('gs-ok').textContent     = (d.ok || 0).toLocaleString();
    document.getElementById('gs-files').textContent  = (d.files || 0).toLocaleString();
    document.getElementById('gs-chunks').textContent = (d.chunks || 0).toLocaleString();
    document.getElementById('records-badge').textContent = (d.alpaca_total || 0).toLocaleString();
  } catch {}
}

/* ─── HEALTH CHECK ───────────────────────────────────────────────────── */
async function checkHealth() {
  try {
    const res = await fetch('/api/v1/health');
    const pill    = document.getElementById('sb-engine-status');
    const badge   = document.getElementById('engine-status');
    if (res.ok) {
      pill.className  = 'engine-pill online';
      pill.textContent = '● Online';
      badge.className  = 'status-badge status-online';
      badge.textContent = 'Backend Connected';
      refreshGlobalStats();
    } else {
      setOffline(pill, badge);
    }
  } catch {
    const pill  = document.getElementById('sb-engine-status');
    const badge = document.getElementById('engine-status');
    setOffline(pill, badge);
  }
}

function setOffline(pill, badge) {
  pill.className  = 'engine-pill offline';
  pill.textContent = '● Offline';
  badge.className  = 'status-badge status-offline';
  badge.textContent = 'Backend Disconnected';
}

/* ─── FILE DROP ZONE ─────────────────────────────────────────────────── */
const dropZone    = document.getElementById('drop-zone');
const fileInput   = document.getElementById('file-input');
const fileChosen  = document.getElementById('file-chosen');
const fileChosenN = document.getElementById('file-chosen-name');

document.getElementById('drop-browse-btn').addEventListener('click', () => fileInput.click());
dropZone.addEventListener('click', () => fileInput.click());

dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
dropZone.addEventListener('drop', e => {
  e.preventDefault();
  dropZone.classList.remove('drag-over');
  if (e.dataTransfer.files.length) setFile(e.dataTransfer.files[0]);
});

fileInput.addEventListener('change', () => {
  if (fileInput.files.length) setFile(fileInput.files[0]);
});

document.getElementById('file-clear-btn').addEventListener('click', clearFile);

function setFile(f) {
  fileChosenN.textContent = f.name;
  fileChosen.style.display = 'flex';
  dropZone.style.display   = 'none';
}

function clearFile() {
  fileInput.value = '';
  fileChosen.style.display = 'none';
  dropZone.style.display   = 'block';
}

/* ─── AUTO-SCROLL TOGGLE ─────────────────────────────────────────────── */
document.getElementById('auto-scroll').addEventListener('change', e => {
  State.autoScroll = e.target.checked;
});

/* ─── LOG FILTERING ──────────────────────────────────────────────────── */
document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    State.logFilter = btn.getAttribute('data-filter');
    applyLogFilter();
  });
});

function applyLogFilter() {
  document.querySelectorAll('#terminal .log-line').forEach(line => {
    const f = State.logFilter;
    if (f === 'all') {
      line.classList.remove('hidden');
    } else {
      line.classList.toggle('hidden', !line.classList.contains(`log-${f}`));
    }
  });
}

document.getElementById('btn-clear-logs').addEventListener('click', () => {
  document.getElementById('terminal').innerHTML = '';
});

/* ─── LOG APPEND ─────────────────────────────────────────────────────── */
function appendLog(msg, type = 'info') {
  const term = document.getElementById('terminal');
  const div  = document.createElement('div');
  div.className = `log-line log-${type}`;
  if (State.logFilter !== 'all' && State.logFilter !== type) div.classList.add('hidden');

  // Timestamp prefix
  const now = new Date().toLocaleTimeString('en', { hour12: false });
  div.textContent = `[${now}] ${msg}`;
  term.appendChild(div);

  if (State.autoScroll) term.scrollTop = term.scrollHeight;
}

/* ─── PIPELINE ELAPSED TIMER ─────────────────────────────────────────── */
function startTimer() {
  State.jobStartTime = Date.now();
  State.timerInterval = setInterval(() => {
    const secs = Math.floor((Date.now() - State.jobStartTime) / 1000);
    document.getElementById('m-time').textContent =
      secs < 60 ? `${secs}s` : `${Math.floor(secs/60)}m ${secs%60}s`;
  }, 1000);
}

function stopTimer() {
  clearInterval(State.timerInterval);
  State.timerInterval = null;
}

/* ─── PIPELINE BUTTON STATE ──────────────────────────────────────────── */
function setPipelineRunning(running) {
  State.isRunning = running;
  const btnRun    = document.getElementById('btn-run');
  const btnCancel = document.getElementById('btn-cancel');

  if (running) {
    btnRun.querySelector('#btn-run-icon').textContent = '⏳';
    btnRun.querySelector('#btn-run-text').textContent = 'RUNNING…';
    btnRun.classList.add('btn-secondary');
    btnRun.classList.remove('btn-primary');
    btnRun.disabled = true;
    btnCancel.style.display = 'flex';
    document.getElementById('progress-area').style.display = 'block';
  } else {
    btnRun.querySelector('#btn-run-icon').textContent = '🚀';
    btnRun.querySelector('#btn-run-text').textContent = 'LAUNCH PIPELINE';
    btnRun.classList.add('btn-primary');
    btnRun.classList.remove('btn-secondary');
    btnRun.disabled = false;
    btnCancel.style.display = 'none';
  }
}

/* ─── PIPELINE LAUNCH ────────────────────────────────────────────────── */
document.getElementById('btn-run').addEventListener('click', async () => {
  if (State.isRunning) return;

  if (!fileInput.files.length) {
    showToast('Please select a file first', 'error');
    return;
  }

  const fd = new FormData();
  fd.append('file', fileInput.files[0]);
  fd.append('training_goal',    document.getElementById('cfg-training-goal').value);
  fd.append('routing_strategy', document.getElementById('cfg-strategy').value);
  fd.append('force_schema',     document.getElementById('cfg-schema').value);
  fd.append('chunk_size',       document.getElementById('cfg-chunk').value);
  fd.append('overlap',          document.getElementById('cfg-overlap').value);
  fd.append('min_quality',      document.getElementById('cfg-quality').value);
  fd.append('multi_schema',     document.getElementById('cfg-multi-schema').checked);
  fd.append('max_schemas',      document.getElementById('cfg-max-schemas').value);

  try {
    const res = await fetch('/api/v1/pipeline/run', { method: 'POST', body: fd });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Upload failed' }));
      showToast(err.detail || 'Upload failed', 'error');
      return;
    }

    const data = await res.json();
    State.currentJobId = data.job_id;

    // Reset metrics
    ['m-success','m-fail','m-time'].forEach(id => {
      document.getElementById(id).textContent =
        id === 'm-time' ? '0s' : '0';
    });
    document.getElementById('progress-bar').style.width = '0%';
    document.getElementById('prog-pct').textContent   = '0%';
    document.getElementById('prog-label').textContent = 'Initializing…';
    document.getElementById('prog-frac').textContent  = '0 / 0';
    document.getElementById('class-detail').style.display = 'none';

    // Show job ID badge
    const badge = document.getElementById('job-id-badge');
    badge.textContent = `Job: ${data.job_id.slice(0,8)}…`;
    badge.style.display = 'inline';

    document.getElementById('terminal').innerHTML = '';
    setPipelineRunning(true);
    startTimer();
    startSSE(data.job_id);

    const sdot = document.getElementById('status-dot');
    sdot.className = 'sdot running';
    document.getElementById('status-txt').textContent = 'Processing…';

    showToast(`Pipeline started — Job ${data.job_id.slice(0,8)}…`, 'success');

  } catch (err) {
    showToast('Network error during upload', 'error');
  }
});

/* ─── PIPELINE CANCEL ────────────────────────────────────────────────── */
document.getElementById('btn-cancel').addEventListener('click', async () => {
  if (!State.currentJobId) return;
  try {
    await fetch(`/api/v1/pipeline/cancel/${State.currentJobId}`, { method: 'POST' });
    showToast('Cancellation requested…', 'warning');
    appendLog('⛔ Cancel requested by user.', 'warn');
  } catch {
    showToast('Failed to send cancel signal', 'error');
  }
});

/* ─── SSE STREAMING ──────────────────────────────────────────────────── */

// Keepalive pulse — shows the stream is alive even between slow LLM calls
let _keepalivePulse = null;
function _resetKeepalivePulse() {
  clearTimeout(_keepalivePulse);
  // If no SSE message arrives in 5s, show a "waiting for LLM..." pulse in the log label
  _keepalivePulse = setTimeout(() => {
    if (State.isRunning) {
      const label = document.getElementById('prog-label');
      if (label) {
        const dots = (label.dataset.dots | 0) % 3 + 1;
        label.dataset.dots = dots;
        label.textContent = `⏳ Waiting for LLM${'…'.slice(0, dots)}`;
      }
      _resetKeepalivePulse(); // keep pulsing
    }
  }, 5000);
}

function startSSE(jobId) {
  if (State.eventSource) State.eventSource.close();
  State.eventSource = new EventSource(`/api/v1/pipeline/stream/${jobId}`);

  State.eventSource.onmessage = e => {
    // Any message (including keepalive comment lines) resets the pulse timer
    _resetKeepalivePulse();
    // Keepalive lines from backend start with ":" — EventSource fires them as empty data
    if (!e.data || e.data.trim() === '') return;
    try {
      const data = JSON.parse(e.data);
      handleSSEEvent(data, jobId);
    } catch {}
  };

  State.eventSource.onerror = () => {
    // Only treat as error if we're still supposed to be running
    if (State.isRunning) {
      appendLog('⚠️ Stream interrupted — backend may be busy or restarting.', 'warn');
      finishJob('error');
    }
  };

  _resetKeepalivePulse();
}

function handleSSEEvent(data, jobId) {
  switch (data.type) {
    case 'log': {
      let lType = 'info';
      if (data.level === 'ERROR')   lType = 'error';
      if (data.level === 'WARNING') lType = 'warn';
      if (data.message?.includes('✓') || data.message?.includes('SUCCESS') ||
          data.message?.includes('done') || data.message?.includes('complete')) lType = 'success';
      appendLog(data.message, lType);
      break;
    }
    case 'progress': {
      const pct = Math.round((data.progress || 0) * 100);
      document.getElementById('progress-bar').style.width = `${pct}%`;
      document.getElementById('prog-pct').textContent     = `${pct}%`;
      document.getElementById('prog-frac').textContent    =
        `${data.chunk || 0} / ${data.total || 0}`;
      document.getElementById('prog-label').textContent   =
        data.file ? `Processing: ${data.file}` : 'Processing…';
      if (data.schema) {
        document.getElementById('d-schema').textContent  = data.schema;
        document.getElementById('class-detail').style.display = 'grid';
      }
      break;
    }
    case 'classification': {
      document.getElementById('d-schema').textContent = data.schema || '–';
      document.getElementById('d-task').textContent   = data.task_type || '–';
      document.getElementById('d-conf').textContent   =
        data.confidence ? `${Math.round(data.confidence * 100)}%` : '–';
      document.getElementById('class-detail').style.display = 'grid';
      appendLog(`📊 Classified: ${data.schema} (${Math.round((data.confidence||0)*100)}% conf, ${data.chunks} chunks)`, 'info');
      break;
    }
    case 'record': {
      const ok = parseInt(document.getElementById('m-success').textContent) || 0;
      document.getElementById('m-success').textContent = ok + (data.count || 1);
      document.getElementById('d-provider').textContent = data.provider || '–';
      break;
    }
    case 'warning': {
      appendLog(`⚠️ ${data.message}`, 'warn');
      break;
    }
    case 'status': {
      appendLog(`ℹ️ ${data.message}`, 'info');
      break;
    }
    case 'error': {
      appendLog(`❌ Error: ${data.message}`, 'error');
      const fail = parseInt(document.getElementById('m-fail').textContent) || 0;
      document.getElementById('m-fail').textContent = fail + 1;
      finishJob('error');
      break;
    }
    case 'complete': {
      const msg = data.message || `✅ Done — ${data.records_ok || 0} records generated.`;
      appendLog(msg, 'success');
      showToast(msg, 'success', 5000);
      refreshGlobalStats();
      finishJob('complete');
      break;
    }
    case 'cancelled': {
      appendLog(data.message || '⛔ Pipeline cancelled.', 'warn');
      finishJob('cancelled');
      break;
    }
    case 'done':
      finishJob('complete');
      break;
  }
}

function finishJob(state) {
  clearTimeout(_keepalivePulse);
  if (State.eventSource) { State.eventSource.close(); State.eventSource = null; }
  setPipelineRunning(false);
  stopTimer();
  State.currentJobId = null;

  // Reset progress label
  const label = document.getElementById('prog-label');
  if (label) { label.textContent = ''; label.dataset.dots = 0; }

  const sdot = document.getElementById('status-dot');
  const stxt = document.getElementById('status-txt');
  const stateMap = {
    complete:  ['sdot idle',      'Completed ✓'],
    cancelled: ['sdot cancelled', 'Cancelled'],
    error:     ['sdot err',       'Error'],
  };
  const [cls, txt] = stateMap[state] || ['sdot idle', 'Done'];
  sdot.className   = cls;
  stxt.textContent = txt;

  // Refresh stats after job ends
  refreshGlobalStats();
}

/* ─── PING BUTTON ────────────────────────────────────────────────────── */
document.getElementById('btn-ping').addEventListener('click', pingProviders);

async function pingProviders() {
  showToast('Pinging all providers…', 'info', 2000);
  try {
    const res  = await fetch('/api/v1/providers/ping', { method: 'POST' });
    const data = await res.json();
    // Update ping badges if provider page is visible
    Object.entries(data).forEach(([name, ok]) => {
      const card = document.querySelector(`.prov-card[data-name="${CSS.escape(name)}"]`);
      if (!card) return;
      let badge = card.querySelector('.prov-ping-badge');
      if (!badge) {
        badge = document.createElement('span');
        badge.className = 'prov-ping-badge';
        card.querySelector('.prov-card-actions').prepend(badge);
      }
      badge.className = `prov-ping-badge ${ok ? 'ok' : 'error'}`;
      badge.textContent = ok ? '✓ Online' : '✗ Offline';
    });
    showToast('Ping complete', 'success');
  } catch {
    showToast('Ping failed — backend unreachable', 'error');
  }
}

/* ─── PROVIDERS ──────────────────────────────────────────────────────── */

/** Load and render the provider grid — uses event delegation (no inline onclick) */
async function loadProviders() {
  try {
    const res = await fetch('/api/v1/providers');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const providers = await res.json();
    const list = document.getElementById('prov-list');

    document.getElementById('prov-badge').textContent = Array.isArray(providers)
      ? providers.length : 0;

    if (!Array.isArray(providers) || providers.length === 0) {
      list.innerHTML = '<div class="prov-empty">No providers configured. Click "Add Provider" to get started.</div>';
      return;
    }

    list.innerHTML = '';
    providers.forEach(p => {
      const card = document.createElement('div');
      card.className = 'prov-card';
      // Store name in data attribute — NO inline onclick (avoids quote-escaping bugs)
      card.dataset.name = p.name;
      card.innerHTML = `
        <div class="prov-card-header">
          <div class="prov-name">
            <span class="prov-status-dot ${p.enabled ? 'enabled' : 'disabled'}"></span>
            ${escapeHtml(p.name)}
          </div>
          <span class="prov-type-badge">${escapeHtml(p.provider_type)}</span>
        </div>
        <div class="prov-card-body">
          <div class="prov-row"><span class="prov-row-lbl">Model</span><span class="prov-row-val">${escapeHtml(p.model)}</span></div>
          <div class="prov-row"><span class="prov-row-lbl">Endpoint</span><span class="prov-row-val">${escapeHtml(p.endpoint)}</span></div>
          <div class="prov-row"><span class="prov-row-lbl">Temp / Tokens</span><span class="prov-row-val">${p.temperature} / ${p.max_tokens}</span></div>
          <div class="prov-row"><span class="prov-row-lbl">Status</span><span class="prov-row-val" style="color:${p.enabled ? 'var(--success)' : 'var(--text-muted)'}">${p.enabled ? '● Enabled' : '○ Disabled'}</span></div>
        </div>
        <div class="prov-card-actions">
          <button class="btn btn-ghost btn-sm prov-edit-btn" data-pname="${escapeAttr(p.name)}">✏️ Edit</button>
          <button class="btn btn-danger btn-sm prov-del-btn"  data-pname="${escapeAttr(p.name)}">🗑️ Delete</button>
        </div>
      `;

      // Attach listeners directly — 100% reliable, no quote issues
      card.querySelector('.prov-edit-btn').addEventListener('click', () => openEditModal(p.name));
      card.querySelector('.prov-del-btn').addEventListener('click',  () => confirmDeleteProvider(p.name));

      list.appendChild(card);
    });
  } catch (err) {
    console.error('Failed to load providers:', err);
    showToast('Failed to load providers — is the backend running?', 'error');
  }
}

/* ── ADD PROVIDER MODAL ──── */
document.getElementById('btn-open-add-modal').addEventListener('click', () => openAddModal());

function openAddModal() {
  document.getElementById('modal-title').textContent   = 'Add New Provider';
  document.getElementById('modal-save-btn').textContent = 'Add Provider';
  document.getElementById('modal-edit-original-name').value = '';
  // Clear form
  ['modal-name','modal-endpoint','modal-model','modal-key'].forEach(id => {
    document.getElementById(id).value = '';
  });
  document.getElementById('modal-type').value        = 'openai_compatible';
  document.getElementById('modal-temperature').value = '0.15';
  document.getElementById('modal-max-tokens').value  = '3000';
  document.getElementById('modal-timeout').value     = '180';
  document.getElementById('modal-enabled').checked   = true;
  openModal('provider-modal');
}

function openEditModal(name) {
  fetch('/api/v1/providers').then(r => r.json()).then(providers => {
    const p = providers.find(x => x.name === name);
    if (!p) { showToast('Provider not found', 'error'); return; }

    document.getElementById('modal-title').textContent   = `Edit: ${p.name}`;
    document.getElementById('modal-save-btn').textContent = 'Update Provider';
    document.getElementById('modal-edit-original-name').value = p.name;
    document.getElementById('modal-name').value        = p.name;
    document.getElementById('modal-type').value        = p.provider_type;
    document.getElementById('modal-endpoint').value   = p.endpoint;
    document.getElementById('modal-model').value       = p.model;
    document.getElementById('modal-temperature').value = p.temperature;
    document.getElementById('modal-max-tokens').value  = p.max_tokens;
    document.getElementById('modal-timeout').value     = p.timeout || 180;
    document.getElementById('modal-key').value         = '';  // Never pre-fill API key
    document.getElementById('modal-enabled').checked   = p.enabled;
    openModal('provider-modal');
  }).catch(() => showToast('Failed to load provider data', 'error'));
}

/* ── MODAL SAVE ── */
document.getElementById('modal-save-btn').addEventListener('click', async () => {
  const originalName = document.getElementById('modal-edit-original-name').value;
  const isEdit = !!originalName;

  const payload = {
    name:          document.getElementById('modal-name').value.trim(),
    provider_type: document.getElementById('modal-type').value,
    endpoint:      document.getElementById('modal-endpoint').value.trim(),
    model:         document.getElementById('modal-model').value.trim(),
    api_key:       document.getElementById('modal-key').value,
    temperature:   parseFloat(document.getElementById('modal-temperature').value),
    max_tokens:    parseInt(document.getElementById('modal-max-tokens').value),
    timeout:       parseInt(document.getElementById('modal-timeout').value),
    max_retries:   3,
    enabled:       document.getElementById('modal-enabled').checked,
    preferred_schemas: [],
  };

  if (!payload.name || !payload.endpoint || !payload.model) {
    showToast('Name, Endpoint, and Model are required.', 'error');
    return;
  }

  const btn = document.getElementById('modal-save-btn');
  btn.disabled = true;
  btn.textContent = isEdit ? 'Updating…' : 'Adding…';

  try {
    const url    = isEdit ? `/api/v1/providers/${encodeURIComponent(originalName)}` : '/api/v1/providers';
    const method = isEdit ? 'PUT' : 'POST';
    const res    = await fetch(url, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (res.ok) {
      showToast(isEdit ? 'Provider updated successfully' : 'Provider added successfully', 'success');
      closeModal('provider-modal');
      loadProviders();
    } else {
      const err = await res.json().catch(() => ({ detail: 'Unknown error' }));
      showToast(err.detail || 'Failed to save provider', 'error');
    }
  } catch {
    showToast('Network error', 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = isEdit ? 'Update Provider' : 'Add Provider';
  }
});

/* ── CONFIRM DELETE ── */
function confirmDeleteProvider(name) {
  document.getElementById('confirm-message').textContent =
    `Are you sure you want to delete the provider "${name}"? This action cannot be undone.`;
  document.getElementById('confirm-ok-btn').onclick = () => deleteProvider(name);
  openModal('confirm-modal');
}

async function deleteProvider(name) {
  try {
    const res = await fetch(`/api/v1/providers/${encodeURIComponent(name)}`, { method: 'DELETE' });
    if (res.ok) {
      showToast('Provider deleted.', 'success');
      closeModal('confirm-modal');
      loadProviders();
    } else {
      const err = await res.json().catch(() => ({ detail: 'Delete failed' }));
      showToast(err.detail || 'Failed to delete provider', 'error');
    }
  } catch {
    showToast('Network error', 'error');
  }
}

/* ── PING ALL BUTTON (providers page) ── */
document.getElementById('btn-ping-all').addEventListener('click', async () => {
  // Briefly show pinging state on all cards
  document.querySelectorAll('.prov-card').forEach(card => {
    let badge = card.querySelector('.prov-ping-badge');
    if (!badge) {
      badge = document.createElement('span');
      badge.className = 'prov-ping-badge pinging';
      card.querySelector('.prov-card-actions').prepend(badge);
    }
    badge.className = 'prov-ping-badge pinging';
    badge.textContent = '…';
  });
  await pingProviders();
});

/* ─── MODAL HELPERS ─────────────────────────────────────────────────── */
function openModal(id)  { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }

// Close buttons
['modal-close-btn','modal-cancel-btn'].forEach(id => {
  document.getElementById(id)?.addEventListener('click', () => closeModal('provider-modal'));
});
['confirm-close-btn','confirm-cancel-btn'].forEach(id => {
  document.getElementById(id)?.addEventListener('click', () => closeModal('confirm-modal'));
});

// Click overlay to close
['provider-modal','confirm-modal'].forEach(id => {
  document.getElementById(id).addEventListener('click', e => {
    if (e.target === e.currentTarget) closeModal(id);
  });
});

// ESC to close
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    closeModal('provider-modal');
    closeModal('confirm-modal');
  }
});

/* ─── SETTINGS ──────────────────────────────────────────────────────── */
function loadSettings() {
  try {
    const saved = JSON.parse(localStorage.getItem('cde_config') || '{}');
    if (saved.routing_strategy) document.getElementById('s-strategy').value    = saved.routing_strategy;
    if (saved.quality_threshold !== undefined) document.getElementById('s-quality').value = saved.quality_threshold;
    if (saved.chunk_size)        document.getElementById('s-chunk').value       = saved.chunk_size;
    if (saved.chunk_overlap)     document.getElementById('s-overlap').value     = saved.chunk_overlap;
    if (saved.max_schemas)       document.getElementById('s-max-schemas').value = saved.max_schemas;

    // Also populate pipeline form
    if (saved.routing_strategy) document.getElementById('cfg-strategy').value = saved.routing_strategy;
    if (saved.quality_threshold !== undefined) document.getElementById('cfg-quality').value = saved.quality_threshold;
    if (saved.chunk_size)        document.getElementById('cfg-chunk').value    = saved.chunk_size;
    if (saved.chunk_overlap)     document.getElementById('cfg-overlap').value  = saved.chunk_overlap;
    if (saved.max_schemas)       document.getElementById('cfg-max-schemas').value = saved.max_schemas;
  } catch {}
}

window.saveSettings = function() {
  const payload = {
    routing_strategy:  document.getElementById('s-strategy').value,
    quality_threshold: parseFloat(document.getElementById('s-quality').value),
    chunk_size:        parseInt(document.getElementById('s-chunk').value),
    chunk_overlap:     parseInt(document.getElementById('s-overlap').value),
    max_schemas:       parseInt(document.getElementById('s-max-schemas').value),
  };
  try {
    localStorage.setItem('cde_config', JSON.stringify(payload));
    showToast('Settings saved.', 'success');
  } catch {
    showToast('Failed to save settings.', 'error');
  }
};

/* ─── CACHE CLEAR ────────────────────────────────────────────────────── */
document.getElementById('btn-clear-cache').addEventListener('click', async () => {
  try {
    const res = await fetch('/api/v1/cache/clear', { method: 'POST' });
    if (res.ok) showToast('File cache cleared.', 'success');
    else showToast('Failed to clear cache.', 'error');
  } catch {
    showToast('Network error.', 'error');
  }
});

/* ─── RECORDS VIEWER ────────────────────────────────────────────────── */
async function loadRecords() {
  const search   = document.getElementById('rec-search').value;
  const taskType = document.getElementById('rec-task-filter').value;
  const params   = new URLSearchParams({
    page:      State.recPage,
    page_size: State.recPageSize,
    search,
    task_type: taskType,
  });

  try {
    const res  = await fetch(`/api/v1/records?${params}`);
    const data = await res.json();
    renderRecords(data);
  } catch {
    showToast('Failed to load records', 'error');
  }
}

function renderRecords(data) {
  const list   = document.getElementById('records-list');
  const pagDiv = document.getElementById('rec-pagination');
  const totLbl = document.getElementById('rec-total-lbl');

  totLbl.textContent = `${(data.total || 0).toLocaleString()} records found`;

  if (!data.records || data.records.length === 0) {
    list.innerHTML = '<div class="prov-empty">No records yet. Run the pipeline on a file to generate training data.</div>';
    pagDiv.innerHTML = '';
    return;
  }

  list.innerHTML = '';
  data.records.forEach(rec => {
    const card = document.createElement('div');
    card.className = 'record-card';
    const schema  = rec.schema_type || rec.task_type || 'unknown';
    const qual    = rec.quality_score != null ? `Q: ${(rec.quality_score * 100).toFixed(0)}%` : '';
    const instr   = rec.instruction || rec.prompt || '';
    const output  = rec.output || rec.response || '';

    card.innerHTML = `
      <div class="record-card-header">
        <span class="record-schema-tag">${escapeHtml(schema)}</span>
        ${qual ? `<span class="record-quality">${qual}</span>` : ''}
      </div>
      <div class="record-instruction">${escapeHtml(instr)}</div>
      <div class="record-output">${escapeHtml(output)}</div>
    `;
    list.appendChild(card);
  });

  // Pagination
  const totalPages = Math.ceil(data.total / data.page_size);
  pagDiv.innerHTML = '';

  const prevBtn = document.createElement('button');
  prevBtn.className = 'page-btn';
  prevBtn.textContent = '← Prev';
  prevBtn.disabled = State.recPage <= 1;
  prevBtn.addEventListener('click', () => { State.recPage--; loadRecords(); });
  pagDiv.appendChild(prevBtn);

  // Page numbers
  const start = Math.max(1, State.recPage - 2);
  const end   = Math.min(totalPages, start + 4);
  for (let i = start; i <= end; i++) {
    const btn = document.createElement('button');
    btn.className = `page-btn${i === State.recPage ? ' active' : ''}`;
    btn.textContent = i;
    btn.addEventListener('click', () => { State.recPage = i; loadRecords(); });
    pagDiv.appendChild(btn);
  }

  const nextBtn = document.createElement('button');
  nextBtn.className = 'page-btn';
  nextBtn.textContent = 'Next →';
  nextBtn.disabled = State.recPage >= totalPages;
  nextBtn.addEventListener('click', () => { State.recPage++; loadRecords(); });
  pagDiv.appendChild(nextBtn);
}

document.getElementById('btn-load-records').addEventListener('click', () => {
  State.recPage  = 1;
  State.recSearch = document.getElementById('rec-search').value;
  State.recTask  = document.getElementById('rec-task-filter').value;
  loadRecords();
});

document.getElementById('rec-search').addEventListener('keydown', e => {
  if (e.key === 'Enter') { State.recPage = 1; loadRecords(); }
});

/* ─── EXPORT BUTTONS ────────────────────────────────────────────────── */
document.getElementById('btn-exp-alpaca').addEventListener('click', () => {
  const neg  = document.getElementById('exp-neg-alpaca').checked;
  const mit  = document.getElementById('exp-mitre-alpaca').checked;
  const curr = document.getElementById('exp-curr-alpaca').checked;
  window.open(`/api/v1/export/alpaca?add_negatives=${neg}&run_mitre_val=${mit}&apply_curriculum=${curr}`, '_blank');
});

document.getElementById('btn-exp-llama').addEventListener('click', () => {
  const neg  = document.getElementById('exp-neg-llama').checked;
  const curr = document.getElementById('exp-curr-llama').checked;
  window.open(`/api/v1/export/llama3?add_negatives=${neg}&apply_curriculum=${curr}`, '_blank');
});

/* ─── UTILITY ───────────────────────────────────────────────────────── */

/** Escape for HTML text content */
function escapeHtml(str) {
  if (typeof str !== 'string') return String(str ?? '');
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
            .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

/** Escape for HTML attribute values (double-quoted) */
function escapeAttr(str) {
  if (typeof str !== 'string') return String(str ?? '');
  return str.replace(/&/g,'&amp;').replace(/"/g,'&quot;');
}

/* ─── INIT ──────────────────────────────────────────────────────────── */
window.addEventListener('DOMContentLoaded', () => {
  loadSettings();
  loadProviders();
  checkHealth();

  // Periodically refresh health & stats every 30s
  setInterval(checkHealth, 30_000);
  setInterval(refreshGlobalStats, 60_000);
});
