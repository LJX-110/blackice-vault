const LS_SALT = 'kv.salt';
const LS_VAULT = 'kv.vault';
const LS_SETTINGS = 'kv.settings';
const LS_COLLAPSED = 'kv.collapsed';
const PBKDF2_ITERATIONS = 100000;

const $ = (id) => document.getElementById(id);

let providers = [];
let cryptoKey = null;
let isSetup = false;
let toastTimer = null;
let idleTimer = null;
let editingProviderId = null;
let editingKey = null;
let editingModel = null;
let dragItem = null;
const visibleKeys = new Set();
const collapsedSet = new Set();

const lockScreen = $('lock-screen');
const appScreen = $('app');
const lockForm = $('lock-form');
const lockPassword = $('lock-password');
const lockConfirmWrap = $('lock-confirm-wrap');
const lockConfirm = $('lock-confirm');
const lockBtn = $('lock-btn');
const lockError = $('lock-error');
const lockHint = $('lock-hint');

const searchInput = $('search-input');
const grid = $('grid');
const emptyState = $('empty-state');
const emptyText = $('empty-text');
const countEl = $('count');
const toggleAllBtn = $('toggle-all-btn');
const collapseAllBtn = $('collapse-all-btn');

const providerModal = $('provider-modal');
const providerForm = $('provider-form');
const providerModalTitle = $('provider-modal-title');
const pName = $('p-name');
const pUrl = $('p-url');
const pNotes = $('p-notes');

const keyModal = $('key-modal');
const keyForm = $('key-form');
const keyModalTitle = $('key-modal-title');
const kProvider = $('k-provider');
const kLabel = $('k-label');
const kKey = $('k-key');
const kNotes = $('k-notes');

const modelModal = $('model-modal');
const modelForm = $('model-form');
const modelModalTitle = $('model-modal-title');
const mProvider = $('m-provider');
const mName = $('m-name');
const mNotes = $('m-notes');

const backupModal = $('backup-modal');
const autoLock = $('auto-lock');
const importFile = $('import-file');

const pwdModal = $('pwd-modal');
const pwdForm = $('pwd-form');
const pOld = $('p-old');
const pNew = $('p-new');
const pConfirm = $('p-confirm');

const toastEl = $('toast');

function b64encode(buf) {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

function b64decode(str) {
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes;
}

function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

function maskKey(key) {
  if (!key) return '';
  return key.length > 6 ? key.slice(0, 4) + '••••••••' : '••••••••';
}

function normalizeUrl(url) {
  const t = (url || '').trim();
  if (!t) return '';
  return /^https?:\/\//i.test(t) ? t : 'https://' + t;
}

function genId() {
  return Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8);
}

async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const base = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptVault() {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new TextEncoder().encode(JSON.stringify({ version: 2, providers }));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, data);
  localStorage.setItem(LS_VAULT, JSON.stringify({ iv: b64encode(iv), ct: b64encode(ct) }));
}

async function decryptVault(vault, key) {
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64decode(vault.iv) },
    key,
    b64decode(vault.ct)
  );
  return JSON.parse(new TextDecoder().decode(plain));
}

function hasVault() {
  return !!localStorage.getItem(LS_SALT);
}

function currentSalt() {
  return b64decode(localStorage.getItem(LS_SALT));
}

function migrateData(raw) {
  if (Array.isArray(raw)) {
    return raw.map((e) => ({
      id: e.id || genId(),
      name: e.name || '未命名',
      url: e.url || '',
      notes: e.notes || '',
      keys: e.key
        ? [{ id: genId(), label: '', key: e.key, notes: '' }]
        : [],
      models: e.model
        ? [{ id: genId(), name: e.model, notes: '' }]
        : []
    }));
  }
  if (raw && Array.isArray(raw.providers)) {
    return raw.providers.map((p) => ({
      id: p.id || genId(),
      name: p.name || '未命名',
      url: p.url || '',
      notes: p.notes || '',
      keys: Array.isArray(p.keys) ? p.keys : [],
      models: Array.isArray(p.models) ? p.models : []
    }));
  }
  return [];
}

function getSettings() {
  try {
    return JSON.parse(localStorage.getItem(LS_SETTINGS) || '{}');
  } catch {
    return {};
  }
}

function saveSettings(s) {
  localStorage.setItem(LS_SETTINGS, JSON.stringify(s));
}

function loadCollapsed() {
  collapsedSet.clear();
  try {
    const list = JSON.parse(localStorage.getItem(LS_COLLAPSED) || '[]');
    if (Array.isArray(list)) list.forEach((id) => collapsedSet.add(id));
  } catch {}
}

function saveCollapsed() {
  localStorage.setItem(LS_COLLAPSED, JSON.stringify([...collapsedSet]));
}

function updateLockScreen() {
  isSetup = !hasVault();
  lockHint.textContent = isSetup
    ? '首次使用，设置一个主密码来加密保护你的密钥，请务必牢记'
    : '输入主密码，开启玉函';
  lockBtn.textContent = isSetup ? '创建并解锁' : '解锁';
  lockConfirmWrap.classList.toggle('hidden', !isSetup);
  lockError.classList.add('hidden');
}

async function handleUnlock(e) {
  e.preventDefault();
  lockError.classList.add('hidden');
  const pw = lockPassword.value;
  if (!pw) {
    lockError.textContent = '请输入密码';
    lockError.classList.remove('hidden');
    return;
  }
  if (isSetup) {
    if (pw.length < 8) {
      lockError.textContent = '密码至少 8 位，建议包含字母和数字';
      lockError.classList.remove('hidden');
      return;
    }
    if (pw !== lockConfirm.value) {
      lockError.textContent = '两次输入的密码不一致';
      lockError.classList.remove('hidden');
      return;
    }
    const salt = crypto.getRandomValues(new Uint8Array(16));
    localStorage.setItem(LS_SALT, b64encode(salt));
    cryptoKey = await deriveKey(pw, salt);
    providers = [];
    await encryptVault();
  } else {
    cryptoKey = await deriveKey(pw, currentSalt());
    try {
      const vault = JSON.parse(localStorage.getItem(LS_VAULT));
      const raw = await decryptVault(vault, cryptoKey);
      providers = migrateData(raw);
      if (JSON.stringify({ version: 2, providers }) !== JSON.stringify(raw)) {
        await encryptVault();
      }
    } catch {
      cryptoKey = null;
      lockPassword.value = '';
      lockError.textContent = '密码错误';
      lockError.classList.remove('hidden');
      return;
    }
  }
  lockPassword.value = '';
  lockConfirm.value = '';
  enterApp();
}

function enterApp() {
  loadCollapsed();
  lockScreen.classList.add('hidden');
  appScreen.classList.remove('hidden');
  render();
  resetIdle();
}

function lockNow() {
  clearTimeout(idleTimer);
  cryptoKey = null;
  providers = [];
  visibleKeys.clear();
  collapsedSet.clear();
  searchInput.value = '';
  closeAllModals();
  appScreen.classList.add('hidden');
  lockScreen.classList.remove('hidden');
  updateLockScreen();
  lockPassword.focus();
}

function resetIdle() {
  clearTimeout(idleTimer);
  const minutes = Number(getSettings().autoLock) || 0;
  if (!minutes) return;
  idleTimer = setTimeout(lockNow, minutes * 60000);
}

function toast(msg, isError) {
  toastEl.textContent = msg;
  toastEl.classList.toggle('error', !!isError);
  toastEl.classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toastEl.classList.add('hidden'), 2400);
}

function eyeSvg(visible) {
  if (visible) {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="15" height="15"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><path d="M14.12 14.12a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';
  }
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="15" height="15"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
}

const SVG = {
  copy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="15" height="15"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',
  pencil: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="15" height="15"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>',
  trash: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="15" height="15"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>',
  link: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="13" height="13"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>',
  chevron: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="16" height="16"><polyline points="6 9 12 15 18 9"/></svg>',
  copyMini: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="12" height="12"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',
  grip: '<svg viewBox="0 0 24 24" fill="currentColor" width="14" height="14"><circle cx="9" cy="6" r="1.6"/><circle cx="15" cy="6" r="1.6"/><circle cx="9" cy="12" r="1.6"/><circle cx="15" cy="12" r="1.6"/><circle cx="9" cy="18" r="1.6"/><circle cx="15" cy="18" r="1.6"/></svg>'
};

function keyRowHtml(p, k) {
  const shown = visibleKeys.has(k.id) ? k.key : maskKey(k.key);
  return `<div class="key-row" title="${escapeHtml(k.notes || '')}">
    <span class="drag-handle" draggable="true" data-drag="key" data-p="${p.id}" data-id="${k.id}" title="拖动排序">${SVG.grip}</span>
    <span class="key-label">${escapeHtml(k.label || '密钥')}</span>
    <span class="key-value">${escapeHtml(shown)}</span>
    <button type="button" class="icon-btn" data-a="toggle-key" data-p="${p.id}" data-id="${k.id}" title="显示/隐藏">${eyeSvg(visibleKeys.has(k.id))}</button>
    <button type="button" class="icon-btn" data-a="copy-key" data-p="${p.id}" data-id="${k.id}" title="复制">${SVG.copy}</button>
    <button type="button" class="icon-btn" data-a="edit-key" data-p="${p.id}" data-id="${k.id}" title="编辑">${SVG.pencil}</button>
    <button type="button" class="icon-btn danger" data-a="del-key" data-p="${p.id}" data-id="${k.id}" title="删除">${SVG.trash}</button>
  </div>`;
}

function modelBadgeHtml(p, m) {
  return `<span class="badge" data-a="edit-model" data-p="${p.id}" data-id="${m.id}" title="${escapeHtml(m.notes || '点击编辑')}">${escapeHtml(m.name)}
    <span class="badge-copy" data-a="copy-model" data-p="${p.id}" data-id="${m.id}" title="复制模型名">${SVG.copyMini}</span>
    <span class="badge-del" data-a="del-model" data-p="${p.id}" data-id="${m.id}" title="删除模型">×</span>
  </span>`;
}

function providerHtml(p) {
  const collapsed = collapsedSet.has(p.id);
  const urlLink = p.url
    ? `<a class="provider-link" href="${escapeHtml(p.url)}" target="_blank" rel="noopener noreferrer" title="${escapeHtml(p.url)}">${SVG.link}${escapeHtml(p.url)}</a>
       <button type="button" class="icon-btn" data-a="copy-url" data-p="${p.id}" title="复制链接">${SVG.copy}</button>`
    : '';
  const notes = p.notes
    ? `<div class="provider-notes">${escapeHtml(p.notes)}</div>`
    : '';
  const keysHtml = p.keys.length
    ? p.keys.map((k) => keyRowHtml(p, k)).join('')
    : '<div class="empty-tip">暂无密钥</div>';
  const modelsHtml = p.models.length
    ? `<div class="badges">${p.models.map((m) => modelBadgeHtml(p, m)).join('')}</div>`
    : '<div class="empty-tip">暂无模型</div>';
  return `<div class="provider-card${collapsed ? ' collapsed' : ''}">
    <div class="provider-head">
      <button type="button" class="collapse-btn" data-a="toggle-card" data-p="${p.id}" title="展开/折叠">${SVG.chevron}</button>
      <span class="provider-name" title="${escapeHtml(p.name)}">${escapeHtml(p.name)}</span>
      ${urlLink}
      <span class="provider-meta">${p.keys.length} 钥 · ${p.models.length} 模</span>
      <div class="card-actions">
        <button type="button" class="icon-btn" data-a="edit-provider" data-p="${p.id}" title="编辑供应商">${SVG.pencil}</button>
        <button type="button" class="icon-btn danger" data-a="del-provider" data-p="${p.id}" title="删除供应商">${SVG.trash}</button>
      </div>
      <button type="button" class="drag-handle" draggable="true" data-drag="provider" data-id="${p.id}" title="拖动排序">${SVG.grip}</button>
    </div>
    ${notes}
    <div class="provider-body">
      <div class="section">
        <div class="section-head">
          <span>密钥</span>
          <button type="button" class="btn-mini" data-a="add-key" data-p="${p.id}">+ 添加</button>
        </div>
        ${keysHtml}
      </div>
      <div class="section">
        <div class="section-head">
          <span>模型</span>
          <button type="button" class="btn-mini" data-a="add-model" data-p="${p.id}">+ 添加</button>
        </div>
        ${modelsHtml}
      </div>
    </div>
  </div>`;
}

function matchProvider(p, q) {
  if (p.name.toLowerCase().includes(q)
    || (p.url || '').toLowerCase().includes(q)
    || (p.notes || '').toLowerCase().includes(q)) return true;
  if (p.keys.some((k) => [k.label, k.key, k.notes].some((v) => v && v.toLowerCase().includes(q)))) return true;
  if (p.models.some((m) => [m.name, m.notes].some((v) => v && v.toLowerCase().includes(q)))) return true;
  return false;
}

function render() {
  const q = searchInput.value.trim().toLowerCase();
  const list = q ? providers.filter((p) => matchProvider(p, q)) : providers;

  const keyCount = providers.reduce((n, p) => n + p.keys.length, 0);
  const modelCount = providers.reduce((n, p) => n + p.models.length, 0);
  countEl.innerHTML = `<b>${providers.length}</b> 家供应商 · <b>${keyCount}</b> 枚密钥 · <b>${modelCount}</b> 个模型`;

  grid.innerHTML = list.map(providerHtml).join('');

  if (list.length === 0) {
    emptyText.textContent = q
      ? '没有匹配的供应商'
      : '玉函空空，点击右上角「新增供应商」封入第一枚密钥';
    emptyState.classList.remove('hidden');
  } else {
    emptyState.classList.add('hidden');
  }

  const anyVisible = providers.some((p) => p.keys.some((k) => visibleKeys.has(k.id)));
  toggleAllBtn.textContent = anyVisible ? '全部隐藏' : '全部显示';
  collapseAllBtn.textContent = collapsedSet.size > 0 ? '全部展开' : '全部收起';
}

function toggleCollapseAll() {
  const anyCollapsed = collapsedSet.size > 0;
  collapsedSet.clear();
  if (!anyCollapsed) {
    providers.forEach((p) => collapsedSet.add(p.id));
  }
  saveCollapsed();
  render();
}

function toggleAllVisible() {
  const anyVisible = providers.some((p) => p.keys.some((k) => visibleKeys.has(k.id)));
  visibleKeys.clear();
  if (!anyVisible) {
    providers.forEach((p) => p.keys.forEach((k) => visibleKeys.add(k.id)));
  }
  render();
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    ta.remove();
    return ok;
  }
}

function findProvider(id) {
  return providers.find((p) => p.id === id);
}

function findKey(pid, kid) {
  const p = findProvider(pid);
  return p && p.keys.find((k) => k.id === kid);
}

function findModel(pid, mid) {
  const p = findProvider(pid);
  return p && p.models.find((m) => m.id === mid);
}

async function copyKey(pid, kid) {
  const k = findKey(pid, kid);
  if (!k) return;
  const ok = await copyText(k.key);
  toast(ok ? '密钥已复制' : '复制失败', !ok);
}

async function copyUrl(pid) {
  const p = findProvider(pid);
  if (!p || !p.url) return;
  const ok = await copyText(p.url);
  toast(ok ? '链接已复制' : '复制失败', !ok);
}

function deleteProvider(id) {
  const p = findProvider(id);
  if (!p) return;
  if (!confirm(`确定删除供应商「${p.name}」吗？将同时删除其 ${p.keys.length} 枚密钥、${p.models.length} 个模型。`)) return;
  providers = providers.filter((x) => x.id !== id);
  collapsedSet.delete(id);
  saveCollapsed();
  encryptVault().then(() => {
    render();
    toast('已删除');
  });
}

function deleteKey(pid, kid) {
  const p = findProvider(pid);
  if (!p) return;
  const k = p.keys.find((x) => x.id === kid);
  if (!k) return;
  if (!confirm(`确定删除密钥「${k.label || '未命名'}」吗？`)) return;
  p.keys = p.keys.filter((x) => x.id !== kid);
  visibleKeys.delete(kid);
  encryptVault().then(() => {
    render();
    toast('密钥已删除');
  });
}

function deleteModel(pid, mid) {
  const p = findProvider(pid);
  if (!p) return;
  p.models = p.models.filter((x) => x.id !== mid);
  encryptVault().then(() => {
    render();
    toast('模型已删除');
  });
}

async function copyModelName(pid, mid) {
  const m = findModel(pid, mid);
  if (!m) return;
  const ok = await copyText(m.name);
  toast(ok ? '模型名已复制' : '复制失败', !ok);
}

function moveProvider(fromId, toId) {
  const from = providers.findIndex((p) => p.id === fromId);
  const to = providers.findIndex((p) => p.id === toId);
  if (from < 0 || to < 0 || from === to) return;
  const [item] = providers.splice(from, 1);
  providers.splice(to, 0, item);
  persistOrder();
}

function moveKey(pid, fromId, toId) {
  const p = findProvider(pid);
  if (!p) return;
  const from = p.keys.findIndex((k) => k.id === fromId);
  const to = p.keys.findIndex((k) => k.id === toId);
  if (from < 0 || to < 0 || from === to) return;
  const [item] = p.keys.splice(from, 1);
  p.keys.splice(to, 0, item);
  persistOrder();
}

function persistOrder() {
  encryptVault().then(() => {
    render();
    toast('排序已保存');
  });
}

function clearDragOver() {
  grid.querySelectorAll('.drag-over, .dragging').forEach((el) => {
    el.classList.remove('drag-over', 'dragging');
  });
}

function resolveDragTarget(el, type) {
  let handle = el && el.closest('[data-drag]');
  if (handle) return handle;
  if (!el || !el.closest) return null;
  if (type === 'provider') {
    const card = el.closest('.provider-card');
    return card ? card.querySelector('.drag-handle') : null;
  }
  if (type === 'key') {
    const row = el.closest('.key-row');
    return row ? row.querySelector('.drag-handle') : null;
  }
  return null;
}

function fillProviderSelect(sel, selectedId) {
  sel.innerHTML = providers.map((p) => `<option value="${escapeHtml(p.id)}">${escapeHtml(p.name)}</option>`).join('');
  sel.value = selectedId || (providers[0] ? providers[0].id : '');
}

function openProviderModal(id) {
  editingProviderId = id || null;
  const p = id ? findProvider(id) : null;
  providerModalTitle.textContent = id ? '编辑供应商' : '新增供应商';
  pName.value = p ? p.name : '';
  pUrl.value = p ? p.url : '';
  pNotes.value = p ? p.notes : '';
  providerModal.classList.remove('hidden');
  pName.focus();
}

function closeProviderModal() {
  providerModal.classList.add('hidden');
  providerForm.reset();
  editingProviderId = null;
}

function handleProviderSubmit(e) {
  e.preventDefault();
  const name = pName.value.trim();
  if (!name) {
    toast('请填写供应商名称', true);
    pName.focus();
    return;
  }
  const url = normalizeUrl(pUrl.value);
  const notes = pNotes.value.trim();
  if (editingProviderId) {
    const p = findProvider(editingProviderId);
    if (p) Object.assign(p, { name, url, notes });
  } else {
    providers.unshift({
      id: genId(),
      name,
      url,
      notes,
      keys: [],
      models: []
    });
  }
  const editing = !!editingProviderId;
  encryptVault().then(() => {
    closeProviderModal();
    render();
    toast(editing ? '已保存' : '供应商已添加');
  });
}

function openKeyModal(pid, kid) {
  editingKey = kid ? { pid, id: kid } : null;
  const k = kid ? findKey(pid, kid) : null;
  keyModalTitle.textContent = kid ? '编辑密钥' : '添加密钥';
  fillProviderSelect(kProvider, pid);
  kProvider.disabled = !!kid;
  kLabel.value = k ? k.label : '';
  kKey.value = k ? k.key : '';
  kNotes.value = k ? k.notes : '';
  keyModal.classList.remove('hidden');
  kLabel.focus();
}

function closeKeyModal() {
  keyModal.classList.add('hidden');
  keyForm.reset();
  kProvider.disabled = false;
  editingKey = null;
}

function handleKeySubmit(e) {
  e.preventDefault();
  const pid = kProvider.value;
  const key = kKey.value.trim();
  if (!pid) {
    toast('请先选择供应商', true);
    return;
  }
  if (!key) {
    toast('请填写 API 密钥', true);
    kKey.focus();
    return;
  }
  const p = findProvider(pid);
  if (!p) return;
  const label = kLabel.value.trim();
  const notes = kNotes.value.trim();
  if (editingKey) {
    const k = findKey(editingKey.pid, editingKey.id);
    if (k) Object.assign(k, { label, key, notes });
  } else {
    p.keys.unshift({ id: genId(), label, key, notes });
  }
  const editing = !!editingKey;
  encryptVault().then(() => {
    closeKeyModal();
    render();
    toast(editing ? '已保存' : '密钥已添加');
  });
}

function openModelModal(pid, mid) {
  editingModel = mid ? { pid, id: mid } : null;
  const m = mid ? findModel(pid, mid) : null;
  modelModalTitle.textContent = mid ? '编辑模型' : '添加模型';
  fillProviderSelect(mProvider, pid);
  mProvider.disabled = !!mid;
  mName.value = m ? m.name : '';
  mNotes.value = m ? m.notes : '';
  modelModal.classList.remove('hidden');
  mName.focus();
}

function closeModelModal() {
  modelModal.classList.add('hidden');
  modelForm.reset();
  mProvider.disabled = false;
  editingModel = null;
}

function handleModelSubmit(e) {
  e.preventDefault();
  const pid = mProvider.value;
  const name = mName.value.trim();
  if (!pid) {
    toast('请先选择供应商', true);
    return;
  }
  if (!name) {
    toast('请填写模型名称', true);
    mName.focus();
    return;
  }
  const p = findProvider(pid);
  if (!p) return;
  const notes = mNotes.value.trim();
  if (editingModel) {
    const m = findModel(editingModel.pid, editingModel.id);
    if (m) Object.assign(m, { name, notes });
  } else {
    p.models.push({ id: genId(), name, notes });
  }
  const editing = !!editingModel;
  encryptVault().then(() => {
    closeModelModal();
    render();
    toast(editing ? '已保存' : '模型已添加');
  });
}

function openBackupModal() {
  autoLock.value = String(getSettings().autoLock || 0);
  backupModal.classList.remove('hidden');
}

function closeBackupModal() {
  backupModal.classList.add('hidden');
  importFile.value = '';
}

function doExport() {
  const salt = localStorage.getItem(LS_SALT);
  const vault = localStorage.getItem(LS_VAULT);
  if (!salt || !vault) return;
  const data = {
    app: '锁玉函',
    version: 1,
    salt,
    vault: JSON.parse(vault)
  };
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  const d = new Date();
  a.download = `锁玉函备份-${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, '0')}${String(d.getDate()).padStart(2, '0')}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
  toast('备份已导出，请妥善保管文件与主密码');
}

async function handleImport(file) {
  if (!file) return;
  try {
    const data = JSON.parse(await file.text());
    if (!data || data.app !== '锁玉函' || !data.salt || !data.vault) {
      throw new Error('bad');
    }
    if (!confirm('导入将覆盖当前全部数据并锁定应用，确定继续？')) return;
    localStorage.setItem(LS_SALT, data.salt);
    localStorage.setItem(LS_VAULT, JSON.stringify(data.vault));
    closeBackupModal();
    lockNow();
    toast('已导入，请使用备份库的主密码解锁');
  } catch {
    toast('备份文件无效', true);
  }
}

function openPwdModal() {
  pwdForm.reset();
  pwdModal.classList.remove('hidden');
  pOld.focus();
}

function closePwdModal() {
  pwdModal.classList.add('hidden');
  pwdForm.reset();
}

async function handlePwdSubmit(e) {
  e.preventDefault();
  const oldPw = pOld.value;
  const newPw = pNew.value;
  if (!oldPw) {
    toast('请输入当前密码', true);
    return;
  }
  if (newPw.length < 8) {
    toast('新密码至少 8 位', true);
    return;
  }
  if (newPw !== pConfirm.value) {
    toast('两次输入的新密码不一致', true);
    return;
  }
  try {
    const checkKey = await deriveKey(oldPw, currentSalt());
    const vault = JSON.parse(localStorage.getItem(LS_VAULT));
    await decryptVault(vault, checkKey);
  } catch {
    toast('当前密码错误', true);
    return;
  }
  const salt = crypto.getRandomValues(new Uint8Array(16));
  localStorage.setItem(LS_SALT, b64encode(salt));
  cryptoKey = await deriveKey(newPw, salt);
  await encryptVault();
  closePwdModal();
  toast('主密码已修改');
}

function togglePassword(id, btn) {
  const input = $(id);
  if (!input) return;
  const show = input.type === 'password';
  input.type = show ? 'text' : 'password';
  const eye = btn.querySelector('.i-eye');
  const eyeOff = btn.querySelector('.i-eye-off');
  if (eye) eye.classList.toggle('hidden', show);
  if (eyeOff) eyeOff.classList.toggle('hidden', !show);
  btn.title = show ? '隐藏密码' : '显示密码';
}

function closeAllModals() {
  closeProviderModal();
  closeKeyModal();
  closeModelModal();
  closeBackupModal();
  closePwdModal();
}

function init() {
  if (!window.crypto || !window.crypto.subtle) {
    lockHint.textContent = '当前浏览器不支持 Web Crypto API，请使用新版 Chrome / Edge / Firefox 打开';
    lockForm.classList.add('hidden');
    return;
  }

  const required = ['lock-btn-top', 'add-btn', 'backup-btn', 'pwd-btn', 'toggle-all-btn', 'collapse-all-btn', 'search-input', 'grid', 'count', 'export-btn', 'auto-lock', 'import-file', 'provider-form', 'key-form', 'model-form', 'pwd-form'];
  const missing = required.filter((id) => !$(id));
  if (missing.length) {
    lockHint.textContent = '页面资源加载异常（缺少：' + missing.join(', ') + '）。请按 Ctrl+F5 强制刷新，或清除浏览器缓存后重试。';
    lockForm.classList.add('hidden');
    return;
  }

  updateLockScreen();

  lockForm.addEventListener('submit', handleUnlock);
  $('lock-btn-top').addEventListener('click', lockNow);
  $('add-btn').addEventListener('click', () => openProviderModal(null));
  toggleAllBtn.addEventListener('click', toggleAllVisible);
  collapseAllBtn.addEventListener('click', toggleCollapseAll);
  $('backup-btn').addEventListener('click', openBackupModal);
  $('pwd-btn').addEventListener('click', openPwdModal);
  $('export-btn').addEventListener('click', doExport);
  importFile.addEventListener('change', () => {
    const file = importFile.files[0];
    importFile.value = '';
    handleImport(file);
  });
  autoLock.addEventListener('change', () => {
    const s = getSettings();
    s.autoLock = Number(autoLock.value) || 0;
    saveSettings(s);
    resetIdle();
    toast('设置已保存');
  });

  searchInput.addEventListener('input', render);

  providerForm.addEventListener('submit', handleProviderSubmit);
  keyForm.addEventListener('submit', handleKeySubmit);
  modelForm.addEventListener('submit', handleModelSubmit);
  pwdForm.addEventListener('submit', handlePwdSubmit);

  grid.addEventListener('click', (e) => {
    const el = e.target.closest('[data-a]');
    if (!el) return;
    const a = el.dataset.a;
    const pid = el.dataset.p;
    const id = el.dataset.id;
    if (a === 'toggle-card') {
      collapsedSet.has(pid) ? collapsedSet.delete(pid) : collapsedSet.add(pid);
      saveCollapsed();
      render();
    } else if (a === 'copy-url') {
      copyUrl(pid);
    } else if (a === 'edit-provider') {
      openProviderModal(pid);
    } else if (a === 'del-provider') {
      deleteProvider(pid);
    } else if (a === 'add-key') {
      openKeyModal(pid, null);
    } else if (a === 'toggle-key') {
      visibleKeys.has(id) ? visibleKeys.delete(id) : visibleKeys.add(id);
      render();
    } else if (a === 'copy-key') {
      copyKey(pid, id);
    } else if (a === 'edit-key') {
      openKeyModal(pid, id);
    } else if (a === 'del-key') {
      deleteKey(pid, id);
    } else if (a === 'add-model') {
      openModelModal(pid, null);
    } else if (a === 'edit-model') {
      openModelModal(pid, id);
    } else if (a === 'del-model') {
      deleteModel(pid, id);
    } else if (a === 'copy-model') {
      copyModelName(pid, id);
    }
  });

  grid.addEventListener('dragstart', (e) => {
    const el = resolveDragTarget(e.target, null);
    if (!el) return;
    dragItem = { type: el.dataset.drag, pid: el.dataset.p || null, id: el.dataset.id };
    e.dataTransfer.effectAllowed = 'move';
    try {
      e.dataTransfer.setData('text/plain', dragItem.id);
    } catch {}
    const highlight = dragItem.type === 'provider' ? el.closest('.provider-card') : el.closest('.key-row');
    if (highlight) highlight.classList.add('dragging');
  });

  grid.addEventListener('dragover', (e) => {
    if (!dragItem) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    const el = resolveDragTarget(e.target, dragItem.type);
    if (!el || el.dataset.drag !== dragItem.type) return;
    if (dragItem.type === 'key' && el.dataset.p !== dragItem.pid) return;
    if (el.dataset.id === dragItem.id) return;
    clearDragOver();
    el.classList.add('drag-over');
  });

  grid.addEventListener('drop', (e) => {
    e.preventDefault();
    if (!dragItem) return;
    const el = resolveDragTarget(e.target, dragItem.type);
    clearDragOver();
    if (el && el.dataset.drag === dragItem.type) {
      if (dragItem.type === 'provider' && el.dataset.id !== dragItem.id) {
        moveProvider(dragItem.id, el.dataset.id);
      } else if (dragItem.type === 'key' && el.dataset.p === dragItem.pid && el.dataset.id !== dragItem.id) {
        moveKey(dragItem.pid, dragItem.id, el.dataset.id);
      }
    }
    dragItem = null;
  });

  grid.addEventListener('dragend', () => {
    clearDragOver();
    dragItem = null;
  });

  document.querySelectorAll('[data-toggle]').forEach((btn) => {
    btn.addEventListener('click', () => togglePassword(btn.dataset.toggle, btn));
  });

  document.querySelectorAll('[data-close]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const m = $(btn.dataset.close);
      if (m) m.classList.add('hidden');
    });
  });

  document.querySelectorAll('.modal-backdrop').forEach((backdrop) => {
    backdrop.addEventListener('click', (e) => {
      if (e.target === backdrop) backdrop.classList.add('hidden');
    });
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeAllModals();
  });

  ['mousemove', 'keydown', 'click', 'scroll', 'touchstart'].forEach((ev) => {
    document.addEventListener(ev, () => {
      if (cryptoKey) resetIdle();
    });
  });
}

init();
