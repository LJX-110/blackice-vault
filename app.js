const LS_SALT = 'kv.salt';
const LS_VAULT = 'kv.vault';
const PBKDF2_ITERATIONS = 100000;

const $ = (id) => document.getElementById(id);

let entries = [];
let cryptoKey = null;
let editingId = null;
let isSetup = false;
let allVisible = false;
let toastTimer = null;
const visibleIds = new Set();

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

const modal = $('modal');
const modalTitle = $('modal-title');
const entryForm = $('entry-form');
const fName = $('f-name');
const fModel = $('f-model');
const fKey = $('f-key');
const fUrl = $('f-url');
const fNotes = $('f-notes');

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
  return String(s).replace(/[&<>"']/g, (c) => (
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

async function encryptEntries() {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new TextEncoder().encode(JSON.stringify(entries));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, data);
  localStorage.setItem(LS_VAULT, JSON.stringify({ iv: b64encode(iv), ct: b64encode(ct) }));
}

async function decryptEntries(vault, key) {
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

function updateLockScreen() {
  isSetup = !hasVault();
  lockHint.textContent = isSetup
    ? '首次使用，设置一个主密码来加密保护你的密钥，请务必牢记'
    : '输入主密码解锁你的密钥库';
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
    entries = [];
    await encryptEntries();
  } else {
    cryptoKey = await deriveKey(pw, currentSalt());
    try {
      const vault = JSON.parse(localStorage.getItem(LS_VAULT));
      entries = await decryptEntries(vault, cryptoKey);
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
  lockScreen.classList.add('hidden');
  appScreen.classList.remove('hidden');
  renderCards();
}

function lockNow() {
  cryptoKey = null;
  entries = [];
  visibleIds.clear();
  allVisible = false;
  searchInput.value = '';
  appScreen.classList.add('hidden');
  lockScreen.classList.remove('hidden');
  updateLockScreen();
  lockPassword.focus();
}

function toast(msg, isError) {
  toastEl.textContent = msg;
  toastEl.classList.toggle('error', !!isError);
  toastEl.classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toastEl.classList.add('hidden'), 2200);
}

function isVisible(id) {
  return visibleIds.has(id);
}

function eyeSvg(visible) {
  if (visible) {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="15" height="15"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><path d="M14.12 14.12a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';
  }
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="15" height="15"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
}

function cardHtml(e) {
  const shown = isVisible(e.id) ? e.key : maskKey(e.key);
  const badge = e.model
    ? `<span class="badge">${escapeHtml(e.model)}</span>`
    : '';
  const keyRow = `<div class="row"><svg class="row-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="14" height="14"><path d="M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z"/><circle cx="16.5" cy="7.5" r=".5" fill="currentColor"/></svg><span class="value mono">${escapeHtml(shown)}</span><button type="button" class="icon-btn" data-action="toggle" data-id="${e.id}" title="显示/隐藏密钥">${eyeSvg(isVisible(e.id))}</button><button type="button" class="icon-btn" data-action="copy-key" data-id="${e.id}" title="复制密钥"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="15" height="15"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button></div>`;
  const urlRow = e.url
    ? `<div class="row"><svg class="row-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="14" height="14"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg><a class="value" href="${escapeHtml(e.url)}" target="_blank" rel="noopener noreferrer" title="${escapeHtml(e.url)}">${escapeHtml(e.url)}</a><button type="button" class="icon-btn" data-action="copy-url" data-id="${e.id}" title="复制链接"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="15" height="15"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button></div>`
    : '';
  const notes = e.notes
    ? `<div class="notes">${escapeHtml(e.notes)}</div>`
    : '';
  return `<div class="card"><div class="card-head"><span class="card-title">${escapeHtml(e.name)}</span>${badge}<div class="card-actions"><button type="button" class="icon-btn" data-action="edit" data-id="${e.id}" title="编辑"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="15" height="15"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg></button><button type="button" class="icon-btn danger" data-action="delete" data-id="${e.id}" title="删除"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="15" height="15"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg></button></div></div>${keyRow}${urlRow}${notes}</div>`;
}

function renderCards() {
  const q = searchInput.value.trim().toLowerCase();
  const list = q
    ? entries.filter((e) => [e.name, e.model, e.notes, e.url, e.key]
        .some((v) => v && v.toLowerCase().includes(q)))
    : entries;

  countEl.textContent = `共 ${entries.length} 条`;
  grid.innerHTML = list.map(cardHtml).join('');

  if (list.length === 0) {
    emptyText.textContent = q
      ? '没有匹配的密钥'
      : '还没有密钥，点击右上角「新增」添加第一条';
    emptyState.classList.remove('hidden');
  } else {
    emptyState.classList.add('hidden');
  }

  const anyVisible = entries.some((e) => isVisible(e.id));
  toggleAllBtn.textContent = anyVisible ? '全部隐藏' : '全部显示';
}

function toggleAllVisible() {
  allVisible = !allVisible;
  visibleIds.clear();
  if (allVisible) {
    entries.forEach((e) => visibleIds.add(e.id));
  }
  renderCards();
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

async function copyKey(id) {
  const entry = entries.find((e) => e.id === id);
  if (!entry) return;
  const ok = await copyText(entry.key);
  toast(ok ? '密钥已复制' : '复制失败', !ok);
}

async function copyUrl(id) {
  const entry = entries.find((e) => e.id === id);
  if (!entry || !entry.url) return;
  const ok = await copyText(entry.url);
  toast(ok ? '链接已复制' : '复制失败', !ok);
}

function deleteEntry(id) {
  const entry = entries.find((e) => e.id === id);
  if (!entry) return;
  if (!confirm(`确定删除「${entry.name}」吗？此操作不可恢复。`)) return;
  entries = entries.filter((e) => e.id !== id);
  visibleIds.delete(id);
  encryptEntries().then(() => {
    renderCards();
    toast('已删除');
  });
}

function openModal(id) {
  editingId = id || null;
  const entry = id ? entries.find((e) => e.id === id) : null;
  modalTitle.textContent = id ? '编辑密钥' : '新增密钥';
  fName.value = entry ? entry.name : '';
  fModel.value = entry ? entry.model : '';
  fKey.value = entry ? entry.key : '';
  fUrl.value = entry ? entry.url : '';
  fNotes.value = entry ? entry.notes : '';
  modal.classList.remove('hidden');
  fName.focus();
}

function closeModal() {
  modal.classList.add('hidden');
  entryForm.reset();
  editingId = null;
}

function handleEntrySubmit(e) {
  e.preventDefault();
  const name = fName.value.trim();
  const key = fKey.value.trim();
  if (!name) {
    toast('请填写名称', true);
    fName.focus();
    return;
  }
  if (!key) {
    toast('请填写 API 密钥', true);
    fKey.focus();
    return;
  }
  const editing = !!editingId;
  if (editing) {
    const idx = entries.findIndex((x) => x.id === editingId);
    if (idx >= 0) {
      entries[idx] = {
        ...entries[idx],
        name,
        model: fModel.value.trim(),
        key,
        url: normalizeUrl(fUrl.value),
        notes: fNotes.value.trim()
      };
    }
  } else {
    entries.unshift({
      id: 'id-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8),
      name,
      model: fModel.value.trim(),
      key,
      url: normalizeUrl(fUrl.value),
      notes: fNotes.value.trim(),
      createdAt: Date.now()
    });
  }
  encryptEntries().then(() => {
    closeModal();
    renderCards();
    toast(editing ? '已保存' : '已添加');
  });
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
    await decryptEntries(vault, checkKey);
  } catch {
    toast('当前密码错误', true);
    return;
  }
  const salt = crypto.getRandomValues(new Uint8Array(16));
  localStorage.setItem(LS_SALT, b64encode(salt));
  cryptoKey = await deriveKey(newPw, salt);
  await encryptEntries();
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

function init() {
  if (!window.crypto || !window.crypto.subtle) {
    lockHint.textContent = '当前浏览器不支持 Web Crypto API，请使用新版 Chrome / Edge / Firefox 打开';
    lockForm.classList.add('hidden');
    return;
  }

  updateLockScreen();

  lockForm.addEventListener('submit', handleUnlock);
  $('lock-btn-top').addEventListener('click', lockNow);
  $('add-btn').addEventListener('click', () => openModal(null));
  toggleAllBtn.addEventListener('click', toggleAllVisible);
  $('pwd-btn').addEventListener('click', openPwdModal);

  searchInput.addEventListener('input', renderCards);

  entryForm.addEventListener('submit', handleEntrySubmit);
  pwdForm.addEventListener('submit', handlePwdSubmit);

  grid.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-action]');
    if (!btn) return;
    const id = btn.dataset.id;
    const action = btn.dataset.action;
    if (action === 'toggle') {
      const v = visibleIds.has(id);
      v ? visibleIds.delete(id) : visibleIds.add(id);
      renderCards();
    } else if (action === 'copy-key') {
      copyKey(id);
    } else if (action === 'copy-url') {
      copyUrl(id);
    } else if (action === 'edit') {
      openModal(id);
    } else if (action === 'delete') {
      deleteEntry(id);
    }
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
    if (e.key === 'Escape') {
      closeModal();
      closePwdModal();
    }
  });
}

init();
