const LS_SALT = 'kv.salt';
const LS_VAULT = 'kv.vault';
const LS_ITER = 'kv.iter';
const LS_SETTINGS = 'kv.settings';
const LS_VAULT_V2 = 'kv.vault.v2';

export const APP_NAME = '黑冰匣';
export const VAULT_VERSION = 3;

export function genId() {
  return Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8);
}

export function normalizeUrl(url) {
  const t = (url || '').trim();
  if (!t) return '';
  try {
    const u = new URL(t);
    if (u.protocol !== 'https:') return '';
    return u.href;
  } catch {
    try {
      const u2 = new URL('https://' + t);
      if (u2.protocol !== 'https:') return '';
      return u2.href;
    } catch {
      return '';
    }
  }
}

export function maskSecret(v) {
  if (!v) return '';
  const s = String(v);
  return s.length > 6 ? s.slice(0, 4) + '••••••••' : '••••••••';
}

function emptyVault() {
  return { version: VAULT_VERSION, entries: [] };
}
export function makeEntry(type, title) {
  const now = new Date().toISOString();
  return {
    id: genId(),
    type,
    title: title || '',
    metadata: {
      createdAt: now,
      updatedAt: now,
      favorite: false,
      tags: [],
      description: ''
    },
    fields: []
  };
}

function normalizeEntry(e) {
  const now = new Date().toISOString();
  const meta = e.metadata && typeof e.metadata === 'object' ? e.metadata : {};
  return {
    id: e.id || genId(),
    type: e.type || 'note',
    title: e.title || e.name || '未命名',
    metadata: {
      createdAt: meta.createdAt || now,
      updatedAt: meta.updatedAt || now,
      favorite: !!meta.favorite,
      tags: Array.isArray(meta.tags) ? meta.tags.map(String) : [],
      description: meta.description || e.notes || ''
    },
    fields: Array.isArray(e.fields) ? e.fields.map(f => ({
      name: f.name || '',
      type: f.type || 'text',
      value: f.value
    })) : []
  };
}

function providerToEntry(p) {
  const e = makeEntry('api', p.name || p.title || '未命名');
  e.fields.push({ name: 'Endpoint', type: 'url', value: p.url || '' });
  e.fields.push({
    name: 'API Keys',
    type: 'keys',
    value: (Array.isArray(p.keys) ? p.keys : []).map(k => ({
      id: k.id || genId(),
      label: k.label || '密钥',
      key: k.key || '',
      notes: k.notes || ''
    }))
  });
  e.fields.push({
    name: 'Models',
    type: 'list',
    value: (Array.isArray(p.models) ? p.models : []).map(m => ({
      id: m.id || genId(),
      name: m.name || m,
      notes: m.notes || ''
    }))
  });
  e.metadata.description = p.notes || p.description || '';
  return e;
}

function migrateV1Array(raw) {
  return raw.map(item => providerToEntry({
    id: item.id,
    name: item.name,
    url: item.url,
    notes: item.notes,
    keys: item.key ? [{ id: genId(), label: '', key: item.key, notes: '' }] : [],
    models: item.model ? [{ id: genId(), name: item.model, notes: '' }] : []
  }));
}

export function migrateData(raw) {
  if (Array.isArray(raw)) {
    return { version: VAULT_VERSION, entries: normalizeEntriesArray(migrateV1Array(raw)) };
  }
  if (raw && Array.isArray(raw.providers)) {
    return { version: VAULT_VERSION, entries: normalizeEntriesArray(raw.providers.map(providerToEntry)) };
  }
  if (raw && Array.isArray(raw.entries)) {
    return { version: VAULT_VERSION, entries: normalizeEntriesArray(raw.entries.map(normalizeEntry)) };
  }
  return emptyVault();
}

function normalizeEntriesArray(entries) {
  return entries.map(normalizeEntry);
}

function getStorageKey(name) {
  const map = { salt: LS_SALT, vault: LS_VAULT, iter: LS_ITER, settings: LS_SETTINGS, vaultV2: LS_VAULT_V2 };
  return map[name];
}

function readLocal(name) {
  try {
    return localStorage.getItem(getStorageKey(name));
  } catch {
    return null;
  }
}

function writeLocal(name, value) {
  try {
    localStorage.setItem(getStorageKey(name), value);
    return true;
  } catch {
    return false;
  }
}

function removeLocal(name) {
  try {
    localStorage.removeItem(getStorageKey(name));
  } catch {}
}

export function getStoredIterations() {
  const n = Number(readLocal('iter'));
  return n > 0 ? n : null;
}

export function saveIterations(n) {
  writeLocal('iter', String(n));
}

export function getSettings() {
  try {
    return JSON.parse(readLocal('settings') || '{}');
  } catch {
    return {};
  }
}

export function saveSettings(s) {
  writeLocal('settings', JSON.stringify(s));
}

export function exportPayload(saltB64, vaultObj) {
  return {
    app: APP_NAME,
    version: 1,
    iter: Number(readLocal('iter')) || undefined,
    salt: saltB64,
    vault: vaultObj
  };
}

export function parseImportPayload(data) {
  if (!data || typeof data !== 'object') return null;
  const okName = data.app === APP_NAME || data.app === '锁玉函';
  if (!okName || !data.salt || !data.vault) return null;
  return data;
}
