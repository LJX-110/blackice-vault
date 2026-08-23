import {
  PBKDF2_ITERATIONS, LEGACY_ITERATIONS,
  b64encode, b64decode, deriveKey, encryptData, decryptData
} from './crypto.js';
import {
  APP_NAME, VAULT_VERSION, genId, normalizeUrl, maskSecret, migrateData, makeEntry,
  readLocal, writeLocal, removeLocal,
  getStoredIterations, saveIterations,
  getSettings, saveSettings,
  exportPayload, parseImportPayload
} from './vault.js';

const $ = (id) => document.getElementById(id);

let entries = [];
let cryptoKey = null;
let isSetup = false;
let activeView = 'all';
let selectedId = null;
let editingEntryId = null;
let dragId = null;
let palIndex = 0;
let palItems = [];
let soundEnabled = true;
let fxEnabled = true;
const revealSet = new Set();
const REDUCED_MOTION = !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);

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
const entryListEl = $('entry-list');
const detailPanel = $('detail-panel');
const emptyState = $('empty-state');
const emptyText = $('empty-text');
const countEl = $('count');

const entryModal = $('entry-modal');
const entryForm = $('entry-form');
const entryModalTitle = $('entry-modal-title');
const entryTypeWrap = $('entry-type-wrap');
const eType = $('e-type');
const eTitle = $('e-title');
const eTags = $('e-tags');
const entryFields = $('entry-fields');
const eDesc = $('e-desc');

const securityModal = $('security-modal');
const pwdForm = $('pwd-form');
const backupModal = $('backup-modal');
const importFile = $('import-file');
const settingsModal = $('settings-modal');
const autoLockSel = $('auto-lock');
const setSound = $('set-sound');
const setFx = $('set-fx');

const toastEl = $('toast');
const palBackdrop = $('palette-backdrop');
const palInput = $('pal-input');
const palList = $('pal-list');

const TYPES = {
  api: { tag: 'API', cls: 't-api' },
  account: { tag: 'ACCOUNT', cls: 't-account' },
  note: { tag: 'NOTE', cls: 't-note' }
};

const SCHEMAS = {
  api: [
    ['Endpoint', 'url'],
    ['API Keys', 'keys'],
    ['Models', 'list']
  ],
  account: [
    ['Username', 'text'],
    ['Email', 'text'],
    ['Password', 'password'],
    ['URL', 'url']
  ],
  note: [
    ['Content', 'textarea']
  ]
};

function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

function fmtDate(iso) {
  const d = iso ? new Date(iso) : new Date();
  if (isNaN(d)) return '';
  return `${d.getFullYear()}.${String(d.getMonth() + 1).padStart(2, '0')}.${String(d.getDate()).padStart(2, '0')}`;
}

function slugOf(t) {
  const s = String(t || '').trim().toUpperCase().replace(/[^A-Z0-9\u4e00-\u9fff]+/g, '-').replace(/^-+|-+$/g, '');
  return s || 'ENTRY';
}

function togglePassword(inputId, btn) {
  const input = $(inputId);
  if (!input) return;
  const show = input.type === 'password';
  input.type = show ? 'text' : 'password';
  const eye = btn.querySelector('.i-eye');
  const eyeOff = btn.querySelector('.i-eye-off');
  if (eye && eyeOff) {
    eye.classList.toggle('hidden', show);
    eyeOff.classList.toggle('hidden', !show);
  } else {
    btn.innerHTML = eyeSvg(show);
  }
  btn.title = show ? '隐藏' : '显示';
}

function getField(e, name) {
  return e.fields.find((f) => f.name === name);
}

function toast(msg, isError, silent) {
  toastEl.textContent = msg;
  toastEl.classList.toggle('error', !!isError);
  toastEl.classList.remove('hidden', 'out');
  clearTimeout(toast._t1);
  clearTimeout(toast._t2);
  toast._t1 = setTimeout(() => {
    toastEl.classList.add('out');
    toast._t2 = setTimeout(() => {
      toastEl.classList.add('hidden');
      toastEl.classList.remove('out');
    }, 220);
  }, 2300);
  if (soundEnabled && !silent) {
    try { (isError ? SFX.err : SFX.ok)(); } catch (err) {}
  }
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
    let ok = false;
    try { ok = document.execCommand('copy'); } catch (err) {}
    ta.remove();
    return ok;
  }
}

function flashCheck(btn) {
  if (!btn || btn.dataset.busy) return;
  btn.dataset.busy = '1';
  const orig = btn.innerHTML;
  btn.innerHTML = SVG.check;
  btn.classList.add('flash-ok');
  setTimeout(() => {
    btn.innerHTML = orig;
    btn.classList.remove('flash-ok');
    delete btn.dataset.busy;
  }, 800);
}

function scrambleText(el, finalText, dur) {
  if (!el) return;
  if (REDUCED_MOTION) { el.textContent = finalText; return; }
  const CHARS = '!<>-_\\/[]{}=+*^?#______01';
  const start = performance.now();
  dur = dur || 800;
  function frame(now) {
    const t = Math.min(1, (now - start) / dur);
    const cut = Math.floor(finalText.length * t);
    let out = '';
    for (let i = 0; i < finalText.length; i++) {
      out += i < cut ? finalText[i] : (finalText[i] === ' ' ? ' ' : CHARS[(Math.random() * CHARS.length) | 0]);
    }
    el.textContent = out;
    if (t < 1) requestAnimationFrame(frame);
    else el.textContent = finalText;
  }
  requestAnimationFrame(frame);
}

const SVG = {
  copy: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="13" height="13"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>',
  pencil: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="13" height="13"><path d="M17 3a2.83 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>',
  trash: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="13" height="13"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>',
  link: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="12" height="12"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>',
  grip: '<svg viewBox="0 0 24 24" fill="currentColor" width="13" height="13"><circle cx="9" cy="6" r="1.5"/><circle cx="15" cy="6" r="1.5"/><circle cx="9" cy="12" r="1.5"/><circle cx="15" cy="12" r="1.5"/><circle cx="9" cy="18" r="1.5"/><circle cx="15" cy="18" r="1.5"/></svg>',
  check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" width="13" height="13"><polyline points="20 6 9 17 4 12"/></svg>',
  star: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="14" height="14"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>',
  back: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="12" height="12"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></svg>'
};

function eyeSvg(visible) {
  if (visible) {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="13" height="13"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><path d="M14.12 14.12a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';
  }
  return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="13" height="13"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
}

const SFX = (function () {
  let ctx = null;
  let master = null;
  function ac() {
    if (!ctx) {
      try {
        ctx = new (window.AudioContext || window.webkitAudioContext)();
        master = ctx.createGain();
        master.gain.value = 1.4;
        master.connect(ctx.destination);
      } catch (e) { return null; }
    }
    if (ctx.state === 'suspended') { try { ctx.resume(); } catch (e) {} }
    return ctx;
  }
  function tone(freq, dur, type, vol, delay, glideTo) {
    const c = ac(); if (!c || !soundEnabled) return;
    const t0 = c.currentTime + (delay || 0);
    const o = c.createOscillator();
    const g = c.createGain();
    o.type = type;
    o.frequency.setValueAtTime(freq, t0);
    if (glideTo) o.frequency.exponentialRampToValueAtTime(glideTo, t0 + dur);
    g.gain.setValueAtTime(0.0001, t0);
    g.gain.exponentialRampToValueAtTime(Math.max(vol, 0.002), t0 + 0.012);
    g.gain.exponentialRampToValueAtTime(0.0001, t0 + dur);
    o.connect(g); g.connect(master || c.destination);
    o.start(t0); o.stop(t0 + dur + 0.05);
  }
  function noise(dur, vol, freq, delay) {
    const c = ac(); if (!c || !soundEnabled) return;
    const t0 = c.currentTime + (delay || 0);
    const len = Math.max(1, Math.floor(c.sampleRate * dur));
    const buf = c.createBuffer(1, len, c.sampleRate);
    const d = buf.getChannelData(0);
    for (let i = 0; i < len; i++) d[i] = Math.random() * 2 - 1;
    const src = c.createBufferSource(); src.buffer = buf;
    const f = c.createBiquadFilter(); f.type = 'bandpass'; f.frequency.value = freq; f.Q.value = 0.8;
    const g = c.createGain();
    g.gain.setValueAtTime(vol, t0);
    g.gain.exponentialRampToValueAtTime(0.0001, t0 + dur);
    src.connect(f); f.connect(g); g.connect(master || c.destination);
    src.start(t0); src.stop(t0 + dur);
  }
  return {
    click:  function () { const f = 720 + Math.random() * 90; tone(f, 0.035, 'square', 0.1); tone(f * 0.5, 0.045, 'square', 0.08, 0.018); },
    tick:   function () { tone(1500 + Math.random() * 200, 0.03, 'square', 0.08); },
    whoosh: function () { noise(0.16, 0.1, 1600); tone(1400, 0.11, 'square', 0.05, 0, 320); },
    ok:     function () { tone(587, 0.05, 'square', 0.12); tone(784, 0.05, 'square', 0.12, 0.05); tone(1175, 0.1, 'square', 0.13, 0.1); },
    err:    function () { tone(220, 0.15, 'sawtooth', 0.2); tone(196, 0.12, 'sawtooth', 0.18, 0.07); noise(0.13, 0.09, 500, 0.02); },
    lock:   function () { noise(0.05, 0.16, 800); tone(150, 0.07, 'square', 0.2); tone(100, 0.12, 'square', 0.17, 0.075); },
    unlock: function () { tone(440, 0.05, 'square', 0.13); tone(659, 0.05, 'square', 0.13, 0.06); tone(880, 0.09, 'square', 0.14, 0.12); tone(1319, 0.13, 'triangle', 0.08, 0.18); },
    sweep:  function () { tone(900, 0.18, 'sine', 0.06, 0, 2400); tone(2400, 0.2, 'sine', 0.04, 0.14, 480); }
  };
})();

document.addEventListener('pointerdown', function (e) {
  if (!soundEnabled || !e.target.closest) return;
  const t = e.target.closest('button, .badge-del, .chip.tappable, .pal-item');
  if (!t) return;
  if (t.closest('#lock-btn-top, #lock-btn')) return;
  if (t.closest('#add-btn, #nav-security, #nav-backup, #nav-settings')) { SFX.whoosh(); return; }
  if (t.closest('.nav-item[data-view], #sound-toggle-btn')) { SFX.tick(); return; }
  SFX.click();
});

const FX = (function () {
  let canvas = null;
  let c2d = null;
  let parts = [];
  let raf = null;
  let mx = 0, my = 0;
  let enabled = true;
  const COLORS = ['255,0,61', '252,238,10', '0,229,255'];
  function resize() {
    if (!canvas) return;
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  }
  function spawn() {
    parts = [];
    const count = Math.min(90, Math.max(28, Math.floor(window.innerWidth * window.innerHeight / 20000)));
    for (let i = 0; i < count; i++) {
      parts.push({
        x: Math.random() * window.innerWidth,
        y: Math.random() * window.innerHeight,
        r: Math.random() * 1.6 + 0.5,
        vx: (Math.random() - 0.5) * 0.16,
        vy: (Math.random() - 0.5) * 0.16,
        a: Math.random() * 0.32 + 0.1,
        c: COLORS[i % COLORS.length],
        ph: Math.random() * Math.PI * 2
      });
    }
  }
  function tick(t) {
    if (!enabled) { raf = null; return; }
    c2d.clearRect(0, 0, canvas.width, canvas.height);
    const px = (mx - window.innerWidth / 2) * 0.01;
    const py = (my - window.innerHeight / 2) * 0.01;
    const LINK = 105, L2 = LINK * LINK;
    c2d.lineWidth = 1;
    for (let i = 0; i < parts.length; i++) {
      for (let j = i + 1; j < parts.length; j++) {
        const dx = parts[i].x - parts[j].x;
        const dy = parts[i].y - parts[j].y;
        const d2 = dx * dx + dy * dy;
        if (d2 < L2) {
          c2d.strokeStyle = 'rgba(0,229,255,' + ((1 - Math.sqrt(d2) / LINK) * 0.08).toFixed(3) + ')';
          c2d.beginPath();
          c2d.moveTo(parts[i].x + px, parts[i].y + py);
          c2d.lineTo(parts[j].x + px, parts[j].y + py);
          c2d.stroke();
        }
      }
    }
    for (const p of parts) {
      p.x += p.vx; p.y += p.vy;
      if (p.x < -10) p.x = window.innerWidth + 10; else if (p.x > window.innerWidth + 10) p.x = -10;
      if (p.y < -10) p.y = window.innerHeight + 10; else if (p.y > window.innerHeight + 10) p.y = -10;
      const tw = 0.7 + 0.3 * Math.sin(t * 0.0012 + p.ph);
      c2d.beginPath();
      c2d.arc(p.x + px * p.r * 2.5, p.y + py * p.r * 2.5, p.r, 0, 6.2832);
      c2d.fillStyle = 'rgba(' + p.c + ',' + (p.a * tw).toFixed(3) + ')';
      c2d.fill();
    }
    raf = requestAnimationFrame(tick);
  }
  function start() {
    if (!c2d || raf || !enabled) return;
    raf = requestAnimationFrame(tick);
  }
  function stop() {
    if (raf) { cancelAnimationFrame(raf); raf = null; }
    if (c2d) c2d.clearRect(0, 0, canvas.width, canvas.height);
  }
  function applyClass() {
    if (canvas) canvas.classList.toggle('fx-off', !enabled);
  }
  function init() {
    if (REDUCED_MOTION) enabled = false;
    try {
      canvas = document.getElementById('fx-canvas');
      if (!canvas) return;
      c2d = canvas.getContext('2d');
      if (!c2d) return;
      resize();
      spawn();
      window.addEventListener('resize', () => { resize(); spawn(); });
      window.addEventListener('pointermove', (e) => { mx = e.clientX; my = e.clientY; }, { passive: true });
      document.addEventListener('visibilitychange', () => {
        if (document.hidden) stop(); else start();
      });
      applyClass();
      start();
    } catch (err) {}
  }
  function setEnabled(v) {
    enabled = !!v && !REDUCED_MOTION;
    applyClass();
    if (enabled) start(); else stop();
  }
  return { init, setEnabled };
})();

const BOOT_LINES = [
  '> BLACKICE SECURE SUBSYSTEM',
  '> CRYPTO MODULE AES-GCM-256 .... OK',
  '> VAULT INTEGRITY .............. OK',
  '> ACCESS GRANTED'
];
let bootRunning = false;
function runBoot(done) {
  if (bootRunning || REDUCED_MOTION) { done(); return; }
  bootRunning = true;
  const box = $('boot-screen');
  const lines = $('boot-lines');
  if (!box || !lines) { done(); return; }
  lines.textContent = '';
  box.classList.remove('hidden');
  box.classList.remove('fade-out');
  SFX.sweep();
  let i = 0;
  const timer = setInterval(() => {
    lines.textContent += BOOT_LINES[i] + '\n';
    i++;
    if (i >= BOOT_LINES.length) {
      clearInterval(timer);
      setTimeout(() => {
        box.classList.add('fade-out');
        if (cryptoKey) done();
        setTimeout(() => {
          box.classList.add('hidden');
          bootRunning = false;
        }, 400);
      }, 260);
    }
  }, 130);
}

function hasVault() {
  return !!readLocal('salt');
}
function currentSalt() {
  return b64decode(readLocal('salt'));
}

async function persistVault() {
  const payload = { version: VAULT_VERSION, entries };
  const enc = await encryptData(cryptoKey, payload);
  if (!writeLocal('vault', JSON.stringify(enc))) {
    toast('本地存储已满，保存失败', true);
  }
}

function updateLockScreen() {
  isSetup = !hasVault();
  lockHint.textContent = isSetup
    ? '首次使用：设置主密码，本地加密你的全部条目。密码不可找回。'
    : '输入主密码，接入 BLACKICE 终端';
  lockBtn.textContent = isSetup ? 'INITIALIZE' : 'UNLOCK';
  lockConfirmWrap.classList.toggle('hidden', !isSetup);
  lockError.classList.add('hidden');
  lockBusy(false);
}

function lockBusy(on) {
  lockBtn.disabled = !!on;
  lockBtn.classList.toggle('busy', !!on);
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
      lockError.textContent = '密码至少 8 位，建议混合字母与符号';
      lockError.classList.remove('hidden');
      return;
    }
    if (pw !== lockConfirm.value) {
      lockError.textContent = '两次输入的密码不一致';
      lockError.classList.remove('hidden');
      return;
    }
    const salt = crypto.getRandomValues(new Uint8Array(16));
    lockBusy(true);
    writeLocal('salt', b64encode(salt));
    saveIterations(PBKDF2_ITERATIONS);
    cryptoKey = await deriveKey(pw, salt, PBKDF2_ITERATIONS);
    entries = [];
    await persistVault();
  } else {
    lockBusy(true);
    const salt = currentSalt();
    const storedIter = getStoredIterations();
    const candidates = storedIter ? [storedIter] : [PBKDF2_ITERATIONS, LEGACY_ITERATIONS];
    const oldVaultStr = readLocal('vault');
    let unlocked = false;
    for (const iter of candidates) {
      try {
        cryptoKey = await deriveKey(pw, salt, iter);
        const vaultObj = JSON.parse(oldVaultStr);
        const raw = await decryptData(vaultObj, cryptoKey);
        const vNorm = migrateData(raw);
        if (raw.providers && !raw.entries) {
          const rawKeys = raw.providers.reduce((n, p) => n + (Array.isArray(p.keys) ? p.keys.length : 0), 0);
          const newKeys = vNorm.entries.reduce((n, en) => {
            const f = en.fields.find((x) => x.type === 'keys');
            return n + (Array.isArray(f && f.value) ? f.value.length : 0);
          }, 0);
          if (rawKeys !== newKeys) throw new Error('migration-mismatch');
          if (raw.providers.length !== vNorm.entries.length) throw new Error('migration-count');
        }
        entries = vNorm.entries;
        unlocked = true;
        if (iter !== PBKDF2_ITERATIONS || raw.version !== VAULT_VERSION) {
          writeLocal('vaultV2', oldVaultStr);
          if (iter !== PBKDF2_ITERATIONS) cryptoKey = await deriveKey(pw, salt, PBKDF2_ITERATIONS);
          await persistVault();
        }
        saveIterations(PBKDF2_ITERATIONS);
        break;
      } catch {
        cryptoKey = null;
      }
    }
    if (!unlocked) {
      lockBusy(false);
      lockPassword.value = '';
      lockError.textContent = '密码错误';
      lockError.classList.remove('hidden');
      return;
    }
  }
  lockPassword.value = '';
  lockConfirm.value = '';
  selectedId = null;
  enterApp();
}

function enterApp() {
  lockScreen.classList.add('hidden');
  runBoot(() => {
    appScreen.classList.remove('hidden');
    applySessionPrefs();
    renderAll();
    SFX.unlock();
    resetIdle();
  });
}

function applySessionPrefs() {
  const st = Object.assign({ autoLock: 0, sound: 'on', fx: 'on' }, getSettings());
  soundEnabled = st.sound !== 'off';
  fxEnabled = st.fx !== 'off';
  syncSoundUI();
  FX.setEnabled(fxEnabled);
}

function syncSoundUI() {
  const b = $('sound-toggle-btn');
  if (b) b.textContent = 'SOUND: ' + (soundEnabled ? 'ON' : 'OFF');
  if (setSound) setSound.value = soundEnabled ? 'on' : 'off';
}

function lockNow() {
  clearTimeout(idleTimer);
  SFX.lock();
  cryptoKey = null;
  entries = [];
  revealSet.clear();
  selectedId = null;
  editingEntryId = null;
  searchInput.value = '';
  activeView = 'all';
  closeAllModals();
  closePalette();
  appScreen.classList.add('hidden');
  detailPanel.classList.remove('open');
  lockScreen.classList.remove('hidden');
  updateLockScreen();
  lockPassword.focus();
}

let idleTimer = null;
function resetIdle() {
  clearTimeout(idleTimer);
  const minutes = Number(getSettings().autoLock) || 0;
  if (!minutes) return;
  idleTimer = setTimeout(lockNow, minutes * 60000);
}

function findEntry(id) {
  return entries.find((en) => en.id === id);
}

function entryHaystack(e) {
  const parts = [e.title, TYPES[e.type] ? TYPES[e.type].tag : '', e.metadata.description, e.metadata.tags.join(' ')];
  for (const f of e.fields) {
    parts.push(f.name);
    if (Array.isArray(f.value)) {
      for (const it of f.value) {
        if (typeof it === 'string') parts.push(it);
        else parts.push(it.label || '', it.key || '', it.notes || '', it.name || '');
      }
    } else if (f.value != null) {
      parts.push(String(f.value));
    }
  }
  return parts.join(' ').toLowerCase();
}

function visibleEntries() {
  const q = searchInput.value.trim().toLowerCase();
  let list = entries;
  if (activeView !== 'all') list = list.filter((en) => en.type === activeView);
  if (q) list = list.filter((en) => entryHaystack(en).includes(q));
  return [...list].sort((a, b) => (b.metadata.favorite ? 1 : 0) - (a.metadata.favorite ? 1 : 0));
}

function renderNavCounts() {
  const n = { all: entries.length, api: 0, account: 0, note: 0 };
  entries.forEach((en) => { if (n[en.type] != null) n[en.type]++; });
  $('c-all').textContent = n.all;
  $('c-api').textContent = n.api;
  $('c-account').textContent = n.account;
  $('c-note').textContent = n.note;
}

function renderToolbarCount(listLen) {
  countEl.innerHTML = `<b>${listLen}</b> ENTRIES`;
}

function entryItemHtml(e, i) {
  const sel = e.id === selectedId ? ' selected' : '';
  const meta = TYPES[e.type] || TYPES.note;
  let stat = '';
  if (e.type === 'api') {
    const kf = getField(e, 'API Keys');
    const mf = getField(e, 'Models');
    const nk = Array.isArray(kf && kf.value) ? kf.value.length : 0;
    const nm = Array.isArray(mf && mf.value) ? mf.value.length : 0;
    stat = `${nk} KEYS · ${nm} MODELS`;
  } else if (e.type === 'account') {
    stat = `${e.fields.filter((f) => (typeof f.value === 'string' ? f.value.trim() : true)).length} FIELDS`;
  } else {
    const cf = getField(e, 'Content');
    const len = cf && typeof cf.value === 'string' ? cf.value.replace(/\s/g, '').length : 0;
    stat = `${len} CHARS`;
  }
  return `<div class="entry-item${sel}" data-id="${e.id}" style="animation-delay:${Math.min(i * 35, 240)}ms">
    <div class="e-row1">
      <span class="e-type ${meta.cls}">${meta.tag}</span>
      <span class="e-title">${escapeHtml(e.title)}</span>
      ${e.metadata.favorite ? '<span class="e-fav">★</span>' : ''}
      <button type="button" class="icon-btn drag-handle" draggable="true" data-drag="${e.id}" title="拖动到顶部">${SVG.grip}</button>
    </div>
    <div class="e-path">BLACKICE://${escapeHtml(slugOf(e.title))}</div>
    <div class="e-meta">${stat} · UPD ${fmtDate(e.metadata.updatedAt)}</div>
  </div>`;
}

function secretKey(eid, fIdx, rIdx) {
  return `${eid}:${fIdx}:${rIdx == null ? -1 : rIdx}`;
}

function fieldRowHtml(e, f, fIdx) {
  const name = escapeHtml(f.name.toUpperCase());
  const wide = ['textarea'].includes(f.type) || f.type === 'keys' || f.type === 'list' ? ' wide' : '';
  let body = '';
  if (f.type === 'keys') {
    const rows = Array.isArray(f.value) ? f.value : [];
    body = rows.length
      ? rows.map((k, r) => {
          const rk = secretKey(e.id, fIdx, r);
          const shown = revealSet.has(rk) ? (k.key || '') : maskSecret(k.key);
          return `<div class="key-block">
            <div class="key-item">
              <span class="key-lab">${escapeHtml(k.label || 'KEY')}</span>
              <span class="val-text${revealSet.has(rk) ? '' : ' secret-hidden'}">${escapeHtml(shown)}</span>
              <button type="button" class="icon-btn" data-a="toggle-secret" data-f="${fIdx}" data-r="${r}" title="显示/隐藏" aria-pressed="${revealSet.has(rk)}">${eyeSvg(revealSet.has(rk))}</button>
              <button type="button" class="icon-btn" data-a="copy-secret" data-f="${fIdx}" data-r="${r}" title="复制密钥">${SVG.copy}</button>
            </div>
            ${k.notes ? `<div class="key-note">${escapeHtml(k.notes)}</div>` : ''}
          </div>`;
        }).join('')
      : '<span class="secret-hidden">// EMPTY</span>';
  } else if (f.type === 'list') {
    const rows = Array.isArray(f.value) ? f.value : [];
    body = rows.length
      ? rows.map((m, r) => `<span class="chip tappable" data-a="copy-model" data-f="${fIdx}" data-r="${r}" title="${escapeHtml(m.notes || '')}点击复制">${escapeHtml(m.name)} ${SVG.copy}</span>`).join(' ')
      : '<span class="secret-hidden">// EMPTY</span>';
  } else if (f.type === 'password') {
    const rk = secretKey(e.id, fIdx, -1);
    const shown = revealSet.has(rk) ? String(f.value || '') : maskSecret(f.value);
    body = `<span class="val-text${revealSet.has(rk) ? '' : ' secret-hidden'}">${escapeHtml(shown || '// EMPTY')}</span>
      <button type="button" class="icon-btn" data-a="toggle-secret" data-f="${fIdx}" title="显示/隐藏" aria-pressed="${revealSet.has(rk)}">${eyeSvg(revealSet.has(rk))}</button>
      <button type="button" class="icon-btn" data-a="copy-field" data-f="${fIdx}" title="复制">${SVG.copy}</button>`;
  } else if (f.type === 'url') {
    const v = String(f.value || '');
    body = v
      ? `<a href="${escapeHtml(v)}" target="_blank" rel="noopener noreferrer">${escapeHtml(v)}</a>
         <button type="button" class="icon-btn" data-a="copy-field" data-f="${fIdx}" title="复制链接">${SVG.copy}</button>`
      : '<span class="secret-hidden">// EMPTY</span>';
  } else if (f.type === 'textarea') {
    body = `<pre>${escapeHtml(String(f.value || '') || '// EMPTY')}</pre>`;
  } else {
    body = `<span class="val-text">${escapeHtml(String(f.value || '') || '// EMPTY')}</span>
      <button type="button" class="icon-btn" data-a="copy-field" data-f="${fIdx}" title="复制">${SVG.copy}</button>`;
  }
  return `<div class="d-field${wide}">
    <div class="d-name">${name}</div>
    <div class="d-value${f.type === 'list' ? ' chips-wrap' : ''}">${body}</div>
  </div>`;
}

function renderDetail() {
  const e = findEntry(selectedId);
  if (!e) {
    detailPanel.innerHTML = `<div class="d-empty">
      <p>NO ENTRY SELECTED</p>
      <p>从左侧列表选择条目</p>
      <p>CTRL K 打开命令面板</p>
    </div>`;
    return;
  }
  const meta = TYPES[e.type] || TYPES.note;
  const tagsHtml = e.metadata.tags.length
    ? `<div class="d-tags">${e.metadata.tags.map((t) => `<span class="chip">#${escapeHtml(t)}</span>`).join('')}</div>`
    : '';
  const descHtml = e.metadata.description
    ? `<div class="d-grid" style="margin-top:12px"><div class="d-field wide"><div class="d-name">DESCRIPTION</div><div class="d-value"><pre>${escapeHtml(e.metadata.description)}</pre></div></div></div>`
    : '';
  const fieldsHtml = e.fields.map((f, i) => fieldRowHtml(e, f, i)).join('');
  detailPanel.innerHTML = `
    <div class="d-head">
      <button type="button" class="back-btn" data-a="back">← BACK TO LIST</button>
      <div class="d-path">BLACKICE://${escapeHtml(slugOf(e.title))}</div>
      <div class="d-title-row">
        <h2 class="d-title">${escapeHtml(e.title)}</h2>
        <button type="button" class="icon-btn" data-a="fav" title="收藏置顶" aria-pressed="${!!e.metadata.favorite}" style="${e.metadata.favorite ? 'color:var(--yellow)' : ''}">${SVG.star}</button>
        <div class="d-actions">
          <button type="button" class="btn-mini" data-a="edit">EDIT</button>
          <button type="button" class="btn-mini danger" data-a="delete">DELETE</button>
        </div>
      </div>
      <div class="d-tags"><span class="chip ${meta.cls}" style="background:none;border-color:var(--border-w);color:${meta.cls === 't-api' ? 'var(--yellow)' : meta.cls === 't-account' ? 'var(--blue)' : 'var(--red)'}">${meta.tag}</span><span class="chip">STATUS: ACTIVE</span><span class="chip">UPDATED ${fmtDate(e.metadata.updatedAt)}</span><span class="chip">CREATED ${fmtDate(e.metadata.createdAt)}</span>${e.metadata.tags.map((t) => `<span class="chip">#${escapeHtml(t)}</span>`).join('')}</div>
    </div>
    <div class="d-grid">${fieldsHtml}</div>
    ${descHtml}
  `;
}

function renderList() {
  const list = visibleEntries();
  renderToolbarCount(list.length);
  const items = list.map(entryItemHtml).join('');
  const empty = $('empty-state');
  if (!list.length) {
    emptyText.textContent = searchInput.value.trim()
      ? '> NO MATCH IN VAULT'
      : '> VAULT EMPTY —— 点击右上角 NEW ENTRY 写入第一条数据';
    empty.classList.remove('hidden');
  } else {
    empty.classList.add('hidden');
  }
  const rows = items ? items : '';
  entryListEl.innerHTML = rows;
  entryListEl.appendChild(empty);
}

function renderAll() {
  renderNavCounts();
  renderList();
  renderDetail();
}

document.querySelectorAll('.nav-item[data-view]').forEach((btn) => {
  btn.addEventListener('click', () => {
    activeView = btn.dataset.view;
    document.querySelectorAll('.nav-item[data-view]').forEach((b) => b.classList.toggle('active', b === btn));
    renderList();
  });
});
$('nav-security').addEventListener('click', () => { pwdForm.reset(); securityModal.classList.remove('hidden'); pOldFocus(); });
$('nav-backup').addEventListener('click', () => { backupModal.classList.remove('hidden'); });
$('nav-settings').addEventListener('click', openSettings);

let _pOldRef = null;
function pOldFocus() {
  _pOldRef = _pOldRef || $('p-old');
  if (_pOldRef) _pOldRef.focus();
}

function openSettings() {
  const st = Object.assign({ autoLock: 0, sound: 'on', fx: 'on' }, getSettings());
  autoLockSel.value = String(st.autoLock || 0);
  setSound.value = soundEnabled ? 'on' : 'off';
  setFx.value = fxEnabled ? 'on' : 'off';
  settingsModal.classList.remove('hidden');
}

$('add-btn').addEventListener('click', () => openEntryModal(null, activeView === 'all' ? 'api' : activeView));

function editorFieldHtml(name, ftype, value, idx) {
  const fid = `ef-${idx}`;
  const label = `<label for="${fid}">${escapeHtml(name)}</label>`;
  if (ftype === 'textarea') {
    return `<div class="field">${label}<textarea id="${fid}" data-fname="${escapeHtml(name)}" rows="4">${escapeHtml(value || '')}</textarea></div>`;
  }
  if (ftype === 'password') {
    return `<div class="field">${label}<div class="password-wrap"><input type="password" id="${fid}" data-fname="${escapeHtml(name)}" autocomplete="new-password" value="${escapeHtml(value || '')}">
      <button type="button" class="icon-btn" data-toggle="${fid}" title="显示/隐藏">${eyeSvg(false)}</button></div></div>`;
  }
  const ph = ftype === 'url' ? 'https://…' : '';
  return `<div class="field">${label}<input type="text" id="${fid}" data-fname="${escapeHtml(name)}" data-ftype="${ftype}" autocomplete="off" placeholder="${ph}" value="${escapeHtml(value || '')}"></div>`;
}

function rebuildEditorFields(type, entry) {
  const schema = SCHEMAS[type] || SCHEMAS.note;
  let html = '';
  schema.forEach(([name, ftype], idx) => {
    const cur = entry ? getField(entry, name) : null;
    const val = cur ? cur.value : (ftype === 'keys' || ftype === 'list' ? [] : '');
    if (ftype === 'keys') {
      const rows = Array.isArray(val) ? val : [{ label: '', key: '', notes: '' }];
      html += `<div class="field"><label>${escapeHtml(name)}</label><div class="row-editor" data-editor="keys" data-fname="${escapeHtml(name)}">
        ${rows.map((k) => `<div class="kv-row has-notes">
          <input type="text" class="k-label" placeholder="LABEL（如 主账号）" value="${escapeHtml(k.label || '')}">
          <input type="password" class="k-key" placeholder="KEY VALUE" value="${escapeHtml(k.key || '')}">
          <input type="text" class="k-notes" placeholder="备注" value="${escapeHtml(k.notes || '')}">
          <button type="button" class="icon-btn row-del" title="删除此行">${SVG.trash}</button>
        </div>`).join('')}
        <button type="button" class="btn-mini editor-add" data-addkey>+ ADD KEY</button>
      </div></div>`;
    } else if (ftype === 'list') {
      const rows = Array.isArray(val) ? val : [];
      html += `<div class="field"><label>${escapeHtml(name)}</label><div class="row-editor" data-editor="list" data-fname="${escapeHtml(name)}">
        ${rows.map((m) => `<div class="kv-row has-notes">
          <input type="text" class="m-name" placeholder="MODEL NAME" value="${escapeHtml(m.name || '')}">
          <input type="text" class="m-notes" placeholder="备注" value="${escapeHtml(m.notes || '')}">
          <button type="button" class="icon-btn row-del" title="删除此行">${SVG.trash}</button>
        </div>`).join('')}
        <button type="button" class="btn-mini editor-add" data-addmodel>+ ADD MODEL</button>
      </div></div>`;
    } else {
      html += editorFieldHtml(name, ftype, cur ? cur.value : '', idx);
    }
  });
  entryFields.innerHTML = html;
}

function openEntryModal(id, forceType) {
  editingEntryId = id || null;
  const e = id ? findEntry(id) : null;
  entryModalTitle.textContent = e ? 'EDIT ENTRY' : 'NEW ENTRY';
  entryTypeWrap.classList.toggle('hidden', !!e);
  eType.value = e ? e.type : (forceType || 'api');
  eTitle.value = e ? e.title : '';
  eTags.value = e ? e.metadata.tags.join(', ') : '';
  eDesc.value = e ? e.metadata.description : '';
  $('entry-desc-wrap').classList.toggle('hidden', eType.value === 'note');
  rebuildEditorFields(e ? e.type : eType.value, e || null);
  entryModal.classList.remove('hidden');
  eTitle.focus();
}

eType.addEventListener('change', () => {
  $('entry-desc-wrap').classList.toggle('hidden', eType.value === 'note');
  rebuildEditorFields(eType.value, null);
});

entryFields.addEventListener('click', (ev) => {
  const del = ev.target.closest('.row-del');
  if (del) {
    const row = del.closest('.kv-row');
    const ed = del.closest('.row-editor');
    if (ed.querySelectorAll('.kv-row').length > 1) row.remove();
    else row.querySelectorAll('input').forEach((i) => { i.value = ''; });
    return;
  }
  if (ev.target.closest('[data-addkey]')) {
    const ed = ev.target.closest('.row-editor');
    const div = document.createElement('div');
    div.className = 'kv-row has-notes';
    div.innerHTML = `<input type="text" class="k-label" placeholder="LABEL"><input type="password" class="k-key" placeholder="KEY VALUE"><input type="text" class="k-notes" placeholder="备注"><button type="button" class="icon-btn row-del" title="删除此行">${SVG.trash}</button>`;
    ed.insertBefore(div, ev.target.closest('[data-addkey]'));
    div.querySelector('.k-label').focus();
    return;
  }
  if (ev.target.closest('[data-addmodel]')) {
    const ed = ev.target.closest('.row-editor');
    const div = document.createElement('div');
    div.className = 'kv-row has-notes';
    div.innerHTML = `<input type="text" class="m-name" placeholder="MODEL NAME"><input type="text" class="m-notes" placeholder="备注"><button type="button" class="icon-btn row-del" title="删除此行">${SVG.trash}</button>`;
    ed.insertBefore(div, ev.target.closest('[data-addmodel]'));
    div.querySelector('.m-name').focus();
  }
});

function collectEditorFields(type) {
  const out = [];
  for (const [name, ftype] of SCHEMAS[type]) {
    if (ftype === 'keys') {
      const ed = entryFields.querySelector(`.row-editor[data-editor="keys"]`);
      const rows = ed ? [...ed.querySelectorAll('.kv-row')] : [];
      const val = rows.map((r) => ({
        id: genId(),
        label: r.querySelector('.k-label').value.trim(),
        key: r.querySelector('.k-key').value,
        notes: r.querySelector('.k-notes').value.trim()
      })).filter((k) => k.key || k.label);
      out.push({ name, type: 'keys', value: val });
    } else if (ftype === 'list') {
      const ed = entryFields.querySelector('.row-editor[data-editor="list"]');
      const rows = ed ? [...ed.querySelectorAll('.kv-row')] : [];
      const val = rows.map((r) => ({
        id: genId(),
        name: r.querySelector('.m-name').value.trim(),
        notes: r.querySelector('.m-notes').value.trim()
      })).filter((m) => m.name);
      out.push({ name, type: 'list', value: val });
    } else {
      const inp = entryFields.querySelector(`[data-fname="${CSS.escape(name)}"]`);
      let v = inp ? inp.value.trim() : '';
      if (ftype === 'url' && v) {
        const nv = normalizeUrl(v);
        if (!nv) {
          return { error: `${name}: 请输入有效的 HTTPS 地址` };
        }
        v = nv;
      }
      out.push({ name, type: ftype, value: v });
    }
  }
  return { fields: out };
}

entryForm.addEventListener('submit', (ev) => {
  ev.preventDefault();
  const title = eTitle.value.trim();
  if (!title) {
    toast('请填写标题', true);
    eTitle.focus();
    return;
  }
  const type = editingEntryId ? (findEntry(editingEntryId) || {}).type : eType.value;
  const res = collectEditorFields(type || 'note');
  if (res.error) {
    toast(res.error, true);
    return;
  }
  const now = new Date().toISOString();
  const tags = eTags.value.split(/[,，]/).map((t) => t.trim()).filter(Boolean);
  const description = eDesc.value.trim();
  if (editingEntryId) {
    const e = findEntry(editingEntryId);
    if (e) {
      e.title = title;
      e.metadata.tags = tags;
      e.metadata.description = description;
      e.metadata.updatedAt = now;
      e.fields = res.fields;
    }
  } else {
    const ne = makeEntry(eType.value, title);
    ne.metadata.tags = tags;
    ne.metadata.description = description;
    ne.fields = res.fields;
    entries.unshift(ne);
    selectedId = ne.id;
  }
  const wasEdit = !!editingEntryId;
  editingEntryId = null;
  persistVault().then(() => {
    entryModal.classList.add('hidden');
    entryForm.reset();
    renderAll();
    toast(wasEdit ? '已保存' : '条目已写入');
  });
});

detailPanel.addEventListener('click', async (ev) => {
  const el = ev.target.closest('[data-a]');
  if (!el) return;
  const e = findEntry(selectedId);
  if (!e) return;
  const a = el.dataset.a;
  if (a === 'back') {
    detailPanel.classList.remove('open');
    return;
  }
  if (a === 'edit') {
    openEntryModal(e.id);
    return;
  }
  if (a === 'delete') {
    openConfirm(`确定删除「${e.title}」吗？该操作不可恢复。`, () => {
      entries = entries.filter((x) => x.id !== e.id);
      if (selectedId === e.id) selectedId = null;
      persistVault().then(() => {
        renderAll();
        toast('条目已删除');
      });
    });
    return;
  }
  if (a === 'fav') {
    e.metadata.favorite = !e.metadata.favorite;
    e.metadata.updatedAt = new Date().toISOString();
    await persistVault();
    renderAll();
    return;
  }
  const fIdx = Number(el.dataset.f);
  const f = e.fields[fIdx];
  if (!f) return;
  if (a === 'toggle-secret') {
    const rk = secretKey(e.id, fIdx, el.dataset.r);
    revealSet.has(rk) ? revealSet.delete(rk) : revealSet.add(rk);
    renderDetail();
    SFX.tick();
    return;
  }
  if (a === 'copy-field' || a === 'copy-secret') {
    let v = f.value;
    if (el.dataset.r != null && Array.isArray(f.value)) v = f.value[Number(el.dataset.r)];
    v = typeof v === 'string' ? v : (v && v.key) || '';
    const ok = await copyText(v);
    flashCheck(el);
    toast(ok ? '已复制到剪贴板' : '复制失败', !ok);
    return;
  }
  if (a === 'copy-model') {
    const m = Array.isArray(f.value) && f.value[Number(el.dataset.r)];
    if (!m) return;
    const ok = await copyText(m.name);
    flashCheck(el);
    toast(ok ? '模型名已复制' : '复制失败', !ok);
  }
});

entryListEl.addEventListener('click', (ev) => {
  if (ev.target.closest('[data-drag]')) return;
  const item = ev.target.closest('.entry-item');
  if (!item) return;
  selectedId = item.dataset.id;
  renderList();
  renderDetail();
  if (window.matchMedia('(max-width: 860px)').matches) {
    detailPanel.classList.add('open');
    detailPanel.scrollTop = 0;
  }
  SFX.click();
});

entryListEl.addEventListener('dragstart', (ev) => {
  const h = ev.target.closest('[data-drag]');
  if (!h) { ev.preventDefault(); return; }
  dragId = h.dataset.drag;
  ev.dataTransfer.effectAllowed = 'move';
  try { ev.dataTransfer.setData('text/plain', dragId); } catch (err) {}
  h.closest('.entry-item').classList.add('dragging');
});
entryListEl.addEventListener('dragover', (ev) => {
  if (!dragId) return;
  ev.preventDefault();
  ev.dataTransfer.dropEffect = 'move';
});
entryListEl.addEventListener('drop', (ev) => {
  ev.preventDefault();
  const item = ev.target.closest('.entry-item');
  const fromId = dragId;
  dragId = null;
  entryListEl.querySelectorAll('.dragging').forEach((el) => el.classList.remove('dragging'));
  if (!item || !fromId) return;
  const toId = item.dataset.id;
  if (!toId || toId === fromId) return;
  const from = entries.findIndex((x) => x.id === fromId);
  if (from < 0) return;
  const [moved] = entries.splice(from, 1);
  const to = entries.findIndex((x) => x.id === toId);
  entries.splice(to, 0, moved);
  persistVault().then(() => {
    renderAll();
    toast('排序已保存');
  });
});
entryListEl.addEventListener('dragend', () => {
  dragId = null;
  entryListEl.querySelectorAll('.dragging').forEach((el) => el.classList.remove('dragging'));
});

function doExport() {
  const salt = readLocal('salt');
  const vault = readLocal('vault');
  if (!salt || !vault) return;
  const data = exportPayload(salt, JSON.parse(vault));
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  const d = new Date();
  a.download = `${APP_NAME}-backup-${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, '0')}${String(d.getDate()).padStart(2, '0')}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
  toast('备份已导出，请妥善保管文件与主密码');
}

async function handleImport(file) {
  if (!file) return;
  try {
    const data = parseImportPayload(JSON.parse(await file.text()));
    if (!data) throw new Error('bad');
    openConfirm('导入将覆盖当前全部数据并锁定应用，确定继续？', () => {
      writeLocal('salt', data.salt);
      writeLocal('vault', JSON.stringify(data.vault));
      removeLocal('iter');
      if (data.iter > 0) saveIterations(data.iter);
      lockNow();
      toast('已导入，使用备份库的主密码解锁');
    });
  } catch {
    toast('备份文件无效', true);
  }
}

async function handlePwdSubmit(ev) {
  ev.preventDefault();
  const oldPw = $('p-old').value;
  const newPw = $('p-new').value;
  const confirmPw = $('p-confirm').value;
  if (!oldPw) { toast('请输入当前密码', true); return; }
  if (newPw.length < 8) { toast('新密码至少 8 位', true); return; }
  if (newPw !== confirmPw) { toast('两次输入的新密码不一致', true); return; }
  const oldSalt = currentSalt();
  const storedIter = getStoredIterations();
  const candidates = storedIter ? [storedIter] : [PBKDF2_ITERATIONS, LEGACY_ITERATIONS];
  let verified = false;
  for (const iter of candidates) {
    try {
      const k = await deriveKey(oldPw, oldSalt, iter);
      await decryptData(JSON.parse(readLocal('vault')), k);
      verified = true;
      break;
    } catch {}
  }
  if (!verified) { toast('当前密码错误', true); return; }
  const salt = crypto.getRandomValues(new Uint8Array(16));
  writeLocal('salt', b64encode(salt));
  saveIterations(PBKDF2_ITERATIONS);
  cryptoKey = await deriveKey(newPw, salt, PBKDF2_ITERATIONS);
  await persistVault();
  securityModal.classList.add('hidden');
  toast('主密码已修改');
}

let confirmCallback = null;
function openConfirm(message, onOk) {
  confirmCallback = onOk;
  $('confirm-message').textContent = message;
  $('confirm-modal').classList.remove('hidden');
  $('confirm-ok').focus();
}
$('confirm-cancel').addEventListener('click', () => {
  $('confirm-modal').classList.add('hidden');
  confirmCallback = null;
});
$('confirm-ok').addEventListener('click', () => {
  $('confirm-modal').classList.add('hidden');
  if (typeof confirmCallback === 'function') confirmCallback();
  confirmCallback = null;
});

function closePalette() {
  palBackdrop.classList.add('hidden');
}
function paletteCommands(q) {
  const cmds = [
    { tag: 'CMD', name: 'Search Vault', run: () => { closePalette(); searchInput.focus(); searchInput.select(); } },
    { tag: 'CMD', name: 'New Entry · API', run: () => { closePalette(); openEntryModal(null, 'api'); } },
    { tag: 'CMD', name: 'New Entry · Account', run: () => { closePalette(); openEntryModal(null, 'account'); } },
    { tag: 'CMD', name: 'New Entry · Secure Note', run: () => { closePalette(); openEntryModal(null, 'note'); } },
    { tag: 'SYS', name: 'Lock Vault', run: () => { closePalette(); lockNow(); } },
    { tag: 'SYS', name: 'Export Backup', run: () => { closePalette(); doExport(); } },
    { tag: 'SYS', name: 'Security · Change Password', run: () => { closePalette(); pwdForm.reset(); securityModal.classList.remove('hidden'); pOldFocus(); } },
    { tag: 'SYS', name: 'Backup', run: () => { closePalette(); backupModal.classList.remove('hidden'); } },
    { tag: 'SYS', name: 'Settings', run: () => { closePalette(); openSettings(); } }
  ];
  const needle = (q || '').toLowerCase();
  const cmdHits = cmds.filter((c) => c.name.toLowerCase().includes(needle));
  const entryHits = entries
    .filter((en) => needle && entryHaystack(en).includes(needle))
    .slice(0, 6)
    .map((en) => ({
      tag: (TYPES[en.type] || TYPES.note).tag.slice(0, 3),
      name: en.title,
      run: () => { closePalette(); selectedId = en.id; activeView = 'all'; renderAll(); }
    }));
  return [...cmdHits, ...entryHits];
}
function renderPalList(q) {
  palItems = paletteCommands(q);
  if (!palItems.length) {
    palList.innerHTML = '<div class="pal-empty">// NO MATCH</div>';
    return;
  }
  palIndex = Math.min(palIndex, palItems.length - 1);
  palList.innerHTML = palItems.map((it, i) =>
    `<div class="pal-item${i === palIndex ? ' active' : ''}" data-i="${i}"><span class="pi-tag">${it.tag}</span>${escapeHtml(it.name)}</div>`
  ).join('');
}
function openPalette() {
  palBackdrop.classList.remove('hidden');
  palInput.value = '';
  palIndex = 0;
  renderPalList('');
  palInput.focus();
}
palInput.addEventListener('input', () => {
  palIndex = 0;
  renderPalList(palInput.value.trim());
});
palList.addEventListener('click', (ev) => {
  const item = ev.target.closest('.pal-item');
  if (item && palItems[Number(item.dataset.i)]) palItems[Number(item.dataset.i)].run();
});
palInput.addEventListener('keydown', (ev) => {
  if (ev.key === 'ArrowDown') { ev.preventDefault(); palIndex = (palIndex + 1) % Math.max(1, palItems.length); renderPalList(palInput.value.trim()); }
  else if (ev.key === 'ArrowUp') { ev.preventDefault(); palIndex = (palIndex - 1 + palItems.length) % Math.max(1, palItems.length); renderPalList(palInput.value.trim()); }
  else if (ev.key === 'Enter') { ev.preventDefault(); if (palItems[palIndex]) palItems[palIndex].run(); }
});

function closeAllModals() {
  document.querySelectorAll('.modal-backdrop').forEach((m) => m.classList.add('hidden'));
  confirmCallback = null;
}

let searchTimer = null;

function init() {
  if (!(window.crypto && window.crypto.subtle)) {
    lockHint.textContent = '当前浏览器不支持 Web Crypto API，请使用新版 Chrome / Edge / Firefox 打开';
    lockForm.classList.add('hidden');
    return;
  }
  const required = ['sidebar', 'entry-list', 'detail-panel', 'search-input', 'count', 'add-btn', 'export-btn', 'auto-lock', 'import-file', 'entry-form', 'pwd-form'];
  const missing = required.filter((id) => !$(id) && !document.querySelector('.' + id));
  if (missing.length) {
    lockHint.textContent = '页面资源加载异常（缺少：' + missing.join(', ') + '）。请刷新重试。';
    lockForm.classList.add('hidden');
    return;
  }

  updateLockScreen();
  scrambleText(document.querySelector('#lock-screen h1'), '黑冰匣', 750);
  lockPassword.focus();

  lockForm.addEventListener('submit', handleUnlock);
  $('lock-btn-top').addEventListener('click', lockNow);
  $('sound-toggle-btn').addEventListener('click', () => {
    soundEnabled = !soundEnabled;
    const st = getSettings();
    st.sound = soundEnabled ? 'on' : 'off';
    saveSettings(st);
    syncSoundUI();
    toast(soundEnabled ? '音效已开启' : '音效已关闭', false, soundEnabled);
    if (soundEnabled) setTimeout(() => SFX.unlock(), 260);
  });

  let st0 = Object.assign({ autoLock: 0, sound: 'on', fx: 'on' }, getSettings());
  soundEnabled = st0.sound !== 'off';
  fxEnabled = st0.fx !== 'off';
  syncSoundUI();
  FX.setEnabled(fxEnabled);

  searchInput.addEventListener('input', () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(renderList, 120);
  });

  importFile.addEventListener('change', () => {
    const file = importFile.files[0];
    importFile.value = '';
    handleImport(file);
  });
  $('export-btn').addEventListener('click', doExport);

  autoLockSel.addEventListener('change', () => {
    const s = getSettings();
    s.autoLock = Number(autoLockSel.value) || 0;
    saveSettings(s);
    resetIdle();
    toast('设置已保存');
  });
  setSound.addEventListener('change', () => {
    soundEnabled = setSound.value !== 'off';
    const s = getSettings();
    s.sound = setSound.value;
    saveSettings(s);
    syncSoundUI();
  });
  setFx.addEventListener('change', () => {
    fxEnabled = setFx.value !== 'off';
    const s = getSettings();
    s.fx = setFx.value;
    saveSettings(s);
    FX.setEnabled(fxEnabled);
  });
  pwdForm.addEventListener('submit', handlePwdSubmit);

  document.addEventListener('keydown', (ev) => {
    if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === 'k') {
      ev.preventDefault();
      if (cryptoKey) {
        palBackdrop.classList.contains('hidden') ? openPalette() : closePalette();
      }
      return;
    }
    if (ev.key === 'Escape') {
      if (!palBackdrop.classList.contains('hidden')) { closePalette(); return; }
      const anyModal = document.querySelector('.modal-backdrop:not(.hidden)');
      if (anyModal) { closeAllModals(); return; }
      if (document.activeElement === searchInput && searchInput.value) {
        searchInput.value = '';
        renderList();
        searchInput.blur();
        return;
      }
      if (detailPanel.classList.contains('open')) detailPanel.classList.remove('open');
    }
    if (ev.key.toLowerCase() === 'l' && cryptoKey && !ev.ctrlKey && !ev.metaKey && !ev.altKey) {
      const ae = document.activeElement;
      const typing = ae && (ae.tagName === 'INPUT' || ae.tagName === 'TEXTAREA' || ae.tagName === 'SELECT');
      if (!typing) lockNow();
    }
    if (ev.key === 'Tab') {
      const open = document.querySelector('.modal-backdrop:not(.hidden), .palette-backdrop:not(.hidden)');
      if (!open) return;
      const f = open.querySelectorAll('button, input, select, textarea, [tabindex]');
      if (!f.length) return;
      const first = f[0], last = f[f.length - 1];
      if (ev.shiftKey && document.activeElement === first) { ev.preventDefault(); last.focus(); }
      else if (!ev.shiftKey && document.activeElement === last) { ev.preventDefault(); first.focus(); }
    }
  });

  ['mousemove', 'keydown', 'click', 'scroll', 'touchstart'].forEach((evtName) => {
    document.addEventListener(evtName, () => {
      if (cryptoKey) resetIdle();
    });
  });

  document.addEventListener('click', (ev) => {
    const b = ev.target.closest('[data-toggle]');
    if (b) togglePassword(b.dataset.toggle, b);
  });
}

FX.init();
init();
