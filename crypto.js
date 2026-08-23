export const PBKDF2_ITERATIONS = 200000;
export const LEGACY_ITERATIONS = 100000;

export function b64encode(buf) {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

export function b64decode(str) {
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes;
}

export async function deriveKey(password, salt, iterations) {
  const iter = iterations || PBKDF2_ITERATIONS;
  const enc = new TextEncoder();
  const base = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encryptData(key, plainObj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new TextEncoder().encode(JSON.stringify(plainObj));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  return { iv: b64encode(iv), ct: b64encode(ct) };
}

export async function decryptData(vault, key) {
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64decode(vault.iv) },
    key,
    b64decode(vault.ct)
  );
  return JSON.parse(new TextDecoder().decode(plain));
}
