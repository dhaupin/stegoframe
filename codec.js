/**
 * Stegoframe Codec — Encryption + Carrier Encoding
 * 
 * Single source of truth for all crypto/codec operations.
 * Works in both browser (Web Crypto API) and Node.js (crypto module).
 * 
 * @flow  plaintext → AES-GCM-256 encrypt → pack frame → embed in carrier → data URL
 *        data URL  → extract frame → unpack → decrypt → plaintext
 */

// ── Constants ─────────────────────────────────────────────────────────────────

const _PI = 100_000;  // PBKDF2 iterations
const _SB = 16;       // salt bytes
const _IB = 12;       // AES-GCM IV bytes
const _BRN = "BRN:";  // packet prefix
const _VR = "1.0";    // version

const Enc = Object.freeze({ SVG: "svg", LSB: "lsb" });

// ── Environment detection ──────────────────────────────────────────────────────

const isNode = typeof window === 'undefined';

// ── Node.js crypto lazy import ────────────────────────────────────────────────

let _nodeCrypto = null;
async function getNodeCrypto() {
  if (!_nodeCrypto) {
    _nodeCrypto = await import('node:crypto');
  }
  return _nodeCrypto;
}

// ── Room ID derivation ────────────────────────────────────────────────────────

const _ROOM_SALT = "stegoframe-v1";

async function deriveRoomId(passphrase) {
  const data = new TextEncoder().encode(passphrase + _ROOM_SALT);
  if (isNode) {
    const { createHash } = await getNodeCrypto();
    const hash = createHash('sha256').update(data).digest();
    const hex = Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
    return hex.substring(0, 6);
  }
  const hash = await crypto.subtle.digest("SHA-256", data);
  const hex = Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0')).join('');
  return hex.substring(0, 6);
}

// ── Random bytes ──────────────────────────────────────────────────────────────

async function getRandomValues(buf) {
  if (isNode) {
    const { randomBytes } = await getNodeCrypto();
    const bytes = randomBytes(buf.byteLength);
    buf.set(bytes);
    return buf;
  }
  return crypto.getRandomValues(buf);
}

// ── Key derivation ────────────────────────────────────────────────────────────

async function _dk(p, s) {
  if (isNode) {
    const { createHmac } = await getNodeCrypto();
    // PBKDF2-like key derivation using HMAC-SHA256
    let key = Buffer.from(p, 'utf8');
    const salt = Buffer.from(s);
    for (let i = 0; i < _PI; i++) {
      key = createHmac('sha256', key).update(salt).digest();
    }
    return key;
  }
  
  const k = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(p), { name: "PBKDF2" }, false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: s, iterations: _PI, hash: "SHA-256" },
    k, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );
}

// ── Hex encoding helpers ──────────────────────────────────────────────────────

function _toHex(buf) {
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

function _fromHex(hex) {
  const buf = new Uint8Array(hex.length / 2);
  for (let i = 0; i < buf.length; i++) {
    buf[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return buf;
}

// ── Encryption / Decryption ───────────────────────────────────────────────────

async function _ae(txt, p) {
  const s = new Uint8Array(_SB);
  const iv = new Uint8Array(_IB);
  await getRandomValues(s);
  await getRandomValues(iv);
  
  const ek = await _dk(p, s);
  
  if (isNode) {
    const { createCipheriv } = await getNodeCrypto();
    
    // Node.js: use crypto.createCipheriv with a derived key
    const key = ek; // Buffer
    const ivBuf = Buffer.from(iv);
    const cipher = createCipheriv('aes-256-gcm', key, ivBuf);
    const encrypted = Buffer.concat([cipher.update(txt, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    
    return _toHex(s) + ":" + _toHex(iv) + ":" + _toHex(authTag) + ":" + _toHex(encrypted);
  }
  
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, ek, new TextEncoder().encode(txt)
  );
  const ctArr = new Uint8Array(ct);
  const encrypted = ctArr.slice(0, ctArr.byteLength - 16);
  const authTag = ctArr.slice(ctArr.byteLength - 16);
  return _toHex(s) + ":" + _toHex(iv) + ":" + _toHex(authTag) + ":" + _toHex(encrypted);
}

async function _ad(d, p) {
  try {
    let hex = typeof d === 'string' ? d : _toHex(d);
    const parts = hex.split(":");
    if (parts.length !== 4) return null;
    const s = _fromHex(parts[0]);
    const iv = _fromHex(parts[1]);
    const authTag = _fromHex(parts[2]);
    const encrypted = _fromHex(parts[3]);
    const ek = await _dk(p, s);
    
    if (isNode) {
      const { createDecipheriv } = await getNodeCrypto();
      // createDecipheriv expects Buffer key and iv, and only the encrypted part (not authTag)
      const decipher = createDecipheriv('aes-256-gcm', ek, Buffer.from(iv));
      decipher.setAuthTag(Buffer.from(authTag));
      const decrypted = Buffer.concat([decipher.update(Buffer.from(encrypted)), decipher.final()]);
      return new TextDecoder().decode(decrypted);
    }
    
    // For Web Crypto: reconstruct GCM ciphertext format with authTag appended
    const ct = new Uint8Array(encrypted.byteLength + authTag.byteLength);
    ct.set(encrypted, 0);
    ct.set(authTag, encrypted.byteLength);
    return new TextDecoder().decode(
      await crypto.subtle.decrypt({ name: "AES-GCM", iv }, ek, ct)
    );
  } catch { return null; }
}

// ── Vant-compatible packet format ──────────────────────────────────────────────

function _pk(p) {
  return _BRN + "ENC:" + p;
}

function _up(b) {
  const s = typeof b === 'string' ? b : new TextDecoder().decode(b);
  if (s.startsWith(_BRN + "ENC:")) {
    return s.slice(_BRN.length + 4);
  }
  return null;
}

// ── Bit helpers ───────────────────────────────────────────────────────────────

function _b2B(bits) {
  // Convert array of 0/1 bits to Uint8Array
  const bytes = new Uint8Array(Math.ceil(bits.length / 8));
  for (let i = 0; i < bits.length; i++) {
    const byteIdx = Math.floor(i / 8);
    const bitIdx = 7 - (i % 8);
    bytes[byteIdx] |= (bits[i] & 1) << bitIdx;
  }
  return bytes;
}

// ── LSB carrier (browser only) ────────────────────────────────────────────────

function lsbWrite(payload) {
  if (isNode) throw new Error("lsbWrite is not available in Node.js");
  
  const pk = _pk(payload);
  const dim = Math.max(32, Math.ceil(Math.sqrt(pk.length * 8)));
  const cv = document.createElement("canvas");
  cv.width = cv.height = dim;
  const cx = cv.getContext("2d");
  const im = cx.createImageData(dim, dim);
  crypto.getRandomValues(im.data);
  for (let i = 3; i < im.data.length; i += 4) im.data[i] = 255;
  for (let i = 0; i < pk.length * 8; i++) {
    const bit = (pk.charCodeAt(Math.floor(i / 8)) >> (7 - (i % 8))) & 1;
    im.data[i * 4] = (im.data[i * 4] & 0xFE) | bit;
  }
  cx.putImageData(im, 0, 0);
  return cv.toDataURL("image/png");
}

async function lsbRead(url) {
  if (isNode) throw new Error("lsbRead is not available in Node.js");
  
  return new Promise(res => {
    const im = new Image();
    im.onload = () => {
      const cv = document.createElement("canvas");
      cv.width = im.width;
      cv.height = im.height;
      const cx = cv.getContext("2d");
      cx.drawImage(im, 0, 0);
      const d = cx.getImageData(0, 0, im.width, im.height).data;
      const hb = [];
      for (let i = 0; i < 64; i++) hb.push(d[i * 4] & 1);
      const hdr = _b2B(hb);
      if (!_up(hdr)) { res(null); return; }
      const l = (hdr[4] << 24) | (hdr[5] << 16) | (hdr[6] << 8) | hdr[7];
      const tb = (8 + l) * 8;
      const ab = [];
      for (let i = 0; i < tb; i++) ab.push(d[i * 4] & 1);
      res(_up(_b2B(ab)));
    };
    im.onerror = () => res(null);
    im.src = url;
  });
}

// ── SVG carrier (browser only) ────────────────────────────────────────────────

function svgWrite(payload) {
  if (isNode) throw new Error("svgWrite is not available in Node.js");
  
  const b64 = btoa(_pk(payload));
  const h = Math.floor(Math.random() * 360);
  const h2 = (h + 137) % 360;
  const numEls = 4 + Math.floor(Math.random() * 5);
  const els = Array.from({ length: numEls }, (_, i) =>
    `<circle cx="${(8 + Math.random() * 84).toFixed(1)}" cy="${(8 + Math.random() * 84).toFixed(1)}" r="${(2 + Math.random() * 8).toFixed(1)}" fill="hsla(${(h + i * 43) % 360},45%,60%,0.1)"/>`
  ).join("");
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100" viewBox="0 0 100 100">`
    + `<desc data-f="${_VR}"/>`
    + `<brn:secret xmlns:brn="http://steganography.dev/brn">${b64}</brn:secret>`
    + `<defs><radialGradient id="g" cx="42%" cy="42%" r="62%">`
    + `<stop offset="0%" stop-color="hsl(${h},50%,62%)"/>`
    + `<stop offset="100%" stop-color="hsl(${h2},42%,18%)"/>`
    + `</radialGradient></defs><rect width="100" height="100" fill="url(#g)"/>${els}</svg>`;
  return "data:image/svg+xml;base64," + btoa(unescape(encodeURIComponent(svg)));
}

function svgRead(url) {
  if (isNode) throw new Error("svgRead is not available in Node.js");
  
  try {
    const raw = decodeURIComponent(escape(atob(url.split(",")[1])));
    const m = raw.match(/<brn:secret[^>]*>([A-Za-z0-9+/=]+)<\/brn:secret>/);
    if (m) return _up(atob(m[1]));
    return null;
  } catch { return null; }
}

// ── Codec public API ──────────────────────────────────────────────────────────

const Codec = {
  async encode(txt, pass, mode) {
    const e = await _ae(txt, pass);
    return mode === Enc.LSB ? lsbWrite(e) : svgWrite(e);
  },
  async decode(url, pass) {
    let r = svgRead(url);
    if (!r) r = await lsbRead(url);
    if (!r) return null;
    return _ad(r, pass);
  },
  sniff(url) {
    if (!url) return Enc.SVG;
    try {
      const raw = atob(url.split(",")[1]).slice(0, 128);
      if (raw.includes("<svg")) return Enc.SVG;
      if (raw.includes("PNG")) return Enc.LSB;
    } catch {}
    return Enc.LSB;
  },
};

// ── ES Module Exports ───────────────────────────────────────────────────────────

export {
  Codec,
  deriveRoomId,
  Enc,
  _PI, _SB, _IB, _BRN, _VR,
  _toHex, _fromHex,
  _pk, _up,
  _ae, _ad,
  _b2B,
  lsbWrite, lsbRead,
  svgWrite, svgRead,
};

// Also attach to window for browser <script> usage
if (typeof window !== 'undefined') {
  window.StegoframeCodec = {
    Codec,
    deriveRoomId,
    Enc,
    _PI, _SB, _IB, _BRN, _VR,
    _toHex, _fromHex,
    _pk, _up,
    _ae, _ad,
    _b2B,
  };
}
