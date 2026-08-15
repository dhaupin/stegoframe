/**
 * Stegoframe Codec — Encryption + Carrier Encoding
 * 
 * Single source of truth for all crypto/codec operations.
 * Works in both browser (Web Crypto API) and Node.js (crypto module).
 * 
 * @example
 * import { Codec } from './lib/codec.js';
 * const carrier = await Codec.encode('hello', 'secret', 'svg');
 * const plaintext = await Codec.decode(carrier, 'secret');
 */

const isNode = typeof window === 'undefined';

// ── Constants ─────────────────────────────────────────────────────────────────

const PBKDF2_ITERATIONS = 100_000;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const PACKET_PREFIX = "BRN:";
const VERSION = "1.0";

const Enc = Object.freeze({ SVG: "svg", LSB: "lsb" });

// ── Node.js crypto lazy import ────────────────────────────────────────────────

let _nodeCrypto = null;
async function getNodeCrypto() {
  if (!_nodeCrypto) {
    _nodeCrypto = await import('node:crypto');
  }
  return _nodeCrypto;
}

// ── Codec Class ────────────────────────────────────────────────────────────────

class Codec {
  // ── Room ID Derivation ──────────────────────────────────────────────────────

  static async deriveRoomId(passphrase) {
    const salt = "stegoframe-v1";
    const data = new TextEncoder().encode(passphrase + salt);
    
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

  // ── Key Derivation ──────────────────────────────────────────────────────────

  static async _deriveKey(passphrase, salt) {
    if (isNode) {
      const { createHmac } = await getNodeCrypto();
      let key = Buffer.from(passphrase, 'utf8');
      const saltBuf = Buffer.from(salt);
      for (let i = 0; i < PBKDF2_ITERATIONS; i++) {
        key = createHmac('sha256', key).update(saltBuf).digest();
      }
      return key;
    }
    
    const k = await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(passphrase), { name: "PBKDF2" }, false, ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
      k, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
    );
  }

  // ── Random Bytes ────────────────────────────────────────────────────────────

  static async _getRandomBytes(length) {
    if (isNode) {
      const { randomBytes } = await getNodeCrypto();
      return new Uint8Array(randomBytes(length));
    }
    return crypto.getRandomValues(new Uint8Array(length));
  }

  // ── Hex Encoding ────────────────────────────────────────────────────────────

  static _toHex(buf) {
    return Array.from(new Uint8Array(buf))
      .map(b => b.toString(16).padStart(2, '0')).join('');
  }

  static _fromHex(hex) {
    const buf = new Uint8Array(hex.length / 2);
    for (let i = 0; i < buf.length; i++) {
      buf[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return buf;
  }

  // ── Encryption / Decryption ─────────────────────────────────────────────────

  /**
   * Encrypt plaintext with AES-GCM-256
   * @param {string} plaintext - The text to encrypt
   * @param {string} passphrase - The encryption passphrase
   * @returns {Promise<string>} Hex string: salt:iv:authTag:encrypted
   */
  static async encrypt(plaintext, passphrase) {
    const salt = await this._getRandomBytes(SALT_BYTES);
    const iv = await this._getRandomBytes(IV_BYTES);
    const key = await this._deriveKey(passphrase, salt);

    if (isNode) {
      const { createCipheriv } = await getNodeCrypto();
      const cipher = createCipheriv('aes-256-gcm', key, Buffer.from(iv));
      const encrypted = Buffer.concat([
        cipher.update(plaintext, 'utf8'),
        cipher.final()
      ]);
      const authTag = cipher.getAuthTag();
      return this._toHex(salt) + ":" + this._toHex(iv) + ":" + 
             this._toHex(authTag) + ":" + this._toHex(encrypted);
    }

    const ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv }, key, new TextEncoder().encode(plaintext)
    );
    const ctArr = new Uint8Array(ct);
    const encrypted = ctArr.slice(0, ctArr.byteLength - 16);
    const authTag = ctArr.slice(ctArr.byteLength - 16);
    return this._toHex(salt) + ":" + this._toHex(iv) + ":" + 
           this._toHex(authTag) + ":" + this._toHex(encrypted);
  }

  /**
   * Decrypt ciphertext with AES-GCM-256
   * @param {string} ciphertext - Hex string: salt:iv:authTag:encrypted
   * @param {string} passphrase - The decryption passphrase
   * @returns {Promise<string|null>} Decrypted plaintext or null on failure
   */
  static async decrypt(ciphertext, passphrase) {
    try {
      const parts = ciphertext.split(":");
      if (parts.length !== 4) return null;
      
      const salt = this._fromHex(parts[0]);
      const iv = this._fromHex(parts[1]);
      const authTag = this._fromHex(parts[2]);
      const encrypted = this._fromHex(parts[3]);
      const key = await this._deriveKey(passphrase, salt);

      if (isNode) {
        const { createDecipheriv } = await getNodeCrypto();
        const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(iv));
        decipher.setAuthTag(Buffer.from(authTag));
        const decrypted = Buffer.concat([
          decipher.update(Buffer.from(encrypted)),
          decipher.final()
        ]);
        return new TextDecoder().decode(decrypted);
      }

      const ct = new Uint8Array(encrypted.byteLength + authTag.byteLength);
      ct.set(encrypted, 0);
      ct.set(authTag, encrypted.byteLength);
      return new TextDecoder().decode(
        await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct)
      );
    } catch {
      return null;
    }
  }

  // ── Packet Format ────────────────────────────────────────────────────────────

  static _pack(hexPayload) {
    return PACKET_PREFIX + "ENC:" + hexPayload;
  }

  static _unpack(data) {
    const s = typeof data === 'string' ? data : new TextDecoder().decode(data);
    if (s.startsWith(PACKET_PREFIX + "ENC:")) {
      return s.slice(PACKET_PREFIX.length + 4);
    }
    return null;
  }

  // ── Bit Conversion ──────────────────────────────────────────────────────────

  /**
   * Convert array of 0/1 bits to Uint8Array
   */
  static _bitsToBytes(bits) {
    const bytes = new Uint8Array(Math.ceil(bits.length / 8));
    for (let i = 0; i < bits.length; i++) {
      const byteIdx = Math.floor(i / 8);
      const bitIdx = 7 - (i % 8);
      bytes[byteIdx] |= (bits[i] & 1) << bitIdx;
    }
    return bytes;
  }

  // ── LSB Carrier (browser only) ───────────────────────────────────────────────

  /**
   * Encode payload into LSB of PNG carrier image
   * @param {string} hexPayload - Hex string payload to encode
   * @returns {string} Data URL of PNG carrier
   */
  static lsbWrite(hexPayload) {
    if (isNode) throw new Error("lsbWrite is not available in Node.js");
    
    const packed = this._pack(hexPayload);
    const dim = Math.max(32, Math.ceil(Math.sqrt(packed.length * 8)));
    const cv = document.createElement("canvas");
    cv.width = cv.height = dim;
    const cx = cv.getContext("2d");
    const im = cx.createImageData(dim, dim);
    crypto.getRandomValues(im.data);
    for (let i = 3; i < im.data.length; i += 4) im.data[i] = 255;
    for (let i = 0; i < packed.length * 8; i++) {
      const bit = (packed.charCodeAt(Math.floor(i / 8)) >> (7 - (i % 8))) & 1;
      im.data[i * 4] = (im.data[i * 4] & 0xFE) | bit;
    }
    cx.putImageData(im, 0, 0);
    return cv.toDataURL("image/png");
  }

  /**
   * Decode payload from LSB of PNG carrier image
   * @param {string} url - Data URL of PNG carrier
   * @returns {Promise<string|null>} Hex payload or null on failure
   */
  static async lsbRead(url) {
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
        
        // Extract first 64 bits as header
        const hb = [];
        for (let i = 0; i < 64; i++) hb.push(d[i * 4] & 1);
        const hdr = this._bitsToBytes(hb);
        
        if (!this._unpack(hdr)) { res(null); return; }
        
        // Extract payload
        const len = (hdr[4] << 24) | (hdr[5] << 16) | (hdr[6] << 8) | hdr[7];
        const totalBits = (8 + len) * 8;
        const ab = [];
        for (let i = 0; i < totalBits; i++) ab.push(d[i * 4] & 1);
        res(this._unpack(this._bitsToBytes(ab)));
      };
      im.onerror = () => res(null);
      im.src = url;
    });
  }

  // ── SVG Carrier (browser only) ───────────────────────────────────────────────

  /**
   * Encode payload into SVG carrier image
   * @param {string} hexPayload - Hex string payload to encode
   * @returns {string} Data URL of SVG carrier
   */
  static svgWrite(hexPayload) {
    if (isNode) throw new Error("svgWrite is not available in Node.js");
    
    const b64 = btoa(this._pack(hexPayload));
    const h = Math.floor(Math.random() * 360);
    const h2 = (h + 137) % 360;
    const numEls = 4 + Math.floor(Math.random() * 5);
    const els = Array.from({ length: numEls }, (_, i) =>
      `<circle cx="${(8 + Math.random() * 84).toFixed(1)}" cy="${(8 + Math.random() * 84).toFixed(1)}" r="${(2 + Math.random() * 8).toFixed(1)}" fill="hsla(${(h + i * 43) % 360},45%,60%,0.1)"/>`
    ).join("");
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100" viewBox="0 0 100 100">`
      + `<desc data-f="${VERSION}"/>`
      + `<brn:secret xmlns:brn="http://steganography.dev/brn">${b64}</brn:secret>`
      + `<defs><radialGradient id="g" cx="42%" cy="42%" r="62%">`
      + `<stop offset="0%" stop-color="hsl(${h},50%,62%)"/>`
      + `<stop offset="100%" stop-color="hsl(${h2},42%,18%)"/>`
      + `</radialGradient></defs><rect width="100" height="100" fill="url(#g)"/>${els}</svg>`;
    return "data:image/svg+xml;base64," + btoa(unescape(encodeURIComponent(svg)));
  }

  /**
   * Decode payload from SVG carrier image
   * @param {string} url - Data URL of SVG carrier
   * @returns {string|null} Hex payload or null on failure
   */
  static svgRead(url) {
    if (isNode) throw new Error("svgRead is not available in Node.js");
    
    try {
      const raw = decodeURIComponent(escape(atob(url.split(",")[1])));
      const m = raw.match(/<brn:secret[^>]*>([A-Za-z0-9+/=]+)<\/brn:secret>/);
      if (m) return this._unpack(atob(m[1]));
      return null;
    } catch {
      return null;
    }
  }

  // ── Public API ──────────────────────────────────────────────────────────────

  /**
   * Encode a message into a carrier image
   * @param {string} plaintext - Message to encode
   * @param {string} passphrase - Encryption passphrase
   * @param {string} mode - 'svg' or 'lsb'
   * @returns {Promise<string>} Data URL of carrier image
   */
  static async encode(plaintext, passphrase, mode = 'svg') {
    const encrypted = await this.encrypt(plaintext, passphrase);
    return mode === Enc.LSB ? this.lsbWrite(encrypted) : this.svgWrite(encrypted);
  }

  /**
   * Decode a message from a carrier image
   * @param {string} url - Data URL of carrier image
   * @param {string} passphrase - Decryption passphrase
   * @returns {Promise<string|null>} Decrypted message or null
   */
  static async decode(url, passphrase) {
    let payload = this.svgRead(url);
    if (!payload) payload = await this.lsbRead(url);
    if (!payload) return null;
    return this.decrypt(payload, passphrase);
  }

  /**
   * Detect carrier type from data URL
   * @param {string} url - Data URL to inspect
   * @returns {string} 'svg' or 'lsb'
   */
  static sniff(url) {
    if (!url) return Enc.SVG;
    try {
      const raw = atob(url.split(",")[1]).slice(0, 128);
      if (raw.includes("<svg")) return Enc.SVG;
      if (raw.includes("PNG")) return Enc.LSB;
    } catch {}
    return Enc.LSB;
  }
}

// ── Exports ────────────────────────────────────────────────────────────────────

export { Codec, Enc };
export { PBKDF2_ITERATIONS, SALT_BYTES, IV_BYTES };
export { Codec as default };
