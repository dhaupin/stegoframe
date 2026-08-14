/**
 * Stegoframe Codec Tests
 * Run with: npm test
 * Or: node --test tests/codec.test.mjs
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';

// ── Constants (must match index.html) ────────────────────────────────────────
const _PI = 100_000;  // PBKDF2 iterations
const _SB = 16;       // salt bytes
const _IB = 12;       // IV bytes
const _BRN = "BRN:";  // packet prefix

// ── Copy of codec functions from index.html for testing ──────────────────────

function _toHex(buf) {
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function _fromHex(hex) {
  const buf = new Uint8Array(hex.length / 2);
  for (let i = 0; i < buf.length; i++) buf[i] = parseInt(hex.substr(i * 2, 2), 16);
  return buf;
}

async function _dk(p, s) {
  const k = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(p), { name: "PBKDF2" }, false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: s, iterations: _PI, hash: "SHA-256" },
    k, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );
}

async function _ae(txt, p) {
  const s = crypto.getRandomValues(new Uint8Array(_SB));
  const iv = crypto.getRandomValues(new Uint8Array(_IB));
  const ek = await _dk(p, s);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, ek, new TextEncoder().encode(txt));
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
    const ct = new Uint8Array(encrypted.byteLength + authTag.byteLength);
    ct.set(encrypted, 0);
    ct.set(authTag, encrypted.byteLength);
    const ek = await _dk(p, s);
    return new TextDecoder().decode(
      await crypto.subtle.decrypt({ name: "AES-GCM", iv }, ek, ct)
    );
  } catch { return null; }
}

function _pk(p) {
  return _BRN + "ENC:" + p;
}

function _up(b) {
  const s = typeof b === 'string' ? b : new TextDecoder().decode(b);
  if (s.startsWith(_BRN + "ENC:")) {
    const hex = s.slice(_BRN.length + 4);
    return hex;
  }
  if (typeof b !== 'string' && b.length >= 8) {
    const magic = (b[0] << 16) | (b[1] << 8) | b[2];
    if (magic === 0x534746 && b[3] === 0x02) {
      const len = (b[4] << 24) | (b[5] << 16) | (b[6] << 8) | b[7];
      if (len > 0 && len <= b.length - 8) {
        return b.slice(8, 8 + len);
      }
    }
  }
  return null;
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe('Hex Encoding', () => {
  it('should encode Uint8Array to hex string', () => {
    const buf = new Uint8Array([0x01, 0xAB, 0xFF]);
    assert.strictEqual(_toHex(buf), '01abff');
  });

  it('should decode hex string to Uint8Array', () => {
    const result = _fromHex('01abff');
    assert.ok(result instanceof Uint8Array);
    assert.strictEqual(result[0], 0x01);
    assert.strictEqual(result[1], 0xAB);
    assert.strictEqual(result[2], 0xFF);
  });

  it('should round-trip hex encoding', () => {
    const original = crypto.getRandomValues(new Uint8Array(32));
    const hex = _toHex(original);
    const decoded = _fromHex(hex);
    assert.deepStrictEqual(decoded, original);
  });
});

describe('Packet Format (BRN:ENC:)', () => {
  it('should pack hex payload with BRN:ENC: prefix', () => {
    const hex = 'deadbeef1234';
    const packed = _pk(hex);
    assert.strictEqual(packed, 'BRN:ENC:deadbeef1234');
  });

  it('should unpack BRN:ENC: payload', () => {
    const hex = 'deadbeef1234';
    const packed = _pk(hex);
    const unpacked = _up(packed);
    assert.strictEqual(unpacked, hex);
  });

  it('should return null for invalid format', () => {
    assert.strictEqual(_up('INVALID:PREFIX:data'), null);
  });

  it('should handle legacy SGF binary format', () => {
    // SGF magic + version + length + payload
    const legacy = new Uint8Array([
      0x53, 0x47, 0x46,  // SGF magic
      0x02,              // version
      0x00, 0x00, 0x00, 0x04,  // length = 4
      0xDE, 0xAD, 0xBE, 0xEF   // payload
    ]);
    const unpacked = _up(legacy);
    assert.ok(unpacked instanceof Uint8Array);
    assert.strictEqual(unpacked.length, 4);
    assert.strictEqual(_toHex(unpacked), 'deadbeef');
  });

  it('should reject wrong SGF magic', () => {
    const invalid = new Uint8Array([0x00, 0x47, 0x46, 0x02, 0x00, 0x00, 0x00, 0x04]);
    assert.strictEqual(_up(invalid), null);
  });

  it('should reject wrong SGF version', () => {
    const invalid = new Uint8Array([0x53, 0x47, 0x46, 0x01, 0x00, 0x00, 0x00, 0x04]);
    assert.strictEqual(_up(invalid), null);
  });
});

describe('AES-GCM Encryption', () => {
  it('should encrypt and decrypt successfully', async () => {
    const plaintext = 'Hello, Stegoframe!';
    const passphrase = 'secret123';

    const encrypted = await _ae(plaintext, passphrase);
    assert.ok(encrypted.includes(':'), 'Encrypted should be colon-separated');
    
    const parts = encrypted.split(':');
    assert.strictEqual(parts.length, 4, 'Should have 4 parts');
    assert.strictEqual(parts[0].length, _SB * 2, 'Salt should be 32 hex chars');
    assert.strictEqual(parts[1].length, _IB * 2, 'IV should be 24 hex chars');
    assert.strictEqual(parts[2].length, 32, 'Auth tag should be 32 hex chars');

    const decrypted = await _ad(encrypted, passphrase);
    assert.strictEqual(decrypted, plaintext);
  });

  it('should produce different ciphertext each time (random salt)', async () => {
    const plaintext = 'Same message';
    const passphrase = 'same-passphrase';

    const encrypted1 = await _ae(plaintext, passphrase);
    const encrypted2 = await _ae(plaintext, passphrase);

    assert.notStrictEqual(encrypted1, encrypted2, 'Same message should produce different ciphertext');

    // But both should decrypt to same plaintext
    assert.strictEqual(await _ad(encrypted1, passphrase), plaintext);
    assert.strictEqual(await _ad(encrypted2, passphrase), plaintext);
  });

  it('should return null with wrong passphrase', async () => {
    const encrypted = await _ae('Secret message', 'correct-pass');
    const decrypted = await _ad(encrypted, 'wrong-pass');
    assert.strictEqual(decrypted, null);
  });

  it('should return null for tampered ciphertext', async () => {
    const encrypted = await _ae('Original message', 'pass');
    const parts = encrypted.split(':');
    // Tamper with the encrypted part - change last char
    const lastIdx = parts[3].length - 1;
    const originalChar = parts[3][lastIdx];
    const tamperedChar = originalChar === '0' ? '1' : '0';
    const tamperedHex = parts[3].slice(0, lastIdx) + tamperedChar;
    const tampered = parts.slice(0, 3).concat(tamperedHex).join(':');
    const decrypted = await _ad(tampered, 'pass');
    assert.strictEqual(decrypted, null);
  });

  it('should handle empty string', async () => {
    const encrypted = await _ae('', 'pass');
    const decrypted = await _ad(encrypted, 'pass');
    assert.strictEqual(decrypted, '');
  });

  it('should handle unicode characters', async () => {
    const plaintext = 'Hello 🌍 你好 🎉';
    const passphrase = 'unicode-test';

    const encrypted = await _ae(plaintext, passphrase);
    const decrypted = await _ad(encrypted, passphrase);
    assert.strictEqual(decrypted, plaintext);
  });

  it('should handle long messages', async () => {
    const plaintext = 'A'.repeat(10000);
    const passphrase = 'long-message-test';

    const encrypted = await _ae(plaintext, passphrase);
    const decrypted = await _ad(encrypted, passphrase);
    assert.strictEqual(decrypted, plaintext);
  });
});

describe('Full Codec Round-trip', () => {
  it('should encrypt, pack, unpack, and decrypt', async () => {
    const plaintext = 'Full round-trip test!';
    const passphrase = 'round-trip-pass';

    // Encrypt
    const encrypted = await _ae(plaintext, passphrase);
    
    // Pack
    const packed = _pk(encrypted);
    assert.ok(packed.startsWith('BRN:ENC:'));

    // Unpack
    const unpacked = _up(packed);
    assert.strictEqual(unpacked, encrypted);

    // Decrypt
    const decrypted = await _ad(unpacked, passphrase);
    assert.strictEqual(decrypted, plaintext);
  });
});
