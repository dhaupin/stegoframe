/**
 * Stegoframe Codec Tests
 * Run with: npm test
 *
 * These tests exercise the REAL codec code: `tests/codec-extract.js` slices
 * the codec block out of `index.html` (between the STEGOFRAME_CODEC markers)
 * and evaluates it, so there is no hand-copied mirror to drift. If the app
 * code changes shape, these tests see the change - that is the point.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { webcrypto } from 'node:crypto';

import { loadCodec, extractCodecSource } from './codec-extract.js';
import { decodePng } from './png.js';

const crypto = webcrypto; // Node 18 floor: bare `crypto` global lands in Node 19
const HERE = dirname(fileURLToPath(import.meta.url));

// The real definitions, straight from index.html.
const {
  _PI, _SB, _IB, _BRN, _VR, Enc, deriveRoomId,
  _toHex, _fromHex, _ae, _ad, _pk, _up,
  _lsbPayload, _lsbExtract, lsbWrite, lsbRead,
} = loadCodec();

// ── Codec wiring: the extractor sees the real block, not a copy ──────────────
describe('Codec block wiring (extracted from index.html)', () => {
  it('finds the codec markers and a non-empty block', () => {
    const src = extractCodecSource();
    assert.ok(src.includes('function _lsbExtract'), 'block carries _lsbExtract');
    assert.ok(src.includes('function lsbWrite'), 'block carries lsbWrite');
  });

  it('exposes the real carrier functions (protects against a rename)', () => {
    assert.strictEqual(typeof lsbWrite, 'function');
    assert.strictEqual(typeof lsbRead, 'function');
    assert.strictEqual(typeof _lsbPayload, 'function');
    assert.strictEqual(typeof _lsbExtract, 'function');
  });

  it('pins the constants the wire depends on', () => {
    assert.strictEqual(_BRN, 'BRN:');
    assert.strictEqual(_IB, 16, 'IV is 16 bytes (full AES block, Vant format)');
    assert.strictEqual(_SB, 16);
    assert.strictEqual(_PI, 100_000);
    assert.deepStrictEqual(Enc, { SVG: 'svg', LSB: 'lsb' });
  });
});

// ── Hex Encoding ─────────────────────────────────────────────────────────────
describe('Hex Encoding', () => {
  it('should encode Uint8Array to hex string', () => {
    assert.strictEqual(_toHex(new Uint8Array([0x01, 0xAB, 0xFF])), '01abff');
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
    assert.deepStrictEqual(_fromHex(_toHex(original)), original);
  });
});

// ── Packet Format (BRN:ENC:) ─────────────────────────────────────────────────
describe('Packet Format (BRN:ENC:)', () => {
  it('should pack hex payload with BRN:ENC: prefix', () => {
    assert.strictEqual(_pk('deadbeef1234'), 'BRN:ENC:deadbeef1234');
  });

  it('should unpack BRN:ENC: payload', () => {
    assert.strictEqual(_up(_pk('deadbeef1234')), 'deadbeef1234');
  });

  it('should return null for invalid format', () => {
    assert.strictEqual(_up('INVALID:PREFIX:data'), null);
  });
});

// ── AES-GCM Encryption ───────────────────────────────────────────────────────
describe('AES-GCM Encryption', () => {
  it('should encrypt and decrypt successfully', async () => {
    const plaintext = 'Hello, Stegoframe!';
    const passphrase = 'secret123';

    const encrypted = await _ae(plaintext, passphrase);
    assert.ok(encrypted.includes(':'), 'Encrypted should be colon-separated');

    const parts = encrypted.split(':');
    assert.strictEqual(parts.length, 4, 'Should have 4 parts');
    assert.strictEqual(parts[0].length, _SB * 2, 'Salt should be 32 hex chars');
    assert.strictEqual(parts[1].length, _IB * 2, 'IV should be 32 hex chars');
    assert.strictEqual(parts[2].length, 32, 'Auth tag should be 32 hex chars');

    assert.strictEqual(await _ad(encrypted, passphrase), plaintext);
  });

  it('should produce different ciphertext each time (random salt)', async () => {
    const encrypted1 = await _ae('Same message', 'same-passphrase');
    const encrypted2 = await _ae('Same message', 'same-passphrase');
    assert.notStrictEqual(encrypted1, encrypted2);
    assert.strictEqual(await _ad(encrypted1, 'same-passphrase'), 'Same message');
    assert.strictEqual(await _ad(encrypted2, 'same-passphrase'), 'Same message');
  });

  it('should return null with wrong passphrase', async () => {
    const encrypted = await _ae('Secret message', 'correct-pass');
    assert.strictEqual(await _ad(encrypted, 'wrong-pass'), null);
  });

  it('should return null for tampered ciphertext', async () => {
    const encrypted = await _ae('Original message', 'pass');
    const parts = encrypted.split(':');
    const lastIdx = parts[3].length - 1;
    const tamperedChar = parts[3][lastIdx] === '0' ? '1' : '0';
    const tampered = parts.slice(0, 3).concat(parts[3].slice(0, lastIdx) + tamperedChar).join(':');
    assert.strictEqual(await _ad(tampered, 'pass'), null);
  });

  it('should handle empty string', async () => {
    const encrypted = await _ae('', 'pass');
    assert.strictEqual(await _ad(encrypted, 'pass'), '');
  });

  it('should handle unicode characters', async () => {
    const plaintext = 'Hello 🌍 你好 🎉';
    const encrypted = await _ae(plaintext, 'unicode-test');
    assert.strictEqual(await _ad(encrypted, 'unicode-test'), plaintext);
  });

  it('should handle long messages', async () => {
    const plaintext = 'A'.repeat(10000);
    const encrypted = await _ae(plaintext, 'long-message-test');
    assert.strictEqual(await _ad(encrypted, 'long-message-test'), plaintext);
  });
});

// ── Full Codec Round-trip ────────────────────────────────────────────────────
describe('Full Codec Round-trip', () => {
  it('should encrypt, pack, unpack, and decrypt', async () => {
    const plaintext = 'Full round-trip test!';
    const passphrase = 'round-trip-pass';

    const packed = _pk(await _ae(plaintext, passphrase));
    assert.ok(packed.startsWith('BRN:ENC:'));

    const unpacked = _up(packed);
    assert.strictEqual(await _ad(unpacked, passphrase), plaintext);
  });
});

// ── LSB wire (canonical [len][packet] header) ────────────────────────────────
// fakeRPlane builds a flat RGBA byte plane (R at [i*4]) with the wire streamed
// into the R-channel LSBs exactly as lsbWrite does - the same shape
// getImageData() hands to _lsbExtract in the browser.
describe('LSB wire (canonical [len][packet] header)', () => {
  function fakeRPlane(bytes) {
    const dim = Math.max(32, Math.ceil(Math.sqrt(bytes.length * 8)));
    const d = new Uint8ClampedArray(dim * dim * 4);
    for (let i = 0; i < d.length; i++) d[i] = (i * 37) & 0xFF; // deterministic noise
    for (let i = 0; i < bytes.length * 8; i++) {
      const bit = (bytes[Math.floor(i / 8)] >> (7 - (i % 8))) & 1;
      d[i * 4] = (d[i * 4] & 0xFE) | bit;
    }
    return d;
  }

  it('round-trips a packet through the wire', () => {
    const hex = _toHex(crypto.getRandomValues(new Uint8Array(48)));
    const packet = _lsbExtract(fakeRPlane(_lsbPayload(_pk(hex))));
    assert.strictEqual(packet, _pk(hex));
    assert.strictEqual(_up(packet), hex);
  });

  it('round-trips a long packet (500+ chars) through the wire', () => {
    const hex = _toHex(crypto.getRandomValues(new Uint8Array(400)));
    const packet = _lsbExtract(fakeRPlane(_lsbPayload(_pk(hex))));
    assert.strictEqual(_up(packet), hex);
  });

  it('returns null on a random (non-payload) bit plane', () => {
    const d = new Uint8ClampedArray(64 * 64 * 4);
    for (let i = 0; i < d.length; i++) d[i] = crypto.getRandomValues(new Uint8Array(1))[0];
    assert.strictEqual(_lsbExtract(d), null);
  });

  it('returns "" on a plane whose length is valid but no BRN packet follows', () => {
    assert.strictEqual(_lsbExtract(fakeRPlane(_lsbPayload('NOT-BRN'))), '');
  });

  it('matches the exact Vant LSB layout pass-178 pins: BE length + MSB-first', () => {
    // Build the Vant wire by hand: u32BE(4) + 'BRN:' -> bits MSB-first.
    const bytes = new Uint8Array([0, 0, 0, 4, 0x42, 0x52, 0x4E, 0x3A]);
    assert.strictEqual(_lsbExtract(fakeRPlane(bytes)), 'BRN:');
  });
});

// ── Golden stone: a committed PNG written by the wire ────────────────────────
// tests/fixtures/lsb-stone.png was produced by the same [len][packet] wire
// (deterministic noise plane, seeded) so it is a real artifact a browser
// `new Image()` rasterizes. If the wire ever changes shape, this pin fails
// loudly instead of silently accepting a drifted layout.
describe('Golden stone (committed PNG carrier)', () => {
  const GOLDEN_PACKET =
    'BRN:ENC:00112233445566778899aabbccddeeff' +
    '000102030405060708090a0b0c0d0e0f' +
    'deadbeefcafebabe0011223344556677' +
    '0a1b2c3d4e5f60718293a4b5c6d7e8f9';

  it('recovers the exact packet from the committed PNG', () => {
    const png = readFileSync(join(HERE, 'fixtures', 'lsb-stone.png'));
    const { width, height, rgba } = decodePng(png);
    assert.strictEqual(width, 34);
    assert.strictEqual(height, 34);
    assert.strictEqual(_lsbExtract(rgba), GOLDEN_PACKET);
    // And the real read path's unwrap yields the hex payload.
    assert.strictEqual(_up(_lsbExtract(rgba)), GOLDEN_PACKET.slice('BRN:ENC:'.length));
  });

  it('does not accept a foreign-dialect plane as a packet', () => {
    // Same dims, no wire: the reader must answer "" (not a payload), never
    // a garbage packet, so a static-noise image reads as empty.
    const { width, height } = decodePng(readFileSync(join(HERE, 'fixtures', 'lsb-stone.png')));
    const blank = new Uint8ClampedArray(width * height * 4).fill(0);
    const out = _lsbExtract(blank);
    assert.ok(out === '' || out === null, `expected empty/null, got ${JSON.stringify(out)}`);
  });
});

// ── Wire version pin ─────────────────────────────────────────────────────────
// Any change to the wire (bit order, header size, magic) must fail here.
describe('Wire version pin (v1.1)', () => {
  it('lays the header as u32 big-endian then the packet bytes', () => {
    const wire = _lsbPayload('BRN:');
    assert.deepStrictEqual(Array.from(wire), [0x00, 0x00, 0x00, 0x04, 0x42, 0x52, 0x4E, 0x3A]);
  });

  it('streams MSB-first, one bit per R-channel pixel, x-major', () => {
    const brn = _lsbPayload('BRN:');
    const d = new Uint8ClampedArray(32 * 32 * 4);
    for (let i = 0; i < d.length; i++) d[i] = (i * 53) & 0xFF;
    for (let i = 0; i < brn.length * 8; i++) {
      const bit = (brn[Math.floor(i / 8)] >> (7 - (i % 8))) & 1;
      d[i * 4] = (d[i * 4] & 0xFE) | bit;
    }
    assert.strictEqual(_lsbExtract(d), 'BRN:');
    // Flip the first bit: the length header becomes 0x80000004 (absurd) -> null.
    d[0] = d[0] ^ 1;
    assert.strictEqual(_lsbExtract(d), null);
  });

  it('carries the version marker the SVG path stamps', () => {
    assert.strictEqual(_VR, '1.0', 'SVG <desc data-f> version; bump consciously');
  });
});

// ── deriveRoomId ─────────────────────────────────────────────────────────────
describe('deriveRoomId', () => {
  it('should derive a 6-character lowercase alphanumeric room ID', async () => {
    const roomId = await deriveRoomId('my-secret-passphrase');
    assert.strictEqual(roomId.length, 6);
    assert.ok(/^[a-z0-9]+$/.test(roomId));
  });

  it('should derive the same room ID for the same passphrase', async () => {
    assert.strictEqual(await deriveRoomId('same-passphrase'), await deriveRoomId('same-passphrase'));
  });

  it('should derive different room IDs for different passphrases', async () => {
    assert.notStrictEqual(await deriveRoomId('passphrase-a'), await deriveRoomId('passphrase-b'));
  });

  it('should be case-sensitive for passphrases', async () => {
    assert.notStrictEqual(await deriveRoomId('Secret123'), await deriveRoomId('secret123'));
  });

  it('should handle unicode passphrases', async () => {
    const roomId = await deriveRoomId('秘密のパスワード 🔐');
    assert.strictEqual(roomId.length, 6);
    assert.ok(/^[a-z0-9]+$/.test(roomId));
  });

  it('should handle empty passphrase', async () => {
    const roomId = await deriveRoomId('');
    assert.strictEqual(roomId.length, 6);
    assert.ok(/^[a-z0-9]+$/.test(roomId));
  });
});
