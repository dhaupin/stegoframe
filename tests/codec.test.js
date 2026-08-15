/**
 * Stegoframe Codec Tests
 * Run with: npm test
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { randomBytes } from 'node:crypto';
import { Codec, SALT_BYTES, IV_BYTES, deriveRoomId, _ae, _ad, _pk, _up, _toHex, _fromHex, _b2B } from '../lib/codec.js';

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
    const original = new Uint8Array(randomBytes(32));
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
});

describe('AES-GCM Encryption', () => {
  it('should encrypt and decrypt successfully', async () => {
    const plaintext = 'Hello, Stegoframe!';
    const passphrase = 'secret123';

    const encrypted = await Codec.encrypt(plaintext, passphrase);
    assert.ok(encrypted.includes(':'), 'Encrypted should be colon-separated');
    
    const parts = encrypted.split(':');
    assert.strictEqual(parts.length, 4, 'Should have 4 parts');
    assert.strictEqual(parts[0].length, SALT_BYTES * 2, 'Salt should be 32 hex chars');
    assert.strictEqual(parts[1].length, IV_BYTES * 2, 'IV should be 24 hex chars');
    assert.strictEqual(parts[2].length, 32, 'Auth tag should be 32 hex chars');

    const decrypted = await Codec.decrypt(encrypted, passphrase);
    assert.strictEqual(decrypted, plaintext);
  });

  it('should produce different ciphertext each time (random salt)', async () => {
    const plaintext = 'Same message';
    const passphrase = 'same-passphrase';

    const encrypted1 = await Codec.encrypt(plaintext, passphrase);
    const encrypted2 = await Codec.encrypt(plaintext, passphrase);

    assert.notStrictEqual(encrypted1, encrypted2, 'Same message should produce different ciphertext');

    // But both should decrypt to same plaintext
    assert.strictEqual(await Codec.decrypt(encrypted1, passphrase), plaintext);
    assert.strictEqual(await Codec.decrypt(encrypted2, passphrase), plaintext);
  });

  it('should return null with wrong passphrase', async () => {
    const encrypted = await Codec.encrypt('Secret message', 'correct-pass');
    const decrypted = await Codec.decrypt(encrypted, 'wrong-pass');
    assert.strictEqual(decrypted, null);
  });

  it('should return null for tampered ciphertext', async () => {
    const encrypted = await Codec.encrypt('Original message', 'pass');
    const parts = encrypted.split(':');
    // Tamper with the encrypted part - change last char
    const lastIdx = parts[3].length - 1;
    const originalChar = parts[3][lastIdx];
    const tamperedChar = originalChar === '0' ? '1' : '0';
    const tamperedHex = parts[3].slice(0, lastIdx) + tamperedChar;
    const tampered = parts.slice(0, 3).concat(tamperedHex).join(':');
    const decrypted = await Codec.decrypt(tampered, 'pass');
    assert.strictEqual(decrypted, null);
  });

  it('should handle empty string', async () => {
    const encrypted = await Codec.encrypt('', 'pass');
    const decrypted = await Codec.decrypt(encrypted, 'pass');
    assert.strictEqual(decrypted, '');
  });

  it('should handle unicode characters', async () => {
    const plaintext = 'Hello 🌍 你好 🎉';
    const passphrase = 'unicode-test';

    const encrypted = await Codec.encrypt(plaintext, passphrase);
    const decrypted = await Codec.decrypt(encrypted, passphrase);
    assert.strictEqual(decrypted, plaintext);
  });

  it('should handle long messages', async () => {
    const plaintext = 'A'.repeat(10000);
    const passphrase = 'long-message-test';

    const encrypted = await Codec.encrypt(plaintext, passphrase);
    const decrypted = await Codec.decrypt(encrypted, passphrase);
    assert.strictEqual(decrypted, plaintext);
  });
});

describe('Full Codec Round-trip', () => {
  it('should encrypt, pack, unpack, and decrypt', async () => {
    const plaintext = 'Full round-trip test!';
    const passphrase = 'round-trip-pass';

    // Encrypt
    const encrypted = await Codec.encrypt(plaintext, passphrase);
    
    // Pack
    const packed = _pk(encrypted);
    assert.ok(packed.startsWith('BRN:ENC:'));

    // Unpack
    const unpacked = _up(packed);
    assert.strictEqual(unpacked, encrypted);

    // Decrypt
    const decrypted = await Codec.decrypt(unpacked, passphrase);
    assert.strictEqual(decrypted, plaintext);
  });
});

describe('Bit Conversion (_b2B)', () => {
  it('should convert bits to bytes', () => {
    // 8 bits: 01000001 = 'A'
    const bits = [0, 1, 0, 0, 0, 0, 0, 1];
    const bytes = _b2B(bits);
    assert.strictEqual(bytes.length, 1);
    assert.strictEqual(bytes[0], 65); // 'A'
  });

  it('should handle partial last byte', () => {
    // 5 bits: 01000 = 'H' (upper 5 bits of byte)
    // Binary: 0b01000000 = 64
    const bits = [0, 1, 0, 0, 0];
    const bytes = _b2B(bits);
    assert.strictEqual(bytes.length, 1);
    assert.strictEqual(bytes[0], 64); // Upper 5 bits of byte
  });
});

describe('Room ID Derivation', () => {
  it('should derive a 6-character alphanumeric room ID', async () => {
    const roomId = await deriveRoomId('my-secret-passphrase');
    assert.strictEqual(roomId.length, 6);
    assert.ok(/^[a-z0-9]+$/.test(roomId), 'Room ID should be lowercase alphanumeric');
  });

  it('should derive the same room ID for the same passphrase', async () => {
    const roomId1 = await deriveRoomId('same-passphrase');
    const roomId2 = await deriveRoomId('same-passphrase');
    assert.strictEqual(roomId1, roomId2);
  });

  it('should derive different room IDs for different passphrases', async () => {
    const roomId1 = await deriveRoomId('passphrase-a');
    const roomId2 = await deriveRoomId('passphrase-b');
    assert.notStrictEqual(roomId1, roomId2);
  });

  it('should be case-sensitive for passphrases', async () => {
    const roomId1 = await deriveRoomId('Secret123');
    const roomId2 = await deriveRoomId('secret123');
    assert.notStrictEqual(roomId1, roomId2);
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

describe('Codec Class API', () => {
  it('should have static methods', () => {
    assert.ok(typeof Codec.deriveRoomId === 'function');
    assert.ok(typeof Codec.encrypt === 'function');
    assert.ok(typeof Codec.decrypt === 'function');
    assert.ok(typeof Codec.encode === 'function');
    assert.ok(typeof Codec.decode === 'function');
    assert.ok(typeof Codec.sniff === 'function');
  });
});
