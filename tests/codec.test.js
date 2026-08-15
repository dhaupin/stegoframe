/**
 * Stegoframe Codec Tests
 * Run with: npm test
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { randomBytes } from 'node:crypto';
import { Codec, SALT_BYTES, IV_BYTES } from '../lib/codec.js';

// ── Tests ────────────────────────────────────────────────────────────────────

describe('Codec.encrypt / Codec.decrypt', () => {
  it('should encrypt and decrypt successfully', async () => {
    const encrypted = await Codec.encrypt('Hello, Stegoframe!', 'secret123');
    assert.ok(encrypted.includes(':'), 'Encrypted should be colon-separated');
    
    const parts = encrypted.split(':');
    assert.strictEqual(parts.length, 4, 'Should have 4 parts');
    assert.strictEqual(parts[0].length, SALT_BYTES * 2, 'Salt should be 32 hex chars');
    assert.strictEqual(parts[1].length, IV_BYTES * 2, 'IV should be 24 hex chars');
    assert.strictEqual(parts[2].length, 32, 'Auth tag should be 32 hex chars');

    const decrypted = await Codec.decrypt(encrypted, 'secret123');
    assert.strictEqual(decrypted, 'Hello, Stegoframe!');
  });

  it('should produce different ciphertext each time (random salt)', async () => {
    const encrypted1 = await Codec.encrypt('Same message', 'same-passphrase');
    const encrypted2 = await Codec.encrypt('Same message', 'same-passphrase');
    assert.notStrictEqual(encrypted1, encrypted2);
    assert.strictEqual(await Codec.decrypt(encrypted1, 'same-passphrase'), 'Same message');
    assert.strictEqual(await Codec.decrypt(encrypted2, 'same-passphrase'), 'Same message');
  });

  it('should return null with wrong passphrase', async () => {
    const encrypted = await Codec.encrypt('Secret message', 'correct-pass');
    const decrypted = await Codec.decrypt(encrypted, 'wrong-pass');
    assert.strictEqual(decrypted, null);
  });

  it('should return null for tampered ciphertext', async () => {
    const encrypted = await Codec.encrypt('Original message', 'pass');
    const parts = encrypted.split(':');
    const lastIdx = parts[3].length - 1;
    const tamperedChar = parts[3][lastIdx] === '0' ? '1' : '0';
    const tampered = parts.slice(0, 3).join(':') + ':' + parts[3].slice(0, lastIdx) + tamperedChar;
    assert.strictEqual(await Codec.decrypt(tampered, 'pass'), null);
  });

  it('should handle empty string', async () => {
    const encrypted = await Codec.encrypt('', 'pass');
    assert.strictEqual(await Codec.decrypt(encrypted, 'pass'), '');
  });

  it('should handle unicode characters', async () => {
    const encrypted = await Codec.encrypt('Hello 🌍 你好 🎉', 'unicode-test');
    assert.strictEqual(await Codec.decrypt(encrypted, 'unicode-test'), 'Hello 🌍 你好 🎉');
  });

  it('should handle long messages', async () => {
    const longMsg = 'A'.repeat(10000);
    const encrypted = await Codec.encrypt(longMsg, 'long-message-test');
    assert.strictEqual(await Codec.decrypt(encrypted, 'long-message-test'), longMsg);
  });
});

describe('Codec.deriveRoomId', () => {
  it('should derive a 6-character alphanumeric room ID', async () => {
    const roomId = await Codec.deriveRoomId('my-secret-passphrase');
    assert.strictEqual(roomId.length, 6);
    assert.ok(/^[a-z0-9]+$/.test(roomId));
  });

  it('should derive the same room ID for the same passphrase', async () => {
    const roomId1 = await Codec.deriveRoomId('same-passphrase');
    const roomId2 = await Codec.deriveRoomId('same-passphrase');
    assert.strictEqual(roomId1, roomId2);
  });

  it('should derive different room IDs for different passphrases', async () => {
    const roomId1 = await Codec.deriveRoomId('passphrase-a');
    const roomId2 = await Codec.deriveRoomId('passphrase-b');
    assert.notStrictEqual(roomId1, roomId2);
  });

  it('should be case-sensitive for passphrases', async () => {
    const roomId1 = await Codec.deriveRoomId('Secret123');
    const roomId2 = await Codec.deriveRoomId('secret123');
    assert.notStrictEqual(roomId1, roomId2);
  });

  it('should handle unicode passphrases', async () => {
    const roomId = await Codec.deriveRoomId('秘密のパスワード 🔐');
    assert.strictEqual(roomId.length, 6);
    assert.ok(/^[a-z0-9]+$/.test(roomId));
  });

  it('should handle empty passphrase', async () => {
    const roomId = await Codec.deriveRoomId('');
    assert.strictEqual(roomId.length, 6);
    assert.ok(/^[a-z0-9]+$/.test(roomId));
  });
});

describe('Codec Class API', () => {
  it('should have all required static methods', () => {
    assert.ok(typeof Codec.deriveRoomId === 'function');
    assert.ok(typeof Codec.encrypt === 'function');
    assert.ok(typeof Codec.decrypt === 'function');
    assert.ok(typeof Codec.encode === 'function');
    assert.ok(typeof Codec.decode === 'function');
    assert.ok(typeof Codec.sniff === 'function');
  });

  it('should export constants', () => {
    assert.strictEqual(typeof SALT_BYTES, 'number');
    assert.strictEqual(typeof IV_BYTES, 'number');
  });
});
