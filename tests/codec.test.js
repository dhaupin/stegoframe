/**
 * Stegoframe Codec Tests
 * Run with: npm test
 * 
 * Tests the room ID derivation (pure JS, no browser dependencies).
 * Encryption/codec tests are done in-browser.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { createHash } from 'node:crypto';

const ROOM_SALT = "stegoframe-v1";

async function deriveRoomId(passphrase) {
  const data = new TextEncoder().encode(passphrase + ROOM_SALT);
  const hash = createHash('sha256').update(data).digest();
  const hex = Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
  return hex.substring(0, 6);
}

describe('deriveRoomId', () => {
  it('should derive a 6-character lowercase alphanumeric room ID', async () => {
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
