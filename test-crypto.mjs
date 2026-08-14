/**
 * Test script for Vant-compatible encryption
 * Run with: node test-crypto.mjs
 */

import crypto from 'node:crypto';

const _PI = 100_000;
const _SB = 16;
const _IB = 12;
const _BRN = "BRN:";
const _VR = "1.0";

function _toHex(buf) {
  return Buffer.from(buf).toString('hex');
}

function _fromHex(hex) {
  return Buffer.from(hex, 'hex');
}

async function _dk(p, s) {
  return crypto.pbkdf2Sync(p, s, _PI, 32, 'sha256');
}

async function _ae(txt, p) {
  const s = crypto.randomBytes(_SB);
  const iv = crypto.randomBytes(_IB);
  const key = await _dk(p, s);
  const ct = crypto.createCipheriv('aes-256-gcm', key, iv);
  let encrypted = ct.update(txt, 'utf8');
  encrypted = Buffer.concat([encrypted, ct.final()]);
  const authTag = ct.getAuthTag();
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
    // GCM wants: ciphertext + authTag concatenated
    const ct = Buffer.concat([encrypted, authTag]);
    const key = await _dk(p, s);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encrypted);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString('utf8');
  } catch (e) { 
    console.log("  Decrypt error:", e.message);
    return null; 
  }
}

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

async function testRoundtrip() {
  console.log("=== Vant-Compatible Encryption Test ===\n");

  const plaintext = "Hello, Stegoframe! This is a test message.";
  const passphrase = "secret123";
  const wrongPass = "wrongpass";

  // Test 1: Encode
  console.log("Test 1: Encoding...");
  const encrypted = await _ae(plaintext, passphrase);
  console.log("  Encrypted (hex):", encrypted.slice(0, 80) + "...");
  console.log("  Format: salt:iv:authTag:encrypted (all hex)");

  // Test 2: Pack
  console.log("\nTest 2: Packing (BRN:ENC: prefix)...");
  const packed = _pk(encrypted);
  console.log("  Packed:", packed.slice(0, 80) + "...");

  // Test 3: Unpack
  console.log("\nTest 3: Unpacking...");
  const unpacked = _up(packed);
  console.log("  Unpacked:", unpacked.slice(0, 80) + "...");
  console.log("  Match:", unpacked === encrypted ? "✓" : "✗");

  // Test 4: Decode with correct passphrase
  console.log("\nTest 4: Decoding with correct passphrase...");
  const decrypted = await _ad(unpacked, passphrase);
  console.log("  Decrypted:", decrypted);
  console.log("  Match:", decrypted === plaintext ? "✓" : "✗");

  // Test 5: Decode with wrong passphrase
  console.log("\nTest 5: Decoding with wrong passphrase...");
  const decryptedWrong = await _ad(unpacked, wrongPass);
  console.log("  Decrypted:", decryptedWrong);
  console.log("  Should be null:", decryptedWrong === null ? "✓" : "✗");

  // Test 6: Verify format components
  console.log("\nTest 6: Format verification...");
  const parts = encrypted.split(":");
  console.log("  Salt:", parts[0].length + " chars (expected " + (_SB * 2) + ")");
  console.log("  IV:", parts[1].length + " chars (expected " + (_IB * 2) + ")");
  console.log("  AuthTag:", parts[2].length + " chars (expected 32)");
  console.log("  Encrypted:", parts[3].length + " chars");

  // Test 7: Multiple messages (different salts)
  console.log("\nTest 7: Multiple encryptions with same passphrase...");
  const msg1 = await _ae("Message 1", "password");
  const msg2 = await _ae("Message 1", "password");
  console.log("  Same message, different ciphertexts:", msg1 !== msg2 ? "✓ (different salts)" : "✗");
  console.log("  Both decode correctly:", (await _ad(msg1, "password")) === "Message 1" && (await _ad(msg2, "password")) === "Message 1" ? "✓" : "✗");

  // Summary
  console.log("\n=== All Tests Complete ===");
}

testRoundtrip().catch(console.error);
