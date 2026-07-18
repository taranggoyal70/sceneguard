import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { createEvidenceVault } from "../server/evidenceVault.js";

const key = crypto.randomBytes(32).toString("base64");

test("evidence vault uses authenticated encryption and a unique IV", () => {
  const vault = createEvidenceVault(key);
  const plaintext = "data:image/png;base64,aGVsbG8=";
  const first = vault.encrypt(plaintext);
  const second = vault.encrypt(plaintext);
  assert.match(first, /^v1:/);
  assert.notEqual(first, second);
  assert.equal(first.includes(plaintext), false);
  assert.equal(vault.decrypt(first), plaintext);
  assert.equal(vault.decrypt(second), plaintext);
});

test("evidence vault rejects tampered ciphertext and malformed keys", () => {
  const vault = createEvidenceVault(key);
  const encrypted = vault.encrypt("private evidence");
  const tampered = `${encrypted.slice(0, -1)}${encrypted.endsWith("A") ? "B" : "A"}`;
  assert.throws(() => vault.decrypt(tampered));
  assert.throws(() => createEvidenceVault("not-a-valid-key"), /32-byte key/);
});
