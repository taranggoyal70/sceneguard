import test from "node:test";
import assert from "node:assert/strict";
import { isStrongPassword, passwordPolicyErrors } from "../src/securityPolicy.js";

test("password policy requires length and every character class", () => {
  assert.equal(isStrongPassword("Correct-Horse7"), true);
  assert.equal(isStrongPassword("lowercase-only-password"), false);
  assert.equal(isStrongPassword("UPPERCASE7!"), false);
  assert.equal(isStrongPassword("NoSymbolsHere7"), false);
  assert.equal(isStrongPassword("Short7!"), false);
});

test("password validation returns user-actionable failures without echoing the password", () => {
  const password = "weak";
  const message = passwordPolicyErrors(password).join(" ");
  assert.match(message, /at least 12/i);
  assert.match(message, /uppercase/i);
  assert.match(message, /number/i);
  assert.match(message, /symbol/i);
  assert.equal(message.includes(password), false);
});
