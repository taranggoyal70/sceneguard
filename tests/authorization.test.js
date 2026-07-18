import test from "node:test";
import assert from "node:assert/strict";
import { requireRole, roleAllows } from "../server/authorization.js";

test("owner-only authorization denies members with a generic response", () => {
  assert.equal(roleAllows("owner", ["owner"]), true);
  assert.equal(roleAllows("member", ["owner"]), false);
  let status;
  let payload;
  let nextCalled = false;
  requireRole("owner")(
    { auth: { role: "member" } },
    { status(value) { status = value; return this; }, json(value) { payload = value; } },
    () => { nextCalled = true; },
  );
  assert.equal(status, 403);
  assert.deepEqual(payload, { error: "You do not have permission to perform this action." });
  assert.equal(nextCalled, false);
});

test("owner-only authorization permits owners", () => {
  let nextCalled = false;
  requireRole("owner")({ auth: { role: "owner" } }, {}, () => { nextCalled = true; });
  assert.equal(nextCalled, true);
});
