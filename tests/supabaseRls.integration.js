import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { createClient } from "@supabase/supabase-js";

const required = ["SUPABASE_URL", "SUPABASE_ANON_KEY", "SUPABASE_SERVICE_ROLE_KEY"];
for (const name of required) {
  if (!process.env[name]) throw new Error(`${name} is required for the live RLS integration test.`);
}

const options = { auth: { persistSession: false, autoRefreshToken: false } };
const admin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, options);

test("RLS blocks cross-user reads, updates, deletes, and role escalation", async () => {
  const marker = crypto.randomUUID();
  const password = "Rls-Test-Only7!";
  const identities = [`rls-a-${marker}@example.test`, `rls-b-${marker}@example.test`];
  const userIds = [];
  try {
    for (const [index, email] of identities.entries()) {
      const { data, error } = await admin.auth.admin.createUser({ email, password, email_confirm: true, user_metadata: { display_name: `RLS User ${index + 1}` } });
      assert.ifError(error);
      userIds.push(data.user.id);
    }

    const clients = identities.map(() => createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY, options));
    for (let index = 0; index < clients.length; index += 1) {
      const { error } = await clients[index].auth.signInWithPassword({ email: identities[index], password });
      assert.ifError(error);
    }

    const { data: created, error: createError } = await clients[0].from("spaces")
      .insert({ user_id: userIds[0], name: "Owner-only space", context: "personal" })
      .select("id,name").single();
    assert.ifError(createError);

    const { data: invisible, error: readError } = await clients[1].from("spaces").select("id,name").eq("id", created.id);
    assert.ifError(readError);
    assert.deepEqual(invisible, []);

    const { data: updated, error: updateError } = await clients[1].from("spaces").update({ name: "Unauthorized change" }).eq("id", created.id).select("id");
    assert.ifError(updateError);
    assert.deepEqual(updated, []);

    const { data: deleted, error: deleteError } = await clients[1].from("spaces").delete().eq("id", created.id).select("id");
    assert.ifError(deleteError);
    assert.deepEqual(deleted, []);

    const { error: escalationError } = await clients[0].from("profiles").update({ role: "owner" }).eq("user_id", userIds[0]);
    assert.ok(escalationError, "authenticated users must not have permission to update the role column");

    const { data: ownerStillHasSpace, error: ownerReadError } = await clients[0].from("spaces").select("id,name").eq("id", created.id).single();
    assert.ifError(ownerReadError);
    assert.equal(ownerStillHasSpace.name, "Owner-only space");
  } finally {
    for (const userId of userIds) await admin.auth.admin.deleteUser(userId);
  }
});
