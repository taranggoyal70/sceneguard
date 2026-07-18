import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { createClient } from "@supabase/supabase-js";

process.env.PORT = "0";
process.env.APP_ORIGINS = "http://trusted.test";

const { server } = await import("../server/index.js");
await new Promise((resolve) => server.listening ? resolve() : server.once("listening", resolve));
const baseUrl = `http://127.0.0.1:${server.address().port}`;
const options = { auth: { persistSession: false, autoRefreshToken: false } };
const admin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, options);
const originHeaders = { Origin: "http://trusted.test", "Content-Type": "application/json" };

test.after(() => new Promise((resolve) => server.close(resolve)));

function cookiesFrom(response) {
  return response.headers.getSetCookie().map((value) => value.split(";", 1)[0]).join("; ");
}

async function api(path, { method = "GET", cookie, body } = {}) {
  const headers = { Origin: "http://trusted.test" };
  if (cookie) headers.Cookie = cookie;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  return fetch(`${baseUrl}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
}

test("secure API encrypts owned evidence, audits account changes, and fully deletes the account", async () => {
  const marker = crypto.randomUUID();
  const email = `api-${marker}@example.test`;
  const nextEmail = `api-next-${marker}@example.test`;
  const password = "Api-Test-Only7!";
  let userId;
  try {
    const weakSignup = await fetch(`${baseUrl}/api/auth/signup`, { method: "POST", headers: originHeaders, body: JSON.stringify({ email: `weak-${marker}@example.test`, password: "weak", displayName: "Weak Password Test" }) });
    assert.equal(weakSignup.status, 400);
    assert.match((await weakSignup.json()).error, /at least 12/i);

    const createdUser = await admin.auth.admin.createUser({ email, password, email_confirm: true, user_metadata: { display_name: "API Security Test" } });
    assert.ifError(createdUser.error);
    userId = createdUser.data.user.id;

    const failedLogin = await fetch(`${baseUrl}/api/auth/login`, { method: "POST", headers: originHeaders, body: JSON.stringify({ email, password: "Wrong-Password7!" }) });
    assert.equal(failedLogin.status, 401);
    assert.deepEqual(await failedLogin.json(), { error: "Invalid email or password." });
    const failedLoginAudit = await admin.from("security_events").select("id").is("user_id", null).eq("event_type", "login_failure");
    assert.ifError(failedLoginAudit.error);
    assert.ok(failedLoginAudit.data.length >= 1);

    const login = await fetch(`${baseUrl}/api/auth/login`, { method: "POST", headers: originHeaders, body: JSON.stringify({ email, password }) });
    assert.equal(login.status, 200);
    assert.deepEqual(login.headers.getSetCookie().map((value) => value.slice(0, value.indexOf("="))).sort(), ["sg_access", "sg_refresh", "sg_session"]);
    const cookie = cookiesFrom(login);
    assert.match(cookie, /sg_access=/);
    assert.match(cookie, /sg_session=/);
    const cookieValues = Object.fromEntries(cookie.split("; ").map((part) => part.split(/=(.*)/s).slice(0, 2)));
    const tokenCheck = await createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY, options).auth.getUser(cookieValues.sg_access);
    assert.ifError(tokenCheck.error);
    const storedSession = await admin.from("app_sessions").select("id,user_id").eq("id", cookieValues.sg_session).single();
    assert.ifError(storedSession.error);
    assert.equal(storedSession.data.user_id, userId);

    const rejected = await api("/api/spaces", { method: "POST", cookie, body: { name: "Strict space", context: "personal", unexpected: true } });
    assert.equal(rejected.status, 400, await rejected.text());

    const createSpace = await api("/api/spaces", { method: "POST", cookie, body: { name: "Encrypted evidence space", context: "personal" } });
    assert.equal(createSpace.status, 201);
    const { space } = await createSpace.json();

    const imageData = "data:image/png;base64,aGVsbG8=";
    const baselineResponse = await api(`/api/spaces/${space.id}/baseline`, { method: "POST", cookie, body: { imageData, width: 160, height: 120 } });
    assert.equal(baselineResponse.status, 201);
    assert.equal((await baselineResponse.json()).baseline.imageData, imageData);

    const stored = await admin.from("baselines").select("image_data").eq("space_id", space.id).single();
    assert.ifError(stored.error);
    assert.match(stored.data.image_data, /^v1:/);
    assert.equal(stored.data.image_data.includes(imageData), false);

    const spacesResponse = await api("/api/spaces", { cookie });
    assert.equal(spacesResponse.status, 200);
    assert.equal((await spacesResponse.json()).spaces[0].baseline.imageData, imageData);

    const emailResponse = await api("/api/account/email", { method: "PATCH", cookie, body: { email: nextEmail } });
    assert.equal(emailResponse.status, 200);
    const emailAudit = await admin.from("security_events").select("event_type,user_id").eq("user_id", userId).eq("event_type", "email_change_requested");
    assert.ifError(emailAudit.error);
    assert.equal(emailAudit.data.length, 1);

    const exportResponse = await api("/api/account/export", { cookie });
    assert.equal(exportResponse.status, 200);
    const exported = await exportResponse.json();
    assert.equal(exported.baselines[0].image_data, imageData);
    assert.equal(exported.account.role, "owner");

    const memberUpdate = await admin.from("profiles").update({ role: "member" }).eq("user_id", userId);
    assert.ifError(memberUpdate.error);
    const deniedExport = await api("/api/account/export", { cookie });
    assert.equal(deniedExport.status, 403);
    await admin.from("profiles").update({ role: "owner" }).eq("user_id", userId);

    const deletion = await api("/api/account", { method: "DELETE", cookie, body: { confirmation: "DELETE" } });
    assert.equal(deletion.status, 204);
    const deletedAuthUser = await admin.auth.admin.getUserById(userId);
    assert.ok(deletedAuthUser.error);
    const remainingEvidence = await admin.from("baselines").select("id").eq("user_id", userId);
    assert.ifError(remainingEvidence.error);
    assert.deepEqual(remainingEvidence.data, []);
    const deletionAudit = await admin.from("security_events").select("user_id").is("user_id", null).eq("event_type", "account_deletion_requested");
    assert.ifError(deletionAudit.error);
    assert.ok(deletionAudit.data.length >= 1);
    userId = null;

    const limitedAttempts = await Promise.all(Array.from({ length: 10 }, () => fetch(`${baseUrl}/api/auth/login`, {
      method: "POST", headers: originHeaders, body: JSON.stringify({ email: "rate-limit@example.test", password: "Wrong-Password7!" }),
    })));
    assert.ok(limitedAttempts.some((response) => response.status === 429));
  } finally {
    if (userId) await admin.auth.admin.deleteUser(userId);
  }
});
