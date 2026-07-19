import test from "node:test";
import assert from "node:assert/strict";

process.env.PORT = "0";
process.env.APP_ORIGINS = "http://trusted.test";
process.env.SUPABASE_URL = "";
process.env.SUPABASE_ANON_KEY = "";
process.env.SUPABASE_SERVICE_ROLE_KEY = "";
process.env.SECURITY_LOG_SALT = "";
process.env.DATA_ENCRYPTION_KEY = "";

const { server } = await import("../server/index.js");
await new Promise((resolve) => server.listening ? resolve() : server.once("listening", resolve));
const address = server.address();
const baseUrl = `http://127.0.0.1:${address.port}`;

test.after(() => new Promise((resolve) => server.close(resolve)));

test("health endpoint reports provider configuration without exposing secrets", async () => {
  const response = await fetch(`${baseUrl}/api/health`);
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.deepEqual(body, { status: "ok", authConfigured: false, aiConfigured: false });
  assert.equal(JSON.stringify(body).includes("key"), false);
  assert.match(response.headers.get("x-request-id"), /^[0-9a-f-]{36}$/);
});

test("readiness reports available product capabilities", async () => {
  const response = await fetch(`${baseUrl}/api/ready`, { headers: { "X-Request-Id": "startup-check-01" } });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("x-request-id"), "startup-check-01");
  assert.deepEqual(await response.json(), {
    status: "ready",
    capabilities: { localTrial: true, accounts: false, aiAnalysis: false },
  });
});

test("security headers prevent framing and restrict script execution", async () => {
  const response = await fetch(`${baseUrl}/`);
  assert.equal(response.headers.get("x-frame-options"), "SAMEORIGIN");
  assert.match(response.headers.get("content-security-policy"), /script-src 'self'/);
  assert.match(response.headers.get("permissions-policy"), /camera=\(self\)/);
});

test("untrusted origins are rejected before authentication", async () => {
  const response = await fetch(`${baseUrl}/api/session`, { headers: { Origin: "https://attacker.example" } });
  assert.equal(response.status, 403);
});

test("trusted CORS preflights allow only the supported credentialed API surface", async () => {
  const response = await fetch(`${baseUrl}/api/account/privacy`, {
    method: "OPTIONS",
    headers: { Origin: "http://trusted.test", "Access-Control-Request-Method": "PATCH", "Access-Control-Request-Headers": "content-type" },
  });
  assert.equal(response.status, 204);
  assert.equal(response.headers.get("access-control-allow-origin"), "http://trusted.test");
  assert.equal(response.headers.get("access-control-allow-credentials"), "true");
  assert.equal(response.headers.get("access-control-allow-headers"), "Content-Type, X-Request-Id");
  assert.match(response.headers.get("access-control-allow-methods"), /PATCH/);
});

test("state-changing API requests require an explicit trusted origin", async () => {
  const response = await fetch(`${baseUrl}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "test@example.com", password: "not-a-real-password" }),
  });
  assert.equal(response.status, 403);
});

test("server files and unknown API routes are not exposed by static hosting", async () => {
  const envResponse = await fetch(`${baseUrl}/.env`);
  const envBody = await envResponse.text();
  assert.equal(envBody.includes("SUPABASE_SERVICE_ROLE_KEY="), false);

  const apiResponse = await fetch(`${baseUrl}/api/not-a-route`);
  assert.equal(apiResponse.status, 404);
  assert.deepEqual(await apiResponse.json(), { error: "API route not found." });
});

test("the login scene is served as an immutable image asset", async () => {
  const response = await fetch(`${baseUrl}/assets/sceneguard-entryway.webp`);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-type"), "image/webp");
  assert.match(response.headers.get("cache-control"), /immutable/);
});

test("authentication remains closed when the trusted provider is not configured", async () => {
  const response = await fetch(`${baseUrl}/api/session`, { headers: { Origin: "http://trusted.test" } });
  const body = await response.json();
  assert.equal(response.status, 503);
  assert.match(body.error, /authentication is not configured/i);
  assert.doesNotMatch(body.error, /Users\//);
});
