import test from "node:test";
import assert from "node:assert/strict";

process.env.NODE_ENV = "production";
process.env.PORT = "0";
process.env.APP_ORIGINS = "https://app.example.test";
process.env.SUPABASE_URL = "";
process.env.SUPABASE_ANON_KEY = "";
process.env.SUPABASE_SERVICE_ROLE_KEY = "";
process.env.SECURITY_LOG_SALT = "";
process.env.DATA_ENCRYPTION_KEY = "";

const { server } = await import("../server/index.js");
await new Promise((resolve) => server.listening ? resolve() : server.once("listening", resolve));
const baseUrl = `http://127.0.0.1:${server.address().port}`;

test.after(() => new Promise((resolve) => server.close(resolve)));

test("production rejects plaintext transport and trusts one HTTPS proxy hop", async () => {
  const plaintext = await fetch(`${baseUrl}/api/health`, { headers: { "X-Forwarded-Proto": "http" } });
  assert.equal(plaintext.status, 426);
  assert.deepEqual(await plaintext.json(), { error: "HTTPS is required." });

  const proxiedHttps = await fetch(`${baseUrl}/api/health`, { headers: { "X-Forwarded-Proto": "https" } });
  assert.equal(proxiedHttps.status, 200);
  assert.match(proxiedHttps.headers.get("strict-transport-security"), /max-age=/);
});
