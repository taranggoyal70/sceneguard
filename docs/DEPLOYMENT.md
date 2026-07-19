# Production deployment

SceneGuard has two product paths. The private local trial works without provider credentials and keeps its data in the current browser tab. Accounts, encrypted persistence, retention, and server-side evidence analysis require the production services described below.

## Runtime contract

SceneGuard runs on Node.js 20 or newer. The process serves the web application and API from one port. Set `HOST=0.0.0.0` in a container and let the platform provide `PORT` when required.

`GET /api/health` confirms that the process is alive. `GET /api/ready` reports the product capabilities available in the current environment and performs a time-bounded database probe when accounts are configured. Both endpoints return an `X-Request-Id` header that can be correlated with server error logs.

## Environment

| Variable | Production use |
| --- | --- |
| `PORT` | Listening port. The default is `5173`. |
| `HOST` | Listening interface. Use `0.0.0.0` in a container. |
| `APP_ORIGINS` | Comma-separated public HTTPS origins allowed to call the API. |
| `SESSION_INACTIVITY_MINUTES` | Inactivity window before an account session is invalidated. |
| `SUPABASE_URL` | Supabase project URL for account features. |
| `SUPABASE_ANON_KEY` | Public Supabase key used only by the server. |
| `SUPABASE_SERVICE_ROLE_KEY` | Server-only key for account deletion, retention, and security events. |
| `SECURITY_LOG_SALT` | Secret value used to hash network addresses in security logs. |
| `DATA_ENCRYPTION_KEY` | Base64-encoded 32-byte AES key for persisted evidence. |
| `OPENAI_API_KEY` | Optional server-only key for structured visual comparison. |
| `OPENAI_MODEL` | Optional model override. The default is `gpt-5.6`. |

Generate independent secrets with `openssl rand -base64 32`. Never reuse the database service key as the evidence encryption key or security log salt.

## Database

Apply every SQL file in `supabase/migrations` in filename order. Confirm that Row Level Security is enabled and that the service-role privilege migration has completed before exposing the account path.

Set the Supabase authentication site URL to the exact public application origin. Set the JWT expiry to 900 seconds. Configure a production SMTP provider if email verification or address changes are enabled.

## Container

Build and verify the image locally:

```bash
docker build -t sceneguard .
docker run --rm -p 5173:5173 --env-file .env -e NODE_ENV=development -e HOST=0.0.0.0 -e APP_ORIGINS=http://127.0.0.1:5173 sceneguard
```

Open `http://127.0.0.1:5173/api/ready` to smoke-test the local image composition. This command deliberately overrides the image's production transport policy because the local check uses HTTP.

In production, keep `NODE_ENV=production`, terminate TLS at a trusted reverse proxy, set `APP_ORIGINS` to the exact public HTTPS origin, and forward `X-Forwarded-Proto`. Check readiness through the public HTTPS URL and confirm that `accounts.operational` is true when account features are expected. The image runs as the unprivileged Node user and includes an internal health check that models the trusted proxy header.

## Release checklist

1. Run `npm ci` and `npm run verify` from a clean checkout.
2. Apply pending Supabase migrations and retain the migration output in the release record.
3. Set the exact HTTPS origin in `APP_ORIGINS` and confirm that the reverse proxy supplies `X-Forwarded-Proto`.
4. Confirm that `/api/ready` reports account configuration and operational status separately, and reports AI analysis configuration as expected.
5. Complete a real camera flow from baseline through human review using authorized test space.
6. Export and delete the test account, then confirm that expired evidence cleanup is running.
7. Record the deployed commit, environment owner, rollback image, and evidence-key rotation procedure.

## Operations

Forward JSON error lines from standard error to the platform log service. Search by `requestId` when investigating a failed request. Alert on repeated HTTP 500 responses, sustained authentication failures, and an unavailable process health check.

Evidence keys require deliberate rotation because existing ciphertext depends on the current key. Plan a decrypt-and-reencrypt migration before changing `DATA_ENCRYPTION_KEY`. If the key is lost, persisted evidence cannot be recovered.
