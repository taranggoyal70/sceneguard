# SceneGuard

SceneGuard is a privacy-first spatial memory and explainable safety-boundary application built for OpenAI Build Week. It lets a person or organization give any authorized physical space a temporary visual memory, define the areas that matter, and receive evidence-backed explanations when those areas meaningfully change.

The product reports observable events. It does not identify people, infer emotion or intent, label someone suspicious, or predict crime.

## The Live Loop

1. Create a space and confirm permission to monitor it.
2. Connect a camera. Continuous video remains in browser memory.
3. Capture the expected baseline state.
4. Draw one or more protected zones and set their sensitivity.
5. Arm the space.
6. Local frame comparison requires two consecutive zone changes before selecting evidence.
7. GPT-5.6 compares only the selected before-and-after frames and produces a structured, observation-only explanation.
8. The user classifies the event as expected or a concern.

No demo incidents or fictional users are shipped. Evidence is created only by real actions performed during the active session.

## Architecture

- **Client:** dependency-light HTML, CSS, and JavaScript using `getUserMedia`, Canvas, and a pure scene-comparison engine.
- **Server:** Express with strict CORS, CSP and security headers, rate limiting, schema-whitelist validation, generic errors, and server-only provider credentials.
- **Authentication:** Supabase Auth proxied through the server. Access, refresh, and application-session identifiers use `HttpOnly`, `SameSite=Strict` cookies; no browser storage is used.
- **Authorization:** PostgreSQL Row Level Security plus explicit ownership queries on every resource route. Account-level mutations require the immutable `owner` role; database column grants prevent self-promotion.
- **Evidence protection:** Baseline and event images are encrypted with authenticated AES-256-GCM before database writes. The key remains server-side and evidence is decrypted only after an authenticated RLS-protected read.
- **AI:** OpenAI Responses API with GPT-5.6 image input and Zod Structured Outputs. Requests use `store: false` and only event frames are sent.
- **Data rights:** configurable short evidence retention, JSON export, and complete account deletion through Supabase Admin Auth.

## Configure

Create a Supabase project, apply [`supabase/migrations/202607170001_sceneguard.sql`](supabase/migrations/202607170001_sceneguard.sql), and copy `.env.example` to `.env`. All credential values remain server-side and `.env` is excluded from git.

Required:

```text
SUPABASE_URL
SUPABASE_ANON_KEY
SUPABASE_SERVICE_ROLE_KEY
SECURITY_LOG_SALT
DATA_ENCRYPTION_KEY
OPENAI_API_KEY
```

Generate `DATA_ENCRYPTION_KEY` with `openssl rand -base64 32`. Production `APP_ORIGINS` values must use HTTPS, and the server rejects non-HTTPS production requests even behind a trusted proxy.

The Supabase project's JWT expiry should be set to 900 seconds. SceneGuard additionally invalidates application sessions after 15 minutes without activity.

## Run

```bash
npm install
npm run dev
```

Open `http://127.0.0.1:5173`. Camera access works on localhost. The server starts without credentials but deliberately keeps the authentication gate closed; it never falls back to insecure demo authentication.

## Verify

```bash
npm run verify
npm run test:integration
```

The integration suite requires the local Supabase stack and the ignored `.env` configuration. It creates isolated synthetic users, attempts cross-user reads and mutations, verifies encrypted database values, and deletes every test account when finished.

Tests cover protected-zone frame comparison, ignored out-of-zone changes, password-policy parity, authenticated evidence encryption, RBAC denial, RLS presence, live cross-user isolation, secure session cookies, the AI safety boundary, CORS rejection, security headers, and fail-closed provider configuration.

## Three-Minute Demo

1. Create a space named by the judge and connect the live camera.
2. Point the camera at a tabletop or mock entryway and set the baseline.
3. Draw a zone around an object or doorway, then arm the space.
4. Move or open the protected item for two monitoring intervals.
5. Review the real before-and-after frames and GPT-5.6 explanation.
6. Classify the event and show the evidence timeline.
7. Export the account data, then show the privacy and deletion controls.
