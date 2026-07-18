import "dotenv/config";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import cookieParser from "cookie-parser";
import express from "express";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import OpenAI from "openai";
import { zodTextFormat } from "openai/helpers/zod";
import { createClient } from "@supabase/supabase-js";
import { z } from "zod";
import { requireRole } from "./authorization.js";
import { createEvidenceVault } from "./evidenceVault.js";
import { PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH, passwordPolicyErrors } from "../src/securityPolicy.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const port = Number(process.env.PORT || 5173);
const production = process.env.NODE_ENV === "production";
const trustedOrigins = new Set((process.env.APP_ORIGINS || `http://127.0.0.1:${port},http://localhost:${port}`).split(",").map((value) => value.trim()).filter(Boolean));
if (production && [...trustedOrigins].some((origin) => !origin.startsWith("https://"))) throw new Error("Production APP_ORIGINS must use HTTPS.");
const inactivityMinutes = Number(process.env.SESSION_INACTIVITY_MINUTES || 15);
const cookieBase = { httpOnly: true, sameSite: "strict", secure: production, path: "/" };
const configured = Boolean(process.env.SUPABASE_URL && process.env.SUPABASE_ANON_KEY && process.env.SUPABASE_SERVICE_ROLE_KEY && process.env.SECURITY_LOG_SALT && process.env.DATA_ENCRYPTION_KEY);
const publicSupabase = configured ? createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY, { auth: { persistSession: false, autoRefreshToken: false } }) : null;
const adminSupabase = configured ? createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false, autoRefreshToken: false } }) : null;
const evidenceVault = process.env.DATA_ENCRYPTION_KEY ? createEvidenceVault(process.env.DATA_ENCRYPTION_KEY) : null;
const openai = process.env.OPENAI_API_KEY ? new OpenAI({ apiKey: process.env.OPENAI_API_KEY }) : null;

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", production ? 1 : false);
app.use((request, response, next) => {
  if (production && !request.secure) return response.status(426).json({ error: "HTTPS is required." });
  next();
});
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "blob:"],
      mediaSrc: ["'self'", "blob:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
    },
  },
  crossOriginEmbedderPolicy: false,
  referrerPolicy: { policy: "no-referrer" },
}));
app.use((request, response, next) => {
  const origin = request.get("origin");
  if (origin && !trustedOrigins.has(origin)) return response.status(403).json({ error: "Request origin is not allowed." });
  if (request.path.startsWith("/api/") && !["GET", "HEAD", "OPTIONS"].includes(request.method) && !origin) {
    return response.status(403).json({ error: "Request origin is required." });
  }
  if (origin) {
    response.setHeader("Access-Control-Allow-Origin", origin);
    response.setHeader("Access-Control-Allow-Credentials", "true");
    response.setHeader("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS");
    response.setHeader("Access-Control-Allow-Headers", "Content-Type");
  }
  response.setHeader("Vary", "Origin");
  response.setHeader("Permissions-Policy", "camera=(self), microphone=(), geolocation=(), browsing-topics=()");
  if (request.path.startsWith("/api/")) response.setHeader("Cache-Control", "no-store");
  else if (!request.path.startsWith("/assets/")) response.setHeader("Cache-Control", "no-cache");
  if (request.method === "OPTIONS") return response.status(204).end();
  next();
});
app.use(express.json({ limit: "6mb", type: "application/json" }));
app.use(cookieParser());
app.use("/api", rateLimit({ windowMs: 15 * 60 * 1000, limit: 180, standardHeaders: "draft-8", legacyHeaders: false }));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: "draft-8", legacyHeaders: false });
const analyzeLimiter = rateLimit({ windowMs: 60 * 1000, limit: 12, standardHeaders: "draft-8", legacyHeaders: false });

const emailSchema = z.string().trim().email().max(254).transform((value) => value.toLowerCase());
const safeName = (maximum) => z.string().trim().min(1).max(maximum)
  .regex(/^[\p{L}\p{N}][\p{L}\p{N}\p{M} .,'&()\/_-]*$/u, "Use letters, numbers, spaces, or common punctuation only.");
const strongPassword = z.string().min(PASSWORD_MIN_LENGTH).max(PASSWORD_MAX_LENGTH).superRefine((password, context) => {
  for (const message of passwordPolicyErrors(password)) context.addIssue({ code: z.ZodIssueCode.custom, message });
});
const signupSchema = z.object({ email: emailSchema, password: strongPassword, displayName: safeName(80) }).strict();
const loginSchema = z.object({ email: emailSchema, password: z.string().min(1).max(128) }).strict();
const spaceSchema = z.object({ name: safeName(80), context: z.enum(["personal", "travel", "workplace", "hospitality", "retail", "other"]) }).strict();
const imageDataSchema = z.string().max(4_500_000).regex(/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/, "Evidence must be a supported encoded image.");
const baselineSchema = z.object({ imageData: imageDataSchema, width: z.number().int().min(160).max(4096), height: z.number().int().min(120).max(4096) }).strict();
const zoneSchema = z.object({
  name: safeName(60),
  sensitivity: z.number().min(0.05).max(0.4),
  x: z.number().min(0).max(1), y: z.number().min(0).max(1),
  width: z.number().min(0.04).max(1), height: z.number().min(0.04).max(1),
}).strict().refine((value) => value.x + value.width <= 1.001 && value.y + value.height <= 1.001, "Zone must remain inside the frame.");
const incidentInputSchema = z.object({
  spaceId: z.string().uuid(), zoneId: z.string().uuid(),
  beforeImage: imageDataSchema, afterImage: imageDataSchema,
  changeRatio: z.number().min(0).max(1),
}).strict();
const reviewSchema = z.object({ reviewStatus: z.enum(["expected", "concern"]) }).strict();
const privacySchema = z.object({ retentionDays: z.union([z.literal(1), z.literal(7), z.literal(30)]) }).strict();
const emailChangeSchema = z.object({ email: emailSchema }).strict();
const deleteSchema = z.object({ confirmation: z.literal("DELETE") }).strict();
const sessionIdSchema = z.string().uuid();
const accessTokenSchema = z.string().min(20).max(8192).regex(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
const refreshTokenSchema = z.string().min(8).max(2048).regex(/^[A-Za-z0-9._~+/=-]+$/);
const modelEventSchema = z.object({
  summary: z.string().max(140),
  observableChanges: z.array(z.string().max(180)).max(5),
  reason: z.string().max(420),
  confidence: z.number().min(0).max(1),
});

function parse(schema, value) {
  const result = schema.safeParse(value);
  if (!result.success) {
    const error = new Error(result.error.issues[0]?.message || "Invalid request.");
    error.status = 400;
    throw error;
  }
  return result.data;
}

function userClient(accessToken) {
  return createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY, {
    global: { headers: { Authorization: `Bearer ${accessToken}` } },
    auth: { persistSession: false, autoRefreshToken: false },
  });
}

function setSessionCookies(response, session, sessionId) {
  response.cookie("sg_access", session.access_token, { ...cookieBase, maxAge: Math.min((session.expires_in || 900) * 1000, 15 * 60 * 1000) });
  response.cookie("sg_refresh", session.refresh_token, { ...cookieBase, maxAge: 7 * 24 * 60 * 60 * 1000 });
  response.cookie("sg_session", sessionId, { ...cookieBase, maxAge: 7 * 24 * 60 * 60 * 1000 });
}

function clearSessionCookies(response) {
  ["sg_access", "sg_refresh", "sg_session"].forEach((name) => response.clearCookie(name, cookieBase));
}

function authenticationError(reason, message = "Authentication required.") {
  const error = new Error(message);
  error.status = 401;
  error.authReason = reason;
  return error;
}

async function logSecurityEvent(type, request, userId = null, metadata = {}) {
  if (!adminSupabase) return false;
  const salt = process.env.SECURITY_LOG_SALT || process.env.SUPABASE_SERVICE_ROLE_KEY;
  const ipHash = crypto.createHmac("sha256", salt).update(request.ip || "unknown").digest("hex");
  const safeMetadata = Object.fromEntries(Object.entries(metadata).filter(([, value]) => typeof value === "string" || typeof value === "number" || typeof value === "boolean"));
  const { error } = await adminSupabase.from("security_events").insert({ user_id: userId, event_type: type, ip_hash: ipHash, metadata: safeMetadata });
  if (error) {
    console.error(JSON.stringify({ level: "error", at: new Date().toISOString(), event: "security_log_write_failed", securityEventType: type }));
    return false;
  }
  return true;
}

function requireConfiguration(_request, _response, next) {
  if (!configured) {
    const error = new Error("SceneGuard authentication is not configured. Add the server-side Supabase environment variables.");
    error.status = 503;
    error.expose = true;
    return next(error);
  }
  next();
}

async function createApplicationSession(response, session) {
  const sessionId = crypto.randomUUID();
  const client = userClient(session.access_token);
  const { error } = await client.from("app_sessions").insert({ id: sessionId, user_id: session.user.id, last_seen_at: new Date().toISOString() });
  if (error) throw new Error("Unable to establish a secure session.");
  setSessionCookies(response, session, sessionId);
}

async function authenticate(request, response, next) {
  try {
    if (!configured) return requireConfiguration(request, response, next);
    const accessResult = accessTokenSchema.safeParse(request.cookies.sg_access);
    const refreshResult = refreshTokenSchema.safeParse(request.cookies.sg_refresh);
    const sessionResult = sessionIdSchema.safeParse(request.cookies.sg_session);
    if (!accessResult.success || !refreshResult.success || !sessionResult.success) {
      const invalidCookies = [!accessResult.success && "access", !refreshResult.success && "refresh", !sessionResult.success && "session"].filter(Boolean).join(",");
      throw authenticationError(`invalid_session_cookie:${invalidCookies}`);
    }
    let accessToken = accessResult.data;
    let refreshToken = refreshResult.data;
    const sessionId = sessionResult.data;
    let authResult = await publicSupabase.auth.getUser(accessToken);
    if (authResult.error) {
      const refreshed = await publicSupabase.auth.refreshSession({ refresh_token: refreshToken });
      if (refreshed.error || !refreshed.data.session) {
        throw authenticationError("token_refresh_failed");
      }
      accessToken = refreshed.data.session.access_token;
      refreshToken = refreshed.data.session.refresh_token;
      setSessionCookies(response, refreshed.data.session, sessionId);
      authResult = { data: { user: refreshed.data.session.user }, error: null };
    }
    const client = userClient(accessToken);
    const { data: applicationSession, error: sessionError } = await client.from("app_sessions").select("id,last_seen_at").eq("id", sessionId).maybeSingle();
    if (sessionError || !applicationSession) {
      throw authenticationError("application_session_missing");
    }
    const inactiveFor = Date.now() - new Date(applicationSession.last_seen_at).getTime();
    if (inactiveFor > inactivityMinutes * 60 * 1000) {
      await client.from("app_sessions").delete().eq("id", sessionId);
      clearSessionCookies(response);
      await logSecurityEvent("inactivity_logout", request, authResult.data.user.id);
      throw authenticationError("session_inactive", "Your session expired due to inactivity.");
    }
    const [{ error: touchError }, { data: profile, error: profileError }] = await Promise.all([
      client.from("app_sessions").update({ last_seen_at: new Date().toISOString() }).eq("id", sessionId),
      client.from("profiles").select("display_name,retention_days,role").eq("user_id", authResult.data.user.id).single(),
    ]);
    if (touchError || profileError || !profile) throw new Error("Unable to verify account authorization.");
    request.auth = { user: authResult.data.user, client, accessToken, refreshToken, sessionId, profile, role: profile.role };
    next();
  } catch (error) {
    if (error.status === 401) {
      clearSessionCookies(response);
      console.warn(JSON.stringify({ level: "warn", at: new Date().toISOString(), event: "authentication_rejected", reason: error.authReason || "unknown" }));
    }
    next(error);
  }
}

function mapZone(row) {
  return { id: row.id, name: row.name, sensitivity: Number(row.sensitivity), x: Number(row.x), y: Number(row.y), width: Number(row.width), height: Number(row.height) };
}

function mapSpace(row) {
  const baselines = Array.isArray(row.baselines) ? row.baselines : row.baselines ? [row.baselines] : [];
  const latestBaseline = baselines.sort((a, b) => new Date(b.created_at) - new Date(a.created_at))[0];
  return {
    id: row.id, name: row.name, context: row.context, createdAt: row.created_at,
    zones: (row.zones || []).map(mapZone),
    baseline: latestBaseline ? { id: latestBaseline.id, imageData: evidenceVault.decrypt(latestBaseline.image_data), width: latestBaseline.width, height: latestBaseline.height, createdAt: latestBaseline.created_at } : null,
  };
}

function mapIncident(row) {
  return {
    id: row.id, spaceId: row.space_id, zoneId: row.zone_id, zoneName: row.zone_name,
    summary: row.summary, reason: row.reason, observableChanges: row.observable_changes,
    confidence: Number(row.confidence), changeRatio: Number(row.change_ratio), analysisSource: row.analysis_source,
    beforeImage: evidenceVault.decrypt(row.before_image), afterImage: evidenceVault.decrypt(row.after_image), reviewStatus: row.review_status, createdAt: row.created_at,
  };
}

app.get("/api/health", (_request, response) => response.json({ status: "ok", authConfigured: configured, aiConfigured: Boolean(openai) }));

app.post("/api/auth/signup", authLimiter, requireConfiguration, async (request, response, next) => {
  try {
    const input = parse(signupSchema, request.body);
    const { data, error } = await publicSupabase.auth.signUp({ email: input.email, password: input.password, options: { data: { display_name: input.displayName } } });
    if (error) {
      await logSecurityEvent("signup_failure", request, null);
      return response.status(400).json({ error: "Unable to create account with those details." });
    }
    if (!data.session) return response.status(202).json({ requiresEmailVerification: true });
    await createApplicationSession(response, data.session);
    await logSecurityEvent("signup_success", request, data.user.id);
    response.status(201).json({ ok: true });
  } catch (error) { next(error); }
});

app.post("/api/auth/login", authLimiter, requireConfiguration, async (request, response, next) => {
  try {
    const input = parse(loginSchema, request.body);
    const { data, error } = await publicSupabase.auth.signInWithPassword(input);
    if (error || !data.session) {
      await logSecurityEvent("login_failure", request, null);
      return response.status(401).json({ error: "Invalid email or password." });
    }
    await createApplicationSession(response, data.session);
    await logSecurityEvent("login_success", request, data.user.id);
    response.json({ ok: true });
  } catch (error) { next(error); }
});

app.post("/api/auth/logout", authenticate, async (request, response, next) => {
  try {
    await request.auth.client.from("app_sessions").delete().eq("id", request.auth.sessionId);
    await publicSupabase.auth.signOut({ scope: "local" });
    clearSessionCookies(response);
    await logSecurityEvent("logout", request, request.auth.user.id);
    response.status(204).end();
  } catch (error) { next(error); }
});

app.get("/api/session", authenticate, async (request, response, next) => {
  try {
    const profile = request.auth.profile;
    response.json({
      user: { id: request.auth.user.id, email: request.auth.user.email, displayName: profile.display_name, retentionDays: profile.retention_days, role: profile.role },
      sessionPolicy: { inactivitySeconds: inactivityMinutes * 60 },
    });
  } catch (error) { next(error); }
});

