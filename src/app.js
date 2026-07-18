import { compareFrames, normalizeRect, percentLabel } from "./sceneEngine.js";
import { passwordPolicyErrors } from "./securityPolicy.js";

const state = {
  authMode: "login",
  user: null,
  spaces: [],
  incidents: [],
  activeSpace: null,
  stream: null,
  cameraFacing: "environment",
  baselineImage: null,
  baselinePixels: null,
  pendingRect: null,
  drawing: false,
  drawStart: null,
  armed: false,
  monitorTimer: null,
  eventStreaks: new Map(),
  eventCooldownUntil: 0,
  activeEvent: null,
  inactivitySeconds: null,
  inactivityTimer: null,
  lastSessionTouchAt: 0,
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));
const sleep = (milliseconds) => new Promise((resolve) => window.setTimeout(resolve, milliseconds));

function refreshIcons() {
  if (window.lucide) window.lucide.createIcons({ attrs: { "aria-hidden": "true" } });
}

function setText(selector, value) {
  const node = typeof selector === "string" ? $(selector) : selector;
  if (node) node.textContent = value ?? "";
}

function showToast(message, type = "success") {
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  const icon = document.createElement("i");
  icon.dataset.lucide = type === "error" ? "circle-alert" : "circle-check";
  const text = document.createElement("span");
  text.textContent = message;
  const close = document.createElement("button");
  close.type = "button";
  close.setAttribute("aria-label", "Dismiss notification");
  close.textContent = "x";
  close.addEventListener("click", () => toast.remove());
  toast.append(icon, text, close);
  $("#toast-region").append(toast);
  refreshIcons();
  window.setTimeout(() => toast.remove(), 5200);
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.body && !(options.body instanceof FormData)) headers.set("Content-Type", "application/json");
  const response = await fetch(path, { ...options, headers, credentials: "same-origin" });
  const contentType = response.headers.get("content-type") || "";
  const payload = contentType.includes("application/json") ? await response.json() : null;
  if (!response.ok) {
    const error = new Error(payload?.error || "The request could not be completed.");
    error.status = response.status;
    throw error;
  }
  return payload;
}

function setAuthMode(mode) {
  state.authMode = mode;
  const signup = mode === "signup";
  const passwordInput = $("#auth-password");
  const passwordToggle = $("#toggle-password");
  $("#name-field").hidden = !signup;
  $("#password-help").hidden = !signup;
  $("#auth-name").required = signup;
  passwordInput.autocomplete = signup ? "new-password" : "current-password";
  passwordInput.type = "password";
  passwordToggle.setAttribute("aria-label", "Show password");
  passwordToggle.setAttribute("aria-pressed", "false");
  passwordToggle.title = "Show password";
  setText("#auth-eyebrow", signup ? "Private from the first frame" : "Welcome back");
  setText("#auth-title", signup ? "Create your private space" : "Return to your spaces");
  setText("#auth-subtitle", signup ? "Start with identity-free, event-only monitoring." : "Review meaningful changes without identity tracking.");
  setText("#auth-submit span", signup ? "Create account" : "Sign in");
  setText("#auth-mode-prefix", signup ? "Already protecting a space?" : "New to SceneGuard?");
  setText("#auth-mode-action", signup ? "Sign in" : "Create account");
  $("#auth-error").hidden = true;
}

function togglePasswordVisibility() {
  const input = $("#auth-password");
  const button = $("#toggle-password");
  const showing = input.type === "text";
  input.type = showing ? "password" : "text";
  button.setAttribute("aria-label", showing ? "Show password" : "Hide password");
  button.title = showing ? "Show password" : "Hide password";
  button.setAttribute("aria-pressed", String(!showing));
}

function showAuth() {
  stopCamera();
  $("#app-shell").hidden = true;
  $("#auth-shell").hidden = false;
  refreshIcons();
}

function showApp() {
  $("#auth-shell").hidden = true;
  $("#app-shell").hidden = false;
  setText("#user-name", state.user.displayName || state.user.email.split("@")[0]);
  setText("#user-email", state.user.email);
  setText("#user-avatar", (state.user.displayName || state.user.email).slice(0, 1).toUpperCase());
  $("#account-email").value = state.user.email;
  $("#retention-days").value = String(state.user.retentionDays || 7);
  scheduleInactivityLogout();
  refreshIcons();
}

function scheduleInactivityLogout() {
  if (!state.user || !Number.isFinite(state.inactivitySeconds)) return;
  window.clearTimeout(state.inactivityTimer);
  state.inactivityTimer = window.setTimeout(async () => {
    await logout();
    showToast("You were signed out after a period of inactivity.");
  }, state.inactivitySeconds * 1000);
  const touchInterval = state.inactivitySeconds * 1000 / 3;
  if (Date.now() - state.lastSessionTouchAt >= touchInterval) {
    state.lastSessionTouchAt = Date.now();
    api("/api/session").catch((error) => {
      if (error.status === 401) {
        window.clearTimeout(state.inactivityTimer);
        state.user = null;
        state.spaces = [];
        state.incidents = [];
        showAuth();
      }
    });
  }
}

async function handleAuthSubmit(event) {
  event.preventDefault();
  const errorNode = $("#auth-error");
  errorNode.hidden = true;
  const body = {
    email: $("#auth-email").value.trim(),
    password: $("#auth-password").value,
  };
  if (state.authMode === "signup") body.displayName = $("#auth-name").value.trim();
  if (state.authMode === "signup") {
    const passwordErrors = passwordPolicyErrors(body.password);
    if (passwordErrors.length) {
      errorNode.textContent = passwordErrors.join(" ");
      errorNode.hidden = false;
      return;
    }
  }
  const submit = $("#auth-submit");
  submit.disabled = true;
  try {
    const result = await api(`/api/auth/${state.authMode}`, { method: "POST", body: JSON.stringify(body) });
    if (result.requiresEmailVerification) {
      errorNode.textContent = "Check your email to verify the account, then sign in.";
      errorNode.hidden = false;
      setAuthMode("login");
      return;
    }
    await bootstrapApp();
  } catch (error) {
    errorNode.textContent = error.message;
    errorNode.hidden = false;
  } finally {
    submit.disabled = false;
  }
}

async function bootstrapApp() {
  try {
    const [session, spaces, incidents] = await Promise.all([
      api("/api/session"),
      api("/api/spaces"),
      api("/api/incidents"),
    ]);
    state.user = session.user;
    state.inactivitySeconds = session.sessionPolicy.inactivitySeconds;
    state.lastSessionTouchAt = Date.now();
    state.spaces = spaces.spaces;
    state.incidents = incidents.incidents;
    state.activeSpace = state.spaces[0] || null;
    state.baselineImage = state.activeSpace?.baseline?.imageData || null;
    state.baselinePixels = null;
    showApp();
    renderAll();
    if (state.baselineImage) await restoreBaselinePixels(state.baselineImage);
  } catch (error) {
    if (error.status === 401 || error.status === 503) {
      showAuth();
      if (error.status === 503) showToast(error.message, "error");
      return;
    }
    showToast(error.message, "error");
  }
}

