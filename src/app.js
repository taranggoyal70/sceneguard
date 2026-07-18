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

function setView(view) {
  const labels = {
    live: ["Observe, do not profile", "Live space"],
    incidents: ["Human-reviewed evidence", "Evidence timeline"],
    spaces: ["One memory per place", "Spaces"],
    privacy: ["Maximum privacy by default", "Privacy and account"],
  };
  $$(".view").forEach((node) => node.classList.toggle("active", node.id === `${view}-view`));
  $$(".nav-item").forEach((node) => node.classList.toggle("active", node.dataset.view === view));
  setText("#view-eyebrow", labels[view][0]);
  setText("#view-title", labels[view][1]);
  if (view !== "live" && state.armed) disarmSpace();
}

function renderAll() {
  renderLiveSpace();
  renderSpaces();
  renderIncidents();
  refreshIcons();
}

function renderLiveSpace() {
  const hasSpace = Boolean(state.activeSpace);
  $("#no-space-state").hidden = hasSpace;
  $("#monitor-workspace").hidden = !hasSpace;
  if (!hasSpace) return;
  setText("#active-space-name", state.activeSpace.name);
  renderZones();
  updateSetupState();
  paintZones();
}

function renderZones() {
  const zones = state.activeSpace?.zones || [];
  setText("#zone-count", String(zones.length));
  const list = $("#zone-list");
  list.replaceChildren();
  if (!zones.length) {
    const empty = document.createElement("p");
    empty.className = "rail-empty";
    empty.textContent = "Draw a boundary over a door, object, or area after setting the baseline.";
    list.append(empty);
    return;
  }
  zones.forEach((zone) => {
    const row = document.createElement("article");
    row.className = "zone-item";
    const color = document.createElement("span");
    const copy = document.createElement("div");
    const name = document.createElement("strong");
    name.textContent = zone.name;
    const detail = document.createElement("small");
    detail.textContent = `${percentLabel(zone.sensitivity)} change threshold`;
    copy.append(name, detail);
    const remove = document.createElement("button");
    remove.className = "icon-button";
    remove.type = "button";
    remove.title = `Remove ${zone.name}`;
    remove.setAttribute("aria-label", `Remove ${zone.name}`);
    const icon = document.createElement("i");
    icon.dataset.lucide = "trash-2";
    remove.append(icon);
    remove.addEventListener("click", () => removeZone(zone.id));
    row.append(color, copy, remove);
    list.append(row);
  });
  refreshIcons();
}

function renderSpaces() {
  const list = $("#space-list");
  list.replaceChildren();
  $("#space-empty").hidden = state.spaces.length > 0;
  state.spaces.forEach((space) => {
    const item = document.createElement("article");
    item.className = "space-item";
    const header = document.createElement("header");
    const symbol = document.createElement("span");
    symbol.className = "space-symbol";
    const symbolIcon = document.createElement("i");
    symbolIcon.dataset.lucide = "scan-line";
    symbol.append(symbolIcon);
    const status = document.createElement("span");
    status.className = `status ${space.baseline ? "live" : "neutral"}`;
    const dot = document.createElement("span");
    status.append(dot, document.createTextNode(space.baseline ? "Baseline ready" : "Setup needed"));
    header.append(symbol, status);
    const heading = document.createElement("h3");
    heading.textContent = space.name;
    heading.style.marginTop = "16px";
    const context = document.createElement("p");
    context.textContent = `${space.context[0].toUpperCase()}${space.context.slice(1)} space`;
    const footer = document.createElement("footer");
    const detail = document.createElement("span");
    detail.textContent = `${space.zones.length} protected ${space.zones.length === 1 ? "zone" : "zones"}`;
    const open = document.createElement("button");
    open.className = "text-button";
    open.type = "button";
    open.textContent = "Open space";
    open.addEventListener("click", () => selectSpace(space.id));
    footer.append(detail, open);
    item.append(header, heading, context, footer);
    list.append(item);
  });
  refreshIcons();
}

function renderIncidents() {
  const list = $("#incident-list");
  list.replaceChildren();
  $("#incident-empty").hidden = state.incidents.length > 0;
  $("#incident-count").hidden = state.incidents.length === 0;
  setText("#incident-count", String(state.incidents.length));
  state.incidents.forEach((incident) => {
    const row = document.createElement("article");
    row.className = "incident-row";
    const thumb = document.createElement("div");
    thumb.className = "incident-thumb";
    const image = document.createElement("img");
    image.src = incident.afterImage;
    image.alt = "Captured event evidence";
    thumb.append(image);
    const copy = document.createElement("div");
    copy.className = "incident-copy";
    const title = document.createElement("h3");
    title.textContent = incident.summary;
    const reason = document.createElement("p");
    reason.textContent = incident.reason;
    const meta = document.createElement("div");
    meta.className = "incident-meta";
    const space = state.spaces.find((candidate) => candidate.id === incident.spaceId);
    const source = incident.analysisSource === "gpt-5.6" ? "GPT-5.6" : "Local detector";
    meta.textContent = `${space?.name || "Protected space"} | ${new Date(incident.createdAt).toLocaleString()} | ${source} | ${Math.round(incident.confidence * 100)}% confidence | ${incident.reviewStatus}`;
    copy.append(title, reason, meta);
    const review = document.createElement("button");
    review.className = "button secondary";
    review.type = "button";
    review.textContent = "Review evidence";
    review.addEventListener("click", () => openEvent(incident));
    row.append(thumb, copy, review);
    list.append(row);
  });
}

async function selectSpace(spaceId) {
  if (state.armed) disarmSpace();
  state.activeSpace = state.spaces.find((space) => space.id === spaceId) || null;
  state.baselineImage = state.activeSpace?.baseline?.imageData || null;
  state.baselinePixels = null;
  if (state.baselineImage) await restoreBaselinePixels(state.baselineImage);
  setView("live");
  renderLiveSpace();
}

function openCreateSpace() {
  $("#space-form").reset();
  $("#space-error").hidden = true;
  $("#space-dialog").showModal();
}

async function createSpace(event) {
  event.preventDefault();
  const errorNode = $("#space-error");
  errorNode.hidden = true;
  if (!$("#space-consent").checked) {
    errorNode.textContent = "Confirm that you have permission to monitor this space.";
    errorNode.hidden = false;
    return;
  }
  try {
    const result = await api("/api/spaces", {
      method: "POST",
      body: JSON.stringify({ name: $("#space-name").value.trim(), context: $("#space-context").value }),
    });
    state.spaces.unshift(result.space);
    state.activeSpace = result.space;
    state.baselineImage = null;
    state.baselinePixels = null;
    $("#space-dialog").close();
    setView("live");
    renderAll();
    await startCamera();
  } catch (error) {
    errorNode.textContent = error.message;
    errorNode.hidden = false;
  }
}

async function startCamera() {
  if (!state.activeSpace) return;
  if (!navigator.mediaDevices?.getUserMedia) {
    showToast("This browser does not provide camera access.", "error");
    return;
  }
  stopCamera();
  try {
    state.stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: { ideal: state.cameraFacing }, width: { ideal: 1280 }, height: { ideal: 720 } },
      audio: false,
    });
    const video = $("#camera-video");
    video.srcObject = state.stream;
    await video.play();
    await new Promise((resolve) => {
      if (video.readyState >= 2) resolve();
      else video.addEventListener("loadeddata", resolve, { once: true });
    });
    sizeCanvases();
    if (state.baselineImage) await restoreBaselinePixels(state.baselineImage, video.videoWidth, video.videoHeight);
    $("#camera-empty").hidden = true;
    $("#camera-flip").hidden = false;
    $("#camera-button").querySelector("span").textContent = "Stop camera";
    $("#camera-button").querySelector("svg")?.setAttribute("data-lucide", "video-off");
    updateSetupState();
    showToast("Camera connected. Continuous video is staying on this device.");
  } catch {
    showToast("Camera permission was not granted. Check the browser permission and try again.", "error");
  }
}

function stopCamera() {
  if (state.armed) disarmSpace();
  state.stream?.getTracks().forEach((track) => track.stop());
  state.stream = null;
  const video = $("#camera-video");
  if (video) video.srcObject = null;
  if ($("#camera-empty")) $("#camera-empty").hidden = false;
  if ($("#camera-flip")) $("#camera-flip").hidden = true;
  const label = $("#camera-button span");
  if (label) label.textContent = "Start camera";
  updateSetupState();
}

async function flipCamera() {
  state.cameraFacing = state.cameraFacing === "environment" ? "user" : "environment";
  await startCamera();
}

function sizeCanvases() {
  const video = $("#camera-video");
  const width = video.videoWidth || 960;
  const height = video.videoHeight || 540;
  [$("#frame-canvas"), $("#zone-canvas")].forEach((canvas) => {
    canvas.width = width;
    canvas.height = height;
  });
  paintZones();
}

function captureFrame() {
  const video = $("#camera-video");
  const canvas = $("#frame-canvas");
  const context = canvas.getContext("2d", { willReadFrequently: true });
  context.drawImage(video, 0, 0, canvas.width, canvas.height);
  return {
    pixels: context.getImageData(0, 0, canvas.width, canvas.height),
    imageData: canvas.toDataURL("image/jpeg", 0.78),
  };
}

async function setBaseline() {
  if (!state.stream || !state.activeSpace) return;
  const capture = captureFrame();
  const button = $("#baseline-button");
  button.disabled = true;
  try {
    const result = await api(`/api/spaces/${state.activeSpace.id}/baseline`, {
      method: "POST",
      body: JSON.stringify({ imageData: capture.imageData, width: capture.pixels.width, height: capture.pixels.height }),
    });
    state.baselineImage = capture.imageData;
    state.baselinePixels = capture.pixels;
    state.activeSpace.baseline = result.baseline;
    updateSpaceInList(state.activeSpace);
    updateSetupState();
    renderSpaces();
    showToast("Baseline remembered. Now mark the areas that matter.");
  } catch (error) {
    showToast(error.message, "error");
  } finally {
    button.disabled = false;
  }
}

async function restoreBaselinePixels(imageData, targetWidth, targetHeight) {
  const image = new Image();
  image.decoding = "async";
  image.src = imageData;
  await image.decode();
  const canvas = $("#frame-canvas");
  canvas.width = targetWidth || image.naturalWidth;
  canvas.height = targetHeight || image.naturalHeight;
  const context = canvas.getContext("2d", { willReadFrequently: true });
  context.drawImage(image, 0, 0);
  state.baselinePixels = context.getImageData(0, 0, canvas.width, canvas.height);
}

function beginZoneDrawing() {
  if (!state.baselinePixels) return;
  state.drawing = true;
  $("#camera-stage").classList.add("drawing");
  $("#zone-button").classList.add("active");
  showToast("Drag over the live view to define an attention boundary.");
}

function pointerPosition(event) {
  const canvas = $("#zone-canvas");
  const bounds = canvas.getBoundingClientRect();
  return {
    x: ((event.clientX - bounds.left) / bounds.width) * canvas.width,
    y: ((event.clientY - bounds.top) / bounds.height) * canvas.height,
  };
}

function handleZonePointerDown(event) {
  if (!state.drawing) return;
  state.drawStart = pointerPosition(event);
  $("#zone-canvas").setPointerCapture(event.pointerId);
}

function handleZonePointerMove(event) {
  if (!state.drawing || !state.drawStart) return;
  const current = pointerPosition(event);
  state.pendingRect = normalizeRect(state.drawStart, current, $("#zone-canvas").width, $("#zone-canvas").height);
  paintZones();
}

function handleZonePointerUp(event) {
  if (!state.drawing || !state.drawStart) return;
  const current = pointerPosition(event);
  const rect = normalizeRect(state.drawStart, current, $("#zone-canvas").width, $("#zone-canvas").height);
  state.drawStart = null;
  if (rect.width < 0.04 || rect.height < 0.04) {
    state.pendingRect = null;
    paintZones();
    showToast("Draw a larger boundary so changes can be measured reliably.", "error");
    return;
  }
  state.pendingRect = rect;
  state.drawing = false;
  $("#camera-stage").classList.remove("drawing");
  $("#zone-form").reset();
  $("#zone-sensitivity").value = "18";
  setText("#sensitivity-output", "18%");
  $("#zone-error").hidden = true;
  $("#zone-dialog").showModal();
}

async function saveZone(event) {
  event.preventDefault();
  if (!state.pendingRect || !state.activeSpace) return;
  const errorNode = $("#zone-error");
  errorNode.hidden = true;
  try {
    const result = await api(`/api/spaces/${state.activeSpace.id}/zones`, {
      method: "POST",
      body: JSON.stringify({
        name: $("#zone-name").value.trim(),
        sensitivity: Number($("#zone-sensitivity").value) / 100,
        ...state.pendingRect,
      }),
    });
    state.activeSpace.zones.push(result.zone);
    state.pendingRect = null;
    $("#zone-dialog").close();
    updateSpaceInList(state.activeSpace);
    renderZones();
    renderSpaces();
    updateSetupState();
    paintZones();
    showToast("Attention boundary protected.");
  } catch (error) {
    errorNode.textContent = error.message;
    errorNode.hidden = false;
  }
}

async function removeZone(zoneId) {
  if (state.armed) disarmSpace();
  try {
    await api(`/api/zones/${zoneId}`, { method: "DELETE" });
    state.activeSpace.zones = state.activeSpace.zones.filter((zone) => zone.id !== zoneId);
    updateSpaceInList(state.activeSpace);
    renderZones();
    renderSpaces();
    updateSetupState();
    paintZones();
  } catch (error) {
    showToast(error.message, "error");
  }
}

function paintZones(metrics = []) {
  const canvas = $("#zone-canvas");
  if (!canvas) return;
  const context = canvas.getContext("2d");
  context.clearRect(0, 0, canvas.width, canvas.height);
  const zones = state.activeSpace?.zones || [];
  [...zones.map((zone) => ({ ...zone, saved: true })), ...(state.pendingRect ? [{ ...state.pendingRect, name: "New zone", saved: false }] : [])].forEach((zone) => {
    const metric = metrics.find((candidate) => candidate.zoneId === zone.id);
    const changed = metric?.triggered;
    const x = zone.x * canvas.width;
    const y = zone.y * canvas.height;
    const width = zone.width * canvas.width;
    const height = zone.height * canvas.height;
    context.fillStyle = changed ? "rgba(239,105,88,.17)" : "rgba(18,110,84,.12)";
    context.strokeStyle = changed ? "#ef6958" : zone.saved ? "#50d29e" : "#e6b94f";
    context.lineWidth = Math.max(2, canvas.width / 500);
    context.setLineDash(zone.saved ? [] : [10, 7]);
    context.fillRect(x, y, width, height);
    context.strokeRect(x, y, width, height);
    context.setLineDash([]);
    const label = metric ? `${zone.name} ${percentLabel(metric.changeRatio)}` : zone.name;
    context.font = `700 ${Math.max(12, canvas.width / 75)}px system-ui`;
    const labelWidth = context.measureText(label).width + 18;
    context.fillStyle = changed ? "#ef6958" : "#126e54";
    context.fillRect(x, Math.max(0, y - 27), labelWidth, 27);
    context.fillStyle = "#ffffff";
    context.fillText(label, x + 9, Math.max(18, y - 8));
  });
}

function updateSetupState() {
  const connected = Boolean(state.stream);
  const baseline = Boolean(state.baselinePixels || state.baselineImage);
  const zoned = Boolean(state.activeSpace?.zones?.length);
  const steps = [["#camera-step", connected], ["#baseline-step", baseline], ["#zone-step", zoned]];
  steps.forEach(([selector, complete]) => $(selector)?.classList.toggle("complete", complete));
  setText("#setup-progress", `${steps.filter(([, complete]) => complete).length}/3`);
  $("#baseline-button").disabled = !connected || state.armed;
  $("#zone-button").disabled = !connected || !baseline || state.armed;
  $("#arm-button").disabled = !(connected && baseline && zoned);
  const cameraStatus = $("#camera-status");
  cameraStatus.className = `status ${connected ? "live" : "neutral"}`;
  cameraStatus.replaceChildren(document.createElement("span"), document.createTextNode(connected ? "Camera live" : "Camera off"));
  refreshIcons();
}

function armSpace() {
  if (state.armed) {
    disarmSpace();
    return;
  }
  if (!state.stream || !state.baselinePixels || !state.activeSpace?.zones.length) return;
  state.armed = true;
  state.eventStreaks.clear();
  state.eventCooldownUntil = 0;
  const status = $("#armed-status");
  status.className = "status live";
  status.replaceChildren(document.createElement("span"), document.createTextNode("Space armed"));
  $("#monitor-pulse").hidden = false;
  $("#arm-button span").textContent = "Disarm space";
  $("#arm-button").classList.add("danger");
  $("#baseline-button").disabled = true;
  $("#zone-button").disabled = true;
  state.monitorTimer = window.setInterval(monitorFrame, 1800);
  monitorFrame();
  showToast("Space armed. Only meaningful zone changes create evidence.");
}

function disarmSpace() {
  state.armed = false;
  if (state.monitorTimer) window.clearInterval(state.monitorTimer);
  state.monitorTimer = null;
  state.eventStreaks.clear();
  const status = $("#armed-status");
  if (status) {
    status.className = "status neutral";
    status.replaceChildren(document.createElement("span"), document.createTextNode("Not armed"));
  }
  if ($("#monitor-pulse")) $("#monitor-pulse").hidden = true;
  if ($("#arm-button span")) $("#arm-button span").textContent = "Arm space";
  $("#arm-button")?.classList.remove("danger");
  updateSetupState();
  paintZones();
}

