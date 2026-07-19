const uuid = () => crypto.randomUUID();
const isoNow = () => new Date().toISOString();

export function createLocalUser(startedAt = isoNow()) {
  return {
    id: "local-trial",
    email: "No account",
    displayName: "Local trial",
    retentionDays: 1,
    role: "owner",
    local: true,
    startedAt,
  };
}

export function createLocalSpace({ name, context }, { id = uuid(), createdAt = isoNow() } = {}) {
  return {
    id,
    name: name.trim(),
    context,
    zones: [],
    baseline: null,
    createdAt,
  };
}

export function createLocalBaseline({ imageData, width, height }, { id = uuid(), createdAt = isoNow() } = {}) {
  return { id, imageData, width, height, createdAt };
}

export function createLocalZone(input, { id = uuid() } = {}) {
  return { id, ...input };
}

export function createLocalIncident(input, { id = uuid(), createdAt = isoNow() } = {}) {
  const changePercent = Math.round(input.changeRatio * 100);
  return {
    id,
    spaceId: input.spaceId,
    zoneId: input.zoneId,
    zoneName: input.zoneName,
    summary: `${input.zoneName} changed`,
    reason: `The on-device comparison measured ${changePercent}% visual change inside this boundary. Review the frames to decide whether it was expected.`,
    observableChanges: [`Local comparison measured ${changePercent}% visual change inside the protected boundary.`],
    confidence: Math.min(0.95, Math.max(0.5, input.changeRatio + 0.45)),
    changeRatio: input.changeRatio,
    analysisSource: "local",
    beforeImage: input.beforeImage,
    afterImage: input.afterImage,
    reviewStatus: "unreviewed",
    createdAt,
  };
}

export function reviewLocalIncident(incident, reviewStatus, reviewedAt = isoNow()) {
  if (!["expected", "concern"].includes(reviewStatus)) throw new Error("Unsupported review status.");
  return { ...incident, reviewStatus, reviewedAt };
}

export function createLocalExport({ user, spaces, incidents }, exportedAt = isoNow()) {
  return {
    exportedAt,
    mode: "local-trial",
    account: {
      displayName: user.displayName,
      retentionDays: user.retentionDays,
      startedAt: user.startedAt,
    },
    spaces,
    incidents,
  };
}
