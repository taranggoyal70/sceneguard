import test from "node:test";
import assert from "node:assert/strict";
import {
  createLocalBaseline,
  createLocalExport,
  createLocalIncident,
  createLocalSpace,
  createLocalUser,
  createLocalZone,
  reviewLocalIncident,
} from "../src/localTrial.js";

test("a local trial starts without an account or persistent identity", () => {
  const user = createLocalUser("2026-07-18T12:00:00.000Z");
  assert.equal(user.local, true);
  assert.equal(user.email, "No account");
  assert.equal(user.retentionDays, 1);
  assert.equal(user.startedAt, "2026-07-18T12:00:00.000Z");
});

test("local spaces, baselines, and zones retain real user input", () => {
  const space = createLocalSpace(
    { name: "  Front entry  ", context: "home" },
    { id: "space-1", createdAt: "2026-07-18T12:00:00.000Z" },
  );
  space.baseline = createLocalBaseline(
    { imageData: "data:image/jpeg;base64,frame", width: 1280, height: 720 },
    { id: "baseline-1", createdAt: "2026-07-18T12:01:00.000Z" },
  );
  space.zones.push(createLocalZone(
    { name: "Door", sensitivity: 0.2, x: 0.1, y: 0.1, width: 0.4, height: 0.7 },
    { id: "zone-1" },
  ));

  assert.equal(space.name, "Front entry");
  assert.equal(space.baseline.width, 1280);
  assert.deepEqual(space.zones[0], {
    id: "zone-1", name: "Door", sensitivity: 0.2, x: 0.1, y: 0.1, width: 0.4, height: 0.7,
  });
});

test("local evidence is explainable and can be human reviewed", () => {
  const incident = createLocalIncident({
    spaceId: "space-1",
    zoneId: "zone-1",
    zoneName: "Door",
    changeRatio: 0.32,
    beforeImage: "before-frame",
    afterImage: "after-frame",
  }, { id: "incident-1", createdAt: "2026-07-18T12:02:00.000Z" });

  assert.equal(incident.analysisSource, "local");
  assert.match(incident.reason, /32% visual change/);
  assert.equal(incident.confidence, 0.77);
  assert.equal(incident.reviewStatus, "unreviewed");

  const reviewed = reviewLocalIncident(incident, "expected", "2026-07-18T12:03:00.000Z");
  assert.equal(reviewed.reviewStatus, "expected");
  assert.equal(reviewed.reviewedAt, "2026-07-18T12:03:00.000Z");
  assert.equal(incident.reviewStatus, "unreviewed");
});

test("local export contains the session data without inventing account details", () => {
  const user = createLocalUser("2026-07-18T12:00:00.000Z");
  const payload = createLocalExport({ user, spaces: [], incidents: [] }, "2026-07-18T12:04:00.000Z");
  assert.equal(payload.mode, "local-trial");
  assert.equal(payload.account.displayName, "Local trial");
  assert.equal("email" in payload.account, false);
  assert.equal(payload.exportedAt, "2026-07-18T12:04:00.000Z");
});

test("local review rejects unsupported classifications", () => {
  assert.throws(() => reviewLocalIncident({}, "dismissed"), /Unsupported review status/);
});
