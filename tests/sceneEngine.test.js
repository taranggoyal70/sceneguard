import test from "node:test";
import assert from "node:assert/strict";
import { compareFrames, normalizeRect, percentLabel } from "../src/sceneEngine.js";

function frame(width, height, pixel = [0, 0, 0, 255]) {
  const data = new Uint8ClampedArray(width * height * 4);
  for (let index = 0; index < data.length; index += 4) data.set(pixel, index);
  return { width, height, data };
}

function paintRectangle(image, left, top, right, bottom, pixel) {
  for (let y = top; y < bottom; y += 1) {
    for (let x = left; x < right; x += 1) image.data.set(pixel, (y * image.width + x) * 4);
  }
}

test("normalizeRect produces a bounded rectangle regardless of drag direction", () => {
  assert.deepEqual(normalizeRect({ x: 80, y: 60 }, { x: 20, y: 10 }, 100, 100), {
    x: 0.2, y: 0.1, width: 0.6, height: 0.5,
  });
});

test("compareFrames does not create an event when a protected zone is unchanged", () => {
  const baseline = frame(30, 30);
  const current = frame(30, 30);
  const result = compareFrames(baseline, current, [{ id: "entry", x: 0, y: 0, width: 1, height: 1, sensitivity: 0.1 }]);
  assert.equal(result.triggered, false);
  assert.equal(result.zones[0].changeRatio, 0);
});

test("compareFrames detects a sustained visual change inside a protected zone", () => {
  const baseline = frame(60, 60);
  const current = frame(60, 60);
  paintRectangle(current, 0, 0, 30, 60, [255, 255, 255, 255]);
  const result = compareFrames(baseline, current, [{ id: "entry", x: 0, y: 0, width: 1, height: 1, sensitivity: 0.2 }]);
  assert.equal(result.triggered, true);
  assert.ok(result.zones[0].changeRatio >= 0.45);
});

test("compareFrames ignores movement outside the user's protected boundary", () => {
  const baseline = frame(60, 60);
  const current = frame(60, 60);
  paintRectangle(current, 30, 0, 60, 60, [255, 255, 255, 255]);
  const result = compareFrames(baseline, current, [{ id: "left", x: 0, y: 0, width: 0.45, height: 1, sensitivity: 0.05 }]);
  assert.equal(result.triggered, false);
});

test("compareFrames rejects frames with different dimensions", () => {
  assert.throws(() => compareFrames(frame(30, 30), frame(40, 30), []), /matching dimensions/);
});

test("percentLabel creates a compact user-facing percentage", () => {
  assert.equal(percentLabel(0.184), "18%");
});
