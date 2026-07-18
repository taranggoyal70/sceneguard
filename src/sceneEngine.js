const CHANNEL_THRESHOLD = 34;
const SAMPLE_STEP = 3;

export function normalizeRect(start, end, width, height) {
  if (![start?.x, start?.y, end?.x, end?.y, width, height].every(Number.isFinite) || width <= 0 || height <= 0) {
    throw new TypeError("A valid canvas and two points are required.");
  }
  const left = Math.max(0, Math.min(start.x, end.x));
  const top = Math.max(0, Math.min(start.y, end.y));
  const right = Math.min(width, Math.max(start.x, end.x));
  const bottom = Math.min(height, Math.max(start.y, end.y));
  return {
    x: left / width,
    y: top / height,
    width: (right - left) / width,
    height: (bottom - top) / height,
  };
}

export function percentLabel(value) {
  return `${Math.round(Number(value) * 100)}%`;
}

export function compareFrames(baseline, current, zones) {
  if (!baseline?.data || !current?.data || baseline.width !== current.width || baseline.height !== current.height) {
    throw new TypeError("Baseline and current frames must have matching dimensions.");
  }
  const width = baseline.width;
  const height = baseline.height;
  const metrics = zones.map((zone) => {
    const left = Math.max(0, Math.floor(zone.x * width));
    const top = Math.max(0, Math.floor(zone.y * height));
    const right = Math.min(width, Math.ceil((zone.x + zone.width) * width));
    const bottom = Math.min(height, Math.ceil((zone.y + zone.height) * height));
    let changed = 0;
    let samples = 0;
    let totalDelta = 0;
    for (let y = top; y < bottom; y += SAMPLE_STEP) {
      for (let x = left; x < right; x += SAMPLE_STEP) {
        const index = (y * width + x) * 4;
        const delta = (
          Math.abs(baseline.data[index] - current.data[index]) +
          Math.abs(baseline.data[index + 1] - current.data[index + 1]) +
          Math.abs(baseline.data[index + 2] - current.data[index + 2])
        ) / 3;
        totalDelta += delta;
        if (delta >= CHANNEL_THRESHOLD) changed += 1;
        samples += 1;
      }
    }
    const changeRatio = samples ? changed / samples : 0;
    return {
      zoneId: zone.id,
      changeRatio,
      meanDelta: samples ? totalDelta / samples : 0,
      triggered: changeRatio >= zone.sensitivity,
    };
  });
  return { zones: metrics, triggered: metrics.some((metric) => metric.triggered) };
}
