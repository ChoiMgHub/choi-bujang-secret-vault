// Only engine-verified practice events belong here, never browser identity claims.
const ISO_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/u;
const WINDOW_MS = 10 * 60 * 1000;
const READ_LIMIT = 120;

function readEvents(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');
  return events.map(event => {
    if (!event || typeof event !== 'object' || Array.isArray(event)) {
      throw new TypeError('invalid_detection_event');
    }
    // Read exactly the three fields defined by docs/DETECT_EVENTS.md.
    const { at, method, identity } = event;
    const subject = identity?.sub;
    const time = typeof at === 'string' && ISO_INSTANT.test(at) ? Date.parse(at) : NaN;
    if (!Number.isFinite(time) || typeof method !== 'string' || !method
        || typeof subject !== 'string' || !subject.trim()) {
      throw new TypeError('invalid_detection_event');
    }
    return { time, method, subject };
  });
}

export function detect(events) {
  const reads = readEvents(events).filter(event => event.method === 'GET');
  // Input order is not trusted. Equal timestamps use a deterministic subject order.
  reads.sort((a, b) => a.time - b.time
    || (a.subject < b.subject ? -1 : a.subject > b.subject ? 1 : 0));
  const windows = new Map();
  for (const event of reads) {
    let window = windows.get(event.subject);
    if (!window) {
      window = { times: [], left: 0 };
      windows.set(event.subject, window);
    }
    window.times.push(event.time);
    // A span of exactly 600,000 ms is within ten minutes; larger spans are outside.
    while (event.time - window.times[window.left] > WINDOW_MS) window.left += 1;
    if (window.times.length - window.left > READ_LIMIT) {
      return { action: 'propose_revocation', reasonCode: 'burst_read', subject: event.subject };
    }
  }
  return { action: 'observe' };
}
