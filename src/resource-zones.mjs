// Resource identity only. Authorization is evaluated separately by the decider/API.
// These are internal resource IDs, not new fields in aleph.decision.v1 requests.
export const RESOURCE_ZONES = Object.freeze({
  notes: Object.freeze({ id: 'student_notes', service: 'notes',
    apiBase: '/api/notes', engineBase: '/notes' }),
  notices: Object.freeze({ id: 'class_notices', service: 'notices',
    apiBase: '/api/notices', engineBase: '/notices' }),
  instructor: Object.freeze({ id: 'instructor_materials', service: 'instructor',
    apiBase: '/api/instructor', engineBase: '/instructor' }),
});

export function identifyResourcePath(path) {
  if (typeof path !== 'string' || /[?#\\]/u.test(path)) return null;
  for (const zone of Object.values(RESOURCE_ZONES)) {
    for (const base of [zone.apiBase, zone.engineBase]) {
      if (path === base || path === `${base}/`) {
        return { zoneId: zone.id, service: zone.service,
          resourceId: `${zone.id}:collection`, itemId: null };
      }
      const prefix = `${base}/`;
      if (!path.startsWith(prefix)) continue;
      const suffix = path.slice(prefix.length).replace(/\/$/u, '');
      if (!suffix || suffix.includes('/') || suffix === '.' || suffix === '..') return null;
      return { zoneId: zone.id, service: zone.service,
        resourceId: `${zone.id}:item:${suffix}`, itemId: suffix };
    }
  }
  return null;
}
