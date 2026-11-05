import { RESOURCE_ZONES, identifyResourcePath } from './resource-zones.mjs';

const NOTE_METHODS = new Set(['GET', 'PUT', 'DELETE']);
const RESERVED_ACTIONS = new Set(['export', 'search', 'bulk', 'admin']);

export function permitsResource(request) {
  if (typeof request?.subjectId !== 'string' || !request.subjectId.trim()
      || request.queryLength !== 0 || typeof request.path !== 'string'
      || /[%\\?#]/u.test(request.path)) return false;
  const resource = identifyResourcePath(request.path);
  if (!resource || resource.service !== request.service) return false;
  const zone = Object.values(RESOURCE_ZONES).find(item => item.id === resource.zoneId);
  const base = request.path === zone.apiBase || request.path.startsWith(`${zone.apiBase}/`)
    ? zone.apiBase : zone.engineBase;
  // The declared route and the actual path must describe the same resource.
  const expectedPath = resource.itemId === null ? base : `${base}/${resource.itemId}`;
  const expectedRoute = `${request.method} ${base}${resource.itemId === null ? '' : '/:id'}`;
  if (request.path !== expectedPath || request.route !== expectedRoute) return false;
  if (resource.itemId !== null && RESERVED_ACTIONS.has(resource.itemId.toLowerCase())) return false;
  if (resource.zoneId === RESOURCE_ZONES.notes.id) {
    return resource.itemId !== null && NOTE_METHODS.has(request.method);
  }
  if (resource.zoneId === RESOURCE_ZONES.notices.id) return request.method === 'GET';
  return false;
}
