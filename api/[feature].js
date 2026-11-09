import ai from '../src/starter-stubs/ai.mjs';
import threatIntel from '../src/starter-stubs/threat-intel.mjs';

// Preserve the two existing 501 endpoints in one function. Explicit static API
// routes retain priority; a URL query cannot select or enable a feature.
const handlers = new Map([['/api/ai', ai], ['/api/threat-intel', threatIntel]]);
export default function handler(request, response) {
  let path;
  try { path = new URL(request.url || '/', 'https://app.invalid').pathname; } catch { /* deny below */ }
  const selected = handlers.get(path);
  if (selected) return selected(request, response);
  response.setHeader('Cache-Control', 'no-store');
  return response.status(404).json({ error: 'NOT_FOUND' });
}
