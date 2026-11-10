import ai from '../src/starter-stubs/ai.mjs';
import threatIntel from '../src/starter-stubs/threat-intel.mjs';
import operations from '../src/operations-api.mjs';
import verification from '../src/verification-api.mjs';
import ruleFixture from '../src/operations-rule-api.mjs';

// Preserve the two existing 501 endpoints in one function. Explicit static API
// routes retain priority; a URL query cannot select or enable a feature.
const handlers = new Map([['/api/ai', ai], ['/api/threat-intel', threatIntel],
  ['/api/operations', operations], ['/api/operations-check', verification], ['/api/operations-rule', ruleFixture]]);
export default function handler(request, response) {
  let path;
  try { path = new URL(request.url || '/', 'https://app.invalid').pathname; } catch { /* deny below */ }
  const selected = handlers.get(path);
  if (selected) return selected(request, response);
  response.setHeader('Cache-Control', 'no-store');
  return response.status(404).json({ error: 'NOT_FOUND' });
}
