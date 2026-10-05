'use strict';
// Deliberately pure: no network, credentials, browser storage or tenant changes.
const verifiedOn = '2026-10-05';
const templates = Object.freeze({
  'get-me': Object.freeze({
    method: 'GET', path: '/me', version: 'v1.0',
    source: 'https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0',
    permissions: { delegated: ['User.Read'], application: null },
    note: '/me requires a signed-in user. This template reads only the selected profile fields.'
  }),
  'update-user-profile': Object.freeze({
    method: 'PATCH', path: '/users/{id}', version: 'v1.0',
    source: 'https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0',
    permissions: { delegated: ['User.ReadUpdate.All'], application: ['User.ReadUpdate.All'] },
    note: 'Updates another user’s department/jobTitle only. Consent, caller privileges and source of authority still apply; synchronized properties can be read-only.'
  })
});
const fields = new Set(['department', 'jobTitle']);
const selectable = new Set(['id', 'displayName', 'userPrincipalName', 'department', 'jobTitle']);
const objectIdPattern = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;
const upnLocalPattern = /^[A-Za-z0-9'.!#^_~-]+$/;
const dnsLabelPattern = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;
function encodeUserKey(userId) {
  if (typeof userId !== 'string' || !userId || userId.length > 254)
    throw new Error('Supply a user object ID or simple UPN, not a URL.');
  if (objectIdPattern.test(userId)) return userId;
  const parts = userId.split('@');
  const validUpn = parts.length === 2 && upnLocalPattern.test(parts[0]) &&
    parts[1].length <= 253 && parts[1].split('.').every(label => dnsLabelPattern.test(label));
  if (!validUpn)
    throw new Error('Supply a user object ID or simple UPN, not a URL.');
  // encodeURIComponent intentionally leaves apostrophes unescaped. Encode them
  // as well so every accepted UPN remains one opaque Graph path segment.
  return encodeURIComponent(userId).replace(/'/g, '%27');
}
function buildRequest({ template, userId, body, select, authMode = 'delegated' } = {}) {
  if (!Object.hasOwn(templates, template)) throw new Error('Choose a supported template.');
  const spec = templates[template];
  if (!['delegated', 'application'].includes(authMode) || !spec.permissions[authMode])
    throw new Error('This authentication mode is not supported by the template.');
  let path = spec.path;
  if (template === 'update-user-profile') {
    // Single opaque identifier, never a caller-supplied URL/path/query.
    path = '/users/' + encodeUserKey(userId);
  } else if (userId !== undefined) throw new Error('get-me does not accept a user ID.');
  let parsed;
  if (spec.method === 'PATCH') {
    if (typeof body === 'string') {
      if (body.length > 65536) throw new Error('JSON body exceeds 64 KiB.');
      try { parsed = JSON.parse(body); } catch { throw new Error('Body must be valid JSON.'); }
    } else parsed = body;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed))
      throw new Error('Body must be a JSON object.');
    const keys = Object.keys(parsed);
    if (!keys.length || keys.some(k => !fields.has(k)))
      throw new Error('This template accepts only department and jobTitle; include at least one.');
    for (const key of keys) if (typeof parsed[key] !== 'string' || !parsed[key].trim())
      throw new Error('Profile fields must be nonempty strings. Clearing values is outside this template.');
    parsed = Object.fromEntries(keys.map(k => [k, parsed[k]]));
    if (select !== undefined) throw new Error('Select is only supported by the get-me template.');
  } else if (body !== undefined) throw new Error('GET must not contain a request body.');
  let query = '';
  if (select !== undefined) {
    if (!Array.isArray(select) || !select.length || select.some(k => !selectable.has(k)))
      throw new Error('Select must be a nonempty list of supported profile fields.');
    query = '?$select=' + [...new Set(select)].join(',');
  }
  return {
    method: spec.method, url: 'https://graph.microsoft.com/' + spec.version + path + query,
    headers: parsed ? { 'Content-Type': 'application/json' } : {},
    ...(parsed ? { body: parsed } : {}),
    documentation: { source: spec.source, verifiedOn, apiVersion: spec.version },
    authMode, permissions: [...spec.permissions[authMode]],
    impact: parsed ? 'Writes the supplied profile fields when executed against a tenant.' : 'Reads the signed-in user profile when executed.',
    limitations: [spec.note, 'Local template checks only: no request sent, no consent or tenant validation, no Graph dry-run.']
  };
}
const psQuote = value => "'" + value.replace(/'/g, "''") + "'";
const shQuote = value => "'" + value.replace(/'/g, "'\"'\"'") + "'";
function exportRequest(request, format) {
  if (format === 'json') return JSON.stringify(request, null, 2);
  if (format === 'powershell') return [
    '# Review tenant, permissions and impact before running. Authenticate separately with Connect-MgGraph.',
    '# ' + request.impact,
    'Invoke-MgGraphRequest -Method ' + request.method + ' -Uri ' + psQuote(request.url) +
      (request.body ? ' -ContentType \'application/json\' -Body ' + psQuote(JSON.stringify(request.body)) : '')
  ].join('\n');
  if (format === 'curl') return [
    '# POSIX shell. Set GRAPH_ACCESS_TOKEN securely outside this file; review tenant and impact first.',
    '# ' + request.impact,
    'curl --request ' + request.method + ' --url ' + shQuote(request.url) +
    ' --header "Authorization: Bearer ${GRAPH_ACCESS_TOKEN:?Set GRAPH_ACCESS_TOKEN first}"' +
    (request.body ? " --header 'Content-Type: application/json' --data-raw " + shQuote(JSON.stringify(request.body)) : '')
  ].join('\n');
  throw new Error('Format must be json, powershell or curl.');
}
module.exports = { templates, buildRequest, exportRequest };
