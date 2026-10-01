'use strict';
const fs = require('node:fs');
const { buildRequest, exportRequest } = require('../lib/graph-builder.cjs');
try {
  const [file, format = 'json', ...extra] = process.argv.slice(2);
  if (!file || extra.length) throw new Error('Usage: node scripts/graph-request.cjs request.json [json|powershell|curl]');
  if (fs.statSync(file).size > 65536) throw new Error('Request definition exceeds 64 KiB.');
  let definition;
  try { definition = JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { throw new Error('Request definition must be valid JSON.'); }
  if (!definition || Array.isArray(definition) || typeof definition !== 'object') throw new Error('Request definition must be an object.');
  const allowed = new Set(['template', 'userId', 'body', 'select', 'authMode']);
  if (Object.keys(definition).some(k => !allowed.has(k))) throw new Error('Unsupported definition field. Do not include tokens or credentials.');
  console.log(exportRequest(buildRequest(definition), format));
} catch (error) {
  // Never echo JSON parser excerpts, input bodies, tokens or file contents.
  console.error(error.code ? 'Unable to read request definition.' : error.message);
  process.exitCode = 1;
}
