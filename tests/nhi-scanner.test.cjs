const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');
const { JSDOM } = require('jsdom');

const html = fs.readFileSync('dist/index.html', 'utf8');
const scanner = fs.readFileSync('dist/nhi-scanner.js', 'utf8');

function setup() {
  const dom = new JSDOM(html, { runScripts: 'outside-only', url: 'https://example.test/' });
  dom.window.eval(scanner);
  return dom;
}

function analyze(dom, snapshot) {
  const document = dom.window.document;
  document.getElementById('nhi-input').value = JSON.stringify(snapshot);
  document.getElementById('nhi-run').click();
  return document;
}

function minimalSnapshot(overrides = {}) {
  return {
    schemaVersion: 1,
    scannedAt: '2026-11-09T12:00:00Z',
    identities: [{
      provider: 'azure',
      id: 'spn-1',
      displayName: 'synthetic-app',
      credentials: [],
      activity: [],
      ...overrides
    }]
  };
}

test('NHI scanner accepts explicit ISO timestamps and remains local', () => {
  const dom = setup();
  const document = analyze(dom, minimalSnapshot({
    credentials: [{ id: 'cert-1', createdAt: '2026-01-01T00:00:00Z', expiresAt: '2027-01-01T00:00:00+00:00' }],
    activity: [{ at: '2026-11-08T09:30:00-05:00', action: 'Synthetic sign-in' }]
  }));
  assert.equal(document.getElementById('nhi-error').textContent, '');
  assert.equal(document.getElementById('nhi-results').hidden, false);
  assert.match(document.getElementById('nhi-status').textContent, /Analyzed 1 identities locally/);
  assert.doesNotMatch(scanner, /fetch\s*\(/);
  dom.window.close();
});

test('NHI scanner rejects malformed, timezone-ambiguous and impossible timestamps', () => {
  for (const invalid of ['2026-11-09T12:00:00', '2026-02-30T12:00:00Z', '2026-11-09T12:00:00+14:30']) {
    const dom = setup();
    const document = analyze(dom, minimalSnapshot({ activity: [{ at: invalid, action: 'Synthetic event' }] }));
    assert.equal(document.getElementById('nhi-results').hidden, true);
    assert.match(document.getElementById('nhi-error').textContent, /Activity timestamp/);
    dom.window.close();
  }
});

test('NHI scanner rejects numeric dates and secret-bearing fields without echoing values', () => {
  const dom = setup();
  let document = analyze(dom, minimalSnapshot({ credentials: [{ id: 'cert-1', expiresAt: 0 }] }));
  assert.match(document.getElementById('nhi-error').textContent, /Credential expiresAt must be an ISO 8601 timestamp/);

  document = analyze(dom, { ...minimalSnapshot(), clientSecret: 'DO_NOT_ECHO' });
  assert.match(document.getElementById('nhi-error').textContent, /Secret-bearing fields are not accepted/);
  assert.doesNotMatch(document.getElementById('nhi-error').textContent, /DO_NOT_ECHO/);
  dom.window.close();
});
