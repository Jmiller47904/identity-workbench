const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { pathToFileURL } = require('node:url');
const test = require('node:test');

test('desktop request policy allows bundled page assets and blocks all other requests', async () => {
  let filter;
  const root = path.resolve(__dirname, '..');
  const local = {
    setPermissionRequestHandler() {}, setPermissionCheckHandler() {},
    webRequest: { onBeforeRequest(handler) { filter = handler; } }
  };
  class BrowserWindow {
    constructor() { this.webContents = { setWindowOpenHandler() {}, on() {} }; }
    loadURL() { return Promise.resolve(); }
  }
  const electron = {
    app: { whenReady: () => Promise.resolve(), on() {} }, BrowserWindow,
    session: { fromPartition: () => local },
    Menu: { buildFromTemplate: x => x, setApplicationMenu() {} }, shell: {}
  };
  vm.runInNewContext(fs.readFileSync(path.join(root, 'electron/main.cjs'), 'utf8'), {
    require: name => name === 'electron' ? electron : require(name),
    __dirname: path.join(root, 'electron'), process: { platform: 'linux' }
  });
  await Promise.resolve();
  assert.equal(typeof filter, 'function');
  const allowed = url => { let result; filter({ url }, x => { result = x; }); return !result.cancel; };
  const html = fs.readFileSync(path.join(root, 'dist/index.html'), 'utf8');
  const assets = [...html.matchAll(/(?:src|href)="([^" ]+\.(?:js|css))"/g)].map(x => x[1]);
  assert.ok(assets.includes('diagnostic-export.js'));
  assert.ok(assets.includes('nhi-scanner.js'));
  for (const asset of ['index.html', ...assets]) {
    assert.ok(allowed(pathToFileURL(path.join(root, 'dist', asset)).href), asset);
  }
  for (const url of ['https://graph.microsoft.com/v1.0/me', 'https://example.com/collect',
    pathToFileURL(path.join(root, 'package.json')).href,
    pathToFileURL(path.join(root, 'dist', 'unlisted.js')).href]) {
    assert.equal(allowed(url), false, url);
  }
});
