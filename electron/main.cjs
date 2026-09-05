'use strict';
const { app, BrowserWindow, Menu, session, shell } = require('electron');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const entry = pathToFileURL(path.join(__dirname, '..', 'dist', 'index.html')).href;
const allowedFiles = new Set(['index.html','app.js','style.css'].map(file => pathToFileURL(path.join(__dirname,'..','dist',file)).href));
const externalLinks = new Set([
  'https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference',
  'https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf'
]);
function openWindow() {
  const win = new BrowserWindow({
    width: 1420, height: 960, minWidth: 420, minHeight: 540,
    backgroundColor: '#0b1015', title: 'Identity Workbench',
    webPreferences: {
      nodeIntegration: false, contextIsolation: true, sandbox: true,
      webSecurity: true, partition: 'identity-workbench', devTools: false,
      spellcheck: false
    }
  });
  win.webContents.setWindowOpenHandler(({url}) => {
    if (externalLinks.has(url)) void shell.openExternal(url);
    return {action:'deny'};
  });
  win.webContents.on('will-navigate', (event,url) => {
    if (url !== entry) event.preventDefault();
  });
  win.webContents.on('will-attach-webview', event => event.preventDefault());
  void win.loadURL(entry);
}
app.whenReady().then(() => {
  const local = session.fromPartition('identity-workbench');
  local.setPermissionRequestHandler((_wc,_permission,callback) => callback(false));
  local.setPermissionCheckHandler(() => false);
  local.webRequest.onBeforeRequest((details,callback) => callback({cancel:!allowedFiles.has(details.url)}));
  Menu.setApplicationMenu(Menu.buildFromTemplate([
    ...(process.platform === 'darwin' ? [{role:'appMenu'}] : []),
    {label:'Edit',submenu:[{role:'undo'},{role:'redo'},{type:'separator'},{role:'cut'},{role:'copy'},{role:'paste'},{role:'selectAll'}]},
    {label:'View',submenu:[{role:'resetZoom'},{role:'zoomIn'},{role:'zoomOut'},{type:'separator'},{role:'togglefullscreen'}]},
    {label:'Window',submenu:[{role:'minimize'},{role:'close'}]}
  ]));
  openWindow();
  app.on('activate', () => {if (!BrowserWindow.getAllWindows().length) openWindow();});
});
app.on('window-all-closed', () => {if(process.platform !== 'darwin') app.quit();});
