'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const root = path.resolve(__dirname,'..');
const output = path.join(root,'web-release');
fs.mkdirSync(output,{recursive:true});
for (const file of ['index.html','style.css','app.js']) fs.copyFileSync(path.join(root,'dist',file),path.join(output,file));
fs.writeFileSync(path.join(output,'.nojekyll'),'');
// A downloadable, self-contained HTML app uses CSP hashes, not unsafe-inline.
const css = fs.readFileSync(path.join(root,'dist/style.css'),'utf8');
const js = fs.readFileSync(path.join(root,'dist/app.js'),'utf8');
const hash = text => crypto.createHash('sha256').update(text).digest('base64');
let html = fs.readFileSync(path.join(root,'dist/index.html'),'utf8');
html = html.replace("script-src 'self'",`script-src 'sha256-${hash(js)}'`).replace("style-src 'self'",`style-src 'sha256-${hash(css)}'`)
  .replace('<link rel="stylesheet" href="style.css">',()=>`<style>${css}</style>`)
  .replace('<script src="app.js"></script>',()=>`<script>${js}</script>`);
fs.writeFileSync(path.join(output,'Identity-Workbench-Offline.html'),html);
let web = fs.readFileSync(path.join(output,'index.html'),'utf8');
web = web.replace('<span class="local">', '<a class="offline-download" href="Identity-Workbench-Offline.html" download>Download offline app ↓</a><span class="local">');
fs.writeFileSync(path.join(output,'index.html'),web);
fs.appendFileSync(path.join(output,'style.css'),'\n.offline-download{color:var(--accent);font-size:14px;margin-left:auto;white-space:nowrap}@media(max-width:700px){header{flex-wrap:wrap}.local{display:none}.offline-download{font-size:12px}}\n');
console.log('Browser site and self-contained offline client built.');
