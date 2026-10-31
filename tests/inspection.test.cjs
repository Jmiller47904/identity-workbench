'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const crypto = require('node:crypto');
const {JSDOM} = require('jsdom');
const html=fs.readFileSync('dist/index.html','utf8');
const js=fs.readFileSync('dist/app.js','utf8');
const graphJs=fs.readFileSync('dist/graph-builder.js','utf8');
function setup(){const dom=new JSDOM(html,{runScripts:'outside-only',url:'https://example.com/identity-workbench/'});dom.window.TextDecoder=TextDecoder;dom.window.eval(graphJs);dom.window.eval(js);return dom;}
function jwt(payload){return Buffer.from('{"alg":"RS256"}').toString('base64url')+'.'+Buffer.from(JSON.stringify(payload)).toString('base64url')+'.ZXhhbXBsZQ';}
test('JWT example reports expiry and Graph audience; clear removes decoded data',()=>{
 const dom=setup(),d=dom.window.document;d.getElementById('jwt-sample').click();
 assert.equal(d.getElementById('error').textContent,'');
 assert.match(d.getElementById('diagnostics').textContent,/Token has expired/);
 assert.match(d.getElementById('diagnostics').textContent,/Microsoft Graph audience/);
 d.getElementById('clear').click();assert.equal(d.getElementById('token').value,'');assert.equal(d.getElementById('raw').textContent,'');assert.equal(d.getElementById('results').hidden,true);dom.window.close();
});
test('JWT expected audience mismatches; claim HTML is text',()=>{
 const dom=setup(),d=dom.window.document;d.getElementById('token').value=jwt({exp:1,aud:'other',name:'<img src=x onerror=alert(1)>'});d.getElementById('audience').value='expected';d.getElementById('analyze').click();assert.match(d.getElementById('diagnostics').textContent,/aud mismatch/);assert.equal(d.getElementById('claims').querySelector('img'),null);dom.window.close();
});
test('non-finite JWT times report only the invalid claim',()=>{
 const dom=setup(),d=dom.window.document;
 const token=Buffer.from('{"alg":"RS256"}').toString('base64url')+'.'+Buffer.from('{"exp":1e309,"nbf":1e309,"iat":1e309}').toString('base64url')+'.ZXhhbXBsZQ';
 d.getElementById('token').value=token;d.getElementById('analyze').click();
 const diagnostics=d.getElementById('diagnostics').textContent;
 assert.match(diagnostics,/Invalid exp claim/);
 assert.match(diagnostics,/Invalid nbf claim/);
 assert.match(diagnostics,/Invalid iat claim/);
 assert.doesNotMatch(diagnostics,/Expiration is in the future|Token is not active yet|Issued in the future|Inconsistent validity window/);
 dom.window.close();
});
test('SAML sample decodes raw XML and Base64 form values',()=>{
 const dom=setup(),d=dom.window.document;d.getElementById('saml-sample').click();assert.equal(d.getElementById('error').textContent,'');assert.equal(d.getElementById('format').textContent,'SAML 2.0');assert.match(d.getElementById('claims').textContent,/Identity Engineering/);
 const xml=d.getElementById('token').value;d.getElementById('token').value=new URLSearchParams({SAMLResponse:Buffer.from(xml).toString('base64')}).toString();d.getElementById('audience').value='urn:example:app';d.getElementById('recipient').value='https://wrong.example.com';d.getElementById('analyze').click();assert.equal(d.getElementById('error').textContent,'');assert.match(d.getElementById('diagnostics').textContent,/Audience matches/);assert.match(d.getElementById('diagnostics').textContent,/Recipient mismatch/);dom.window.close();
});
test('Multiple SAML audience restrictions all must match',()=>{
 const dom=setup(),d=dom.window.document;d.getElementById('saml-sample').click();d.getElementById('token').value=d.getElementById('token').value.replace('</saml:Conditions>','<saml:AudienceRestriction><saml:Audience>urn:other</saml:Audience></saml:AudienceRestriction></saml:Conditions>');d.getElementById('audience').value='urn:example:app';d.getElementById('analyze').click();assert.match(d.getElementById('diagnostics').textContent,/Audience mismatch/);dom.window.close();
});
test('SAML conditions reject normalized and timezone-ambiguous dates',()=>{
 const dom=setup(),d=dom.window.document;d.getElementById('saml-sample').click();
 for(const invalid of ['2026-02-30T00:00:00Z','2026-10-19T00:00:00']){
  d.getElementById('token').value=d.getElementById('token').value.replace(/NotBefore="[^"]+"/,`NotBefore="${invalid}"`);d.getElementById('analyze').click();
  const diagnostics=d.getElementById('diagnostics').textContent;
  assert.match(diagnostics,/Invalid timestamp/);assert.doesNotMatch(diagnostics,/Conditions \/ NotBeforetime condition passes/);
 }
 dom.window.close();
});
test('Malformed, encrypted and entity-bearing inputs fail without stale results',()=>{
 const dom=setup(),d=dom.window.document;for(const input of ['a.b.c.d.e','<broken>','<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>']){d.getElementById('jwt-sample').click();d.getElementById('token').value=input;d.getElementById('analyze').click();assert.notEqual(d.getElementById('error').textContent,'');assert.equal(d.getElementById('results').hidden,true);}dom.window.close();
});
test('Offline build embeds exact scripts with matching CSP hashes',()=>{
 require('../scripts/build-web.cjs');const offline=fs.readFileSync('web-release/Identity-Workbench-Offline.html','utf8');const dom=new JSDOM(offline);const d=dom.window.document;const csp=d.querySelector('meta[http-equiv="Content-Security-Policy"]').content;for(const tag of ['script','style']){for(const element of d.querySelectorAll(tag)){const h=crypto.createHash('sha256').update(element.textContent).digest('base64');assert.ok(csp.includes("'sha256-"+h+"'"));}}assert.equal(d.querySelector('script[src]'),null);assert.equal(d.querySelector('link[rel="stylesheet"]'),null);dom.window.close();
});

test('Graph browser workbench previews without sending requests and exports reviewed text',()=>{
 const dom=setup(),d=dom.window.document;
 let fetchCalls=0;dom.window.fetch=()=>{fetchCalls++;throw new Error('network use is forbidden in this test');};
 assert.match(d.querySelector('meta[http-equiv="Content-Security-Policy"]').content,/connect-src 'none'/);
 d.getElementById('graph-preview-button').click();
 assert.equal(d.getElementById('graph-result').hidden,false);
 assert.equal(d.getElementById('graph-method').textContent,'GET');
 assert.equal(d.getElementById('graph-url').textContent,'https://graph.microsoft.com/v1.0/me');
 assert.match(d.getElementById('graph-permissions').textContent,/User.Read/);
 assert.match(d.getElementById('graph-result').textContent,/NOT EXECUTED/);

 d.getElementById('graph-template').value='update-user-profile';
 d.getElementById('graph-template').dispatchEvent(new dom.window.Event('change'));
 d.getElementById('graph-user-id').value='demo@example.com';
 d.getElementById('graph-preview-button').click();
 assert.equal(d.getElementById('graph-method').textContent,'PATCH');
 assert.equal(d.getElementById('graph-url').textContent,'https://graph.microsoft.com/v1.0/users/demo%40example.com');
 assert.match(d.getElementById('graph-impact').textContent,/Writes/);
 assert.match(d.getElementById('graph-preview-body').textContent,/Identity/);
 d.querySelector('[data-graph-export="powershell"]').click();
 assert.match(d.getElementById('graph-export-output').value,/Invoke-MgGraphRequest/);
 d.querySelector('[data-graph-export="curl"]').click();
 assert.match(d.getElementById('graph-export-output').value,/GRAPH_ACCESS_TOKEN/);
 assert.doesNotMatch(d.getElementById('graph-export-output').value,/Bearer [A-Za-z0-9._-]{12,}/);
 d.getElementById('graph-body').value='{"department":"Changed"}';
 d.getElementById('graph-body').dispatchEvent(new dom.window.Event('input'));
 assert.equal(d.getElementById('graph-result').hidden,true);
 assert.equal(d.getElementById('graph-export-output').value,'');
 d.querySelector('[data-graph-export="curl"]').click();
 assert.equal(d.getElementById('graph-export-output').value,'');
 assert.equal(fetchCalls,0);
 dom.window.close();
});

test('Graph browser workbench shows local validation errors without echoing body values',()=>{
 const dom=setup(),d=dom.window.document;
 d.getElementById('graph-template').value='update-user-profile';
 d.getElementById('graph-template').dispatchEvent(new dom.window.Event('change'));
 d.getElementById('graph-user-id').value='demo@example.com';
 d.getElementById('graph-body').value='{"password":"SYNTHETIC_SECRET"}';
 d.getElementById('graph-preview-button').click();
 assert.notEqual(d.getElementById('graph-error').textContent,'');
 assert.doesNotMatch(d.getElementById('graph-error').textContent,/SYNTHETIC_SECRET/);
 assert.equal(d.getElementById('graph-result').hidden,true);
 assert.equal(d.querySelector('[data-graph-execute]'),null);
 dom.window.close();
});
