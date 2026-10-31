'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const crypto = require('node:crypto');
const {JSDOM} = require('jsdom');
const html=fs.readFileSync('dist/index.html','utf8');
const js=fs.readFileSync('dist/app.js','utf8');
function setup(){const dom=new JSDOM(html,{runScripts:'outside-only',url:'https://example.com/identity-workbench/'});dom.window.TextDecoder=TextDecoder;dom.window.eval(js);return dom;}
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
test('OIDC authorization error callback explains interaction and compares state locally',()=>{
 const dom=setup(),d=dom.window.document;
 d.getElementById('token').value='https://login.example.test/callback?error=interaction_required&error_description=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E&state=expected-state&trace_id=synthetic-trace';
 d.getElementById('expected-oauth-state').value='expected-state';
 d.getElementById('analyze').click();
 assert.equal(d.getElementById('error').textContent,'');
 assert.equal(d.getElementById('format').textContent,'OAuth/OIDC error');
 const diagnostics=d.getElementById('diagnostics');
 assert.match(diagnostics.textContent,/additional user interaction or consent/);
 assert.match(diagnostics.textContent,/State matches/);
 assert.match(d.getElementById('claims').textContent,/synthetic-trace/);
 assert.equal(diagnostics.querySelector('img'),null);
 assert.equal(d.querySelector('#claims a'),null);
 assert.match(diagnostics.textContent,/does not retry or perform authentication/);
 dom.window.close();
});
test('OIDC error JSON preserves diagnostics as text and flags a state mismatch',()=>{
 const dom=setup(),d=dom.window.document;
 d.getElementById('token').value=JSON.stringify({
  error:'invalid_scope',error_description:'<svg onload=alert(1)>',
  error_codes:[70011],timestamp:'2026-10-31T00:00:00Z',
  trace_id:'synthetic-trace',correlation_id:'synthetic-correlation',
  error_uri:'https://login.example.test/error'
 });
 d.getElementById('expected-oauth-state').value='expected-state';
 d.getElementById('analyze').click();
 assert.equal(d.getElementById('format').textContent,'OAuth/OIDC error');
 assert.match(d.getElementById('diagnostics').textContent,/Requested scope was rejected/);
 assert.match(d.getElementById('diagnostics').textContent,/State value is missing/);
 assert.match(d.getElementById('claims').textContent,/synthetic-correlation/);
 assert.equal(d.querySelector('#claims svg'),null);
 assert.equal(d.querySelector('#claims a'),null);
 assert.match(d.getElementById('raw').textContent,/error_uri/);
 assert.doesNotMatch(d.getElementById('raw').textContent,/access_token|authorization_code/);
 dom.window.close();
});
test('OIDC error handling rejects successful callback secrets and clear resets expected state',()=>{
 const dom=setup(),d=dom.window.document;
 d.getElementById('token').value='https://app.example.test/callback?code=synthetic-authorization-code&state=synthetic-state';
 d.getElementById('analyze').click();
 assert.match(d.getElementById('error').textContent,/error responses only/);
 assert.doesNotMatch(d.getElementById('error').textContent,/synthetic-authorization-code/);
 d.getElementById('oidc-sample').click();
 assert.equal(d.getElementById('format').textContent,'OAuth/OIDC error');
 d.getElementById('clear').click();
 assert.equal(d.getElementById('token').value,'');
 assert.equal(d.getElementById('expected-oauth-state').value,'');
 assert.equal(d.getElementById('results').hidden,true);
 dom.window.close();
});
test('Changing an expected OIDC state invalidates a displayed comparison',()=>{
 const dom=setup(),d=dom.window.document;
 d.getElementById('oidc-sample').click();
 assert.equal(d.getElementById('results').hidden,false);
 d.getElementById('expected-oauth-state').value='changed-state';
 d.getElementById('expected-oauth-state').dispatchEvent(new dom.window.Event('input',{bubbles:true}));
 assert.equal(d.getElementById('results').hidden,true);
 assert.equal(d.getElementById('format').textContent,'READY');
 assert.equal(d.getElementById('claims').textContent,'');
 dom.window.close();
});
test('Malformed, encrypted and entity-bearing inputs fail without stale results',()=>{
 const dom=setup(),d=dom.window.document;for(const input of ['a.b.c.d.e','<broken>','<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>']){d.getElementById('jwt-sample').click();d.getElementById('token').value=input;d.getElementById('analyze').click();assert.notEqual(d.getElementById('error').textContent,'');assert.equal(d.getElementById('results').hidden,true);}dom.window.close();
});
test('Offline build embeds exact scripts with matching CSP hashes',()=>{
 require('../scripts/build-web.cjs');const offline=fs.readFileSync('web-release/Identity-Workbench-Offline.html','utf8');const dom=new JSDOM(offline);const d=dom.window.document;const csp=d.querySelector('meta[http-equiv="Content-Security-Policy"]').content;for(const tag of ['script','style']){const content=d.querySelector(tag).textContent;const h=crypto.createHash('sha256').update(content).digest('base64');assert.ok(csp.includes("'sha256-"+h+"'"));}assert.equal(d.querySelector('script[src]'),null);assert.equal(d.querySelector('link[rel="stylesheet"]'),null);dom.window.close();
});
