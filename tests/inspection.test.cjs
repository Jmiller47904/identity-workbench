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
test('SAML sample decodes raw XML and Base64 form values',()=>{
 const dom=setup(),d=dom.window.document;d.getElementById('saml-sample').click();assert.equal(d.getElementById('error').textContent,'');assert.equal(d.getElementById('format').textContent,'SAML 2.0');assert.match(d.getElementById('claims').textContent,/Identity Engineering/);
 const xml=d.getElementById('token').value;d.getElementById('token').value=new URLSearchParams({SAMLResponse:Buffer.from(xml).toString('base64')}).toString();d.getElementById('audience').value='urn:example:app';d.getElementById('recipient').value='https://wrong.example.com';d.getElementById('analyze').click();assert.equal(d.getElementById('error').textContent,'');assert.match(d.getElementById('diagnostics').textContent,/Audience matches/);assert.match(d.getElementById('diagnostics').textContent,/Recipient mismatch/);dom.window.close();
});
test('Multiple SAML audience restrictions all must match',()=>{
 const dom=setup(),d=dom.window.document;d.getElementById('saml-sample').click();d.getElementById('token').value=d.getElementById('token').value.replace('</saml:Conditions>','<saml:AudienceRestriction><saml:Audience>urn:other</saml:Audience></saml:AudienceRestriction></saml:Conditions>');d.getElementById('audience').value='urn:example:app';d.getElementById('analyze').click();assert.match(d.getElementById('diagnostics').textContent,/Audience mismatch/);dom.window.close();
});
test('Malformed, encrypted and entity-bearing inputs fail without stale results',()=>{
 const dom=setup(),d=dom.window.document;for(const input of ['a.b.c.d.e','<broken>','<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>']){d.getElementById('jwt-sample').click();d.getElementById('token').value=input;d.getElementById('analyze').click();assert.notEqual(d.getElementById('error').textContent,'');assert.equal(d.getElementById('results').hidden,true);}dom.window.close();
});
test('Offline build embeds exact scripts with matching CSP hashes',()=>{
 require('../scripts/build-web.cjs');const offline=fs.readFileSync('web-release/Identity-Workbench-Offline.html','utf8');const dom=new JSDOM(offline);const d=dom.window.document;const csp=d.querySelector('meta[http-equiv="Content-Security-Policy"]').content;for(const tag of ['script','style']){const content=d.querySelector(tag).textContent;const h=crypto.createHash('sha256').update(content).digest('base64');assert.ok(csp.includes("'sha256-"+h+"'"));}assert.equal(d.querySelector('script[src]'),null);assert.equal(d.querySelector('link[rel="stylesheet"]'),null);dom.window.close();
});
