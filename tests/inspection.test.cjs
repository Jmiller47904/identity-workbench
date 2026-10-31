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
test('SAML recipient comparison treats SubjectConfirmation entries as alternatives',()=>{
 const dom=setup(),d=dom.window.document;
 d.getElementById('saml-sample').click();
 const xml=d.getElementById('token').value;
 const expiry=xml.match(/<saml:SubjectConfirmationData Recipient="https:\/\/app\.example\.com\/saml\/acs" NotOnOrAfter="([^"]+)"/)[1];
 const alternative='<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="https://other.example.com/saml/acs" NotOnOrAfter="'+expiry+'"/></saml:SubjectConfirmation>';
 d.getElementById('token').value=xml.replace('</saml:Subject>',alternative+'</saml:Subject>');
 d.getElementById('recipient').value='https://app.example.com/saml/acs';
 d.getElementById('analyze').click();
 const diagnostics=d.getElementById('diagnostics').textContent;
 assert.match(diagnostics,/Recipient matches/);
 assert.match(diagnostics,/At least one SubjectConfirmationData recipient matches/);
 assert.doesNotMatch(diagnostics,/Recipient mismatch/);
 dom.window.close();
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

test('Graph response explainer gives local throttling guidance and escapes response text',()=>{
 const dom=setup(),d=dom.window.document;
 let fetchCalls=0;dom.window.fetch=()=>{fetchCalls++;throw new Error('network use is forbidden in this test');};
 d.getElementById('graph-response-status').value='429';
 d.getElementById('graph-response-retry').value='10';
 d.getElementById('graph-response-body').value=JSON.stringify({error:{
  code:'TooManyRequests',message:'<img src=x onerror=alert(1)>',
  innerError:{code:'429','request-id':'synthetic-request-id'}
 }});
 d.getElementById('graph-response-explain').click();
 const result=d.getElementById('graph-response-result');
 assert.equal(result.hidden,false);
 assert.match(result.textContent,/throttled this request/);
 assert.match(result.textContent,/Retry-After value \(10\)/);
 assert.match(result.textContent,/Do not retry immediately/);
 assert.match(result.textContent,/synthetic-request-id/);
 assert.equal(result.querySelector('img'),null);
 assert.equal(fetchCalls,0);
 dom.window.close();
});

test('Graph response explainer identifies opaque nextLink paging without following it',()=>{
 const dom=setup(),d=dom.window.document;
 d.getElementById('graph-response-status').value='200';
 d.getElementById('graph-response-body').value=JSON.stringify({
  value:[],
  '@odata.nextLink':'https://graph.microsoft.com/v1.0/users?$skiptoken=synthetic-cursor'
 });
 d.getElementById('graph-response-explain').click();
 const result=d.getElementById('graph-response-result').textContent;
 assert.match(result,/Another page is available/);
 assert.match(result,/complete URL exactly as returned/);
 assert.match(result,/custom headers/);
 assert.doesNotMatch(result,/synthetic-cursor/);
 dom.window.close();
});

test('Graph response explainer diagnoses access denial and clears stale input/results',()=>{
 const dom=setup(),d=dom.window.document;
 d.getElementById('graph-response-status').value='403';
 d.getElementById('graph-response-body').value=JSON.stringify({error:{
  code:'Authorization_RequestDenied',message:'Access denied.'
 }});
 d.getElementById('graph-response-explain').click();
 assert.match(d.getElementById('graph-response-result').textContent,/Access was denied/);
 assert.match(d.getElementById('graph-response-result').textContent,/signed-in user/);
 d.getElementById('graph-response-status').value='429';
 d.getElementById('graph-response-status').dispatchEvent(new dom.window.Event('input'));
 assert.equal(d.getElementById('graph-response-result').hidden,true);
 d.getElementById('graph-response-body').value='{invalid';
 d.getElementById('graph-response-explain').click();
 assert.match(d.getElementById('graph-response-error').textContent,/valid JSON/);
 d.getElementById('graph-response-clear').click();
 assert.equal(d.getElementById('graph-response-status').value,'');
 assert.equal(d.getElementById('graph-response-body').value,'');
 assert.equal(d.getElementById('graph-response-result').hidden,true);
 dom.window.close();
});

test('searchable Entra reference distinguishes directory properties from token claims',()=>{
 const dom=setup(),d=dom.window.document;
 assert.equal(d.querySelectorAll('#reference-rows tr').length,8);
 assert.match(d.getElementById('reference-rows').textContent,/No guaranteed direct claim mapping/);
 assert.equal(d.querySelectorAll('#reference-rows tr:first-child a').length,2);
 assert.match(d.querySelector('#reference-rows tr:first-child a').href,/graph\/api\/resources\/user/);
 assert.match(d.querySelector('#reference-rows tr:first-child a:last-of-type').href,/entra\/identity-platform/);
 const search=d.getElementById('reference-search');search.value='jobTitle';search.dispatchEvent(new dom.window.Event('input',{bubbles:true}));
 assert.equal(d.querySelectorAll('#reference-rows tr').length,1);
 assert.match(d.getElementById('reference-rows').textContent,/No guaranteed built-in mapping/);
 search.value='not-a-property';search.dispatchEvent(new dom.window.Event('input',{bubbles:true}));
 assert.equal(d.querySelectorAll('#reference-rows tr').length,0);
 assert.equal(d.getElementById('reference-empty').hidden,false);
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
