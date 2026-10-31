'use strict';
const $=id=>document.getElementById(id);
const descriptions={aud:'Intended recipient. Compare with the API or application expecting this token.',iss:'Issuer identifier. Must match the trusted issuer configuration.',exp:'Expiration time, shown in UTC.',nbf:'Token must not be accepted before this time.',iat:'Time the token was issued.',tid:'Entra tenant identifier.',oid:'Object identifier in the issuing tenant.',sub:'Subject identifier.',scp:'Delegated permission scopes.',roles:'Role values; their meaning depends on the token and application.',amr:'Authentication methods reported by the issuer.',azp:'Authorized client application in a v2 token.',appid:'Client application identifier commonly present in v1 tokens.',ver:'Token format version.',nonce:'Value to correlate an ID token with the authentication request.'};
function decode64(s){s=s.replace(/\s/g,'').replace(/-/g,'+').replace(/_/g,'/');if(!/^[A-Za-z0-9+/]*={0,2}$/.test(s)||s.length%4===1)throw Error('Invalid Base64 encoding.');return new TextDecoder('utf-8',{fatal:true}).decode(Uint8Array.from(atob(s),c=>c.charCodeAt(0)));}
function node(tag,cls,text){const el=document.createElement(tag);if(cls)el.className=cls;if(text!==undefined)el.textContent=text;return el;}
function analyzeJWT(input,expected,now){const parts=input.replace(/^Bearer\s+/i,'').split('.');if(parts.length===5)throw Error('This is an encrypted JWE. Decrypt it with an authorized tool before inspecting its claims.');if(parts.length!==3)throw Error('A JWT must have three dot-separated segments. For SAML, paste raw XML or a Base64 SAMLResponse.');let header,payload;try{header=JSON.parse(decode64(parts[0]));payload=JSON.parse(decode64(parts[1]));}catch{throw Error('Could not decode the JWT header or payload as UTF-8 JSON. Check that the complete token was pasted.');}if(!header||Array.isArray(header)||typeof header!=='object'||!payload||Array.isArray(payload)||typeof payload!=='object')throw Error('JWT header and payload must be JSON objects.');const findings=[];const add=(level,title,body)=>findings.push({level,title,body});add('info','Signature not verified','Decoded claims are untrusted. The receiving application must verify the signature using a trusted issuer’s keys and enforce its validation policy.');if(header.alg==='none'||!parts[2])add('issue','Unsigned token','No usable signature is present. Do not accept this token as proof of identity.');else if(!header.alg)add('issue','Missing signing algorithm','The JOSE header has no alg value.');
for(const k of ['exp','nbf','iat']){if(payload[k]!==undefined&&(typeof payload[k]!=='number'||!Number.isFinite(payload[k])))add('issue','Invalid '+k+' claim','JWT time claims must be numeric seconds since the Unix epoch.');}
if(Number.isFinite(payload.exp))add(payload.exp<=now?'issue':'info',payload.exp<=now?'Token has expired':'Expiration is in the future',`exp: ${date(payload.exp)}. Checked against this device’s clock with zero clock-skew allowance.`);else if(payload.exp===undefined)add('warn','No expiration claim','Check the token profile and receiving application’s lifetime requirements.');
if(Number.isFinite(payload.nbf)&&payload.nbf>now)add('issue','Token is not active yet','Check issuer and application clocks, nbf, and the validator’s allowed clock skew.');if(Number.isFinite(payload.iat)&&payload.iat>now+60)add('warn','Issued in the future','The issuing clock may be ahead of this device’s clock.');if(Number.isFinite(payload.exp)&&Number.isFinite(payload.nbf)&&payload.exp<=payload.nbf)add('issue','Inconsistent validity window','Expiration is at or before the not-before time.');
for(const [key,value]of [['aud',expected.aud],['iss',expected.iss]]){if(value){const match=Array.isArray(payload[key])?payload[key].includes(value):payload[key]===value;add(match?'info':'issue',key+' '+(match?'matches':'mismatch'),match?'The decoded value matches your expected configuration. This does not establish trust.':'The decoded value does not exactly match your expected configuration. Check the requested resource and application registration.');}else if(!payload[key])add('warn','Missing '+key,'Check the required claims for your token profile.');}
if(['00000003-0000-0000-c000-000000000000','https://graph.microsoft.com','https://graph.microsoft.com/'].includes(payload.aud))add('info','Microsoft Graph audience','This token targets Microsoft Graph. A token for Graph is not an access token for your own API. Graph owns its access-token format; a v2 endpoint request does not force a v2 access token.');else if(payload.ver==='1.0'||payload.ver==='2.0')add('info','Entra token version '+payload.ver,'For access tokens, the resource API controls the token version. ID-token versions follow the endpoint used. Version alone does not show that a proxy changed the token.');
if(payload.scp)add('info','Delegated scopes present','scp reports delegated scopes. Confirm the required permission appears as an exact space-delimited scope and consent is in place.');if(payload.roles)add('info','Role claims present','Compare role values with the receiving application’s required roles. roles alone does not prove this is an application-only access token.');if(payload.hasgroups||payload._claim_names?.groups)add('warn','Group overage indicator','The full group list may be omitted. Check group overage handling and use trusted directory APIs with appropriate permissions; do not blindly follow a token-provided URL.');
return{format:'JWT',claims:Object.entries(payload),raw:JSON.stringify({header,payload},null,2),findings,stats:[['Algorithm',header.alg||'Missing'],['Version',payload.ver||'Unspecified'],['Claims',Object.keys(payload).length]]};}
function date(n){try{return new Date(n*1000).toISOString();}catch{return 'Out of supported date range';}}
function parseSamlTime(value){const match=/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:\d{2})$/.exec(value);if(!match)return NaN;const year=Number(match[1]),month=Number(match[2]),day=Number(match[3]),hour=Number(match[4]),minute=Number(match[5]),second=Number(match[6]);const leap=year%4===0&&(year%100!==0||year%400===0);const days=[31,leap?29:28,31,30,31,30,31,31,30,31,30,31];if(month<1||month>12||day<1||day>days[month-1]||hour>23||minute>59||second>59)return NaN;if(match[7]!=='Z'){const offsetHour=Number(match[7].slice(1,3)),offsetMinute=Number(match[7].slice(4,6));if(offsetHour>14||offsetMinute>59||(offsetHour===14&&offsetMinute!==0))return NaN;}const stamp=Date.parse(value);return Number.isFinite(stamp)?stamp/1000:NaN;}
function analyzeSAML(input,expected,now){let xml=input;if(/(?:^|[?&])SAMLResponse=/.test(xml)){const params=new URLSearchParams(xml.includes('?')?xml.slice(xml.indexOf('?')+1):xml);xml=params.get('SAMLResponse')||'';}else if(/^%3c/i.test(xml))xml=decodeURIComponent(xml);if(!xml.trim().startsWith('<'))xml=decode64(xml);if(/<!DOCTYPE|<!ENTITY/i.test(xml))throw Error('XML document types and entity declarations are not supported. Paste the SAML response without a DTD.');const doc=new DOMParser().parseFromString(xml,'application/xml');if(doc.querySelector('parsererror'))throw Error('The SAML XML is malformed. Check that the full response was pasted.');const A='urn:oasis:names:tc:SAML:2.0:assertion',P='urn:oasis:names:tc:SAML:2.0:protocol';const all=(name,ns=A)=>Array.from(doc.getElementsByTagNameNS(ns,name));if(!['Response','Assertion'].includes(doc.documentElement.localName)||![A,P].includes(doc.documentElement.namespaceURI))throw Error('Expected a SAML 2.0 Response or Assertion.');const findings=[];const add=(level,title,body)=>findings.push({level,title,body});const assertions=all('Assertion');if(all('EncryptedAssertion').length)throw Error('Encrypted SAML assertions cannot be inspected here. Decrypt the assertion with an authorized tool first.');if(assertions.length>1)throw Error('Multiple assertions found. Inspect one assertion at a time; this tool does not resolve assertion selection or signature wrapping.');if(!assertions.length)throw Error('No readable SAML assertion was found. Check the response status or paste the decoded assertion.');const issuers=all('Issuer').map(x=>x.textContent.trim());const audiences=all('Audience').map(x=>x.textContent.trim());const names=all('NameID').map(x=>x.textContent);const recipients=all('SubjectConfirmationData').map(x=>x.getAttribute('Recipient')).filter(Boolean);const claims=[['Issuer',issuers],['Audience',audiences],['NameID',names],['Recipient',recipients]];for(const at of all('Attribute'))claims.push([at.getAttribute('Name')||'(unnamed attribute)',Array.from(at.getElementsByTagNameNS(A,'AttributeValue')).map(v=>v.textContent)]);
add('info','SAML signature not verified','A signature element is not proof of authenticity. This tool does not validate signatures, trust, response correlation, replay protection, or complete SAML profile rules.');if(!doc.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#','Signature').length)add('warn','No XML signature found','Check your service provider’s signing requirements and trusted IdP certificate.');const statuses=all('StatusCode',P).map(x=>x.getAttribute('Value'));if(statuses.length)add(statuses[0]==='urn:oasis:names:tc:SAML:2.0:status:Success'?'info':'issue','Response status',statuses.join(' → '));
for(const el of [...all('Conditions'),...all('SubjectConfirmationData')])for(const key of ['NotBefore','NotOnOrAfter']){const value=el.getAttribute(key);if(!value)continue;claims.push([el.localName+'.'+key,value]);const stamp=parseSamlTime(value);const bad=!Number.isFinite(stamp)||(key==='NotBefore'?stamp>now:stamp<=now);add(bad?'issue':'info',el.localName+' / '+key,!Number.isFinite(stamp)?'Invalid timestamp. Expected an XML dateTime with an explicit Z or numeric timezone and a real calendar date.':`${value} — ${bad?(key==='NotBefore'?'not active yet':'expired'):'time condition passes'}. Uses this device’s clock, with no skew allowance.`);}
if(![...all('Conditions'),...all('SubjectConfirmationData')].some(x=>x.hasAttribute('NotOnOrAfter')))add('warn','No assertion expiration found','Check the required lifetime restrictions for your SAML profile.');for(const [label,value,actual] of [['Issuer',expected.iss,issuers],['Audience',expected.aud,audiences],['Recipient',expected.recipient,recipients]])if(value){const match=actual.length>0&&(label==='Audience'?all('AudienceRestriction').length>0&&all('AudienceRestriction').every(r=>Array.from(r.getElementsByTagNameNS(A,'Audience')).some(x=>x.textContent.trim()===value)):actual.every(x=>x===value));add(match?'info':'issue',label+' '+(match?'matches':'mismatch'),match?'The inspected values match your expected configuration. Full protocol validation is still required.':'One or more required values are absent or differ. Compare the IdP and service provider configuration.');}if(!audiences.length)add('warn','No audience restriction found','Check the service provider’s audience requirements.');if(!names.length)add('info','No NameID found','Inspect subject and attribute mappings against the service provider’s requirements.');return{format:'SAML 2.0',claims,raw:xml,findings,stats:[['Assertions',assertions.length],['Attributes',all('Attribute').length],['Signatures',doc.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#','Signature').length]]};}
function render(r){$('empty').hidden=true;$('results').hidden=false;$('format').textContent=r.format;$('summary').replaceChildren(...r.stats.map(([k,v])=>{const d=node('div','stat');d.append(node('small','',k),node('strong','',String(v)));return d;}));$('count').textContent=r.findings.length+' checks';$('diagnostics').replaceChildren(...r.findings.map(f=>{const row=node('div','finding');const body=node('div');body.append(node('b','',f.title),node('p','',f.body));row.append(node('span','severity '+f.level,f.level.toUpperCase()),body);return row;}));$('claims').replaceChildren(...r.claims.map(([k,v])=>{const row=node('div','claim');const val=node('div','claim-value',typeof v==='object'?JSON.stringify(v,null,2):String(v));if(descriptions[k])val.append(node('span','claim-help',descriptions[k]));if(['exp','nbf','iat'].includes(k)&&typeof v==='number')val.append(node('span','claim-help',date(v)));row.append(node('div','claim-name',k),val);return row;}));$('raw').textContent=r.raw;}
function inspect(){ $('error').textContent='';try{let input=$('token').value.trim();if(!input)throw Error('Paste a token or choose an example first.');if(input.length>1000000)throw Error('Input exceeds the 1 MB inspection limit.');const expected={aud:$('audience').value.trim(),iss:$('issuer').value.trim(),recipient:$('recipient').value.trim()};const now=Date.now()/1000;const isJWT=/^(Bearer\s+)?[A-Za-z0-9_-]+\./i.test(input);render(isJWT?analyzeJWT(input,expected,now):analyzeSAML(input,expected,now));}catch(e){$('error').textContent=e.message;$('results').hidden=true;$('empty').hidden=false;$('format').textContent='CHECK INPUT';}}
$('analyze').onclick=inspect;$('clear').onclick=()=>{$('token').value='';$('error').textContent='';$('results').hidden=true;$('empty').hidden=false;$('format').textContent='READY';for(const id of ['claims','diagnostics','summary','raw'])$(id).replaceChildren();$('token').focus();};
function resetExpected(){for(const id of ['audience','issuer','recipient'])$(id).value='';}
$('jwt-sample').onclick=()=>{resetExpected();const n=Math.floor(Date.now()/1000);const enc=o=>btoa(JSON.stringify(o)).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');$('token').value=enc({typ:'JWT',alg:'RS256',kid:'synthetic-example'})+'.'+enc({aud:'00000003-0000-0000-c000-000000000000',iss:'https://sts.windows.net/11111111-2222-3333-4444-555555555555/',iat:n-3900,nbf:n-3900,exp:n-300,ver:'1.0',tid:'11111111-2222-3333-4444-555555555555',name:'Synthetic example user',scp:'User.Read',appid:'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'})+'.c3ludGhldGljLXNpZ25hdHVyZQ';inspect();};
$('saml-sample').onclick=()=>{resetExpected();const now=Date.now();$('token').value=`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_demo_response" Version="2.0" IssueInstant="${new Date(now).toISOString()}">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="_demo_assertion" Version="2.0" IssueInstant="${new Date(now).toISOString()}">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject><saml:NameID>demo@example.com</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="https://app.example.com/saml/acs" NotOnOrAfter="${new Date(now+300000).toISOString()}"/></saml:SubjectConfirmation></saml:Subject>
    <saml:Conditions NotBefore="${new Date(now-60000).toISOString()}" NotOnOrAfter="${new Date(now+300000).toISOString()}"><saml:AudienceRestriction><saml:Audience>urn:example:app</saml:Audience></saml:AudienceRestriction></saml:Conditions>
    <saml:AttributeStatement><saml:Attribute Name="role"><saml:AttributeValue>Reader</saml:AttributeValue></saml:Attribute><saml:Attribute Name="department"><saml:AttributeValue>Identity Engineering</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`;inspect();};

const graphBuilder=globalThis.IdentityGraphBuilder;
let currentGraphRequest=null;
function invalidateGraphPreview(){
 currentGraphRequest=null;
 $('graph-result').hidden=true;
 $('graph-error').textContent='';
 $('graph-export-output').value='';
}
function syncGraphTemplate(){
 const updating=$('graph-template').value==='update-user-profile';
 $('graph-user-field').hidden=!updating;
 $('graph-body-field').hidden=!updating;
 $('graph-select-field').hidden=updating;
}
function selectedGraphFields(){
 const value=$('graph-select').value.trim();
 return value ? value.split(',').map(item=>item.trim()).filter(Boolean) : undefined;
}
function buildGraphPreview(){
 invalidateGraphPreview();
 try{
  const template=$('graph-template').value;
  const request=graphBuilder.buildRequest({
   template,
   authMode:$('graph-auth-mode').value,
   ...(template==='update-user-profile'?{userId:$('graph-user-id').value.trim(),body:$('graph-body').value}:{select:selectedGraphFields()})
  });
  $('graph-method').textContent=request.method;
  $('graph-url').textContent=request.url;
  $('graph-version').textContent=request.documentation.apiVersion;
  $('graph-permissions').textContent=request.authMode+': '+(request.permissions.length?request.permissions.join(', '):'none listed');
  $('graph-impact').textContent=request.impact;
  $('graph-limitations').textContent=request.limitations.join(' ');
  const documentation=$('graph-documentation');
  documentation.href=request.documentation.source;
  $('graph-preview-body-wrap').hidden=!request.body;
  $('graph-preview-body').textContent=request.body?JSON.stringify(request.body,null,2):'';
  $('graph-export-output').value=graphBuilder.exportRequest(request,'json');
  currentGraphRequest=request;
  $('graph-result').hidden=false;
  $('graph-result').dataset.template=template;
  $('graph-result').dataset.authMode=request.authMode;
 }catch(error){
  $('graph-error').textContent=error.message;
 }
}
$('graph-template').addEventListener('change',()=>{syncGraphTemplate();invalidateGraphPreview();});
$('graph-auth-mode').addEventListener('change',invalidateGraphPreview);
for(const id of ['graph-user-id','graph-select','graph-body'])$(id).addEventListener('input',invalidateGraphPreview);
$('graph-preview-button').addEventListener('click',buildGraphPreview);
$('graph-clear-button').addEventListener('click',()=>{
 $('graph-template').value='get-me';$('graph-auth-mode').value='delegated';$('graph-user-id').value='';
 $('graph-select').value='';$('graph-body').value='{"department":"Identity","jobTitle":"Analyst"}';
 $('graph-export-output').value='';$('graph-error').textContent='';invalidateGraphPreview();syncGraphTemplate();
});
document.querySelectorAll('[data-graph-export]').forEach(button=>button.addEventListener('click',()=>{
 if($('graph-result').hidden||!currentGraphRequest)return;
 try{
  $('graph-export-output').value=graphBuilder.exportRequest(currentGraphRequest,button.dataset.graphExport);
 }catch(error){$('graph-error').textContent=error.message;$('graph-result').hidden=true;}
}));
syncGraphTemplate();

function graphResponseGuidance(status, retryAfter, response) {
 const findings=[];
 const add=(level,title,body)=>findings.push({level,title,body});
 const error=response?.error && typeof response.error==='object' && !Array.isArray(response.error)
  ? response.error : null;
 if(status===429){
  add('issue','Microsoft Graph throttled this request (429)',
   retryAfter
    ? 'Do not retry immediately. Wait for the supplied Retry-After value ('+retryAfter+') before retrying; reduce call frequency or operations per request.'
    : 'Do not retry immediately. Microsoft recommends exponential backoff when Retry-After is absent; reduce call frequency or operations per request.');
 }else if(status===503){
  add('warn','Microsoft Graph is temporarily unavailable (503)',
   retryAfter
    ? 'Wait for the supplied Retry-After value ('+retryAfter+') before retrying.'
    : 'The service may be unavailable or overloaded. Delay retries and follow endpoint-specific guidance.');
 }else if(status===401){
  add('issue','Authentication was not accepted (401)',
   'Check that the request used a valid access token intended for Microsoft Graph and the expected authentication flow. This local explainer does not inspect tokens or tenant configuration.');
 }else if(status===403){
  add('issue','Access was denied (403)',
   'Check the endpoint permission and consent, and whether the signed-in user can access the target. A granted permission does not by itself establish that the user has the required privilege.');
 }else if(status===404){
  add('warn','Resource or route was not found (404)',
   'Check the documented endpoint and API version, and confirm the target identifier and resource are correct for this tenant.');
 }else if(status===400||status===422){
  add('warn','Request was rejected ('+status+')',
   'Compare the endpoint, API version, query parameters, headers, and JSON body with that API’s documentation. The structured Graph error code may provide more specific context.');
 }else if(status>=500){
  add('warn','Microsoft Graph returned a server error ('+status+')',
   'Inspect the structured error details and request ID. Retry behavior depends on the endpoint and any Retry-After guidance.');
 }else if(status>=400){
  add('warn','Microsoft Graph returned HTTP '+status,
   'Use the HTTP status and structured error code as diagnostic context. Handling depends on the endpoint and tenant configuration.');
 }else if(status>=200&&status<300){
  add('info','Successful HTTP status',
   'The response status is in the success range. This tool does not validate the response contents or confirm an operation’s intended effect.');
 }else{
  add('info','HTTP status '+status,
   'Use the status and structured error details as context; handling depends on the endpoint.');
 }
 if((status===429||status===503)&&!retryAfter)
  add('info','No Retry-After value supplied',
   status===429
    ? 'Microsoft recommends exponential backoff when a throttled response has no Retry-After header.'
    : 'Check the endpoint documentation for retry behavior when no delay is supplied.');
 if(error){
  if(typeof error.code==='string')add('info','Graph error code',error.code);
  if(typeof error.message==='string')add('info','Graph error message',error.message);
  const inner=error.innerError&&typeof error.innerError==='object'?error.innerError:null;
  if(inner&&typeof inner.code==='string')add('info','Inner error code',inner.code);
  if(inner&&typeof inner['request-id']==='string')add('info','Request ID',inner['request-id']);
  else if(typeof error['request-id']==='string')add('info','Request ID',error['request-id']);
 }
 if(response&&typeof response['@odata.nextLink']==='string'&&response['@odata.nextLink']){
  add('info','Another page is available',
   'This response includes @odata.nextLink. Use the complete URL exactly as returned and treat it as opaque; this tool will not follow it. For directory pages, resend any required custom headers because they are not included by default on subsequent requests.');
 }
 return findings;
}
function invalidateGraphResponse(){
 $('graph-response-result').hidden=true;
 $('graph-response-result').replaceChildren();
 $('graph-response-error').textContent='';
}
function explainGraphResponse(){
 invalidateGraphResponse();
 try{
  const statusText=$('graph-response-status').value.trim();
  const status=Number(statusText);
  if(!statusText||!Number.isInteger(status)||status<100||status>599)
   throw Error('Enter an HTTP status code from 100 to 599.');
  const raw=$('graph-response-body').value;
  if(raw.length>500000)throw Error('Response JSON exceeds the 500 KB local inspection limit.');
  let response=null;
  if(raw.trim()){
   try{response=JSON.parse(raw);}catch{throw Error('Response body must be valid JSON or empty.');}
   if(!response||typeof response!=='object'||Array.isArray(response))
    throw Error('Response JSON must be an object.');
  }
  const findings=graphResponseGuidance(status,$('graph-response-retry').value.trim(),response);
  const result=$('graph-response-result');
  result.replaceChildren(...findings.map(f=>{
   const row=node('div','finding');
   const body=node('div');
   body.append(node('b','',f.title),node('p','',f.body));
   row.append(node('span','severity '+f.level,f.level.toUpperCase()),body);
   return row;
  }));
  result.hidden=false;
 }catch(error){$('graph-response-error').textContent=error.message;}
}
$('graph-response-explain').addEventListener('click',explainGraphResponse);
for(const id of ['graph-response-status','graph-response-retry','graph-response-body'])
 $(id).addEventListener('input',invalidateGraphResponse);
$('graph-response-clear').addEventListener('click',()=>{
 $('graph-response-status').value='';
 $('graph-response-retry').value='';
 $('graph-response-body').value='';
 invalidateGraphResponse();
 $('graph-response-status').focus();
});

const entraGraphSource='https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0';
const entraReference=[
 {property:'displayName',type:'String',claim:'ID token: name',guidance:'The name claim is a display value. Treat it as presentation data, not a stable identifier; confirm the token type and configuration.',claimSource:'https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference',claimSourceLabel:'ID token claims'},
 {property:'givenName',type:'String',claim:'ID token: given_name',guidance:'The given_name claim reflects the given name on the user object when included. Verify whether the application requests or receives this claim for the token type.',claimSource:'https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference',claimSourceLabel:'ID token claims'},
 {property:'surname',type:'String',claim:'ID token: family_name',guidance:'The family_name claim reflects the surname on the user object when included. Verify token configuration and avoid using it as an identifier.',claimSource:'https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference',claimSourceLabel:'ID token claims'},
 {property:'userPrincipalName',type:'String',claim:'Optional upn; preferred_username in v2 ID tokens',guidance:'UPN and preferred_username are not durable identifiers. Their presence and format vary by token version and configuration; do not assume they equal the sign-in name.',claimSource:'https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims-reference',claimSourceLabel:'Optional claims reference'},
 {property:'mail',type:'String',claim:'No guaranteed direct claim mapping',guidance:'Do not infer an email claim from mail. Email claims can be absent or differ; inspect the token and the application’s claim configuration.',claimSource:'https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference',claimSourceLabel:'Access token claims'},
 {property:'department',type:'String',claim:'No guaranteed built-in mapping',guidance:'A directory property does not automatically become a token claim. If required, verify an explicitly supported customization for the relevant token type.',claimSource:'https://learn.microsoft.com/en-us/entra/identity-platform/reference-claims-customization',claimSourceLabel:'Claims customization'},
 {property:'jobTitle',type:'String',claim:'No guaranteed built-in mapping',guidance:'A directory property does not automatically become a token claim. Confirm supported claim customization and test the actual token in the target application.',claimSource:'https://learn.microsoft.com/en-us/entra/identity-platform/reference-claims-customization',claimSourceLabel:'Claims customization'},
 {property:'id',type:'String (GUID)',claim:'oid (object identifier)',guidance:'The object identifier identifies the directory object within its tenant context. Validate tenant context too; do not substitute a display name or UPN.',claimSource:'https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference',claimSourceLabel:'Access token claims'}
];
function renderReference(query=''){
 const normalized=query.trim().toLocaleLowerCase();
 const matches=entraReference.filter(x=>Object.values(x).some(v=>String(v).toLocaleLowerCase().includes(normalized)));
 $('reference-rows').replaceChildren(...matches.map(x=>{
  const row=document.createElement('tr');
  const property=node('td','reference-property',x.property);property.append(node('span','reference-type',x.type));
  const claim=node('td','reference-claim',x.claim);const guidance=node('td','',x.guidance);
  const source=node('td');for(const [href,label] of [[entraGraphSource,'Graph v1.0'],[x.claimSource,x.claimSourceLabel]]){const link=document.createElement('a');link.href=href;link.target='_blank';link.rel='noreferrer';link.textContent=label+' ↗';source.append(link,document.createElement('br'));}
  row.append(property,claim,guidance,source);return row;
 }));
 $('reference-count').textContent=matches.length+' of '+entraReference.length+' entries';
 $('reference-empty').hidden=matches.length!==0;
}
renderReference();
$('reference-search').addEventListener('input',e=>renderReference(e.target.value));
