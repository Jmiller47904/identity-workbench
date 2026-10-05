'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { buildRequest, exportRequest } = require('../lib/graph-builder.cjs');
test('read-only template constrains endpoint, permissions and selected fields', () => {
  const r = buildRequest({template:'get-me', select:['id','department','id']});
  assert.equal(r.url, 'https://graph.microsoft.com/v1.0/me?$select=id,department');
  assert.deepEqual(r.permissions, ['User.Read']);
  assert.equal(r.documentation.verifiedOn, '2026-10-05');
  assert.throws(() => buildRequest({template:'get-me', authMode:'application'}));
  assert.throws(() => buildRequest({template:'get-me', body:{}}));
  assert.throws(() => buildRequest({template:'get-me', select:['passwordProfile']}));
});
test('profile update permits a documented subset and marks write impact', () => {
  const body = {department:'Identity', jobTitle:'Analyst'};
  const r = buildRequest({template:'update-user-profile', userId:'demo@example.com', body});
  assert.equal(r.method,'PATCH');
  assert.equal(r.url,'https://graph.microsoft.com/v1.0/users/demo%40example.com');
  body.department = 'changed';
  assert.equal(r.body.department,'Identity');
  assert.match(r.impact,/Writes/);
  assert.deepEqual(r.permissions,['User.ReadUpdate.All']);
});
test('profile update safely supports documented B2B and UPN characters', () => {
  const body = {department:'Identity'};
  const guest = buildRequest({
    template:'update-user-profile',
    userId:'AdeleVance_adatum.com#EXT#@contoso.onmicrosoft.com',
    body
  });
  assert.equal(
    guest.url,
    'https://graph.microsoft.com/v1.0/users/AdeleVance_adatum.com%23EXT%23%40contoso.onmicrosoft.com'
  );
  const apostrophe = buildRequest({
    template:'update-user-profile',
    userId:"o'brien!ops@example.com",
    body
  });
  assert.equal(
    apostrophe.url,
    'https://graph.microsoft.com/v1.0/users/o%27brien!ops%40example.com'
  );
});
test('reject malformed, unsupported and secret-bearing input without echoing it', () => {
  for (const body of ['{"secret":"do-not-print"', '[]', '{}', '{"passwordProfile":{}}', '{"department":null}', '{"department":42}']) {
    assert.throws(() => buildRequest({template:'update-user-profile', userId:'00000000-0000-0000-0000-000000000001', body}), e => !e.message.includes('do-not-print'));
  }
  for (const userId of ['https://evil.example','../me','id?x=y','id#frag',"id\n",'$user@example.com','user@-example.com']) {
    assert.throws(() => buildRequest({template:'update-user-profile', userId, body:{department:'IT'}}));
  }
  assert.throws(() => buildRequest({template:'__proto__'}));
});
test('exports quote literals without embedding or requesting credentials', () => {
  const r = buildRequest({template:'update-user-profile', userId:'00000000-0000-0000-0000-000000000001', body:{department:"O'Brien $(touch /tmp/nope) `whoami`"}});
  assert.match(exportRequest(r,'powershell'),/O''Brien/);
  assert.ok(exportRequest(r,'curl').includes("O'\"'\"'Brien"));
  assert.match(exportRequest(r,'curl'),/GRAPH_ACCESS_TOKEN/);
  assert.equal(JSON.parse(exportRequest(r,'json')).method,'PATCH');
  assert.throws(() => exportRequest(r,'bash'));
});
test('CLI returns a request and rejects secret-bearing definitions without disclosure', () => {
  const fs = require('node:fs'), os = require('node:os'), path = require('node:path');
  const { spawnSync } = require('node:child_process');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(),'graph-request-'));
  const file = path.join(dir,'request.json');
  const cli = path.resolve(__dirname,'../scripts/graph-request.cjs');
  try {
    fs.writeFileSync(file, JSON.stringify({template:'get-me'}));
    let result = spawnSync(process.execPath,[cli,file],{encoding:'utf8'});
    assert.equal(result.status,0);
    assert.equal(JSON.parse(result.stdout).method,'GET');
    fs.writeFileSync(file, JSON.stringify({template:'get-me',token:'SECRET'}));
    result = spawnSync(process.execPath,[cli,file],{encoding:'utf8'});
    assert.equal(result.status,1);
    assert.equal(result.stdout,'');
    assert.ok(!result.stderr.includes('SECRET'));
  } finally { fs.rmSync(dir,{recursive:true,force:true}); }
});
