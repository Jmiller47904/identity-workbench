'use strict';
(function(root){
 function text(value,limit){
  return typeof value==='string' ? value.slice(0,limit) : '';
 }
 function buildSanitizedDiagnostic(result,generatedAt){
  if(!result||typeof result!=='object')throw new Error('Inspect a response before exporting diagnostics.');
  const findings=Array.isArray(result.findings)?result.findings:[];
  const claims=Array.isArray(result.claims)?result.claims:[];
  return {
   schema:'identity-workbench-sanitized-diagnostic-v1',
   generatedAt:new Date(generatedAt===undefined?Date.now():generatedAt).toISOString(),
   format:text(result.format,80),
   diagnostics:findings.slice(0,500).map(item=>({
    level:['info','warn','issue'].includes(item?.level)?item.level:'info',
    title:text(item?.title,200)
   })),
   claimNames:[...new Set(claims.slice(0,1000).map(item=>text(item?.[0],300)).filter(Boolean))],
   omitted:['raw input','decoded claim values','expected configuration values','diagnostic detail text'],
   notice:'Sanitized local inspection summary only. It does not verify signatures, trust, replay protection, or full protocol validity.'
  };
 }
 const api={buildSanitizedDiagnostic};
 if(typeof module==='object'&&module.exports)module.exports=api;
 else root.IdentityDiagnosticExport=api;
})(typeof globalThis==='object'?globalThis:this);
