import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {publishPrivateEvidence,readPrivateEvidence,runPrivateEvidenceCli} from '../aws/stage-b-private-evidence.mjs';
import {brokerDigest} from '../aws/stage-b-staged-broker-contract.mjs';

const sourceSha='a'.repeat(40);
function fixture(kind='prerequisite'){
 const values=new Map();const store={putArtifact:(key,value)=>{if(values.has(key))assert.deepEqual(values.get(key),value);values.set(key,value);},getArtifact:key=>{assert.ok(values.has(key));return values.get(key);}};
 const bytes=Buffer.from('sensitive Terraform state');const reference=publishPrivateEvidence({bytes,kind,sourceSha,workflowRunId:'123',store});
 return {values,store,bytes,reference,kind,sourceSha,workflowRunId:'123'};
}
test('both private handoffs expose only exact immutable references and authenticate bytes',()=>{
 for(const kind of ['prerequisite','preparation']){
  const f=fixture(kind);assert.deepEqual(readPrivateEvidence(f),f.bytes);
  assert.ok(!JSON.stringify(f.reference).includes('sensitive'));assert.ok(!Object.hasOwn(f.reference,'payloadBase64'));
  for(const [key,value] of [['kind',kind==='preparation'?'prerequisite':'preparation'],['sourceSha','b'.repeat(40)],['workflowRunId','124'],['workflowRunAttempt','2']])assert.throws(()=>readPrivateEvidence({...f,[key]:value}));
  for(const [key,value] of [['payloadSha256','0'.repeat(64)],['payloadByteSize',999],['workflowPath','other.yml'],['evidenceSha256','1'.repeat(64)],['extra','sensitive']])assert.throws(()=>readPrivateEvidence({...f,reference:{...f.reference,[key]:value}}));
 }
});
test('missing, substituted or corrupt encrypted material fails closed',()=>{
 const f=fixture();assert.throws(()=>readPrivateEvidence({...f,store:{getArtifact:()=>undefined}}));
 const value=f.values.get(f.reference.evidenceSha256);
 assert.throws(()=>readPrivateEvidence({...f,store:{getArtifact:()=>({...value,payloadBase64:Buffer.from('different state').toString('base64')})}}));
 const bad={...value,payloadBase64:value.payloadBase64+'\n'};
 assert.throws(()=>readPrivateEvidence({...f,reference:{...f.reference,evidenceSha256:brokerDigest(bad)},store:{getArtifact:()=>bad}}));
});
test('public hosted CLI publishes and hydrates using the real conditional encrypted store, without overwrites',()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'stage-b-private-cli-'));fs.chmodSync(directory,0o700);
 const objects=new Map();const calls=[];
 const run=args=>{
  calls.push(args);
  if(args[0]==='s3api'&&args[1]==='put-object'){
   assert.equal(args[args.indexOf('--server-side-encryption')+1],'AES256');assert.equal(args[args.indexOf('--if-none-match')+1],'*');
   const key=args[args.indexOf('--key')+1];if(objects.has(key))return {status:1,stderr:'(PreconditionFailed)'};
   objects.set(key,fs.readFileSync(args[args.indexOf('--body')+1]));return {status:0,stdout:'{}'};
  }
  if(args[0]==='s3api'&&args[1]==='get-object'){
   const key=args[args.indexOf('--key')+1];assert.ok(objects.has(key));fs.writeFileSync(args.at(-1),objects.get(key));return '{}';
  }
  throw new Error('Unexpected external operation');
 };
 try{
  for(const kind of ['prerequisite','preparation']){
   const workflow=kind==='prerequisite'?'produce-production-green-stage-b-prerequisite-bundle':'prepare-production-green-stage-b-state-reconciliation';
   const input=path.join(directory,kind+'.zip'),reference=path.join(directory,kind+'-reference.json'),output=path.join(directory,kind+'-restored.zip');fs.writeFileSync(input,'private '+kind,{mode:0o600});
   const common=['--kind',kind,'--source-sha',sourceSha,'--producer-run-id','123'];
   const env={GITHUB_ACTIONS:'true',GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_REPOSITORY:'T-ej2003/genuine-scan-main',GITHUB_SHA:sourceSha,GITHUB_RUN_ID:'123',GITHUB_RUN_ATTEMPT:'1',GITHUB_WORKFLOW_REF:`T-ej2003/genuine-scan-main/.github/workflows/${workflow}.yml@refs/heads/main`};
   const argv=['--mode','publish',...common,'--input',input,'--output',reference];
   assert.throws(()=>runPrivateEvidenceCli(argv,{env:{...env,GITHUB_SHA:'b'.repeat(40)},run}));
   runPrivateEvidenceCli(argv,{env,run});runPrivateEvidenceCli(argv,{env,run});
   const read=['--mode','read',...common,'--input',reference,'--output',output];runPrivateEvidenceCli(read,{run});runPrivateEvidenceCli(read,{run});
   assert.equal(fs.readFileSync(output,'utf8'),'private '+kind);assert.equal(fs.statSync(output).mode&0o777,0o600);
   fs.writeFileSync(output,'changed');assert.throws(()=>runPrivateEvidenceCli(read,{run}));
  }
  assert.ok(calls.every(args=>args[0]==='s3api'));assert.equal(objects.size,2);
 }finally{fs.rmSync(directory,{recursive:true,force:true});}
});
