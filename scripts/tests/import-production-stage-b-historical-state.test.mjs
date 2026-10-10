import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {brokerDigest} from '../aws/stage-b-staged-broker-contract.mjs';
import {STAGE_B_TERRAFORM_BACKEND} from '../aws/stage-b-terraform-backend-contract.mjs';
import {importHistoricalStageBState,assertHistoricalStateImport} from '../aws/import-production-stage-b-historical-state.mjs';
import {rig,ready,authorization as authorize} from './fixtures/staged-broker-runtime.mjs';

const releaseSourceSha='2'.repeat(40),recoveryToolingSha='3'.repeat(40),recoveryId='4'.repeat(64),versionId='exact-version';

async function fixture(overrides={}) {
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'mscqr-historical-import-test-'));fs.chmodSync(directory,0o700);
 const r=rig({sourceSha:releaseSourceSha}),published=await ready(r);
 const preparation=structuredClone(r.p),publication=structuredClone(published.p.publication);
 const state={version:4,lineage:preparation.state.lineage,serial:preparation.state.serial,outputs:{},resources:[]};
 const bytes=Buffer.from(JSON.stringify(state));preparation.state.stateSha256=brokerDigest(bytes);
 const authorization=authorize(preparation);
 publication.preparationSha256=brokerDigest(preparation);publication.authorizationSha256=brokerDigest(authorization);
 const artifacts=new Map(),store={putArtifact:(reference,value)=>{assert.equal(brokerDigest(value),reference);
  const old=artifacts.get(reference);if(old)assert.deepEqual(old,value);else artifacts.set(reference,structuredClone(value));},
 getArtifact:reference=>{assert.ok(artifacts.has(reference),'Missing imported artifact');return structuredClone(artifacts.get(reference));}};
 let gets=0,verification=0;
 const run=args=>{
  if(args[0]==='sts')return JSON.stringify({Arn:overrides.callerArn||'arn:aws:iam::368992683803:root'});
  assert.deepEqual(args.slice(0,9),['s3api','get-object','--bucket',STAGE_B_TERRAFORM_BACKEND.bucketName,'--key',STAGE_B_TERRAFORM_BACKEND.stateKey,'--version-id',overrides.versionId||versionId,'--expected-bucket-owner']);
  gets++;fs.writeFileSync(args.at(-1),overrides.bytes||bytes,{mode:0o600});return '{}';
 };
 return {directory,store,artifacts,bytes,preparation,authorization,publication,run,
  args:{releaseSourceSha,recoveryToolingSha,recoveryId,brokerVersion:'13',versionId,expectedSha256:brokerDigest(bytes)},
  deps:{run,store,directory,readAuthority:()=>({preparation,authorization}),readReceipt:()=>publication,
   authenticateTooling:()=>true,verifyAuthorization:async()=>{verification++;return true;},
   signImport:()=>"AQ==",verifyImport:()=>true},calls:()=>({gets,verification})};
}

test('governed import binds exact S3 version and source receipt in the existing write-once store',async()=>{
 const f=await fixture();
 try{
  const result=await importHistoricalStageBState(f.args,f.deps);
  assert.equal(result.sha256,brokerDigest(f.bytes));assert.equal(result.serial,f.preparation.state.serial);
  const receipt=f.store.getArtifact(result.reference);
  assert.equal(receipt.historical.versionId,versionId);
  assert.deepEqual(assertHistoricalStateImport(receipt,{releaseSourceSha,recoveryToolingSha,recoveryId,brokerVersion:'13',
   publication:f.publication,store:f.store,verifyImport:()=>true}),f.bytes);
  assert.deepEqual(f.calls(),{gets:1,verification:1});
  assert.equal(fs.readdirSync(f.directory).length,0,'Historical state remained on local disk');
 }finally{fs.rmSync(f.directory,{recursive:true,force:true});}
});

test('historical import fails before publication for unauthorized identity, wrong version or forged publication',async()=>{
 for(const change of [f=>{f.run=()=>JSON.stringify({Arn:'arn:aws:iam::368992683803:role/mscqr-production-release-deployer'});f.deps.run=f.run;},
  f=>{f.args.versionId='other-version';},f=>{f.publication.target.version='12';},
  f=>{f.publication.sourceSha='f'.repeat(40);},f=>{f.deps.verifyAuthorization=async()=>false;}]){
  const f=await fixture();try{change(f);await assert.rejects(()=>importHistoricalStageBState(f.args,f.deps));
   assert.equal(f.artifacts.size,0);assert.equal(f.calls().gets,0);}finally{fs.rmSync(f.directory,{recursive:true,force:true});}
 }
});

test('historical import rejects changed bytes, lineage and serial without writing evidence',async()=>{
 for(const mutate of [s=>({...s,serial:s.serial+1}),s=>({...s,lineage:'0'.repeat(36)}),s=>({...s,outputs:{changed:{value:true}}})]){
  const f=await fixture();try{f.deps.run=args=>{if(args[0]==='sts')return f.run(args);
   const state=mutate(JSON.parse(f.bytes));fs.writeFileSync(args.at(-1),JSON.stringify(state),{mode:0o600});return '{}';};
   await assert.rejects(()=>importHistoricalStageBState(f.args,f.deps));assert.equal(f.artifacts.size,0);
   assert.equal(fs.readdirSync(f.directory).length,0);}finally{fs.rmSync(f.directory,{recursive:true,force:true});}
 }
});

test('import receipt rejects substituted operation, release, version metadata or store bytes',async()=>{
 const f=await fixture();try{const result=await importHistoricalStageBState(f.args,f.deps),receipt=f.store.getArtifact(result.reference);
  const options={releaseSourceSha,recoveryToolingSha,recoveryId,brokerVersion:'13',publication:f.publication,store:f.store,verifyImport:()=>true};
  for(const change of [r=>({...r,recoveryId:'f'.repeat(64)}),r=>({...r,releaseSourceSha:'f'.repeat(40)}),
   r=>({...r,publicationResultSha256:'f'.repeat(64)}),r=>({...r,historical:{...r.historical,sha256:'f'.repeat(64)}})])
   assert.throws(()=>assertHistoricalStateImport(change(receipt),options));
  assert.throws(()=>assertHistoricalStateImport(receipt,{...options,verifyImport:()=>false}),/root signature/);
 }finally{fs.rmSync(f.directory,{recursive:true,force:true});}
});
