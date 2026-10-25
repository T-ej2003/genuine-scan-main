import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {createReleaseCoordinatorStore} from '../aws/production-release-evidence-store.mjs';
import {stageBApplyAttemptS3Key} from '../aws/stage-b-terraform-backend-contract.mjs';
import {brokerDigest} from '../aws/stage-b-staged-broker-contract.mjs';

test('operator claim time is read from the exact owned S3 object',()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'mscqr-claim-time-'));
 fs.chmodSync(directory,0o700);
 try{
  let command;
  const store=createReleaseCoordinatorStore({directory,repositoryRoot:process.cwd(),run:args=>{
   command=args;return JSON.stringify({LastModified:'2026-10-22T10:00:00+00:00'});
  }});
  assert.equal(store.readOperationCommittedAt('a'.repeat(64),'BRIDGE:OPERATOR:DISPATCH'),'2026-10-22T10:00:00+00:00');
  assert.deepEqual(command.slice(0,2),['s3api','head-object']);
  assert.ok(command.includes('--expected-bucket-owner'));
  assert.equal(command[command.indexOf('--expected-bucket-owner')+1],'368992683803');
  assert.equal(command[command.indexOf('--key')+1],stageBApplyAttemptS3Key(brokerDigest({
   kind:'PRODUCTION_RELEASE_COORDINATOR_OPERATION',key:{operationId:'a'.repeat(64),phase:'BRIDGE:OPERATOR:DISPATCH'}})));
  assert.throws(()=>createReleaseCoordinatorStore({directory,repositoryRoot:process.cwd(),run:()=>JSON.stringify({LastModified:'invalid'})})
   .readOperationCommittedAt('a'.repeat(64),'BRIDGE:OPERATOR:DISPATCH'),/native S3 commit time/);
 }finally{fs.rmSync(directory,{recursive:true,force:true});}
});

test('green recovery keeps preparation and execution in the existing conditional journal',()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'mscqr-green-claim-time-'));
 fs.chmodSync(directory,0o700);
 try{
  const keys=[];
  const store=createReleaseCoordinatorStore({directory,repositoryRoot:process.cwd(),namespace:'green-backend-recovery',run:args=>{
   keys.push(args[args.indexOf('--key')+1]);
   return JSON.stringify({LastModified:'2026-10-25T20:00:00Z'});
  }});
  for(const phase of ['BACKEND:PREDECESSOR','BACKEND:REGISTER:DISPATCH',`BACKEND:HANDOFF:PREPARED:${'b'.repeat(64)}`,
   'BACKEND:UPDATE:DISPATCH','BACKEND:RECOVERY:COMPLETE']) store.readOperationCommittedAt('a'.repeat(64),phase);
  assert.equal(keys.length,5);
  for(const key of keys.slice(0,3)) assert.match(key,/\/green-backend-recovery\/prepare\/[a-f0-9]{64}\.json$/);
  for(const key of keys.slice(3)) assert.match(key,/\/green-backend-recovery\/execute\/[a-f0-9]{64}\.json$/);
  assert.equal(new Set(keys).size,5);
 }finally{fs.rmSync(directory,{recursive:true,force:true});}
});

test('green execution claim is atomic and cannot overwrite its prepared handoff',()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'mscqr-green-journal-'));
 fs.chmodSync(directory,0o700);
 const objects=new Map();
 const run=args=>{
  const key=args[args.indexOf('--key')+1];
  if(args[1]==='put-object'){
   if(objects.has(key))return {status:1,stderr:'PreconditionFailed (412)'};
   objects.set(key,fs.readFileSync(args[args.indexOf('--body')+1]));return '';
  }
  if(args[1]==='get-object'){
   if(!objects.has(key))throw Object.assign(new Error('NoSuchKey'),{stderr:'(NoSuchKey)'});
   fs.writeFileSync(args.at(-1),objects.get(key));return '{}';
  }
  throw Error('Unexpected AWS operation');
 };
 try{
  const store=createReleaseCoordinatorStore({directory,repositoryRoot:process.cwd(),namespace:'green-backend-recovery',run});
  const id='a'.repeat(64), prepared=`BACKEND:HANDOFF:PREPARED:${'b'.repeat(64)}`;
  assert.equal(store.claimOperation(id,prepared,{sourceSha:'c'.repeat(40)}),true);
  assert.equal(store.claimOperation(id,'BACKEND:UPDATE:DISPATCH',{target:'revision-35'}),true);
  assert.throws(()=>store.claimOperation(id,'BACKEND:UPDATE:DISPATCH',{target:'revision-35'}),/already exists/);
  assert.equal(objects.size,2);
  assert.equal([...objects.keys()].filter(key=>key.includes('/prepare/')).length,1);
  assert.equal([...objects.keys()].filter(key=>key.includes('/execute/')).length,1);
 }finally{fs.rmSync(directory,{recursive:true,force:true});}
});
