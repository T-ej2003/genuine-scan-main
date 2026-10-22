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
