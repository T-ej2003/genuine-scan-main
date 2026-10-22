import test from 'node:test';
import assert from 'node:assert/strict';
import {createBridgeNativeAttestationRequest,assertBridgeNativeAttestationRequest,createBridgeNativeAttestation,
 assertBridgeNativeAttestation,bridgeNativeAttestationMessage,signBridgeNativeAttestationOnce} from '../aws/production-release-bridge-native-attestation.mjs';
import {STAGE_B} from '../aws/production-green-stage-b-contract.mjs';

const completion={operationId:'a'.repeat(64),releaseId:'b'.repeat(64),sourceSha:'c'.repeat(40),
 rotationId:'rotation-20260913011819-98b062c4',requestSha256:'d'.repeat(64)};
const start=Date.parse('2026-10-22T10:00:00.000Z');
const request=createBridgeNativeAttestationRequest({completion,nativeResultSha256:'e'.repeat(64),
 nativeProofSha256:'1'.repeat(64),
 environmentApprovalSha256:'f'.repeat(64),workflowRunId:'123',workflowRunAttempt:'1',
 issuedAt:new Date(start).toISOString(),expiresAt:new Date(start+10*60*1000).toISOString()});

test('fresh post-cutover checker request binds the exact native result and protected run',()=>{
 assert.equal(assertBridgeNativeAttestationRequest(request,{sourceSha:completion.sourceSha,
  rotationId:completion.rotationId,nativeResultSha256:'e'.repeat(64)},start),request);
 assert.throws(()=>assertBridgeNativeAttestationRequest(request,{},start+10*60*1000),/expired/);
 assert.throws(()=>assertBridgeNativeAttestationRequest({...request,nativeResultSha256:'0'.repeat(64)}, {},start),/Expected values to be strictly deep-equal/);
 assert.throws(()=>createBridgeNativeAttestationRequest({...request,completion,expiresAt:new Date(start+10*60*1000+1).toISOString()}),/lifetime/);
});

test('checker attestation is exact, short lived and cannot change result or signer',()=>{
 const signedAt=new Date(start+1000).toISOString();
 const principal='arn:aws:sts::368992683803:assumed-role/mscqr-production-rls-independent-checker/session';
 const attestation=createBridgeNativeAttestation({request,nativeProofSha256:'1'.repeat(64),principal,signedAt});
 assert.equal(attestation.keyArn,STAGE_B.approvalKmsKeyArn);
 assert.equal(assertBridgeNativeAttestation(attestation,{request,nativeProofSha256:'1'.repeat(64),now:start+2000}),attestation);
 assert.ok(bridgeNativeAttestationMessage(attestation).length<4096);
 for(const changed of [{...attestation,nativeProofSha256:'2'.repeat(64)},
  {...attestation,signerArn:'arn:aws:iam::368992683803:root'},
  {...attestation,sourceSha:'0'.repeat(40)}])assert.throws(()=>assertBridgeNativeAttestation(changed,{request,nativeProofSha256:'1'.repeat(64),now:start+2000}));
 assert.throws(()=>assertBridgeNativeAttestation(attestation,{request,nativeProofSha256:'1'.repeat(64),now:start}),/future dated/);
});

test('post-cutover checker Sign is captured once and reused after interruption',async()=>{
 const records=new Map(),commits=new Map();let signs=0;
 const store={readOperation:async(_id,phase)=>records.get(phase)||null,
  readOperationCommittedAt:async(_id,phase)=>commits.get(phase),
  claimOperation:async(_id,phase,value)=>{assert.equal(records.has(phase),false);records.set(phase,value);
   commits.set(phase,value.claimedAt);return true;},
  writeOperation:async(_id,phase,value)=>{records.set(phase,value);return true;}};
 const caller={Account:STAGE_B.account,Arn:'arn:aws:sts::368992683803:assumed-role/mscqr-production-rls-independent-checker/session'};
 const checkerRun=args=>{
  if(args[0]==='sts')return JSON.stringify(caller);
  assert.equal(args[0],'kms');assert.equal(args[1],'sign');signs++;
  return JSON.stringify({KeyId:STAGE_B.approvalKmsKeyArn,Signature:Buffer.from('signature').toString('base64')});
 };
 const verifyRun=args=>{assert.deepEqual(args.slice(0,2),['kms','verify']);return JSON.stringify({KeyId:STAGE_B.approvalKmsKeyArn,SignatureValid:true});};
 const input={store,request,nativeProofSha256:'1'.repeat(64),checkerRun,verifyRun,now:()=>start+1000};
 const first=await signBridgeNativeAttestationOnce(input);
 assert.equal(signs,1);assert.equal(first.attestation.nativeProofSha256,'1'.repeat(64));
 const again=await signBridgeNativeAttestationOnce({...input,now:()=>start+11*60*1000});
 assert.deepEqual(again,first);assert.equal(signs,1,'expired authorization cannot replay completed Sign');
 records.delete('BRIDGE:NATIVE:ATTESTATION:SIGN:ROUND:0:COMPLETED');
 await signBridgeNativeAttestationOnce({...input,now:()=>start+12*60*1000});
 assert.equal(signs,1,'lost completion marker is recovered from captured signature');
 await assert.rejects(()=>signBridgeNativeAttestationOnce({...input,nativeProofSha256:'2'.repeat(64)}),/strictly equal/);
});

test('ambiguous checker Sign and late native claim never trigger another Sign',async()=>{
 const phase='BRIDGE:NATIVE:ATTESTATION:SIGN:ROUND:0:DISPATCH';let signs=0,claim;
 const store={readOperation:async(_id,key)=>key===phase?claim:null,
  readOperationCommittedAt:async()=>new Date(start+1000).toISOString(),
  claimOperation:async(_id,_key,value)=>{claim=value;return true;}};
 const caller={Account:STAGE_B.account,Arn:'arn:aws:sts::368992683803:assumed-role/mscqr-production-rls-independent-checker/session'};
 const checkerRun=args=>args[0]==='sts'?JSON.stringify(caller):(signs++,(()=>{throw Error('lost response')})());
 const input={store,request,nativeProofSha256:'1'.repeat(64),checkerRun,
  verifyRun:()=>{throw Error('not reached')},now:()=>start+1000};
 await assert.rejects(()=>signBridgeNativeAttestationOnce(input),/OUTCOME_UNKNOWN/);
 await assert.rejects(()=>signBridgeNativeAttestationOnce(input),/OUTCOME_UNKNOWN/);
 assert.equal(signs,1);
 const lateStore={...store,readOperationCommittedAt:async()=>request.expiresAt};
 await assert.rejects(()=>signBridgeNativeAttestationOnce({...input,store:lateStore,now:()=>start+11*60*1000}),/REAUTHORIZATION_REQUIRED/);
 assert.equal(signs,1);
});
