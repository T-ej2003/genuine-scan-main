import assert from 'node:assert/strict';
import {brokerDigest} from './stage-b-staged-broker-contract.mjs';
import {canonicalJson,STAGE_B} from './production-green-stage-b-contract.mjs';
import {mkdtempSync,rmSync,writeFileSync} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {assertProductionEnvironmentApprovalIdentity,assertProductionEnvironmentApprovalFreshness,
 PRODUCTION_ENVIRONMENT_APPROVAL} from './production-github-environment-approval.mjs';

const SHA40=/^[a-f0-9]{40}$/,SHA256=/^[a-f0-9]{64}$/;
const CHECKER=/^arn:aws:sts::368992683803:assumed-role\/mscqr-production-rls-independent-checker\/[^/]+$/;

export function createBridgeNativeAttestationRequest({completion,nativeResultSha256,nativeProofSha256,environmentApprovalSha256,
 workflowRunId,workflowRunAttempt,round=0,issuedAt,expiresAt}={}){
 assert.match(completion?.releaseId||'',SHA256);assert.match(completion?.sourceSha||'',SHA40);
 assert.match(completion?.rotationId||'',/^rotation-[a-z0-9-]+$/);
 assert.match(completion?.operationId||'',SHA256);assert.match(completion?.requestSha256||'',SHA256);
 assert.match(nativeResultSha256||'',SHA256);assert.match(nativeProofSha256||'',SHA256);assert.match(environmentApprovalSha256||'',SHA256);
 assert.match(String(workflowRunId||''),/^[1-9][0-9]*$/);assert.match(String(workflowRunAttempt||''),/^[1-9][0-9]*$/);
 assert.ok(Number.isSafeInteger(round)&&round>=0&&round<32);
 const start=Date.parse(issuedAt),end=Date.parse(expiresAt);
 assert.ok(Number.isSafeInteger(start)&&Number.isSafeInteger(end)&&end>start&&end-start<=10*60*1000,
  'Post-cutover checker authorization lifetime is invalid');
 const body={kind:'PRODUCTION_RELEASE_NATIVE_CHECKER_REQUEST_V1',schemaVersion:1,
  operationId:completion.operationId,releaseId:completion.releaseId,sourceSha:completion.sourceSha,rotationId:completion.rotationId,
  cutoverRequestSha256:completion.requestSha256,nativeResultSha256,nativeProofSha256,environmentApprovalSha256,
  workflowRunId:String(workflowRunId),workflowRunAttempt:String(workflowRunAttempt),round,issuedAt,expiresAt};
 return Object.freeze({...body,requestSha256:brokerDigest(body)});
}

export function assertBridgeNativeAttestationRequest(value,expected={},now=Date.now(),allowExpired=false){
 assert.ok(value&&typeof value==='object'&&!Array.isArray(value));
 assert.deepEqual(Object.keys(value).sort(),['kind','schemaVersion','operationId','releaseId','sourceSha','rotationId',
  'cutoverRequestSha256','nativeResultSha256','nativeProofSha256','environmentApprovalSha256','workflowRunId','workflowRunAttempt','round',
  'issuedAt','expiresAt','requestSha256'].sort());
 assert.deepEqual(value,createBridgeNativeAttestationRequest({...value,completion:{operationId:value.operationId,
  releaseId:value.releaseId,sourceSha:value.sourceSha,rotationId:value.rotationId,requestSha256:value.cutoverRequestSha256}}));
 for(const field of ['operationId','releaseId','sourceSha','rotationId','nativeResultSha256','nativeProofSha256','environmentApprovalSha256'])
  if(expected[field]!==undefined)assert.equal(value[field],expected[field],`Checker request ${field} differs`);
 assert.ok(allowExpired||now>=Date.parse(value.issuedAt)&&now<Date.parse(value.expiresAt),
  'Post-cutover checker request is expired or not yet valid');
 return value;
}

export function createBridgeNativeAttestation({request,nativeProofSha256,principal,signedAt}={}){
 assertBridgeNativeAttestationRequest(request,{},Date.parse(signedAt));
 assert.equal(nativeProofSha256,request.nativeProofSha256);assert.match(principal||'',CHECKER);
 const body={kind:'PRODUCTION_RELEASE_NATIVE_CHECKER_ATTESTATION_V1',schemaVersion:1,
  operationId:request.operationId,releaseId:request.releaseId,sourceSha:request.sourceSha,rotationId:request.rotationId,
  requestSha256:request.requestSha256,nativeResultSha256:request.nativeResultSha256,nativeProofSha256,
  signerArn:principal,keyArn:STAGE_B.approvalKmsKeyArn,signedAt};
 const message=Buffer.from(canonicalJson(body));
 assert.ok(message.length<=4096);
 return Object.freeze({...body,messageSha256:brokerDigest(body)});
}

export function assertBridgeNativeAttestation(value,{request,nativeProofSha256,now=Date.now()}={}){
 assert.ok(value&&typeof value==='object'&&!Array.isArray(value));
 assert.deepEqual(Object.keys(value).sort(),['kind','schemaVersion','operationId','releaseId','sourceSha','rotationId',
  'requestSha256','nativeResultSha256','nativeProofSha256','signerArn','keyArn','signedAt','messageSha256'].sort());
 assertBridgeNativeAttestationRequest(request,{},Date.parse(value.signedAt));
 assert.deepEqual(value,createBridgeNativeAttestation({request,nativeProofSha256,principal:value.signerArn,signedAt:value.signedAt}));
 assert.ok(now>=Date.parse(value.signedAt),'Post-cutover attestation is future dated');
 return value;
}

export const bridgeNativeAttestationMessage=value=>Buffer.from(canonicalJson(Object.fromEntries(
 Object.entries(value).filter(([key])=>key!=='messageSha256'))));

export async function requestBridgeNativeAttestation({store,cutoverRequest,candidate,nativeProof,approval,
 workflowRunId,workflowRunAttempt,now=Date.now()}={}){
 assert.equal(candidate?.operationId,cutoverRequest?.operationId);
 assert.equal(candidate.cutoverRequestSha256,cutoverRequest.requestSha256);
 assert.equal(candidate.releaseId,cutoverRequest.releaseId);
 assert.equal(candidate.sourceSha,cutoverRequest.sourceSha);assert.equal(candidate.rotationId,cutoverRequest.rotationId);
 assert.match(candidate.nativeResultArtifactSha256||'',SHA256);
 assert.equal(nativeProof?.nativeResultSha256,candidate.nativeResultArtifactSha256);
 assert.equal(nativeProof.sourceSha,candidate.sourceSha);assert.equal(nativeProof.rotationId,candidate.rotationId);
 assert.equal(nativeProof.proofSha256,brokerDigest(Object.fromEntries(Object.entries(nativeProof).filter(([key])=>key!=='proofSha256'))));
 const operationId=candidate.operationId;
 let round=0;
 for(;round<32;round++){
  const prior=await store.readOperation(operationId,`BRIDGE:NATIVE:ATTESTATION:REQUEST:ROUND:${round}`);
  if(!prior)break;
  assertBridgeNativeAttestationRequest(prior,{operationId,releaseId:candidate.releaseId,sourceSha:candidate.sourceSha,
   rotationId:candidate.rotationId,nativeResultSha256:candidate.nativeResultArtifactSha256,
   nativeProofSha256:nativeProof.proofSha256},now,true);
  const signPhase=`BRIDGE:NATIVE:ATTESTATION:SIGN:ROUND:${round}`;
  const dispatch=await store.readOperation(operationId,`${signPhase}:DISPATCH`);
  if(dispatch){
   assert.equal(dispatch.requestSha256,prior.requestSha256);
   const result=await store.readOperation(operationId,`${signPhase}:RESULT`);
   if(result)return prior;
   const committed=Date.parse(await store.readOperationCommittedAt(operationId,`${signPhase}:DISPATCH`));
   if(dispatch.executionContract!=='S3_COMMIT_BEFORE_SIGN_V1'||committed+1000<=Date.parse(prior.expiresAt))
    throw new Error('OUTCOME_UNKNOWN: prior checker Sign dispatch has no captured result');
  }
  if(now<Date.parse(prior.expiresAt))return prior;
 }
 assert.ok(round<32,'Post-cutover checker authorization rounds exhausted');
 assertProductionEnvironmentApprovalIdentity(approval,{sourceSha:candidate.sourceSha,
  repository:PRODUCTION_ENVIRONMENT_APPROVAL.repository});
 assertProductionEnvironmentApprovalFreshness(approval,{now:new Date(now)});
 assert.equal(approval.workflowRef,PRODUCTION_ENVIRONMENT_APPROVAL.releaseTrainWorkflowRef);
 assert.equal(approval.workflowRunId,String(workflowRunId));assert.equal(approval.workflowRunAttempt,String(workflowRunAttempt));
 assert.equal(approval.schemaVersion,3,'Fresh protected environment approval is required for checker attestation');
 const request=createBridgeNativeAttestationRequest({completion:{...candidate,requestSha256:candidate.cutoverRequestSha256},
  nativeResultSha256:candidate.nativeResultArtifactSha256,nativeProofSha256:nativeProof.proofSha256,
  environmentApprovalSha256:brokerDigest(approval),workflowRunId,workflowRunAttempt,round,
  issuedAt:new Date(now).toISOString(),expiresAt:new Date(Math.min(now+10*60*1000,
   Date.parse(approval.observedAt)+PRODUCTION_ENVIRONMENT_APPROVAL.maxAgeMs)).toISOString()});
 await store.putArtifact(brokerDigest(approval),approval);
 await store.putArtifact(nativeProof.proofSha256,nativeProof);
 assert.equal(await store.claimOperation(operationId,`BRIDGE:NATIVE:ATTESTATION:REQUEST:ROUND:${round}`,request),true);
 assert.deepEqual(await store.readOperation(operationId,`BRIDGE:NATIVE:ATTESTATION:REQUEST:ROUND:${round}`),request);
 return request;
}

export async function verifyBridgeNativeAttestationSignature({attestation,response,run}={}){
 assert.equal(typeof run,'function');
 assert.equal(response?.KeyId,STAGE_B.approvalKmsKeyArn);
 assert.match(response.Signature||'',/^[A-Za-z0-9+/]+={0,2}$/);
 const signature=Buffer.from(response.Signature,'base64');assert.ok(signature.length>0);
 const directory=mkdtempSync(path.join(os.tmpdir(),'mscqr-native-attestation-'));
 try{
  const messageFile=path.join(directory,'message'),signatureFile=path.join(directory,'signature');
  writeFileSync(messageFile,bridgeNativeAttestationMessage(attestation),{mode:0o600});
  writeFileSync(signatureFile,signature,{mode:0o600});
  const result=JSON.parse(run(['kms','verify','--key-id',STAGE_B.approvalKmsKeyArn,
   '--message',`fileb://${messageFile}`,'--message-type','RAW','--signature',`fileb://${signatureFile}`,
   '--signing-algorithm','RSASSA_PSS_SHA_256','--output','json','--no-cli-pager']));
  assert.equal(result.KeyId,STAGE_B.approvalKmsKeyArn);assert.equal(result.SignatureValid,true);
  return true;
 }finally{rmSync(directory,{recursive:true,force:true});}
}

export async function signBridgeNativeAttestationOnce({store,request,nativeProofSha256,checkerRun,verifyRun,now=Date.now}={}){
 assert.equal(typeof checkerRun,'function');assert.equal(typeof verifyRun,'function');
 assertBridgeNativeAttestationRequest(request,{},now(),true);
 assert.equal(nativeProofSha256,request.nativeProofSha256);
 const operationId=request.operationId,phase=`BRIDGE:NATIVE:ATTESTATION:SIGN:ROUND:${request.round}`;
 const caller=JSON.parse(checkerRun(['sts','get-caller-identity','--output','json','--no-cli-pager']));
 assert.equal(caller.Account,STAGE_B.account);assert.match(caller.Arn||'',CHECKER);
 const dispatch=await store.readOperation(operationId,`${phase}:DISPATCH`);
 if(dispatch){
  assert.equal(dispatch.requestSha256,request.requestSha256);assert.equal(dispatch.nativeProofSha256,nativeProofSha256);
  assert.match(dispatch.principal||'',CHECKER);
  const result=await store.readOperation(operationId,`${phase}:RESULT`);
  if(!result){
   const committed=Date.parse(await store.readOperationCommittedAt(operationId,`${phase}:DISPATCH`));
   if(dispatch.executionContract==='S3_COMMIT_BEFORE_SIGN_V1'&&committed+1000>Date.parse(request.expiresAt))
    throw new Error('REAUTHORIZATION_REQUIRED: checker claim committed after expiry; native Sign was forbidden');
   throw new Error('OUTCOME_UNKNOWN: checker KMS Sign dispatch has no durable result; never sign again');
  }
  assert.deepEqual(result.dispatch,dispatch);
  const completed=await store.readOperation(operationId,`${phase}:COMPLETED`);
  if(completed)assert.equal(completed.resultSha256,brokerDigest(result),'Checker KMS Sign completion conflicts');
  assertBridgeNativeAttestation(result.attestation,{request,nativeProofSha256,now:now()});
  assert.equal(dispatch.messageSha256,result.attestation.messageSha256);
  assert.equal(dispatch.principal,result.attestation.signerArn);
  await verifyBridgeNativeAttestationSignature({attestation:result.attestation,response:result.response,run:verifyRun});
  if(!completed){
   const recovered={dispatch,resultSha256:brokerDigest(result)};
   await store.writeOperation(operationId,`${phase}:COMPLETED`,recovered);
   assert.deepEqual(await store.readOperation(operationId,`${phase}:COMPLETED`),recovered);
  }
  return result;
 }
 assertBridgeNativeAttestationRequest(request,{},now());
 const attestation=createBridgeNativeAttestation({request,nativeProofSha256,principal:caller.Arn,signedAt:new Date(now()).toISOString()});
 const claim={operationId,requestSha256:request.requestSha256,nativeProofSha256,principal:caller.Arn,
  keyArn:STAGE_B.approvalKmsKeyArn,messageSha256:attestation.messageSha256,
  claimedAt:attestation.signedAt,executionContract:'S3_COMMIT_BEFORE_SIGN_V1'};
 assert.equal(await store.claimOperation(operationId,`${phase}:DISPATCH`,claim),true);
 assert.deepEqual(await store.readOperation(operationId,`${phase}:DISPATCH`),claim);
 const committed=Date.parse(await store.readOperationCommittedAt(operationId,`${phase}:DISPATCH`));
 assert.ok(Number.isSafeInteger(committed)&&committed>=Date.parse(claim.claimedAt)-1000);
 if(committed+1000>Date.parse(request.expiresAt))
  throw new Error('REAUTHORIZATION_REQUIRED: checker claim committed after expiry; native Sign was forbidden');
 const directory=mkdtempSync(path.join(os.tmpdir(),'mscqr-native-sign-'));
 try{
  const messageFile=path.join(directory,'message');writeFileSync(messageFile,bridgeNativeAttestationMessage(attestation),{mode:0o600});
  let response;
  try{response=JSON.parse(checkerRun(['kms','sign','--key-id',STAGE_B.approvalKmsKeyArn,
   '--message',`fileb://${messageFile}`,'--message-type','RAW','--signing-algorithm','RSASSA_PSS_SHA_256',
   '--output','json','--no-cli-pager']));}
  catch(error){throw new Error('OUTCOME_UNKNOWN: checker KMS Sign response was lost; never sign again',{cause:error});}
  const result={dispatch:claim,attestation,response};
  await store.writeOperation(operationId,`${phase}:RESULT`,result);
  assert.deepEqual(await store.readOperation(operationId,`${phase}:RESULT`),result);
  await verifyBridgeNativeAttestationSignature({attestation,response,run:verifyRun});
  const completion={dispatch:claim,resultSha256:brokerDigest(result)};
  await store.writeOperation(operationId,`${phase}:COMPLETED`,completion);
  assert.deepEqual(await store.readOperation(operationId,`${phase}:COMPLETED`),completion);
  return result;
 }finally{rmSync(directory,{recursive:true,force:true});}
}
