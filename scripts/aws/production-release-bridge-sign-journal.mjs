import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {brokerDigest} from './stage-b-staged-broker-contract.mjs';
import {assertBridgeRequest} from './production-release-bridge-contract.mjs';
import {STAGE_B} from './production-green-stage-b-contract.mjs';
import {createProductionAwsCommandRunner,PRODUCTION_AWS_CREDENTIAL_SOURCE} from './production-credential-source-contract.mjs';
import {createReleaseCoordinatorStore} from './production-release-evidence-store.mjs';

const SHA256=/^[a-f0-9]{64}$/;
const PHASE_KEYS=Object.freeze({ROOT_DROP:STAGE_B.rootDropKmsKeyArn,INVENTORY_ADOPTION:STAGE_B.approvalKmsKeyArn,ROTATION_SUCCESSOR:STAGE_B.approvalKmsKeyArn});
const checkerPrefix=`arn:aws:sts::${STAGE_B.account}:assumed-role/mscqr-production-rls-independent-checker/`;
const unknown=()=>Object.assign(new Error('KMS Sign outcome unknown; recover an authenticated result or obtain separate authorization. Never sign again.'),{code:'OUTCOME_UNKNOWN'});

export function createBridgeSignJournal({store,request,releaseId,sourceSha,ticketId,rotationId,manifestSha256,readCaller,phaseTimestamp,now=Date.now}={}) {
 assert.equal(typeof store?.readOperation,'function');assert.equal(typeof store?.claimOperation,'function');assert.equal(typeof store?.writeOperation,'function');
 assert.equal(typeof readCaller,'function');
 assertBridgeRequest(request,{releaseId,sourceSha,ticketId,rotationId,manifestSha256,now:now(),allowExpired:true});
 const operationId=request.operationId;
 return async function signOnce({phase,keyId,message,messageType,signingAlgorithm,invoke,recoverOnly=false}={}) {
  assert.ok(Object.hasOwn(PHASE_KEYS,phase),'Unsupported bridge signing phase');
  assert.equal(keyId,PHASE_KEYS[phase],'Bridge signing key differs');
  assert.ok(Buffer.isBuffer(message)&&message.length>0&&message.length<=4096,'Exact bounded KMS message required');
  assert.ok(['RAW','DIGEST'].includes(messageType));assert.equal(signingAlgorithm,'RSASSA_PSS_SHA_256');
  assert.equal(typeof invoke,'function');
  const caller=await readCaller();assert.equal(caller.Account,STAGE_B.account);
  if(phase==='ROOT_DROP')assert.equal(caller.Arn,`arn:aws:iam::${STAGE_B.account}:root`,'Root signer differs');
  else assert.ok(caller.Arn.startsWith(checkerPrefix)&&caller.Arn.length>checkerPrefix.length,'Independent checker signer differs');
  const input={keyId,messageBase64:message.toString('base64'),messageType,signingAlgorithm};
  const inputSha256=brokerDigest(input),recordPhase=`BRIDGE:SIGN:${phase}`;
  const dispatch=await store.readOperation(operationId,`${recordPhase}:DISPATCH`);
  if(dispatch){
   assert.equal(dispatch.requestSha256,request.requestSha256,'Bridge authorization changed after Sign dispatch');
   assert.equal(dispatch.inputSha256,inputSha256,'Bridge KMS input changed after Sign dispatch');
   assert.deepEqual(dispatch.input,input,'Bridge native Sign message changed');
   assert.equal(dispatch.principal,caller.Arn,'Bridge signer changed after Sign dispatch');
   const result=await store.readOperation(operationId,`${recordPhase}:RESULT`);
   if(!result)throw unknown();
   assert.deepEqual(result.dispatch,dispatch,'Persisted KMS result has a different dispatch');
   assert.equal(result.response?.KeyId,keyId);assert.match(result.response?.Signature||'',/^[A-Za-z0-9+/]+={0,2}$/);
   const completion=await store.readOperation(operationId,`${recordPhase}:COMPLETED`);
   if(completion)assert.equal(completion.resultSha256,brokerDigest(result),'KMS completion conflicts with native result');
   else{
    const recovered={dispatch,resultSha256:brokerDigest(result)};
    await store.writeOperation(operationId,`${recordPhase}:COMPLETED`,recovered);
    assert.deepEqual(await store.readOperation(operationId,`${recordPhase}:COMPLETED`),recovered);
   }
   return result.response;
  }
  if(recoverOnly)throw new Error('No durable KMS dispatch exists for the existing local signature');
  assertBridgeRequest(request,{releaseId,sourceSha,ticketId,rotationId,manifestSha256,now:now()});
  if(phaseTimestamp){const issued=Date.parse(phaseTimestamp);assert.ok(Number.isSafeInteger(issued)&&Math.abs(now()-issued)<=60000,'Bridge signing phase timestamp is stale or invalid');}
  const scope={operationId,phase,requestSha256:request.requestSha256,inputSha256,input,principal:caller.Arn,
   ...(phaseTimestamp?{phaseTimestamp}:{}),executionId:randomBytes(32).toString('hex'),claimedAt:new Date(now()).toISOString()};
  // A lost claim response never grants signing ownership, even if readback finds the record.
  assert.equal(await store.claimOperation(operationId,`${recordPhase}:DISPATCH`,scope),true);
  assert.deepEqual(await store.readOperation(operationId,`${recordPhase}:DISPATCH`),scope,'Sign dispatch claim readback differs');
  try{
   const response=await invoke();assert.equal(response?.KeyId,keyId);assert.match(response.Signature||'',/^[A-Za-z0-9+/]+={0,2}$/);
   const result={dispatch:scope,response};await store.writeOperation(operationId,`${recordPhase}:RESULT`,result);
   assert.deepEqual(await store.readOperation(operationId,`${recordPhase}:RESULT`),result,'Sign result readback differs');
   const completion={dispatch:scope,resultSha256:brokerDigest(result)};
   await store.writeOperation(operationId,`${recordPhase}:COMPLETED`,completion);
   assert.deepEqual(await store.readOperation(operationId,`${recordPhase}:COMPLETED`),completion,'Sign completion readback differs');
   return response;
  }catch(error){
   try{await store.writeOperation(operationId,`${recordPhase}:OUTCOME_UNKNOWN`,{dispatch:scope});}catch{/* Dispatch claim remains authoritative. */}
   throw Object.assign(unknown(),{cause:error});
  }
 };
}

export async function bridgeSignerFromEnvironment({env=process.env,directory,repositoryRoot=process.cwd(),readCaller}={}) {
 if(!env.MSCQR_BRIDGE_OPERATION_ID)return null;
 const operationId=env.MSCQR_BRIDGE_OPERATION_ID,runId=env.MSCQR_BRIDGE_RUN_ID,attempt=env.MSCQR_BRIDGE_RUN_ATTEMPT;
 assert.match(operationId,SHA256);assert.match(runId||'',/^[1-9][0-9]*$/);assert.match(attempt||'',/^[1-9][0-9]*$/);
 const run=createProductionAwsCommandRunner({credentialSource:PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE,profile:'mscqr-production-release-deployer',env});
 const store=createReleaseCoordinatorStore({run,directory,repositoryRoot});
 const request=await store.readOperation(operationId,`BRIDGE:REQUEST:${runId}:${attempt}`);
 assert.ok(request,'Authenticated bridge request is absent');assert.equal(request.operationId,operationId);
 return createBridgeSignJournal({store,request,releaseId:env.MSCQR_BRIDGE_RELEASE_ID,sourceSha:env.MSCQR_BRIDGE_SOURCE_SHA,
  ticketId:env.MSCQR_BRIDGE_TICKET_ID,rotationId:env.MSCQR_BRIDGE_ROTATION_ID,manifestSha256:env.MSCQR_BRIDGE_MANIFEST_SHA256,
  phaseTimestamp:env.MSCQR_BRIDGE_PHASE_TIMESTAMP,readCaller});
}
