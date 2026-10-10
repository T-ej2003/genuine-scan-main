import assert from 'node:assert/strict';
import {brokerDigest,brokerExecutionCheckout,prepareBrokerStateRefresh} from './stage-b-staged-broker-contract.mjs';

const sha=/^[a-f0-9]{40}$/,digest=/^[a-f0-9]{64}$/;

export function assertSuccessorRecoveryRequest(value) {
 assert.deepEqual(Object.keys(value||{}).sort(),['brokerVersion','currentStateSha256','expectedAliasRevision','expectedAliasVersion',
  'historicalImportReference','imageEvidenceReference','imageSignatureReference','kind','publicationResultSha256',
  'recoveryId','recoveryToolingSha','releaseSourceSha','ticketId']);
 assert.equal(value.kind,'STAGE_B_SUCCESSOR_CUTOVER_REQUEST');
 for(const name of ['releaseSourceSha','recoveryToolingSha'])assert.match(value[name],sha);
 assert.notEqual(value.releaseSourceSha,value.recoveryToolingSha,'Successor recovery requires descendant tooling');
 for(const name of ['currentStateSha256','historicalImportReference','imageEvidenceReference','imageSignatureReference',
  'publicationResultSha256','recoveryId'])assert.match(value[name],digest);
 for(const name of ['brokerVersion','expectedAliasVersion'])assert.match(value[name],/^[1-9][0-9]*$/);
 assert.match(value.expectedAliasRevision,/^[A-Za-z0-9-]{1,128}$/);
 assert.match(value.ticketId,/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/);
 assert.notEqual(value.brokerVersion,value.expectedAliasVersion);
 return value;
}

// A new, explicit cutover-only coordinator. It never enters registration,
// pruning, policy convergence or publication, all of which are durable history.
export async function runSuccessorReleaseCoordinator({recoveryReference},runtime) {
 assert.match(recoveryReference||'',digest);
 const store=runtime.store,request=assertSuccessorRecoveryRequest(await store.getArtifact(recoveryReference));
 assert.equal(brokerDigest(request),recoveryReference);
 await runtime.authenticateRequest(request);
 const identity={schemaVersion:2,sourceSha:request.releaseSourceSha,ticketId:request.ticketId,
  recoveryReference,toolingSha:request.recoveryToolingSha};
 const release={...identity,releaseId:brokerDigest(identity)};
 const startKey={sourceSha:release.sourceSha,ticketId:release.ticketId};
 const put=async value=>{const id=brokerDigest(value);await store.putArtifact(id,value);return id;};
 const get=async id=>{assert.match(id||'',digest);const value=await store.getArtifact(id);assert.equal(brokerDigest(value),id);return value;};
 const start=await store.readStart(startKey);
 if(start){assert.deepEqual(Object.keys(start).sort(),['recovery','release']);assert.equal(start.recovery,recoveryReference);
  assert.deepEqual(await get(start.release),release);}
 else await store.writeStart(startKey,{release:await put(release),recovery:recoveryReference});
 const read=async name=>{const record=await store.readStep(release.releaseId,name);
  if(record){assert.equal(record.releaseId,release.releaseId);assert.equal(record.sourceSha,release.sourceSha);assert.equal(record.name,name);}
  return record;};
 const write=(name,details)=>store.writeStep({releaseId:release.releaseId,sourceSha:release.sourceSha,name,...details});
 const publication=await runtime.authenticatePublication(request);
 assert.equal(brokerDigest(publication.result),request.publicationResultSha256);
 let cutover;
 for(const phase of ['cutover','closure']){
  const prior=await read(`${phase}:result`),saved=await read(`${phase}:prepared`);
  const inputs=await runtime.materializeInputs({request,release,phase,prepared:prior?await get(prior.prepared):saved?await get(saved.result):null,publication,cutover});
  let prepared,authorization,result;
  if(prior){prepared=await get(prior.prepared);authorization=await get(prior.authorization);result=await get(prior.result);
   await runtime.hydratePreparation({release,inputs},phase,prepared);
   await runtime.authenticateAuthorization(prepared.preparation,authorization,result.authorizedAt);
   await runtime.authenticateCompletedTransition({release,inputs,request},phase,prepared,authorization,result,cutover);
  }else{
   if(saved)prepared=await get(saved.result);
   else{
    const value=phase==='cutover'
     ?await runtime.runStageOperation({...inputs,operation:'prepare-successor-cutover',
      publicationPreparation:publication.preparation,publicationAuthorization:publication.authorization,
      publicationResult:publication.result,successorRecovery:inputs.successorRecovery})
     :{...cutover.prepared,preparation:prepareBrokerStateRefresh({preparation:cutover.prepared.preparation,
      authorization:cutover.authorization,casResult:cutover.result})};
    prepared=await runtime.capturePreparation({release,inputs},phase,value);
    await write(`${phase}:prepared`,{result:await put(prepared)});
   }
   assert.equal(prepared.preparation.sourceSha,release.sourceSha);
   assert.equal(brokerExecutionCheckout(prepared.preparation).sourceSha,request.recoveryToolingSha);
   await runtime.hydratePreparation({release,inputs},phase,prepared);
   const preparedReference=brokerDigest(prepared),authorized=await read(`${phase}:authorized:0`);
   if(authorized){assert.equal(authorized.prepared,preparedReference);authorization=await get(authorized.authorization);}
   else{
    const pending=await read(`${phase}:pending:0`);
    if(pending)assert.equal(pending.prepared,preparedReference);
    const approval=await runtime.obtainAuthorization({release,store,inputs,authorizationRound:0,pendingApproval:pending},phase,prepared,preparedReference);
    if(approval.status==='WAITING_FOR_APPROVAL'){
     if(!pending)await write(`${phase}:pending:0`,{prepared:preparedReference,runId:String(approval.runId),runUrl:approval.runUrl});
     return {status:'WAITING_FOR_APPROVAL',releaseId:release.releaseId,sourceSha:release.sourceSha,
      phase,runId:String(approval.runId),runUrl:approval.runUrl};
    }
    assert.equal(approval.status,'AUTHORIZED');authorization=approval.authorization;
    await runtime.authenticateAuthorization(prepared.preparation,authorization);
    assert.deepEqual(authorization.release,{releaseId:release.releaseId,phase,preparationReference:preparedReference,authorizationRound:0});
    await write(`${phase}:authorized:0`,{prepared:preparedReference,authorization:await put(authorization)});
   }
   await runtime.authenticateAuthorization(prepared.preparation,authorization);
   assert.deepEqual(authorization.release,{releaseId:release.releaseId,phase,preparationReference:preparedReference,authorizationRound:0});
   const attempt=await read(`${phase}:attempt:0`),native=await runtime.classifyNativeAttempt({release,inputs},phase,prepared,authorization);
   assert.ok(['PRE_NATIVE','RECOVER'].includes(native));
   if(!attempt){assert.equal(native,'PRE_NATIVE');assert.ok(Date.parse(authorization.expiresAt)>Date.now(),'Successor authorization expired before native intent');
    await write(`${phase}:attempt:0`,{prepared:preparedReference,authorization:brokerDigest(authorization)});}
   else{assert.equal(attempt.prepared,preparedReference);assert.equal(attempt.authorization,brokerDigest(authorization));
    if(native==='PRE_NATIVE')assert.ok(Date.parse(authorization.expiresAt)>Date.now(),
     'Pre-native successor authorization expired');}
   const executionInputs={files:inputs.files,directory:inputs.directory,terraformDataDir:inputs.terraformDataDir};
   result=await runtime.runStageOperation({...executionInputs,operation:native==='RECOVER'
    ?phase==='cutover'?'recover-cutover':'recover-reconciliation'
    :phase==='cutover'?'cutover':'reconcile',preparation:prepared.preparation,authorization,planPath:prepared.planPath,
    ...(phase==='closure'?{casResult:cutover.result,cutoverPreparation:cutover.prepared.preparation,
     cutoverAuthorization:cutover.authorization}:{})});
   await runtime.authenticateCompletedTransition({release,inputs,request},phase,prepared,authorization,result,cutover);
   await write(`${phase}:result`,{prepared:preparedReference,authorization:brokerDigest(authorization),result:await put(result)});
  }
  if(phase==='cutover')cutover={prepared,authorization,result};
  else{const closure=await runtime.authenticateClosure({release,inputs,request},{cutover,closure:{prepared,authorization,result}});
   return {status:'BROKER_CLOSURE_COMPLETE',releaseId:release.releaseId,sourceSha:release.sourceSha,
    toolingSha:request.recoveryToolingSha,closureSha256:await put(closure)};}
 }
 throw new Error('Unreachable successor phase');
}
