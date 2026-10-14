import assert from 'node:assert/strict';
import {brokerDigest,brokerExecutionCheckout,prepareBrokerStateRefresh} from './stage-b-staged-broker-contract.mjs';
import {releaseTransitionDispatchInputs,successorReleaseStartKey} from './production-release-coordinator.mjs';

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
 const now=()=>runtime.now?.()??Date.now();
 const store=runtime.store,request=assertSuccessorRecoveryRequest(await store.getArtifact(recoveryReference));
 assert.equal(brokerDigest(request),recoveryReference);
 const continuation=await runtime.authenticateRequest(request)||null;
 const identity={schemaVersion:2,sourceSha:request.releaseSourceSha,ticketId:request.ticketId,
  recoveryReference,toolingSha:request.recoveryToolingSha};
 const release={...identity,releaseId:brokerDigest(identity)};
 const startKey=successorReleaseStartKey(release);
 const put=async value=>{const id=brokerDigest(value);await store.putArtifact(id,value);return id;};
 const get=async id=>{assert.match(id||'',digest);const value=await store.getArtifact(id);assert.equal(brokerDigest(value),id);return value;};
 const legacy=await store.readStart({sourceSha:release.sourceSha,ticketId:release.ticketId});
 const start=await store.readStart(startKey)||(legacy?.recovery===recoveryReference?legacy:null);
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
  const continuationPreparation=phase==='closure'&&continuation?await read(`closure:prepared:${continuation.round??1}`):null;
  const saved=continuationPreparation||(phase==='closure'&&continuation?null:await read(`${phase}:prepared`));
  const prior=await read(`${phase}:result`);
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
      publicationResult:publication.result,prerequisiteChain:publication.preparation.prerequisiteChain,
      successorRecovery:inputs.successorRecovery})
     :await (async()=>{
      const base=prepareBrokerStateRefresh({preparation:cutover.prepared.preparation,authorization:cutover.authorization,casResult:cutover.result});
      if(!continuation)return {...cutover.prepared,preparation:base};
      assert.equal(phase,'closure');assert.ok(continuation.currentTooling);
      const identity={schemaVersion:1,releaseId:release.releaseId,recoveryReference,
       releaseSourceSha:release.sourceSha,historicalTooling:cutover.prepared.preparation.recoveryTooling,
       currentTooling:continuation.currentTooling,cutover:base.cutover};
      const closureContinuation={...identity,operationId:brokerDigest(identity)};
      const previousRound=continuation.previousRound??0;
      const old=await read(previousRound?`closure:prepared:${previousRound}`:'closure:prepared');
      if(old){
       const oldReference=old.result;
       const oldAttempt=await read(`closure:attempt:${previousRound}`);
       if(oldAttempt){
        const proof=continuation.preNativeAbort;assert.equal(proof?.status,'PRE_NATIVE_ABORTED');
        assert.equal(proof.releaseId,release.releaseId);assert.equal(proof.sourceSha,release.sourceSha);
        assert.equal(proof.round,previousRound);assert.equal(proof.prepared,oldReference);
        assert.equal(proof.attemptSha256,brokerDigest(oldAttempt));
        assert.equal(proof.authorization,(await read(`closure:authorized:${previousRound}`))?.authorization);
        assert.deepEqual(proof.currentTooling,continuation.currentTooling);
       }else assert.equal(await read(`closure:authorized:${previousRound}`),null,'Historical closure authorization cannot be replaced');
       const retired=await read(`closure:retired:${previousRound}`);
       if(retired)assert.equal(retired.prepared,oldReference);
       else await write(`closure:retired:${previousRound}`,{prepared:oldReference,reason:continuation.preNativeAbort?'PRE_NATIVE_ABORTED':'TOOLING_ADVANCED_AFTER_CAS',
        ...(continuation.preNativeAbort?{preNativeAbort:continuation.preNativeAbort}:{}),
        ...(continuation.supersededAuthorization?{runId:continuation.supersededAuthorization.runId}: {})});
      }
      return {...cutover.prepared,preparation:prepareBrokerStateRefresh({preparation:cutover.prepared.preparation,
       authorization:cutover.authorization,casResult:cutover.result,closureContinuation})};
     })();
    prepared=await runtime.capturePreparation({release,inputs},phase,value);
    await write(phase==='closure'&&continuation?`closure:prepared:${continuation.round??1}`:`${phase}:prepared`,{result:await put(prepared)});
   }
   assert.equal(prepared.preparation.sourceSha,release.sourceSha);
   assert.equal(brokerExecutionCheckout(prepared.preparation).sourceSha,
    continuation&&phase==='closure'?continuation.currentTooling.sourceSha:request.recoveryToolingSha);
   await runtime.hydratePreparation({release,inputs},phase,prepared);
   const firstRound=phase==='closure'&&continuation?(continuation.round??1):0;
   for(let round=firstRound;;round++){
    assert.ok(round<20,'Repeated expired successor approvals require a new governed operation');
    if(phase==='cutover'&&round>0){
     const renewed=await read(`${phase}:prepared:${round}`);
     if(renewed)prepared=await get(renewed.result);
     else{
      if(Date.parse(prepared.preparation.successorReconciliation?.expiresAt||'')<=now()){
       const value=await runtime.runStageOperation({...inputs,operation:'prepare-successor-cutover',
        publicationPreparation:publication.preparation,publicationAuthorization:publication.authorization,
        publicationResult:publication.result,prerequisiteChain:publication.preparation.prerequisiteChain,
        successorRecovery:inputs.successorRecovery});
       prepared=await runtime.capturePreparation({release,inputs},phase,value);
      }
      await write(`${phase}:prepared:${round}`,{result:await put(prepared)});
     }
     assert.equal(prepared.preparation.sourceSha,release.sourceSha);
     assert.equal(brokerExecutionCheckout(prepared.preparation).sourceSha,request.recoveryToolingSha);
     await runtime.hydratePreparation({release,inputs},phase,prepared);
    }
    if(phase==='closure'&&round>firstRound){
     const renewed=await read(`closure:prepared:${round}`);
     if(renewed)prepared=await get(renewed.result);
     else await write(`closure:prepared:${round}`,{result:await put(prepared)});
     assert.equal(brokerExecutionCheckout(prepared.preparation).sourceSha,continuation?.currentTooling.sourceSha||request.recoveryToolingSha);
    }
    const preparedReference=brokerDigest(prepared);
    const attempt=await read(`${phase}:attempt:${round}`);
    const retired=await read(`${phase}:retired:${round}`);
    if(retired){assert.equal(retired.prepared,preparedReference);
     if(attempt){const signed=await read(`${phase}:authorized:${round}`);assert.equal(signed?.prepared,preparedReference);
      assert.equal(await runtime.classifyNativeAttempt({release,inputs},phase,prepared,await get(signed.authorization)),'PRE_NATIVE');}
     continue;}
    const failed=await read(`${phase}:approval-failed:${round}`);
    if(failed){
     assert.equal(attempt,null);assert.equal(await read(`${phase}:authorized:${round}`),null);
     assert.equal(failed.prepared,preparedReference);
     const pending=await read(`${phase}:pending:${round}`);
     assert.ok(pending,'Failed approval lacks its recorded child');
     assert.equal(pending.prepared,preparedReference);assert.equal(failed.runId,pending.runId);
     const checked=await runtime.obtainAuthorization({release,store,inputs,authorizationRound:round,pendingApproval:pending},phase,prepared,preparedReference);
     assert.deepEqual(checked,{status:'APPROVAL_FAILED',runId:failed.runId,conclusion:failed.conclusion});
     continue;
    }
    const evidenceExpired=()=>phase==='cutover'&&Date.parse(prepared.preparation.successorReconciliation?.expiresAt||'')<=now();
    if(evidenceExpired()&&!attempt){await write(`${phase}:retired:${round}`,{prepared:preparedReference,reason:'EVIDENCE_EXPIRED'});continue;}
    const authenticatedDispatch=async()=>{
     const journal=await read(`${phase}:dispatch:${round}`),identity=journal?.dispatch?.identity;
     assert.ok(identity,'Timed-out approval lacks authenticated dispatch');
     assert.equal(identity.repository,'T-ej2003/genuine-scan-main');
     assert.equal(identity.workflow,'authorize-production-stage-b-release-transition.yml');
     assert.equal(identity.workflowPath,'.github/workflows/authorize-production-stage-b-release-transition.yml');
     assert.equal(identity.ref,'main');assert.equal(identity.targetSha,brokerExecutionCheckout(prepared.preparation).sourceSha);
     assert.deepEqual(identity.inputs,releaseTransitionDispatchInputs({release,authorizationRound:round},phase,preparedReference,prepared.preparation));
    };
    const timedOut=await read(`${phase}:approval-timeout:${round}`);
    if(timedOut){assert.equal(attempt,null);assert.equal(await read(`${phase}:authorized:${round}`),null);
     assert.equal(timedOut.prepared,preparedReference);assert.match(timedOut.runId,/^[1-9][0-9]*$/);
     const pending=await read(`${phase}:pending:${round}`);
     if(pending){assert.equal(pending.prepared,preparedReference);assert.equal(pending.runId,timedOut.runId);}
     else await authenticatedDispatch();
     continue;}
    const authorized=await read(`${phase}:authorized:${round}`);
    if(authorized){assert.equal(authorized.prepared,preparedReference);authorization=await get(authorized.authorization);}
    else{
     assert.equal(attempt,null,'Native intent cannot lack its authenticated authorization');
     const pending=await read(`${phase}:pending:${round}`);
     if(pending)assert.equal(pending.prepared,preparedReference);
     const approval=await runtime.obtainAuthorization({release,store,inputs,authorizationRound:round,pendingApproval:pending},phase,prepared,preparedReference);
     if(approval.status==='APPROVAL_TIMED_OUT'){
      assert.match(String(approval.runId),/^[1-9][0-9]*$/);
      if(pending)assert.equal(String(approval.runId),pending.runId);
      else await authenticatedDispatch();
      await write(`${phase}:approval-timeout:${round}`,{prepared:preparedReference,runId:String(approval.runId)});
      continue;
     }
     if(approval.status==='APPROVAL_FAILED'){
      assert.ok(['failure','cancelled'].includes(approval.conclusion));
      assert.match(String(approval.runId),/^[1-9][0-9]*$/);
      if(pending)assert.equal(String(approval.runId),pending.runId,'Failed child differs from the recorded approval');
      else{
       await authenticatedDispatch();
       await write(`${phase}:pending:${round}`,{prepared:preparedReference,runId:String(approval.runId),
        runUrl:`https://github.com/T-ej2003/genuine-scan-main/actions/runs/${approval.runId}`});
      }
      await write(`${phase}:approval-failed:${round}`,{prepared:preparedReference,runId:String(approval.runId),conclusion:approval.conclusion});
      continue;
     }
     if(approval.status==='WAITING_FOR_APPROVAL'){
      assert.match(String(approval.runId),/^[1-9][0-9]*$/);
      assert.equal(approval.runUrl,`https://github.com/T-ej2003/genuine-scan-main/actions/runs/${approval.runId}`);
      if(pending){assert.equal(String(approval.runId),pending.runId);assert.equal(approval.runUrl,pending.runUrl);}
      else await write(`${phase}:pending:${round}`,{prepared:preparedReference,runId:String(approval.runId),runUrl:approval.runUrl});
      return {status:'WAITING_FOR_APPROVAL',releaseId:release.releaseId,sourceSha:release.sourceSha,
       phase,authorizationRound:round,runId:String(approval.runId),runUrl:approval.runUrl};
     }
     assert.equal(approval.status,'AUTHORIZED');authorization=approval.authorization;
     if(pending){assert.equal(authorization.schemaVersion,2);
      assert.equal(authorization.protectedEnvironmentApprovalEvidence.workflowRunId,pending.runId);}
     await runtime.authenticateAuthorization(prepared.preparation,authorization);
     assert.deepEqual(authorization.release,{releaseId:release.releaseId,phase,preparationReference:preparedReference,authorizationRound:round});
     await write(`${phase}:authorized:${round}`,{prepared:preparedReference,authorization:await put(authorization)});
    }
    await runtime.authenticateAuthorization(prepared.preparation,authorization);
    assert.deepEqual(authorization.release,{releaseId:release.releaseId,phase,preparationReference:preparedReference,authorizationRound:round});
    const native=await runtime.classifyNativeAttempt({release,inputs},phase,prepared,authorization);
    assert.ok(['PRE_NATIVE','RECOVER'].includes(native));
    if(!attempt){assert.equal(native,'PRE_NATIVE');if(Date.parse(authorization.expiresAt)<=now()||evidenceExpired()){
      await write(`${phase}:retired:${round}`,{prepared:preparedReference,reason:evidenceExpired()?'EVIDENCE_EXPIRED':'AUTHORIZATION_EXPIRED'});continue;}
     await write(`${phase}:attempt:${round}`,{prepared:preparedReference,authorization:brokerDigest(authorization)});}
    else{assert.equal(attempt.prepared,preparedReference);assert.equal(attempt.authorization,brokerDigest(authorization));
     if(native==='PRE_NATIVE'&&(Date.parse(authorization.expiresAt)<=now()||evidenceExpired())){
      await write(`${phase}:retired:${round}`,{prepared:preparedReference,reason:evidenceExpired()?'EVIDENCE_EXPIRED':'AUTHORIZATION_EXPIRED'});continue;}}
    const executionInputs={files:inputs.files,directory:inputs.directory,terraformDataDir:inputs.terraformDataDir};
    result=await runtime.runStageOperation({...executionInputs,operation:native==='RECOVER'
     ?phase==='cutover'?'recover-cutover':'recover-reconciliation'
     :phase==='cutover'?'cutover':'reconcile',preparation:prepared.preparation,authorization,planPath:prepared.planPath,
     ...(phase==='closure'?{casResult:cutover.result,cutoverPreparation:cutover.prepared.preparation,
      cutoverAuthorization:cutover.authorization}:{})});
    await runtime.authenticateCompletedTransition({release,inputs,request},phase,prepared,authorization,result,cutover);
    await write(`${phase}:result`,{prepared:preparedReference,authorization:brokerDigest(authorization),result:await put(result)});
    break;
   }
  }
  if(phase==='cutover')cutover={prepared,authorization,result};
  else{const closure=await runtime.authenticateClosure({release,inputs,request},{cutover,closure:{prepared,authorization,result}});
    return {status:'BROKER_CLOSURE_COMPLETE',releaseId:release.releaseId,sourceSha:release.sourceSha,
    toolingSha:request.recoveryToolingSha,closureToolingSha:brokerExecutionCheckout(prepared.preparation).sourceSha,
    closureSha256:await put(closure)};}
 }
 throw new Error('Unreachable successor phase');
}
