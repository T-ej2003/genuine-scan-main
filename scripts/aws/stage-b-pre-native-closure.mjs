import assert from 'node:assert/strict';
import {assertBrokerAuthorization,brokerDigest,brokerExecutionCheckout,BROKER_STATE_REFRESH} from './stage-b-staged-broker-contract.mjs';
import {releaseTransitionDispatchInputs} from './production-release-coordinator.mjs';
import {readStagedBrokerReceipt,normalizeBrokerAlias} from './stage-b-staged-broker-executor.mjs';
import {readStageBTerraformStateIdentity} from './stage-b-terraform-backend-contract.mjs';
import {STAGE_B} from './production-green-stage-b-contract.mjs';

// Absence is only corroboration: expired authenticated authority and unchanged live state are also required.
export async function authenticatePreNativeClosureAbort({store,releaseId,sourceSha,release,round,prepared,currentTooling,casResult,
 run,directory,verify,readReceipt=readStagedBrokerReceipt,readState=()=>readStageBTerraformStateIdentity(run),
 readAlias=()=>normalizeBrokerAlias(JSON.parse(run(['lambda','get-alias','--function-name',STAGE_B.brokerFunctionArn,
 '--name','reviewed','--output','json','--no-cli-pager']))),now=new Date()}) {
 const reference=brokerDigest(prepared),attempt=store.readStep(releaseId,`closure:attempt:${round}`);
 assert.equal(prepared.preparation.sourceSha,sourceSha);assert.equal(prepared.preparation.purpose,BROKER_STATE_REFRESH);
 assert.equal(prepared.preparation.cutover.resultSha256,brokerDigest(casResult));
 const signed=store.readStep(releaseId,`closure:authorized:${round}`);
 for(const [record,name] of [[attempt,`closure:attempt:${round}`],[signed,`closure:authorized:${round}`]]){
  assert.ok(record,'Historical closure attempt and authorization are required');
  assert.equal(record.releaseId,releaseId);assert.equal(record.sourceSha,sourceSha);assert.equal(record.name,name);
  assert.equal(record.prepared,reference);
 }
 assert.equal(attempt.authorization,signed.authorization);
 const authorization=store.getArtifact(signed.authorization);assert.equal(brokerDigest(authorization),signed.authorization);
 assert.deepEqual(authorization.release,{releaseId,phase:'closure',preparationReference:reference,authorizationRound:round});
 await assertBrokerAuthorization(authorization,prepared.preparation,{verify,now:new Date(authorization.issuedAt)});
 assert.ok(Date.parse(authorization.expiresAt)<=now.getTime(),'Historical closure authorization is still executable');
 const pending=store.readStep(releaseId,`closure:pending:${round}`),dispatch=store.readStep(releaseId,`closure:dispatch:${round}`);
 for(const [record,name] of [[pending,`closure:pending:${round}`],[dispatch,`closure:dispatch:${round}`]])if(record){
  assert.equal(record.releaseId,releaseId);assert.equal(record.sourceSha,sourceSha);assert.equal(record.name,name);
 }
 if(pending){assert.equal(pending.prepared,reference);assert.equal(pending.runId,authorization.protectedEnvironmentApprovalEvidence.workflowRunId);}
 if(dispatch){
  const identity=dispatch.dispatch.identity;
  assert.equal(identity.repository,'T-ej2003/genuine-scan-main');
  assert.equal(identity.workflow,'authorize-production-stage-b-release-transition.yml');
  assert.equal(identity.workflowPath,'.github/workflows/authorize-production-stage-b-release-transition.yml');
  assert.equal(identity.ref,'main');assert.equal(identity.targetSha,brokerExecutionCheckout(prepared.preparation).sourceSha);
  assert.ok(Number.isSafeInteger(identity.workflowId)&&identity.workflowId>0);
  assert.deepEqual(identity.inputs,releaseTransitionDispatchInputs({release,authorizationRound:round},'closure',reference,prepared.preparation));
  assert.equal(dispatch.dispatch.beforeRunIds.map(String).includes(authorization.protectedEnvironmentApprovalEvidence.workflowRunId),false);
 }
 assert.equal(store.readStep(releaseId,'closure:result'),null,'Completed closure must be adopted');
 const absent=[];
 for(const status of ['STATE_REFRESH_INTENT','STATE_REFRESH_UNKNOWN','RECONCILED_PENDING_RELEASE_CAS','STAGED_BROKER_TERMINAL_HANDOFF']){
  try{await readReceipt({run,id:signed.authorization,status,directory});}
  catch(error){if(error.code==='RECEIPT_ABSENT'){absent.push(status);continue;}throw error;}
  assert.fail('Existing native closure evidence requires native recovery');
 }
 const state=await readState(),alias=await readAlias();
 assert.equal(brokerDigest(state),brokerDigest(prepared.preparation.state),'Historical closure state changed');
 assert.equal(brokerDigest(alias),brokerDigest(casResult.alias),'Completed CAS alias changed');
 assert.equal(alias.FunctionVersion,prepared.preparation.target.version);
 return {status:'PRE_NATIVE_ABORTED',releaseId,sourceSha,round,prepared:reference,
  attemptSha256:brokerDigest(attempt),authorization:signed.authorization,currentTooling,state,alias,absent};
}
