import assert from 'node:assert/strict';
import {STAGE_B,stageBApprovalIdForReleaseSha} from './production-green-stage-b-contract.mjs';
import {classifyNormalActivationLiveOutcome} from './production-normal-backend-activation.mjs';

const rlsModes=['full-rls-capability-preflight','full-rls-admin-bootstrap','full-rls-role-provision',
 'full-rls-role-verify','full-rls-admin-ownership','full-rls-runtime-policy','full-rls-verification',
 'full-rls-application-canary','full-rls-rollback'];

// Retry is permitted only when the failed child never entered a mutation step
// and the native service and broker claims still prove the exact predecessor.
export async function classifyPreMutationGateRetry({mode,job,run,sourceSha,backendService,frontendService,
 expectedBackendArn,expectedFrontendArn}={}){
 assert.ok(['OVERLAP','NORMAL'].includes(mode));
 assert.equal(job?.status,'completed');assert.ok(['failure','cancelled','timed_out'].includes(job.conclusion));
 assert.equal(typeof run,'function');
 const step=name=>{
  const matches=(job.steps||[]).filter(item=>item.name===name);
  return matches.length===1?matches[0]:null;
 };
 const stable=(service,target)=>service?.taskDefinition===target&&service.desiredCount>0&&
  service.runningCount===service.desiredCount&&service.pendingCount===0;
 if(!stable(backendService,expectedBackendArn)||!stable(frontendService,expectedFrontendArn))return 'OUTCOME_UNKNOWN';
 if(mode==='OVERLAP')return step('Deploy rotation transition backend ECS service')?.conclusion==='skipped'
  ?'INCOMPLETE':'OUTCOME_UNKNOWN';
 if(step('Apply and verify checksum-bound production RLS package')?.conclusion!=='skipped'||
  step('Activate exact Stage-B backend candidate')?.conclusion!=='skipped'||
  step('Activate authenticated frontend image')?.conclusion!=='skipped')return 'OUTCOME_UNKNOWN';
 const approvalId=stageBApprovalIdForReleaseSha(sourceSha);
 for(const modeName of rlsModes){
  const key=`${approvalId}#${modeName}`;
  const claim=JSON.parse(run(['dynamodb','get-item','--table-name',STAGE_B.replayTable,
   '--key',JSON.stringify({approvalMode:{S:key}}),'--consistent-read','--output','json','--no-cli-pager']));
  if(claim.Item)return 'OUTCOME_UNKNOWN';
 }
 return 'INCOMPLETE';
}

// A failed child may be rerun under its original run ID only after native
// journals and live state prove that its completed ECS transitions are reusable.
export async function classifyPostMutationNormalGateRecovery({store,backendOperationId,frontendOperationId,run,
 childRunId,expectedOverlapRunId,sourceSha,authorizationSha256,webAuthorizationSha256,backendService,frontendService,expectedFrontendArn,componentState,webRequired,
 classifyBackend=classifyNormalActivationLiveOutcome}={}){
 assert.equal(typeof store?.readOperation,'function');assert.equal(typeof run,'function');
 const binding=await store.readOperation(backendOperationId,'BACKEND:BINDING');
 const dispatch=await store.readOperation(backendOperationId,'BACKEND:UPDATE:DISPATCH');
 if(!binding||!dispatch||binding.identity?.sourceSha!==sourceSha||
  binding.identity.authorizationSha256!==authorizationSha256||dispatch.authorizationSha256!==authorizationSha256||
  String(binding.identity?.runIdentity?.workflowRunId)!==String(childRunId)||
  dispatch.sourceSha!==sourceSha||dispatch.targetTaskDefinitionArn!==binding.binding?.targetArn||
  dispatch.sourceTaskDefinitionArn!==binding.binding?.sourceArn)return 'OUTCOME_UNKNOWN';
 if(backendService?.taskDefinition!==binding.binding.targetArn||
  backendService.enableExecuteCommand!==true||backendService.propagateTags!=='TASK_DEFINITION'||
  classifyBackend({run,binding:binding.binding}).status!=='TARGET_STABLE')return 'OUTCOME_UNKNOWN';
 const stable=service=>service?.status==='ACTIVE'&&service.desiredCount===2&&
  service.runningCount===2&&service.pendingCount===0&&service.deployments?.length===1&&
  service.deployments[0].status==='PRIMARY'&&service.deployments[0].rolloutState==='COMPLETED'&&
  service.deployments[0].taskDefinition===service.taskDefinition;
 if(!stable(frontendService))return 'OUTCOME_UNKNOWN';
 const frontendDispatch=webRequired?await store.readOperation(frontendOperationId,'FRONTEND:UPDATE:DISPATCH'):null;
 if(frontendDispatch){
  const registration=await store.readOperation(frontendOperationId,'FRONTEND:REGISTER:COMPLETED');
  if(frontendDispatch.sourceSha!==sourceSha||frontendDispatch.authorizationSha256!==webAuthorizationSha256||
   !registration||registration.intent?.authorizationSha256!==webAuthorizationSha256||
   frontendDispatch.targetTaskDefinitionArn!==registration.taskDefinitionArn||
   frontendService.taskDefinition!==registration.taskDefinitionArn)return 'OUTCOME_UNKNOWN';
 }else if(frontendService.taskDefinition!==expectedFrontendArn)return 'OUTCOME_UNKNOWN';
 const backendProvenance=String(componentState?.componentProvenance?.backend?.githubRunId||'');
 const overlapPredecessor=/^[1-9][0-9]*$/.test(String(expectedOverlapRunId||''))&&
  String(expectedOverlapRunId)===backendProvenance&&
  componentState?.components?.backend?.taskDefinitionArn===binding.binding.sourceArn&&
  componentState?.components?.security?.sourceSha===sourceSha;
 if(componentState?.components?.backend?.taskDefinitionArn===binding.binding.targetArn&&!overlapPredecessor){
  if(backendProvenance!==String(childRunId)||
   componentState.components.backend.imageDigest!==binding.binding.digest||
   componentState.components.security?.sourceSha!==sourceSha)return 'CONFLICTED';
 }else if(!overlapPredecessor&&componentState?.components?.backend?.taskDefinitionArn!==binding.binding.sourceArn)return 'CONFLICTED';
 return 'RESUME_SAME_RUN';
}

// The RLS broker's native per-mode claims/receipts decide whether a rerun may
// execute a missing mode. A claim without its receipt remains fail closed there.
export async function classifyPreBackendNormalGateRecovery({store,backendOperationId,frontendOperationId,
 backendService,frontendService,expectedBackendArn,expectedFrontendArn,componentState,expectedOverlapRunId,sourceSha}={}){
 assert.equal(typeof store?.readOperation,'function');
 if(await store.readOperation(backendOperationId,'BACKEND:UPDATE:DISPATCH')||
  frontendOperationId&&await store.readOperation(frontendOperationId,'FRONTEND:REGISTER:DISPATCH'))return 'OUTCOME_UNKNOWN';
 const stable=(service,arn)=>service?.taskDefinition===arn&&service.status==='ACTIVE'&&
  service.desiredCount===2&&service.runningCount===2&&service.pendingCount===0&&
  service.deployments?.length===1&&service.deployments[0].status==='PRIMARY'&&
  service.deployments[0].taskDefinition===arn&&service.deployments[0].rolloutState==='COMPLETED';
 if(!stable(backendService,expectedBackendArn)||!stable(frontendService,expectedFrontendArn)||
  componentState?.components?.backend?.taskDefinitionArn!==expectedBackendArn||
  sourceSha&&componentState?.components?.security?.sourceSha!==sourceSha||
  String(componentState?.componentProvenance?.backend?.githubRunId)!==String(expectedOverlapRunId))return 'CONFLICTED';
 return 'RESUME_SAME_RUN';
}

export function classifyPostMutationOverlapGateRecovery({backendService,frontendService,expectedFrontendArn,
 predecessorArn,targetArn,imageDigest,componentState,runningTasks,sourceSha}={}){
 const stable=(service,arn)=>service?.taskDefinition===arn&&service.status==='ACTIVE'&&
  service.desiredCount===2&&service.runningCount===2&&service.pendingCount===0&&
  service.deployments?.length===1&&service.deployments[0].status==='PRIMARY'&&
  service.deployments[0].taskDefinition===arn&&service.deployments[0].rolloutState==='COMPLETED';
 if(!stable(backendService,targetArn)||backendService.enableExecuteCommand!==true||
  backendService.propagateTags!=='TASK_DEFINITION'||!stable(frontendService,expectedFrontendArn)||
  !Array.isArray(runningTasks)||runningTasks.length!==2||runningTasks.some(task=>
   task.lastStatus!=='RUNNING'||task.taskDefinitionArn!==targetArn||
   task.containers?.filter(container=>container.name==='backend'&&container.imageDigest===imageDigest).length!==1))
  return 'OUTCOME_UNKNOWN';
 const backend=componentState?.components?.backend;
 if(backend?.taskDefinitionArn===predecessorArn)return 'INCOMPLETE';
 if(backend?.taskDefinitionArn===targetArn&&backend.imageDigest===imageDigest&&
  componentState.components.security?.sourceSha===sourceSha)return 'INCOMPLETE';
 return 'CONFLICTED';
}
