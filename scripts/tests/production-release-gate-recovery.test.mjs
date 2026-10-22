import test from 'node:test';
import assert from 'node:assert/strict';
import {classifyPreMutationGateRetry,classifyPostMutationNormalGateRecovery,classifyPreBackendNormalGateRecovery,classifyPostMutationOverlapGateRecovery} from '../aws/production-release-gate-recovery.mjs';
import {gateEcsOperationId} from '../aws/production-release-gate-ecs-journal.mjs';

const backend={taskDefinition:'backend:1',desiredCount:2,runningCount:2,pendingCount:0};
const frontend={taskDefinition:'frontend:1',desiredCount:2,runningCount:2,pendingCount:0};
const sourceSha='a'.repeat(40);
const steps=Object.freeze(['Apply and verify checksum-bound production RLS package','Activate exact Stage-B backend candidate',
 'Activate authenticated frontend image'].map(name=>({name,conclusion:'skipped'})));
const input={mode:'NORMAL',job:{status:'completed',conclusion:'failure',steps},sourceSha,
 backendService:backend,frontendService:frontend,expectedBackendArn:backend.taskDefinition,
 expectedFrontendArn:frontend.taskDefinition,run:()=>JSON.stringify({})};

test('failed Gate may retry only after native predecessor and broker-claim absence',async()=>{
 assert.equal(await classifyPreMutationGateRetry(input),'INCOMPLETE');
 assert.equal(await classifyPreMutationGateRetry({...input,job:{...input.job,conclusion:'cancelled'}}),'INCOMPLETE');
 assert.equal(await classifyPreMutationGateRetry({...input,job:{...input.job,conclusion:'timed_out'}}),'INCOMPLETE');
 assert.equal(await classifyPreMutationGateRetry({...input,run:()=>JSON.stringify({Item:{approvalMode:{S:'claimed'}}})}),
  'OUTCOME_UNKNOWN');
 assert.equal(await classifyPreMutationGateRetry({...input,backendService:{...backend,taskDefinition:'target:2'}}),
  'OUTCOME_UNKNOWN');
 const backendStarted={...input.job,steps:steps.map(step=>step.name==='Activate exact Stage-B backend candidate'
  ?{...step,conclusion:'failure'}:step)};
 assert.equal(await classifyPreMutationGateRetry({...input,job:backendStarted}),'OUTCOME_UNKNOWN');
 const overlap={...input,mode:'OVERLAP',job:{...input.job,steps:[{name:'Deploy rotation transition backend ECS service',
  conclusion:'skipped'}]}};
 assert.equal(await classifyPreMutationGateRetry(overlap),'INCOMPLETE');
 assert.equal(await classifyPreMutationGateRetry({...overlap,job:{...overlap.job,steps:[{name:'Deploy rotation transition backend ECS service',
  conclusion:'failure'}]}}),'OUTCOME_UNKNOWN');
});

test('failed child with completed backend switch resumes the same run only after native and live reconciliation',async()=>{
 const auth='b'.repeat(64),webAuth='c'.repeat(64),rotationId='rotation-test';
 const backendId=gateEcsOperationId({sourceSha,rotationId,releaseTrainRunId:'42',authorizationSha256:auth,kind:'BACKEND'});
 const frontendId=gateEcsOperationId({sourceSha,rotationId,releaseTrainRunId:'42',authorizationSha256:webAuth,kind:'FRONTEND'});
 const records=new Map();const readOperation=async(id,phase)=>records.get(`${id}:${phase}`)||null;
 const binding={sourceArn:'backend:1',targetArn:'backend:2',digest:'sha256:'+ 'd'.repeat(64)};
 records.set(`${backendId}:BACKEND:BINDING`,{identity:{sourceSha,authorizationSha256:auth,runIdentity:{workflowRunId:'91'}},binding});
 records.set(`${backendId}:BACKEND:UPDATE:DISPATCH`,{sourceSha,authorizationSha256:auth,sourceTaskDefinitionArn:binding.sourceArn,targetTaskDefinitionArn:binding.targetArn});
 const stable=taskDefinition=>({taskDefinition,status:'ACTIVE',desiredCount:2,runningCount:2,pendingCount:0,
  enableExecuteCommand:true,propagateTags:'TASK_DEFINITION',
  deployments:[{status:'PRIMARY',rolloutState:'COMPLETED',taskDefinition}]});
 const baseline={store:{readOperation},backendOperationId:backendId,frontendOperationId:frontendId,run:()=>{},
  childRunId:'91',sourceSha,authorizationSha256:auth,webAuthorizationSha256:webAuth,
  backendService:stable(binding.targetArn),frontendService:stable('frontend:1'),expectedFrontendArn:'frontend:1',
  componentState:{components:{backend:{taskDefinitionArn:binding.sourceArn}}},webRequired:true,
  classifyBackend:()=>({status:'TARGET_STABLE'})};
 assert.equal(await classifyPostMutationNormalGateRecovery(baseline),'RESUME_SAME_RUN');
 assert.equal(await classifyPostMutationNormalGateRecovery({...baseline,backendService:stable('attacker:3')}),'OUTCOME_UNKNOWN');
 assert.equal(await classifyPostMutationNormalGateRecovery({...baseline,authorizationSha256:'0'.repeat(64)}),'OUTCOME_UNKNOWN');
 assert.equal(await classifyPostMutationNormalGateRecovery({...baseline,childRunId:'92'}),'OUTCOME_UNKNOWN');
 assert.equal(await classifyPostMutationNormalGateRecovery({...baseline,frontendService:stable('frontend:2')}),'OUTCOME_UNKNOWN');
 const frontendIntent={sourceSha,authorizationSha256:webAuth,targetTaskDefinitionArn:'frontend:2'};
 records.set(`${frontendId}:FRONTEND:UPDATE:DISPATCH`,frontendIntent);
 records.set(`${frontendId}:FRONTEND:REGISTER:COMPLETED`,{intent:{authorizationSha256:webAuth},taskDefinitionArn:'frontend:2'});
 assert.equal(await classifyPostMutationNormalGateRecovery({...baseline,frontendService:stable('frontend:2')}),'RESUME_SAME_RUN');
 assert.equal(await classifyPostMutationNormalGateRecovery({...baseline,webAuthorizationSha256:'0'.repeat(64),frontendService:stable('frontend:2')}),'OUTCOME_UNKNOWN');
 const committed={components:{backend:{taskDefinitionArn:binding.targetArn,imageDigest:binding.digest},security:{sourceSha}},
  componentProvenance:{backend:{githubRunId:'91'}}};
 assert.equal(await classifyPostMutationNormalGateRecovery({...baseline,frontendService:stable('frontend:2'),componentState:committed}),'RESUME_SAME_RUN');
 assert.equal(await classifyPostMutationNormalGateRecovery({...baseline,frontendService:stable('frontend:2'),componentState:{...committed,componentProvenance:{backend:{githubRunId:'92'}}}}),'CONFLICTED');
 const sameTask={...binding,sourceArn:binding.targetArn};
 records.set(`${backendId}:BACKEND:BINDING`,{identity:{sourceSha,authorizationSha256:auth,runIdentity:{workflowRunId:'91'}},binding:sameTask});
 records.set(`${backendId}:BACKEND:UPDATE:DISPATCH`,{sourceSha,authorizationSha256:auth,
  sourceTaskDefinitionArn:sameTask.sourceArn,targetTaskDefinitionArn:sameTask.targetArn});
 const overlapState={components:{backend:{taskDefinitionArn:sameTask.sourceArn,imageDigest:sameTask.digest},security:{sourceSha}},
  componentProvenance:{backend:{githubRunId:'80'}}};
 assert.equal(await classifyPostMutationNormalGateRecovery({...baseline,frontendService:stable('frontend:2'),expectedOverlapRunId:'80',componentState:overlapState}),
  'RESUME_SAME_RUN');
 assert.equal(await classifyPostMutationNormalGateRecovery({...baseline,frontendService:stable('frontend:2'),expectedOverlapRunId:'81',componentState:overlapState}),
  'CONFLICTED');
 assert.equal(await classifyPostMutationNormalGateRecovery({...baseline,frontendService:stable('frontend:2'),expectedOverlapRunId:'80',
  componentState:{...overlapState,components:{...overlapState.components,security:{sourceSha:'0'.repeat(40)}}}}),'CONFLICTED');
});

test('RLS-stage failure resumes the same child only with the exact overlap predecessor and no ECS dispatch',async()=>{
 const records=new Map(),store={readOperation:async(_,phase)=>records.get(phase)||null};
 const stable=taskDefinition=>({taskDefinition,status:'ACTIVE',desiredCount:2,runningCount:2,pendingCount:0,
  deployments:[{status:'PRIMARY',taskDefinition,rolloutState:'COMPLETED'}]});
 const input={store,backendOperationId:'backend',frontendOperationId:'frontend',backendService:stable('backend:1'),
  frontendService:stable('frontend:1'),expectedBackendArn:'backend:1',expectedFrontendArn:'frontend:1',
  expectedOverlapRunId:'80',componentState:{components:{backend:{taskDefinitionArn:'backend:1'}},
   componentProvenance:{backend:{githubRunId:'80'}}}};
 assert.equal(await classifyPreBackendNormalGateRecovery(input),'RESUME_SAME_RUN');
 assert.equal(await classifyPreBackendNormalGateRecovery({...input,sourceSha,componentState:{...input.componentState,
  components:{...input.componentState.components,security:{sourceSha:'0'.repeat(40)}}}}),'CONFLICTED');
 records.set('BACKEND:UPDATE:DISPATCH',{operationId:'backend'});
 assert.equal(await classifyPreBackendNormalGateRecovery(input),'OUTCOME_UNKNOWN');
 records.clear();
 assert.equal(await classifyPreBackendNormalGateRecovery({...input,componentState:{...input.componentState,
  componentProvenance:{backend:{githubRunId:'81'}}}}),'CONFLICTED');
 assert.equal(await classifyPreBackendNormalGateRecovery({...input,frontendService:stable('frontend:2')}),'CONFLICTED');
});

test('failed overlap child can use the existing native zero-update reconciliation only for exact stable target',()=>{
 const digest='sha256:'+ 'f'.repeat(64),targetArn='backend:2';
 const stable=taskDefinition=>({taskDefinition,status:'ACTIVE',desiredCount:2,runningCount:2,pendingCount:0,
  enableExecuteCommand:true,propagateTags:'TASK_DEFINITION',
  deployments:[{status:'PRIMARY',taskDefinition,rolloutState:'COMPLETED'}]});
 const input={backendService:stable(targetArn),frontendService:stable('frontend:1'),expectedFrontendArn:'frontend:1',
  predecessorArn:'backend:1',targetArn,imageDigest:digest,sourceSha,
  componentState:{components:{backend:{taskDefinitionArn:'backend:1'}}},
  runningTasks:[1,2].map(()=>({lastStatus:'RUNNING',taskDefinitionArn:targetArn,
   containers:[{name:'backend',imageDigest:digest}]}))};
 assert.equal(classifyPostMutationOverlapGateRecovery(input),'INCOMPLETE');
 assert.equal(classifyPostMutationOverlapGateRecovery({...input,backendService:stable('attacker:3')}),'OUTCOME_UNKNOWN');
 assert.equal(classifyPostMutationOverlapGateRecovery({...input,runningTasks:input.runningTasks.slice(0,1)}),'OUTCOME_UNKNOWN');
 assert.equal(classifyPostMutationOverlapGateRecovery({...input,componentState:{components:{backend:{taskDefinitionArn:'attacker:3'}}}}),'CONFLICTED');
});
