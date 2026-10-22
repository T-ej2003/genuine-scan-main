import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createHash} from 'node:crypto';
import test from 'node:test';
import {assertNormalGateCompletion} from '../aws/production-release-gate-completion.mjs';
import {NORMAL_ACTIVATION} from '../aws/production-normal-backend-activation.mjs';
import {stageBApprovalIdForReleaseSha} from '../aws/production-green-stage-b-contract.mjs';

const source='a'.repeat(40);
const names=['Authenticate production environment approval boundary','Apply and verify checksum-bound production RLS package',
 'Upload immutable production database receipt','Activate exact Stage-B backend candidate','Verify backend health',
 'Activate authenticated frontend image','Verify production after frontend activation','Commit authenticated security component state'];

test('normal Gate completion requires a successful post-frontend smoke before state commit',()=>{
 const workflow=fs.readFileSync(new URL('../../.github/workflows/release-gate.yml',import.meta.url),'utf8');
 assert.ok(workflow.indexOf('name: Activate authenticated frontend image')<workflow.indexOf('name: Verify production after frontend activation'));
 assert.ok(workflow.indexOf('name: Verify production after frontend activation')<workflow.indexOf('name: Commit authenticated security component state'));
 const run={id:10,run_attempt:1,head_sha:source,head_branch:'main',path:'.github/workflows/release-gate.yml',event:'workflow_dispatch',status:'completed',conclusion:'success',
  actor:{login:'bot'},repository:{full_name:'T-ej2003/genuine-scan-main'},head_repository:{full_name:'T-ej2003/genuine-scan-main'}};
 const steps=names.map((name,index)=>({name,number:index+1,status:'completed',conclusion:name==='Activate authenticated frontend image'?'skipped':'success'}));
 const job={run_id:10,run_attempt:1,head_sha:source,status:'completed',conclusion:'success',steps};
 const input={run,job,releaseTrainRunId:'9',sourceSha:source,webRequired:false};
 assert.throws(()=>assertNormalGateCompletion({...input,job:{...job,steps:steps.filter(step=>step.name!=='Verify production after frontend activation')}}),/post.*smoke|Verify production after frontend activation/i);
 assert.throws(()=>assertNormalGateCompletion({...input,job:{...job,steps:steps.map(step=>step.name==='Verify production after frontend activation'?{...step,conclusion:'failure'}:step)}}),/failure.*success|Expected values to be strictly equal/);
 assert.throws(()=>assertNormalGateCompletion({...input,run:{...run,head_sha:'b'.repeat(40)}}),/Expected values to be strictly equal/);
});

test('normal Gate completion binds backend, frontend, database and smoke to one live child run',()=>{
 const digest=`sha256:${'1'.repeat(64)}`,webDigest=`sha256:${'2'.repeat(64)}`;
 const targetArn='arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:27';
 const sourceArn='arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:24';
 const webArn='arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-frontend:7';
 const authorization={imageReleaseSha:source,authorizationSha256:'b'.repeat(64),images:[{service:'backend',digest}]};
 const rlsReceipt={schemaVersion:2,environment:'production',releaseSha:source,approvalId:stageBApprovalIdForReleaseSha(source),
  images:{backend:`368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${digest}`}};
 rlsReceipt.receiptBundleSha256=createHash('sha256').update(`${JSON.stringify(rlsReceipt)}\n`).digest('hex');
 const backendActivation={schemaVersion:2,operation:'PRODUCTION_NORMAL_BACKEND_ACTIVATION',sourceSha:source,imageReleaseSha:source,
  stageBAuthorizationSha256:authorization.authorizationSha256,workflowRunId:'10',releaseTrainRunId:'9',sourceArn,targetArn,
  normalActivationSourceArn:sourceArn,previousTaskDefinitionArn:sourceArn,targetTaskDefinitionArn:targetArn,newTaskDefinitionArn:targetArn,
  observedTaskDefinitionArn:targetArn,imageRef:`368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${digest}`,imageDigest:digest,
  clusterArn:NORMAL_ACTIVATION.clusterArn,serviceArn:NORMAL_ACTIVATION.serviceArn,serviceStable:true,desiredCount:2,runningCount:2,pendingCount:0};
 const run={id:10,run_attempt:1,head_sha:source,head_branch:'main',path:'.github/workflows/release-gate.yml',event:'workflow_dispatch',status:'completed',conclusion:'success',
  actor:{login:'bot'},repository:{full_name:'T-ej2003/genuine-scan-main'},head_repository:{full_name:'T-ej2003/genuine-scan-main'}};
 const job={run_id:10,run_attempt:1,head_sha:source,status:'completed',conclusion:'success',steps:names.map((name,index)=>({name,number:index+1,status:'completed',conclusion:'success'}))};
 const approvals=[{state:'approved',user:{type:'User',login:'operator',id:11},environments:[{name:'production'}]}];
 const components={backend:{sourceSha:source,establishedThroughSha:source,imageDigest:digest,taskDefinitionArn:targetArn,desiredCount:2},
  frontend:{sourceSha:source,establishedThroughSha:source,imageDigest:webDigest,taskDefinitionArn:webArn,desiredCount:2},
  database:{sourceSha:source,releaseIdentity:rlsReceipt.receiptBundleSha256},security:{sourceSha:source,releaseIdentity:'c'.repeat(64)}};
 const provenance={lane:'NORMAL_APPLICATION',workflow:'release-gate.yml',githubRunId:'10',generation:4,updatedAt:'2026-10-22T00:00:00.000Z'};
 const componentState={schemaVersion:2,environment:'production',repository:'T-ej2003/genuine-scan-main',generation:4,
  updatedAt:provenance.updatedAt,updatedByLane:'SECURITY_INFRASTRUCTURE',updatedByWorkflow:'release-gate.yml',githubRunId:'10',components,
  componentProvenance:Object.fromEntries(Object.keys(components).map(name=>[name,{...provenance}]))};
 const backendService={taskDefinition:targetArn,desiredCount:2,runningCount:2,pendingCount:0};
 const frontendService={taskDefinition:webArn,desiredCount:2,runningCount:2,pendingCount:0};
 const input={run,job,approvals,releaseTrainRunId:'9',sourceSha:source,authorization,rlsReceipt,backendActivation,componentState,backendService,frontendService,webRequired:true};
 assert.equal(assertNormalGateCompletion(input).frontendImageDigest,webDigest);
 assert.throws(()=>assertNormalGateCompletion({...input,frontendService:{...frontendService,taskDefinition:'wrong'}}));
 assert.throws(()=>assertNormalGateCompletion({...input,componentState:{...componentState,components:{...components,database:{...components.database,releaseIdentity:'wrong'}}}}));
 assert.throws(()=>assertNormalGateCompletion({...input,job:{...job,steps:job.steps.filter(step=>step.name!=='Verify production after frontend activation')}}));
});
