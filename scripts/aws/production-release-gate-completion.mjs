import assert from 'node:assert/strict';
import {assertProductionRlsReleaseReceipt,assertNormalBackendActivationEvidence} from './production-normal-backend-activation.mjs';
import {assertProductionComponentDeploymentState,componentDeploymentProvenance} from './production-component-deployment-state.mjs';
import {brokerDigest} from './stage-b-staged-broker-contract.mjs';

const repository='T-ej2003/genuine-scan-main';
const steps=['Authenticate production environment approval boundary','Apply and verify checksum-bound production RLS package',
 'Upload immutable production database receipt','Activate exact Stage-B backend candidate','Verify backend health',
 'Activate authenticated frontend image','Verify production after frontend activation','Commit authenticated security component state'];

export function assertNormalGateCompletion({run,job,approvals,releaseTrainRunId,sourceSha,authorization,rlsReceipt,backendActivation,componentState,backendService,frontendService,webRequired}={}){
 assert.match(String(releaseTrainRunId||''),/^[1-9][0-9]*$/);
 assert.equal(run?.repository?.full_name,repository);assert.equal(run.head_repository?.full_name,repository);
 assert.equal(run.head_sha,sourceSha);assert.equal(run.head_branch,'main');assert.equal(run.path,'.github/workflows/release-gate.yml');
 assert.equal(run.event,'workflow_dispatch');assert.equal(run.status,'completed');
 assert.ok(['success','failure'].includes(run.conclusion),'Normal Gate has no final authenticated conclusion');
 assert.equal(job?.run_id,run.id);assert.equal(job.run_attempt,run.run_attempt);assert.equal(job.head_sha,sourceSha);
 assert.equal(job.status,'completed');assert.equal(job.conclusion,'success');
 const byName=name=>{const matches=(job.steps||[]).filter(step=>step.name===name);assert.equal(matches.length,1,`${name} step identity is ambiguous`);return matches[0];};
 let previous=-1;
 for(const name of steps){
  const step=byName(name),index=job.steps.indexOf(step);
  assert.ok(index>previous,`Normal Gate ${name} occurred out of order`);previous=index;
  if(name==='Activate authenticated frontend image'&&!webRequired)assert.equal(step.conclusion,'skipped');
  else{assert.equal(step.status,'completed');assert.equal(step.conclusion,'success');}
 }
 assert.equal(byName('Verify production after frontend activation').conclusion,'success');
 const reviews=(approvals||[]).filter(item=>item.state==='approved'&&item.environments?.some(env=>env.name==='production'));
 assert.equal(reviews.length,1,'Normal Gate lacks one exact protected environment approval');
 assert.equal(reviews[0].user?.type,'User');assert.notEqual(reviews[0].user?.login?.toLowerCase(),run.actor?.login?.toLowerCase());
 assertProductionRlsReleaseReceipt(rlsReceipt,{sourceSha,imageDigest:authorization.images.find(item=>item.service==='backend')?.digest});
 assertNormalBackendActivationEvidence(backendActivation,{sourceSha,stageBAuthorization:authorization});
 assert.equal(String(backendActivation.workflowRunId),String(run.id));
 assert.equal(String(backendActivation.releaseTrainRunId),String(releaseTrainRunId));
 assertProductionComponentDeploymentState(componentState);
 for(const name of ['backend','database','security',...(webRequired?['frontend']:[])]){
  assert.equal(name==='backend'?componentState.components.backend?.establishedThroughSha:componentState.components[name]?.sourceSha,sourceSha,`${name} component release differs`);
  assert.equal(componentDeploymentProvenance(componentState,name).githubRunId,String(run.id),`${name} component is not from this Gate`);
 }
 assert.equal(componentState.components.database.releaseIdentity,rlsReceipt.receiptBundleSha256);
 assert.equal(componentState.components.backend.taskDefinitionArn,backendActivation.targetArn);
 assert.equal(componentState.components.backend.imageDigest,backendActivation.imageDigest);
 assert.equal(backendService?.taskDefinition,backendActivation.targetArn);
 assert.equal(backendService?.runningCount,backendService.desiredCount);assert.equal(backendService.pendingCount,0);
 if(webRequired){
  assert.equal(frontendService?.taskDefinition,componentState.components.frontend.taskDefinitionArn);
  assert.equal(frontendService.runningCount,frontendService.desiredCount);assert.equal(frontendService.pendingCount,0);
 }
 return {backendTaskDefinitionArn:backendActivation.targetArn,backendImageDigest:backendActivation.imageDigest,
  frontendTaskDefinitionArn:componentState.components.frontend?.taskDefinitionArn,
  frontendImageDigest:componentState.components.frontend?.imageDigest,
  rlsReceiptSha256:brokerDigest(rlsReceipt),componentStateGeneration:componentState.generation,smokeVerified:true};
}
