import assert from 'node:assert/strict';
import {canonicalSha256} from './production-green-stage-b-contract.mjs';
import {assertProductionComponentDeploymentState,stateHash} from './production-component-deployment-state.mjs';

export const componentCommitOperationId=({sourceSha,rotationId,releaseTrainRunId,authorizationSha256}={})=>{
 assert.match(sourceSha||'',/^[a-f0-9]{40}$/);assert.match(rotationId||'',/^rotation-[a-z0-9-]+$/);
 assert.match(String(releaseTrainRunId||''),/^[1-9][0-9]*$/);
 assert.match(authorizationSha256||'',/^[a-f0-9]{64}$/);
 return canonicalSha256({kind:'PRODUCTION_RELEASE_GATE_COMPONENT_COMMIT_V1',sourceSha,rotationId,
  releaseTrainRunId:String(releaseTrainRunId),authorizationSha256});
};

export function matchesCommittedReleaseState({state,sourceSha,authorizationSha256,rlsReceipt,
 backendActivation,frontendActivation,childRunId,webRequired}={}){
 assertProductionComponentDeploymentState(state);
 const sourceBound=(name)=>String(state.componentProvenance?.[name]?.githubRunId)===String(childRunId);
 return state.components.security?.sourceSha===sourceSha&&
  state.components.security?.releaseIdentity===authorizationSha256&&
  state.components.database?.sourceSha===sourceSha&&
  state.components.database?.releaseIdentity===rlsReceipt?.receiptBundleSha256&&
  state.components.backend?.taskDefinitionArn===backendActivation?.targetArn&&
  state.components.backend?.imageDigest===backendActivation?.imageDigest&&
  ['security','database','backend'].every(sourceBound)&&
  (!webRequired||(state.components.frontend?.taskDefinitionArn===frontendActivation?.candidateTaskDefinitionArn&&
   state.components.frontend?.imageDigest===frontendActivation?.imageRef?.split('@')[1]&&sourceBound('frontend')));
}

export async function journalComponentCommit({store,operationId,intent,readState,commit,verifyCommitted}={}){
 for(const functionValue of [readState,commit,verifyCommitted])assert.equal(typeof functionValue,'function');
 assert.equal(typeof store?.claimOperation,'function');assert.equal(intent?.operationId,operationId);
 const prior=await store.readOperation(operationId,'COMPONENT:STATE:INTENT');
 if(prior)assert.deepEqual(prior,intent,'Component commit intent changed');
 else await store.writeOperation(operationId,'COMPONENT:STATE:INTENT',intent);
 assert.deepEqual(await store.readOperation(operationId,'COMPONENT:STATE:INTENT'),intent);
 const dispatch=await store.readOperation(operationId,'COMPONENT:STATE:DISPATCH');
 if(dispatch)assert.deepEqual(dispatch,intent,'Component commit dispatch changed');
 const completed=await store.readOperation(operationId,'COMPONENT:STATE:COMPLETED');
 const current=await readState();
 if(await verifyCommitted(current)){
  assert.ok(dispatch,'CONFLICTED: component state changed without this native dispatch');
  const result={intent,generation:current.generation,stateSha256:stateHash(current)};
  if(completed)assert.deepEqual(completed,result,'Component completion receipt changed');
  else await store.writeOperation(operationId,'COMPONENT:STATE:COMPLETED',result);
  assert.deepEqual(await store.readOperation(operationId,'COMPONENT:STATE:COMPLETED'),result);
  return {state:current,reused:true};
 }
 if(dispatch||completed)throw new Error('OUTCOME_UNKNOWN: component state dispatch did not produce the exact release state');
 assert.equal(await store.claimOperation(operationId,'COMPONENT:STATE:DISPATCH',intent),true,
  'Another child owns the component-state transition');
 assert.deepEqual(await store.readOperation(operationId,'COMPONENT:STATE:DISPATCH'),intent);
 await commit();
 const after=await readState();
 assert.ok(await verifyCommitted(after),'OUTCOME_UNKNOWN: component state commit lacks exact native readback');
 const result={intent,generation:after.generation,stateSha256:stateHash(after)};
 await store.writeOperation(operationId,'COMPONENT:STATE:COMPLETED',result);
 assert.deepEqual(await store.readOperation(operationId,'COMPONENT:STATE:COMPLETED'),result);
 return {state:after,reused:false};
}
