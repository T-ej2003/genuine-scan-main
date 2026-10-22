import test from 'node:test';
import assert from 'node:assert/strict';
import {createProductionComponentDeploymentState} from '../aws/production-component-deployment-state.mjs';
import {componentCommitOperationId,journalComponentCommit,matchesCommittedReleaseState} from '../aws/production-release-gate-component-journal.mjs';

const sourceSha='a'.repeat(40),authorizationSha256='b'.repeat(64);
const operationId=componentCommitOperationId({sourceSha,rotationId:'rotation-test',releaseTrainRunId:'42',authorizationSha256});
const base={backend:null,frontend:null,database:null,security:null};
const before=createProductionComponentDeploymentState({components:base,now:'2026-10-22T00:00:00.000Z'});
const after=createProductionComponentDeploymentState({components:{...base,security:{sourceSha,releaseIdentity:authorizationSha256}},
 now:'2026-10-22T00:00:01.000Z'});
const memoryStore=()=>{
 const records=new Map();return {records,readOperation:async(_,phase)=>records.get(phase)||null,
  writeOperation:async(_,phase,value)=>{if(records.has(phase))assert.deepEqual(records.get(phase),value);
   else records.set(phase,value);return true;},
  claimOperation:async(_,phase,value)=>{if(records.has(phase))throw Error('claim conflict');records.set(phase,value);return true;}};
};

test('component state response loss reconciles exact native state without a second commit',async()=>{
 const store=memoryStore(),intent={operationId,sourceSha,authorizationSha256};
 let live=before,writes=0;
 const options={store,operationId,intent,readState:async()=>live,
  verifyCommitted:state=>state.components.security?.releaseIdentity===authorizationSha256,
  commit:async()=>{writes++;live=after;throw Error('DynamoDB response lost');}};
 await assert.rejects(journalComponentCommit(options),/response lost/);
 assert.equal((await journalComponentCommit(options)).reused,true);assert.equal(writes,1);
 assert.equal((await journalComponentCommit(options)).reused,true);assert.equal(writes,1);
 live=before;await assert.rejects(journalComponentCommit(options),/OUTCOME_UNKNOWN/);
});

test('forged component completion, changed intent and concurrent owner fail closed',async()=>{
 const store=memoryStore(),intent={operationId,sourceSha,authorizationSha256};
 const options={store,operationId,intent,readState:async()=>after,verifyCommitted:()=>true,commit:async()=>assert.fail()};
 await store.writeOperation(operationId,'COMPONENT:STATE:COMPLETED',{intent,generation:after.generation});
 await assert.rejects(journalComponentCommit(options),/without this native dispatch/);
 const fresh=memoryStore();
 await fresh.claimOperation(operationId,'COMPONENT:STATE:DISPATCH',intent);
 await assert.rejects(journalComponentCommit({...options,store:fresh,intent:{...intent,sourceSha:'0'.repeat(40)}}),/dispatch changed/);
});

test('native component readback binds database, backend and frontend to the child run',()=>{
 const digest='sha256:'+ '1'.repeat(64),webDigest='sha256:'+ '2'.repeat(64);
 const backendArn='arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:7';
 const frontendArn='arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-frontend:8';
 const state=createProductionComponentDeploymentState({components:{
  backend:{sourceSha,establishedThroughSha:sourceSha,imageDigest:digest,taskDefinitionArn:backendArn,desiredCount:2},
  frontend:{sourceSha,establishedThroughSha:sourceSha,imageDigest:webDigest,taskDefinitionArn:frontendArn,desiredCount:2},
  database:{sourceSha,releaseIdentity:'r'.repeat(64)},security:{sourceSha,releaseIdentity:authorizationSha256}},
  now:'2026-10-22T00:00:00.000Z',githubRunId:'91'});
 const input={state,sourceSha,authorizationSha256,rlsReceipt:{receiptBundleSha256:'r'.repeat(64)},
  backendActivation:{targetArn:backendArn,imageDigest:digest},
  frontendActivation:{candidateTaskDefinitionArn:frontendArn,imageRef:`example@${webDigest}`},
  childRunId:'91',webRequired:true};
 assert.equal(matchesCommittedReleaseState(input),true);
 assert.equal(matchesCommittedReleaseState({...input,childRunId:'92'}),false);
 assert.equal(matchesCommittedReleaseState({...input,backendActivation:{...input.backendActivation,imageDigest:webDigest}}),false);
 assert.equal(matchesCommittedReleaseState({...input,frontendActivation:{...input.frontendActivation,candidateTaskDefinitionArn:backendArn}}),false);
});
