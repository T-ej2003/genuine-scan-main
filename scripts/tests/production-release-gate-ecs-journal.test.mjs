import test from 'node:test';
import assert from 'node:assert/strict';
import {journalEcsRegistration,journalEcsServiceUpdate,gateEcsOperationId} from '../aws/production-release-gate-ecs-journal.mjs';

const sha='a'.repeat(40),rotationId='rotation-20260913011819-98b062c4',auth='b'.repeat(64);
const operationId=gateEcsOperationId({sourceSha:sha,rotationId,releaseTrainRunId:'42',authorizationSha256:auth,kind:'FRONTEND'});
const store=()=>{
 const records=new Map();
 const key=(id,phase)=>`${id}:${phase}`;
 return {records,readOperation:async(id,phase)=>records.get(key(id,phase))||null,
  writeOperation:async(id,phase,value)=>{const name=key(id,phase);if(records.has(name)){assert.deepEqual(records.get(name),value);return false;}records.set(name,value);return true;},
  claimOperation:async(id,phase,value)=>{const name=key(id,phase);if(records.has(name))throw Error('claim conflict');records.set(name,value);return true;}};
};

test('lost frontend registration response adopts one exact native revision without registration replay',async()=>{
 const journal=store(),intent={operationId,sourceSha:sha,rotationId,inputSha256:auth};
 const arn='arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-frontend:37';
 let native=null,registerCount=0;
 const options={store:journal,operationId,intent,list:async()=>native?[native]:[],verify:async value=>assert.equal(value,arn),
  register:async()=>{registerCount++;native=arn;throw Error('response lost');}};
 await assert.rejects(journalEcsRegistration(options),/response lost/);
 const result=await journalEcsRegistration(options);
 assert.deepEqual(result,{taskDefinitionArn:arn,reused:true});assert.equal(registerCount,1);
 const ambiguous=store();await ambiguous.claimOperation(operationId,'FRONTEND:REGISTER:DISPATCH',intent);
 await assert.rejects(journalEcsRegistration({...options,store:ambiguous,list:async()=>[arn,arn]}),/multiple native revisions/);
});

test('frontend registration refuses forged revision and ambiguous dispatch',async()=>{
 const journal=store(),intent={operationId,sourceSha:sha,rotationId,inputSha256:auth};
 await assert.rejects(journalEcsRegistration({store:journal,operationId,intent,list:async()=>['forged'],verify:async()=>{},register:async()=>{}}),/without this operation dispatch/);
 const claimed=store();await claimed.claimOperation(operationId,'FRONTEND:REGISTER:DISPATCH',intent);
 await assert.rejects(journalEcsRegistration({store:claimed,operationId,intent,list:async()=>[],verify:async()=>{},register:async()=>{}}),/OUTCOME_UNKNOWN/);
 const forged=store();await forged.writeOperation(operationId,'FRONTEND:REGISTER:COMPLETED',
  {intent,taskDefinitionArn:'forged'});
 await assert.rejects(journalEcsRegistration({store:forged,operationId,intent,list:async()=>[],verify:async()=>{},register:async()=>{}}),/no native dispatch/);
});

test('lost ECS UpdateService response reconciles a stable exact target and never updates twice',async()=>{
 const journal=store(),intent={operationId,sourceTaskDefinitionArn:'source:1',targetTaskDefinitionArn:'target:2',inputSha256:auth};
 let active='source:1',calls=0;
 const service=()=>({serviceArn:'service:1',status:'ACTIVE',taskDefinition:active,desiredCount:2,runningCount:2,pendingCount:0,
  deployments:[{id:active==='source:1'?'ecs-svc/1':'ecs-svc/2',status:'PRIMARY',taskDefinition:active,rolloutState:'COMPLETED'}]});
 const options={store:journal,operationId,phase:'FRONTEND:UPDATE',intent,read:async()=>service(),
  verify:async(value,stage)=>assert.equal(value.taskDefinition,stage==='source'?'source:1':'target:2'),
  update:async()=>{calls++;active='target:2';throw Error('response lost');}};
 await assert.rejects(journalEcsServiceUpdate(options),/response lost/);
 assert.deepEqual(await journalEcsServiceUpdate(options),{taskDefinitionArn:'target:2',reused:true});assert.equal(calls,1);
 assert.equal((await journal.readOperation(operationId,'FRONTEND:UPDATE:COMPLETED')).nativeResult.deploymentId,'ecs-svc/2');
 const changed=await journalEcsServiceUpdate({...options,read:async()=>({
  ...service(),deployments:[{...service().deployments[0],id:'ecs-svc/3'}]})}).then(()=>null,error=>error);
 assert.match(changed.message,/completion conflicts with durable history/);
 active='source:1';await assert.rejects(journalEcsServiceUpdate(options),/CONFLICTED/);
});

test('ECS target without dispatch, changed input, and source after dispatch fail closed',async()=>{
 const journal=store(),intent={operationId,sourceTaskDefinitionArn:'source:1',targetTaskDefinitionArn:'target:2',inputSha256:auth};
 const options={store:journal,operationId,phase:'BACKEND:UPDATE',intent,read:async()=>({taskDefinition:'target:2'}),verify:async()=>{},update:async()=>{}};
 await assert.rejects(journalEcsServiceUpdate(options),/without this operation dispatch/);
 const forged=store();await forged.writeOperation(operationId,'BACKEND:UPDATE:COMPLETED',
  {intent,taskDefinitionArn:'target:2'});
 await assert.rejects(journalEcsServiceUpdate({...options,store:forged}),/no native dispatch/);
 await journal.claimOperation(operationId,'BACKEND:UPDATE:DISPATCH',intent);
 await assert.rejects(journalEcsServiceUpdate({...options,read:async()=>({taskDefinition:'source:1'})}),/OUTCOME_UNKNOWN/);
 await assert.rejects(journalEcsServiceUpdate({...options,intent:{...intent,inputSha256:'c'.repeat(64)}}),/conflicts/);
});
