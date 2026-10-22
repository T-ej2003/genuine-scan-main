import assert from 'node:assert/strict';
import {canonicalSha256} from './production-green-stage-b-contract.mjs';

const equal=(actual,expected,label)=>assert.deepEqual(actual,expected,`${label} conflicts with durable history`);
const nativeServiceResult=service=>{
 const primary=service?.deployments?.[0];
 assert.ok(service?.serviceArn&&service.status==='ACTIVE'&&service.desiredCount>0&&
  service.runningCount===service.desiredCount&&service.pendingCount===0&&service.deployments?.length===1&&
  primary?.status==='PRIMARY'&&primary.taskDefinition===service.taskDefinition&&
  primary.rolloutState==='COMPLETED'&&typeof primary.id==='string','ECS native service result is not stable');
 return {serviceArn:service.serviceArn,taskDefinitionArn:service.taskDefinition,deploymentId:primary.id,
  desiredCount:service.desiredCount,enableExecuteCommand:service.enableExecuteCommand===true,
  propagateTags:service.propagateTags||null};
};

export async function journalEcsRegistration({store,operationId,intent,register,list,verify}={}){
 assert.equal(typeof store?.claimOperation,'function');
 for(const fn of [register,list,verify])assert.equal(typeof fn,'function');
 assert.match(operationId||'',/^[a-f0-9]{64}$/);
 assert.equal(intent?.operationId,operationId);
 const phase='FRONTEND:REGISTER';
 const old=await store.readOperation(operationId,`${phase}:INTENT`);
 if(old)equal(old,intent,'Frontend registration intent');
 else await store.writeOperation(operationId,`${phase}:INTENT`,intent);
 equal(await store.readOperation(operationId,`${phase}:INTENT`),intent,'Frontend registration intent readback');
 const dispatch=await store.readOperation(operationId,`${phase}:DISPATCH`);
 if(dispatch)equal(dispatch,intent,'Frontend registration dispatch');
 const complete=await store.readOperation(operationId,`${phase}:COMPLETED`);
 if(complete){assert.ok(dispatch,'CONFLICTED: frontend completion has no native dispatch');equal(complete.intent,intent,'Frontend registration completion');await verify(complete.taskDefinitionArn);return {taskDefinitionArn:complete.taskDefinitionArn,reused:true};}
 const matches=await list(operationId);
 assert.ok(Array.isArray(matches)&&matches.length<=1,'Frontend registration is ambiguous: multiple native revisions');
 if(matches.length===1){
  assert.ok(dispatch,'CONFLICTED: frontend revision exists without this operation dispatch');
  await verify(matches[0]);
  const result={intent,taskDefinitionArn:matches[0]};
  await store.writeOperation(operationId,`${phase}:COMPLETED`,result);
  equal(await store.readOperation(operationId,`${phase}:COMPLETED`),result,'Frontend registration reconciliation');
  return {taskDefinitionArn:matches[0],reused:true};
 }
 if(dispatch)throw new Error('OUTCOME_UNKNOWN: frontend registration dispatched without a uniquely authenticated revision');
 assert.equal(await store.claimOperation(operationId,`${phase}:DISPATCH`,intent),true,'Frontend registration has another owner');
 equal(await store.readOperation(operationId,`${phase}:DISPATCH`),intent,'Frontend registration dispatch readback');
 const response=await register();
 const arn=response?.taskDefinition?.taskDefinitionArn||response?.taskDefinitionArn;
 await verify(arn);
 const result={intent,taskDefinitionArn:arn};
 await store.writeOperation(operationId,`${phase}:COMPLETED`,result);
 equal(await store.readOperation(operationId,`${phase}:COMPLETED`),result,'Frontend registration completion readback');
 return {taskDefinitionArn:arn,reused:false};
}

export async function journalEcsServiceUpdate({store,operationId,phase,intent,read,update,verify,
 isTarget=service=>service?.taskDefinition===intent.targetTaskDefinitionArn,
 isSource=service=>service?.taskDefinition===intent.sourceTaskDefinitionArn,
 allowPriorTarget=false}={}){
 assert.equal(typeof store?.claimOperation,'function');
 for(const fn of [read,update,verify])assert.equal(typeof fn,'function');
 assert.match(operationId||'',/^[a-f0-9]{64}$/);
 assert.match(phase||'',/^(BACKEND|FRONTEND):UPDATE$/);
 assert.equal(intent?.operationId,operationId);
 const previous=await store.readOperation(operationId,`${phase}:INTENT`);
 if(previous)equal(previous,intent,'ECS update intent');
 else await store.writeOperation(operationId,`${phase}:INTENT`,intent);
 equal(await store.readOperation(operationId,`${phase}:INTENT`),intent,'ECS update intent readback');
 const completed=await store.readOperation(operationId,`${phase}:COMPLETED`);
 const dispatch=await store.readOperation(operationId,`${phase}:DISPATCH`);
 if(dispatch)equal(dispatch,intent,'ECS update dispatch');
 if(completed){assert.ok(dispatch,'CONFLICTED: ECS completion has no native dispatch');equal(completed.intent,intent,'ECS update completion');}
 const current=await read();
 if(isTarget(current)&&(dispatch||completed)){
  await verify(current);
  const settled=await read();assert.ok(isTarget(settled),'ECS target changed during native verification');
  const result={intent,taskDefinitionArn:intent.targetTaskDefinitionArn,nativeResult:nativeServiceResult(settled)};
  if(completed)equal(completed,result,'ECS update completion');
  if(!completed)await store.writeOperation(operationId,`${phase}:COMPLETED`,result);
  equal(await store.readOperation(operationId,`${phase}:COMPLETED`),result,'ECS update reconciliation');
  return {taskDefinitionArn:intent.targetTaskDefinitionArn,reused:true};
 }
 if(isTarget(current)&&!allowPriorTarget)throw new Error('CONFLICTED: ECS target is active without this operation dispatch');
 if(completed)throw new Error('CONFLICTED: completed ECS update no longer owns the service');
 if(!isSource(current))throw new Error('CONFLICTED: ECS service is neither the exact source nor target');
 if(dispatch)throw new Error('OUTCOME_UNKNOWN: ECS update dispatched but target is not stably authenticated');
 await verify(current,'source');
 assert.equal(await store.claimOperation(operationId,`${phase}:DISPATCH`,intent),true,'ECS update has another owner');
 equal(await store.readOperation(operationId,`${phase}:DISPATCH`),intent,'ECS update dispatch readback');
 await update();
 const after=await read();
 assert.ok(isTarget(after),'OUTCOME_UNKNOWN: ECS update target is not active');
 await verify(after);
 const settled=await read();assert.ok(isTarget(settled),'ECS target changed during native verification');
 const result={intent,taskDefinitionArn:intent.targetTaskDefinitionArn,nativeResult:nativeServiceResult(settled)};
 await store.writeOperation(operationId,`${phase}:COMPLETED`,result);
 equal(await store.readOperation(operationId,`${phase}:COMPLETED`),result,'ECS update completion readback');
 return {taskDefinitionArn:intent.targetTaskDefinitionArn,reused:false};
}

export const gateEcsOperationId=({sourceSha,rotationId,releaseTrainRunId,authorizationSha256,kind}={})=>{
 assert.match(sourceSha||'',/^[a-f0-9]{40}$/);assert.match(rotationId||'',/^rotation-[a-z0-9-]+$/);
 assert.match(String(releaseTrainRunId||''),/^[1-9][0-9]*$/);
 assert.match(authorizationSha256||'',/^[a-f0-9]{64}$/);
 assert.ok(['BACKEND','FRONTEND'].includes(kind));
 return canonicalSha256({kind:`PRODUCTION_RELEASE_GATE_${kind}_ECS_V1`,sourceSha,rotationId,
  releaseTrainRunId:String(releaseTrainRunId),authorizationSha256});
};
