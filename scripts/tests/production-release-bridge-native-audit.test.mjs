import test from 'node:test';
import assert from 'node:assert/strict';
import {writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {brokerDigest} from '../aws/stage-b-staged-broker-contract.mjs';
import {STAGE_B} from '../aws/production-green-stage-b-contract.mjs';
import {buildOverlapReadinessEvidence} from '../aws/produce-production-overlap-readiness-evidence.mjs';
import {READY_FOR_OVERLAP_DEPLOYMENT_STAGES} from '../aws/production-overlap-readiness-contract.mjs';
import {readBridgeNativeAudit} from '../aws/production-release-bridge-native-audit.mjs';
import {OVERLAP_OPERATION_TAG} from '../aws/production-overlap-task-definition.mjs';
import {ECS_EXEC_OPERATOR_BOOTSTRAP_USER_ARN} from '../aws/production-ecs-exec-operator-contract.mjs';

const sourceSha='a'.repeat(40),rotationId='rotation-20260913011819-98b062c4',digest='b'.repeat(64);
const taskDefinitionArn='arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:1';
const imageDigest=`sha256:${digest}`,taskArn='arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/abc';
const verifierArn='arn:aws:sts::368992683803:assumed-role/mscqr-production-ecs-exec-verifier/session';
const releaseArn='arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/session';
const verifierRole='arn:aws:iam::368992683803:role/mscqr-production-ecs-exec-verifier';
const secretRoot='arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/artifact-signing/';
const bindings=Object.fromEntries(['ARTIFACT_SIGN_PRIVATE_KEY_CURRENT','ARTIFACT_SIGN_PUBLIC_KEY_CURRENT',
 'ARTIFACT_SIGN_ACTIVE_KEY_VERSION','ARTIFACT_SIGN_PUBLIC_KEYS_JSON'].map(key=>[key,`${secretRoot}${key}`]));
const statePolicy={Version:'2012-10-17',Statement:[]};
const state={lineage:'4e438e59-8b8b-194d-030c-5ede0c26344a',serial:98,
 resources:[{mode:'managed',type:'aws_iam_role_policy',name:'execution',instances:[{index_key:'backend',attributes:{policy:JSON.stringify(statePolicy)}}]}]};
const receipt={sourceSha,rotationId,taskArn,taskDefinitionArn};
const adoption={payload:{rotationId,taskArn,taskDefinitionArn,sourceSha,operationKey:'production-predeployment-rotation-inventory#test',
 schemaVersion:2,inventorySha256:digest,completionReceiptSha256:brokerDigest(receipt)}};
const secretRefs=[...Object.values(bindings),...Array.from({length:3},(_,i)=>
 `arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/prod/rotation/secret${i}`)];
const taskDefinition={family:'mscqr-production-rls-green-backend-candidate',containerDefinitions:[{name:'backend',
 image:`repo@${imageDigest}`,secrets:secretRefs.map((valueFrom,i)=>({name:`${i<4?'ARTIFACT_SIGN_':'QR_'}${i}`,valueFrom}))}]};
const registrationPayload={taskDefinition,tags:[{key:OVERLAP_OPERATION_TAG,value:''}]};
const registrationId=(()=>{
 const payload={taskDefinition,tags:[]};
 const id=brokerDigest({sourceSha,rotationId,payload});
 registrationPayload.tags[0].value=id;
 return id;
})();
const registrationIntent={sourceSha,rotationId,operationId:registrationId,payloadSha256:brokerDigest(registrationPayload)};
const registrationEvidenceSha256=createHash('sha256').update(JSON.stringify(registrationPayload)).digest('hex');
const readiness=buildOverlapReadinessEvidence({sourceSha,rotationId,rotationStateSha256:digest,
 stages:Object.fromEntries(READY_FOR_OVERLAP_DEPLOYMENT_STAGES.map(name=>[name,{valid:true,evidenceRef:name,
  evidenceSha256:name==='overlapTaskDefinition'?registrationEvidenceSha256:digest,
  identityBindings:{sourceSha,...(name==='imageAuthorization'||name==='overlapTaskDefinition'?{imageReleaseSha:sourceSha}:{}),
   ...(name==='overlapTaskDefinition'?{taskDefinitionArn,imageDigest}:{})}}]))});
const nativeBody={kind:'PRODUCTION_RELEASE_BRIDGE_NATIVE_RESULT_V1',schemaVersion:1,sourceSha,rotationId,
 runtimeConfigSha256:digest,rotationStateSha256:digest,rotationFixtureSha256:digest,readinessSha256:digest,
 taskDefinitionArn,verifier:{callerArn:verifierArn,roleArn:verifierRole,expiration:'2026-10-22T12:00:00Z',evidenceSha256:digest},
 artifactSigning:{activeKeyVersion:'v1',publicRegistryCount:1,bindings},
 inventory:{taskArn,taskDefinitionArn,receiptSha256:digest,resultSha256:digest},
 rotation:{resultSha256:digest},infrastructure:{resultSha256:digest,applyCount:0},
 registration:{resultSha256:digest,mutationCount:1},readinessResultSha256:digest};
const native={...nativeBody,nativeResultSha256:brokerDigest(nativeBody)};

function runner({tamper}={}){
 const definition={...taskDefinition,taskDefinitionArn,status:'ACTIVE',registeredBy:releaseArn};
 const readyAt=Date.parse(readiness.generatedAt);
 const events={AssumeRole:{eventID:'assume-1',eventSource:'sts.amazonaws.com',userIdentity:{arn:ECS_EXEC_OPERATOR_BOOTSTRAP_USER_ARN,
  sessionContext:{attributes:{mfaAuthenticated:'true'}}},requestParameters:{roleArn:verifierRole},
  responseElements:{assumedRoleUser:{arn:verifierArn},credentials:{expiration:native.verifier.expiration}}},
  RegisterTaskDefinition:{eventID:'register-1',eventSource:'ecs.amazonaws.com',userIdentity:{arn:releaseArn},
   responseElements:{taskDefinition:{taskDefinitionArn}},requestParameters:{family:definition.family}}};
 assert.ok(Number.isFinite(readyAt));
 return args=>{
  const action=`${args[0]}:${args[1]}`;let value;
  if(action==='dynamodb:get-item')value={Item:Object.fromEntries(Object.entries(receipt).map(([key,entry])=>[key,{S:entry}]))};
  else if(action==='ecs:describe-task-definition')value={taskDefinition:definition,tags:registrationPayload.tags};
  else if(action==='s3api:get-object'){
   const file=args[args.indexOf('--expected-bucket-owner')+2];writeFileSync(file,JSON.stringify(state));value={};
  }else if(action==='iam:get-role-policy')value={PolicyDocument:statePolicy};
  else if(action==='secretsmanager:describe-secret'){
   const arn=args[args.indexOf('--secret-id')+1];value={ARN:arn,VersionIdsToStages:{version1:['AWSCURRENT']}};
  }else if(action==='cloudtrail:lookup-events'){
   const name=args[args.indexOf('--lookup-attributes')+1].split('AttributeValue=')[1];
   const event=events[name];value={Events:event?[{EventId:event.eventID,CloudTrailEvent:JSON.stringify(event)}]:[]};
  }else throw new Error(`Unexpected AWS audit command ${action}`);
  return JSON.stringify(tamper?.(action,value)||value);
 };
}

test('checker and hosted native census agree only on authoritative source-bound AWS readbacks',async()=>{
 const journal={readOperation:async(id,phase)=>{
  assert.equal(id,registrationId);
  return {PAYLOAD:registrationPayload,INTENT:registrationIntent,COMPLETED:{intent:registrationIntent,taskDefinitionArn}}[phase]||null;
 }};
 const proof=await readBridgeNativeAudit({run:runner(),store:journal,native,readiness,adoption});
 assert.equal(proof.sourceSha,sourceSha);assert.equal(proof.rotationId,rotationId);
 assert.equal(proof.nativeResultSha256,native.nativeResultSha256);
 assert.equal(proof.proofSha256,brokerDigest(Object.fromEntries(Object.entries(proof).filter(([key])=>key!=='proofSha256'))));
 await assert.rejects(readBridgeNativeAudit({run:runner({tamper:(action,value)=>action==='ecs:describe-task-definition'
  ?{...value,taskDefinition:{...value.taskDefinition,taskDefinitionArn:taskDefinitionArn.replace(':1',':2')}}:value}),store:journal,native,readiness,adoption}));
 await assert.rejects(readBridgeNativeAudit({run:runner({tamper:(action,value)=>action==='secretsmanager:describe-secret'
  ?{...value,VersionIdsToStages:{}}:value}),store:journal,native,readiness,adoption}));
 await assert.rejects(readBridgeNativeAudit({run:runner({tamper:(action,value)=>action==='cloudtrail:lookup-events'
  ?{Events:[]}:value}),store:journal,native,readiness,adoption}));
});
