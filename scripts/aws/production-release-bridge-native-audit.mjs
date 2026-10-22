import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {brokerDigest} from './stage-b-staged-broker-contract.mjs';
import {canonicalJson,STAGE_B} from './production-green-stage-b-contract.mjs';
import {parseAuthenticatedStateBytes} from './generate-production-green-stage-a-prerequisites.mjs';
import {assertBridgeNativeResult} from './production-release-bridge-native-result.mjs';
import {assertReadyForOverlapDeployment} from './production-overlap-readiness-contract.mjs';
import {inventoryCompletionKey} from '../../infra/aws/terraform/lambda/production-rls-approval-broker/index.mjs';
import {normalizeIamPolicyDocument} from './iam-policy-document.mjs';
import {OVERLAP_OPERATION_TAG} from './production-overlap-task-definition.mjs';
import {assertEcsTaskDefinitionReadback} from '../../infra/aws/terraform/lambda/production-rls-approval-broker/ecs-task-definition-readback.mjs';
import {ECS_EXEC_OPERATOR_BOOTSTRAP_USER_ARN} from './production-ecs-exec-operator-contract.mjs';

const ACCOUNT='368992683803',REGION='eu-west-2';
const STATE_BUCKET='mscqr-production-terraform-state-368992683803-eu-west-2';
const STATE_KEY='env:/production/mscqr/production/rls-green/stage-b/terraform.tfstate';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const json=(run,args)=>JSON.parse(run([...args,'--region',REGION,'--output','json','--no-cli-pager']));
const scalar=item=>Object.fromEntries(Object.entries(item||{}).map(([key,value])=>{
 assert.deepEqual(Object.keys(value||{}),['S'],`Inventory completion ${key} is not an exact string`);
 return [key,value.S];
}));

async function cloudtrailEvents(run,name,start,end){
 const events=[],seen=new Set();let token;
 do{
  const page=json(run,['cloudtrail','lookup-events','--lookup-attributes',`AttributeKey=EventName,AttributeValue=${name}`,
   '--start-time',new Date(start).toISOString(),'--end-time',new Date(end).toISOString(),'--no-paginate',
   ...(token?['--next-token',token]:[])]);
  assert.ok(Array.isArray(page.Events));
  for(const entry of page.Events){
   assert.ok(typeof entry.CloudTrailEvent==='string'&&entry.CloudTrailEvent.length<1024*1024);
   const event=JSON.parse(entry.CloudTrailEvent);
   assert.equal(entry.EventId,event.eventID,'CloudTrail event identity differs');events.push(event);
  }
  assert.ok(events.length<=5000,'Native audit event census is unbounded');
  token=page.NextToken;
  if(token){assert.ok(typeof token==='string'&&!seen.has(token)&&seen.size<100);seen.add(token);}
 }while(token);
 return events;
}

// Both the trusted checker and hosted release role run this read-only census.
// A matching signed digest is useful only when both observe the same native state.
export async function readBridgeNativeAudit({run,store,native,readiness,adoption,now=Date.now()}={}){
 assert.equal(typeof run,'function');assertBridgeNativeResult(native);
 assert.equal(typeof store?.readOperation,'function','Durable native registration journal is required');
 assertReadyForOverlapDeployment(readiness,{sourceSha:native.sourceSha,rotationId:native.rotationId,
  rotationStateSha256:native.rotationStateSha256,now});
 const payload=adoption?.payload;
 assert.equal(payload?.rotationId,native.rotationId);assert.equal(payload.taskArn,native.inventory.taskArn);
 assert.equal(payload.taskDefinitionArn,native.inventory.taskDefinitionArn);
 assert.equal(payload.schemaVersion===5?payload.stateBoundInventorySha256:payload.inventorySha256,native.inventory.receiptSha256);
 assert.match(payload.completionReceiptSha256||'',/^[a-f0-9]{64}$/);
 const receipt=scalar(json(run,['dynamodb','get-item','--table-name',STAGE_B.replayTable,
  '--key',JSON.stringify({approvalMode:{S:inventoryCompletionKey(payload.operationKey)}}),'--consistent-read']).Item);
 assert.equal(brokerDigest(receipt),payload.completionReceiptSha256,'Native inventory completion row differs from signed adoption');
 assert.equal(receipt.sourceSha,payload.sourceSha);assert.equal(receipt.rotationId,native.rotationId);
 assert.equal(receipt.taskArn,native.inventory.taskArn);assert.equal(receipt.taskDefinitionArn,native.inventory.taskDefinitionArn);
 // Historical stopped tasks may age out of ECS DescribeTasks. The broker's
 // consistent, write-once completion row remains the native inventory result.
 const definition=json(run,['ecs','describe-task-definition','--task-definition',native.taskDefinitionArn,'--include','TAGS']);
 assert.equal(definition.taskDefinition?.taskDefinitionArn,native.taskDefinitionArn);
 assert.equal(definition.taskDefinition.status,'ACTIVE');
 assert.equal(definition.taskDefinition.containerDefinitions?.find(item=>item.name==='backend')?.image?.split('@').at(-1),
  readiness.overlapTaskDefinition.identityBindings.imageDigest);
 assert.ok(definition.tags?.some(tag=>tag.key===OVERLAP_OPERATION_TAG&&/^[a-f0-9]{64}$/.test(tag.value)),
  'Native registration operation tag is absent');
 const registrationId=definition.tags.find(tag=>tag.key===OVERLAP_OPERATION_TAG).value;
 const registrationPayload=await store.readOperation(registrationId,'PAYLOAD');
 const registrationIntent=await store.readOperation(registrationId,'INTENT');
 const registrationDone=await store.readOperation(registrationId,'COMPLETED');
 assert.ok(registrationPayload&&registrationIntent&&registrationDone,'Native ECS registration journal is incomplete');
 assert.deepEqual(registrationIntent,{sourceSha:native.sourceSha,rotationId:native.rotationId,
  operationId:registrationId,payloadSha256:sha(canonicalJson(registrationPayload))});
 const preTagPayload={...registrationPayload,tags:registrationPayload.tags.filter(tag=>tag.key!==OVERLAP_OPERATION_TAG)};
 assert.equal(registrationPayload.tags.filter(tag=>tag.key===OVERLAP_OPERATION_TAG).length,1);
 assert.equal(registrationId,sha(canonicalJson({sourceSha:native.sourceSha,rotationId:native.rotationId,payload:preTagPayload})));
 assert.equal(sha(JSON.stringify(registrationPayload)),readiness.overlapTaskDefinition.evidenceSha256,
  'Native ECS payload differs from authenticated overlap readiness');
 assert.deepEqual(registrationDone,{intent:registrationIntent,taskDefinitionArn:native.taskDefinitionArn});
 assertEcsTaskDefinitionReadback({definition:{...definition.taskDefinition,tags:definition.tags},
  taskDefinitionArn:native.taskDefinitionArn,expected:registrationPayload.taskDefinition,
  label:'Native overlap task definition'});
 assert.deepEqual([...definition.tags].sort((a,b)=>a.key.localeCompare(b.key)),
  [...registrationPayload.tags].sort((a,b)=>a.key.localeCompare(b.key)));
 const registeredBy=definition.taskDefinition.registeredBy;
 assert.match(registeredBy||'',/^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[^/]+$/);
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'mscqr-native-audit-'));fs.chmodSync(directory,0o700);
 let state;
 try{
  const file=path.join(directory,'state');
  json(run,['s3api','get-object','--bucket',STATE_BUCKET,'--key',STATE_KEY,'--expected-bucket-owner',ACCOUNT,file]);
  const bytes=fs.readFileSync(file);const parsed=parseAuthenticatedStateBytes(bytes);
  assert.equal(parsed.lineage,'4e438e59-8b8b-194d-030c-5ede0c26344a');
  assert.ok(Number.isSafeInteger(parsed.serial)&&parsed.serial>=76);
  const execution=(parsed.resources||[]).filter(resource=>resource.mode==='managed'&&resource.type==='aws_iam_role_policy'&&
   resource.name==='execution').flatMap(resource=>resource.instances||[]).filter(instance=>instance.index_key==='backend');
  assert.equal(execution.length,1,'Stage B state lacks one exact backend execution policy');
  state={sha256:sha(bytes),serial:parsed.serial,executionPolicy:normalizeIamPolicyDocument(execution[0].attributes?.policy)};
 }finally{fs.rmSync(directory,{recursive:true,force:true});}
 const policy=json(run,['iam','get-role-policy','--role-name','mscqr-production-rls-green-backend-execution',
  '--policy-name','stage-b-exact-image-logs-and-secrets']);
 const document=normalizeIamPolicyDocument(policy.PolicyDocument);
 assert.equal(canonicalJson(state.executionPolicy),canonicalJson(document),'Terraform policy state differs from live IAM');
 const secretRefs=[...new Set(definition.taskDefinition.containerDefinitions.flatMap(container=>
  (container.secrets||[]).filter(secret=>/^(JWT_|QR_|ARTIFACT_SIGN_)/.test(secret.name)).map(secret=>
   secret.valueFrom.replace(/:value::$|:[A-Za-z0-9_-]+::$/,'')).filter(value=>
   [`arn:aws:secretsmanager:${REGION}:${ACCOUNT}:secret:mscqr/prod/rotation/`,
    `arn:aws:secretsmanager:${REGION}:${ACCOUNT}:secret:mscqr/production/rls-green/artifact-signing/`]
    .some(prefix=>value.startsWith(prefix)))))];
 assert.ok(secretRefs.length>=7&&secretRefs.length<=20);
 for(const binding of Object.values(native.artifactSigning.bindings))
  assert.ok(secretRefs.includes(binding.replace(/:value::$|:[A-Za-z0-9_-]+::$/,'')),
   'Reviewed artifact-signing binding is absent from the registered task definition');
 const secretVersions={};
 for(const arn of secretRefs){
  const metadata=json(run,['secretsmanager','describe-secret','--secret-id',arn]);
  assert.equal(metadata.ARN,arn);assert.equal(metadata.DeletedDate,undefined);
  const current=Object.entries(metadata.VersionIdsToStages||{}).filter(([,stages])=>stages.includes('AWSCURRENT'));
  assert.equal(current.length,1,`Native secret version is ambiguous: ${arn}`);
  secretVersions[arn]=current[0][0];
 }
 const readyAt=Date.parse(readiness.generatedAt),assumeStart=readyAt-90*60*1000;
 const assumed=(await cloudtrailEvents(run,'AssumeRole',assumeStart,readyAt+1000)).filter(event=>
  event.eventSource==='sts.amazonaws.com'&&!event.errorCode&&event.userIdentity?.arn===ECS_EXEC_OPERATOR_BOOTSTRAP_USER_ARN&&
  event.userIdentity?.sessionContext?.attributes?.mfaAuthenticated==='true'&&
  event.requestParameters?.roleArn===native.verifier.roleArn&&
  event.responseElements?.assumedRoleUser?.arn===native.verifier.callerArn&&
  Date.parse(event.responseElements?.credentials?.expiration)===Date.parse(native.verifier.expiration));
 assert.equal(assumed.length,1,'Unique native MFA verifier issuance event is required');
 // A registered revision may be reused after an interrupted prepare-overlap.
 const registered=(await cloudtrailEvents(run,'RegisterTaskDefinition',readyAt-89*24*60*60*1000,readyAt+1000)).filter(event=>
  event.eventSource==='ecs.amazonaws.com'&&!event.errorCode&&event.userIdentity?.arn===registeredBy&&
  event.responseElements?.taskDefinition?.taskDefinitionArn===native.taskDefinitionArn&&
  event.requestParameters?.family===definition.taskDefinition.family);
 assert.equal(registered.length,1,'Unique native ECS registration event is required');
 const proof={kind:'PRODUCTION_RELEASE_BRIDGE_NATIVE_AUDIT_V1',schemaVersion:1,sourceSha:native.sourceSha,
  rotationId:native.rotationId,nativeResultSha256:native.nativeResultSha256,inventoryCompletionSha256:payload.completionReceiptSha256,
  inventoryTaskArn:native.inventory.taskArn,verifierAssumeRoleEventId:assumed[0].eventID,
  registrationEventId:registered[0].eventID,taskDefinitionArn:native.taskDefinitionArn,
  terraformStateSha256:state.sha256,terraformStateSerial:state.serial,
  executionPolicySha256:sha(canonicalJson(document)),secretVersions};
 return Object.freeze({...proof,proofSha256:brokerDigest(proof)});
}
