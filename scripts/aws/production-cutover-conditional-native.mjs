import fs from 'node:fs';
import {execFileSync} from 'node:child_process';
import {buildOverlapTaskDefinition,OVERLAP_OPERATION_TAG} from './production-overlap-task-definition.mjs';
import {canonicalJson} from './production-green-stage-b-contract.mjs';
import {conditionalHash,parseConditionalJson,exactConditionalKeys} from './production-cutover-conditional-authorization.mjs';
import {assertRootDropEvidence,buildRootDropEvidence} from './production-root-drop-evidence.mjs';
import assert from 'node:assert/strict';
const reads={
  sts:['get-caller-identity'],kms:['get-public-key','get-key-policy','describe-key','list-resource-tags','verify'],
  secretsmanager:['describe-secret','get-secret-value','list-secret-version-ids'],
  iam:['get-role','get-user','get-policy','get-policy-version','get-role-policy','list-role-policies','list-attached-role-policies','list-policy-versions','list-mfa-devices','simulate-principal-policy'],
  s3api:['get-object','head-object','get-bucket-policy','get-bucket-encryption','get-bucket-versioning','get-public-access-block'],
  ec2:['describe-security-group-rules','describe-security-groups','describe-vpc-endpoints','describe-subnets','describe-network-interfaces'],
  ecs:['describe-services','describe-task-definition','describe-tasks','list-task-definitions','list-tasks'],
  ecr:['describe-images','batch-get-image','get-download-url-for-layer','describe-repositories'],
  dynamodb:['get-item','describe-table'],lambda:['get-function','get-function-configuration','get-alias','get-policy'],
  cloudtrail:['lookup-events'],logs:['get-log-events','describe-log-streams'],rds:['describe-db-instances'],organizations:['describe-organization','describe-account'],
};
export function conditionalReadCommand(args,{coordinator}={}) {
  assert.ok(Array.isArray(args)&&args.every(value=>typeof value==='string'));
  if(args[0]==='node') {
    assert.equal(args[1],coordinator);assert.equal(args.length,9,'Exact coordinator status interface required');
    assert.deepEqual([args[2],args[3],args[5],args[7]],['--status','--config','--config-sha256','--state-file'],'Conditional coordinator mutation forbidden');
    assert.match(args[6],/^[a-f0-9]{64}$/);return;
  }
  if(args[0]==='terraform') {
    assert.ok(args.some(value=>['show','version','plan','init'].includes(value))&&!args.some(value=>['apply','destroy','import','state','force-unlock'].includes(value)),'Conditional Terraform mutation forbidden');return;
  }
  if(args[0]==='s3') {assert.equal(args[1],'cp');assert.ok(args[2]?.startsWith('s3://'));assert.ok(args[3]&&!args[3].startsWith('s3://'));return;}
  assert.ok(reads[args[0]]?.includes(args[1]),'Conditional native command outside read-only envelope');
}
export const conditionalReadRunner=(run,config)=>args=>{conditionalReadCommand(args,{coordinator:config.rotationCoordinator||'backend/scripts/security/rotate-production-signing-material.mjs'});return run(args);};

// Validate the canonical producer's unsigned effect before dispatch, independently of its output checks.
export function assertConditionalUnsignedEffect({d,phase,request,materialization,outputs,now}) {
  const bytes=Buffer.from(request.messageBase64,'base64'),p=parseConditionalJson(bytes);
  assert.equal(bytes.toString('utf8'),canonicalJson(p),'Native effect must use canonical payload bytes');
  if(phase==='ROOT_DROP') {
    const structural=buildRootDropEvidence({payload:p,signatureBase64:'AA=='});
    assertRootDropEvidence(structural,{sourceSha:d.historicalReleaseSha,rotationId:d.rotationId,imageAuthorizationSha256:d.artifacts.imageAuthorizationSha256,
      successorRecoveryAuthorizationSha256:null,administratorEvidenceSha256:d.artifacts.administratorFileSha256,
      administratorSignatureSha256:d.artifacts.administratorSignatureFileSha256,now,verifySignature:()=>true});
    assert.ok(Date.parse(p.generatedAt)<=now && now-Date.parse(p.generatedAt)<60000,'Fresh root timestamp required before Sign');
    return;
  }
  assert.ok(materialization,'Native effect requires a materialized runtime');
  if(phase==='INVENTORY_ADOPTION') {
    assert.equal(p.purpose,'adopt-completed-predeployment-inventory');
    assert.equal(p.rotationId,d.rotationId); assert.equal(p.continuationSourceSha,d.historicalReleaseSha);
    assert.equal(p.continuationConfigSha256,materialization.manifest.runtimeFileSha256);
    assert.equal(p.originalConfigSha256,d.predecessor.configSha256);
    assert.equal(p.completionReceiptSha256,d.inventory.completionReceiptSha256);
    assert.equal(p.taskArn,d.inventory.taskArn);
    assert.equal(p.operationKey,d.inventory.operationKey);
    assert.equal(p.operationIdentitySha256,d.inventory.operationIdentitySha256);
    assert.equal(p.schemaVersion===5?p.stateBoundInventorySha256:p.inventorySha256,d.inventory.stateBoundInventorySha256);
    return;
  }
  exactConditionalKeys(p,['kind','schemaVersion','predecessorSourceSha','successorSourceSha','rotationId','ticket','configSha256','predecessorConfigSha256','predecessorStateSha256','predecessorFixtureSha256','predecessorStatusSha256','inventoryAdoptionSha256','successorStateSha256'],'Successor payload');
  assert.equal(phase,'ROTATION_SUCCESSOR'); assert.equal(p.kind,'PRODUCTION_ROTATION_SOURCE_SUCCESSOR'); assert.equal(p.schemaVersion,1);
  assert.equal(p.predecessorSourceSha,materialization.config.completedInventoryPredecessorSourceSha);
  assert.equal(p.successorSourceSha,d.historicalReleaseSha); assert.equal(p.rotationId,d.rotationId); assert.equal(p.ticket,d.ticketId);
  assert.equal(p.configSha256,materialization.manifest.runtimeFileSha256);
  for(const [field,key] of [['predecessorConfigSha256','configSha256'],['predecessorStateSha256','stateSha256'],['predecessorFixtureSha256','fixtureSha256'],['predecessorStatusSha256','statusSha256']]) assert.equal(p[field],d.predecessor[key]);
  assert.equal(p.inventoryAdoptionSha256,conditionalHash(outputs.INVENTORY_ADOPTION));
}

export function conditionalRegistrationRequest(d,executionId) {
  const payload=buildOverlapTaskDefinition(d.postPrepareTaskInput);
  const operationId=conditionalHash({sourceSha:d.historicalReleaseSha,rotationId:d.rotationId,payload});
  return {...payload.taskDefinition,tags:[...payload.tags,{key:OVERLAP_OPERATION_TAG,value:operationId},{key:'MSCQRConditionalExecution',value:executionId}]};
}

export function assertConditionalPrepareEffect({d,executionId,action,request,successor}) {
  if(action==='REGISTER_TASK_DEFINITION') assert.deepEqual(request,conditionalRegistrationRequest(d,executionId),'Registration differs from exact approved derivation');
  else {
    assert.equal(action,'ROTATION_LOCAL_STATE','Unexpected prepare-overlap mutation');
    assert.deepEqual(request,{stateFile:d.runtimeTemplate.rotationStateFile,fixtureFile:d.runtimeTemplate.rotationFixtureFile,
      stateFileSha256:conditionalHash(Buffer.from(`${JSON.stringify(successor.state,null,2)}\n`)),fixtureFileSha256:d.predecessor.fixtureSha256},'Rotation local persistence differs from signed successor');
  }
}


export function conditionalToolPaths(execute=execFileSync) {
  return Object.fromEntries(['aws','terraform','git','node'].map(name=>[name,fs.realpathSync(name==='node'?process.execPath:String(execute('/usr/bin/which',[name],{encoding:'utf8'})).trim())]));
}
export function createConditionalExecutor(d,execute=execFileSync) {
  const tools=conditionalToolPaths(execute);
  for(const file of Object.values(tools))assert.ok(d.files.some(entry=>entry.path===file&&entry.fileSha256===conditionalHash(fs.readFileSync(file))),'Native tool is outside sealed census');
  return (name,args,options)=>{
    const executable=tools[name]||Object.values(tools).find(value=>value===name)||(name===process.execPath?tools.node:undefined);assert.ok(executable,'Unsupported conditional native executable');
    const entry=d.files.find(value=>value.path===executable);
    assert.equal(fs.realpathSync(executable),executable);assert.equal(conditionalHash(fs.readFileSync(executable)),entry.fileSha256,'Native executable changed');
    return execute(executable,args,{timeout:30000,...options});
  };
}
