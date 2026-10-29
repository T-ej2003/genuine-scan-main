import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { assertWebRegistryReadPlan, reconcileWebRegistryReadIam, WEB_REGISTRY_READ_TRANSITION as t,
  assertPhase3IamAuthorization, phase3IamAuthorizationMarker, claimPhase3IamOwner } from '../aws/bootstrap-production-web-release-iam.mjs';
const target = JSON.parse(fs.readFileSync('infra/aws/terraform/production-web-release/web-evidence-registry-read-policy.json'));
const predecessor = structuredClone(target);
predecessor.Statement[1].Action = ['ecr:BatchGetImage', 'ecr:GetDownloadUrlForLayer'];
const sourceSha = 'b'.repeat(40), authorizationId = 42;
// Attestation metadata only; no OTP or AWS credentials are present in this fixture.
const operatorAttestation = () => ({sourceSha, ticketId:t.ticketId, authorizationId,
  operatorArn:'arn:aws:iam::368992683803:user/mscqr-production-bootstrap-operator',
  mfaSerial:'arn:aws:iam::368992683803:mfa/mscqr-production-bootstrap-operator', accessKeyIdSha256:'f'.repeat(64),
  verifiedAt:new Date().toISOString(), expiresAt:new Date(Date.now()+900000).toISOString()});
const inline = policy => ({name:t.registryPolicyName,role:t.roleName,policy:JSON.stringify(policy)});
function plan(before=predecessor) {
  const noops=['aws_iam_policy.publisher_boundary','aws_iam_role.publisher','aws_iam_role_policy.publisher',
    'aws_iam_role_policy.frontend_activation','aws_iam_role_policy.stage_b_native_audit'];
  const change=(address,actions,before,after)=>({address,mode:'managed',provider_name:'registry.terraform.io/hashicorp/aws',change:{actions,before,after,after_unknown:{}}});
  return {variables:{phase3_iam_source_sha:{value:sourceSha}},resource_changes:[
    ...noops.map(address=>change(address,['no-op'],{},{})),
    change('aws_iam_role_policy.web_evidence_registry_read',[before===target?'no-op':'update'],inline(before),inline(target))]};
}
function fixture({live=predecessor,loseResponse=false,mark=true,dispatched=false}={}) {
  let document=live, dispatch=dispatched; const calls=[];
  const run=args=>{calls.push(args);const flag=name=>args[args.indexOf(name)+1];
    if(args[0]==='sts')return JSON.stringify({Account:t.account,Arn:`arn:aws:iam::${t.account}:root`});
    assert.equal(flag('--role-name'),t.roleName);assert.equal(flag('--policy-name'),t.registryPolicyName);
    if(args[1]==='get-role-policy')return JSON.stringify({PolicyDocument:document});
    assert.equal(args[1],'put-role-policy');document=JSON.parse(flag('--policy-document'));
    if(loseResponse)throw Error('Lost response'); return '{}';
  };
  const owner={ownershipSha256:'a'.repeat(64),hasDispatch:()=>dispatch,
    markDispatch:()=>{if(mark)dispatch=true;return mark;},complete:()=> 'c'.repeat(64)};
  return {calls,run,owner};
}
const execute=(f,extra={})=>reconcileWebRegistryReadIam({run:f.run,sourceSha,ticketId:t.ticketId,plan:plan(),authorizationId,
  mfaEvidence:operatorAttestation(),assertProtectedSource:()=>sourceSha,assertCurrentAuthorization:()=>authorizationId,claimOwnership:()=>f.owner,...extra});
const writes=f=>f.calls.filter(args=>args[1]==='put-role-policy');
test('registry exact predecessor installs only its reviewed read delta and verifies it',()=>{
  const f=fixture();assert.equal(execute(f).status,'WEB_REGISTRY_READ_RECONCILED');assert.equal(writes(f).length,1);
});
test('registry plan rejects source substitution, other changes, unknowns, replacement and policy substitution',()=>{
  for(const mutate of [p=>p.variables.phase3_iam_source_sha.value='c'.repeat(40),
    p=>p.resource_changes[0].change.actions=['update'],p=>p.resource_changes.push(p.resource_changes[0]),
    p=>p.resource_changes.at(-1).change.after_unknown={policy:true},
    p=>p.resource_changes.at(-1).change.actions=['delete','create'],
    p=>p.resource_changes.at(-1).change.after.role='other-role',
    p=>p.resource_changes.at(-1).change.after.policy=JSON.stringify({Statement:[{Effect:'Allow',Action:'*',Resource:'*'}]})]) {
    const value=plan();mutate(value);assert.throws(()=>assertWebRegistryReadPlan(value,sourceSha));
  }
});
test('expired MFA, changed approval, source drift, unexpected policy and consumed dispatch prevent writes',()=>{
  for(const extra of [{mfaEvidence:{...operatorAttestation(),expiresAt:new Date(0).toISOString()}},
    {assertCurrentAuthorization:()=>99},{assertProtectedSource:()=> 'c'.repeat(40)}]) {
    const f=fixture();assert.throws(()=>execute(f,extra));assert.equal(writes(f).length,0);
  }
  const drift=fixture({live:{Statement:[]}});assert.throws(()=>execute(drift));assert.equal(writes(drift).length,0);
  const used=fixture({mark:false});assert.throws(()=>execute(used),/outcome unknown/);assert.equal(writes(used).length,0);
});
test('lost write response reconciles live target; repeat is read-only and requires dispatch history',()=>{
  const f=fixture({loseResponse:true});assert.equal(execute(f).status,'WEB_REGISTRY_READ_RECONCILED');
  const resumed=fixture({live:target,dispatched:true});execute(resumed,{plan:plan(target)});assert.equal(writes(resumed).length,0);
  const unowned=fixture({live:target});assert.throws(()=>execute(unowned,{plan:plan(target)}),/authenticated dispatch/);
  const stale=fixture({live:target});assert.throws(()=>execute(stale),/saved plan is stale/);
});
test('registry authorization is post-merge, unedited, unexpired and isolated from Phase 3 approvals',()=>{
  const now=Date.now(), merged_at=new Date(now-60000).toISOString(), head='a'.repeat(40);
  const reviewedPull={number:t.reviewedPrNumber,merged:true,head:{sha:t.reviewedHeadSha},merge_commit_sha:t.reviewedMergeSha,
    base:{sha:t.baselineSha,ref:'main',repo:{full_name:'T-ej2003/genuine-scan-main'}},user:{id:183396573},merged_at:new Date(now-120000).toISOString()};
  const pull={number:776,merged:true,head:{sha:head},merge_commit_sha:sourceSha,base:{sha:t.reviewedMergeSha,ref:'main',repo:{full_name:'T-ej2003/genuine-scan-main'}},user:{id:183396573},merged_at};
  const comment={id:42,user:{id:183396573,type:'User'},body:phase3IamAuthorizationMarker(head,sourceSha,t),created_at:new Date(now-1000).toISOString(),updated_at:new Date(now-1000).toISOString()};
  const input={pull,reviewedPull,comments:[comment],operator:{id:183396573},prNumber:776,sourceSha,now,transition:t};
  assert.equal(assertPhase3IamAuthorization(input),42);
  for(const comments of [[],[{...comment,body:phase3IamAuthorizationMarker(head,sourceSha)}],
    [{...comment,user:{id:1,type:'User'}}],[{...comment,updated_at:new Date(now).toISOString()}],
    [{...comment,created_at:new Date(now-7200001).toISOString(),updated_at:new Date(now-7200001).toISOString()}]]) {
    assert.throws(()=>assertPhase3IamAuthorization({...input,comments}));
  }
});
test('registry ownership uses durable existing journal, restricts policy names and rejects another owner',()=>{
  const d=fs.mkdtempSync(path.join(os.tmpdir(),'mscqr-registry-owner-test-'));fs.chmodSync(d,0o700);
  const objects=new Map();const run=args=>{const flag=k=>args[args.indexOf(k)+1],key=flag('--key');
    if(args[1]==='put-object'){assert.equal(flag('--if-none-match'),'*');if(objects.has(key))throw Error('PreconditionFailed');objects.set(key,fs.readFileSync(flag('--body')));return '{}';}
    if(!objects.has(key))throw Error('NoSuchKey');fs.writeFileSync(args.at(-1),objects.get(key));return '{}';};
  const input={run,sourceSha,authorizationId,mfaEvidence:operatorAttestation(),transition:t,ownerFile:path.join(d,'owner.json')};
  try {
    const owner=claimPhase3IamOwner(input);assert.throws(()=>owner.markDispatch('MSCQRProductionFrontendActivation',t.registryTargetSha256));
    assert.equal(owner.markDispatch(t.registryPolicyName,t.registryTargetSha256),true);
    assert.equal(owner.markDispatch(t.registryPolicyName,t.registryTargetSha256),false);
    assert.equal(owner.hasDispatch(t.registryPolicyName,t.registryTargetSha256),true);assert.match(owner.complete(),/^[a-f0-9]{64}$/);
    const retry=claimPhase3IamOwner({...input,resumeOnly:true});assert.equal(retry.ownershipSha256,owner.ownershipSha256);
    assert.throws(()=>claimPhase3IamOwner({...input,ownerFile:path.join(d,'other.json')}),/ownership outcome/);
  } finally {fs.rmSync(d,{recursive:true,force:true});}
});
test('registry rechecks approval and MFA after its dispatch journal before mutation',()=>{
  const f=fixture();let approvals=0;
  assert.throws(()=>execute(f,{assertCurrentAuthorization:()=>++approvals===3?99:authorizationId}),/authorization changed/);
  assert.equal(writes(f).length,0);
  const second=fixture(),evidence=operatorAttestation();
  const mark=second.owner.markDispatch;second.owner.markDispatch=()=>{evidence.expiresAt=new Date(0).toISOString();return mark();};
  assert.throws(()=>execute(second,{mfaEvidence:evidence}),/expired/);assert.equal(writes(second).length,0);
  const other=fixture();other.run=args=>args[0]==='sts'?JSON.stringify({Account:t.account,Arn:`arn:aws:iam::${t.account}:user/operator`}):fixture().run(args);
  assert.throws(()=>execute(other));assert.equal(writes(other).length,0);
});

test('native plan permits only the exact unchanged release-role data source',()=>{
  const value=plan(),role={name:t.roleName,arn:`arn:aws:iam::${t.account}:role/${t.roleName}`};
  value.resource_changes.push({address:'data.aws_iam_role.release_deployer',mode:'data',type:'aws_iam_role',provider_name:'registry.terraform.io/hashicorp/aws',change:{actions:['no-op'],before:role,after:{...role},after_unknown:{}}});
  assert.doesNotThrow(()=>assertWebRegistryReadPlan(value,sourceSha));
  value.resource_changes.at(-1).change.after.arn+='-other';assert.throws(()=>assertWebRegistryReadPlan(value,sourceSha));
});
