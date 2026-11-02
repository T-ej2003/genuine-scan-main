import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { execFileSync } from 'node:child_process';
import { compactNormalActivationPolicy } from '../aws/production-normal-backend-activation-policy.mjs';
import { RELEASE_POLICY_SOURCES } from '../aws/validate-production-green-stage-b-permissions.mjs';
const file='documents/ops/iam/MSCQRProductionGreenStageBB03Registration-v1.json';
const policy=JSON.parse(fs.readFileSync(file));
const family='arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-b03-incremental:*';
const actions=s=>[s.Action].flat();
test('B03 registration authority is limited to its exact family and fixed runtime dimensions',()=>{
 const allows=policy.Statement.filter(s=>s.Effect==='Allow'&&actions(s).some(a=>a.startsWith('ecs:')));
 assert.equal(allows.length,2);
 for(const s of allows){assert.equal(s.Resource,family);assert.equal(s.Condition.StringEquals['aws:RequestedRegion'],'eu-west-2');
  assert.equal(s.Condition.StringEquals['aws:RequestTag/Component'],'b03-incremental-release');
  assert.equal(s.Condition.StringEquals['aws:RequestTag/Environment'],'production');
  assert.equal(s.Condition.StringEquals['aws:RequestTag/ManagedBy'],'Terraform');
  assert.deepEqual(s.Condition['ForAllValues:StringEquals']['aws:TagKeys'],['Environment','ManagedBy','Component']);}
 const register=allows.find(s=>s.Action==='ecs:RegisterTaskDefinition');
 assert.equal(register.Condition.StringEquals['ecs:privileged'],'false');
 assert.deepEqual(register.Condition['ForAllValues:StringEquals']['ecs:compute-compatibility'],['FARGATE']);
 assert.deepEqual(register.Condition.NumericEquals,{'ecs:task-cpu':1024,'ecs:task-memory':2048});
 assert.equal(policy.Statement.some(s=>s.Effect==='Allow'&&actions(s).some(a=>['ecs:RunTask','ecs:StartTask','iam:PassRole','secretsmanager:GetSecretValue'].includes(a))),false);
});
test('normal Release Gate is explicitly denied B03 launch and administrator-secret reads',()=>{
 const deny=policy.Statement.filter(s=>s.Effect==='Deny');assert.equal(deny.length,2);
 assert.deepEqual(deny.find(s=>s.Sid==='DenyDirectB03Execution'),{Sid:'DenyDirectB03Execution',Effect:'Deny',Action:['ecs:RunTask','ecs:StartTask'],Resource:family});
 assert.match(deny.find(s=>s.Sid==='DenyDirectB03AdministratorSecretRead').Resource,/^arn:aws:secretsmanager:eu-west-2:368992683803:secret:rds!/);
});
test('policy split preserves every prior permission and fits AWS quotas without new roles or wildcard permissions',()=>{
 const final='documents/ops/iam/MSCQRProductionGreenStageBFinalApplyWrite-v1.json';
 const baseline=JSON.parse(execFileSync('git',['show',`9b901d072f64b680db4e979ecf3641f701023e91:${final}`],{encoding:'utf8'}));
 const current=JSON.parse(fs.readFileSync(final));
 assert.deepEqual(current,baseline,'Existing normal-activation and broker ownership authority is unchanged');
 for(const {sourcePath}of RELEASE_POLICY_SOURCES){const document=JSON.parse(fs.readFileSync(sourcePath));
  const published=sourcePath===final?compactNormalActivationPolicy(document):document;
  assert.ok(JSON.stringify(published).replace(/\s/g,'').length<=6144,sourcePath);}
 assert.equal(RELEASE_POLICY_SOURCES.length,10,'Uses the existing role managed-policy capacity; no new role');
 const read=JSON.parse(fs.readFileSync('documents/ops/iam/MSCQRProductionGreenStageBProviderReadOnly-v1.json'));
 assert.ok(read.Statement.find(s=>s.Sid==='ReadExactStagedBrokerCallerPolicies').Resource.includes('arn:aws:iam::368992683803:policy/MSCQRProductionGreenStageBB03Registration'));
});

test('canonical native preflight checks explicit denial of B03 launches and administrator secret reads',()=>{
 const manifest=JSON.parse(fs.readFileSync('documents/ops/iam/MSCQRProductionGreenStageBPermissionManifest-v1.json'));
 const entries=manifest.forbidden.filter(e=>e.id.startsWith('b03-deny-'));
 assert.deepEqual(entries.map(e=>e.action).sort(),['ecs:RunTask','ecs:StartTask','secretsmanager:GetSecretValue']);
 for(const entry of entries){assert.equal(entry.expectedDecision,'explicitDeny');assert.deepEqual(entry.expectedMissingContextValues,[]);assert.notDeepEqual(entry.resources,['*']);}
});
