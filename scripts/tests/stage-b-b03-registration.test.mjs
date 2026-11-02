import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import yaml from 'js-yaml';
import { fixture } from './fixtures/production-b03-plan.mjs';
import { canonicalBrokerPolicy } from './fixtures/staged-broker.mjs';
import { taskChange, rotationVariables } from './fixtures/stage-b-task-rotation.mjs';
import { assertPrerequisitePlan, TASK_REGISTRATION, TASK_REGISTRATION_ADDRESSES, deriveBrokerPolicy, taskMapFromRegisteredDefinitions } from '../aws/stage-b-release-prerequisites.mjs';
import { B03_TASK_ADDRESS } from '../aws/production-b03-plan-contract.mjs';
import { registrationAddressesFromPlan, registrationAddressesFromDefinitions, brokerRegisteredTaskArns } from '../aws/stage-b-task-registration-contract.mjs';
import { assertStageBBrokerPolicyDocument } from '../aws/stage-b-deployment-contract.mjs';
import { produceB03ExecutorDefinition } from '../aws/produce-production-b03-executor-definition.mjs';
import { canonicalSha256, STAGE_B } from '../aws/production-green-stage-b-contract.mjs';
function registration() {
  const b03 = fixture();
  const plan = { ...b03, complete: false, errored: false, variables: { ...rotationVariables, ...b03.variables },
    resource_changes: [...TASK_REGISTRATION_ADDRESSES.map((address,i) => {
      const c = taskChange(address, i + 1, { ...rotationVariables, ...b03.variables }); c.change.before.skip_destroy = true; c.change.after.skip_destroy = true; c.change.after.arn = null; c.change.after.revision = null; c.change.after_unknown = { arn: true, revision: true }; return c;
    }), ...b03.resource_changes] };
  const preparation = { purpose: TASK_REGISTRATION, sourceSha: b03.variables.tooling_sha.value, canonicalAddresses: plan.resource_changes.map(c=>c.address) };
  return { plan, preparation };
}
test('canonical staged registration includes exactly the 12 existing tasks plus fixed B03 create', () => {
  const { plan, preparation } = registration(); assert.equal(assertPrerequisitePlan(plan, preparation).length, 13);
  const definitions = Object.fromEntries(plan.resource_changes.map(c=>[c.address,{arn:`arn:aws:ecs:eu-west-2:368992683803:task-definition/${c.change.after.family}:42`}]));
  assert.equal(registrationAddressesFromDefinitions(definitions).length,13);
  const map = taskMapFromRegisteredDefinitions(definitions); assert.equal(Object.keys(map).length,9);
  const policy = deriveBrokerPolicy(canonicalBrokerPolicy(),map,definitions);
  assertStageBBrokerPolicyDocument(policy);
  assert.deepEqual(policy.Statement.find(s=>s.Sid==='RunOnlyApprovedExecutorAndCanaryRevisions').Resource,brokerRegisteredTaskArns(map,definitions));
  assert.equal(policy.Statement.find(s=>s.Sid==='RunOnlyApprovedExecutorAndCanaryRevisions').Resource.length,10);
});
for(const [name, mutate] of Object.entries({
  missing:p=>p.resource_changes=p.resource_changes.filter(c=>c.address!==B03_TASK_ADDRESS),
  'wrong source':p=>p.variables.tooling_sha.value='c'.repeat(40),
  'wrong image':p=>p.variables.backend_image.value=p.variables.backend_image.value.replace('a'.repeat(64),'b'.repeat(64)),
  'runtime override':p=>{const c=p.resource_changes.at(-1);const cs=JSON.parse(c.change.after.container_definitions);cs[0].command=['sh'];c.change.after.container_definitions=JSON.stringify(cs);},
  replace:p=>p.resource_changes.at(-1).change.actions=['create','delete'],
  'extra task':p=>p.resource_changes.push({...p.resource_changes.at(-1),address:'aws_ecs_task_definition.untrusted[0]'}),
})) test(`staged B03 registration rejects ${name}`,()=>{const {plan,preparation}=registration();mutate(plan);assert.throws(()=>assertPrerequisitePlan(plan,preparation));});

test('legacy 12-output receipts remain exact; unknown outputs and wildcard B03 revisions fail',()=>{
  const definitions=Object.fromEntries(TASK_REGISTRATION_ADDRESSES.map(a=>[a,{}]));assert.equal(registrationAddressesFromDefinitions(definitions).length,12);
  assert.throws(()=>registrationAddressesFromDefinitions({...definitions,other:{}}));
  assert.throws(()=>registrationAddressesFromDefinitions({...definitions,[B03_TASK_ADDRESS]:{arn:'arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-b03-incremental:*'}}));
  const policy=canonicalBrokerPolicy();policy.Statement.find(s=>s.Sid==='RunOnlyApprovedExecutorAndCanaryRevisions').Resource.push('arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-b03-incremental:*');assert.throws(()=>assertStageBBrokerPolicyDocument(policy));
});
function producer() {
  const plan=fixture();
  const sourceSha=plan.variables.tooling_sha.value;
  const predecessorBody={sourceSha:'d785aa7f1e154f37c0dc621082e3f6c46d5d5aec',candidateSourceSha:'d785aa7f1e154f37c0dc621082e3f6c46d5d5aec'};
  const predecessor={...predecessorBody,requirementsSha256:canonicalSha256(predecessorBody)};
  const successor={sourceSha,candidateSourceSha:sourceSha};
  const reference=sha=>({sourceSha:sha,runId:'1',runAttempt:'1',artifactId:'1',artifactDigest:'sha256:'+'a'.repeat(64),fileSha256:'b'.repeat(64)});
  return {sourceSha,backendImage:plan.variables.backend_image.value,references:{predecessor:reference(predecessor.sourceSha),successor:reference(sourceSha)},
    repositoryRoot:process.cwd(),download:({reference})=>({bytes:Buffer.from(JSON.stringify(reference.sourceSha===sourceSha?successor:predecessor))}),
    validateSuccessor:(s,e)=>{assert.equal(s.sourceSha,e.sourceSha);assert.equal(s.candidateSourceSha,e.sourceSha);},
    buildPackage:()=>({schemaVersion:1,kind:'PRODUCTION_B03_INCREMENTAL_PACKAGE',sourceSha,mutations:Array.from({length:44},()=>({owner:'auth',sql:'SELECT 1'}))}),
    run:()=>JSON.stringify({DBInstances:[{DBInstanceIdentifier:STAGE_B.greenDatabaseIdentifier,DBInstanceStatus:'available',Engine:'postgres',Endpoint:{Address:'db.example.internal'}}]})};
}
test('canonical B03 definition producer binds authenticated references and live database identity',()=>{
  const input=producer(),definition=produceB03ExecutorDefinition(input);assert.equal(definition.containerDefinitions[0].image,input.backendImage);
  assert.equal(definition.taskRoleArn,undefined);assert.deepEqual(definition.containerDefinitions[0].command,[]);
  input.references.successor.sourceSha='0'.repeat(40);assert.throws(()=>produceB03ExecutorDefinition(input));
});
for(const [name,mutate] of Object.entries({
  'missing reference':i=>delete i.references.predecessor,
  'wrong predecessor':i=>i.references.predecessor.sourceSha='b'.repeat(40),
  'forged artifact':i=>i.download=()=>({bytes:Buffer.from('{}')}),
  'wrong database':i=>i.run=()=>JSON.stringify({DBInstances:[{DBInstanceIdentifier:'other'}]}),
  'wrong package':i=>i.buildPackage=()=>({sourceSha:'b'.repeat(40)}),
  'wrong repository':i=>i.backendImage=i.backendImage.replace('mscqr-backend','other'),
}))test(`B03 producer rejects ${name}`,()=>{const input=producer();mutate(input);assert.throws(()=>produceB03ExecutorDefinition(input));});
test('Release Train transports B03 requirements only into the governed coordinator',()=>{
 const w=yaml.load(fs.readFileSync('.github/workflows/release-train.yml','utf8'));
 assert.equal(w.jobs.orchestrate.env.B03_REQUIREMENTS_REFERENCE_JSON,'${{ inputs.b03_requirements_reference_json }}');
 assert.equal(w.jobs.orchestrate.env.DATABASE_INSTALL_MODE,'${{ inputs.database_install_mode }}');
 assert.equal(w.jobs.orchestrate.environment,'production');
});

test('13-task registration seals B03 in the same one-use result and feeds exact broker IAM', async () => {
  const { executeTaskRegistration } = await import('../aws/stage-b-release-prerequisites.mjs');
  const { brokerDigest } = await import('../aws/stage-b-staged-broker-contract.mjs');
  const { plan, preparation } = registration();
  const bytes = Buffer.from('exact reviewed registration plan');
  Object.assign(preparation,{treeSha256:'b'.repeat(64),savedPlanSha256:brokerDigest(bytes),logicalPlanSha256:brokerDigest(plan),artifactSetSha256:'c'.repeat(64)});
  const states=Object.fromEntries(plan.resource_changes.map(c=>[c.address,{...structuredClone(c.change.after),arn:`arn:aws:ecs:eu-west-2:368992683803:task-definition/${c.change.after.family}:42`,revision:42}]));
  let applied=0, reserved=false;const records=[];
  const deps={authenticatePrerequisiteAuthorization:async()=> 'd'.repeat(64),readPlan:async()=>({plan,bytes,artifactSetSha256:preparation.artifactSetSha256}),
    reserve:async()=>{assert.equal(reserved,false);reserved=true;},record:async(...r)=>records.push(r),applyTaskRegistration:async()=>{applied++;},
    readRegisteredTaskDefinition:async a=>states[a],describeTaskDefinition:async arn=>{
      const s=Object.values(states).find(s=>s.arn===arn),platform=Array.isArray(s.runtime_platform)?s.runtime_platform[0]:s.runtime_platform;
      return {taskDefinitionArn:arn,revision:42,status:'ACTIVE',family:s.family,taskRoleArn:s.task_role_arn||undefined,executionRoleArn:s.execution_role_arn,
        networkMode:s.network_mode,cpu:s.cpu,memory:s.memory,requiresCompatibilities:s.requires_compatibilities,
        runtimePlatform:{operatingSystemFamily:platform.operating_system_family,cpuArchitecture:platform.cpu_architecture},volumes:s.volume.map(({name})=>({name})),
        containerDefinitions:JSON.parse(s.container_definitions),tags:Object.entries(s.tags).map(([key,value])=>({key,value}))};}};
  const result=await executeTaskRegistration({preparation,authorization:{}},deps);
  assert.equal(applied,1);assert.equal(Object.keys(result.definitions).length,13);
  assert.equal(result.definitions[B03_TASK_ADDRESS].arn,states[B03_TASK_ADDRESS].arn);
  assert.equal(records.at(-1)[1],'TASK_REGISTERED');
  const policy=deriveBrokerPolicy(canonicalBrokerPolicy(),result.taskMap,result.definitions);assertStageBBrokerPolicyDocument(policy);
  assert.ok(policy.Statement.find(s=>s.Sid==='RunOnlyApprovedExecutorAndCanaryRevisions').Resource.includes(result.definitions[B03_TASK_ADDRESS].arn));
  await assert.rejects(executeTaskRegistration({preparation,authorization:{}},deps));assert.equal(applied,1);
});
