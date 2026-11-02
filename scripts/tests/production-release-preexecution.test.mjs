import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import yaml from 'js-yaml';
import { assertApplicationReleaseWorkflowGraph } from '../aws/certify-production-backend-release-gate.mjs';
const read=name=>yaml.load(fs.readFileSync(`.github/workflows/${name}`,'utf8'));
const fixture=()=>({train:read('release-train.yml'),gate:read('release-gate.yml'),web:read('production-web-activation.yml')});
test('source-backed executable release DAG checks SQL before backend and backend proof before web',()=>{
 const graph=assertApplicationReleaseWorkflowGraph(fixture());
 assert.equal(graph.productionExecutionReady,false);
 const find=name=>graph.nodes.find(n=>n.name===name);
 assert.equal(find('Activate authenticated frontend image').index,fixture().gate.jobs['deploy-production-ecs'].steps.findIndex(s=>s.name==='Activate authenticated frontend image'));
 assert.deepEqual(graph.nodes.filter(n=>n.kind==='coordinator-phase').map(n=>n.id),['registration','pruning','policy','publication','cutover','closure'].map(n=>'coordinator:'+n));
 assert.ok(graph.nodes.find(n=>n.id==='gate:resolve-deploy-target').needs.includes(find('Trigger final Release Gate').id));
 assert.equal(graph.externalOperations.find(n=>n.id==='bounded-registration-iam-installation').before,'coordinator:registration');
 assert.equal(graph.externalOperations.find(n=>n.id==='worker-activation').after,find('Verify production after frontend activation').id);
 assert.ok(graph.liveOnly.includes('committed SQL catalogue'));
 assert.ok(graph.nodes.length>80,'Actual workflow jobs/steps must be represented');
});
for(const [name,mutate] of Object.entries({
 'missing production approval':f=>delete f.train.jobs.orchestrate.environment,
 'missing requirements transport':f=>delete f.train.jobs.orchestrate.env.B03_REQUIREMENTS_REFERENCE_JSON,
 'wrong installation mode':f=>f.train.jobs.orchestrate.env.DATABASE_INSTALL_MODE='clean-room',
 'missing independent verification':f=>{const s=f.gate.jobs['deploy-production-ecs'].steps.find(s=>s.run?.includes('apply-production-b03-incremental-release.mjs'));s.run=s.run.replaceAll('--compatibility-reference','--fake-reference');},
 'direct SQL launch':f=>{const s=f.gate.jobs['deploy-production-ecs'].steps.find(s=>s.run?.includes('apply-production-b03-incremental-release.mjs'));s.run=s.run.replace('node scripts/aws/apply-production-b03-incremental-release.mjs','aws ecs run-task; node scripts/aws/apply-production-b03-incremental-release.mjs');},
 'direct SQL launch with tabs':f=>{const s=f.gate.jobs['deploy-production-ecs'].steps.find(s=>s.run?.includes('apply-production-b03-incremental-release.mjs'));s.run=s.run.replace('node scripts/aws/apply-production-b03-incremental-release.mjs','aws\tecs\trun-task; node scripts/aws/apply-production-b03-incremental-release.mjs');},
 'backend before SQL':f=>{const s=f.gate.jobs['deploy-production-ecs'].steps;const at=s.findIndex(s=>s.name==='Prepare governed green backend recovery handoff');s.unshift(s.splice(at,1)[0]);},
 'missing backend web proof':f=>{for(const j of Object.values(f.web.jobs))for(const s of j.steps||[])if(s.name==='Authenticate coordinated Stage-B and web evidence')delete s.env.BACKEND_ACTIVATION_EVIDENCE_JSON;},
}))test(`release graph fails closed on ${name}`,()=>{const f=fixture();mutate(f);assert.throws(()=>assertApplicationReleaseWorkflowGraph(f));});

for(const [workflow,job,names] of [
 ['train','orchestrate',['Authenticate unchanged protected source','Converge exact Stage B prerequisites','Require authenticated prerequisite closure','Trigger final Release Gate']],
 ['gate','deploy-production-ecs',['Apply and verify checksum-bound production RLS package','Upload immutable production database receipt','Activate exact Stage-B backend candidate','Verify backend health','Activate authenticated frontend image','Verify production after frontend activation']],
 ['web','activate',['Authenticate coordinated Stage-B and web evidence']],
]) for(const name of names) test(`observed DAG rejects removed ${name}`,()=>{
 const f=fixture();f[workflow].jobs[job].steps=f[workflow].jobs[job].steps.filter(s=>s.name!==name);
 assert.throws(()=>assertApplicationReleaseWorkflowGraph(f));
});
for(const name of ['Require authenticated prerequisite closure','Trigger final Release Gate'])test(`observed DAG rejects reordered ${name}`,()=>{
 const f=fixture(),steps=f.train.jobs.orchestrate.steps,index=steps.findIndex(s=>s.name===name);steps.unshift(steps.splice(index,1)[0]);
 assert.throws(()=>assertApplicationReleaseWorkflowGraph(f));
});
for(const name of ['Activate exact Stage-B backend candidate','Verify backend health','Activate authenticated frontend image','Verify production after frontend activation'])test(`observed DAG rejects reordered ${name}`,()=>{
 const f=fixture(),steps=f.gate.jobs['deploy-production-ecs'].steps,index=steps.findIndex(s=>s.name===name);steps.unshift(steps.splice(index,1)[0]);
 assert.throws(()=>assertApplicationReleaseWorkflowGraph(f));
});
test('observed DAG rejects missing job needs and dependency cycles',()=>{
 for(const needs of [undefined,'orchestrate']){const f=fixture();f.train.jobs.orchestrate.needs=needs;assert.throws(()=>assertApplicationReleaseWorkflowGraph(f));}
});
test('observed DAG rejects missing or substituted composite coordinator implementation',()=>{
 for(const mutate of [f=>f.train.jobs.orchestrate.steps.find(s=>s.name==='Converge exact Stage B prerequisites').uses='./other',f=>{f.coordinatorAction={runs:{using:'composite',steps:[]}};}]){const f=fixture();mutate(f);assert.throws(()=>assertApplicationReleaseWorkflowGraph(f));}
});
test('observed DAG validates the production coordinator phase table consumed by execution',async()=>{
 const {RELEASE_PREREQUISITE_TRANSITIONS}=await import('../aws/production-release-coordinator.mjs');
 for(const mutate of [a=>a.splice(0,1),a=>a.reverse(),a=>a[3][2]='unreviewed-publish',a=>a.push(a[0])]){
  const f=fixture();f.transitions=structuredClone(RELEASE_PREREQUISITE_TRANSITIONS);mutate(f.transitions);
  assert.throws(()=>assertApplicationReleaseWorkflowGraph(f));
 }
});
test('observed DAG rejects loss of B03 completion containment and backend health command',()=>{
 for(const mutate of [s=>s.find(s=>s.name==='Apply and verify checksum-bound production RLS package').run=s.find(s=>s.name==='Apply and verify checksum-bound production RLS package').run.replace(/(if \[\[ "\$b03_mode" == start \]\]; then[\s\S]*?)exit 1/,'$1true'),s=>s.find(s=>s.name==='Verify backend health').run='true']){
  const f=fixture();mutate(f.gate.jobs['deploy-production-ecs'].steps);assert.throws(()=>assertApplicationReleaseWorkflowGraph(f));
 }
});

test('B03 installation package is exact, privileged, approval-gated and cannot silently broaden operations',()=>{
 const current=JSON.parse(fs.readFileSync('documents/ops/iam/MSCQRProductionGreenStageBB03RegistrationInstallation-v1.json'));
 for(const mutate of [p=>p.executionPrincipal='arn:aws:iam::368992683803:role/mscqr-production-release-deployer',p=>p.policyArn+='-other',p=>p.mutatingActions.push('iam:CreatePolicyVersion'),p=>p.policyFileSha256='0'.repeat(64),p=>p.forbiddenSimulationIds.pop(),p=>p.beforeRegistration=false,p=>p.noExistingPolicyUpdates=false,p=>p.automation='AUTOMATED']){
  const f=fixture();f.iamInstallation=structuredClone(current);mutate(f.iamInstallation);assert.throws(()=>assertApplicationReleaseWorkflowGraph(f));
 }
});

test('observed DAG rejects skipped approval and critical operations or continue-on-error',()=>{
 for(const [workflow,job,name]of [['train','orchestrate','Converge exact Stage B prerequisites'],['train','orchestrate','Trigger final Release Gate'],['gate','deploy-production-ecs','Apply and verify checksum-bound production RLS package'],['gate','deploy-production-ecs','Verify backend health'],['gate','deploy-production-ecs','Activate authenticated frontend image'],['web','activate','Authenticate coordinated Stage-B and web evidence']]){
  for(const field of ['if','continue-on-error']){const f=fixture();f[workflow].jobs[job].steps.find(s=>s.name===name)[field]=field==='if'?'false':true;assert.throws(()=>assertApplicationReleaseWorkflowGraph(f));}
 }
 for(const [workflow,job]of [['train','orchestrate'],['gate','deploy-production-ecs'],['web','activate']]){const f=fixture();delete f[workflow].jobs[job].environment;assert.throws(()=>assertApplicationReleaseWorkflowGraph(f));}
});
