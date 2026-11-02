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
 assert.deepEqual(graph.nodes.find(n=>n.id==='b03-authorization').needs,['c02-independent-verification','alias-cas-and-state-closure']);
 assert.deepEqual(graph.nodes.find(n=>n.id==='frontend-and-smoke').needs,['backend-and-smoke']);
 assert.ok(graph.liveOnly.includes('committed SQL catalogue'));
 assert.ok(graph.nodes.find(n=>n.id==='registration').needs.includes('bounded-registration-iam-installation'));
});
for(const [name,mutate] of Object.entries({
 'missing production approval':f=>delete f.train.jobs.orchestrate.environment,
 'missing requirements transport':f=>delete f.train.jobs.orchestrate.env.B03_REQUIREMENTS_REFERENCE_JSON,
 'wrong installation mode':f=>f.train.jobs.orchestrate.env.DATABASE_INSTALL_MODE='clean-room',
 'missing independent verification':f=>{const s=f.gate.jobs['deploy-production-ecs'].steps.find(s=>s.run?.includes('apply-production-b03-incremental-release.mjs'));s.run=s.run.replaceAll('--compatibility-reference','--fake-reference');},
 'direct SQL launch':f=>{const s=f.gate.jobs['deploy-production-ecs'].steps.find(s=>s.run?.includes('apply-production-b03-incremental-release.mjs'));s.run=s.run.replace('node scripts/aws/apply-production-b03-incremental-release.mjs','aws ecs run-task; node scripts/aws/apply-production-b03-incremental-release.mjs');},
 'backend before SQL':f=>{const s=f.gate.jobs['deploy-production-ecs'].steps;const at=s.findIndex(s=>s.name==='Prepare governed green backend recovery handoff');s.unshift(s.splice(at,1)[0]);},
 'missing backend web proof':f=>{for(const j of Object.values(f.web.jobs))for(const s of j.steps||[])if(s.name==='Authenticate coordinated Stage-B and web evidence')delete s.env.BACKEND_ACTIVATION_EVIDENCE_JSON;},
}))test(`release graph fails closed on ${name}`,()=>{const f=fixture();mutate(f);assert.throws(()=>assertApplicationReleaseWorkflowGraph(f));});
