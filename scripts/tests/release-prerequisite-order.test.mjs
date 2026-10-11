import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import test from 'node:test';
import yaml from 'js-yaml';
const train=yaml.load(fs.readFileSync('.github/workflows/release-train.yml','utf8'));
const gates=train.jobs.gates.steps;
const dispatch=gates.find(step=>step.id==='gate_runs');
test('actual prerequisite gate sequence uses exact-source CI without overlap, and rejects missing CI or non-main',()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'mscqr-prerequisite-order-test-'));
 try{
  fs.writeFileSync(path.join(dir,'gh'),'#!/bin/sh\nprintf "%s" "$FIXTURE_RUN_ID"\n',{mode:0o700});
  const env={...process.env,PATH:dir+':'+process.env.PATH,RELEASE_LIFECYCLE:'prerequisites',DISPATCH_REF:'main',TARGET_SHA:'a'.repeat(40),GITHUB_REPOSITORY:'T-ej2003/genuine-scan-main',RUNNER_TEMP:dir,GITHUB_ENV:path.join(dir,'env'),GITHUB_OUTPUT:path.join(dir,'output'),FIXTURE_RUN_ID:'123'};
  const execute=extra=>spawnSync('bash',['-c',dispatch.run],{env:{...env,...extra},encoding:'utf8'});
  assert.equal(execute().status,0);
  const output=fs.readFileSync(env.GITHUB_OUTPUT,'utf8');
  assert.equal(Object.keys(JSON.parse(output.split('gate_run_ids_json=')[1].trim())).length,5);
  assert.notEqual(execute({DISPATCH_REF:'refs/tags/v1'}).status,0);
  assert.notEqual(execute({FIXTURE_RUN_ID:''}).status,0);
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
test('both deployment routes retain rotation gates while prerequisite-only stops before Release Gate',()=>{
 assert.equal(train.on.workflow_dispatch.inputs.prerequisites_only.default,false);
 assert.equal(train.jobs.orchestrate.environment,'production');
 assert.equal(train.jobs.orchestrate.needs,'gates');
 const steps=train.jobs.orchestrate.steps;
 assert.ok(steps.findIndex(step=>step.name==='Require authenticated prerequisite closure')<steps.findIndex(step=>step.name==='Trigger final Release Gate'));
 assert.equal(steps.find(step=>step.name==='Trigger final Release Gate').if,'${{ !inputs.prerequisites_only }}');
 assert.match(dispatch.run,/strict\)\s+;;/);
 assert.match(dispatch.run,/authenticated-initial-overlap\)[\s\S]*--mode validate-candidate/);
 assert.match(dispatch.run,/--image-release-sha "\$image_release_sha"/);
 for(const file of ['quality-gate','deployment-audit']){
  const text=fs.readFileSync(`.github/workflows/${file}.yml`,'utf8');
  assert.match(text,/--image-release-sha "\$image_release_sha"/);
  assert.doesNotMatch(text,/prerequisites\)/);
 }
 assert.doesNotMatch(fs.readFileSync('.github/workflows/release-gate.yml','utf8'),/prerequisites\)/);
});
