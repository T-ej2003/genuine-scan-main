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


test('coordinator composite installs locked backend dependencies before credentials and startup',()=>{
 const action=yaml.load(fs.readFileSync('.github/actions/converge-stage-b-prerequisites/action.yml','utf8'));
 const steps=action.runs.steps,installation=steps.findIndex(step=>step.name==='Install locked coordinator backend dependencies');
 assert.ok(installation>=0);
 assert.equal(steps[installation].shell,'bash');
 assert.equal(steps[installation].run,'npm --prefix backend ci --ignore-scripts --no-audit --no-fund');
 assert.equal(steps[installation]['continue-on-error'],undefined);
 assert.equal(steps[installation].if,undefined);
 assert.ok(installation<steps.findIndex(step=>step.id==='credentials'));
 assert.ok(installation<steps.findIndex(step=>step.id==='converge'));
 assert.ok(fs.existsSync('backend/package-lock.json'));
});

test('root-only hosted layout reproduces missing backend SDK; installed backend loads the real coordinator without production context',()=>{
 const root=process.cwd(),dir=fs.mkdtempSync(path.join(os.tmpdir(),'mscqr-coordinator-startup-test-'));
 try{
  fs.mkdirSync(path.join(dir,'backend'));
  fs.copyFileSync(path.join(root,'backend/package.json'),path.join(dir,'backend/package.json'));
  const code=`const m=await import(${JSON.stringify(new URL('../../scripts/aws/run-production-release-coordinator.mjs',import.meta.url).href)});if(typeof m.runHostedReleaseCoordinator!=='function'||typeof m.createHostedReleaseRuntime!=='function')throw Error('Coordinator entrypoints unavailable');console.log('COORDINATOR_LOADED')`;
  const load=()=>spawnSync(process.execPath,['--input-type=module','-e',code],{cwd:dir,encoding:'utf8',env:{HOME:process.env.HOME,PATH:process.env.PATH},timeout:30000});
  const missing=load();assert.notEqual(missing.status,0);assert.match(missing.stderr,/Cannot find module '@aws-sdk\/client-secrets-manager'/);
  // The installer flags/order are checked above; use existing installed packages
  // for this import regression, without a second installation or live AWS context.
  fs.symlinkSync(fs.realpathSync(path.join(root,'backend/node_modules')),path.join(dir,'backend/node_modules'),'dir');
  const installed=load();assert.equal(installed.status,0,installed.stderr);assert.match(installed.stdout,/COORDINATOR_LOADED/);
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
