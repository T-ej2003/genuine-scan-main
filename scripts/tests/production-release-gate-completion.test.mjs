import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import {assertNormalGateCompletion} from '../aws/production-release-gate-completion.mjs';

const source='a'.repeat(40);
const names=['Authenticate production environment approval boundary','Apply and verify checksum-bound production RLS package',
 'Upload immutable production database receipt','Activate exact Stage-B backend candidate','Verify backend health',
 'Activate authenticated frontend image','Verify production after frontend activation','Commit authenticated security component state'];

test('normal Gate completion requires a successful post-frontend smoke before state commit',()=>{
 const workflow=fs.readFileSync(new URL('../../.github/workflows/release-gate.yml',import.meta.url),'utf8');
 assert.ok(workflow.indexOf('name: Activate authenticated frontend image')<workflow.indexOf('name: Verify production after frontend activation'));
 assert.ok(workflow.indexOf('name: Verify production after frontend activation')<workflow.indexOf('name: Commit authenticated security component state'));
 const run={id:10,run_attempt:1,head_sha:source,head_branch:'main',path:'.github/workflows/release-gate.yml',event:'workflow_dispatch',status:'completed',conclusion:'success',
  actor:{login:'bot'},repository:{full_name:'T-ej2003/genuine-scan-main'},head_repository:{full_name:'T-ej2003/genuine-scan-main'}};
 const steps=names.map((name,index)=>({name,number:index+1,status:'completed',conclusion:name==='Activate authenticated frontend image'?'skipped':'success'}));
 const job={run_id:10,run_attempt:1,head_sha:source,status:'completed',conclusion:'success',steps};
 const input={run,job,releaseTrainRunId:'9',sourceSha:source,webRequired:false};
 assert.throws(()=>assertNormalGateCompletion({...input,job:{...job,steps:steps.filter(step=>step.name!=='Verify production after frontend activation')}}),/post.*smoke|Verify production after frontend activation/i);
 assert.throws(()=>assertNormalGateCompletion({...input,job:{...job,steps:steps.map(step=>step.name==='Verify production after frontend activation'?{...step,conclusion:'failure'}:step)}}),/failure.*success|Expected values to be strictly equal/);
 assert.throws(()=>assertNormalGateCompletion({...input,run:{...run,head_sha:'b'.repeat(40)}}),/Expected values to be strictly equal/);
});
