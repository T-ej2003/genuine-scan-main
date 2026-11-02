import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import yaml from 'js-yaml';
import {createProductionEnvironmentApprovalEvidence} from '../aws/production-github-environment-approval.mjs';
import {canonicalJson} from '../aws/production-green-stage-b-contract.mjs';
import {PROVIDER_READONLY_RECONCILIATION as C} from '../aws/production-provider-readonly-policy-reconciliation.mjs';
import {JOURNAL_EXPORT_KEYS as keys, validateExportRequest, validateJournalExportObject, exportProviderReadonlyJournals} from '../aws/export-production-provider-readonly-journals.mjs';
import {createSecurityCatalogueTransportKeyPair, decryptSecurityCatalogueTransport} from '../aws/production-security-rebaseline-transport.mjs';
const pair=createSecurityCatalogueTransportKeyPair(), sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const env={GITHUB_ACTIONS:'true',GITHUB_REPOSITORY:'T-ej2003/genuine-scan-main',GITHUB_REF:'refs/heads/main',GITHUB_WORKFLOW_REF:C.executionWorkflowRef,GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_RUN_ID:'123',GITHUB_ACTOR:'release-operator',GITHUB_RUN_ATTEMPT:'1',SOURCE_SHA:'a'.repeat(40),GITHUB_SHA:'a'.repeat(40),OPERATION:'export-journals',RECIPIENT_PUBLIC_KEY_BASE64:Buffer.from(pair.publicKeyPem).toString('base64'),RECIPIENT_PUBLIC_KEY_SHA256:sha(crypto.createPublicKey(pair.publicKeyPem).export({type:'spki',format:'der'}))};
const approval=()=>createProductionEnvironmentApprovalEvidence({environmentConfig:{id:1,name:'production',can_admins_bypass:false,protection_rules:[{type:'required_reviewers',prevent_self_review:true,reviewers:[{type:'User',reviewer:{id:2,login:'T-ej2003'}}]}]},repository:env.GITHUB_REPOSITORY,environment:'production',sourceSha:env.SOURCE_SHA,workflowRef:env.GITHUB_WORKFLOW_REF,eventName:env.GITHUB_EVENT_NAME,workflowRunId:env.GITHUB_RUN_ID,workflowRunAttempt:'1',executionActor:env.GITHUB_ACTOR,actualApproval:{state:'approved',environmentId:1,environmentName:'production',userId:2,userLogin:'T-ej2003'}});
function record(key){const [,id,name]=key.split('/');const b={kind:`PRODUCTION_PROVIDER_READONLY_POLICY_RECONCILIATION_${{'reservation.json':'RESERVATION','write-attempt.json':'WRITE_ATTEMPT','terminal.json':'TERMINAL'}[name]}`,operationId:id,sourceSha:id.startsWith('496')?'d6f515fe393e0bcfda76e248aa8b3f2f3aae10e4':'e3b7fcce67be6c7151a6d082fc0aa23654d61764',account:C.account,targetPolicyArn:C.policyArn,...(name==='terminal.json'?{status:'COMPLETED',authorizationConsumed:true}:{})};return Buffer.from(canonicalJson({...b,recordSha256:sha(canonicalJson(b))})+'\n');}
const meta=b=>({ContentLength:b.length,ServerSideEncryption:'AES256',VersionId:'exact-version',ETag:'"abc123"'});
test('fixed keys and source identity reject requests and write inputs',()=>{
 assert.equal(keys.length,6);assert.equal(new Set(keys).size,6);validateExportRequest(env);
 for(const [k,v] of Object.entries({GITHUB_REPOSITORY:'evil/repo',GITHUB_REF:'refs/heads/evil',GITHUB_WORKFLOW_REF:'other',GITHUB_EVENT_NAME:'pull_request',GITHUB_RUN_ATTEMPT:'2',SOURCE_SHA:'short',GITHUB_SHA:'b'.repeat(40),OPERATION:'reconcile',RECIPIENT_PUBLIC_KEY_SHA256:'a'.repeat(64),PREPARATION_JSON_BASE64:'payload',AUTHORIZATION_WORKFLOW_RUN_ID:'1'})) assert.throws(()=>validateExportRequest({...env,[k]:v}));
 for(const a of [['--key',keys[0]],['--mode','execute'],['--output','/tmp/leak']])assert.throws(()=>validateExportRequest(env,a));
});
test('journal identity and integrity reject corruption and path substitution',()=>{
 for(const key of keys)validateJournalExportObject(key,record(key),meta(record(key)));
 for(const key of ['../terminal.json',keys[0]+'/../terminal.json',keys[0].replace('496','497')])assert.throws(()=>validateJournalExportObject(key,record(keys[0]),meta(record(keys[0]))));
 const b=record(keys[0]);for(const m of [{...meta(b),VersionId:'null'},{...meta(b),ContentLength:1},{...meta(b),ServerSideEncryption:'aws:kms'}])assert.throws(()=>validateJournalExportObject(keys[0],b,m));
 const d=JSON.parse(b);d.account='wrong';assert.throws(()=>validateJournalExportObject(keys[0],Buffer.from(JSON.stringify(d)),meta(b)));
 assert.throws(()=>validateJournalExportObject(keys[1],b,meta(b)));
});
test('export performs only fixed read calls, encrypts all content and fails closed',async()=>{
 const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'journal-export-test-'));let calls=[],auths=0;
 const run=a=>{calls.push(a);if(a[0]==='sts')return JSON.stringify({Account:C.account,Arn:`arn:aws:sts::${C.account}:assumed-role/${C.executorRoleName}/test`});assert.deepEqual(a.slice(0,2),['s3api','get-object']);const key=a[a.indexOf('--key')+1];assert.ok(keys.includes(key));const b=record(key);fs.writeFileSync(a.at(-1),b);return JSON.stringify(meta(b));};
 try{await exportProviderReadonlyJournals({env:{...env,RUNNER_TEMP:tmp},argv:[],run,authenticateSource:()=>{auths++;},approval});assert.equal(calls.length,13);assert.equal(auths,8);const output=fs.readFileSync(path.join(tmp,'provider-readonly-export/encrypted-export.json'),'utf8');assert.ok(!output.includes('recordSha256'));const {binding,chunks}=JSON.parse(output);const d=decryptSecurityCatalogueTransport(chunks,pair.privateKeyPem,binding);assert.equal(d.records.length,6);assert.equal(d.sourceSha,env.SOURCE_SHA);
 await assert.rejects(exportProviderReadonlyJournals({env,argv:['--mode','execute'],run,authenticateSource:()=>{},approval:()=>({})}));
 await assert.rejects(exportProviderReadonlyJournals({env:{...env,RUNNER_TEMP:tmp},argv:[],run:()=>{throw Error('denied');},authenticateSource:()=>{},approval:()=>({})}));
 }finally{fs.rmSync(tmp,{recursive:true,force:true});}
});
test('workflow session and job exclude writes and arbitrary keys',()=>{
 const w=yaml.load(fs.readFileSync('.github/workflows/execute-production-provider-readonly-policy-reconciliation.yml','utf8'));const job=w.jobs['export-journals'];assert.equal(job.environment,'production');assert.equal(job.if,"${{ inputs.operation == 'export-journals' }}");assert.ok(!w.jobs.execute.if.includes('export-journals'));
 const policy=JSON.parse(job.steps.find(s=>s.name==='Configure read-only six-object session').with['inline-session-policy']);assert.equal(policy.Statement.length,1);assert.equal(policy.Statement[0].Action,'s3:GetObject');assert.deepEqual(policy.Statement[0].Resource,keys.map(k=>`arn:aws:s3:::${C.journalBucket}/${k}`));assert.ok(!JSON.stringify(job).includes('reconcile-production-provider-readonly-policy.mjs'));
 const upload=job.steps.at(-1);assert.equal(upload.if,undefined);assert.equal(upload.with.path,'${{ runner.temp }}/provider-readonly-export/encrypted-export.json');
});

test('missing approval, source drift and changed S3 versions prevent publication', async()=>{
 const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'journal-export-rejection-'));const e={...env,RUNNER_TEMP:tmp};let reads=0;
 try {
 for(const approved of [()=>({}),()=>({...approval(),sourceSha:'b'.repeat(40)}),()=>{throw Error('missing approval');}])await assert.rejects(exportProviderReadonlyJournals({env:e,argv:[],authenticateSource:()=>{},approval:approved,run:()=>{reads++;throw Error('AWS must be unreachable');}}));
 assert.equal(reads,0);
 await assert.rejects(exportProviderReadonlyJournals({env:e,argv:[],authenticateSource:()=>{throw Error('source drift');},approval,run:()=>{reads++;}}));assert.equal(reads,0);
 const run=a=>{if(a[0]==='sts')return JSON.stringify({Account:C.account,Arn:`arn:aws:sts::${C.account}:assumed-role/${C.executorRoleName}/test`});const b=record(keys[0]);fs.writeFileSync(a.at(-1),b);return JSON.stringify({...meta(b),VersionId:++reads===1?'first':'changed'});};
 await assert.rejects(exportProviderReadonlyJournals({env:e,argv:[],authenticateSource:()=>{},approval,run}),/changed|equal/);
 assert.equal(fs.existsSync(path.join(tmp,'provider-readonly-export')),false);
 }finally {fs.rmSync(tmp,{recursive:true,force:true});}
});
