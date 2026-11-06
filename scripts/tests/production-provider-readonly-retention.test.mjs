import assert from 'node:assert/strict';
import test from 'node:test';
import crypto from 'node:crypto';
import fs from 'node:fs';
import yaml from 'js-yaml';
import {canonicalJson} from '../aws/production-green-stage-b-contract.mjs';
import {createProductionEnvironmentApprovalEvidence} from '../aws/production-github-environment-approval.mjs';
import {PROVIDER_READONLY_RECONCILIATION as C,createProviderReadonlyRetirementPreparation,createProviderReadonlyPreparation,assertProviderReadonlyRetirementPreparation,authenticateProviderReadonlyVersionArchive,readProviderReadonlyRetentionPolicy,readProviderReadonlyDesiredPolicy,createProviderReadonlyAuthorization,assertProviderReadonlyAuthorization,createProviderReadonlyJournal,executeProviderReadonlyRetirement,executeProviderReadonlyReconciliation} from '../aws/production-provider-readonly-policy-reconciliation.mjs';
const sha=b=>crypto.createHash('sha256').update(Buffer.isBuffer(b)?b:canonicalJson(b)).digest('hex');
const source='a'.repeat(40),now=new Date('2026-11-02T20:00:00.000Z'),desired=readProviderReadonlyDesiredPolicy();
function archive(){
 const v5=structuredClone(desired.stagedPredecessorDocument),v4=structuredClone(v5);
 v4.Statement=v4.Statement.filter(s=>!['ListRegionalBrokerEventMappings','ReadExactStagedBrokerCallerPolicies'].includes(s.Sid));
 for(const s of v4.Statement){if(s.Sid==='ReadExactStageBRoles')s.Resource=s.Resource.filter(r=>r!==C.releaseRoleArn);if(s.Sid==='ReadExactStageBBrokerFunction')s.Action=s.Action.filter(a=>!['lambda:ListAliases','lambda:ListFunctionUrlConfigs'].includes(a));if(s.Sid==='ReadExactStageBBrokerAlias')s.Resource=s.Resource.filter(r=>!r.endsWith(':*'));}
 const v3=structuredClone(v4);v3.Statement=v3.Statement.filter(s=>s.Sid!=='ReadExactStageBWorkerPublicationImage');
 const v2=structuredClone(v3);v2.Statement=v2.Statement.filter(s=>s.Sid!=='ReadExactLegacyBackendRecoveryRepository');
 const v1=structuredClone(v2);v1.Statement=v1.Statement.filter(s=>s.Sid!=='ReadExactStageARootDropProviderKey');
 for(const s of v1.Statement){if(s.Sid==='ReadExactStageBRoles')s.Action=s.Action.filter(a=>a!=='iam:ListAttachedRolePolicies');if(s.Sid==='ReadExactStageBLogTags')s.Resource=s.Resource.filter(r=>!r.includes('rls-green-read-only-canary'));if(s.Sid==='ReadExactStageBBrokerFunction')s.Action=s.Action.filter(a=>a!=='lambda:GetFunctionCodeSigningConfig');}
 return {policyArn:C.policyArn,versions:[v1,v2,v3,v4,v5].map((document,i)=>({versionId:`v${i+1}`,isDefault:i===4,createDate:now.toISOString(),document}))};
}
const a=archive();
const state=()=>({policyArn:C.policyArn,defaultVersionId:'v5',document:a.versions[4].document,versions:a.versions.map(({versionId,isDefault})=>({versionId,isDefault})),attachedRoles:[C.releaseRoleName],attachedUsers:[],attachedGroups:[],permissionsBoundaryUsageCount:0});
const prep=()=>createProviderReadonlyRetirementPreparation({sourceSha:source,liveState:state(),archive:a,preparedAt:now.toISOString()});
const approval=(at=now)=>createProductionEnvironmentApprovalEvidence({environmentConfig:{id:1,name:'production',can_admins_bypass:false,protection_rules:[{type:'required_reviewers',prevent_self_review:true,reviewers:[{type:'User',reviewer:{id:2,login:'T-ej2003'}}]}]},repository:'T-ej2003/genuine-scan-main',environment:'production',sourceSha:source,workflowRef:C.workflowRef,eventName:'workflow_dispatch',workflowRunId:'123',workflowRunAttempt:'1',executionActor:'release-operator',observedAt:at.toISOString(),actualApproval:{state:'approved',environmentId:1,environmentName:'production',userId:2,userLogin:'T-ej2003'}});
function auth(p,at=now){const authorization=createProviderReadonlyAuthorization({preparation:p,protectedEnvironmentApprovalEvidence:approval(at),now:at});const b={schemaVersion:1,kind:'PRODUCTION_PROVIDER_READONLY_POLICY_RECONCILIATION_AUTHORIZATION_PROVENANCE',repository:'T-ej2003/genuine-scan-main',workflowPath:C.workflowPath,workflowRunId:'123',workflowRunAttempt:'1',event:'workflow_dispatch',status:'completed',conclusion:'success',headSha:source,artifactId:1,artifactName:C.artifactName,artifactDigest:`sha256:${'b'.repeat(64)}`,authorizationFileSha256:'c'.repeat(64),authorizationSha256:authorization.authorizationSha256,approvedBy:'T-ej2003'};return {authorization,provenance:{...b,provenanceSha256:sha(b)}};}
function harness(){const p=prep(),grants=auth(p),store=new Map();let live=state(),writes=0;const journal=createProviderReadonlyJournal({read:async k=>store.get(k)||null,create:async(k,b)=>{if(store.has(k))return false;store.set(k,Buffer.from(b));return true;}});const input={sourceSha:source,preparation:p,...grants,journal:{...journal},readLiveState:async()=>structuredClone(live),readVersionArchive:async()=>structuredClone(a),deletePolicyVersion:async args=>{assert.deepEqual(args,{PolicyArn:C.policyArn,VersionId:'v1'});assert.ok([...store.keys()].some(k=>k.endsWith('/version-archive.json')));writes++;live.versions=live.versions.filter(v=>v.versionId!=='v1');},reauthenticateSource:()=>{},now:()=>now,sleep:async()=>{}};return {input,store,get writes(){return writes;},get live(){return live;}};}
test('source-owned v1 decision authenticates all five documents and preserves v5 default',()=>{
 authenticateProviderReadonlyVersionArchive(a);assert.deepEqual(Object.fromEntries(a.versions.map(v=>[v.versionId,sha(v.document)])),readProviderReadonlyRetentionPolicy().versionDocumentSha256);
 const p=prep();assertProviderReadonlyRetirementPreparation(p,{sourceSha:source,now});assert.equal(p.deletionCandidate.versionId,'v1');assert.equal(p.desiredDocumentSha256,p.currentDefaultDocumentSha256);assert.equal(p.expectedWritePlan.length,1);assert.equal(p.expectedWritePlan[0].action,'iam:DeletePolicyVersion');assertProviderReadonlyAuthorization(auth(p).authorization,p,{sourceSha:source,now});
});
test('drift, default protection, archive tampering, authorization mismatch and expiry reject',()=>{
 for(const mutate of [x=>x.versions.pop(),x=>x.versions[0].isDefault=true,x=>x.versions[1].document.Statement.push({Effect:'Allow',Action:'*',Resource:'*'}),x=>x.versions.reverse()]){const bad=structuredClone(a);mutate(bad);assert.throws(()=>authenticateProviderReadonlyVersionArchive(bad));}
 const p=prep();for(const change of [{sourceSha:'b'.repeat(40)},{currentDefaultVersionId:'v1'},{deletionCandidate:{...p.deletionCandidate,versionId:'v2'}},{versionInventory:p.versionInventory.slice(1)}])assert.throws(()=>assertProviderReadonlyRetirementPreparation({...p,...change},{sourceSha:source,now}));
 assert.throws(()=>assertProviderReadonlyRetirementPreparation(p,{sourceSha:source,now:new Date(now.getTime()+31*60000)}));assert.throws(()=>assertProviderReadonlyAuthorization({...auth(p).authorization,deletionRequired:false},p,{sourceSha:source,now}));
});
test('archive/readback precedes one deletion; repeated execution consumes without new mutation',async()=>{
 const h=harness();const result=await executeProviderReadonlyRetirement(h.input);assert.equal(result.status,'COMPLETED');assert.equal(h.writes,1);assert.deepEqual(h.live.versions.map(v=>v.versionId),['v2','v3','v4','v5']);assert.equal(h.live.defaultVersionId,'v5');assert.equal((await executeProviderReadonlyRetirement(h.input)).status,'CONSUMED');assert.equal(h.writes,1);
 await assert.rejects(executeProviderReadonlyReconciliation(h.input),/cannot enter/);
});
test('archive failure and inventory drift cannot delete',async()=>{
 for(const variant of ['archive','drift']){const h=harness();if(variant==='archive'){const original=h.input.journal.create;h.input.journal.create=async(auth,key,body)=>key==='version-archive.json'?false:original(auth,key,body);}else h.live.versions[0].isDefault=true;await assert.rejects(executeProviderReadonlyRetirement(h.input));assert.equal(h.writes,0);}
});
test('lost delete response and interrupted completion recover from retained state without deletion replay',async()=>{
 const h=harness(),del=h.input.deletePolicyVersion;h.input.deletePolicyVersion=async args=>{await del(args);throw Error('lost response');};const create=h.input.journal.create;let blocked=true;h.input.journal.create=async(auth,key,body)=>{if(key==='terminal.json'&&blocked)throw Error('completion unavailable');return create(auth,key,body);};await assert.rejects(executeProviderReadonlyRetirement(h.input),/uncertain/);assert.equal(h.writes,1);blocked=false;assert.equal((await executeProviderReadonlyRetirement(h.input)).status,'COMPLETED');assert.equal(h.writes,1);
});
test('uncertain unchanged inventory and failed deletion never retry; v5 stays intact',async()=>{
 const h=harness();let calls=0;h.input.deletePolicyVersion=async()=>{calls++;throw Error('unknown outcome');};await assert.rejects(executeProviderReadonlyRetirement(h.input),/uncertain/);await assert.rejects(executeProviderReadonlyRetirement(h.input),/will not be retried/);assert.equal(calls,1);assert.equal(h.live.defaultVersionId,'v5');assert.equal(h.live.versions.length,5);
});
test('workflow selects fixed retirement mode and source policy has no global deletion',()=>{
 const w=yaml.load(fs.readFileSync('.github/workflows/execute-production-provider-readonly-policy-reconciliation.yml','utf8'));assert.match(w.jobs.execute.if,/retire-v1/);assert.equal(w.jobs.execute.environment,'production');const step=w.jobs.execute.steps.find(s=>s.name==='Execute exact authorized reconciliation');assert.match(step.run,/retire-v1\) mode=execute-retirement/);assert.ok(!step.run.includes('eval'));
 const p=JSON.parse(fs.readFileSync('infra/aws/terraform/production-initial-activation-policy-reconciler/permissions-policy.json'));assert.deepEqual(p.Statement.filter(s=>s.Action==='iam:DeletePolicyVersion').map(s=>s.Resource),[C.policyArn]);
});

test('corrupt archive readback cannot authorize deletion',async()=>{
 const h=harness(),read=h.input.journal.read;
 h.input.journal.read=async(auth,key)=>{const r=await read(auth,key);return key==='version-archive.json'&&r?{...r,sourceSha:'b'.repeat(40)}:r;};
 await assert.rejects(executeProviderReadonlyRetirement(h.input),/evidence mismatch/);assert.equal(h.writes,0);
});
test('concurrent retirement attempts cannot duplicate deletion',async()=>{
 const h=harness();const results=await Promise.allSettled([executeProviderReadonlyRetirement(h.input),executeProviderReadonlyRetirement(h.input)]);
 assert.equal(results.filter(r=>r.status==='fulfilled').length,1);assert.equal(h.writes,1);
});
test('failed separately authorized replacement preserves v5 and never repeats retirement',async()=>{
 const h=harness();await executeProviderReadonlyRetirement(h.input);
 const p=createProviderReadonlyPreparation({sourceSha:source,liveState:h.live,preparedAt:now.toISOString()}),g=auth(p),store=new Map();
 const journal=createProviderReadonlyJournal({read:async k=>store.get(k)||null,create:async(k,b)=>{if(store.has(k))return false;store.set(k,Buffer.from(b));return true;}});
 let creates=0;const input={sourceSha:source,preparation:p,...g,journal,readLiveState:async()=>structuredClone(h.live),createPolicyVersion:async()=>{creates++;throw Error('unknown create outcome');},reauthenticateSource:()=>{},now:()=>now,sleep:async()=>{}};
 await assert.rejects(executeProviderReadonlyReconciliation(input));await assert.rejects(executeProviderReadonlyReconciliation(input),/ambiguous/);
 assert.equal(creates,1);assert.equal(h.writes,1);assert.equal(h.live.defaultVersionId,'v5');assert.equal(h.live.versions.length,4);
});
test('expired approval blocks new deletion but can authenticate completed outcome',async()=>{
 const h=harness();h.input.now=()=>new Date(now.getTime()+31*60000);await assert.rejects(executeProviderReadonlyRetirement(h.input),/stale|expired/);assert.equal(h.writes,0);
 h.input.now=()=>now;await executeProviderReadonlyRetirement(h.input);h.input.now=()=>new Date(now.getTime()+31*60000);assert.equal((await executeProviderReadonlyRetirement(h.input)).status,'CONSUMED');assert.equal(h.writes,1);
});
test('source drift after durable attempt cannot invoke deletion',async()=>{
 const h=harness();h.input.reauthenticateSource=()=>{if([...h.store.keys()].some(k=>k.endsWith('/write-attempt.json')))throw Error('source advanced');};
 await assert.rejects(executeProviderReadonlyRetirement(h.input),/source advanced/);assert.equal(h.writes,0);assert.equal(h.live.defaultVersionId,'v5');
});

test('fresh approval can adopt an expired zero-write reservation and verified archive',async()=>{
 const h=harness(),create=h.input.journal.create;
 h.input.journal.create=async(a,k,b)=>k==='write-attempt.json'?false:create(a,k,b);
 await assert.rejects(executeProviderReadonlyRetirement(h.input),/write attempt raced/);assert.equal(h.writes,0);
 const later=new Date(now.getTime()+31*60000),p=createProviderReadonlyRetirementPreparation({sourceSha:source,liveState:h.live,archive:a,preparedAt:later.toISOString()});
 assert.equal(p.operationId,h.input.preparation.operationId);
 h.input={...h.input,preparation:p,...auth(p,later),now:()=>later,journal:{...h.input.journal,create}};
 assert.equal((await executeProviderReadonlyRetirement(h.input)).status,'COMPLETED');assert.equal(h.writes,1);
});
