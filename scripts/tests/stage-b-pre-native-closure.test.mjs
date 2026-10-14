import assert from 'node:assert/strict';
import test from 'node:test';
import {authenticatePreNativeClosureAbort} from '../aws/stage-b-pre-native-closure.mjs';
import {brokerDigest,prepareBrokerStateRefresh} from '../aws/stage-b-staged-broker-contract.mjs';
import {createBrokerProtectedEnvironmentAuthorization} from '../aws/stage-b-staged-broker-authorization.mjs';
import {createProductionEnvironmentApprovalEvidence,PRODUCTION_ENVIRONMENT_APPROVAL} from '../aws/production-github-environment-approval.mjs';
import {rig,ready} from './fixtures/staged-broker-runtime.mjs';

async function fixture(){
 const r=await ready(rig()),cutoverAuthorization=r.auth;
 const casResult={status:'CUTOVER_COMMITTED_STATE_PENDING',preparationSha256:brokerDigest(r.p),authorizationSha256:brokerDigest(cutoverAuthorization),
  alias:{...r.p.alias,FunctionVersion:r.p.target.version,RevisionId:'committed'}};
 const prepared={preparation:prepareBrokerStateRefresh({preparation:r.p,authorization:cutoverAuthorization,casResult})};
 const releaseId='1'.repeat(64),round=1,issued=new Date('2026-10-11T12:00:00.000Z'),now=new Date('2026-10-11T13:00:00.000Z');
 const approval=createProductionEnvironmentApprovalEvidence({environmentConfig:{id:7,name:'production',can_admins_bypass:false,
  protection_rules:[{type:'required_reviewers',prevent_self_review:false,reviewers:[{type:'User',reviewer:{id:1,login:'operator'}}]}]},
  repository:PRODUCTION_ENVIRONMENT_APPROVAL.repository,environment:'production',sourceSha:r.p.sourceSha,
  workflowRef:PRODUCTION_ENVIRONMENT_APPROVAL.stageBReleaseTransitionWorkflowRef,eventName:'workflow_dispatch',workflowRunId:'701',
  workflowRunAttempt:'1',executionActor:'operator',observedAt:issued.toISOString(),
  actualApproval:{state:'approved',environmentId:7,environmentName:'production',userId:1,userLogin:'operator'}});
 const authorization=createBrokerProtectedEnvironmentAuthorization(prepared.preparation,{approval,now:issued,
  release:{releaseId,phase:'closure',preparationReference:brokerDigest(prepared),authorizationRound:round}});
 const reference=brokerDigest(authorization),steps=new Map();
 for(const kind of ['attempt','authorized'])steps.set(`closure:${kind}:1`,{releaseId,sourceSha:r.p.sourceSha,name:`closure:${kind}:1`,
  prepared:brokerDigest(prepared),authorization:reference});
 const store={readStep:(id,name)=>{assert.equal(id,releaseId);return steps.get(name)||null;},getArtifact:id=>{assert.equal(id,reference);return authorization;}};
 const read=[];const input={store,releaseId,sourceSha:r.p.sourceSha,round,prepared,casResult,currentTooling:{sourceSha:'c'.repeat(40),treeSha256:'d'.repeat(64)},
  now,verify:async()=>true,readReceipt:({status})=>{read.push(status);throw Object.assign(new Error('Absent'),{code:'RECEIPT_ABSENT'});},
  readState:()=>structuredClone(prepared.preparation.state),readAlias:()=>structuredClone(casResult.alias)};
 return {input,steps,authorization,read};
}
test('expired genuine closure authority plus unchanged live state authenticates a pre-native abort without rewriting history',async()=>{
 const f=await fixture(),before=structuredClone([...f.steps]);
 const proof=await authenticatePreNativeClosureAbort(f.input);
 assert.equal(proof.status,'PRE_NATIVE_ABORTED');assert.equal(proof.authorization,brokerDigest(f.authorization));
 assert.equal(f.read.length,4);assert.deepEqual([...f.steps],before);
});
test('expired authorization without a native attempt requires its retirement and unchanged live state',async()=>{
 const f=await fixture();f.steps.delete('closure:attempt:1');
 await assert.rejects(()=>authenticatePreNativeClosureAbort(f.input),/attempt is required/);
 f.input.allowMissingAttempt=true;
 await assert.rejects(()=>authenticatePreNativeClosureAbort(f.input));
 f.steps.set('closure:retired:1',{releaseId:f.input.releaseId,sourceSha:f.input.sourceSha,name:'closure:retired:1',
  prepared:brokerDigest(f.input.prepared),reason:'AUTHORIZATION_EXPIRED'});
 const before=structuredClone([...f.steps]),proof=await authenticatePreNativeClosureAbort(f.input);
 assert.equal(proof.status,'PRE_NATIVE_ABORTED');assert.equal(Object.hasOwn(proof,'attemptSha256'),false);
 assert.deepEqual([...f.steps],before);assert.equal(f.read.length,4);
 f.input.readState=()=>({...f.input.prepared.preparation.state,serial:999});
 await assert.rejects(()=>authenticatePreNativeClosureAbort(f.input),/state changed/);
});
for(const [name,change] of [
 ['wrong retirement source',f=>f.steps.get('closure:retired:1').sourceSha='f'.repeat(40)],
 ['wrong retirement preparation',f=>f.steps.get('closure:retired:1').prepared='f'.repeat(64)],
 ['wrong retirement round',f=>f.steps.get('closure:retired:1').name='closure:retired:2'],
 ['missing retirement',f=>f.steps.delete('closure:retired:1')],
 ['wrong retirement reason',f=>f.steps.get('closure:retired:1').reason='PRE_NATIVE_ABORTED'],
 ['extra retirement field',f=>f.steps.get('closure:retired:1').runId='701'],
 ['failed approval marker',f=>f.steps.set('closure:approval-failed:1',{})],
 ['timeout marker',f=>f.steps.set('closure:approval-timeout:1',{})],
 ['missing signed authorization',f=>f.steps.delete('closure:authorized:1')],
 ['invalid KMS authorization proof',f=>f.input.verify=async()=>false],
 ['cross-round signed authorization',f=>f.authorization.release.authorizationRound=2],
 ['cross-release signed authorization',f=>f.authorization.release.releaseId='f'.repeat(64)],
 ])test(`no-attempt retirement rejects ${name}`,async()=>{
 const f=await fixture();f.steps.delete('closure:attempt:1');f.input.allowMissingAttempt=true;
 f.steps.set('closure:retired:1',{releaseId:f.input.releaseId,sourceSha:f.input.sourceSha,name:'closure:retired:1',
  prepared:brokerDigest(f.input.prepared),reason:'AUTHORIZATION_EXPIRED'});
 change(f);await assert.rejects(()=>authenticatePreNativeClosureAbort(f.input));
});
for(const [name,change] of [
 ['unexpired authority',f=>f.input.now=new Date(f.authorization.issuedAt)],
 ['invalid approval',f=>f.input.verify=async()=>false],
 ['changed state hash',f=>f.input.readState=()=>({...f.input.prepared.preparation.state,stateSha256:'f'.repeat(64)})],
 ['changed lineage',f=>f.input.readState=()=>({...f.input.prepared.preparation.state,lineage:'99999999-9999-9999-9999-999999999999'})],
 ['wrong release',f=>f.input.sourceSha='f'.repeat(40)],
 ['wrong CAS receipt',f=>f.input.casResult={...f.input.casResult,status:'WRONG'}],
 ['changed serial',f=>f.input.readState=()=>({...f.input.prepared.preparation.state,serial:999})],
 ['changed alias revision',f=>f.input.readAlias=()=>({...f.input.casResult.alias,RevisionId:'different'})],
 ['cross-round attempt',f=>f.steps.get('closure:attempt:1').prepared='f'.repeat(64)],
 ['missing authorization',f=>f.steps.delete('closure:authorized:1')],
 ['native intent',f=>f.input.readReceipt=()=>({status:'STATE_REFRESH_INTENT'})],
 ['uncertain native execution',f=>f.input.readReceipt=({status})=>{if(status==='STATE_REFRESH_UNKNOWN')return {};throw Object.assign(new Error('Absent'),{code:'RECEIPT_ABSENT'});}],
 ['native result',f=>f.input.readReceipt=({status})=>{if(status==='RECONCILED_PENDING_RELEASE_CAS')return {};throw Object.assign(new Error('Absent'),{code:'RECEIPT_ABSENT'});}],
 ['receipt access denial',f=>f.input.readReceipt=()=>{throw Object.assign(new Error('Denied'),{code:'AccessDenied'});}],
 ['completed closure',f=>f.steps.set('closure:result',{})],
 ])test(`pre-native abort rejects ${name}`,async()=>{const f=await fixture();change(f);await assert.rejects(()=>authenticatePreNativeClosureAbort(f.input));});
