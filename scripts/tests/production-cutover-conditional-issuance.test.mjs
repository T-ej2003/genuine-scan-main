import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import test from 'node:test';
import JSZip from 'jszip';
import {conditionalFixture,memoryConditionalStore} from './fixtures/conditional-cutover.mjs';
import {conditionalIssuanceRequest,issueConditionalAuthorization,runConditionalIssuanceCli} from '../aws/production-cutover-conditional-issuance.mjs';
import {conditionalHash,verifyConditionalKmsEnvelope,conditionalOperationId} from '../aws/production-cutover-conditional-authorization.mjs';
import {produceConditionalOverlapAuthorization,authenticateConditionalWorkflowArtifact} from '../aws/production-cutover-conditional-workflow.mjs';
import {canonicalJson,STAGE_B} from '../aws/production-green-stage-b-contract.mjs';

const issuer=(f,phase)=>{
  const kind=phase==='ROOT_DROP'?'root':'checker',key=f.d.keys[kind];
  const request=conditionalIssuanceRequest(f.d,f.envelopes[phase].payload);
  const read=args=>args[0]==='sts'?{Account:STAGE_B.account,Arn:kind==='root'?'arn:aws:iam::368992683803:root':'arn:aws:sts::368992683803:assumed-role/mscqr-production-rls-independent-checker/test'}:args[1]==='get-public-key'?{KeyId:key.keyArn,PublicKey:f.trust[kind].publicKeyDerBase64}:args[1]==='get-key-policy'?{Policy:JSON.stringify(kind==='root'?f.rootPolicy:f.policy)}:{KeyMetadata:{Arn:key.keyArn,KeyId:key.keyArn.split('/').at(-1),Description:'Root-only MSCQR production cutover evidence signing key',KeyUsage:'SIGN_VERIFY',KeySpec:'RSA_3072',KeyState:'Enabled',Enabled:true,KeyManager:'CUSTOMER',Origin:'AWS_KMS',MultiRegion:false}};
  return {d:f.d,request,approvedRequestSha256:conditionalHash(request),store:memoryConditionalStore(),read,now:f.now(),sign:async native=>{assert.equal(native.keyId,key.keyArn);return f.signResponse(kind,Buffer.from(canonicalJson(request.payload)));}};
};
test('real phase issuance uses confirmed claims, separate journals and actual downstream signature verification',async t=>{
  const f=await conditionalFixture();t.after(f.cleanup);
  for(const phase of ['ROOT_DROP','INVENTORY_ADOPTION','ROTATION_SUCCESSOR']) {
    const input=issuer(f,phase),output=await issueConditionalAuthorization(input);
    verifyConditionalKmsEnvelope(output,{d:f.d,phase,trust:f.trust,now:f.now()});
    assert.equal([...input.store.map.keys()].filter(key=>key.endsWith('ISSUANCE:DISPATCH')).length,1);
    assert.equal([...input.store.map.keys()].filter(key=>key.endsWith('ISSUANCE:RESULT')).length,1);
    assert.equal([...input.store.map.keys()].filter(key=>key.endsWith('ISSUANCE:COMPLETED')).length,1);
    await assert.rejects(issueConditionalAuthorization(input),/claim conflict/);
  }
});
test('issuance rejects wrong authority, approved bytes, phase, policy and lost claim before Sign',async t=>{
  const f=await conditionalFixture();t.after(f.cleanup);
  for(const attack of ['authority','request','phase','policy','claim']) {
    const input=issuer(f,'INVENTORY_ADOPTION');let calls=0;input.sign=async()=>{calls++;throw Error('must not sign');};
    const read=input.read;
    if(attack==='authority')input.read=args=>args[0]==='sts'?{Account:STAGE_B.account,Arn:'arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test'}:read(args);
    if(attack==='request')input.approvedRequestSha256='0'.repeat(64);
    if(attack==='phase')input.request.payload.phase='ROOT_DROP';
    if(attack==='policy')input.read=args=>args[1]==='get-key-policy'?{Policy:'{}'}:read(args);
    if(attack==='claim'){const claim=input.store.claimOperation;input.store.claimOperation=(...args)=>{claim(...args);throw Error('lost claim');};}
    await assert.rejects(issueConditionalAuthorization(input));assert.equal(calls,0,attack);
  }
});
test('lost issuance response remains unknown and cannot sign again, independently of the later bundle',async t=>{
  const f=await conditionalFixture();t.after(f.cleanup);const input=issuer(f,'ROOT_DROP');let calls=0;
  input.sign=async()=>{calls++;throw Error('signed but lost');};
  await assert.rejects(issueConditionalAuthorization(input),/UNKNOWN/);await assert.rejects(issueConditionalAuthorization(input));assert.equal(calls,1);
  assert.equal([...input.store.map.keys()].some(key=>key.endsWith('ISSUANCE:UNKNOWN')),true);
  assert.equal([...input.store.map.keys()].some(key=>key.endsWith('ISSUANCE:COMPLETED')),false);
  await assert.rejects(runConditionalIssuanceCli([]),/disabled/);
});
test('actual conditional workflow producer round-trips through protected artifact consumer without broker operations',async t=>{
  const f=await conditionalFixture();t.after(f.cleanup);
  const releaseId=conditionalOperationId(f.d.rotationId,f.d.predecessor.stateSha256),reference=conditionalHash(f.d);
  const env={GITHUB_ACTIONS:'true',GITHUB_SHA:f.d.toolingSourceSha,GITHUB_REPOSITORY:f.d.repository,GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_WORKFLOW_REF:f.envelopes.PREPARE_OVERLAP.workflowArtifactProvenance.workflowRef,GITHUB_RUN_ATTEMPT:'1',GITHUB_RUN_ID:'101',GITHUB_ACTOR:'executor',GH_TOKEN:'fixture',RELEASE_ID:releaseId,RELEASE_PHASE:'prepare-overlap-conditional',RELEASE_PREPARATION_REFERENCE:reference,RELEASE_AUTHORIZATION_ROUND:'0'};
  const options={d:f.d,sourceSha:f.d.historicalReleaseSha,ticketId:f.d.ticketId,releaseId,preparationReference:reference,authorizationRound:0,env,fetchImpl:f.fetchImpl,now:f.now()};
  const envelope=await produceConditionalOverlapAuthorization(options);
  const bytes=await new JSZip().file('authorization.json',`${JSON.stringify(envelope)}\n`).generateAsync({type:'nodebuffer'});
  const artifact={...f.artifact,size_in_bytes:bytes.length,digest:`sha256:${conditionalHash(bytes)}`};
  const fetchImpl=async(url,init)=>url.endsWith('/actions/artifacts/102')?{ok:true,json:async()=>artifact}:url.endsWith('/zip')?{ok:true,arrayBuffer:async()=>bytes}:f.fetchImpl(url,init);
  const authenticated=await authenticateConditionalWorkflowArtifact({d:f.d,runId:'101',artifactId:'102',token:'fixture',fetchImpl,now:f.now()});
  assert.deepEqual(authenticated.envelope,envelope);
  for(const patch of [{ticketId:'CHG-WRONG-1'},{sourceSha:'0'.repeat(40)},{env:{...env,GITHUB_RUN_ATTEMPT:'2'}},{env:{...env,GITHUB_ACTOR:'reviewer'}},{env:{...env,GITHUB_SHA:'0'.repeat(40)}}])await assert.rejects(produceConditionalOverlapAuthorization({...options,...patch}));
});

test('issuance checks private outputs and live expiry before native signing',async t=>{
 const f=await conditionalFixture();t.after(f.cleanup);let calls=0;
 const input=issuer(f,'ROOT_DROP');input.sign=async()=>{calls++;throw Error('must not sign');};
 const directory=path.join(f.directory,'unsafe');fs.mkdirSync(directory,{mode:0o755});input.output=path.join(directory,'envelope.json');
 await assert.rejects(issueConditionalAuthorization(input));assert.equal(calls,0);
 delete input.output;let time=f.now();input.now=()=>time;
 const claim=input.store.claimOperation;input.store.claimOperation=(...args)=>{const result=claim(...args);time=Date.parse(f.d.notAfter);return result;};
 await assert.rejects(issueConditionalAuthorization(input),/window/);assert.equal(calls,0);
});

test('advance issuance cannot authorize early execution or extend the absolute execution window',async t=>{
 const f=await conditionalFixture();t.after(f.cleanup);const input=issuer(f,'ROOT_DROP');input.now=()=>f.now()-60_000;
 const envelope=await issueConditionalAuthorization(input);
 assert.equal(envelope.payload.notBefore,f.d.notBefore);assert.equal(envelope.payload.notAfter,f.d.notAfter);
 assert.throws(()=>verifyConditionalKmsEnvelope(envelope,{d:f.d,phase:'ROOT_DROP',trust:f.trust,now:input.now()}),/execution window/);
 const tooEarly=issuer(f,'ROOT_DROP');tooEarly.now=()=>Date.parse(f.d.notBefore)-1_800_001;
 await assert.rejects(issueConditionalAuthorization(tooEarly),/window/);
});
