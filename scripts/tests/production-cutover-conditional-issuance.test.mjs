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
import {generateKeyPairSync,sign,constants} from 'node:crypto';
import {SOLO_OPERATOR_POLICY,SOLO_OPERATOR_CONTROLLED_V1,soloPolicyHash} from '../aws/production-cutover-human-policy.mjs';
import {authenticateSoloPhaseApproval,assertSoloAuthorityActive,recordSoloAuthorityState,issueSoloPhaseApproval} from '../aws/production-cutover-solo-authority.mjs';

const issuer=(f,phase)=>{
  const kind=phase==='ROOT_DROP'?'root':'checker',key=f.d.keys[kind];
  const request=conditionalIssuanceRequest(f.d,f.envelopes[phase].payload);
  const read=args=>args[0]==='sts'?{Account:STAGE_B.account,Arn:kind==='root'?'arn:aws:iam::368992683803:root':'arn:aws:sts::368992683803:assumed-role/mscqr-production-rls-independent-checker/test'}:args[1]==='get-public-key'?{KeyId:key.keyArn,PublicKey:f.trust[kind].publicKeyDerBase64}:args[1]==='get-key-policy'?{Policy:JSON.stringify(kind==='root'?f.rootPolicy:f.policy)}:{KeyMetadata:{Arn:key.keyArn,KeyId:key.keyArn.split('/').at(-1),Description:'Root-only MSCQR production cutover evidence signing key',KeyUsage:'SIGN_VERIFY',KeySpec:'RSA_3072',KeyState:'Enabled',Enabled:true,KeyManager:'CUSTOMER',Origin:'AWS_KMS',MultiRegion:false}};
  const policyRead=kind==='root'?undefined:args=>args[0]==='sts'?{Account:STAGE_B.account,Arn:'arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test'}:read(args);
  return {d:f.d,request,approvedRequestSha256:conditionalHash(request),store:memoryConditionalStore(),read,policyRead,now:f.now(),sign:async native=>{assert.equal(native.keyId,key.keyArn);return f.signResponse(kind,Buffer.from(canonicalJson(request.payload)));}};
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
    if(attack==='policy')input.policyRead=args=>args[1]==='get-key-policy'?{Policy:'{}'}:issuer(f,'INVENTORY_ADOPTION').policyRead(args);
    if(attack==='claim'){const claim=input.store.claimOperation;input.store.claimOperation=(...args)=>{claim(...args);throw Error('lost claim');};}
    await assert.rejects(issueConditionalAuthorization(input));assert.equal(calls,0,attack);
  }
});
test('checker metadata cannot be substituted with a signing or unrelated reader',async t=>{
  const f=await conditionalFixture();t.after(f.cleanup);
  for(const attack of ['missing','checker-reader','wrong-account','changed-after-claim']){
    const input=issuer(f,'INVENTORY_ADOPTION');let signed=0;input.sign=async()=>{signed++;throw Error('must not sign');};
    const original=input.policyRead;let policyReads=0;
    if(attack==='missing')delete input.policyRead;
    else input.policyRead=args=>{
      if(args[0]==='sts')return {Account:attack==='wrong-account'?'000000000000':STAGE_B.account,Arn:attack==='checker-reader'?'arn:aws:sts::368992683803:assumed-role/mscqr-production-rls-independent-checker/test':'arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test'};
      if(args[1]==='get-key-policy'&&attack==='changed-after-claim'&&++policyReads===2)return {Policy:'{}'};
      return original(args);
    };
    await assert.rejects(issueConditionalAuthorization(input));assert.equal(signed,0,attack);
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
  f.environmentConfig.protection_rules[0].prevent_self_review=false;
  f.environmentConfig.protection_rules[0].reviewers=[{type:'User',reviewer:{id:1,login:'executor'}}];
  const selfReviewFetch=async(url,init)=>url.endsWith('/approvals')?{ok:true,json:async()=>[{state:'approved',environments:[{id:101,name:'production'}],user:{id:1,login:'executor'}}]}:f.fetchImpl(url,init);
  await assert.rejects(produceConditionalOverlapAuthorization({...options,fetchImpl:selfReviewFetch}),/self-reviewed/);
});
test('mocked active solo policy round-trips the actual protected overlap producer and consumer',async t=>{
  const f=await conditionalFixture();t.after(f.cleanup);
  const policy={...SOLO_OPERATOR_POLICY,enabled:true,githubUserId:1,githubLogin:'executor',toolingSourceSha:f.d.toolingSourceSha,historicalReleaseSha:f.d.historicalReleaseSha,backendImageDigest:f.d.backendImageDigest,notAfter:f.d.notAfter};
  const releaseId=conditionalOperationId(f.d.rotationId,f.d.predecessor.stateSha256),reference=conditionalHash(f.d);
  f.environmentConfig.protection_rules[0].prevent_self_review=false;
  f.environmentConfig.protection_rules[0].reviewers=[{type:'User',reviewer:{id:1,login:'executor'}}];
  const env={GITHUB_ACTIONS:'true',GITHUB_SHA:f.d.toolingSourceSha,GITHUB_REPOSITORY:f.d.repository,GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_WORKFLOW_REF:f.envelopes.PREPARE_OVERLAP.workflowArtifactProvenance.workflowRef,GITHUB_RUN_ATTEMPT:'1',GITHUB_RUN_ID:'101',GITHUB_ACTOR:'executor',GH_TOKEN:'fixture',RELEASE_ID:releaseId,RELEASE_PHASE:'prepare-overlap-conditional',RELEASE_PREPARATION_REFERENCE:reference,RELEASE_AUTHORIZATION_ROUND:'0',RELEASE_AUTHORIZATION_POLICY_VERSION:SOLO_OPERATOR_CONTROLLED_V1};
  const fetchImpl=async(url,init)=>url.endsWith('/approvals')?{ok:true,json:async()=>[{state:'approved',environments:[{id:101,name:'production'}],user:{id:1,login:'executor'}}]}:f.fetchImpl(url,init);
  const envelope=await produceConditionalOverlapAuthorization({d:f.d,sourceSha:f.d.historicalReleaseSha,ticketId:f.d.ticketId,releaseId,preparationReference:reference,authorizationRound:0,authorizationPolicyVersion:SOLO_OPERATOR_CONTROLLED_V1,policy,env,fetchImpl,now:f.now()});
  const zip=await new JSZip().file('authorization.json',JSON.stringify(envelope)).generateAsync({type:'nodebuffer'});
  const artifact={...f.artifact,size_in_bytes:zip.length,digest:`sha256:${conditionalHash(zip)}`};
  const consumeFetch=async(url,init)=>url.endsWith('/actions/artifacts/102')?{ok:true,json:async()=>artifact}:url.endsWith('/zip')?{ok:true,arrayBuffer:async()=>zip}:fetchImpl(url,init);
  const result=await authenticateConditionalWorkflowArtifact({d:f.d,runId:'101',artifactId:'102',token:'fixture',policy,fetchImpl:consumeFetch,now:f.now()});
  assert.equal(result.policyVersion,SOLO_OPERATOR_CONTROLLED_V1);
  assert.deepEqual(result.envelope,envelope);
  await assert.rejects(authenticateConditionalWorkflowArtifact({d:f.d,runId:'101',artifactId:'102',token:'fixture',fetchImpl:consumeFetch,now:f.now()}),/disabled/);
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

test('mocked designated issuer binds solo approval to exact adoption request and live authority state',async t=>{
 const f=await conditionalFixture();t.after(f.cleanup);
 const pair=generateKeyPairSync('rsa',{modulusLength:2048});
 const approvalTrust={designated:true,issuerId:'fixture-human-mfa-issuer',keyArn:'arn:aws:kms:eu-west-2:368992683803:key/22222222-2222-2222-2222-222222222222',publicKeyDerBase64:pair.publicKey.export({format:'der',type:'spki'}).toString('base64'),policySha256:'a'.repeat(64)};
 const suspensionTrust={...approvalTrust,issuerId:'fixture-emergency-issuer',keyArn:'arn:aws:kms:eu-west-2:368992683803:key/33333333-3333-3333-3333-333333333333'};
 const signPayload=bytes=>sign('sha256',bytes,{key:pair.privateKey,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32}).toString('base64');
 const policy={...SOLO_OPERATOR_POLICY,enabled:true,githubUserId:1,githubLogin:'executor',toolingSourceSha:f.d.toolingSourceSha,historicalReleaseSha:f.d.historicalReleaseSha,backendImageDigest:f.d.backendImageDigest,notAfter:f.d.notAfter};
 const approvalId=conditionalHash({kind:'FIXTURE_SOLO_APPROVAL',phase:'INVENTORY_ADOPTION'});
 const sessionArn='arn:aws:sts::368992683803:assumed-role/mscqr-production-rls-independent-checker/test';
 const payload={...f.envelopes.INVENTORY_ADOPTION.payload,kind:'CUTOVER_CONDITIONAL_AUTHORIZATION_V2',schemaVersion:2,approvalProvenance:approvalId,
   authorizationPolicyVersion:SOLO_OPERATOR_CONTROLLED_V1,policyManifestSha256:soloPolicyHash(policy),
   humanAuthorization:{operatorAwsUserArn:policy.checkerUserArn,operatorGithubUserId:1,operatorSessionArn:sessionArn,selfAuthorized:true}};
 const request=conditionalIssuanceRequest(f.d,payload,policy);
 const approvalPayload={kind:'CUTOVER_SOLO_PHASE_APPROVAL_V1',schemaVersion:1,policyVersion:SOLO_OPERATOR_CONTROLLED_V1,
   policyManifestSha256:soloPolicyHash(policy),issuerId:approvalTrust.issuerId,authorizationId:approvalId,phase:'INVENTORY_ADOPTION',
   derivationSha256:conditionalHash(f.d),requestSha256:conditionalHash(request),operatorGithubUserId:1,operatorAwsUserArn:policy.checkerUserArn,
   operatorSessionArn:sessionArn,mfaAttestationSha256:'b'.repeat(64),issuedAt:new Date(f.now()-1000).toISOString(),expiresAt:new Date(f.now()+600000).toISOString()};
 const alteredApproval=p=>({payload:p,payloadSha256:conditionalHash(p),issuerKeyArn:approvalTrust.keyArn,signatureBase64:signPayload(Buffer.from(canonicalJson(p)))});
 const approval=alteredApproval(approvalPayload);
 await assert.rejects(issueSoloPhaseApproval({payload:approvalPayload,trust:approvalTrust,store:memoryConditionalStore(),sign:signPayload}),/not designated/);
 for(const mutate of [p=>{delete p.mfaAttestationSha256;},p=>{p.operatorGithubUserId=2;},p=>{p.operatorAwsUserArn='arn:aws:iam::368992683803:user/other';},p=>{p.operatorSessionArn=sessionArn.replace('/test','/other');},p=>{p.phase='ROTATION_SUCCESSOR';},p=>{p.derivationSha256='0'.repeat(64);},p=>{p.requestSha256='0'.repeat(64);},p=>{p.policyVersion='INDEPENDENT_REVIEW_V1';},p=>{p.expiresAt=new Date(f.now()-1).toISOString();}]){
   const bad=structuredClone(approvalPayload);mutate(bad);
   assert.throws(()=>authenticateSoloPhaseApproval({envelope:alteredApproval(bad),trust:approvalTrust,d:f.d,phase:'INVENTORY_ADOPTION',requestSha256:conditionalHash(request),operatorSessionArn:sessionArn,policy,now:f.now()}));
 }
 assert.throws(()=>authenticateSoloPhaseApproval({envelope:approval,trust:approvalTrust,d:f.d,phase:'ROOT_DROP',requestSha256:conditionalHash(request),operatorSessionArn:sessionArn,policy,now:f.now()}),/cannot use solo/);
 assert.throws(()=>authenticateSoloPhaseApproval({envelope:approval,trust:{...approvalTrust,keyArn:f.d.keys.checker.keyArn},d:f.d,phase:'INVENTORY_ADOPTION',requestSha256:conditionalHash(request),operatorSessionArn:sessionArn,policy,now:f.now()}),/cannot be the checker/);
 const statePayload={kind:'CUTOVER_SOLO_AUTHORITY_STATE_V1',schemaVersion:1,policyVersion:SOLO_OPERATOR_CONTROLLED_V1,
   policyManifestSha256:soloPolicyHash(policy),issuerId:suspensionTrust.issuerId,operatorGithubUserId:1,operatorAwsUserArn:policy.checkerUserArn,
   toolingSourceSha:f.d.toolingSourceSha,rotationId:f.d.rotationId,state:'ACTIVE',reason:'fixture authorization',issuedAt:new Date(f.now()-1000).toISOString(),expiresAt:f.d.notAfter};
 const state={payload:statePayload,payloadSha256:conditionalHash(statePayload),issuerKeyArn:suspensionTrust.keyArn,signatureBase64:signPayload(Buffer.from(canonicalJson(statePayload)))};
 const store=memoryConditionalStore();await recordSoloAuthorityState({store,envelope:state,trust:suspensionTrust,policy,d:f.d,now:f.now()});
 assert.equal(await assertSoloAuthorityActive({store,policy,d:f.d,trust:suspensionTrust,now:f.now()}),true);
 await assert.rejects(assertSoloAuthorityActive({store:memoryConditionalStore(),policy,d:f.d,trust:suspensionTrust,now:f.now()}),/active solo authority state required/);
 await assert.rejects(assertSoloAuthorityActive({store:{readOperation:()=>{throw Error('S3 read failed');}},policy,d:f.d,trust:suspensionTrust,now:f.now()}),/S3 read failed/);
 await assert.rejects(recordSoloAuthorityState({store:memoryConditionalStore(),envelope:state,trust:{...suspensionTrust,issuerId:'unauthorized'},policy,d:f.d,now:f.now()}));
 const read=args=>args[0]==='sts'?{Account:STAGE_B.account,Arn:sessionArn}:args[1]==='get-public-key'?{KeyId:f.d.keys.checker.keyArn,PublicKey:f.trust.checker.publicKeyDerBase64}:{Policy:JSON.stringify(f.policy)};
 const policyRead=args=>args[0]==='sts'?{Account:STAGE_B.account,Arn:'arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test'}:read(args);
 const input={d:f.d,request,approvedRequestSha256:conditionalHash(request),soloApproval:approval,soloPolicy:policy,approvalTrust,suspensionTrust,store,read,policyRead,now:f.now(),
   sign:async()=>f.signResponse('checker',Buffer.from(canonicalJson(payload)))};
 const envelope=await issueConditionalAuthorization(input);
 verifyConditionalKmsEnvelope(envelope,{d:f.d,phase:'INVENTORY_ADOPTION',trust:f.trust,policy,approvalTrust,now:f.now()});
 for(const attack of [undefined,{...approval,payload:{...approvalPayload,phase:'ROTATION_SUCCESSOR'}},{...approval,payload:{...approvalPayload,requestSha256:'0'.repeat(64)}}]){
   const altered={...input,store:memoryConditionalStore(),soloApproval:attack};
   await assert.rejects(issueConditionalAuthorization(altered));
 }
 const suspendedPayload={...statePayload,state:'SUSPENDED',reason:'emergency stop'};
 const suspended={payload:suspendedPayload,payloadSha256:conditionalHash(suspendedPayload),issuerKeyArn:suspensionTrust.keyArn,signatureBase64:signPayload(Buffer.from(canonicalJson(suspendedPayload)))};
 await recordSoloAuthorityState({store,envelope:suspended,trust:suspensionTrust,policy,d:f.d,now:f.now()});
 await assert.rejects(assertSoloAuthorityActive({store,policy,d:f.d,trust:suspensionTrust,now:f.now()}),/suspended/);
 const revokedPayload={...statePayload,state:'REVOKED',reason:'fixture revocation'};
 const revoked={payload:revokedPayload,payloadSha256:conditionalHash(revokedPayload),issuerKeyArn:suspensionTrust.keyArn,signatureBase64:signPayload(Buffer.from(canonicalJson(revokedPayload)))};
 await recordSoloAuthorityState({store,envelope:revoked,trust:suspensionTrust,policy,d:f.d,now:f.now()});
 await assert.rejects(assertSoloAuthorityActive({store,policy,d:f.d,trust:suspensionTrust,now:f.now()}),/suspended or revoked/);
 await assert.rejects(recordSoloAuthorityState({store,envelope:state,trust:suspensionTrust,policy,d:f.d,now:f.now()}),/conflict/);
 const duringRead={...store,readOperation:(id,name)=>name==='SOLO:SUSPENDED'?suspended:store.readOperation(id,name)};
 await assert.rejects(assertSoloAuthorityActive({store:duringRead,policy,d:f.d,trust:suspensionTrust,now:f.now()}),/suspended/);
 await assert.rejects(issueConditionalAuthorization({...input,store,request:{...request,payload:{...payload,authorizationId:'c'.repeat(64)}}}));
 assert.throws(()=>authenticateSoloPhaseApproval({envelope:approval,trust:undefined,d:f.d,phase:'INVENTORY_ADOPTION',requestSha256:conditionalHash(request),operatorSessionArn:sessionArn,policy,now:f.now()}),/designated/);
});
