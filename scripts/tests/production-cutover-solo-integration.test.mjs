import assert from 'node:assert/strict';
import test from 'node:test';
import JSZip from 'jszip';
import {generateKeyPairSync,sign,constants} from 'node:crypto';
import {conditionalFixture,memoryConditionalStore,h} from './fixtures/conditional-cutover.mjs';
import {conditionalIssuanceRequest} from '../aws/production-cutover-conditional-issuance.mjs';
import {authenticateConditionalBundle,conditionalOperationId,CONDITIONAL_PRINCIPALS} from '../aws/production-cutover-conditional-authorization.mjs';
import {createConditionalConsumptionJournal} from '../aws/production-cutover-consumption-journal.mjs';
import {produceConditionalOverlapAuthorization,authenticateConditionalWorkflowArtifact} from '../aws/production-cutover-conditional-workflow.mjs';
import {SOLO_OPERATOR_POLICY,SOLO_OPERATOR_CONTROLLED_V1,soloPolicyHash} from '../aws/production-cutover-human-policy.mjs';
import {authenticateSoloIssuerTrust,recordSoloAuthorityState} from '../aws/production-cutover-solo-authority.mjs';
import {canonicalJson} from '../aws/production-green-stage-b-contract.mjs';

const signed=(payload,trust,privateKey)=>({payload,payloadSha256:h(payload),issuerKeyArn:trust.keyArn,
  signatureBase64:sign('sha256',Buffer.from(canonicalJson(payload)),{key:privateKey,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32}).toString('base64')});
const issuer=async(id,keyArn,pair,d,now)=>{
  const policy={Version:'2012-10-17',Statement:[]};
  const trust={designated:true,issuerId:id,keyArn,publicKeyDerBase64:pair.publicKey.export({format:'der',type:'spki'}).toString('base64'),policySha256:h(policy)};
  const read=args=>args[0]==='sts'?{Account:'368992683803',Arn:'arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test'}:args[1]==='get-public-key'?{KeyId:keyArn,PublicKey:trust.publicKeyDerBase64}:{Policy:JSON.stringify(policy)};
  return authenticateSoloIssuerTrust({trust,read,d,now});
};

async function soloBundle(f){
  const policy={...SOLO_OPERATOR_POLICY,enabled:true,githubUserId:1,githubLogin:'executor',toolingSourceSha:f.d.toolingSourceSha,
    historicalReleaseSha:f.d.historicalReleaseSha,backendImageDigest:f.d.backendImageDigest,notAfter:f.d.notAfter};
  const approvalPair=generateKeyPairSync('rsa',{modulusLength:2048}),statePair=generateKeyPairSync('rsa',{modulusLength:2048});
  const approvalTrust=await issuer('fixture-human-mfa-issuer','arn:aws:kms:eu-west-2:368992683803:key/22222222-2222-2222-2222-222222222222',approvalPair,f.d,f.now());
  const stateTrust=await issuer('fixture-emergency-issuer','arn:aws:kms:eu-west-2:368992683803:key/33333333-3333-3333-3333-333333333333',statePair,f.d,f.now());
  const session='arn:aws:sts::368992683803:assumed-role/mscqr-production-rls-independent-checker/test';
  const envelopes={...f.envelopes};
  for(const phase of ['INVENTORY_ADOPTION','ROTATION_SUCCESSOR']){
    const authorizationId=h({phase,kind:'human-approval'});
    const payload={...f.envelopes[phase].payload,kind:'CUTOVER_CONDITIONAL_AUTHORIZATION_V2',schemaVersion:2,
      authorizationPolicyVersion:SOLO_OPERATOR_CONTROLLED_V1,policyManifestSha256:soloPolicyHash(policy),approvalProvenance:authorizationId,
      humanAuthorization:{operatorAwsUserArn:policy.checkerUserArn,operatorGithubUserId:1,operatorSessionArn:session,selfAuthorized:true}};
    const request=conditionalIssuanceRequest(f.d,payload,policy);
    const human={kind:'CUTOVER_SOLO_PHASE_APPROVAL_V1',schemaVersion:1,policyVersion:SOLO_OPERATOR_CONTROLLED_V1,
      policyManifestSha256:soloPolicyHash(policy),issuerId:approvalTrust.issuerId,authorizationId,phase,
      derivationSha256:h(f.d),requestSha256:h(request),operatorGithubUserId:1,operatorAwsUserArn:policy.checkerUserArn,
      operatorSessionArn:session,mfaAttestationSha256:'b'.repeat(64),issuedAt:new Date(f.now()-1000).toISOString(),expiresAt:new Date(f.now()+600000).toISOString()};
    envelopes[phase]={payload,payloadSha256:h(payload),signingKeyArn:f.d.keys.checker.keyArn,signingAlgorithm:'RSASSA_PSS_SHA_256',
      signatureBase64:f.signBytes('checker',Buffer.from(canonicalJson(payload))),approvalEvidence:signed(human,approvalTrust,approvalPair.privateKey)};
  }
  f.environmentConfig.protection_rules[0].prevent_self_review=false;
  f.environmentConfig.protection_rules[0].reviewers=[{type:'User',reviewer:{id:1,login:'executor'}}];
  const releaseId=conditionalOperationId(f.d.rotationId,f.d.predecessor.stateSha256),reference=h(f.d);
  const env={GITHUB_ACTIONS:'true',GITHUB_SHA:f.d.toolingSourceSha,GITHUB_REPOSITORY:f.d.repository,GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_WORKFLOW_REF:f.envelopes.PREPARE_OVERLAP.workflowArtifactProvenance.workflowRef,GITHUB_RUN_ATTEMPT:'1',GITHUB_RUN_ID:'101',GITHUB_ACTOR:'executor',GH_TOKEN:'fixture',RELEASE_ID:releaseId,RELEASE_PHASE:'prepare-overlap-conditional',RELEASE_PREPARATION_REFERENCE:reference,RELEASE_AUTHORIZATION_ROUND:'0',RELEASE_AUTHORIZATION_POLICY_VERSION:SOLO_OPERATOR_CONTROLLED_V1};
  const fetchImpl=async(url,init)=>url.endsWith('/approvals')?{ok:true,json:async()=>[{state:'approved',environments:[{id:101,name:'production'}],user:{id:1,login:'executor'}}]}:f.fetchImpl(url,init);
  envelopes.PREPARE_OVERLAP=await produceConditionalOverlapAuthorization({d:f.d,sourceSha:f.d.historicalReleaseSha,ticketId:f.d.ticketId,releaseId,preparationReference:reference,authorizationRound:0,authorizationPolicyVersion:SOLO_OPERATOR_CONTROLLED_V1,policy,env,fetchImpl,now:f.now()});
  const zip=await new JSZip().file('authorization.json',JSON.stringify(envelopes.PREPARE_OVERLAP)).generateAsync({type:'nodebuffer'});
  const artifact={...f.artifact,size_in_bytes:zip.length,digest:`sha256:${h(zip)}`};
  const consumeFetch=async(url,init)=>url.endsWith('/actions/artifacts/102')?{ok:true,json:async()=>artifact}:url.endsWith('/zip')?{ok:true,arrayBuffer:async()=>zip}:fetchImpl(url,init);
  const workflowArtifact=await authenticateConditionalWorkflowArtifact({d:f.d,runId:'101',artifactId:'102',token:'fixture',policy,fetchImpl:consumeFetch,now:f.now()});
  const binding=authenticateConditionalBundle({d:f.d,envelopes,trust:f.trust,workflowArtifact,policy,approvalTrust,now:f.now()});
  const statePayload={kind:'CUTOVER_SOLO_AUTHORITY_STATE_V1',schemaVersion:1,policyVersion:SOLO_OPERATOR_CONTROLLED_V1,
    policyManifestSha256:soloPolicyHash(policy),issuerId:stateTrust.issuerId,operatorGithubUserId:1,operatorAwsUserArn:policy.checkerUserArn,
    toolingSourceSha:f.d.toolingSourceSha,rotationId:f.d.rotationId,state:'ACTIVE',reason:'fixture authorization',issuedAt:new Date(f.now()-1000).toISOString(),expiresAt:f.d.notAfter};
  return {policy,approvalTrust,stateTrust,binding,active:signed(statePayload,stateTrust,statePair.privateKey),
    suspended:signed({...statePayload,state:'SUSPENDED',reason:'emergency stop'},stateTrust,statePair.privateKey)};
}

test('real bundle, execution claim and native-effect boundary require live solo authority',async t=>{
  const f=await conditionalFixture();t.after(f.cleanup);const s=await soloBundle(f);
  assert.equal(s.binding.policyVersion,SOLO_OPERATOR_CONTROLLED_V1);
  const store=memoryConditionalStore();
  const journal=createConditionalConsumptionJournal({store,rotationId:f.d.rotationId,predecessorStateSha256:f.d.predecessor.stateSha256,
    operatorControl:{d:f.d,policy:s.policy,trust:s.stateTrust,now:f.now}});
  await assert.rejects(journal.claimExecution(s.binding),/active solo authority state required/);
  await recordSoloAuthorityState({store,envelope:s.active,trust:s.stateTrust,policy:s.policy,d:f.d,now:f.now()});
  const execution=await journal.claimExecution(s.binding);
  const phaseBinding={...s.binding,phase:'ROOT_DROP',runtimeFileSha256:null,dependencyHashes:{},dependencyReceipts:{}};
  const token=await journal.claimPhase(execution,'ROOT_DROP',phaseBinding);
  await recordSoloAuthorityState({store,envelope:s.suspended,trust:s.stateTrust,policy:s.policy,d:f.d,now:f.now()});
  let invoked=0;
  const signer=journal.createNativeSigner(token,{d:f.d,phase:'ROOT_DROP',trust:f.trust,materialization:undefined,outputs:{},beforeDispatch:async()=>{},principal:CONDITIONAL_PRINCIPALS.root,now:f.now,invokeNative:async invoke=>{invoked++;return invoke();}});
  await assert.rejects(f.adapters.root({nativeSign:signer.sign}),/suspended/);
  assert.equal(invoked,0);
});

test('suspension racing a native claim burns the attempt before any KMS call',async t=>{
  const f=await conditionalFixture();t.after(f.cleanup);const s=await soloBundle(f);
  const base=memoryConditionalStore();
  const active=await recordSoloAuthorityState({store:base,envelope:s.active,trust:s.stateTrust,policy:s.policy,d:f.d,now:f.now()});
  let suspended=false,invoked=0;
  const store={...base,claimOperation:(id,name,value)=>{
    const result=base.claimOperation(id,name,value);
    if(name.endsWith('DISPATCH:KMS_SIGN')&&!suspended){base.claimOperation(active.key,'SOLO:SUSPENDED',s.suspended);suspended=true;}
    return result;
  }};
  const journal=createConditionalConsumptionJournal({store,rotationId:f.d.rotationId,predecessorStateSha256:f.d.predecessor.stateSha256,
    operatorControl:{d:f.d,policy:s.policy,trust:s.stateTrust,now:f.now}});
  const execution=await journal.claimExecution(s.binding);
  const token=await journal.claimPhase(execution,'ROOT_DROP',{...s.binding,phase:'ROOT_DROP',runtimeFileSha256:null,dependencyHashes:{},dependencyReceipts:{}});
  const signer=journal.createNativeSigner(token,{d:f.d,phase:'ROOT_DROP',trust:f.trust,materialization:undefined,outputs:{},beforeDispatch:async()=>{},principal:CONDITIONAL_PRINCIPALS.root,now:f.now,invokeNative:async invoke=>{invoked++;return invoke();}});
  await assert.rejects(f.adapters.root({nativeSign:signer.sign}),/outcome unknown/);
  assert.equal(invoked,0);assert.equal(suspended,true);
  assert.equal(await journal.status('ROOT_DROP','KMS_SIGN'),'OUTCOME_UNKNOWN');
});
