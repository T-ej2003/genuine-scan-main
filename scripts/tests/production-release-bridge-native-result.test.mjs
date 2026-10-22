import test from 'node:test';
import assert from 'node:assert/strict';
import {buildOverlapReadinessEvidence} from '../aws/produce-production-overlap-readiness-evidence.mjs';
import {projectBridgeNativeResult,assertBridgeNativeResult} from '../aws/production-release-bridge-native-result.mjs';
import {READY_FOR_OVERLAP_DEPLOYMENT_STAGES} from '../aws/production-overlap-readiness-contract.mjs';
import {readBridgeNativeCandidate,verifyHostedBridgeNativeStages} from '../aws/production-release-bridge-native-verifier.mjs';
import {brokerDigest} from '../aws/stage-b-staged-broker-contract.mjs';
import {createHash} from 'node:crypto';

const sourceSha='a'.repeat(40),rotationId='rotation-20260913011819-98b062c4',digest='b'.repeat(64);
const taskDefinitionArn='arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:1';
const readiness=buildOverlapReadinessEvidence({sourceSha,rotationId,rotationStateSha256:digest,
 stages:Object.fromEntries(READY_FOR_OVERLAP_DEPLOYMENT_STAGES.map(name=>[name,{valid:true,evidenceRef:name,evidenceSha256:digest,
  identityBindings:{sourceSha,...(name==='imageAuthorization'||name==='overlapTaskDefinition'?{imageReleaseSha:sourceSha}:{}),
   ...(name==='overlapTaskDefinition'?{taskDefinitionArn,imageDigest:`sha256:${digest}`}:{})}}]))});
const result={readyForOverlapDeployment:true,sourceSha,rotationId,rotationStateSha256:digest,rotationFixtureSha256:digest,
 readinessSha256:digest,taskDefinitionArn,readiness,results:{
  verifierIdentity:{valid:true,roleArn:'arn:aws:iam::368992683803:role/mscqr-production-ecs-exec-verifier',
   callerArn:'arn:aws:sts::368992683803:assumed-role/mscqr-production-ecs-exec-verifier/session',
   expiration:'2026-10-22T11:00:00Z',evidenceSha256:digest},
  artifactSigning:{activeKeyVersion:'v1',publicRegistryCount:1,bindings:Object.fromEntries([
   'ARTIFACT_SIGN_PRIVATE_KEY_CURRENT','ARTIFACT_SIGN_PUBLIC_KEY_CURRENT',
   'ARTIFACT_SIGN_ACTIVE_KEY_VERSION','ARTIFACT_SIGN_PUBLIC_KEYS_JSON'].map(name=>[
    name,`${'arn:aws:'}secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/artifact-signing/${name}`]))},
  preDeploymentInventory:{valid:true,taskArn:'arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/abc',
   taskDefinitionArn,evidenceSha256:digest,inventory:{count:1}},rotationPrepare:{rotationStateSha256:digest},
  rotationInfrastructure:{converged:true,applyCount:0},overlapTaskDefinition:{taskDefinitionArn,mutationCount:0},readiness}};

test('bridge handoff projects native references without verifier session or secret values',()=>{
 Object.defineProperty(result.results.verifierIdentity,'session',{value:{AccessKeyId:'PRIVATE_ACCESS_KEY_VALUE'},enumerable:false});
 const projected=projectBridgeNativeResult(result,{sourceSha,rotationId,runtimeConfigSha256:digest});
 assertBridgeNativeResult(projected,{sourceSha,rotationId,taskDefinitionArn});
 assert.equal(JSON.stringify(projected).includes('PRIVATE_ACCESS_KEY_VALUE'),false);
 assert.throws(()=>assertBridgeNativeResult({...projected,privateKey:'PRIVATE'}),/unexpected or sensitive/);
 assert.throws(()=>assertBridgeNativeResult({...projected,sourceSha:'c'.repeat(40)}),/strictly equal/);
 assert.throws(()=>projectBridgeNativeResult({...result,results:{...result.results,verifierIdentity:{...result.results.verifierIdentity,
  callerArn:'arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/session'}}},
  {sourceSha,rotationId,runtimeConfigSha256:digest}),/input did not match/);
});

test('hosted native verifier rejects forged or missing candidate and unsigned completion',async()=>{
 const bytes=Buffer.from(JSON.stringify(readiness));
 const readinessBlob={bytesBase64:bytes.toString('base64'),sha256:createHash('sha256').update(bytes).digest('hex')};
 const native=projectBridgeNativeResult({...result,readinessSha256:readinessBlob.sha256},
  {sourceSha,rotationId,runtimeConfigSha256:digest});
 const adoption={payload:{rotationId}};
 const request={requestSha256:'c'.repeat(64)};
 const candidate={operationId:'d'.repeat(64),requestSha256:request.requestSha256,
  cutoverRequestSha256:request.requestSha256,releaseId:'e'.repeat(64),sourceSha,rotationId,
  nativeResultArtifactSha256:brokerDigest(native),readinessArtifactSha256:brokerDigest(readinessBlob),
  readinessSha256:readinessBlob.sha256,adoptionEvidenceArtifactSha256:brokerDigest(adoption),
  rotationStateSha256:digest,taskDefinitionArn};
 const artifacts=new Map([[candidate.nativeResultArtifactSha256,native],
  [candidate.readinessArtifactSha256,readinessBlob],[candidate.adoptionEvidenceArtifactSha256,adoption]]);
 let stored=candidate;
 const store={readOperation:async()=>stored,getArtifact:async sha=>artifacts.get(sha)};
 const read=()=>readBridgeNativeCandidate({store,operationId:candidate.operationId});
 assert.deepEqual((await read()).candidate,candidate);
 const verify=()=>verifyHostedBridgeNativeStages({store,run:()=>{throw Error('unexpected AWS call');},
  observeApproval:async()=>{},readAudit:async()=>({proofSha256:'f'.repeat(64)}),
  evidence:{request,completion:{...candidate,nativeProofSha256:'f'.repeat(64)},readiness,adoption}});
 await assert.rejects(verify());
 stored=null;
 await assert.rejects(verify(),/Native cutover candidate is absent/);
 stored={...candidate,sourceSha:'f'.repeat(40)};
 await assert.rejects(read(),/Native result sourceSha differs/);
 stored={...candidate,nativeResultArtifactSha256:'0'.repeat(64)};
 await assert.rejects(read());
});
