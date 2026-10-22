import assert from 'node:assert/strict';
import {brokerDigest} from './stage-b-staged-broker-contract.mjs';
import {assertBridgeNativeResult} from './production-release-bridge-native-result.mjs';
import {readBridgeNativeAudit} from './production-release-bridge-native-audit.mjs';
import {assertBridgeNativeAttestationRequest,assertBridgeNativeAttestation,
 verifyBridgeNativeAttestationSignature} from './production-release-bridge-native-attestation.mjs';
import {authenticateBridgeEnvironmentApproval} from './verify-production-release-terminal-bridge.mjs';

export async function readBridgeNativeCandidate({store,operationId}={}){
 const candidate=await store.readOperation(operationId,'BRIDGE:CUTOVER:CANDIDATE');
 if(!candidate)return null;
 assert.equal(candidate.operationId,operationId);
 assert.equal(candidate.cutoverRequestSha256,candidate.requestSha256);
 const native=assertBridgeNativeResult(await store.getArtifact(candidate.nativeResultArtifactSha256),
  {sourceSha:candidate.sourceSha,rotationId:candidate.rotationId,
   rotationStateSha256:candidate.rotationStateSha256,rotationFixtureSha256:candidate.rotationFixtureSha256,
   readinessSha256:candidate.readinessSha256,taskDefinitionArn:candidate.taskDefinitionArn});
 assert.equal(brokerDigest(native),candidate.nativeResultArtifactSha256);
 const readinessBlob=await store.getArtifact(candidate.readinessArtifactSha256);
 assert.equal(brokerDigest(readinessBlob),candidate.readinessArtifactSha256);
 const readinessBytes=Buffer.from(readinessBlob.bytesBase64||'','base64');
 assert.equal(readinessBytes.toString('base64'),readinessBlob.bytesBase64);
 assert.equal(readinessBlob.sha256,candidate.readinessSha256);
 const readiness=JSON.parse(readinessBytes.toString('utf8'));
 const adoption=await store.getArtifact(candidate.adoptionEvidenceArtifactSha256);
 assert.equal(brokerDigest(adoption),candidate.adoptionEvidenceArtifactSha256);
 return {candidate,native,readiness,adoption};
}

export async function verifyHostedBridgeNativeStages({store,run,evidence,observeApproval,readAudit=readBridgeNativeAudit}={}){
 assert.equal(typeof run,'function');
 assert.equal(typeof observeApproval,'function');
 const {completion,request,readiness,adoption}=evidence;
 const loaded=await readBridgeNativeCandidate({store,operationId:completion.operationId});
 assert.ok(loaded,'Native cutover candidate is absent');
 const {candidate,native}=loaded;
 assert.equal(candidate.requestSha256,request.requestSha256);
 for(const key of Object.keys(candidate))if(key!=='cutoverRequestSha256')assert.deepEqual(completion[key],candidate[key],
  `Terminal completion changed native ${key}`);
 assert.deepEqual(loaded.readiness,readiness);
 assert.deepEqual(loaded.adoption,adoption);
 const observed=await readAudit({run,store,native,readiness,adoption});
 assert.equal(completion.nativeProofSha256,observed.proofSha256,'Native AWS proof changed after checker attestation');
 const round=completion.nativeAttestationRound;
 assert.ok(Number.isSafeInteger(round)&&round>=0&&round<32);
 const attestationRequest=await store.readOperation(completion.operationId,`BRIDGE:NATIVE:ATTESTATION:REQUEST:ROUND:${round}`);
 assertBridgeNativeAttestationRequest(attestationRequest,{operationId:completion.operationId,releaseId:completion.releaseId,
  sourceSha:completion.sourceSha,rotationId:completion.rotationId,nativeResultSha256:completion.nativeResultArtifactSha256,
  nativeProofSha256:observed.proofSha256},Date.now(),true);
 assert.equal(attestationRequest.cutoverRequestSha256,request.requestSha256);
 await authenticateBridgeEnvironmentApproval({store,request:attestationRequest,observeApproval});
 const result=await store.readOperation(completion.operationId,`BRIDGE:NATIVE:ATTESTATION:SIGN:ROUND:${round}:RESULT`);
 const dispatch=await store.readOperation(completion.operationId,`BRIDGE:NATIVE:ATTESTATION:SIGN:ROUND:${round}:DISPATCH`);
 const done=await store.readOperation(completion.operationId,`BRIDGE:NATIVE:ATTESTATION:SIGN:ROUND:${round}:COMPLETED`);
 assert.ok(dispatch&&result&&done,'Independent checker native attestation is incomplete');
 assert.deepEqual(result.dispatch,dispatch);
 assert.deepEqual(done.dispatch,dispatch);
 assert.equal(dispatch.executionContract,'S3_COMMIT_BEFORE_SIGN_V1');
 const committed=Date.parse(await store.readOperationCommittedAt(completion.operationId,
  `BRIDGE:NATIVE:ATTESTATION:SIGN:ROUND:${round}:DISPATCH`));
 assert.ok(Number.isSafeInteger(committed)&&committed+1000<=Date.parse(attestationRequest.expiresAt),
  'Checker Sign claim committed after protected authorization expiry');
 assert.equal(done.resultSha256,brokerDigest(result));
 assert.equal(completion.nativeAttestationResultSha256,brokerDigest(result));
 assertBridgeNativeAttestation(result.attestation,{request:attestationRequest,nativeProofSha256:observed.proofSha256});
 assert.equal(dispatch.principal,result.attestation.signerArn);
 assert.equal(dispatch.requestSha256,attestationRequest.requestSha256);
 assert.equal(dispatch.nativeProofSha256,observed.proofSha256);
 assert.equal(dispatch.messageSha256,result.attestation.messageSha256);
 assert.equal(dispatch.keyArn,result.attestation.keyArn);
 assert.equal(dispatch.claimedAt,result.attestation.signedAt);
 assert.ok(Date.parse(result.attestation.signedAt)<Date.parse(attestationRequest.expiresAt));
 await verifyBridgeNativeAttestationSignature({attestation:result.attestation,response:result.response,run});
 return true;
}
