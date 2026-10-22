import assert from 'node:assert/strict';
import {brokerDigest} from './stage-b-staged-broker-contract.mjs';
import {canonicalJson} from './production-green-stage-b-contract.mjs';
import {kmsAdoptionMessage} from './production-completed-inventory-adoption.mjs';
import {createHash,createPublicKey,verify,constants} from 'node:crypto';
import {assertBridgeRequest,bridgeOperationId} from './production-release-bridge-contract.mjs';
import {assertReadyForOverlapDeployment} from './production-overlap-readiness-contract.mjs';
import {assertRootDropEvidence,canonicalRootDropPayload,verifyRootDropEvidenceWithKms} from './production-root-drop-evidence.mjs';
import {STAGE_B} from './production-green-stage-b-contract.mjs';

const stages=Object.freeze({ROOT_DROP:'rootEvidenceArtifactSha256',INVENTORY_ADOPTION:'adoptionEvidenceArtifactSha256',ROTATION_SUCCESSOR:'successorEvidenceArtifactSha256'});
const SHA256=/^[a-f0-9]{64}$/;
const decodeTransport=(value,expectedSha)=>{
 assert.deepEqual(Object.keys(value||{}).sort(),['bytesBase64','sha256']);
 assert.match(value.bytesBase64||'',/^[A-Za-z0-9+/]+={0,2}$/);
 const bytes=Buffer.from(value.bytesBase64,'base64');
 assert.equal(bytes.toString('base64'),value.bytesBase64);
 assert.equal(createHash('sha256').update(bytes).digest('hex'),expectedSha);
 assert.equal(value.sha256,expectedSha);
 return {bytes,value:JSON.parse(bytes.toString('utf8'))};
};

export async function authenticateTerminalCutover({store,releaseId,sourceSha,ticketId,rotationId,manifestSha256,verifyCheckerSignature,verifyRootSignature,readLive}={}){
 assert.equal(typeof store?.readOperation,'function');assert.equal(typeof store?.getArtifact,'function');
 assert.equal(typeof verifyCheckerSignature,'function');assert.equal(typeof verifyRootSignature,'function');assert.equal(typeof readLive,'function');
 const operationId=bridgeOperationId({releaseId,sourceSha,rotationId});
 const completion=await store.readOperation(operationId,'BRIDGE:CUTOVER:COMPLETED');
 if(!completion)return null;
 let owner;
 for(let round=0;round<32;round++){
  const candidate=await store.readOperation(operationId,`BRIDGE:REQUEST:ROUND:${round}`);
  if(!candidate)break;
  if(candidate.requestSha256===completion.requestSha256){owner=candidate;break;}
 }
 assert.ok(owner&&owner.operationId===operationId,'Owned trusted-terminal request is absent');
 const request=await store.readOperation(operationId,`BRIDGE:REQUEST:${owner.workflowRunId}:${owner.workflowRunAttempt}`);
 assertBridgeRequest(request,{releaseId,sourceSha,ticketId,rotationId,manifestSha256,allowExpired:true});
 assert.equal(request.requestSha256,owner.requestSha256);
 assert.equal(completion.operationId,operationId);assert.equal(completion.requestSha256,request.requestSha256);
 for(const key of ['releaseId','sourceSha','rotationId','manifestSha256'])assert.equal(completion[key],request[key]);
 for(const key of [...Object.values(stages),'readinessArtifactSha256','readinessSha256','rotationStateArtifactSha256','rotationStateSha256','rotationFixtureSha256'])assert.match(completion[key]||'',SHA256);
 const [root,adoption,successor,readinessBlob,stateBlob]=await Promise.all([
  store.getArtifact(completion.rootEvidenceArtifactSha256),store.getArtifact(completion.adoptionEvidenceArtifactSha256),
  store.getArtifact(completion.successorEvidenceArtifactSha256),store.getArtifact(completion.readinessArtifactSha256),
  store.getArtifact(completion.rotationStateArtifactSha256)]);
 assert.equal(brokerDigest(root),completion.rootEvidenceArtifactSha256);
 assert.equal(brokerDigest(adoption),completion.adoptionEvidenceArtifactSha256);
 assert.equal(brokerDigest(successor),completion.successorEvidenceArtifactSha256);
 assert.equal(brokerDigest(readinessBlob),completion.readinessArtifactSha256);
 assert.equal(brokerDigest(stateBlob),completion.rotationStateArtifactSha256);
 const {value:readiness,bytes:readinessBytes}=decodeTransport(readinessBlob,completion.readinessSha256);
 const {value:state,bytes:stateBytes}=decodeTransport(stateBlob,completion.rotationStateSha256);
 assertReadyForOverlapDeployment(readiness,{sourceSha,rotationId});
 assert.equal(readiness.rootDrop.evidenceSha256,root.evidenceSha256,'Readiness root reference differs');
 assert.equal(readiness.overlapTaskDefinition.identityBindings.taskDefinitionArn,completion.taskDefinitionArn);
 assert.equal(readiness.overlapTaskDefinition.identityBindings.imageDigest,completion.imageDigest);
 assert.ok(readiness.rotationStateSha256===completion.rotationStateSha256||readiness.rotationStateSha256===state.verification?.preparedStateSha256,'Prepared state hash differs');
 const rootIssued=Date.parse(root.generatedAt),readyAt=Date.parse(readiness.generatedAt);
 assert.ok(Number.isSafeInteger(rootIssued)&&Number.isSafeInteger(readyAt)&&readyAt>=rootIssued,'Readiness predates root issuance');
 assertRootDropEvidence(root,{sourceSha,rotationId,imageAuthorizationSha256:root.imageAuthorizationSha256,
  successorRecoveryAuthorizationSha256:root.successorRecoveryAuthorizationSha256,
  administratorEvidenceSha256:root.administratorEvidenceSha256,administratorSignatureSha256:root.administratorSignatureSha256,
  now:rootIssued,verifySignature:verifyRootSignature});
 for(const [phase,evidence] of Object.entries({ROOT_DROP:root,INVENTORY_ADOPTION:adoption,ROTATION_SUCCESSOR:successor})){
  const prefix=`BRIDGE:SIGN:${phase}`;
  const dispatch=await store.readOperation(operationId,`${prefix}:DISPATCH`);
  const result=await store.readOperation(operationId,`${prefix}:RESULT`);
  const done=await store.readOperation(operationId,`${prefix}:COMPLETED`);
  assert.ok(dispatch&&result&&done,`${phase} native Sign completion is absent`);
  assert.equal(dispatch.operationId,operationId);assert.equal(dispatch.requestSha256,request.requestSha256);
  assert.equal(dispatch.phase,phase);assert.equal(dispatch.inputSha256,brokerDigest(dispatch.input));
  assert.deepEqual(result.dispatch,dispatch);assert.equal(done.resultSha256,brokerDigest(result));
  assert.equal(result.response.Signature,evidence.signatureBase64,'Native KMS signature differs from evidence');
  assert.equal(result.response.KeyId,phase==='ROOT_DROP'?STAGE_B.rootDropKmsKeyArn:STAGE_B.approvalKmsKeyArn);
  if(phase==='ROOT_DROP'){
   assert.equal(dispatch.principal,`arn:aws:iam::${STAGE_B.account}:root`);
   const {signingKeyArn,signingAlgorithm,signedPayloadSha256,signatureBase64,evidenceSha256,...unsigned}=root;
   assert.equal(dispatch.input.messageBase64,Buffer.from(canonicalRootDropPayload(unsigned)).toString('base64'));
  }
  else{
   assert.match(dispatch.principal||'',new RegExp(`^arn:aws:sts::${STAGE_B.account}:assumed-role/mscqr-production-rls-independent-checker/[^/]+$`));
   assert.equal(await verifyCheckerSignature({dispatch,result,evidence}),true,`${phase} independent checker signature is invalid`);
  }
 }
 assert.equal(adoption.payload.rotationId,rotationId);assert.equal(successor.payload.rotationId,rotationId);
 assert.equal(successor.payload.successorSourceSha||successor.payload.sourceSha,sourceSha);
 assert.equal(await readLive({completion,readiness,state}),true,'Native AWS state does not match overlap readiness');
 return {request,completion,readiness,state,readinessBytes,stateBytes,root,adoption,successor};
}

export function rootBridgeVerifier(run){return input=>verifyRootDropEvidenceWithKms({...input,run});}

export function checkerBridgeVerifier(run){
 assert.equal(typeof run,'function');
 return async ({dispatch,result,evidence})=>{
  const original=Buffer.from(canonicalJson(evidence.payload));
  const input=dispatch.phase==='INVENTORY_ADOPTION'?kmsAdoptionMessage(original):{bytes:original,type:'RAW'};
  if(dispatch.input.keyId!==STAGE_B.approvalKmsKeyArn||dispatch.input.messageType!==input.type||dispatch.input.messageBase64!==input.bytes.toString('base64')
    ||dispatch.input.signingAlgorithm!=='RSASSA_PSS_SHA_256')return false;
  const response=JSON.parse(run(['kms','get-public-key','--key-id',STAGE_B.approvalKmsKeyArn,'--output','json','--no-cli-pager']));
  if(response.KeyId!==STAGE_B.approvalKmsKeyArn||response.KeyUsage!=='SIGN_VERIFY'||!response.SigningAlgorithms?.includes('RSASSA_PSS_SHA_256'))return false;
  const key=createPublicKey({key:Buffer.from(response.PublicKey,'base64'),format:'der',type:'spki'});
  return verify('sha256',original,{key,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32},
   Buffer.from(result.response.Signature,'base64'));
 };
}

export function bridgeOverlapLiveReader(run){
 assert.equal(typeof run,'function');
 const json=args=>JSON.parse(run([...args,'--output','json','--no-cli-pager']));
 return async ({completion})=>{
  const service=json(['ecs','describe-services','--cluster','mscqr-prod-euw2-main','--services','mscqr-backend-servi-euw2']).services?.[0];
  assert.equal(service?.status,'ACTIVE');
  assert.equal(service.taskDefinition,completion.expectedCurrentTaskDefinitionArn,'Backend predecessor changed before overlap');
  assert.ok(service.desiredCount>0&&service.runningCount===service.desiredCount,'Backend predecessor is not stable');
  const task=json(['ecs','describe-task-definition','--task-definition',completion.taskDefinitionArn]).taskDefinition;
  assert.equal(task?.taskDefinitionArn,completion.taskDefinitionArn);
  assert.equal(task.containerDefinitions?.find(item=>item.name==='backend')?.image?.split('@').at(-1),completion.imageDigest);
  return true;
 };
}
