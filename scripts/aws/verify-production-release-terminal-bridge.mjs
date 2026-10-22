import assert from 'node:assert/strict';
import {brokerDigest} from './stage-b-staged-broker-contract.mjs';
import {canonicalJson} from './production-green-stage-b-contract.mjs';
import {kmsAdoptionMessage} from './production-completed-inventory-adoption.mjs';
import {mkdtempSync,rmSync,writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import {assertBridgeRequest,bridgeOperationId,bridgeOperatorClaimPhase,bridgeOperatorExpiryAction,bridgeRequestForSign} from './production-release-bridge-contract.mjs';
import {assertReadyForOverlapDeployment} from './production-overlap-readiness-contract.mjs';
import {assertRootDropEvidence,canonicalRootDropPayload,verifyRootDropEvidenceWithKms} from './production-root-drop-evidence.mjs';
import {STAGE_B} from './production-green-stage-b-contract.mjs';
import {assertProductionEnvironmentApprovalIdentity,PRODUCTION_ENVIRONMENT_APPROVAL} from './production-github-environment-approval.mjs';

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

export async function requireBridgeNativeStages(verifyNativeStages,evidence){
 assert.equal(typeof verifyNativeStages,'function','Independent Stage B native receipt verification is required before Release Gate');
 assert.equal(await verifyNativeStages(evidence),true,'Independent Stage B native receipts are incomplete');
}

export async function authenticateBridgeEnvironmentApproval({store,request,observeApproval}={}){
 assert.equal(typeof observeApproval,'function');
 const approval=await store.getArtifact(request.environmentApprovalSha256);
 assert.equal(brokerDigest(approval),request.environmentApprovalSha256);
 assertProductionEnvironmentApprovalIdentity(approval,{sourceSha:request.sourceSha,repository:PRODUCTION_ENVIRONMENT_APPROVAL.repository});
 assert.equal(approval.schemaVersion,3);assert.equal(approval.workflowRef,PRODUCTION_ENVIRONMENT_APPROVAL.releaseTrainWorkflowRef);
 assert.equal(approval.workflowRunId,request.workflowRunId);assert.equal(approval.workflowRunAttempt,request.workflowRunAttempt);
 const observed=await observeApproval(approval,request);
 assert.deepEqual(observed.actualApproval,approval.actualApproval,'Protected environment approval changed');
 return approval;
}

export async function authenticateTerminalCutover({store,releaseId,sourceSha,ticketId,rotationId,manifestSha256,verifyCheckerSignature,verifyRootSignature,observeApproval,readLive,verifyNativeStages}={}){
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
 const operatorPhase=bridgeOperatorClaimPhase(request);
 const operator=await store.readOperation(operationId,operatorPhase);
 assert.equal(bridgeOperatorExpiryAction({request,operator,
  operatorCommittedAt:operator?await store.readOperationCommittedAt(operationId,operatorPhase):undefined}),'RECONCILE',
  'Terminal completion has no timely, matching operator dispatch claim');
 await authenticateBridgeEnvironmentApproval({store,request,observeApproval});
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
  const phaseRequest=await bridgeRequestForSign({store,operationId,dispatch,releaseId,sourceSha,ticketId,rotationId,manifestSha256});
  if(phaseRequest.requestSha256!==request.requestSha256)await authenticateBridgeEnvironmentApproval({store,request:phaseRequest,observeApproval});
  assert.equal(dispatch.phase,phase);assert.equal(dispatch.inputSha256,brokerDigest(dispatch.input));
  assert.deepEqual(result.dispatch,dispatch);assert.equal(done.resultSha256,brokerDigest(result));
  assert.equal(result.response.Signature,evidence.signatureBase64,'Native KMS signature differs from evidence');
  if(phase==='ROOT_DROP')assert.match(result.response.KeyId||'',new RegExp(`^arn:aws:kms:${STAGE_B.region}:${STAGE_B.account}:key/[a-f0-9-]{36}$`));
  else assert.equal(result.response.KeyId,STAGE_B.approvalKmsKeyArn);
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
 await requireBridgeNativeStages(verifyNativeStages,{request,completion,readiness,state});
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
  const directory=mkdtempSync(path.join(os.tmpdir(),'mscqr-bridge-kms-verify-'));
  try{
   const messagePath=path.join(directory,'message'),signaturePath=path.join(directory,'signature');
   writeFileSync(messagePath,input.bytes,{mode:0o600});writeFileSync(signaturePath,Buffer.from(result.response.Signature,'base64'),{mode:0o600});
   const response=JSON.parse(run(['kms','verify','--key-id',STAGE_B.approvalKmsKeyArn,'--message',`fileb://${messagePath}`,
    '--message-type',input.type,'--signature',`fileb://${signaturePath}`,'--signing-algorithm','RSASSA_PSS_SHA_256','--output','json','--no-cli-pager']));
   return response.KeyId===STAGE_B.approvalKmsKeyArn&&response.SignatureValid===true;
  }finally{rmSync(directory,{recursive:true,force:true});}
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
