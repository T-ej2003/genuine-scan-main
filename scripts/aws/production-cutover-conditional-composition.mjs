import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {STAGE_B,assertConditionalProductionEnabled} from './production-green-stage-b-contract.mjs';
import {conditionalHash,parseConditionalJson,assertConditionalDerivation} from './production-cutover-conditional-authorization.mjs';
import {readConditionalPrepareContext} from './production-cutover-conditional-capability.mjs';
import {createProductionCutoverRuntimeComposition,isProductionCutoverRuntimeComposition} from './production-cutover-runtime-composition.mjs';
import {PRODUCTION_CUTOVER_MODE,runProductionCutoverControlPlane} from './production-cutover-control-plane.mjs';
import {createProductionAwsCommandRunner,PRODUCTION_AWS_CREDENTIAL_SOURCE as SOURCE} from './production-credential-source-contract.mjs';
import {createAwsStsRunner,establishVerifierIdentity,revalidateProcessVerifierIdentity} from './production-identity-adapters.mjs';
import {readStageBProtectedMainCheckout,readFreshProtectedMainIdentity} from './stage-b-deployment-identity.mjs';
import {readStageBPrivateFileBytes,readBoundStageBPrivateJson,writeStageBPrivateFilesAtomic} from './stage-b-artifact-contract.mjs';
import {resolveQrVersionResolutionArtifact,assertQrVersionSelector} from './production-qr-version-selector-resolution.mjs';
import {assertReadyForOverlapDeployment} from './production-overlap-readiness-contract.mjs';
import {runCli as produceRoot} from './produce-production-root-drop-evidence.mjs';
import {prepareCompletedInventoryAdoption} from './prepare-completed-inventory-adoption.mjs';
import {prepareProductionRotationSuccessor} from './prepare-production-rotation-successor.mjs';
import {authenticateCompletedInventoryAdoptionEvidence} from './production-completed-inventory-adoption.mjs';
import {authenticateRotationSuccessor,readOriginalRotationStatus} from './production-rotation-successor.mjs';
import {assertConditionalFileCensus,assertConditionalFreshOutputs,assertConditionalPinnedWindow} from './production-cutover-runtime-materialization.mjs';
import {createPreDeploymentOperationIdentity,preDeploymentOperationKey,inventoryCompletionKey,preDeploymentOperationIdentitySha256} from '../../infra/aws/terraform/lambda/production-rls-approval-broker/index.mjs';
import {verifyRootDropEvidenceWithKms} from './production-root-drop-evidence.mjs';
import {conditionalReadRunner,createConditionalExecutor} from './production-cutover-conditional-native.mjs';

const stateUri='s3://mscqr-production-terraform-state-368992683803-eu-west-2/env:/production/mscqr/production/rls-green/stage-b/terraform.tfstate';
const json=(run,args)=>parseConditionalJson(run([...args,'--output','json','--no-cli-pager']));
const file=(p)=>readStageBPrivateFileBytes({filePath:p,repositoryRoot:process.cwd(),label:'Sealed conditional input'});
const byHash=(d,sha)=>{const matches=d.files.filter(value=>value.fileSha256===sha);assert.equal(matches.length,1,'Exact sealed input path is ambiguous');return matches[0].path;};
const fromAws=item=>Object.fromEntries(Object.entries(item||{}).map(([key,value])=>[key,value.S??(value.N!==undefined?Number(value.N):value.SS)]));
const secretArns=r=>[...new Set(Object.values({...r.jwt,...r.qr}).filter(value=>typeof value==='string'&&value.startsWith('arn:aws:secretsmanager:')))].sort();

export function readConditionalLiveObservation({d,read,execute=execFileSync}) {
  const r=d.runtimeTemplate;assertConditionalFileCensus(d);assertConditionalPinnedWindow(d);
  const checkout=readStageBProtectedMainCheckout({expectedSourceSha:d.toolingSourceSha,requireCanonicalRepository:true,run:args=>execute('git',args,{cwd:process.cwd(),encoding:'utf8'})});
  const original=readBoundStageBPrivateJson({filePath:r.rotationSuccessor.predecessorConfigFile,expectedSha256:d.predecessor.configSha256,label:'Original rotation config'});
  const originalState=readBoundStageBPrivateJson({filePath:r.rotationSuccessor.predecessorStateFile,expectedSha256:d.predecessor.stateSha256,label:'Original rotation state'});
  const identity=createPreDeploymentOperationIdentity({approvalId:original.inventoryApprovalId,releaseSha:original.sourceSha,imageReleaseSha:original.imageReleaseSha,rotationId:original.rotationId,taskDefinitionArn:original.inventoryTaskDefinitionArn,imageDigest:original.overlapTaskInput.backendImage});
  const operationKey=preDeploymentOperationKey(identity);
  const receipt=fromAws(json(read,['dynamodb','get-item','--table-name',STAGE_B.replayTable,'--consistent-read','--key',JSON.stringify({approvalMode:{S:inventoryCompletionKey(operationKey)}})]).Item);assert.ok(Object.keys(receipt).length,'Missing durable inventory receipt');
  const alias=json(read,['lambda','get-alias','--function-name',STAGE_B.brokerFunctionArn,'--name',STAGE_B.brokerAliasArn.split(':').at(-1)]);
  const broker=json(read,['lambda','get-function-configuration','--function-name',STAGE_B.brokerFunctionArn,'--qualifier',alias.FunctionVersion]);
  const closure=file(byHash(d,d.broker.closureFileSha256));
  const service=json(read,['ecs','describe-services','--cluster',STAGE_B.clusterArn,'--services','mscqr-backend-servi-euw2']).services?.[0];assert.ok(service);
  const task=json(read,['ecs','describe-task-definition','--task-definition',service.taskDefinition,'--include','TAGS']).taskDefinition;
  const selector=assertQrVersionSelector({taskDefinition:task,expectedSecretArn:d.predecessor.qrSecretArn});
  const qr=json(read,['secretsmanager','describe-secret','--secret-id',selector.secretArn]);
  const current=Object.entries(qr.VersionIdsToStages).filter(([,stages])=>stages.includes('AWSCURRENT'));assert.equal(current.length,1);
  const qrValue=json(read,['secretsmanager','get-secret-value','--secret-id',selector.secretArn,'--version-id',current[0][0]]);
  const slots=Object.fromEntries(secretArns(r).map(arn=>[arn,json(read,['secretsmanager','describe-secret','--secret-id',arn]).VersionIdsToStages]));
  const stateBytes=Buffer.from(read(['s3','cp',stateUri,'-'])),state=parseConditionalJson(stateBytes);
  const publication=json(read,['secretsmanager','describe-secret','--secret-id',STAGE_B.approvalSecretArn]);
  const published=Object.entries(publication.VersionIdsToStages).filter(([,stages])=>stages.includes('AWSCURRENT'));assert.equal(published.length,1);
  const keys=Object.fromEntries(Object.entries(d.keys).map(([kind,key])=>{
    const live=json(read,['kms','get-public-key','--key-id',key.keyArn]);assert.equal(live.KeyId,key.keyArn);
    if(kind==='root')assert.equal(json(read,['kms','describe-key','--key-id',STAGE_B.rootDropKmsKeyArn]).KeyMetadata.Arn,key.keyArn);
    const policy=json(read,['kms','get-key-policy','--key-id',key.keyArn,'--policy-name','default']);
    return [kind,{keyArn:live.KeyId,publicKeySha256:conditionalHash(Buffer.from(live.PublicKey,'base64')),policySha256:conditionalHash(parseConditionalJson(policy.Policy))}];
  }));
  const immutableArtifact=configField=>conditionalHash(file(r[configField]).bytes);
  return {toolingSourceSha:checkout.currentHead,historicalReleaseSha:r.sourceSha,rotationId:originalState.rotationId,backendImageDigest:r.overlapTaskInput.backendImage.split('@')[1],
    broker:{aliasArn:alias.AliasArn,version:alias.FunctionVersion,revisionId:alias.RevisionId,closureFileSha256:closure.sha256,closurePayloadSha256:conditionalHash(parseConditionalJson(closure.bytes).result),configurationSha256:conditionalHash(broker)},
    inventory:{operationKey,operationIdentitySha256:preDeploymentOperationIdentitySha256(identity),completionReceiptSha256:conditionalHash(receipt),stateBoundInventorySha256:originalState.inventoryEvidenceSha256,completionInventorySha256:receipt.inventorySha256,originalImageReleaseSha:original.imageReleaseSha,originalImageDigest:original.overlapTaskInput.backendImage.split('@')[1],taskArn:receipt.taskArn},
    predecessor:{configSha256:file(r.rotationSuccessor.predecessorConfigFile).sha256,stateSha256:file(r.rotationSuccessor.predecessorStateFile).sha256,fixtureSha256:file(r.rotationSuccessor.predecessorFixtureFile).sha256,statusSha256:readOriginalRotationStatus({config:r,execute}),taskDefinitionSha256:selector.taskDefinitionSha256,secretSlotsSha256:conditionalHash(slots),terraformStateSha256:conditionalHash(stateBytes),terraformPlanSha256:file(r.rotationTerraformPlanFile).sha256,terraformConfigSha256:conditionalHash(d.files.filter(value=>value.path.includes('/infra/aws/terraform/'))),tfvarsBindingSha256:file(r.stageBTfvarsBindingReportPath).sha256,phase:'overlap-deploy-required',taskDefinitionArn:service.taskDefinition,terraformLineage:state.lineage,terraformSerial:state.serial,qrSecretArn:selector.secretArn,qrVersionId:current[0][0],qrCurrentVersion:parseConditionalJson(qrValue.SecretString).value},
    artifacts:{imageFileSha256:immutableArtifact('imageAuthorizationFile'),imageAuthorizationSha256:parseConditionalJson(file(r.imageAuthorizationFile).bytes).authorizationSha256,stageBApprovalFileSha256:file(byHash(d,d.artifacts.stageBApprovalFileSha256)).sha256,stageBPublicationVersion:published[0][0],administratorFileSha256:immutableArtifact('iamEvidenceFile'),administratorSignatureFileSha256:immutableArtifact('iamEvidenceSignatureFile'),checkerReportFileSha256:immutableArtifact('releasePreflightEvidenceFile'),checkerAttestationFileSha256:immutableArtifact('releasePreflightAttestationFile'),checkerSignatureFileSha256:immutableArtifact('releasePreflightAttestationSignatureFile'),ticketScopeSha256:file(byHash(d,d.artifacts.ticketScopeSha256)).sha256},keys};
}

export async function prepareCanonicalConditionalOverlap({conditionalContext,verifierStsAdapter,composition}) {
  assertConditionalProductionEnabled();
  composition ||= createProductionCutoverRuntimeComposition();
  assert.ok(isProductionCutoverRuntimeComposition(composition),'Canonical production composition required');
  const {d,materialization}=readConditionalPrepareContext(conditionalContext),config=materialization.config;
  const adapters=composition.constructAdapters({config,sourceSha:d.historicalReleaseSha,rotationId:d.rotationId,runtimeConfigSha256:materialization.manifest.runtimeFileSha256,conditionalContext,verifierStsAdapter});
  return runProductionCutoverControlPlane({mode:PRODUCTION_CUTOVER_MODE.PREPARE_OVERLAP,sourceSha:d.historicalReleaseSha,operationExecutionSourceSha:d.toolingSourceSha,rotationId:d.rotationId,conditionalContext,
    imageAuthorization:readBoundStageBPrivateJson({filePath:config.imageAuthorizationFile,expectedSha256:config.imageAuthorizationSha256,label:'Canonical image authorization'}),...adapters});
}

export function createCanonicalConditionalAdapters({d,qrWorkflowRunId,githubToken,execute=execFileSync,fetchImpl=fetch}) {
  assertConditionalProductionEnabled();assertConditionalDerivation(d);
  assert.equal(process.env.TF_WORKSPACE,'default','Conditional recovery requires the outer default Terraform workspace');
  assertConditionalFreshOutputs(d);
  execute=createConditionalExecutor(d,execute);
  const r=d.runtimeTemplate,repositoryRoot=process.cwd();
  assert.ok(!r.rebaselineRuntime?.successorRecoveryAuthorizationSha256,'Conditional source-advanced recovery authorization is outside this derivation contract');
  const source={credentialSource:SOURCE.NAMED_PROFILE,profile:'mscqr-production-release-deployer',exec:execute};
  const read=conditionalReadRunner(createProductionAwsCommandRunner(source),r);
  const signer=phase=>phase==='ROOT_DROP'?{credentialSource:SOURCE.NAMED_PROFILE,profile:'default',exec:execute}:{credentialSource:SOURCE.INHERITED_CHECKER_SESSION,exec:execute};
  const mixed=phase=>{const ordinary=createProductionAwsCommandRunner(signer(phase)),native=createProductionAwsCommandRunner({...signer(phase),singleAttemptMutation:'KMS_SIGN'});return args=>args[0]==='kms'&&args[1]==='sign'?native(args):ordinary(args);};
  const checker=mixed('INVENTORY_ADOPTION');
  const git=args=>execute('git',args,{cwd:repositoryRoot,encoding:'utf8'});
  const authenticateCheckout=options=>readStageBProtectedMainCheckout({...options,run:git});
  const proveDescendant=({ancestorSha,descendantSha})=>{try{execute('git',['merge-base','--is-ancestor',ancestorSha,descendantSha],{cwd:repositoryRoot,stdio:'ignore'});return true;}catch{return false;}};
  const verifySignature=({keyId,keyArn,message,signature})=>verifyRootDropEvidenceWithKms({message,signature,keyArn:keyId||keyArn,run:read});
  const verifierSts=createAwsStsRunner({profile:r.bootstrapProfile||'mscqr-production-bootstrap-mfa',run:execute});
  const originalState=readBoundStageBPrivateJson({filePath:r.rotationSuccessor.predecessorStateFile,expectedSha256:d.predecessor.stateSha256,label:'Original state'});
  const verifyAdoption=(evidence,mat)=>authenticateCompletedInventoryAdoptionEvidence(evidence,{config:mat.config,configSha256:mat.manifest.runtimeFileSha256,proveDescendant,now:new Date()},verifySignature);
  const verifySuccessor=(value,mat,adoption)=>authenticateRotationSuccessor({config:mat.config,configSha256:mat.manifest.runtimeFileSha256,predecessorState:originalState,predecessorStateSha256:d.predecessor.stateSha256,predecessorFixtureSha256:d.predecessor.fixtureSha256,predecessorStatusSha256:readOriginalRotationStatus({config:mat.config,execute}),state:value.state,fixtureSha256:d.predecessor.fixtureSha256,inventoryEvidence:adoption,evidence:value.evidence,proveDescendant,verifySignature});
  return {
    observe:()=>readConditionalLiveObservation({d,read,execute}),
    currentIdentity:phase=>json(phase==='ROOT_DROP'?createProductionAwsCommandRunner(signer(phase)):phase==='PREPARE_OVERLAP'?read:checker,['sts','get-caller-identity']).Arn,
    establishVerifier:()=>establishVerifierIdentity({adapter:verifierSts,mfaSerial:process.env.MSCQR_VERIFIER_MFA_SERIAL,getMfaCode:async()=>{const {promptProductionMfaCode}=await import('../security/production-interactive-mfa-provider.mjs');return promptProductionMfaCode({prompt:'Production verifier MFA: '});}}),
    verifyVerifier:()=>revalidateProcessVerifierIdentity({adapter:verifierSts}),
    qr:async()=>{const taskDefinition=json(read,['ecs','describe-task-definition','--task-definition',d.predecessor.taskDefinitionArn,'--include','TAGS']).taskDefinition;const readSecretMetadata=()=>json(read,['secretsmanager','describe-secret','--secret-id',d.predecessor.qrSecretArn]);return {taskDefinition,readSecretMetadata,resolution:await resolveQrVersionResolutionArtifact({workflowRunId:qrWorkflowRunId,sourceSha:d.toolingSourceSha,changeTicket:d.ticketId,expectedSecretArn:d.predecessor.qrSecretArn,taskDefinition,secretMetadata:readSecretMetadata(),token:githubToken,fetchImpl})};},
    verifyRoot:verifySignature,
    root:async({nativeSign})=>{await produceRoot(['--source-sha',d.historicalReleaseSha,'--broker-recovery',byHash(d,d.broker.closureFileSha256),'--broker-recovery-sha256',d.broker.closureFileSha256,'--output',r.rootDropEvidenceFile,'--profile','default','--rotation-id',d.rotationId,'--image-authorization-sha256',d.artifacts.imageAuthorizationSha256,'--successor-recovery-authorization-sha256','none','--administrator-evidence-sha256',d.artifacts.administratorFileSha256,'--administrator-signature-sha256',d.artifacts.administratorSignatureFileSha256],{nativeSign,commandRunner:()=>mixed('ROOT_DROP'),protectedMain:options=>readFreshProtectedMainIdentity({...options,run:git})});return file(r.rootDropEvidenceFile).bytes;},
    persistRuntime:async mat=>{writeStageBPrivateFilesAtomic({files:[{filePath:r.rotationConfigFile,bytes:mat.bytes,label:'Conditional runtime'},{filePath:path.join(path.dirname(r.rotationConfigFile),'cutover-runtime-manifest.json'),bytes:Buffer.from(`${JSON.stringify(mat.manifest,null,2)}\n`),label:'Conditional materialization'}],repositoryRoot});return file(r.rotationConfigFile).bytes;},
    adopt:async(mat,nativeSign)=>{const result=await prepareCompletedInventoryAdoption({argv:['--original-config',r.rotationSuccessor.predecessorConfigFile,'--original-config-sha256',d.predecessor.configSha256,'--continuation-config',r.rotationConfigFile,'--continuation-config-sha256',mat.manifest.runtimeFileSha256,'--current-approval',byHash(d,d.artifacts.stageBApprovalFileSha256),'--current-approval-sha256',d.artifacts.stageBApprovalFileSha256],runRead:read,runSign:checker,authenticateCheckout,proveSourceAdvance:proveDescendant,nativeSign});return parseConditionalJson(file(result.outputPath).bytes);},
    verifyAdoption,
    successor:(mat,adoption,nativeSign)=>prepareProductionRotationSuccessor({argv:['--config',r.rotationConfigFile,'--config-sha256',mat.manifest.runtimeFileSha256],readAws:read,signAws:checker,statusRun:execute,authenticateCheckout,proveSourceAdvance:proveDescendant,nativeSign,deferStateWrites:true}),
    verifySuccessor,
    prepareOverlap:({conditionalContext})=>prepareCanonicalConditionalOverlap({conditionalContext,verifierStsAdapter:verifierSts,composition:createProductionCutoverRuntimeComposition({releaseRun:read,exec:execute})}),
    verifyReadiness:result=>assertReadyForOverlapDeployment(result.readiness,{sourceSha:d.historicalReleaseSha,executionSourceSha:d.toolingSourceSha,rotationId:d.rotationId,rotationStateSha256:result.rotationStateSha256}),
  };
}
