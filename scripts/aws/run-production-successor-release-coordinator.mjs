#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {runSuccessorReleaseCoordinator} from './production-successor-release-coordinator.mjs';
import {HOSTED_RELEASE_ROOT,createReleaseCoordinatorStore,captureReleasePhaseMaterial,
 hydrateReleasePhaseMaterial,obtainReleaseTransitionAuthorization} from './production-release-coordinator.mjs';
import {assertHistoricalStateImport,authenticateProtectedTooling} from './import-production-stage-b-historical-state.mjs';
import {brokerDigest,brokerTargetIdentity,assertBrokerAuthorization,assertBrokerClosurePlan} from './stage-b-staged-broker-contract.mjs';
import {readStagedBrokerSourceAuthority,readStagedBrokerReceipt,stagedBrokerSourceReservation,
 normalizeBrokerAlias} from './stage-b-staged-broker-executor.mjs';
import {createBrokerKmsAuthorizationBoundary} from './stage-b-staged-broker-authorization.mjs';
import {createProductionAwsCommandRunner,PRODUCTION_AWS_CREDENTIAL_SOURCE} from './production-credential-source-contract.mjs';
import {ensureStageBPrivateDirectory,writeStageBPrivateFileAtomic,assertStageBPrivateFile} from './stage-b-artifact-contract.mjs';
import {STAGE_B_TERRAFORM_BACKEND,ensureStageBTerraformBackendMetadataPrivate} from './stage-b-terraform-backend-contract.mjs';
import {generateStageBTerraformBackendConfig} from './generate-production-green-stage-b-backend-config.mjs';
import {STAGE_B} from './production-green-stage-b-contract.mjs';
import {deriveStageBToolingInputTreeSha256,deriveStageBImageImpactReport} from './validate-stage-b-image-reuse.mjs';
import {packageStageBBroker} from './package-production-green-stage-b-broker.mjs';
import {generateStageAPrerequisites,STAGE_A_STATE_OBJECT} from './generate-production-green-stage-a-prerequisites.mjs';
import {generateStageBTfvars} from './generate-production-green-stage-b-tfvars.mjs';
import {verifyImageEvidenceSignature,assertImageEvidence,assertImageEvidenceReuseBridge} from './production-green-stage-b-image-evidence.mjs';
import {runStagedBrokerRequest} from './run-stage-b-staged-broker.mjs';
import {createRootAttestationKmsVerifier} from './production-root-attestation-key.mjs';

const root=path.resolve(fileURLToPath(new URL('../..',import.meta.url)));
const terraformRoot=path.join(root,'infra/aws/terraform/production-green-stage-b');
const files=directory=>({package:path.join(directory,'broker-package.zip'),packageManifest:path.join(directory,'broker-package.zip.manifest.json'),
 tfvars:path.join(directory,'stage-b.tfvars'),backendMetadata:path.join(directory,'terraform','terraform.tfstate')});
const paths=directory=>({historicalStatePath:path.join(directory,'historical-state.json'),
 currentStatePath:path.join(directory,'current-state.json'),bindingReportPath:path.join(directory,'stage-b-tfvars-binding.json'),
 imageEvidencePath:path.join(directory,'image-evidence.json'),imageSignaturePath:path.join(directory,'image-evidence-signature.json')});
const equal=(actual,expected)=>assert.equal(brokerDigest(actual),brokerDigest(expected));

export function createHostedSuccessorRuntime({env=process.env,
 awsRun=createProductionAwsCommandRunner({credentialSource:PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER,env}),
 ghRun=(args,options)=>execFileSync('gh',args,{encoding:'utf8',maxBuffer:8*1024*1024,...options}),
 stage=runStagedBrokerRequest,createStore=createReleaseCoordinatorStore,
 packageBroker=packageStageBBroker,generateTfvars=generateStageBTfvars,
 generateStageA=generateStageAPrerequisites,verifyImage=verifyImageEvidenceSignature,
 authorize=obtainReleaseTransitionAuthorization,authenticateTooling=authenticateProtectedTooling,
 readAuthority=readStagedBrokerSourceAuthority,readReceipt=readStagedBrokerReceipt,
 verifyAuthorization,readVersion,readReviewedAlias,authenticateImages,verifyImport,
 commandRun=(cmd,args,options)=>execFileSync(cmd,args,{cwd:root,encoding:'utf8',stdio:['ignore','pipe','pipe'],...options})}={}) {
 assert.equal(env.GITHUB_ACTIONS,'true');assert.equal(env.GITHUB_EVENT_NAME,'workflow_dispatch');
 assert.equal(env.GITHUB_REPOSITORY,'T-ej2003/genuine-scan-main');
 assert.equal(env.GITHUB_WORKFLOW_REF,`${env.GITHUB_REPOSITORY}/.github/workflows/recover-production-stage-b-successor.yml@refs/heads/main`);
 assert.match(env.GITHUB_SHA||'',/^[a-f0-9]{40}$/);assert.match(env.GITHUB_RUN_ATTEMPT||'',/^[1-9][0-9]*$/);
 assert.ok(path.isAbsolute(env.RUNNER_TEMP||''));assert.ok(/^[1-9][0-9]*$/.test(env.GITHUB_RUN_ID||''));
 ensureStageBPrivateDirectory({directory:HOSTED_RELEASE_ROOT,repositoryRoot:root,create:true});
 const store=createStore({run:awsRun,directory:HOSTED_RELEASE_ROOT,repositoryRoot:root});
 const verifier=verifyAuthorization||createBrokerKmsAuthorizationBoundary({run:awsRun,githubRun:ghRun}).verify;
 const importVerifier=verifyImport||createRootAttestationKmsVerifier({run:awsRun});
 const output=reference=>{const artifact=store.getArtifact(reference);assert.deepEqual(Object.keys(artifact).sort(),['base64','kind','sha256']);
  assert.equal(artifact.kind,'PRODUCTION_RELEASE_BINARY');const bytes=Buffer.from(artifact.base64,'base64');
  assert.equal(bytes.toString('base64'),artifact.base64);assert.equal(brokerDigest(bytes),artifact.sha256);return bytes;};
 const json=args=>JSON.parse(awsRun([...args,'--output','json','--no-cli-pager']));
 const privateWrite=(file,bytes)=>{
  ensureStageBPrivateDirectory({directory:path.dirname(file),repositoryRoot:root,create:true});
  if(fs.existsSync(file)){assertStageBPrivateFile({filePath:file,repositoryRoot:root,label:'Successor evidence'});
   equal(fs.readFileSync(file),bytes);return;}
  writeStageBPrivateFileAtomic({filePath:file,bytes,repositoryRoot:root,label:'Successor evidence'});
 };
 const phaseDirectory=(release,phase)=>path.join(HOSTED_RELEASE_ROOT,release.releaseId,phase==='closure'?'cutover':phase);
 const readPublication=async request=>{
  const directory=path.join(HOSTED_RELEASE_ROOT,'source-read');ensureStageBPrivateDirectory({directory,repositoryRoot:root,create:true});
  const authority=readAuthority({run:awsRun,sourceSha:request.releaseSourceSha,directory});assert.ok(authority);
  const result=readReceipt({run:awsRun,id:brokerDigest(authority.authorization),status:'PUBLISHED',directory});
  assert.equal(result.sourceSha,request.releaseSourceSha);
  assert.equal(result.preparationSha256,brokerDigest(authority.preparation));
  assert.equal(result.authorizationSha256,brokerDigest(authority.authorization));
  assert.equal(brokerDigest(result),request.publicationResultSha256);
  assert.equal(result.target.version,request.brokerVersion);
  await assertBrokerAuthorization(authority.authorization,authority.preparation,{verify:verifier,now:new Date(result.authorizedAt)});
  const live=readVersion?await readVersion(request.brokerVersion)
   :json(['lambda','get-function-configuration','--function-name',STAGE_B.brokerFunctionArn,'--qualifier',request.brokerVersion]);
  equal(brokerTargetIdentity(live,authority.preparation.packageSha256),result.target);
  return {...authority,result};
 };
 const readAlias=()=>normalizeBrokerAlias(readReviewedAlias?readReviewedAlias()
  :json(['lambda','get-alias','--function-name',STAGE_B.brokerFunctionArn,'--name','reviewed']));
 return {
  store,
  authenticateRequest:async request=>{
   assert.equal(env.GITHUB_SHA,request.recoveryToolingSha,'Hosted recovery checkout differs from operation tooling');
   authenticateTooling(request.releaseSourceSha,request.recoveryToolingSha);
   const publication=await readPublication(request),historical=store.getArtifact(request.historicalImportReference);
   assertHistoricalStateImport(historical,{releaseSourceSha:request.releaseSourceSha,
    recoveryToolingSha:request.recoveryToolingSha,recoveryId:request.recoveryId,brokerVersion:request.brokerVersion,
    publication:publication.result,store,verifyImport:importVerifier});
   const alias=readAlias();
   const body={schemaVersion:2,sourceSha:request.releaseSourceSha,ticketId:request.ticketId,
    recoveryReference:brokerDigest(request),toolingSha:request.recoveryToolingSha};
   const releaseId=brokerDigest(body),attempt=store.readStep(releaseId,'cutover:attempt:0');
   const completed=store.readStep(releaseId,'cutover:result');
   assert.ok(completed?alias.FunctionVersion===request.brokerVersion:attempt
    ?[request.expectedAliasVersion,request.brokerVersion].includes(alias.FunctionVersion)
    :alias.FunctionVersion===request.expectedAliasVersion,
   'Reviewed alias differs from authenticated successor operation state');
   assert.ok(alias.RevisionId,'Reviewed alias revision is missing');
   if(!attempt)assert.equal(alias.RevisionId,request.expectedAliasRevision,
    'Reviewed alias revision changed before successor cutover');
   const evidence=JSON.parse(output(request.imageEvidenceReference)),signature=JSON.parse(output(request.imageSignatureReference));
   const imageReleaseSha=publication.result.target.configuration.Environment.Variables.BROKER_IMAGE_RELEASE_SHA;
   const saved=store.readStep(releaseId,'cutover:prepared');
   const preparation=saved?store.getArtifact(saved.result).preparation:null;
   const evidenceTime=attempt&&preparation?.successorReconciliation?.createdAt
    ?preparation.successorReconciliation.createdAt:new Date().toISOString();
   if(authenticateImages)await authenticateImages({request,evidence,signature,imageReleaseSha,now:evidenceTime});
   else{
    assertImageEvidence(evidence,{signatureArtifact:signature,publicationSourceSha:evidence.publicationSourceSha||evidence.imageReleaseSha,
     currentSourceSha:request.releaseSourceSha,imageReleaseSha,workflowRunId:evidence.workflowRunId,
     artifactSha256:evidence.canonicalArtifactSha256,now:evidenceTime,
     verifySignature:options=>verifyImage({...options,run:awsRun})});
    assertImageEvidenceReuseBridge(evidence,{currentSourceSha:request.releaseSourceSha,
     imageReuseEvidence:deriveStageBImageImpactReport({imageReleaseSha,toolingSha:request.releaseSourceSha})});
   }
  },
  authenticatePublication:readPublication,
  materializeInputs:async({request,release,phase,prepared,publication,cutover})=>{
   const directory=phaseDirectory(release,phase),terraformDataDir=path.join(directory,'terraform'),stageFiles=files(directory),successorRecovery=paths(directory);
   ensureStageBPrivateDirectory({directory,repositoryRoot:root,create:true});
   ensureStageBPrivateDirectory({directory:terraformDataDir,repositoryRoot:root,create:true});
   const inputs={files:stageFiles,directory,terraformDataDir,successorRecovery};
   if(prepared){assert.equal(path.dirname(prepared.planPath),directory);return inputs;}
   if(phase==='closure'){
    assert.ok(cutover?.prepared?.materializationSha256,'Closure requires captured cutover material');
    await hydrateReleasePhaseMaterial({reference:cutover.prepared.materializationSha256,prepared:cutover.prepared,
     files:stageFiles,planPath:cutover.prepared.planPath,store,repositoryRoot:root});
    return inputs;
   }
   assert.equal(phase,'cutover');
   const historical=store.getArtifact(request.historicalImportReference);
   privateWrite(successorRecovery.historicalStatePath,assertHistoricalStateImport(historical,
    {releaseSourceSha:request.releaseSourceSha,recoveryToolingSha:request.recoveryToolingSha,recoveryId:request.recoveryId,
     brokerVersion:request.brokerVersion,publication:publication.result,store,verifyImport:importVerifier}));
   privateWrite(successorRecovery.imageEvidencePath,output(request.imageEvidenceReference));
   privateWrite(successorRecovery.imageSignaturePath,output(request.imageSignatureReference));
   if(!fs.existsSync(successorRecovery.currentStatePath)){
    awsRun(['s3api','get-object','--bucket',STAGE_B_TERRAFORM_BACKEND.bucketName,'--key',STAGE_B_TERRAFORM_BACKEND.stateKey,
     '--expected-bucket-owner',STAGE_B.account,'--no-cli-pager',successorRecovery.currentStatePath]);
    fs.chmodSync(successorRecovery.currentStatePath,0o600);
   }
   assertStageBPrivateFile({filePath:successorRecovery.currentStatePath,repositoryRoot:root,label:'Current Stage B state'});
   assert.equal(brokerDigest(fs.readFileSync(successorRecovery.currentStatePath)),request.currentStateSha256,
    'Current Terraform state changed after successor recovery request');
   const historicalRoot=path.join(directory,'original-source');
   ensureStageBPrivateDirectory({directory:historicalRoot,repositoryRoot:root,create:true});
   const sourcePaths=['infra/aws/terraform/lambda/production-rls-approval-broker',
    'infra/aws/terraform/production-green-stage-b/broker/deployment-contract.json',
    'documents/ops/iam/MSCQRProductionGreenStageBBrokerPackageManifest-v1.schema.json',
    'scripts/aws/production-green-stage-b-contract.mjs'];
   if(!fs.existsSync(path.join(historicalRoot,sourcePaths[0]))){
    const archive=execFileSync('git',['archive','--format=tar',request.releaseSourceSha,'--',...sourcePaths],{cwd:root,maxBuffer:64*1024*1024});
    execFileSync('tar',['-xf','-','-C',historicalRoot],{input:archive,maxBuffer:64*1024*1024});
   }
   const originalTree=deriveStageBToolingInputTreeSha256(request.releaseSourceSha);
   assert.equal(originalTree,publication.preparation.treeSha256);
   if(!fs.existsSync(stageFiles.package))await packageBroker({outputPath:stageFiles.package,manifestPath:stageFiles.packageManifest,
    toolingSha:request.releaseSourceSha,toolingTreeSha256:originalTree,repositoryRoot:historicalRoot,
    sourceDirectory:path.join(historicalRoot,sourcePaths[0])});
   assert.equal(brokerDigest(fs.readFileSync(stageFiles.package)),publication.preparation.packageSha256,
    'Reconstructed original broker differs from published version');
   const stageAState=path.join(directory,'stage-a-state.json'),stageAInput=path.join(directory,'stage-a-input.json');
   if(!fs.existsSync(stageAState)){awsRun(['s3api','get-object','--bucket',STAGE_B_TERRAFORM_BACKEND.bucketName,
    '--key',STAGE_A_STATE_OBJECT,'--expected-bucket-owner',STAGE_B.account,'--no-cli-pager',stageAState]);fs.chmodSync(stageAState,0o600);}
   if(!fs.existsSync(stageAInput))generateStageA({stateBackup:stageAState,stateObject:STAGE_A_STATE_OBJECT,
    toolingSha:request.releaseSourceSha,toolingTreeSha256:originalTree,outputPath:stageAInput,phase:'POST_APPLY',run:awsRun});
   const checksumsFile=path.join(directory,'original-release-checksums.json');
   if(!fs.existsSync(checksumsFile))privateWrite(checksumsFile,execFileSync('git',
    ['show',`${request.releaseSourceSha}:documents/security/rls-program/generated/checksums.json`],{cwd:root,maxBuffer:8*1024*1024}));
   if(!fs.existsSync(stageFiles.tfvars)){
    const evidence=JSON.parse(fs.readFileSync(successorRecovery.imageEvidencePath));
    generateTfvars({imageEvidence:successorRecovery.imageEvidencePath,imageEvidenceSignature:successorRecovery.imageSignaturePath,
     stateBackup:successorRecovery.currentStatePath,stageAInput,stageAStateBackup:stageAState,brokerPackagePath:stageFiles.package,
     toolingSha:request.releaseSourceSha,toolingTreeSha256:originalTree,imageReleaseSha:evidence.imageReleaseSha,
     workflowRunId:evidence.workflowRunId,canonicalArtifactSha256:evidence.canonicalArtifactSha256,
     checksumsFile,brokerPackageHistoricalSourceSha:request.releaseSourceSha,
     outputPath:stageFiles.tfvars,bindingReportPath:successorRecovery.bindingReportPath,
     verifySignature:options=>verifyImage({...options,run:awsRun})});
   }
   const backendConfig=path.join(directory,'backend.hcl');
   if(!fs.existsSync(backendConfig))generateStageBTerraformBackendConfig({outputPath:backendConfig});
   commandRun('terraform',[`-chdir=${terraformRoot}`,'init',`-backend-config=${backendConfig}`,'-input=false','-lockfile=readonly','-no-color'],
    {env:{...env,TF_DATA_DIR:terraformDataDir,TF_WORKSPACE:'default'}});
   ensureStageBTerraformBackendMetadataPrivate({terraformDataDir,repositoryRoot:root,normalize:true});
   return inputs;
  },
  capturePreparation:({inputs},_phase,prepared)=>captureReleasePhaseMaterial({prepared,files:inputs.files,store,repositoryRoot:root})
   .then(materializationSha256=>({...prepared,materializationSha256})),
  hydratePreparation:({inputs},_phase,prepared)=>hydrateReleasePhaseMaterial({reference:prepared.materializationSha256,prepared,
   files:inputs.files,planPath:prepared.planPath,store,repositoryRoot:root}),
  runStageOperation:request=>stage(request),
  authenticateAuthorization:(preparation,authorization,authorizedAt)=>assertBrokerAuthorization(authorization,preparation,
   {verify:verifier,now:new Date(authorizedAt||authorization.issuedAt)}),
  obtainAuthorization:(context,phase,prepared,reference)=>authorize(context,phase,prepared,reference,
   {token:env.GH_TOKEN,run:ghRun,attempts:120}),
  classifyNativeAttempt:async({inputs},phase,_prepared,authorization)=>{
   try{readReceipt({run:awsRun,id:brokerDigest(authorization),
    status:phase==='cutover'?'CUTOVER_INTENT':'STATE_REFRESH_INTENT',directory:inputs.directory});return 'RECOVER';}
   catch(error){if(error.code!=='RECEIPT_ABSENT')throw error;return 'PRE_NATIVE';}
  },
  authenticateCompletedTransition:async({inputs},phase,prepared,authorization,result)=>{
   if(phase==='cutover')equal(readReceipt({run:awsRun,id:brokerDigest(authorization),
    status:'CUTOVER_COMMITTED_STATE_PENDING',directory:inputs.directory}),result);
   else assertBrokerClosurePlan(result.closurePlan,prepared.preparation);
  },
  authenticateClosure:async({release,inputs},{cutover,closure})=>{
   const terminal=readReceipt({run:awsRun,id:stagedBrokerSourceReservation(release.sourceSha),
    status:'STAGED_BROKER_TERMINAL_HANDOFF',directory:inputs.directory});
   equal(terminal,{preparation:cutover.prepared.preparation,authorization:cutover.authorization,
    closure:{preparation:closure.prepared.preparation,authorization:closure.authorization},
    casResult:cutover.result,record:closure.result});
   return terminal;
  },
 };
}

export async function runHostedSuccessorReleaseCoordinator({recoveryReference},options={}) {
 const {runtimeFactory=createHostedSuccessorRuntime,...runtimeOptions}=options;
 return runSuccessorReleaseCoordinator({recoveryReference},runtimeFactory(runtimeOptions));
}

if(process.argv[1]===fileURLToPath(import.meta.url)){
 try{const result=await runHostedSuccessorReleaseCoordinator({recoveryReference:process.env.SUCCESSOR_RECOVERY_REFERENCE});
  process.stdout.write(`${JSON.stringify(result)}\n`);
 }catch(error){process.stderr.write(`${error.message}\n`);process.exitCode=1;}
}
