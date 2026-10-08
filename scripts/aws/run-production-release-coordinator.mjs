#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {runReleaseCoordinator,createReleaseCoordinatorStore,readHostedReleaseSource,authenticateHostedStageBImages,HOSTED_RELEASE_ROOT,
 authenticateReleaseGateRuns,captureReleasePhaseMaterial,hydrateReleasePhaseMaterial,
 obtainReleaseTransitionAuthorization} from './production-release-coordinator.mjs';
import {readReleaseGateEvidence} from '../github/check-required-workflow-gates.mjs';
import {createProductionAwsCommandRunner,PRODUCTION_AWS_CREDENTIAL_SOURCE} from './production-credential-source-contract.mjs';
import {materializeStageBPrerequisiteFiles} from './produce-production-green-stage-b-prerequisite-bundle.mjs';
import {generateStageBTerraformBackendConfig} from './generate-production-green-stage-b-backend-config.mjs';
import {ensureStageBTerraformBackendMetadataPrivate} from './stage-b-terraform-backend-contract.mjs';
import {ensureStageBPrivateDirectory,writeStageBPrivateFileAtomic} from './stage-b-artifact-contract.mjs';
import {runRefreshOnly} from '../refresh-production-green-stage-b.mjs';
import {runStagedBrokerRequest} from './run-stage-b-staged-broker.mjs';
import {readBrokerPolicyInventory} from './stage-b-staged-broker-observations.mjs';
import {createBrokerPolicyOwnershipClient} from './stage-b-broker-policy-ownership.mjs';
import {brokerDigest,assertBrokerAuthorization,assertBrokerClosurePlan,assertRegistrationHandoff,assertPolicyPruningHandoff} from './stage-b-staged-broker-contract.mjs';
import {createBrokerKmsAuthorizationBoundary} from './stage-b-staged-broker-authorization.mjs';
import {readStagedBrokerReceipt} from './stage-b-staged-broker-executor.mjs';
import {authenticateRegisteredDefinition} from './stage-b-release-prerequisites.mjs';
import {deriveStageBImageImpactReport} from './validate-stage-b-image-reuse.mjs';

const root=path.resolve(fileURLToPath(new URL('../..',import.meta.url)));
const terraformRoot=path.join(root,'infra/aws/terraform/production-green-stage-b');
const sha256=bytes=>createHash('sha256').update(bytes).digest('hex');
const exact=(left,right)=>assert.equal(brokerDigest(left),brokerDigest(right));
const phaseDirectory=(releaseId,phase)=>path.join(HOSTED_RELEASE_ROOT,releaseId,phase==='closure'?'cutover':phase);
const phaseFiles=directory=>({package:path.join(directory,'broker-package.zip'),packageManifest:path.join(directory,'broker-package.zip.manifest.json'),
 tfvars:path.join(directory,'stage-b.tfvars'),backendMetadata:path.join(directory,'terraform','terraform.tfstate')});
const shell=(command,args,options={})=>execFileSync(command,args,{cwd:root,encoding:'utf8',stdio:['ignore','pipe','pipe'],...options});

// All business writes remain inside runStagedBrokerRequest. This adapter only
// creates authenticated inputs and selects the next public operation.
export function createHostedReleaseRuntime({sourceSha,ticketId,imageTransportJson,imageTransportSha256,
 requiredGateRunIdsJson,lifecycle='strict',env=process.env,
 awsRun=createProductionAwsCommandRunner({credentialSource:PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER,env}),
 ghRun=(args,options)=>execFileSync('gh',args,{encoding:'utf8',maxBuffer:8*1024*1024,...options}),
 runStageOperation=runStagedBrokerRequest,sourceReader=readHostedReleaseSource,
 imageReader=authenticateHostedStageBImages,gateReader=readReleaseGateEvidence,
 materialize=materializeStageBPrerequisiteFiles,refresh=runRefreshOnly,
 createStore=createReleaseCoordinatorStore,verifyAuthorization,readReceipt=readStagedBrokerReceipt,
 completedRegistrationPath=path.join(root,'documents/ops/iam/MSCQRProductionStageBCompletedRegistration-2026-10-08.json')}={}) {
 assert.equal(env.GITHUB_ACTIONS,'true');assert.equal(env.GITHUB_EVENT_NAME,'workflow_dispatch');
 assert.equal(env.GITHUB_REPOSITORY,'T-ej2003/genuine-scan-main');
 assert.equal(env.GITHUB_WORKFLOW_REF,`${env.GITHUB_REPOSITORY}/.github/workflows/release-train.yml@refs/heads/main`);
 assert.match(env.GITHUB_RUN_ATTEMPT||'',/^[1-9][0-9]*$/);assert.equal(env.GITHUB_SHA,sourceSha);
 assert.match(sourceSha||'',/^[a-f0-9]{40}$/);assert.match(ticketId||'',/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/);
 assert.ok(path.isAbsolute(env.RUNNER_TEMP||''));assert.ok(/^\d+$/.test(env.GITHUB_RUN_ID||''));
 assert.equal(typeof awsRun,'function');assert.equal(typeof ghRun,'function');
 ensureStageBPrivateDirectory({directory:HOSTED_RELEASE_ROOT,repositoryRoot:root,create:true});
 const store=createStore({run:awsRun,directory:HOSTED_RELEASE_ROOT,repositoryRoot:root});
 const checker=createBrokerKmsAuthorizationBoundary({run:awsRun,githubRun:ghRun});
 const verify=verifyAuthorization||checker.verify;
 const gateIds=JSON.parse(requiredGateRunIdsJson);
 const imageArtifacts=()=>imageReader({sourceSha,transportJson:imageTransportJson,transportSha256:imageTransportSha256,run:awsRun});
 const prepareDirectory=(release,phase)=>{
  const directory=phaseDirectory(release.releaseId,phase);
  ensureStageBPrivateDirectory({directory,repositoryRoot:root,create:true});
  ensureStageBPrivateDirectory({directory:path.join(directory,'terraform'),repositoryRoot:root,create:true});
  return directory;
 };
 const githubJson=async endpoint=>JSON.parse(ghRun(['api',`repos/${env.GITHUB_REPOSITORY}${endpoint}`],{encoding:'utf8'}));
 const receipts={registration:'TASK_REGISTERED',pruning:'BROKER_POLICY_PRUNED',policy:'BROKER_POLICY_CONVERGED',publication:'PUBLISHED',cutover:'CUTOVER_COMMITTED_STATE_PENDING'};
 return {
  store,
  authenticateSource:async(source,frozen)=>{
   const observed=sourceReader(source,{run:awsRun});
   if(frozen){assert.equal(brokerDigest(observed.baseline),frozen.baselineSha256,'Deployed release baseline changed');
    assert.equal(observed.baseline.generation,frozen.baselineGeneration,'Deployed release generation changed');}
   return observed;
  },
  resolveArtifacts:async()=>imageArtifacts(),
  authenticateArtifacts:async(_release,artifacts)=>exact(artifacts,imageArtifacts()),
  resolveGates:async()=>gateReader({sourceSha,lifecycle,expectedWorkflowRunIds:gateIds,githubJson}),
  authenticateGates:async(release,evidence)=>authenticateReleaseGateRuns(release,evidence),
  materializeInputs:async(release,artifacts,{phase,prepared,adopted=false})=>{
   const directory=prepareDirectory(release,phase),terraformDataDir=path.join(directory,'terraform'),files=phaseFiles(directory);
   if(adopted){assert.equal(phase,'registration');assert.equal(prepared,null);
    return {files,directory,terraformDataDir};}
   if(prepared){
    assert.equal(path.dirname(prepared.planPath),directory,'Prepared saved plan changed hosted phase directory');
    if(!fs.existsSync(files.backendMetadata)){
     shell('terraform',[`-chdir=${terraformRoot}`,'init','-backend=false','-input=false','-lockfile=readonly'],{env:{...env,TF_DATA_DIR:terraformDataDir,TF_WORKSPACE:'default'}});
     fs.rmSync(files.backendMetadata,{force:true});
    }
    return {files,directory,terraformDataDir};
   }
   const authorizationFile=path.join(directory,'image-authorization.json');
   const current=fs.existsSync(authorizationFile)?fs.readFileSync(authorizationFile):null;
   if(current)assert.equal(sha256(current),artifacts.authorizationRawSha256,'Existing image authorization changed');
   else writeStageBPrivateFileAtomic({filePath:authorizationFile,bytes:Buffer.from(artifacts.authorizationJson),repositoryRoot:root,label:'Release image authorization'});
   const produced=await materialize({sourceSha:release.sourceSha,imageAuthorizationPath:authorizationFile,
    imageAuthorizationSha256:artifacts.authorizationRawSha256,outputDirectory:directory,run:awsRun});
   const backendConfig=path.join(directory,'backend.hcl');generateStageBTerraformBackendConfig({outputPath:backendConfig});
   shell('terraform',[`-chdir=${terraformRoot}`,'init',`-backend-config=${backendConfig}`,'-input=false','-lockfile=readonly','-no-color'],
    {env:{...env,TF_DATA_DIR:terraformDataDir,TF_WORKSPACE:'default'}});
   ensureStageBTerraformBackendMetadataPrivate({terraformDataDir,repositoryRoot:root,normalize:true});
   const bindingSha=sha256(fs.readFileSync(produced.bindingReportPath)),refreshPath=path.join(directory,'refresh-report.json');
   refresh({argv:['--closure-mode','production','--tfvars',files.tfvars,'--binding-report',produced.bindingReportPath,
    '--binding-report-sha256',bindingSha,'--stage-b-state-backup',produced.stageBStateBackupPath,
    '--tooling-sha',release.sourceSha,'--tooling-tree-sha256',produced.toolingTreeSha256,
    '--terraform-data-dir',terraformDataDir,'--backend-metadata',files.backendMetadata,'--output',refreshPath],
    env:{...env,TF_DATA_DIR:terraformDataDir,TF_WORKSPACE:'default'}});
   const planningOptions=['--binding-report',produced.bindingReportPath,'--binding-report-sha256',bindingSha,
    '--tooling-tree-sha256',produced.toolingTreeSha256,'--image-release-sha',produced.imageReleaseSha,
    '--refresh-report',refreshPath,'--refresh-report-sha256',sha256(fs.readFileSync(refreshPath)),
    '--closure-mode','production'];
   const historical=JSON.parse(fs.readFileSync(completedRegistrationPath));
   const predecessor=historical.preparation.registrationPredecessor;
   const live=readBrokerPolicyInventory(awsRun);
   const alias=JSON.parse(awsRun(['lambda','get-alias','--function-name',historical.preparation.alias.AliasArn.split(':').slice(0,-1).join(':'),'--name','reviewed','--output','json','--no-cli-pager']));
   const predecessorReceiptRecovery=phase==='registration'&&live.version==='v13'&&alias.FunctionVersion==='12'&&predecessor
    ? {registrationTransactionId:predecessor.registrationTransactionId,policyTransactionId:predecessor.policyTransactionId}:undefined;
   return {files,directory,terraformDataDir,planningOptions,...(predecessorReceiptRecovery?{predecessorReceiptRecovery}:{})};
  },
  capturePreparation:(context,_phase,prepared)=>captureReleasePhaseMaterial({prepared,files:context.inputs.files,store,repositoryRoot:root})
   .then(materializationSha256=>({...prepared,materializationSha256})),
  hydratePreparation:(context,_phase,prepared)=>hydrateReleasePhaseMaterial({reference:prepared.materializationSha256,prepared,
   files:context.inputs.files,planPath:prepared.planPath,store,repositoryRoot:root}),
  findCompletedRegistration:async(release)=>{
   const entry=JSON.parse(fs.readFileSync(completedRegistrationPath));
   const impact=deriveStageBImageImpactReport({imageReleaseSha:entry.preparation.sourceSha,toolingSha:release.sourceSha});
   return impact.imageReuseCompatible&&impact.newImagesRequired===false?entry:null;
  },
  authenticateRegistration:async(release,entry,inputs,{predecessorAdvanced=false}={})=>{
   assertRegistrationHandoff(entry,{sourceSha:release.sourceSha,treeSha256:entry.adoption?.release?.treeSha256||entry.preparation.treeSha256});
   await assertBrokerAuthorization(entry.authorization,entry.preparation,{verify,now:new Date(entry.result.authorizedAt)});
   const id=brokerDigest(entry.authorization);
   exact(readReceipt({run:awsRun,id,status:'TASK_REGISTERED',directory:inputs.directory}),entry.result);
   for(const [address,definition] of Object.entries(entry.result.definitions)){
    const observed=JSON.parse(awsRun(['ecs','describe-task-definition','--task-definition',definition.arn,'--include','TAGS','--output','json','--no-cli-pager']));
    const state={...definition.desired,arn:definition.arn,revision:definition.revision};
    exact(authenticateRegisteredDefinition({address,desired:definition.desired,state,observed:{...observed.taskDefinition,tags:observed.tags}}),definition);
   }
   if(entry.adoption&&!predecessorAdvanced){
    const observed=await runStageOperation({...inputs,predecessorReceiptRecovery:undefined,operation:'prepare-registration-adoption',
     prerequisiteChain:{registration:{preparation:entry.preparation,authorization:entry.authorization,result:entry.result}}});
    exact(observed.prerequisiteChain.registration,entry);
   }
  },
  runStageOperation:request=>runStageOperation(request),
  readRecoveredTransition:async(context,name,_prepared,authorization,result)=>{
   if(name==='pruning'||name==='policy')return readReceipt({run:awsRun,id:brokerDigest(authorization),
    status:name==='pruning'?'BROKER_POLICY_PRUNED':'BROKER_POLICY_CONVERGED',directory:context.inputs.directory,allowPolicyNoWrite:true});
   return result;
  },
  now:()=>new Date(),
  authenticateAuthorization:(preparation,authorization)=>assertBrokerAuthorization(authorization,preparation,{verify,now:new Date(authorization.issuedAt)}),
  authenticateCompletedTransition:async(context,name,prepared,authorization,result)=>{
   const cutover=name==='closure'?store.readStep(context.release.releaseId,'cutover:result'):null;
   const casResult=cutover?store.getArtifact(cutover.result):undefined;
   await assertBrokerAuthorization(authorization,prepared.preparation,{verify,
    now:new Date(name==='closure'?casResult?.authorizedAt:result.authorizedAt)});
   if(name==='registration')assertRegistrationHandoff({preparation:prepared.preparation,authorization,result},
    {sourceSha:context.release.sourceSha,treeSha256:prepared.preparation.treeSha256});
   else if(name==='pruning')assertPolicyPruningHandoff({preparation:prepared.preparation,authorization,result},prepared.preparation.prerequisiteChain);
   else if(name==='closure')assertBrokerClosurePlan(result.closurePlan,prepared.preparation);
   else{assert.equal(result.preparationSha256,brokerDigest(prepared.preparation));assert.equal(result.authorizationSha256,brokerDigest(authorization));}
   // A durable result is historical evidence. Re-running its recovery after a
   // later phase advanced Terraform or the alias would incorrectly demand the
   // old predecessor still be current. The next public phase authenticates
   // live state; terminal recovery authenticates the final live state.
   if(name==='closure'){
    const recovered=await runStageOperation({...context.inputs,operation:'recover-reconciliation',preparation:prepared.preparation,
     authorization,planPath:prepared.planPath,casResult});
    exact(recovered,result);
   }else exact(readReceipt({run:awsRun,id:brokerDigest(authorization),status:receipts[name],
    directory:context.inputs.directory,allowPolicyNoWrite:name==='pruning'||name==='policy'}),result);
  },
  authenticatePolicyRetention:async()=>{
   const owner=createBrokerPolicyOwnershipClient({run:awsRun}).read();
   assert.ok(owner?.status==='RELEASED'&&owner.terminal?.outcome==='SUCCEEDED','Active policy owner requires recovery before retention');
   const live=readBrokerPolicyInventory(awsRun),versions=live.versions;
   const inventory=versions.map(version=>{
    const response=JSON.parse(awsRun(['iam','get-policy-version','--policy-arn',owner.identity.policyArn,
     '--version-id',version.VersionId,'--output','json','--no-cli-pager']));
    assert.equal(response.PolicyVersion.VersionId,version.VersionId);
    const encoded=response.PolicyVersion.Document;
    const document=typeof encoded==='string'?JSON.parse(decodeURIComponent(encoded)):encoded;
    return {versionId:version.VersionId,isDefault:version.IsDefaultVersion,createDate:version.CreateDate,
     documentSha256:brokerDigest(document)};
   });
   const nonDefault=inventory.filter(v=>!v.isDefault).sort((a,b)=>Date.parse(b.createDate)-Date.parse(a.createDate));
   const protectedVersionIds=[live.version,...nonDefault.slice(0,1).map(v=>v.versionId)];
   return {inventory,protectedVersionIds,obsoleteVersionIds:nonDefault.slice(1).map(v=>v.versionId)};
  },
  obtainAuthorization:(context,phase,prepared,reference)=>obtainReleaseTransitionAuthorization(context,phase,prepared,reference,
   {token:env.GH_TOKEN,run:ghRun,attempts:120}),
  authenticateClosure:async(context,packages)=>{
   const p=packages.cutover.prepared.preparation,result=packages.closure.result;
   assertBrokerClosurePlan(result.closurePlan,p);
   return readReceipt({run:awsRun,id:brokerDigest(packages.cutover.authorization),status:'STAGED_BROKER_TERMINAL_HANDOFF',directory:context.inputs.directory});
  },
 };
}

export async function runHostedReleaseCoordinator({sourceSha,ticketId,imageTransportJson,imageTransportSha256,requiredGateRunIdsJson,lifecycle='strict'},options={}){
 const {runtimeFactory=createHostedReleaseRuntime,...runtimeOptions}=options;
 const runtime=runtimeFactory({sourceSha,ticketId,imageTransportJson,imageTransportSha256,requiredGateRunIdsJson,lifecycle,...runtimeOptions});
 return runReleaseCoordinator({sourceSha,ticketId},runtime);
}

export function hostedReleaseTrainRequest(env=process.env){
 return {sourceSha:env.TARGET_SHA,ticketId:env.RELEASE_TICKET_ID,imageTransportJson:env.NORMAL_IMAGE_AUTHORIZATION_JSON,
  imageTransportSha256:env.NORMAL_IMAGE_AUTHORIZATION_SHA256,requiredGateRunIdsJson:env.REQUIRED_GATE_RUN_IDS_JSON,
  lifecycle:env.RELEASE_LIFECYCLE};
}

if(process.argv[1]===fileURLToPath(import.meta.url)){
 try{
  const result=await runHostedReleaseCoordinator(hostedReleaseTrainRequest());
  process.stdout.write(`${JSON.stringify(result)}\n`);
 }catch(error){process.stderr.write(`${error.message}\n`);process.exitCode=1;}
}
