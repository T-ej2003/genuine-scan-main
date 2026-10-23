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
import {ensureStageBTerraformBackendMetadataPrivate,writeStageBTerraformStateBackup} from './stage-b-terraform-backend-contract.mjs';
import {ensureStageBPrivateDirectory,writeStageBPrivateFileAtomic} from './stage-b-artifact-contract.mjs';
import {runRefreshOnly} from '../refresh-production-green-stage-b.mjs';
import {runStagedBrokerRequest} from './run-stage-b-staged-broker.mjs';
import {readBrokerPolicyInventory} from './stage-b-staged-broker-observations.mjs';
import {createBrokerPolicyOwnershipClient} from './stage-b-broker-policy-ownership.mjs';
import {brokerDigest,assertBrokerAuthorization,assertBrokerClosurePlan,assertRegistrationHandoff,assertPolicyPruningHandoff} from './stage-b-staged-broker-contract.mjs';
import {createBrokerKmsAuthorizationBoundary} from './stage-b-staged-broker-authorization.mjs';
import {readStagedBrokerReceipt,stagedBrokerSourceReservation,assertReceiptBoundGitAncestry} from './stage-b-staged-broker-executor.mjs';
import {readStagedBrokerClosure,assertStagedBrokerProof} from './stage-b-staged-broker-closure.mjs';
import {readStageBProtectedMainCheckout} from './stage-b-deployment-identity.mjs';
import {authenticateReceiptBoundRegisteredDefinition,deriveBrokerPolicy,TASK_REGISTRATION_ADDRESSES} from './stage-b-release-prerequisites.mjs';
import {deriveStageBImageImpactReport,deriveStageBToolingInputTreeSha256} from './validate-stage-b-image-reuse.mjs';

const root=path.resolve(fileURLToPath(new URL('../..',import.meta.url)));
const terraformRoot=path.join(root,'infra/aws/terraform/production-green-stage-b');
const sha256=bytes=>createHash('sha256').update(bytes).digest('hex');
const exact=(left,right)=>assert.equal(brokerDigest(left),brokerDigest(right));
const phaseDirectory=(releaseId,phase)=>path.join(HOSTED_RELEASE_ROOT,releaseId,phase==='closure'?'cutover':phase);
const phaseFiles=directory=>({package:path.join(directory,'broker-package.zip'),packageManifest:path.join(directory,'broker-package.zip.manifest.json'),
 tfvars:path.join(directory,'stage-b.tfvars'),backendMetadata:path.join(directory,'terraform','terraform.tfstate')});
const shell=(command,args,options={})=>execFileSync(command,args,{cwd:root,encoding:'utf8',stdio:['ignore','pipe','pipe'],...options});

export function registeredTaskStateFromBytes(bytes,expected,addresses){
 const state=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
 assert.equal(sha256(bytes),expected.stateSha256,'Registered task Terraform state changed');
 assert.equal(state.lineage,expected.lineage);assert.equal(state.serial,expected.serial);assert.equal(state.version,4);
 return Object.fromEntries(addresses.map(address=>{
  const match=/^(\w+)\.(\w+)(?:\["([^"]+)"\])?$/.exec(address);assert.ok(match);
  const [,type,name,index]=match;
  const resources=state.resources.filter(r=>!r.module&&r.mode==='managed'&&r.type===type&&r.name===name);
  assert.equal(resources.length,1,`Terraform task resource differs: ${address}`);
  const instances=resources[0].instances.filter(i=>i.deposed===undefined&&i.index_key===index);
  assert.equal(instances.length,1,`Terraform task instance differs: ${address}`);
  return [address,instances[0].attributes];
 }));
}

// Resolve immutable coordinator authority, never a caller-supplied local file.
export async function readDurableCompletedRegistration({store,sourceSha,ticketId}) {
 assert.match(sourceSha||'',/^[a-f0-9]{40}$/);
 const start=await store.readStart({sourceSha,ticketId});assert.ok(start,'Missing predecessor coordinator start');
 assert.deepEqual(Object.keys(start).sort(),['baseline','release']);
 const get=async reference=>{assert.match(reference||'',/^[a-f0-9]{64}$/);const value=await store.getArtifact(reference);assert.equal(brokerDigest(value),reference,'Predecessor artifact substitution');return value;};
 const release=await get(start.release),{releaseId,...identity}=release;
 assert.equal(brokerDigest(identity),releaseId);assert.equal(release.sourceSha,sourceSha);assert.equal(release.ticketId,ticketId);
 assert.equal(brokerDigest(await get(start.baseline)),release.baselineSha256);
 const record=await store.readStep(releaseId,'registration:result');assert.ok(record,'Missing completed predecessor registration');
 assert.equal(record.releaseId,releaseId);assert.equal(record.sourceSha,sourceSha);assert.equal(record.name,'registration:result');
 const prepared=await get(record.prepared),authorization=await get(record.authorization),result=await get(record.result);
 const entry={preparation:prepared.preparation,authorization,result};
 assertRegistrationHandoff(entry,{sourceSha,treeSha256:entry.preparation.treeSha256});
 assert.equal(result.status,'REGISTERED_NONTERMINAL');assert.equal(result.savedPlanSha256,entry.preparation.savedPlanSha256);
 assert.deepEqual(Object.keys(result.definitions).sort(),TASK_REGISTRATION_ADDRESSES.slice().sort(),'Incomplete predecessor registration');
 if(authorization.schemaVersion===2){
  assert.equal(authorization.release.releaseId,releaseId);assert.equal(authorization.release.phase,'registration');
  assert.equal(authorization.release.preparationReference,brokerDigest(prepared));
 }
 return entry;
}

// Select only a completed, signed predecessor. The native receipt and live
// policy/runtime split are reauthenticated by the existing registration path.
export async function readDurablePrepublicationPredecessor({store,sourceSha,ticketId,currentSourceSha,verify}) {
 assertReceiptBoundGitAncestry({historicalSourceSha:sourceSha,consumerSourceSha:currentSourceSha,cwd:root});
 assert.notEqual(sourceSha,currentSourceSha,'Prepublication predecessor must be historical');
 const registration=await readDurableCompletedRegistration({store,sourceSha,ticketId});
 await assertBrokerAuthorization(registration.authorization,registration.preparation,
  {verify,now:new Date(registration.result.authorizedAt)});
 const start=await store.readStart({sourceSha,ticketId});
 const release=await store.getArtifact(start.release);
 const record=await store.readStep(release.releaseId,'policy:result');
 assert.ok(record,'Missing completed predecessor policy');
 assert.equal(record.releaseId,release.releaseId);assert.equal(record.sourceSha,sourceSha);
 assert.equal(record.name,'policy:result');
 const prepared=await store.getArtifact(record.prepared),authorization=await store.getArtifact(record.authorization);
 const result=await store.getArtifact(record.result);
 assert.equal(result.status,'BROKER_POLICY_CONVERGED_NONTERMINAL');assert.equal(result.sourceSha,sourceSha);
 assert.equal(authorization.schemaVersion,2,'Predecessor policy requires release-bound authorization');
 assert.ok(Number.isSafeInteger(authorization.release?.authorizationRound)&&authorization.release.authorizationRound>=0);
 assert.deepEqual(authorization.release,{releaseId:release.releaseId,phase:'policy',
  preparationReference:record.prepared,authorizationRound:authorization.release.authorizationRound});
 assert.equal(result.authorizationSha256,brokerDigest(authorization));
 assert.equal(result.preparationSha256,brokerDigest(prepared.preparation));
 exact(result.successorIdentity.policy,result.policy);
 exact(result.successorIdentity.taskMap,registration.result.taskMap);
 await assertBrokerAuthorization(authorization,prepared.preparation,{verify,now:new Date(result.authorizedAt)});
 return {sourceSha,ticketId,registrationTransactionId:brokerDigest(registration.authorization),
  policyTransactionId:brokerDigest(authorization)};
}

export async function pinPrepublicationPredecessor({store,release,sourceSha,ticketId,verify,
 read=readDurablePrepublicationPredecessor}) {
 assert.match(sourceSha||'',/^[a-f0-9]{40}$/);
 assert.match(ticketId||'',/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/);
 const selection=await read({store,sourceSha,ticketId,currentSourceSha:release.sourceSha,verify});
 assert.deepEqual(Object.keys(selection).sort(),['sourceSha','ticketId','registrationTransactionId','policyTransactionId'].sort());
 assert.equal(selection.sourceSha,sourceSha);assert.equal(selection.ticketId,ticketId);
 for(const id of [selection.registrationTransactionId,selection.policyTransactionId])assert.match(id||'',/^[a-f0-9]{64}$/);
 const name='PREPUBLICATION_PREDECESSOR',existing=await store.readStep(release.releaseId,name);
 if(existing){
  assert.equal(existing.releaseId,release.releaseId);assert.equal(existing.sourceSha,release.sourceSha);
  assert.equal(existing.name,name);exact(existing.selection,selection);
 }else await store.writeStep({releaseId:release.releaseId,sourceSha:release.sourceSha,name,selection});
 return {registrationTransactionId:selection.registrationTransactionId,policyTransactionId:selection.policyTransactionId};
}

// All business writes remain inside runStagedBrokerRequest. This adapter only
// creates authenticated inputs and selects the next public operation.
export function createHostedReleaseRuntime({sourceSha,ticketId,imageTransportJson,imageTransportSha256,
 requiredGateRunIdsJson,lifecycle='strict',completedBrokerClosureSourceSha,env=process.env,
 awsRun=createProductionAwsCommandRunner({credentialSource:PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER,env}),
 ghRun=(args,options)=>execFileSync('gh',args,{encoding:'utf8',maxBuffer:8*1024*1024,...options}),
 runStageOperation=runStagedBrokerRequest,sourceReader=readHostedReleaseSource,
 imageReader=authenticateHostedStageBImages,gateReader=readReleaseGateEvidence,
 materialize=materializeStageBPrerequisiteFiles,refresh=runRefreshOnly,
 createStore=createReleaseCoordinatorStore,verifyAuthorization,readReceipt=readStagedBrokerReceipt,
 readPrepublicationPredecessor=readDurablePrepublicationPredecessor,
 readClosure=readStagedBrokerClosure,protectedCheckout=readStageBProtectedMainCheckout,
 imageImpact=deriveStageBImageImpactReport,
 completedRegistrationPath=path.join(root,'documents/ops/iam/MSCQRProductionStageBCompletedRegistration-2026-10-08.json')}={}) {
 if(lifecycle==='prerequisites')assert.equal(env.RELEASE_PREREQUISITES_ONLY,'true','Prerequisite gates require explicit prerequisite-only execution');
 assert.equal(env.GITHUB_ACTIONS,'true');assert.equal(env.GITHUB_EVENT_NAME,'workflow_dispatch');
 assert.equal(env.GITHUB_REPOSITORY,'T-ej2003/genuine-scan-main');
 assert.equal(env.GITHUB_WORKFLOW_REF,`${env.GITHUB_REPOSITORY}/.github/workflows/release-train.yml@refs/heads/main`);
 assert.match(env.GITHUB_RUN_ATTEMPT||'',/^[1-9][0-9]*$/);assert.equal(env.GITHUB_SHA,sourceSha);
 assert.match(sourceSha||'',/^[a-f0-9]{40}$/);assert.match(ticketId||'',/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/);
 const completedClosureSourceSha=completedBrokerClosureSourceSha??env.COMPLETED_BROKER_CLOSURE_SOURCE_SHA;
 if(completedClosureSourceSha!==undefined&&completedClosureSourceSha!=='')assert.match(completedClosureSourceSha,/^[a-f0-9]{40}$/);
 const predecessorSourceSha=env.PREPUBLICATION_PREDECESSOR_SOURCE_SHA||undefined;
 const predecessorTicketId=env.PREPUBLICATION_PREDECESSOR_TICKET_ID||undefined;
 assert.equal(Boolean(predecessorSourceSha),Boolean(predecessorTicketId),'Prepublication predecessor source and ticket must be supplied together');
 if(predecessorSourceSha){assert.match(predecessorSourceSha,/^[a-f0-9]{40}$/);assert.match(predecessorTicketId,/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/);}
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
 const registeredState=(expected,addresses)=>{
  const directory=fs.mkdtempSync(path.join(HOSTED_RELEASE_ROOT,'.adoption-state-'));fs.chmodSync(directory,0o700);
  try{
   const file=path.join(directory,'terraform.tfstate');writeStageBTerraformStateBackup({run:awsRun,output:file});
   return registeredTaskStateFromBytes(fs.readFileSync(file),expected,addresses);
  }finally{fs.rmSync(directory,{recursive:true,force:true});}
 };
 const githubJson=async endpoint=>JSON.parse(ghRun(['api',`repos/${env.GITHUB_REPOSITORY}${endpoint}`],{encoding:'utf8'}));
 const receipts={registration:'TASK_REGISTERED',pruning:'BROKER_POLICY_PRUNED',policy:'BROKER_POLICY_CONVERGED',publication:'PUBLISHED',cutover:'CUTOVER_COMMITTED_STATE_PENDING'};
 const runtime={
  gateLifecycle:lifecycle,
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
  authenticateGates:async(release,evidence)=>{assert.equal(evidence.lifecycle,lifecycle,'Gate lifecycle substitution');return authenticateReleaseGateRuns(release,evidence);},
  materializeInputs:async(release,artifacts,{phase,prepared,adopted=false})=>{
   const pinned=await store.readStep(release.releaseId,'PREPUBLICATION_PREDECESSOR');
   if(pinned){
    assert.equal(pinned.releaseId,release.releaseId);assert.equal(pinned.sourceSha,release.sourceSha);
    assert.equal(pinned.name,'PREPUBLICATION_PREDECESSOR');
    assert.equal(pinned.selection.sourceSha,predecessorSourceSha,'Prepublication predecessor source changed');
    assert.equal(pinned.selection.ticketId,predecessorTicketId,'Prepublication predecessor ticket changed');
   }
   const directory=prepareDirectory(release,phase),terraformDataDir=path.join(directory,'terraform'),files=phaseFiles(directory);
   if(['cutover','closure'].includes(phase)&&(!prepared||prepared.brokerPackagePath)){
    const published=phaseFiles(phaseDirectory(release.releaseId,'publication'));
    if(prepared)assert.equal(prepared.brokerPackagePath,published.package,'Prepared cutover package path changed');
    files.package=published.package;files.packageManifest=published.packageManifest;
    if(phase==='cutover'&&!prepared){
     const record=await store.readStep(release.releaseId,'publication:result');
     assert.ok(record,'Cutover requires completed broker publication');
     assert.equal(record.sourceSha,release.sourceSha,'Publication source changed');
     assert.equal(record.releaseId,release.releaseId,'Publication release changed');
     assert.equal(record.name,'publication:result','Publication step changed');
     const publication=await store.getArtifact(record.prepared);
     assert.equal(brokerDigest(fs.readFileSync(files.package)),publication.preparation.packageSha256,
      'Cutover package differs from authenticated publication');
    }
   }
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
    imageAuthorizationSha256:artifacts.authorizationRawSha256,outputDirectory:directory,
    ...(phase==='cutover'?{existingBrokerPackagePath:files.package}:{}),run:awsRun});
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
   let predecessorReceiptRecovery;
   if(phase==='registration'&&predecessorSourceSha){
    predecessorReceiptRecovery=await pinPrepublicationPredecessor({store,release,sourceSha:predecessorSourceSha,
     ticketId:predecessorTicketId,verify,read:readPrepublicationPredecessor});
   }else if(phase==='registration'&&live.version==='v13'&&alias.FunctionVersion==='12'&&predecessor){
    predecessorReceiptRecovery={registrationTransactionId:predecessor.registrationTransactionId,
     policyTransactionId:predecessor.policyTransactionId};
   }
   return {files,directory,terraformDataDir,planningOptions,...(predecessorReceiptRecovery?{predecessorReceiptRecovery}:{})};
  },
  capturePreparation:(context,phase,prepared)=>captureReleasePhaseMaterial({prepared,files:context.inputs.files,store,repositoryRoot:root})
   .then(materializationSha256=>({...prepared,materializationSha256,
    ...(['cutover','closure'].includes(phase)&&context.inputs.files.package===phaseFiles(phaseDirectory(context.release.releaseId,'publication')).package
     ?{brokerPackagePath:context.inputs.files.package}:{})})),
  hydratePreparation:(context,_phase,prepared)=>hydrateReleasePhaseMaterial({reference:prepared.materializationSha256,prepared,
   files:context.inputs.files,planPath:prepared.planPath,store,repositoryRoot:root,run:awsRun}),
  findCompletedRegistration:async(release)=>{
   const {completedRegistrationSourceSha,completedRegistrationTicketId}=imageArtifacts();
   const entry=completedRegistrationSourceSha
    ? await readDurableCompletedRegistration({store,sourceSha:completedRegistrationSourceSha,ticketId:completedRegistrationTicketId||ticketId})
    : JSON.parse(fs.readFileSync(completedRegistrationPath));
   const impact=imageImpact({imageReleaseSha:entry.preparation.sourceSha,toolingSha:release.sourceSha});
   if(completedRegistrationSourceSha){
    assert.ok(impact.imageReuseCompatible&&impact.newImagesRequired===false,'Predecessor registration is incompatible with current source');
    await assertBrokerAuthorization(entry.authorization,entry.preparation,{verify,now:new Date(entry.result.authorizedAt)});
    const directory=prepareDirectory(release,'registration');
    exact(readReceipt({run:awsRun,id:brokerDigest(entry.authorization),status:'TASK_REGISTERED',directory}),entry.result);
   }
   return impact.imageReuseCompatible&&impact.newImagesRequired===false?entry:null;
  },
  findCompletedBrokerClosure:async(release,registration)=>{
   if(!completedClosureSourceSha)return null;
   assert.ok(registration,'Broker closure adoption requires a completed registration');
   const terminal=readReceipt({run:awsRun,id:stagedBrokerSourceReservation(completedClosureSourceSha),
    status:'STAGED_BROKER_TERMINAL_HANDOFF',directory:HOSTED_RELEASE_ROOT});
   return {sourceSha:completedClosureSourceSha,terminalSha256:brokerDigest(terminal),
    closureSha256:brokerDigest(terminal.record),registrationTransactionId:registration.result.authorizationSha256};
  },
  authenticateCompletedBrokerClosure:async(release,registration,candidate)=>{
   assert.deepEqual(Object.keys(candidate).sort(),['closureSha256','registrationTransactionId','sourceSha','terminalSha256']);
   assert.match(candidate.sourceSha,/^[a-f0-9]{40}$/);
   if(completedClosureSourceSha)assert.equal(candidate.sourceSha,completedClosureSourceSha,'Broker closure source substituted');
   assert.equal(candidate.registrationTransactionId,registration.result.authorizationSha256);
   assertReceiptBoundGitAncestry({historicalSourceSha:registration.preparation.sourceSha,
    consumerSourceSha:candidate.sourceSha,cwd:root});
   const proof=await readClosure({sourceSha:candidate.sourceSha,run:awsRun,readCheckout:()=>{
    const checkout=protectedCheckout({cwd:root,fetchOriginMain:true,
     expectedSourceSha:release.sourceSha,requireCanonicalRepository:true});
    return {sourceSha:checkout.currentHead,treeSha256:deriveStageBToolingInputTreeSha256(checkout.currentHead)};
   }});
   assert.ok(proof,'Completed broker closure source is absent');
   assertStagedBrokerProof(proof,candidate.sourceSha);
   assertReceiptBoundGitAncestry({historicalSourceSha:proof.tooling.sourceSha,
    consumerSourceSha:release.sourceSha,cwd:root});
   assert.equal(proof.evidenceSha256,candidate.closureSha256,'Broker closure proof changed');
   const terminal=readReceipt({run:awsRun,id:stagedBrokerSourceReservation(candidate.sourceSha),
    status:'STAGED_BROKER_TERMINAL_HANDOFF',directory:HOSTED_RELEASE_ROOT});
   assert.equal(brokerDigest(terminal),candidate.terminalSha256,'Broker terminal receipt changed');
   assert.equal(brokerDigest(terminal.record),proof.evidenceSha256);
   assert.equal(terminal.record.alias.FunctionVersion,terminal.preparation.target.version);
   exact(terminal.preparation.prerequisites.taskMap,registration.result.taskMap);
   const stateByAddress=registeredState(terminal.record.stateAfter,Object.keys(registration.result.definitions));
   await runtime.authenticateRegistration({sourceSha:registration.preparation.sourceSha},registration,
    {directory:HOSTED_RELEASE_ROOT},{predecessorAdvanced:true,stateByAddress});
   await proof.revalidate();
   return terminal;
  },
  authenticateRegistration:async(release,entry,inputs,{predecessorAdvanced=false,stateByAddress}={})=>{
   assertRegistrationHandoff(entry,{sourceSha:release.sourceSha,treeSha256:entry.adoption?.release?.treeSha256||entry.preparation.treeSha256});
   await assertBrokerAuthorization(entry.authorization,entry.preparation,{verify,now:new Date(entry.result.authorizedAt)});
   const id=brokerDigest(entry.authorization);
   exact(readReceipt({run:awsRun,id,status:'TASK_REGISTERED',directory:inputs.directory}),entry.result);
   for(const [address,definition] of Object.entries(entry.result.definitions)){
    const observed=JSON.parse(awsRun(['ecs','describe-task-definition','--task-definition',definition.arn,'--include','TAGS','--output','json','--no-cli-pager']));
    const state=stateByAddress?stateByAddress[address]:{...definition.desired,arn:definition.arn,revision:definition.revision};
    assert.ok(state,`Missing Terraform task binding: ${address}`);
    exact(authenticateReceiptBoundRegisteredDefinition({address,desired:definition.desired,state,
     observed:{...observed.taskDefinition,tags:observed.tags},receipt:definition}),definition);
   }
   if(entry.adoption&&!predecessorAdvanced){
    const observed=await runStageOperation({...inputs,predecessorReceiptRecovery:undefined,operation:'prepare-registration-adoption',
     prerequisiteChain:{registration:{preparation:entry.preparation,authorization:entry.authorization,result:entry.result}}});
    exact(observed.prerequisiteChain.registration,entry);
   }
  },
  runStageOperation:request=>runStageOperation(request),
  classifyNativeAttempt:async(context,name,_prepared,authorization)=>{
   const id=brokerDigest(authorization),status={registration:'TASK_REGISTRATION_INTENT',pruning:'BROKER_POLICY_PRUNING_INTENT',
    policy:'BROKER_POLICY_INTENT',publication:'PUBLICATION_INTENT',cutover:'CUTOVER_INTENT',closure:'STATE_REFRESH_INTENT'}[name];
   assert.ok(status,'Unknown Stage B transition');
   try {readReceipt({run:awsRun,id,status,directory:context.inputs.directory});return 'RECOVER';}
   catch(error){if(error.code!=='RECEIPT_ABSENT')throw error;}
   if(name==='pruning'||name==='policy'){
    const owner=createBrokerPolicyOwnershipClient({run:awsRun}).read();
    if(owner?.identity?.operationIdentity===id){
     assert.equal(owner.identity.sourceSha,context.release.sourceSha);
     return 'RECOVER';
    }
   }
   return 'PRE_NATIVE';
  },
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
    now:new Date(name==='closure'?result.stateAuthorizedAt:result.authorizedAt)});
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
    const cutoverPrepared=store.getArtifact(cutover.prepared),cutoverAuthorization=store.getArtifact(cutover.authorization);
    const recovered=await runStageOperation({...context.inputs,operation:'recover-reconciliation',preparation:prepared.preparation,
     authorization,planPath:prepared.planPath,casResult,cutoverPreparation:cutoverPrepared.preparation,cutoverAuthorization});
    exact(recovered,result);
   }else exact(readReceipt({run:awsRun,id:brokerDigest(authorization),status:receipts[name],
    directory:context.inputs.directory,allowPolicyNoWrite:name==='pruning'||name==='policy'}),result);
  },
  authenticatePolicyRetention:async(_context,chain)=>{
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
   const noOpPolicyCandidate=chain?.registration&&brokerDigest(deriveBrokerPolicy(live.policy,chain.registration.result.taskMap))===brokerDigest(live.policy);
   return {inventory,protectedVersionIds,obsoleteVersionIds:nonDefault.slice(1).map(v=>v.versionId),
    ...(inventory.length===5?{noOpPolicyCandidate:Boolean(noOpPolicyCandidate)}:{})};
  },
  obtainAuthorization:(context,phase,prepared,reference)=>obtainReleaseTransitionAuthorization(context,phase,prepared,reference,
   {token:env.GH_TOKEN,run:ghRun,attempts:120}),
  authenticateClosure:async(context,packages)=>{
   const p=packages.cutover.prepared.preparation,result=packages.closure.result;
   assertBrokerClosurePlan(result.closurePlan,p);
   const terminal=readReceipt({run:awsRun,id:stagedBrokerSourceReservation(context.release.sourceSha),status:'STAGED_BROKER_TERMINAL_HANDOFF',directory:context.inputs.directory});
   exact(terminal,{preparation:p,authorization:packages.cutover.authorization,
    closure:{preparation:packages.closure.prepared.preparation,authorization:packages.closure.authorization},
    casResult:packages.cutover.result,record:result});
   return terminal;
  },
 };
 return runtime;
}

export async function runHostedReleaseCoordinator({sourceSha,ticketId,imageTransportJson,imageTransportSha256,requiredGateRunIdsJson,lifecycle='strict',completedBrokerClosureSourceSha},options={}){
 const {runtimeFactory=createHostedReleaseRuntime,...runtimeOptions}=options;
 const runtime=runtimeFactory({sourceSha,ticketId,imageTransportJson,imageTransportSha256,requiredGateRunIdsJson,lifecycle,completedBrokerClosureSourceSha,...runtimeOptions});
 return runReleaseCoordinator({sourceSha,ticketId},runtime);
}

export function hostedReleaseTrainRequest(env=process.env){
 return {sourceSha:env.TARGET_SHA,ticketId:env.RELEASE_TICKET_ID,imageTransportJson:env.NORMAL_IMAGE_AUTHORIZATION_JSON,
  imageTransportSha256:env.NORMAL_IMAGE_AUTHORIZATION_SHA256,requiredGateRunIdsJson:env.REQUIRED_GATE_RUN_IDS_JSON,
  lifecycle:env.RELEASE_LIFECYCLE,completedBrokerClosureSourceSha:env.COMPLETED_BROKER_CLOSURE_SOURCE_SHA};
}

if(process.argv[1]===fileURLToPath(import.meta.url)){
 try{
  const result=await runHostedReleaseCoordinator(hostedReleaseTrainRequest());
  process.stdout.write(`${JSON.stringify(result)}\n`);
 }catch(error){process.stderr.write(`${error.message}\n`);process.exitCode=1;}
}
