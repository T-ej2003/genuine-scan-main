#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {execFileSync,spawnSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';
import {brokerDigest} from './stage-b-staged-broker-contract.mjs';
import {assertBridgeRequest,bridgeOperationId,bridgeOperatorClaimPhase,bridgeOperatorExpiryAction,bridgeRequestForSign,classifyBridgeNativeResult} from './production-release-bridge-contract.mjs';
import {verifyBridgeCapturedSign} from './production-release-bridge-sign-journal.mjs';
import {authenticateBridgeEnvironmentApproval} from './verify-production-release-terminal-bridge.mjs';
import {assertBridgeManifest} from './production-release-bridge-manifest.mjs';
import {createReleaseCoordinatorStore} from './production-release-evidence-store.mjs';
import {createProductionAwsCommandRunner,PRODUCTION_AWS_CREDENTIAL_SOURCE} from './production-credential-source-contract.mjs';
import {assertProductionEnvironmentApprovalIdentity,PRODUCTION_ENVIRONMENT_APPROVAL,fetchProductionEnvironmentApprovalEvidence} from './production-github-environment-approval.mjs';
import {readGitHubApiToken} from './production-qr-version-selector-resolution.mjs';
import {readStageBPrivateFileBytes} from './stage-b-artifact-contract.mjs';
import {readStageBProtectedMainCheckout} from './stage-b-deployment-identity.mjs';
import {assertReadyForOverlapDeployment} from './production-overlap-readiness-contract.mjs';
import {readTerminalOwner} from './production-release-bridge-terminal-owner.mjs';
import {assertBridgeNativeResult} from './production-release-bridge-native-result.mjs';
import {readBridgeNativeAudit} from './production-release-bridge-native-audit.mjs';
import {assertBridgeNativeAttestationRequest,signBridgeNativeAttestationOnce} from './production-release-bridge-native-attestation.mjs';

const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const argv=(value)=>Object.fromEntries(value.slice(0).reduce((items,item,index)=>{if(index%2===0)items.push([item,value[index+1]]);return items;},[]));
const replace=(args,runtime)=>args.map(value=>value==='@RUNTIME_CONFIG'?runtime.configPath:value==='@RUNTIME_CONFIG_SHA256'?runtime.runtimeConfigSha256:value);
const scripts=Object.freeze({root:'produce-production-root-drop-evidence.mjs',runtime:'prepare-production-cutover-runtime.mjs',adoption:'prepare-completed-inventory-adoption.mjs',successor:'prepare-production-rotation-successor.mjs',operator:'run-production-cutover-operator.mjs'});

export function recoverMaterializedBridgeRuntime({outputDirectory,sourceSha,rotationId,rootDropPath,repositoryRoot=process.cwd()}={}){
 const configPath=path.join(path.resolve(outputDirectory),'rotation-config.json');
 if(!fs.existsSync(configPath))return null;
 const configBytes=readStageBPrivateFileBytes({filePath:configPath,repositoryRoot,label:'Materialized rotation config'}).bytes;
 const manifestPath=path.join(path.resolve(outputDirectory),'cutover-runtime-manifest.json');
 const manifest=JSON.parse(readStageBPrivateFileBytes({filePath:manifestPath,repositoryRoot,label:'Materialized cutover manifest'}).bytes);
 const config=JSON.parse(configBytes);
 assert.equal(manifest.generatedBy,'scripts/aws/prepare-production-cutover-runtime.mjs');
 assert.equal(manifest.readyToConsumeMfa,true);assert.deepEqual(manifest.blockers,[]);
 assert.equal(manifest.runtimeConfigSha256,hash(configBytes));
 assert.equal(manifest.staticBindingSha256,brokerDigest(config));
 assert.equal(manifest.protectedMainSha,sourceSha);assert.equal(manifest.releaseSourceSha,sourceSha);
 assert.equal(config.sourceSha,sourceSha);assert.equal(config.rotationId,rotationId);
 assert.equal(path.resolve(config.rootDropEvidenceFile),path.resolve(rootDropPath));
 return {READY_TO_CONSUME_MFA:true,ROTATION_CONFIG:configPath,ROTATION_CONFIG_SHA256:manifest.runtimeConfigSha256,RELEASE_SOURCE_SHA:sourceSha};
}

export async function reserveBridgeOperator({store,request,configSha256,commands,now=Date.now}={}){
 const {operationId,requestSha256}=request;
 const phase=bridgeOperatorClaimPhase(request);
 const prior=await store.readOperation(operationId,phase);
 const claimedAt=now();
 const action=bridgeOperatorExpiryAction({request,operator:prior,
  operatorCommittedAt:prior?await store.readOperationCommittedAt(operationId,phase):undefined,now:claimedAt});
 if(action==='REAUTHORIZE')throw new Error('REAUTHORIZATION_REQUIRED: operator mutation was not claimed before request expiry');
 const inputSha256=brokerDigest({configSha256,commands});
 if(prior){assert.equal(prior.inputSha256,inputSha256,'Prior operator mutation has different inputs');return 'RECONCILE';}
 const dispatch={requestSha256,operationId,inputSha256,claimedAt:new Date(claimedAt).toISOString(),executionContract:'S3_COMMIT_BEFORE_NATIVE_V2'};
 assert.equal(await store.claimOperation(operationId,phase,dispatch),true,'Another operator owns the native cutover');
 assert.deepEqual(await store.readOperation(operationId,phase),dispatch);
 assert.equal(bridgeOperatorExpiryAction({request,operator:dispatch,operatorCommittedAt:await store.readOperationCommittedAt(operationId,phase)}),
  'RECONCILE','REAUTHORIZATION_REQUIRED: operator claim committed after authorization expiry; no native execution was permitted');
 return 'EXECUTE';
}

export async function reserveBridgePhaseTimestamp({store,operationId,requestSha256,name,now=Date.now}){
 const dispatched=await store.readOperation(operationId,`BRIDGE:SIGN:${name}:DISPATCH`);
 if(dispatched){
  assert.equal(dispatched.requestSha256,requestSha256);
  assert.ok(Number.isSafeInteger(Date.parse(dispatched.phaseTimestamp)),'Dispatched Sign timestamp is missing');
  return dispatched.phaseTimestamp;
 }
 for(let round=0;round<32;round++){
  const key=`BRIDGE:PHASE:${name}:TIMESTAMP:${round}`;
  let record=await store.readOperation(operationId,key);
  if(!record){
   record={requestSha256,timestamp:new Date(now()).toISOString()};
   await store.writeOperation(operationId,key,record);
   assert.deepEqual(await store.readOperation(operationId,key),record);
   return record.timestamp;
  }
  if(record.requestSha256!==requestSha256)continue;
  if(now()-Date.parse(record.timestamp)<45000)return record.timestamp;
 }
 throw new Error('Bridge signing timestamp attempts exhausted before any native Sign');
}

export async function waitForBridgeNativeAttestationRequest({store,operationId,nativeResultSha256,now=Date.now,
 wait=ms=>new Promise(resolve=>setTimeout(resolve,ms)),maxPolls=480}={}){
 for(let poll=0;poll<maxPolls;poll++){
  for(let round=0;round<32;round++){
   const request=await store.readOperation(operationId,`BRIDGE:NATIVE:ATTESTATION:REQUEST:ROUND:${round}`);
   if(!request)break;
   assertBridgeNativeAttestationRequest(request,{operationId,nativeResultSha256},now(),true);
   if(now()<Date.parse(request.expiresAt))return request;
   const result=await store.readOperation(operationId,`BRIDGE:NATIVE:ATTESTATION:SIGN:ROUND:${round}:RESULT`);
   if(result)return request;
  }
  await wait(15000);
 }
 throw new Error('Post-cutover checker authorization remains unavailable; preserve candidate and resume');
}

function executePhase(phase,args,{env=process.env,root=process.cwd()}={}){
 const file=path.join(root,'scripts/aws',scripts[phase]);
 if(phase==='operator'){
  const result=spawnSync(process.execPath,[file,...args],{cwd:root,env,stdio:'inherit'});
  if(result.error)throw result.error;
  assert.equal(result.status,0,'Interactive verifier cutover failed');
  return null;
 }
 const output=execFileSync(process.execPath,[file,...args],{cwd:root,env,encoding:'utf8',stdio:['inherit','pipe','inherit'],maxBuffer:8*1024*1024});
 return JSON.parse(output.trim());
}

export async function runTerminalBridge({manifestPath,releaseId,runId,runAttempt,store,runPhase=executePhase,prompt,fetchApproval=fetchProductionEnvironmentApprovalEvidence,githubRun,env=process.env,root=process.cwd(),now=Date.now}={}){
 assert.ok(process.stdin.isTTY&&process.stdout.isTTY,'Bridge requires an interactive trusted terminal');
 assert.match(String(releaseId||''),/^[a-f0-9]{64}$/);
 assert.match(String(runId||''),/^[1-9][0-9]*$/);
 assert.match(String(runAttempt||''),/^[1-9][0-9]*$/);
 const manifestBytes=readStageBPrivateFileBytes({filePath:path.resolve(manifestPath),repositoryRoot:root,label:'Release bridge manifest'}).bytes;
 const manifest=JSON.parse(manifestBytes.toString('utf8'));
 assertBridgeManifest(manifest);
 readStageBProtectedMainCheckout({cwd:root,expectedSourceSha:manifest.sourceSha,requireCanonicalRepository:true});
 const releaseRun=createProductionAwsCommandRunner({credentialSource:PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE,profile:'mscqr-production-release-deployer',env});
 const journal=store||createReleaseCoordinatorStore({run:releaseRun,directory:path.dirname(path.resolve(manifestPath)),repositoryRoot:root});
 const operationId=bridgeOperationId({...manifest,releaseId}),phase=`BRIDGE:REQUEST:${runId}:${runAttempt}`;
 const request=await journal.readOperation(operationId,phase);
 assertBridgeRequest(request,{...manifest,releaseId,manifestSha256:brokerDigest(manifest),now:now(),allowExpired:true});
 let latestRound=-1;
 for(let round=0;round<32;round++){
  const owner=await journal.readOperation(operationId,`BRIDGE:REQUEST:ROUND:${round}`);
  if(!owner)break;
  latestRound=round;
  if(round===request.authorizationRound)assert.equal(owner.requestSha256,request.requestSha256);
 }
 assert.equal(request.authorizationRound,latestRound,'Trusted-terminal request was superseded by a new authorization');
 const completed=await journal.readOperation(operationId,'BRIDGE:CUTOVER:COMPLETED');
 if(completed){
  assert.equal(completed.requestSha256,request.requestSha256);
  assert.equal(completed.releaseId,request.releaseId);assert.equal(completed.sourceSha,request.sourceSha);assert.equal(completed.rotationId,request.rotationId);
  const transport=await journal.getArtifact(completed.readinessArtifactSha256);
  assert.equal(hash(Buffer.from(transport.bytesBase64,'base64')),completed.readinessSha256);
  const ready=JSON.parse(Buffer.from(transport.bytesBase64,'base64'));
  assertReadyForOverlapDeployment(ready,{sourceSha:request.sourceSha,rotationId:request.rotationId});
  assert.equal(brokerDigest(transport),completed.readinessArtifactSha256);
  return completed;
 }
 const approval=await journal.getArtifact(request.environmentApprovalSha256);
 assertProductionEnvironmentApprovalIdentity(approval,{sourceSha:manifest.sourceSha,repository:PRODUCTION_ENVIRONMENT_APPROVAL.repository});
 assert.equal(approval.schemaVersion,3);assert.equal(approval.workflowRef,PRODUCTION_ENVIRONMENT_APPROVAL.releaseTrainWorkflowRef);
 assert.equal(approval.workflowRunId,request.workflowRunId);assert.equal(approval.workflowRunAttempt,request.workflowRunAttempt);
 const token=readGitHubApiToken({env});
 const observed=await fetchApproval({token,repository:PRODUCTION_ENVIRONMENT_APPROVAL.repository,environment:'production',sourceSha:manifest.sourceSha,
  workflowRef:approval.workflowRef,eventName:'workflow_dispatch',workflowRunId:request.workflowRunId,workflowRunAttempt:request.workflowRunAttempt,
  executionActor:approval.executionActor,requireActualApproval:true});
 assert.deepEqual(observed.actualApproval,approval.actualApproval,'GitHub approval no longer matches immutable authorization');
 const run=githubRun?await githubRun(request.workflowRunId):JSON.parse(execFileSync('gh',['api',`repos/${PRODUCTION_ENVIRONMENT_APPROVAL.repository}/actions/runs/${request.workflowRunId}`],{encoding:'utf8',stdio:['ignore','pipe','pipe']}));
 assert.equal(String(run.id),request.workflowRunId);assert.equal(String(run.run_attempt),request.workflowRunAttempt);
 assert.equal(run.head_sha,manifest.sourceSha);assert.equal(run.head_branch,'main');assert.equal(run.event,'workflow_dispatch');
 assert.equal(run.path,'.github/workflows/release-train.yml');assert.equal(run.repository?.full_name,PRODUCTION_ENVIRONMENT_APPROVAL.repository);
 assert.equal(run.actor?.login?.toLowerCase(),approval.executionActor.toLowerCase());
 const args=assertBridgeManifest(manifest,request);
 for(const [rootKey,runtimeKey] of [['--administrator-evidence-sha256','--iam-evidence'],['--administrator-signature-sha256','--iam-evidence-signature']]){
  const file=readStageBPrivateFileBytes({filePath:path.resolve(args.runtime.get(runtimeKey)),repositoryRoot:root,label:runtimeKey});
  assert.equal(file.sha256,args.root.get(rootKey),`Root ${rootKey} does not bind the prepared prerequisite file`);
 }
 const imageAuthorization=JSON.parse(readStageBPrivateFileBytes({filePath:path.resolve(args.runtime.get('--image-authorization')),repositoryRoot:root,label:'Image authorization'}).bytes);
 assert.equal(imageAuthorization.authorizationSha256,args.root.get('--image-authorization-sha256'));
 const operatorPhase=bridgeOperatorClaimPhase(request);
 const priorOperatorClaim=await journal.readOperation(operationId,operatorPhase);
 const operatorAction=bridgeOperatorExpiryAction({request,operator:priorOperatorClaim,
  operatorCommittedAt:priorOperatorClaim?await journal.readOperationCommittedAt(operationId,operatorPhase):undefined,now:now()});
 if(operatorAction==='REAUTHORIZE')throw new Error('REAUTHORIZATION_REQUIRED: request expired before operator claim');
 process.stdout.write(`MSCQR PRODUCTION RELEASE AUTHORIZATION\nRelease: ${request.releaseId}\nSource: ${manifest.sourceSha}\nRotation: ${manifest.rotationId}\nOperation: prepare-overlap legacy\nExpected signers: exact AWS account root; independent checker\nAuthorization expires: ${request.expiresAt}\nRequest authenticated: YES\n`);
 assert.equal(typeof prompt,'function','Explicit operator confirmation callback is required');
 assert.equal(await prompt(`Type ${manifest.rotationId} to authorize the exact bound cutover: `),manifest.rotationId,'Operator did not confirm exact rotation');
 // One terminal owns this authorization round. A lost claim response cannot grant execution rights.
 const owner=readTerminalOwner({directory:path.dirname(path.resolve(manifestPath)),operationId,requestSha256:request.requestSha256});
 const executionClaim={...owner,runId:request.workflowRunId,runAttempt:request.workflowRunAttempt};
 const executionPhase=`BRIDGE:TERMINAL:EXECUTION:${request.authorizationRound}`;
 const existingExecution=await journal.readOperation(operationId,executionPhase);
 if(existingExecution)assert.deepEqual(existingExecution,executionClaim,'Another trusted terminal owns this cutover authorization');
 else assert.equal(await journal.claimOperation(operationId,executionPhase,executionClaim),true,
  'Another trusted terminal owns this cutover authorization');
 assert.deepEqual(await journal.readOperation(operationId,executionPhase),executionClaim,
  'Trusted-terminal execution claim readback differs');
 const bridgeEnv={...env,AWS_MAX_ATTEMPTS:'1',AWS_RETRY_MODE:'standard',MSCQR_BRIDGE_OPERATION_ID:operationId,
  MSCQR_BRIDGE_RUN_ID:request.workflowRunId,MSCQR_BRIDGE_RUN_ATTEMPT:request.workflowRunAttempt,MSCQR_BRIDGE_RELEASE_ID:request.releaseId,
  MSCQR_BRIDGE_SOURCE_SHA:request.sourceSha,MSCQR_BRIDGE_TICKET_ID:request.ticketId,MSCQR_BRIDGE_ROTATION_ID:request.rotationId,
  MSCQR_BRIDGE_MANIFEST_SHA256:request.manifestSha256};
 const signedPhases={root:'ROOT_DROP',adoption:'INVENTORY_ADOPTION',successor:'ROTATION_SUCCESSOR'};
 const phaseBindings={};
 for(const [name,signingPhase] of Object.entries(signedPhases)){
  const prefix=`BRIDGE:SIGN:${signingPhase}`,dispatch=await journal.readOperation(operationId,`${prefix}:DISPATCH`);
  if(!dispatch){phaseBindings[name]={request};continue;}
  const owner=await bridgeRequestForSign({store:journal,operationId,dispatch,...manifest,releaseId,
   manifestSha256:request.manifestSha256});
  const result=await journal.readOperation(operationId,`${prefix}:RESULT`);
  const done=await journal.readOperation(operationId,`${prefix}:COMPLETED`);
  if(owner.requestSha256!==request.requestSha256){
   assert.equal(classifyBridgeNativeResult({dispatch,result,completion:done}),'COMPLETED',`${signingPhase} outcome requires reconciliation`);
   assert.equal(verifyBridgeCapturedSign({phase:signingPhase,dispatch,result,request:owner,run:releaseRun}),true,
    `${signingPhase} native signature cannot be reused`);
   await authenticateBridgeEnvironmentApproval({store:journal,request:owner,observeApproval:(approved,original)=>fetchApproval({token,
    repository:PRODUCTION_ENVIRONMENT_APPROVAL.repository,environment:'production',sourceSha:manifest.sourceSha,
    workflowRef:approved.workflowRef,eventName:'workflow_dispatch',workflowRunId:original.workflowRunId,
    workflowRunAttempt:original.workflowRunAttempt,executionActor:approved.executionActor,requireActualApproval:true})});
  }
  phaseBindings[name]={request:owner,dispatch};
 }
 const phaseRun=(name,values,extra={})=>{
  const bound=phaseBindings[name]?.request||request;
  return runPhase(name,values,{env:{...bridgeEnv,MSCQR_BRIDGE_RUN_ID:bound.workflowRunId,
   MSCQR_BRIDGE_RUN_ATTEMPT:bound.workflowRunAttempt,...extra},root});
 };
 const phaseTime=name=>{
  const bound=phaseBindings[Object.keys(signedPhases).find(key=>signedPhases[key]===name)];
  return bound?.dispatch?.phaseTimestamp||reserveBridgePhaseTimestamp({store:journal,operationId,
   requestSha256:request.requestSha256,name,now});
 };
 // The immutable preparation performs the expensive read-only checks before root issuance.
 const recoveredRuntime=recoverMaterializedBridgeRuntime({outputDirectory:args.runtime.get('--output-directory'),sourceSha:manifest.sourceSha,
  rotationId:manifest.rotationId,rootDropPath:args.root.get('--output'),repositoryRoot:root});
 let materialized;
 if(priorOperatorClaim){
  assert.ok(recoveredRuntime,'OUTCOME_UNKNOWN: verifier-owned mutation has no authenticated runtime checkpoint');
  materialized=recoveredRuntime;
 }else{
  if(!recoveredRuntime){
   const preflight=await phaseRun('runtime',[...manifest.commands.runtime,'--bridge-preflight','true']);
   assert.equal(preflight?.ready,true,'Pre-root runtime preparation is not ready');
  }
  assertBridgeRequest(request,{...manifest,releaseId,manifestSha256:brokerDigest(manifest),now:now()});
  const rootTimestamp=await phaseTime('ROOT_DROP'),rootStarted=Date.parse(rootTimestamp);
  await phaseRun('root',manifest.commands.root,{MSCQR_BRIDGE_PHASE_TIMESTAMP:rootTimestamp});
  assert.ok(now()-rootStarted<780000,'Root freshness reserve exhausted before runtime materialization');
  materialized=recoveredRuntime||await phaseRun('runtime',manifest.commands.runtime);
  assert.ok(now()-rootStarted<780000,'Root freshness reserve exhausted before checker preparation');
 }
 const runtime={configPath:materialized?.ROTATION_CONFIG,runtimeConfigSha256:materialized?.ROTATION_CONFIG_SHA256,
  releaseSourceSha:materialized?.RELEASE_SOURCE_SHA};
 assert.ok(materialized?.READY_TO_CONSUME_MFA===true&&runtime.configPath&&runtime.runtimeConfigSha256,'Materialized runtime is not ready');
 assert.equal(runtime.releaseSourceSha||runtime.RELEASE_SOURCE_SHA,manifest.sourceSha);
 if(!priorOperatorClaim){
  await phaseRun('adoption',replace(manifest.commands.adoption,runtime),{MSCQR_BRIDGE_PHASE_TIMESTAMP:await phaseTime('INVENTORY_ADOPTION')});
  await phaseRun('successor',replace(manifest.commands.successor,runtime),{MSCQR_BRIDGE_PHASE_TIMESTAMP:await phaseTime('ROTATION_SUCCESSOR')});
  assert.ok(now()-Date.parse(await phaseTime('ROOT_DROP'))<780000,'Root freshness reserve exhausted before final verifier');
 }
 const config=JSON.parse(readStageBPrivateFileBytes({filePath:runtime.configPath,repositoryRoot:root,label:'Runtime config'}).bytes);
 const nativeResultFile=path.join(path.dirname(runtime.configPath),'bridge-native-result.json');
 const operatorArgs=[...replace(manifest.commands.operator,runtime),'--native-result-output',nativeResultFile];
 const operatorDisposition=await reserveBridgeOperator({store:journal,request,
  configSha256:runtime.runtimeConfigSha256,commands:operatorArgs,now});
 if(operatorDisposition==='EXECUTE'){
  await phaseRun('operator',operatorArgs);
 }
 if(operatorDisposition==='RECONCILE'&&(!fs.existsSync(config.readinessEvidenceFile)||!fs.existsSync(config.rotationStateFile)))
  throw new Error('OUTCOME_UNKNOWN: prior verifier-owned cutover has no complete local readiness; reconcile native AWS state before retry');
 const readinessBytes=readStageBPrivateFileBytes({filePath:config.readinessEvidenceFile,repositoryRoot:root,label:'Overlap readiness'}).bytes;
 const nativeResult=assertBridgeNativeResult(JSON.parse(readStageBPrivateFileBytes({filePath:nativeResultFile,repositoryRoot:root,label:'Bridge native result handoff'}).bytes),
  {sourceSha:manifest.sourceSha,rotationId:manifest.rotationId,runtimeConfigSha256:runtime.runtimeConfigSha256});
 const stateBytes=readStageBPrivateFileBytes({filePath:config.rotationStateFile,repositoryRoot:root,label:'Rotation state'}).bytes;
 const readiness=JSON.parse(readinessBytes),state=JSON.parse(stateBytes);
 const stateSha256=hash(stateBytes),readinessSha256=hash(readinessBytes);
 const readinessTransport={bytesBase64:readinessBytes.toString('base64'),sha256:readinessSha256};
 const stateTransport={bytesBase64:stateBytes.toString('base64'),sha256:stateSha256};
 const rootEvidence=JSON.parse(readStageBPrivateFileBytes({filePath:args.root.get('--output'),repositoryRoot:root,label:'Root evidence'}).bytes);
 const adoptionEvidence=JSON.parse(readStageBPrivateFileBytes({filePath:path.join(path.dirname(runtime.configPath),'inventory-completed-adoption-evidence.json'),repositoryRoot:root,label:'Adoption evidence'}).bytes);
 const successorEvidence=JSON.parse(readStageBPrivateFileBytes({filePath:path.join(path.dirname(runtime.configPath),'rotation-successor-evidence.json'),repositoryRoot:root,label:'Successor evidence'}).bytes);
 assertReadyForOverlapDeployment(readiness,{sourceSha:manifest.sourceSha,rotationId:manifest.rotationId});
 assert.ok(readiness.rotationStateSha256===stateSha256||readiness.rotationStateSha256===state.verification?.preparedStateSha256,'Persisted rotation state differs from prepared readiness');
 const completion={kind:'PRODUCTION_RELEASE_TERMINAL_CUTOVER_V1',schemaVersion:1,operationId,requestSha256:request.requestSha256,
  releaseId:request.releaseId,sourceSha:request.sourceSha,rotationId:request.rotationId,manifestSha256:request.manifestSha256,
  readinessArtifactSha256:brokerDigest(readinessTransport),readinessSha256,rotationStateArtifactSha256:brokerDigest(stateTransport),rotationStateSha256:stateSha256,
  rootEvidenceArtifactSha256:brokerDigest(rootEvidence),adoptionEvidenceArtifactSha256:brokerDigest(adoptionEvidence),successorEvidenceArtifactSha256:brokerDigest(successorEvidence),
  nativeResultArtifactSha256:brokerDigest(nativeResult),
  rotationFixtureSha256:hash(readStageBPrivateFileBytes({filePath:config.rotationFixtureFile,repositoryRoot:root,label:'Rotation fixture'}).bytes),
  taskDefinitionArn:readiness.overlapTaskDefinition.identityBindings.taskDefinitionArn,
  expectedCurrentTaskDefinitionArn:config.expectedCurrentTaskDefinitionArn,
  imageDigest:readiness.overlapTaskDefinition.identityBindings.imageDigest,deploymentSha:manifest.sourceSha};
 await journal.putArtifact(completion.readinessArtifactSha256,readinessTransport);
 await journal.putArtifact(completion.rotationStateArtifactSha256,stateTransport);
 await journal.putArtifact(completion.rootEvidenceArtifactSha256,rootEvidence);
 await journal.putArtifact(completion.adoptionEvidenceArtifactSha256,adoptionEvidence);
 await journal.putArtifact(completion.successorEvidenceArtifactSha256,successorEvidence);
 await journal.putArtifact(completion.nativeResultArtifactSha256,nativeResult);
 const candidate={...completion,cutoverRequestSha256:completion.requestSha256};
 await journal.writeOperation(operationId,'BRIDGE:CUTOVER:CANDIDATE',candidate);
 assert.deepEqual(await journal.readOperation(operationId,'BRIDGE:CUTOVER:CANDIDATE'),candidate);
 const checkerRun=createProductionAwsCommandRunner({credentialSource:PRODUCTION_AWS_CREDENTIAL_SOURCE.INHERITED_CHECKER_SESSION,env});
 for(const [phase,evidence] of Object.entries({ROOT_DROP:rootEvidence,INVENTORY_ADOPTION:adoptionEvidence,ROTATION_SUCCESSOR:successorEvidence})){
  const prefix=`BRIDGE:SIGN:${phase}`;
  const dispatch=await journal.readOperation(operationId,`${prefix}:DISPATCH`);
  const result=await journal.readOperation(operationId,`${prefix}:RESULT`);
  const owner=phaseBindings[Object.keys(signedPhases).find(key=>signedPhases[key]===phase)]?.request;
  assert.equal(result?.response?.Signature,evidence.signatureBase64);
  assert.equal(verifyBridgeCapturedSign({phase,dispatch,result,request:owner,run:releaseRun}),true,
   `Checker cannot independently authenticate ${phase} native signature`);
 }
 const attestationRequest=await waitForBridgeNativeAttestationRequest({store:journal,operationId,
  nativeResultSha256:completion.nativeResultArtifactSha256,now});
 assert.equal(attestationRequest.cutoverRequestSha256,request.requestSha256);
 const approved=await authenticateBridgeEnvironmentApproval({store:journal,request:attestationRequest,
  observeApproval:(value,requested)=>fetchApproval({token,repository:PRODUCTION_ENVIRONMENT_APPROVAL.repository,
   environment:'production',sourceSha:manifest.sourceSha,workflowRef:value.workflowRef,eventName:'workflow_dispatch',
   workflowRunId:requested.workflowRunId,workflowRunAttempt:requested.workflowRunAttempt,
   executionActor:value.executionActor,requireActualApproval:true})});
 assert.equal(brokerDigest(approved),attestationRequest.environmentApprovalSha256);
 const nativeAudit=await readBridgeNativeAudit({run:checkerRun,store:journal,native:nativeResult,readiness,adoption:adoptionEvidence,now:now()});
 assert.equal(nativeAudit.proofSha256,attestationRequest.nativeProofSha256,
  'Independent checker AWS readback differs from hosted native proof');
 const signed=await signBridgeNativeAttestationOnce({store:journal,request:attestationRequest,
  nativeProofSha256:nativeAudit.proofSha256,checkerRun,verifyRun:releaseRun,now});
 const finalCompletion={...completion,nativeProofSha256:nativeAudit.proofSha256,
  nativeAttestationRound:attestationRequest.round,nativeAttestationResultSha256:brokerDigest(signed)};
 await journal.writeOperation(operationId,'BRIDGE:CUTOVER:COMPLETED',finalCompletion);
 assert.deepEqual(await journal.readOperation(operationId,'BRIDGE:CUTOVER:COMPLETED'),finalCompletion,'Durable terminal completion readback differs');
 return finalCompletion;
}

export function terminalLockCommand({platform=process.platform,manifest,executable=process.execPath,script=process.argv[1],args=process.argv.slice(2)}={}){
 const lock=path.resolve(manifest)+'.lock';
 if(platform==='linux')return {command:'flock',args:['-n',lock,executable,script,...args]};
 if(platform==='darwin'||platform==='freebsd')return {command:'lockf',args:['-t','0',lock,executable,script,...args]};
 throw new Error(`Unsupported trusted-terminal lock platform: ${platform}`);
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 const values=argv(process.argv.slice(2));
 if(process.env.MSCQR_BRIDGE_LOCAL_LOCK!=='held'){
  const {command,args}=terminalLockCommand({manifest:values['--manifest']||''});
  const locked=spawnSync(command,args,
   {stdio:'inherit',env:{...process.env,MSCQR_BRIDGE_LOCAL_LOCK:'held'}});
  if(locked.error)throw locked.error;
  process.exitCode=locked.status??1;
 }else{
  const prompt=async message=>{process.stdout.write(message);return new Promise(resolve=>{process.stdin.once('data',value=>resolve(String(value).trim()));});};
  runTerminalBridge({manifestPath:values['--manifest'],releaseId:values['--release-id'],runId:values['--run-id'],runAttempt:values['--run-attempt'],prompt}).then(result=>process.stdout.write(`${JSON.stringify({status:'COMPLETED',operationId:result.operationId,readinessSha256:result.readinessSha256})}\n`),error=>{process.stderr.write(`${error.message}\n`);process.exitCode=1;});
 }
}
