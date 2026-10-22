#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';
import {createProductionAwsCommandRunner,PRODUCTION_AWS_CREDENTIAL_SOURCE} from './production-credential-source-contract.mjs';
import {createReleaseCoordinatorStore} from './production-release-evidence-store.mjs';
import {HOSTED_RELEASE_ROOT} from './production-release-coordinator.mjs';
import {runTerminalCutoverRequest} from './request-production-release-terminal-cutover.mjs';
import {authenticateTerminalCutover,checkerBridgeVerifier,rootBridgeVerifier,bridgeOverlapLiveReader} from './verify-production-release-terminal-bridge.mjs';
import {resolveProductionOverlapDeploymentReceipt} from './production-overlap-deployment-receipt.mjs';
import {createProductionComponentDeploymentStateClient,componentDeploymentProvenance} from './production-component-deployment-state.mjs';
import {stateHash} from './production-component-deployment-state.mjs';
import {componentCommitOperationId} from './production-release-gate-component-journal.mjs';
import {smokeOperationId} from './run-production-release-gate-smoke.mjs';
import {assertNormalGateCompletion} from './production-release-gate-completion.mjs';
import {dispatchSourceBoundWorkflow,dispatchProtectedMainReleaseGate} from '../github/dispatch-source-bound-workflow.mjs';
import {requiredWorkflowFiles,usesLifecycleInputs} from '../github/release-lifecycle-contract.mjs';
import {packReleaseEvidenceTransport,unpackReleaseEvidenceTransport} from './production-release-dispatch-contract.mjs';
import {brokerDigest} from './stage-b-staged-broker-contract.mjs';
import {createBridgeCredentialRefresher} from './production-release-bridge-credentials.mjs';
import {fetchProductionEnvironmentApprovalEvidence,PRODUCTION_ENVIRONMENT_APPROVAL} from './production-github-environment-approval.mjs';
import {bridgeOperatorClaimPhase,bridgeOperatorExpiryAction,classifyBridgeNativeResult} from './production-release-bridge-contract.mjs';
import {readBridgeNativeCandidate,verifyHostedBridgeNativeStages} from './production-release-bridge-native-verifier.mjs';
import {readBridgeNativeAudit} from './production-release-bridge-native-audit.mjs';
import {requestBridgeNativeAttestation} from './production-release-bridge-native-attestation.mjs';
import {classifyPreMutationGateRetry,classifyPostMutationNormalGateRecovery,classifyPreBackendNormalGateRecovery,classifyPostMutationOverlapGateRecovery} from './production-release-gate-recovery.mjs';
import {gateEcsOperationId} from './production-release-gate-ecs-journal.mjs';

const repository='T-ej2003/genuine-scan-main';
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const json=(run,args)=>JSON.parse(run([...args,'--output','json','--no-cli-pager']));
const gh=(args)=>execFileSync('gh',args,{encoding:'utf8',stdio:['ignore','pipe','pipe'],maxBuffer:8*1024*1024});

export const createProductionNativeStageVerifier=({store,run,env})=>evidence=>verifyHostedBridgeNativeStages({store,run,evidence,
 observeApproval:(approval,request)=>fetchProductionEnvironmentApprovalEvidence({token:env.GH_TOKEN,
  repository:PRODUCTION_ENVIRONMENT_APPROVAL.repository,environment:'production',sourceSha:request.sourceSha,
  workflowRef:approval.workflowRef,eventName:'workflow_dispatch',workflowRunId:request.workflowRunId,
  workflowRunAttempt:request.workflowRunAttempt,executionActor:approval.executionActor,requireActualApproval:true})});

export async function requestNormalGateRerun({store,operationId,runId,runAttempt,sourceSha,releaseTrainRunId,
 requireMain,fetchImpl,fetchRun,token,repositoryName=repository}={}){
 const marker={runId,runAttempt,sourceSha,releaseTrainRunId};
 const definitiveRejection=status=>status>=400&&status<500&&status!==408&&status!==429;
 const observe=async()=>{
  const observed=await fetchRun(runId);
  assert.equal(String(observed.id),String(runId));assert.equal(observed.head_sha,sourceSha);
  assert.equal(observed.path,'.github/workflows/release-gate.yml');assert.equal(observed.event,'workflow_dispatch');
  assert.equal(observed.repository?.full_name,repositoryName);
  if(observed.run_attempt>runAttempt)return 'WAIT';
  throw new Error('OUTCOME_UNKNOWN: GitHub rerun dispatch has no durable accepted attempt; reconcile before retry');
 };
 for(let request=1;request<=3;request++){
  const phase=`BRIDGE:GATE:NORMAL:RERUN:${runAttempt}:DISPATCH:${request}`;
  const prior=await store.readOperation(operationId,phase);
  if(prior){
   assert.deepEqual(prior,marker,'Conflicting normal Gate rerun ownership');
   const result=await store.readOperation(operationId,`${phase}:RESULT`);
   if(result){
    assert.deepEqual(result.marker,marker);
    if(result.status===201)return 'WAIT';
    assert.ok(Number.isInteger(result.status)&&result.status>=100&&result.status<600,
     'Invalid rerun response receipt');
    if(definitiveRejection(result.status))continue;
    return observe();
   }
   return observe();
  }
  await requireMain();
  assert.equal(await store.claimOperation(operationId,phase,marker),true,
   'Another Release Train invocation owns this child rerun');
  const response=await fetchImpl(`https://api.github.com/repos/${repositoryName}/actions/runs/${runId}/rerun`,{
   method:'POST',headers:{Accept:'application/vnd.github+json',Authorization:`Bearer ${token}`,
    'X-GitHub-Api-Version':'2022-11-28'}});
  const result={marker,status:response.status};
  await store.writeOperation(operationId,`${phase}:RESULT`,result);
  assert.deepEqual(await store.readOperation(operationId,`${phase}:RESULT`),result,
   'Normal Gate rerun response was not durably captured');
  if(response.status===201)return 'WAIT';
  if(!definitiveRejection(response.status))return observe();
  throw new Error(`GitHub rejected normal Gate rerun request for ${runId} with ${response.status}; next invocation may retry`);
 }
 throw new Error('Normal Gate rerun exhausted bounded rejected requests');
}

export function classifyNormalGateRerunOutcome(child,recovery){
 if(child.conclusion==='success')return 'COMPLETED';
 assert.ok(recovery<2,'Normal Gate exhausted same-run recovery; preserve its child identity for reconciliation');
 return 'RECONCILE';
}

export async function waitForTerminalCutover({verify,coordinateNative=async()=>{},ensureCredentials,store,request,now=Date.now,wait=sleep,maxPolls=1200}={}){
 const operationId=request.operationId;
 for(let i=0;i<maxPolls;i++){
  await ensureCredentials();
  const completed=await verify();if(completed)return completed;
  await coordinateNative();
  if(now()>=Date.parse(request.expiresAt)){
   const signed=await Promise.all(['ROOT_DROP','INVENTORY_ADOPTION','ROTATION_SUCCESSOR'].map(async phase=>{
    const prefix=`BRIDGE:SIGN:${phase}`,dispatch=await store.readOperation(operationId,`${prefix}:DISPATCH`);
    if(!dispatch)return 'NOT_STARTED';
    const result=await store.readOperation(operationId,`${prefix}:RESULT`);
    const completion=await store.readOperation(operationId,`${prefix}:COMPLETED`);
    return classifyBridgeNativeResult({dispatch,result,completion});
   }));
   assert.ok(!signed.includes('OUTCOME_UNKNOWN'),'OUTCOME_UNKNOWN: native KMS Sign dispatch has no authenticated result');
   const operatorPhase=bridgeOperatorClaimPhase(request);
   const operator=await store.readOperation(operationId,operatorPhase);
   const action=bridgeOperatorExpiryAction({request,operator,
    operatorCommittedAt:operator?await store.readOperationCommittedAt(operationId,operatorPhase):undefined,now:now()});
   if(action==='REAUTHORIZE')throw new Error(signed.every(state=>state==='NOT_STARTED')
    ?'REAUTHORIZATION_REQUIRED: trusted-terminal request expired before a native Sign dispatch'
    :'REAUTHORIZATION_REQUIRED: completed native signatures are preserved; resume under a fresh protected request');
  }
  await wait(15000);
 }
 throw new Error('Trusted-terminal outcome remains unknown after the bounded recovery wait');
}

export async function runHostedBridge({env=process.env,requestCutover=runTerminalCutoverRequest,authenticate=authenticateTerminalCutover,
 verifyNativeStages,dispatchSource=dispatchSourceBoundWorkflow,dispatchGate=dispatchProtectedMainReleaseGate,wait=sleep,fetchImpl=fetch,now=Date.now}={}){
 assert.ok(verifyNativeStages===undefined||typeof verifyNativeStages==='function','Independent Stage B native verifier must be callable');
 assert.equal(env.GITHUB_ACTIONS,'true');assert.equal(env.GITHUB_EVENT_NAME,'workflow_dispatch');
 assert.equal(env.GITHUB_REPOSITORY,repository);
 assert.equal(env.GITHUB_WORKFLOW_REF,`${repository}/.github/workflows/release-train.yml@refs/heads/main`);
 assert.match(env.TARGET_SHA||'',/^[a-f0-9]{40}$/);assert.equal(env.TARGET_SHA,env.GITHUB_SHA);
 assert.equal(env.TARGET_REF,'main');assert.match(env.BRIDGE_ROTATION_ID||'',/^rotation-[a-z0-9-]+$/);
 assert.match(env.BRIDGE_MANIFEST_SHA256||'',/^[a-f0-9]{64}$/);
 assert.ok(env.GH_TOKEN&&env.NORMAL_IMAGE_AUTHORIZATION_JSON&&env.NORMAL_IMAGE_AUTHORIZATION_SHA256);
 fs.mkdirSync(HOSTED_RELEASE_ROOT,{recursive:true,mode:0o700});fs.chmodSync(HOSTED_RELEASE_ROOT,0o700);
 const credentials=createBridgeCredentialRefresher({env,fetchImpl,now});
 await credentials.ensure();
 const run=args=>createProductionAwsCommandRunner({credentialSource:PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER,env:credentials.env()})(args);
 const caller=json(run,['sts','get-caller-identity']);
 assert.equal(caller.Account,'368992683803');assert.match(caller.Arn||'',/^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[^/]+$/);
 const store=createReleaseCoordinatorStore({run,directory:HOSTED_RELEASE_ROOT,repositoryRoot:process.cwd()});
 const nativeVerifier=verifyNativeStages||createProductionNativeStageVerifier({store,run,env});
 const authorizationTransport=unpackReleaseEvidenceTransport({json:env.NORMAL_IMAGE_AUTHORIZATION_JSON,sha256:env.NORMAL_IMAGE_AUTHORIZATION_SHA256});
 const auth=JSON.parse(authorizationTransport.authorizationJson);
 const fetchJson=async endpoint=>{
  const response=await fetchImpl(`https://api.github.com/repos/${repository}/${endpoint}`,{headers:{Accept:'application/vnd.github+json',Authorization:`Bearer ${env.GH_TOKEN}`,'X-GitHub-Api-Version':'2022-11-28'}});
  if(!response.ok)throw new Error(`GitHub read failed ${response.status} for ${endpoint}`);
  return response.json();
 };
 const requireMain=async()=>{const branch=await fetchJson('branches/main');assert.equal(branch.protected,true);assert.equal(branch.commit?.sha,env.TARGET_SHA,'Protected main advanced during release');};
 await requireMain();
 const requested=await requestCutover({env:credentials.env()});
 const operationId=requested.operationId,releaseId=env.BRIDGE_RELEASE_ID||null;
 const bridgeRequest=await store.readOperation(operationId,`BRIDGE:REQUEST:${requested.workflowRunId}:${requested.workflowRunAttempt}`);
 assert.equal(bridgeRequest?.requestSha256,requested.requestSha256);
 const start=await store.readStart({sourceSha:env.TARGET_SHA,ticketId:env.RELEASE_TICKET_ID});
 assert.ok(start);const release=await store.getArtifact(start.release);
 assert.equal(release.releaseId,requested.releaseId);assert.equal(release.releaseId,releaseId||release.releaseId);assert.equal(release.sourceSha,env.TARGET_SHA);
 process.stdout.write(`TRUSTED_TERMINAL_REQUEST_RELEASE_ID=${requested.releaseId}\nTRUSTED_TERMINAL_REQUEST_RUN_ID=${requested.workflowRunId}\nTRUSTED_TERMINAL_REQUEST_RUN_ATTEMPT=${requested.workflowRunAttempt}\n`);
 const verify=()=>authenticate({store,releaseId:release.releaseId,sourceSha:release.sourceSha,ticketId:release.ticketId,
  rotationId:env.BRIDGE_ROTATION_ID,manifestSha256:env.BRIDGE_MANIFEST_SHA256,
  observeApproval:(approval,request)=>fetchProductionEnvironmentApprovalEvidence({token:env.GH_TOKEN,
   repository:PRODUCTION_ENVIRONMENT_APPROVAL.repository,environment:'production',sourceSha:request.sourceSha,
   workflowRef:approval.workflowRef,eventName:'workflow_dispatch',workflowRunId:request.workflowRunId,
   workflowRunAttempt:request.workflowRunAttempt,executionActor:approval.executionActor,requireActualApproval:true}),
  verifyCheckerSignature:checkerBridgeVerifier(run),verifyRootSignature:rootBridgeVerifier(run),verifyNativeStages:nativeVerifier,readLive:async input=>{
   const priorNormal=await store.readOperation(operationId,'BRIDGE:GATE:NORMAL:RUN');
   if(priorNormal){
    const child=await fetchJson(`actions/runs/${priorNormal.runId}`);
    assert.equal(child.head_sha,env.TARGET_SHA);assert.equal(child.path,'.github/workflows/release-gate.yml');
    if(child.status!=='completed'||child.conclusion!=='success')return true;
    const state=createProductionComponentDeploymentStateClient({run}).read();
    assert.equal(state.components.backend.establishedThroughSha,env.TARGET_SHA);
    assert.equal(componentDeploymentProvenance(state,'backend').githubRunId,priorNormal.runId);
    const service=json(run,['ecs','describe-services','--cluster','mscqr-prod-euw2-main','--services','mscqr-backend-servi-euw2']).services?.[0];
    assert.equal(service?.taskDefinition,state.components.backend.taskDefinitionArn);
    assert.equal(service.runningCount,service.desiredCount);assert.equal(service.pendingCount,0);
    return true;
   }
   const prior=await store.readOperation(operationId,'BRIDGE:GATE:OVERLAP:RUN');
   if(!prior)return bridgeOverlapLiveReader(run)(input);
   const child=await fetchJson(`actions/runs/${prior.runId}`);
   assert.equal(child.head_sha,env.TARGET_SHA);assert.equal(child.path,'.github/workflows/release-gate.yml');
   if(child.status!=='completed'||child.conclusion!=='success')return true;
   const service=json(run,['ecs','describe-services','--cluster','mscqr-prod-euw2-main','--services','mscqr-backend-servi-euw2']).services?.[0];
   assert.equal(service?.taskDefinition,input.completion.taskDefinitionArn);
   assert.equal(service.runningCount,service.desiredCount);assert.equal(service.pendingCount,0);
   const state=createProductionComponentDeploymentStateClient({run}).read();
   assert.equal(state.components.backend.taskDefinitionArn,input.completion.taskDefinitionArn);
   assert.equal(componentDeploymentProvenance(state,'backend').githubRunId,prior.runId);
   return true;
  }});
 let candidateSha,proof;
 const coordinateNative=async()=>{
  const loaded=await readBridgeNativeCandidate({store,operationId});
  if(!loaded)return;
  const {candidate,native,readiness,adoption}=loaded;
  assert.equal(candidate.releaseId,release.releaseId);assert.equal(candidate.sourceSha,env.TARGET_SHA);
  assert.equal(candidate.rotationId,env.BRIDGE_ROTATION_ID);assert.equal(candidate.requestSha256,bridgeRequest.requestSha256);
  if(candidateSha!==brokerDigest(candidate)){
   await credentials.ensure();
   proof=await readBridgeNativeAudit({run,store,native,readiness,adoption,now:now()});
   candidateSha=brokerDigest(candidate);
  }
  const approval=await fetchProductionEnvironmentApprovalEvidence({token:env.GH_TOKEN,
   repository:PRODUCTION_ENVIRONMENT_APPROVAL.repository,environment:'production',sourceSha:env.TARGET_SHA,
   workflowRef:env.GITHUB_WORKFLOW_REF,eventName:'workflow_dispatch',workflowRunId:env.GITHUB_RUN_ID,
   workflowRunAttempt:env.GITHUB_RUN_ATTEMPT,executionActor:env.GITHUB_ACTOR,requireActualApproval:true});
  await requestBridgeNativeAttestation({store,cutoverRequest:bridgeRequest,candidate,nativeProof:proof,approval,
   workflowRunId:env.GITHUB_RUN_ID,workflowRunAttempt:env.GITHUB_RUN_ATTEMPT,now:now()});
 };
 const verified=await waitForTerminalCutover({verify,coordinateNative,ensureCredentials:()=>credentials.ensure(),store,request:bridgeRequest,now,wait});
 const {completion,readiness,readinessBytes,stateBytes}=verified;
 assert.equal(completion.operationId,operationId);
 const stateJson=stateBytes.toString('utf8'),readinessJson=readinessBytes.toString('utf8');
 const priorOverlap=await store.readOperation(operationId,'BRIDGE:GATE:OVERLAP:RUN');
 const boundParentRunId=priorOverlap?.inputs?.release_train_run_id||String(env.GITHUB_RUN_ID);
 const base={git_ref:'main',target_sha:env.TARGET_SHA,release_train_run_id:boundParentRunId,rotation_id:env.BRIDGE_ROTATION_ID,
  rotation_state_json:stateJson,rotation_state_sha256:completion.rotationStateSha256,
  rotation_task_definition_arn:completion.taskDefinitionArn,rotation_image_digest:completion.imageDigest,
  rotation_deployment_sha:completion.deploymentSha};
 const dispatchOnce=async(mode,inputs,attempt=0)=>{
  await credentials.ensure();
  await requireMain();
  const prefix=`BRIDGE:GATE:${mode}${attempt?`:RETRY:${attempt}`:''}`,
   prior=await store.readOperation(operationId,`${prefix}:RUN`);
  if(prior){assert.deepEqual(prior.inputs,inputs,'Child Gate inputs changed during recovery');return prior.runId;}
  const child=await dispatchGate({repository,token:env.GH_TOKEN,targetSha:env.TARGET_SHA,targetRef:'main',inputs,
   dispatchJournal:{read:()=>store.readOperation(operationId,`${prefix}:DISPATCH`),write:async value=>{
    assert.equal(await store.writeOperation(operationId,`${prefix}:DISPATCH`,value),true,'Concurrent Gate dispatch owns this attempt');
   }}});
  const record={inputs,runId:String(child.id),headSha:child.head_sha};
  await store.writeOperation(operationId,`${prefix}:RUN`,record);
  assert.deepEqual(await store.readOperation(operationId,`${prefix}:RUN`),record);
  return record.runId;
 };
 const waitChild=async(id,workflow,{allowFailure=false,maxPolls=720,minAttempt=1}={})=>{
  for(let i=0;i<maxPolls;i++){
   const child=await fetchJson(`actions/runs/${id}`);
   assert.equal(String(child.id),String(id));assert.equal(child.head_sha,env.TARGET_SHA);
   assert.equal(child.path,`.github/workflows/${workflow}`);assert.equal(child.event,'workflow_dispatch');
   assert.equal(child.repository?.full_name,repository);assert.equal(child.head_repository?.full_name,repository);
   if(child.status==='completed'&&child.run_attempt>=minAttempt){
    if(!allowFailure)assert.equal(child.conclusion,'success',`${workflow} did not complete successfully`);
    else assert.ok(['success','failure','cancelled','timed_out'].includes(child.conclusion));
    return child;
   }
   await wait(15000);
  }
  throw new Error(`${workflow} did not reach a terminal authenticated status`);
 };
 const runGate=async(mode,inputs,{expectedBackendArn,expectedFrontendArn,expectedOverlapRunId,targetBackendArn,targetImageDigest}={})=>{
  let latest=0;
  for(let attempt=1;attempt<3;attempt++){
   if(await store.readOperation(operationId,`BRIDGE:GATE:${mode}:RETRY:${attempt}:RUN`))latest=attempt;
   else break;
  }
  for(let attempt=latest;attempt<3;attempt++){
   const id=await dispatchOnce(mode,inputs,attempt);
   let child=await waitChild(id,'release-gate.yml',{allowFailure:true});
   for(let recovery=0;recovery<3;recovery++){
   if(child.conclusion==='success')return {runId:id,child};
   await credentials.ensure();
   const jobs=await fetchJson(`actions/runs/${id}/attempts/${child.run_attempt}/jobs?per_page=100`);
   const matches=(jobs.jobs||[]).filter(job=>job.name==='Deploy production ECS'&&String(job.run_id)===String(id));
   if(matches.length!==1)return {runId:id,child};
   assert.equal(matches[0].head_sha,env.TARGET_SHA);
   assert.equal(matches[0].run_attempt,child.run_attempt);
   const live=name=>json(run,['ecs','describe-services','--cluster','mscqr-prod-euw2-main','--services',name]).services?.[0];
   const disposition=await classifyPreMutationGateRetry({mode,job:matches[0],run,sourceSha:env.TARGET_SHA,
    backendService:live('mscqr-backend-servi-euw2'),frontendService:live('mscqr-frontend-servi-euw2'),
    expectedBackendArn,expectedFrontendArn});
   if(mode==='OVERLAP'){
    if(disposition==='INCOMPLETE')break;
    const taskArns=json(run,['ecs','list-tasks','--cluster','mscqr-prod-euw2-main',
     '--service-name','mscqr-backend-servi-euw2','--desired-status','RUNNING']).taskArns||[];
    const described=taskArns.length===2?json(run,['ecs','describe-tasks','--cluster','mscqr-prod-euw2-main',
     '--tasks',...taskArns]):{tasks:[]};
    const overlapRecovery=classifyPostMutationOverlapGateRecovery({
     backendService:live('mscqr-backend-servi-euw2'),frontendService:live('mscqr-frontend-servi-euw2'),
     expectedFrontendArn,predecessorArn:expectedBackendArn,targetArn:targetBackendArn,
     imageDigest:targetImageDigest,componentState:createProductionComponentDeploymentStateClient({run}).read(),
     runningTasks:described.failures?.length?[]:described.tasks,sourceSha:env.TARGET_SHA});
    if(overlapRecovery==='INCOMPLETE')break;
    return {runId:id,child};
   }
   if(mode!=='NORMAL')return {runId:id,child};
   const backendOperationId=gateEcsOperationId({sourceSha:env.TARGET_SHA,rotationId:env.BRIDGE_ROTATION_ID,
    releaseTrainRunId:boundParentRunId,authorizationSha256:auth.authorizationSha256,kind:'BACKEND'});
   const webAuthorization=env.WEB_IMAGE_AUTHORIZATION_JSON?JSON.parse(env.WEB_IMAGE_AUTHORIZATION_JSON):null;
   const webRequired=auth.imageReuseEvidence?.webPublicationRequired===true;
   const frontendOperationId=webRequired?gateEcsOperationId({sourceSha:env.TARGET_SHA,
    rotationId:env.BRIDGE_ROTATION_ID,releaseTrainRunId:boundParentRunId,
    authorizationSha256:webAuthorization?.authorizationSha256,kind:'FRONTEND'}):null;
   const recoveryInput={store,backendOperationId,
    frontendOperationId,run,childRunId:id,expectedOverlapRunId,sourceSha:env.TARGET_SHA,
    authorizationSha256:auth.authorizationSha256,webAuthorizationSha256:webAuthorization?.authorizationSha256,
    backendService:live('mscqr-backend-servi-euw2'),frontendService:live('mscqr-frontend-servi-euw2'),
    expectedFrontendArn,componentState:createProductionComponentDeploymentStateClient({run}).read(),webRequired};
   const backendDispatched=await store.readOperation(backendOperationId,'BACKEND:UPDATE:DISPATCH');
   const recoveryDisposition=backendDispatched
    ?await classifyPostMutationNormalGateRecovery(recoveryInput)
    :await classifyPreBackendNormalGateRecovery({...recoveryInput,expectedBackendArn});
   if(recoveryDisposition!=='RESUME_SAME_RUN')return {runId:id,child};
   await requestNormalGateRerun({store,operationId,runId:id,runAttempt:child.run_attempt,
    sourceSha:env.TARGET_SHA,releaseTrainRunId:boundParentRunId,requireMain,fetchImpl,
    fetchRun:runId=>fetchJson(`actions/runs/${runId}`),token:env.GH_TOKEN});
   child=await waitChild(id,'release-gate.yml',{allowFailure:true,minAttempt:child.run_attempt+1});
   if(classifyNormalGateRerunOutcome(child,recovery)==='COMPLETED')return {runId:id,child};
   }
  }
  throw new Error(`${mode} Gate exhausted bounded authenticated pre-mutation retries`);
 };
 const overlapInputs={...base,release_mode:'rotation-overlap',release_lifecycle:'strict',
  rotation_expected_current_task_definition_arn:completion.expectedCurrentTaskDefinitionArn,
  rotation_readiness_evidence_json:readinessJson,rotation_readiness_evidence_sha256:completion.readinessSha256,
  rotation_fixture_sha256:completion.rotationFixtureSha256};
 const stateClient=createProductionComponentDeploymentStateClient({run});
 const overlapBefore=stateClient.read();
 const {runId:overlapRunId,child:overlapChild}=await runGate('OVERLAP',overlapInputs,
  {expectedBackendArn:completion.expectedCurrentTaskDefinitionArn,
   expectedFrontendArn:overlapBefore.components.frontend.taskDefinitionArn,
   targetBackendArn:completion.taskDefinitionArn,targetImageDigest:completion.imageDigest});
 await credentials.ensure();
 const resolved=resolveProductionOverlapDeploymentReceipt({workflowRunId:overlapRunId,workflowRunAttempt:String(overlapChild.run_attempt),sourceSha:env.TARGET_SHA,run:(command,args)=>execFileSync(command,args,{encoding:'utf8',stdio:['ignore','pipe','pipe'],maxBuffer:8*1024*1024})});
 assert.equal(resolved.receipt.rotationStateSha256,completion.rotationStateSha256);
 assert.equal(resolved.receipt.readinessSha256,completion.readinessSha256);
 const afterOverlap=stateClient.read();
 const alreadyNormal=await store.readOperation(operationId,'BRIDGE:GATE:NORMAL:RUN');
 if(!alreadyNormal){
  assert.equal(afterOverlap.components.backend.taskDefinitionArn,completion.taskDefinitionArn);
  assert.equal(afterOverlap.components.backend.imageDigest,completion.imageDigest);
  assert.equal(componentDeploymentProvenance(afterOverlap,'backend').githubRunId,String(overlapRunId));
 }
 const required=requiredWorkflowFiles('authenticated-initial-overlap'),gateRunIds={};
 for(const file of required){
  await requireMain();
  const name=`BRIDGE:POST_CUTOVER_GATE:${file}`;
  const inputs=usesLifecycleInputs('authenticated-initial-overlap',file)?{
   release_lifecycle:'authenticated-initial-overlap',target_sha:env.TARGET_SHA,rotation_id:env.BRIDGE_ROTATION_ID,
   rotation_state_json:stateJson,rotation_state_sha256:completion.rotationStateSha256,
   rotation_task_definition_arn:completion.taskDefinitionArn,rotation_image_digest:completion.imageDigest,
   rotation_deployment_sha:completion.deploymentSha}:{};
  let record=await store.readOperation(operationId,`${name}:RUN`);
  if(record)assert.deepEqual(record.inputs,inputs);
  else{
   const child=await dispatchSource({repository,token:env.GH_TOKEN,workflow:file,ref:'main',targetSha:env.TARGET_SHA,inputs,
    dispatchJournal:{read:()=>store.readOperation(operationId,`${name}:DISPATCH`),write:async value=>{
     assert.equal(await store.writeOperation(operationId,`${name}:DISPATCH`,value),true,'Concurrent gate dispatch owns this attempt');
    }}});
   record={inputs,runId:String(child.id)};await store.writeOperation(operationId,`${name}:RUN`,record);
  }
  await waitChild(record.runId,file);gateRunIds[file]=record.runId;
  await credentials.ensure();
 }
 const transport=packReleaseEvidenceTransport({authorizationJson:env.NORMAL_IMAGE_AUTHORIZATION_JSON,
  authorizationSha256:env.NORMAL_IMAGE_AUTHORIZATION_SHA256,historicalRuntimeJson:env.HISTORICAL_RUNTIME_EVIDENCE_JSON,
  historicalRuntimeSha256:env.HISTORICAL_RUNTIME_EVIDENCE_SHA256});
 const normalInputs={...base,release_mode:'normal',release_lifecycle:'authenticated-initial-overlap',
  required_gate_run_ids_json:JSON.stringify(gateRunIds),normal_image_authorization_json:transport.json,
  normal_image_authorization_sha256:transport.sha256,
  ...(env.WEB_IMAGE_AUTHORIZATION_JSON?{web_image_authorization_json:env.WEB_IMAGE_AUTHORIZATION_JSON}:{})};
 const {runId:normalRunId,child:normalChild}=await runGate('NORMAL',normalInputs,
  {expectedBackendArn:completion.taskDefinitionArn,expectedFrontendArn:afterOverlap.components.frontend.taskDefinitionArn,
   expectedOverlapRunId:overlapRunId});
 // A failed workflow can still have a completed deployment job; native receipts decide reuse.
 await credentials.ensure();
 const jobs=await fetchJson(`actions/runs/${normalRunId}/attempts/${normalChild.run_attempt}/jobs?per_page=100`);
 const job=(jobs.jobs||[]).filter(item=>item.name==='Deploy production ECS'&&String(item.run_id)===String(normalRunId));
 assert.equal(job.length,1);
 const approvals=await fetchJson(`actions/runs/${normalRunId}/approvals`);
 const artifacts=await fetchJson(`actions/runs/${normalRunId}/artifacts?per_page=100`);
 const artifact=async(name,file)=>{
  const matches=(artifacts.artifacts||[]).filter(item=>item.name===name&&!item.expired&&String(item.workflow_run?.id)===String(normalRunId));
  assert.equal(matches.length,1,`${name} artifact is not exact`);
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'mscqr-gate-artifact-'));fs.chmodSync(directory,0o700);
  try{gh(['run','download',String(normalRunId),'--repo',repository,'--name',name,'--dir',directory]);return JSON.parse(fs.readFileSync(path.join(directory,file),'utf8'));}
  finally{fs.rmSync(directory,{recursive:true,force:true});}
 };
 const rlsReceipt=await artifact(`production-rls-release-receipt-attempt-${normalChild.run_attempt}`,'production-rls-release-receipt.json');
 const backendActivation=await artifact(`production-normal-backend-activation-evidence-attempt-${normalChild.run_attempt}`,'backend-deployment.json');
 const liveService=name=>json(run,['ecs','describe-services','--cluster','mscqr-prod-euw2-main','--services',name]).services?.[0];
 const componentState=stateClient.read();
 const webRequired=auth.imageReuseEvidence?.webPublicationRequired===true;
 const frontendActivation=webRequired?await artifact(`production-frontend-activation-evidence-attempt-${normalChild.run_attempt}`,'frontend-activation.json'):undefined;
 const deployed=assertNormalGateCompletion({run:normalChild,job:job[0],approvals,releaseTrainRunId:boundParentRunId,
  sourceSha:env.TARGET_SHA,authorization:auth,rlsReceipt,backendActivation,frontendActivation,componentState,
  backendService:liveService('mscqr-backend-servi-euw2'),frontendService:liveService('mscqr-frontend-servi-euw2'),webRequired});
 const backendOperationId=gateEcsOperationId({sourceSha:env.TARGET_SHA,rotationId:env.BRIDGE_ROTATION_ID,
  releaseTrainRunId:boundParentRunId,authorizationSha256:auth.authorizationSha256,kind:'BACKEND'});
 const backendJournal=await store.readOperation(backendOperationId,'BACKEND:UPDATE:COMPLETED');
 assert.equal(backendJournal?.taskDefinitionArn,backendActivation.targetArn,'Backend native journal is incomplete');
 assert.equal(backendJournal.intent?.authorizationSha256,auth.authorizationSha256);
 const backendLive=liveService('mscqr-backend-servi-euw2');
 assert.equal(backendJournal.nativeResult?.serviceArn,backendLive?.serviceArn);
 assert.equal(backendJournal.nativeResult?.deploymentId,backendLive?.deployments?.[0]?.id);
 if(webRequired){
  const webAuthorization=JSON.parse(env.WEB_IMAGE_AUTHORIZATION_JSON);
  const frontendOperationId=gateEcsOperationId({sourceSha:env.TARGET_SHA,rotationId:env.BRIDGE_ROTATION_ID,
   releaseTrainRunId:boundParentRunId,authorizationSha256:webAuthorization.authorizationSha256,kind:'FRONTEND'});
  const registration=await store.readOperation(frontendOperationId,'FRONTEND:REGISTER:COMPLETED');
  const frontendUpdate=await store.readOperation(frontendOperationId,'FRONTEND:UPDATE:COMPLETED');
  const activation=await store.readOperation(frontendOperationId,'FRONTEND:ACTIVATION:COMPLETED');
  assert.equal(registration?.taskDefinitionArn,frontendActivation.candidateTaskDefinitionArn,'Frontend native registration journal is incomplete');
  const frontendLive=liveService('mscqr-frontend-servi-euw2');
  assert.equal(frontendUpdate?.nativeResult?.serviceArn,frontendLive?.serviceArn);
  assert.equal(frontendUpdate?.nativeResult?.deploymentId,frontendLive?.deployments?.[0]?.id);
  assert.equal(frontendUpdate?.taskDefinitionArn,frontendActivation.candidateTaskDefinitionArn);
  assert.equal(activation?.candidateTaskDefinitionArn,frontendActivation.candidateTaskDefinitionArn,'Frontend activation journal is incomplete');
  assert.equal(activation?.imageRef,frontendActivation.imageRef);
 }
 const componentOperationId=componentCommitOperationId({sourceSha:env.TARGET_SHA,rotationId:env.BRIDGE_ROTATION_ID,
  releaseTrainRunId:boundParentRunId,authorizationSha256:auth.authorizationSha256});
 const componentJournal=await store.readOperation(componentOperationId,'COMPONENT:STATE:COMPLETED');
 assert.equal(componentJournal?.stateSha256,stateHash(componentState),'Component-state native journal is incomplete');
 const smokeId=smokeOperationId({sourceSha:env.TARGET_SHA,rotationId:env.BRIDGE_ROTATION_ID,
  releaseTrainRunId:boundParentRunId});
 const smokeReceipt=await store.readOperation(smokeId,`SMOKE:COMPLETED:${normalChild.run_attempt}`);
 assert.equal(smokeReceipt?.intent?.childRunId,String(normalRunId),'Exact-run production smoke receipt is missing');
 assert.equal(smokeReceipt.intent.sourceSha,env.TARGET_SHA);
 assert.equal(smokeReceipt.services?.backend?.taskDefinition,backendActivation.targetArn);
 assert.equal(smokeReceipt.services?.frontend?.taskDefinition,componentState.components.frontend.taskDefinitionArn);
 const receipt={name:'RELEASE_COMPLETE',releaseId:release.releaseId,sourceSha:env.TARGET_SHA,rotationId:env.BRIDGE_ROTATION_ID,
  requestSha256:verified.request.requestSha256,terminalEnvironmentApprovalSha256:verified.request.environmentApprovalSha256,
  terminalCompletionSha256:brokerDigest(completion),overlapGateReviewer:resolved.reviewer,
  overlapGateRunId:String(overlapRunId),overlapGateWorkflowConclusion:overlapChild.conclusion,overlapReceiptSha256:resolved.receipt.receiptSha256,
  normalGateRunId:String(normalRunId),normalGateWorkflowConclusion:normalChild.conclusion,normalGateApprovalUserId:approvals.find(item=>item.state==='approved'&&item.environments?.some(environment=>environment.name==='production')).user.id,
  parentReleaseTrainRunId:boundParentRunId,completionInvocationRunId:String(env.GITHUB_RUN_ID),gateRunIds,
  imageAuthorizationSha256:env.NORMAL_IMAGE_AUTHORIZATION_SHA256,
  ...deployed,completedAt:new Date(now()).toISOString()};
 const existing=await store.readStep(release.releaseId,'RELEASE_COMPLETE');
 if(existing){
  const {completedAt:priorCompletedAt,completionInvocationRunId:priorInvocation,...priorBody}=existing;
  const {completedAt,completionInvocationRunId,...expectedBody}=receipt;
  assert.ok(Number.isSafeInteger(Date.parse(priorCompletedAt))&&/^[1-9][0-9]*$/.test(String(priorInvocation)));
  assert.deepEqual(priorBody,expectedBody,'Persisted RELEASE_COMPLETE differs from authenticated live completion');
  return existing;
 }
 await store.writeStep(receipt);
 assert.deepEqual(await store.readStep(release.releaseId,'RELEASE_COMPLETE'),receipt,'Final release receipt readback differs');
 return receipt;
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)
 runHostedBridge().then(receipt=>process.stdout.write(`RELEASE_COMPLETE=true\nRELEASE_ID=${receipt.releaseId}\n`),error=>{process.stderr.write(`${error.message}\n`);process.exitCode=1;});
