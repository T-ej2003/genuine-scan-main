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
import {assertNormalGateCompletion} from './production-release-gate-completion.mjs';
import {dispatchSourceBoundWorkflow,dispatchProtectedMainReleaseGate} from '../github/dispatch-source-bound-workflow.mjs';
import {requiredWorkflowFiles,usesLifecycleInputs} from '../github/release-lifecycle-contract.mjs';
import {packReleaseEvidenceTransport,unpackReleaseEvidenceTransport} from './production-release-dispatch-contract.mjs';
import {brokerDigest} from './stage-b-staged-broker-contract.mjs';
import {createBridgeCredentialRefresher} from './production-release-bridge-credentials.mjs';
import {fetchProductionEnvironmentApprovalEvidence,PRODUCTION_ENVIRONMENT_APPROVAL} from './production-github-environment-approval.mjs';

const repository='T-ej2003/genuine-scan-main';
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
const json=(run,args)=>JSON.parse(run([...args,'--output','json','--no-cli-pager']));
const gh=(args)=>execFileSync('gh',args,{encoding:'utf8',stdio:['ignore','pipe','pipe'],maxBuffer:8*1024*1024});

export async function runHostedBridge({env=process.env,requestCutover=runTerminalCutoverRequest,authenticate=authenticateTerminalCutover,
 dispatchSource=dispatchSourceBoundWorkflow,dispatchGate=dispatchProtectedMainReleaseGate,wait=sleep,fetchImpl=fetch,now=Date.now}={}){
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
 const start=await store.readStart({sourceSha:env.TARGET_SHA,ticketId:env.RELEASE_TICKET_ID});
 assert.ok(start);const release=await store.getArtifact(start.release);
 assert.equal(release.releaseId,requested.releaseId);assert.equal(release.releaseId,releaseId||release.releaseId);assert.equal(release.sourceSha,env.TARGET_SHA);
 process.stdout.write(`TRUSTED_TERMINAL_REQUEST_RELEASE_ID=${requested.releaseId}\nTRUSTED_TERMINAL_REQUEST_RUN_ID=${requested.workflowRunId}\nTRUSTED_TERMINAL_REQUEST_RUN_ATTEMPT=${requested.workflowRunAttempt}\n`);
 let verified;
 const verify=()=>authenticate({store,releaseId:release.releaseId,sourceSha:release.sourceSha,ticketId:release.ticketId,
  rotationId:env.BRIDGE_ROTATION_ID,manifestSha256:env.BRIDGE_MANIFEST_SHA256,
  observeApproval:(approval,request)=>fetchProductionEnvironmentApprovalEvidence({token:env.GH_TOKEN,
   repository:PRODUCTION_ENVIRONMENT_APPROVAL.repository,environment:'production',sourceSha:request.sourceSha,
   workflowRef:approval.workflowRef,eventName:'workflow_dispatch',workflowRunId:request.workflowRunId,
   workflowRunAttempt:request.workflowRunAttempt,executionActor:approval.executionActor,requireActualApproval:true}),
  verifyCheckerSignature:checkerBridgeVerifier(run),verifyRootSignature:rootBridgeVerifier(run),readLive:async input=>{
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
 for(let i=0;i<120;i++){
  await credentials.ensure();
  verified=await verify();if(verified)break;
  if(now()>=Date.parse(requested.expiresAt)){
   const dispatched=await Promise.all(['ROOT_DROP','INVENTORY_ADOPTION','ROTATION_SUCCESSOR']
    .map(phase=>store.readOperation(operationId,`BRIDGE:SIGN:${phase}:DISPATCH`)));
   if(dispatched.every(value=>!value))throw new Error('Trusted-terminal request expired before a native Sign dispatch');
  }
  await wait(15000);
 }
 assert.ok(verified,'Trusted-terminal completion was not durably authenticated');
 const {completion,readiness,readinessBytes,stateBytes}=verified;
 assert.equal(completion.operationId,operationId);
 const stateJson=stateBytes.toString('utf8'),readinessJson=readinessBytes.toString('utf8');
 const priorOverlap=await store.readOperation(operationId,'BRIDGE:GATE:OVERLAP:RUN');
 const boundParentRunId=priorOverlap?.inputs?.release_train_run_id||String(env.GITHUB_RUN_ID);
 const base={git_ref:'main',target_sha:env.TARGET_SHA,release_train_run_id:boundParentRunId,rotation_id:env.BRIDGE_ROTATION_ID,
  rotation_state_json:stateJson,rotation_state_sha256:completion.rotationStateSha256,
  rotation_task_definition_arn:completion.taskDefinitionArn,rotation_image_digest:completion.imageDigest,
  rotation_deployment_sha:completion.deploymentSha};
 const dispatchOnce=async(mode,inputs)=>{
  await credentials.ensure();
  await requireMain();
  const prefix=`BRIDGE:GATE:${mode}`,prior=await store.readOperation(operationId,`${prefix}:RUN`);
  if(prior){assert.deepEqual(prior.inputs,inputs,'Child Gate inputs changed during recovery');return prior.runId;}
  const child=await dispatchGate({repository,token:env.GH_TOKEN,targetSha:env.TARGET_SHA,targetRef:'main',inputs,
   dispatchJournal:{read:()=>store.readOperation(operationId,`${prefix}:DISPATCH`),write:value=>store.writeOperation(operationId,`${prefix}:DISPATCH`,value)}});
  const record={inputs,runId:String(child.id),headSha:child.head_sha};
  await store.writeOperation(operationId,`${prefix}:RUN`,record);
  assert.deepEqual(await store.readOperation(operationId,`${prefix}:RUN`),record);
  return record.runId;
 };
 const waitChild=async(id,workflow,{allowFailure=false,maxPolls=720}={})=>{
  for(let i=0;i<maxPolls;i++){
   const child=await fetchJson(`actions/runs/${id}`);
   assert.equal(String(child.id),String(id));assert.equal(child.head_sha,env.TARGET_SHA);
   assert.equal(child.path,`.github/workflows/${workflow}`);assert.equal(child.event,'workflow_dispatch');
   assert.equal(child.repository?.full_name,repository);assert.equal(child.head_repository?.full_name,repository);
   if(child.status==='completed'){
    if(!allowFailure)assert.equal(child.conclusion,'success',`${workflow} did not complete successfully`);
    else assert.ok(['success','failure'].includes(child.conclusion));
    return child;
   }
   await wait(15000);
  }
  throw new Error(`${workflow} did not reach a terminal authenticated status`);
 };
 const overlapInputs={...base,release_mode:'rotation-overlap',release_lifecycle:'strict',
  rotation_expected_current_task_definition_arn:completion.expectedCurrentTaskDefinitionArn,
  rotation_readiness_evidence_json:readinessJson,rotation_readiness_evidence_sha256:completion.readinessSha256,
  rotation_fixture_sha256:completion.rotationFixtureSha256};
 const overlapRunId=await dispatchOnce('OVERLAP',overlapInputs);
 const overlapChild=await waitChild(overlapRunId,'release-gate.yml',{allowFailure:true});
 await credentials.ensure();
 const resolved=resolveProductionOverlapDeploymentReceipt({workflowRunId:overlapRunId,workflowRunAttempt:String(overlapChild.run_attempt),sourceSha:env.TARGET_SHA,run:(command,args)=>execFileSync(command,args,{encoding:'utf8',stdio:['ignore','pipe','pipe'],maxBuffer:8*1024*1024})});
 assert.equal(resolved.receipt.rotationStateSha256,completion.rotationStateSha256);
 assert.equal(resolved.receipt.readinessSha256,completion.readinessSha256);
 const stateClient=createProductionComponentDeploymentStateClient({run});
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
    dispatchJournal:{read:()=>store.readOperation(operationId,`${name}:DISPATCH`),write:value=>store.writeOperation(operationId,`${name}:DISPATCH`,value)}});
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
 const normalRunId=await dispatchOnce('NORMAL',normalInputs);
 const normalChild=await waitChild(normalRunId,'release-gate.yml');
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
 const rlsReceipt=await artifact('production-rls-release-receipt','production-rls-release-receipt.json');
 const backendActivation=await artifact('production-normal-backend-activation-evidence','backend-deployment.json');
 const liveService=name=>json(run,['ecs','describe-services','--cluster','mscqr-prod-euw2-main','--services',name]).services?.[0];
 const componentState=stateClient.read();
 const webRequired=auth.imageReuseEvidence?.webPublicationRequired===true;
 const deployed=assertNormalGateCompletion({run:normalChild,job:job[0],approvals,releaseTrainRunId:boundParentRunId,
  sourceSha:env.TARGET_SHA,authorization:auth,rlsReceipt,backendActivation,componentState,
  backendService:liveService('mscqr-backend-servi-euw2'),frontendService:liveService('mscqr-frontend-servi-euw2'),webRequired});
 const receipt={name:'RELEASE_COMPLETE',releaseId:release.releaseId,sourceSha:env.TARGET_SHA,rotationId:env.BRIDGE_ROTATION_ID,
  requestSha256:verified.request.requestSha256,terminalEnvironmentApprovalSha256:verified.request.environmentApprovalSha256,
  terminalCompletionSha256:brokerDigest(completion),overlapGateReviewer:resolved.reviewer,
  overlapGateRunId:String(overlapRunId),overlapReceiptSha256:resolved.receipt.receiptSha256,
  normalGateRunId:String(normalRunId),normalGateApprovalUserId:approvals.find(item=>item.state==='approved'&&item.environments?.some(environment=>environment.name==='production')).user.id,
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
