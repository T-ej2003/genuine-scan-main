import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import {createBrokerProtectedEnvironmentAuthorization} from '../aws/stage-b-staged-broker-authorization.mjs';
import {createProductionEnvironmentApprovalEvidence,PRODUCTION_ENVIRONMENT_APPROVAL} from '../aws/production-github-environment-approval.mjs';
import {brokerDigest,prepareBrokerStateRefresh} from '../aws/stage-b-staged-broker-contract.mjs';
import {STAGE_B_TERRAFORM_BACKEND_CONFIG} from '../aws/stage-b-terraform-backend-contract.mjs';
import {createHostedSuccessorRuntime} from '../aws/run-production-successor-release-coordinator.mjs';
import {runSuccessorReleaseCoordinator} from '../aws/production-successor-release-coordinator.mjs';
import {HOSTED_RELEASE_ROOT,releaseTransitionDispatchInputs} from '../aws/production-release-coordinator.mjs';
import {deriveStageBToolingInputTreeSha256} from '../aws/validate-stage-b-image-reuse.mjs';
import {ROOT_ATTESTATION_KEY_ALIAS_ARN,ROOT_ATTESTATION_SIGNING_ALGORITHM} from '../aws/production-root-attestation-key.mjs';
import {rig,ready,authorization as authorize} from './fixtures/staged-broker-runtime.mjs';

const A='29406b0ec537ac60618642bba20133dd0cf45529',C='7b40ee371b7751e19a413a4789c516c779af09d9',E='cdcc33eeee92eadaf0b07333d241015e220bf37b',D='dbc862c8aea597fb0d7c34bc1b1d04b26c83801d';
const binary=bytes=>({kind:'PRODUCTION_RELEASE_BINARY',sha256:brokerDigest(bytes),base64:bytes.toString('base64')});

test('hosted successor materializer consumes immutable import reference and original-release contracts under descendant tooling',async()=>{
 const packageBytes=Buffer.from('published-broker-package'),packageSha256=brokerDigest(packageBytes);
 const rigged=rig({sourceSha:A,packageIdentity:packageSha256,toolingTreeSha256:deriveStageBToolingInputTreeSha256(A)});
 const published=await ready(rigged),preparation=structuredClone(rigged.p),result=structuredClone(published.p.publication);
 const historicalBytes=Buffer.from(JSON.stringify({version:4,lineage:preparation.state.lineage,serial:preparation.state.serial,outputs:{},resources:[]}));
 preparation.state.stateSha256=brokerDigest(historicalBytes);const authorization=authorize(preparation);
 result.preparationSha256=brokerDigest(preparation);result.authorizationSha256=brokerDigest(authorization);
 const statePath='/private/tmp/original-publication/broker-package.zip';
 const currentBytes=Buffer.from(JSON.stringify({version:4,lineage:preparation.state.lineage,serial:preparation.state.serial+1,outputs:{},resources:[
  {mode:'managed',type:'aws_lambda_function',name:'broker',instances:[{attributes:{filename:statePath,
   source_code_hash:Buffer.from(packageSha256,'hex').toString('base64')}}]},
 ]}));
 const imageBytes=Buffer.from(JSON.stringify({imageReleaseSha:'9'.repeat(40),workflowRunId:'123',canonicalArtifactSha256:'1'.repeat(64)}));
 const signatureBytes=Buffer.from(JSON.stringify({signed:true}));
 const artifacts=new Map(),steps=new Map(),starts=new Map();let crashAfter;
 const store={putArtifact:(id,value)=>{assert.equal(brokerDigest(value),id);artifacts.set(id,value);},
  getArtifact:id=>{assert.ok(artifacts.has(id));return structuredClone(artifacts.get(id));},
  readStep:(id,name)=>steps.get(`${id}/${name}`)||null,
  writeStep:value=>{const key=`${value.releaseId}/${value.name}`,old=steps.get(key);
   if(old)assert.deepEqual(old,value);else steps.set(key,structuredClone(value));
   if(crashAfter===value.name){crashAfter=null;throw new Error(`Process stopped after ${value.name}`);}},
  readStart:key=>starts.get(JSON.stringify(key))||null,
  writeStart:(key,value)=>{const id=JSON.stringify(key),old=starts.get(id);
   if(old)assert.deepEqual(old,value);else starts.set(id,structuredClone(value));}};
 const put=value=>{const ref=brokerDigest(value);store.putArtifact(ref,value);return ref;};
 const historicalReference=put(binary(historicalBytes)),imageEvidenceReference=put(binary(imageBytes)),
  imageSignatureReference=put(binary(signatureBytes));
 const receipt={kind:'STAGE_B_HISTORICAL_STATE_IMPORT',releaseSourceSha:A,recoveryToolingSha:C,recoveryId:'2'.repeat(64),
  publicationResultSha256:brokerDigest(result),importerArn:'arn:aws:iam::368992683803:root',
  historical:{bucket:'mscqr-production-terraform-state-368992683803-eu-west-2',
   key:'env:/production/mscqr/production/rls-green/stage-b/terraform.tfstate',
   versionId:'exact-historical-version',sha256:brokerDigest(historicalBytes),lineage:preparation.state.lineage,
   serial:preparation.state.serial},artifactReference:historicalReference};
 const historicalImportReference=put({...receipt,signature:{keyArn:ROOT_ATTESTATION_KEY_ALIAS_ARN,
  signingAlgorithm:ROOT_ATTESTATION_SIGNING_ALGORITHM,receiptSha256:brokerDigest(receipt),signatureBase64:'AQ=='}});
 const request={kind:'STAGE_B_SUCCESSOR_CUTOVER_REQUEST',releaseSourceSha:A,recoveryToolingSha:C,recoveryId:receipt.recoveryId,
  ticketId:'MSCQR-RECOVER',brokerVersion:'13',expectedAliasVersion:'12',expectedAliasRevision:preparation.alias.RevisionId,historicalImportReference,
  currentStateSha256:brokerDigest(currentBytes),publicationResultSha256:brokerDigest(result),
  imageEvidenceReference,imageSignatureReference};
 const env={GITHUB_ACTIONS:'true',GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_REPOSITORY:'T-ej2003/genuine-scan-main',
  GITHUB_WORKFLOW_REF:'T-ej2003/genuine-scan-main/.github/workflows/recover-production-stage-b-successor.yml@refs/heads/main',
  GITHUB_SHA:C,GITHUB_RUN_ATTEMPT:'1',GITHUB_RUN_ID:'700',RUNNER_TEMP:'/tmp'};
 const releaseId='d'.repeat(64),directory=path.join(HOSTED_RELEASE_ROOT,releaseId,'cutover');let continuationReleaseId;
 const run=args=>{if(args[0]!=='s3api'||args[1]!=='get-object')throw new Error('Unexpected AWS operation');
  const bytes=args.includes('env:/production/mscqr/production/rls-green/stage-b/terraform.tfstate')?currentBytes:Buffer.from('{}');
  fs.writeFileSync(args.at(-1),bytes,{mode:0o600});return '{}';};
 let imageObservation,providerError=false;const terraformCalls=[];
 let liveAlias=preparation.alias,casReceipt,nativeStatus,liveState;
 const runtime=createHostedSuccessorRuntime({env,awsRun:run,ghRun:args=>{
   if(args[1].endsWith('/actions/runs/700'))return JSON.stringify({id:700,workflow_id:77,repository:{full_name:'T-ej2003/genuine-scan-main'},
    head_repository:{full_name:'T-ej2003/genuine-scan-main'},head_sha:C,head_branch:'main',
    path:'.github/workflows/authorize-production-stage-b-release-transition.yml',event:'workflow_dispatch',run_attempt:1,status:'completed',conclusion:'failure'});
   if(args[1].endsWith('/artifacts'))return JSON.stringify([{artifacts:[]}]);
   throw new Error(`Unexpected GitHub call ${args.join(' ')}`);},
  createStore:()=>store,authenticateTooling:(a,c)=>{assert.equal(a,A);assert.ok([C,D,E].includes(c));},verifyImport:()=>true,
  readAuthority:()=>({preparation,authorization}),readState:()=>liveState,readReceipt:({status})=>{
   if(['STATE_REFRESH_INTENT','STATE_REFRESH_UNKNOWN','RECONCILED_PENDING_RELEASE_CAS','STAGED_BROKER_TERMINAL_HANDOFF'].includes(status)){
    if(status===nativeStatus)return {};throw Object.assign(new Error('Absent'),{code:'RECEIPT_ABSENT'});}
   return status==='CUTOVER_COMMITTED_STATE_PENDING'?casReceipt:result;},
  verifyAuthorization:async()=>true,readVersion:()=>rigged.deps.getVersion('13'),readReviewedAlias:()=>liveAlias,
  authenticateImages:({request:seen,evidence,imageReleaseSha,now})=>{
   assert.equal(seen.recoveryToolingSha,C);assert.equal(evidence.imageReleaseSha,imageReleaseSha);imageObservation=now;},
  packageBroker:async({outputPath,manifestPath,toolingSha})=>{
   assert.equal(toolingSha,A);fs.writeFileSync(outputPath,packageBytes,{mode:0o600});
   fs.writeFileSync(manifestPath,'{}',{mode:0o600});},
  generateStageA:({outputPath,toolingSha})=>{assert.equal(toolingSha,A);fs.writeFileSync(outputPath,'{}',{mode:0o600});},
  generateTfvars:({outputPath,bindingReportPath,checksumsFile,toolingSha,brokerPackageHistoricalSourceSha,successorBrokerPackageStatePath})=>{
   assert.equal(toolingSha,A);assert.equal(brokerPackageHistoricalSourceSha,A);
   assert.equal(successorBrokerPackageStatePath,statePath);
   assert.deepEqual(fs.readFileSync(checksumsFile),Buffer.from(fs.readFileSync(checksumsFile)));
   fs.writeFileSync(outputPath,'tooling_sha = "'+A+'"\n',{mode:0o600});
   fs.writeFileSync(bindingReportPath,'{"toolingSha":"'+A+'"}',{mode:0o600});},
  commandRun:(command,args,{env:commandEnv})=>{terraformCalls.push({command,args,env:commandEnv});
   if(args.includes('-backend=false')){if(providerError)throw new Error('Provider installation failed');return;}
   const metadata=path.join(commandEnv.TF_DATA_DIR,'terraform.tfstate');
   fs.writeFileSync(metadata,JSON.stringify({backend:{type:'s3',hash:1,config:STAGE_B_TERRAFORM_BACKEND_CONFIG}}),{mode:0o600});}});
 try{
  await assert.rejects(()=>runtime.authenticateRequest({...request,expectedAliasRevision:'other-revision'}),
   /alias revision changed/);
  await runtime.authenticateRequest(request);
  const inputs=await runtime.materializeInputs({request,release:{sourceSha:A,releaseId},phase:'cutover',
   prepared:null,publication:{preparation,authorization,result}});
  assert.deepEqual(fs.readFileSync(inputs.successorRecovery.historicalStatePath),historicalBytes);
  assert.deepEqual(fs.readFileSync(inputs.successorRecovery.currentStatePath),currentBytes);
  assert.deepEqual(fs.readFileSync(inputs.successorRecovery.imageEvidencePath),imageBytes);
  assert.deepEqual(fs.readFileSync(inputs.successorRecovery.imageSignaturePath),signatureBytes);
  assert.equal(JSON.parse(fs.readFileSync(inputs.successorRecovery.bindingReportPath)).toolingSha,A);
  assert.equal(fs.readFileSync(inputs.files.package).toString(),'published-broker-package');
  const saved={planPath:path.join(directory,'saved.tfplan')};
  const metadata=fs.readFileSync(inputs.files.backendMetadata);
  for(const phase of ['cutover','closure']){
   const resumed=await runtime.materializeInputs({request,release:{sourceSha:A,releaseId},phase,prepared:saved});
   assert.equal(resumed.terraformDataDir,inputs.terraformDataDir);
   assert.deepEqual(terraformCalls.at(-1).args,[terraformCalls[0].args[0],'init','-backend=false','-input=false','-lockfile=readonly','-no-color']);
   assert.equal(terraformCalls.at(-1).env.TF_DATA_DIR,inputs.terraformDataDir);
   assert.equal(terraformCalls.at(-1).env.TF_WORKSPACE,'default');
   assert.deepEqual(fs.readFileSync(inputs.files.backendMetadata),metadata,'Provider installation must preserve authenticated backend metadata');
  }
  const callsBeforeInvalid=terraformCalls.length;
  await assert.rejects(()=>runtime.materializeInputs({release:{releaseId},phase:'cutover',prepared:{planPath:'/tmp/other/saved.tfplan'}}));
  assert.equal(terraformCalls.length,callsBeforeInvalid,'Reject substituted phase path before initialization');
  fs.unlinkSync(inputs.files.backendMetadata);
  await runtime.materializeInputs({release:{releaseId},phase:'cutover',prepared:saved});
  assert.equal(fs.existsSync(inputs.files.backendMetadata),false,'Fresh runner must obtain metadata from authenticated hydration');
  fs.writeFileSync(inputs.files.backendMetadata,metadata,{mode:0o600});
  providerError=true;
  await assert.rejects(()=>runtime.materializeInputs({release:{releaseId},phase:'closure',prepared:saved}),/Provider installation failed/);
  await assert.rejects(()=>runtime.materializeInputs({release:{releaseId},phase:'closure',prepared:null,
   cutover:{prepared:{materializationSha256:'1'.repeat(64)}}}),/Provider installation failed/,
  'First closure materialization must initialize providers before hydrating cutover evidence');
  providerError=false;
  const identity={schemaVersion:2,sourceSha:A,ticketId:request.ticketId,
   recoveryReference:brokerDigest(request),toolingSha:C},operationId=brokerDigest(identity);
  const old={preparation:{successorReconciliation:{createdAt:'2026-10-01T00:00:00.000Z'}}};
  const renewed={preparation:{successorReconciliation:{createdAt:'2026-10-10T09:00:00.000Z'}}};
  const oldRef=put(old),renewedRef=put(renewed);
  steps.set(`${operationId}/cutover:prepared`,{result:oldRef});
  steps.set(`${operationId}/cutover:prepared:1`,{result:renewedRef});
  steps.set(`${operationId}/cutover:attempt:1`,{prepared:renewedRef});
  await runtime.authenticateRequest(request);
  assert.equal(imageObservation,'2026-10-10T09:00:00.000Z');
  const recoveryReference=brokerDigest(request),release={schemaVersion:2,sourceSha:A,ticketId:request.ticketId,recoveryReference,toolingSha:C};
  continuationReleaseId=brokerDigest(release);release.releaseId=continuationReleaseId;
  const cutoverPreparation=structuredClone(published.p);cutoverPreparation.recoveryTooling={sourceSha:C,
   treeSha256:deriveStageBToolingInputTreeSha256(C),publicationResultSha256:brokerDigest(cutoverPreparation.publication)};
  const cutoverAuthorization=authorize(cutoverPreparation),casResult={status:'CUTOVER_COMMITTED_STATE_PENDING',
   preparationSha256:brokerDigest(cutoverPreparation),authorizationSha256:brokerDigest(cutoverAuthorization),
   alias:{...preparation.alias,FunctionVersion:'13',RevisionId:'cas-complete'},authorizedAt:cutoverAuthorization.issuedAt};
  casReceipt=casResult;liveAlias=casResult.alias;
  const cutoverPrepared={preparation:cutoverPreparation,planPath:path.join(HOSTED_RELEASE_ROOT,continuationReleaseId,'cutover','cutover.tfplan'),
   materializationSha256:'8'.repeat(64)};
  const cutoverPreparedRef=put(cutoverPrepared),cutoverAuthorizationRef=put(cutoverAuthorization),casResultRef=put(casResult);
  steps.set(`${continuationReleaseId}/cutover:result`,{sourceSha:A,releaseId:continuationReleaseId,name:'cutover:result',prepared:cutoverPreparedRef,
   authorization:cutoverAuthorizationRef,result:casResultRef});
  const oldClosure={...cutoverPrepared,preparation:prepareBrokerStateRefresh({preparation:cutoverPreparation,authorization:cutoverAuthorization,casResult})};
  const oldClosureRef=put(oldClosure),dispatchInputs=releaseTransitionDispatchInputs({release,authorizationRound:0},'closure',oldClosureRef,oldClosure.preparation);
  steps.set(`${continuationReleaseId}/closure:prepared`,{releaseId:continuationReleaseId,sourceSha:A,name:'closure:prepared',result:oldClosureRef});
  steps.set(`${continuationReleaseId}/closure:pending:0`,{releaseId:continuationReleaseId,sourceSha:A,name:'closure:pending:0',prepared:oldClosureRef,runId:'700'});
  steps.set(`${continuationReleaseId}/closure:dispatch:0`,{releaseId:continuationReleaseId,sourceSha:A,name:'closure:dispatch:0',
   dispatch:{identity:{repository:'T-ej2003/genuine-scan-main',workflow:'authorize-production-stage-b-release-transition.yml',
    workflowPath:'.github/workflows/authorize-production-stage-b-release-transition.yml',workflowId:77,ref:'main',targetSha:C,inputs:dispatchInputs},
    beforeRunIds:['699']}});
  env.GITHUB_SHA=D;
  const continuation=await runtime.authenticateRequest(request);
  assert.deepEqual(continuation,{round:1,previousRound:0,currentTooling:{sourceSha:D,treeSha256:deriveStageBToolingInputTreeSha256(D)},
   supersededAuthorization:{runId:'700',toolingSha:C,conclusion:'failure',preparationReference:oldClosureRef,authorizationRound:0}});
  assert.equal(steps.get(`${continuationReleaseId}/cutover:result`).result,casResultRef,'Continuation must adopt the completed CAS receipt');
  assert.equal(liveAlias.FunctionVersion,'13','Continuation must not move the reviewed alias');
  const binding={schemaVersion:1,releaseId:continuationReleaseId,recoveryReference,releaseSourceSha:A,
   historicalTooling:cutoverPreparation.recoveryTooling,currentTooling:continuation.currentTooling,
   cutover:oldClosure.preparation.cutover};
  const continued={...cutoverPrepared,preparation:prepareBrokerStateRefresh({preparation:cutoverPreparation,
   authorization:cutoverAuthorization,casResult,closureContinuation:{...binding,operationId:brokerDigest(binding)}})};
  const continuedRef=put(continued),savedRound={releaseId:continuationReleaseId,sourceSha:A,name:'closure:prepared:1',result:continuedRef};
  steps.set(`${continuationReleaseId}/closure:prepared:1`,savedRound);
  assert.deepEqual(await runtime.authenticateRequest(request),{currentTooling:continuation.currentTooling,round:1});
  env.GITHUB_SHA=E;
  const advanced=await runtime.authenticateRequest(request);
  assert.equal(advanced.round,2);assert.equal(advanced.previousRound,1);assert.equal(advanced.currentTooling.sourceSha,E);
  assert.deepEqual(steps.get(`${continuationReleaseId}/closure:prepared:1`),savedRound,'Historical round remains immutable');
  const issued=new Date(Date.now()-60*60_000);
  const approval=createProductionEnvironmentApprovalEvidence({environmentConfig:{id:7,name:'production',can_admins_bypass:false,
   protection_rules:[{type:'required_reviewers',prevent_self_review:false,reviewers:[{type:'User',reviewer:{id:1,login:'operator'}}]}]},
   repository:PRODUCTION_ENVIRONMENT_APPROVAL.repository,environment:'production',sourceSha:D,
   workflowRef:PRODUCTION_ENVIRONMENT_APPROVAL.stageBReleaseTransitionWorkflowRef,eventName:'workflow_dispatch',workflowRunId:'701',
   workflowRunAttempt:'1',executionActor:'operator',observedAt:issued.toISOString(),
   actualApproval:{state:'approved',environmentId:7,environmentName:'production',userId:1,userLogin:'operator'}});
  liveState=continued.preparation.state;
  const oldAuthorization=createBrokerProtectedEnvironmentAuthorization(continued.preparation,{approval,now:issued,
   release:{releaseId:continuationReleaseId,phase:'closure',preparationReference:continuedRef,authorizationRound:1}});
  for(const kind of ['attempt','authorized'])steps.set(`${continuationReleaseId}/closure:${kind}:1`,{
   releaseId:continuationReleaseId,sourceSha:A,name:`closure:${kind}:1`,prepared:continuedRef,authorization:put(oldAuthorization)});
  const aborted=await runtime.authenticateRequest(request);
  assert.equal(aborted.round,2);assert.equal(aborted.preNativeAbort.status,'PRE_NATIVE_ABORTED');
  assert.equal(aborted.preNativeAbort.authorization,brokerDigest(oldAuthorization));
  assert.equal(aborted.preNativeAbort.currentTooling.sourceSha,E);
  for(const status of ['STATE_REFRESH_INTENT','STATE_REFRESH_UNKNOWN','RECONCILED_PENDING_RELEASE_CAS','STAGED_BROKER_TERMINAL_HANDOFF']){
   nativeStatus=status;await assert.rejects(()=>runtime.authenticateRequest(request),/requires native recovery/);
  }
  nativeStatus=undefined;
  steps.delete(`${continuationReleaseId}/closure:attempt:1`);
  const expiredRetirement={releaseId:continuationReleaseId,sourceSha:A,name:'closure:retired:1',
   prepared:continuedRef,reason:'AUTHORIZATION_EXPIRED'};
  steps.set(`${continuationReleaseId}/closure:retired:1`,expiredRetirement);
  const expired=await runtime.authenticateRequest(request);
  assert.equal(expired.round,2);assert.equal(expired.preNativeAbort.status,'PRE_NATIVE_ABORTED');
  assert.equal(Object.hasOwn(expired.preNativeAbort,'attemptSha256'),false);
  assert.equal(expired.preNativeAbort.authorization,brokerDigest(oldAuthorization));
  assert.deepEqual(steps.get(`${continuationReleaseId}/closure:retired:1`),expiredRetirement);
  await assert.rejects(()=>runtime.authenticateRequest({...request,ticketId:'DIFFERENT-TICKET'}));
  const wrongRound={releaseId:continuationReleaseId,sourceSha:A,name:'closure:prepared:3',result:continuedRef};
  steps.set(`${continuationReleaseId}/closure:prepared:3`,wrongRound);
  await assert.rejects(()=>runtime.authenticateRequest(request),/missing round/);
  steps.delete(`${continuationReleaseId}/closure:prepared:3`);
  const signedKey=`${continuationReleaseId}/closure:authorized:1`,signed=steps.get(signedKey);
  for(const [name,change] of [
   ['reason',()=>{expiredRetirement.reason='PRE_NATIVE_ABORTED';return ()=>expiredRetirement.reason='AUTHORIZATION_EXPIRED';}],
   ['preparation',()=>{expiredRetirement.prepared='f'.repeat(64);return ()=>expiredRetirement.prepared=continuedRef;}],
   ['authorization',()=>{steps.delete(signedKey);return ()=>steps.set(signedKey,signed);}],
   ['native uncertainty',()=>{nativeStatus='STATE_REFRESH_UNKNOWN';return ()=>nativeStatus=undefined;}],
   ['state drift',()=>{liveState={...continued.preparation.state,serial:999};return ()=>liveState=continued.preparation.state;}],
   ['alias drift',()=>{liveAlias={...casResult.alias,RevisionId:'wrong'};return ()=>liveAlias=casResult.alias;}],
  ]){const restore=change();await assert.rejects(()=>runtime.authenticateRequest(request),undefined,name);restore();}
  steps.delete(`${continuationReleaseId}/closure:retired:1`);
  await assert.rejects(()=>runtime.authenticateRequest(request));
  steps.set(`${continuationReleaseId}/closure:retired:1`,expiredRetirement);
  steps.delete(signedKey);expiredRetirement.reason='UNKNOWN';
  await assert.rejects(()=>runtime.authenticateRequest(request));
  steps.set(signedKey,signed);expiredRetirement.reason='AUTHORIZATION_EXPIRED';

  let closureWrites=0,approvalCalls=0;
  assert.equal(put(request),recoveryReference);
  steps.set(`${continuationReleaseId}/cutover:prepared`,{releaseId:continuationReleaseId,sourceSha:A,
   name:'cutover:prepared',result:oldRef});
  const resume=()=>runSuccessorReleaseCoordinator({recoveryReference},
   {...runtime,now:()=>Date.now(),materializeInputs:async()=>({files:{},directory:'/tmp',terraformDataDir:'/tmp'}),
    hydratePreparation:async()=>{},authenticateAuthorization:async()=>{},authenticateCompletedTransition:async()=>{},
    capturePreparation:async(_context,_phase,value)=>value,
    obtainAuthorization:async(context,phase,prepared,reference)=>{
     approvalCalls++;assert.equal(phase,'closure');assert.equal(context.authorizationRound,2);
     const issued=new Date();const approval=createProductionEnvironmentApprovalEvidence({environmentConfig:{id:7,name:'production',
      can_admins_bypass:false,protection_rules:[{type:'required_reviewers',prevent_self_review:false,
       reviewers:[{type:'User',reviewer:{id:1,login:'operator'}}]}]},repository:PRODUCTION_ENVIRONMENT_APPROVAL.repository,
      environment:'production',sourceSha:E,workflowRef:PRODUCTION_ENVIRONMENT_APPROVAL.stageBReleaseTransitionWorkflowRef,
      eventName:'workflow_dispatch',workflowRunId:'702',workflowRunAttempt:'1',executionActor:'operator',observedAt:issued.toISOString(),
      actualApproval:{state:'approved',environmentId:7,environmentName:'production',userId:1,userLogin:'operator'}});
     return {status:'AUTHORIZED',authorization:createBrokerProtectedEnvironmentAuthorization(prepared.preparation,{approval,now:issued,
      release:{releaseId:continuationReleaseId,phase,preparationReference:reference,authorizationRound:2}})};},
    classifyNativeAttempt:async()=> 'PRE_NATIVE',
    runStageOperation:async input=>{assert.equal(input.operation,'reconcile');closureWrites++;
     return {status:'RECONCILED_PENDING_RELEASE_CAS',preparationSha256:brokerDigest(input.preparation),
      authorizationSha256:brokerDigest(input.authorization)};},
    authenticateClosure:async()=>({status:'CLOSED',sourceSha:A})});
  for(const boundary of ['closure:prepared:2','closure:authorized:2']){
   crashAfter=boundary;await assert.rejects(resume,new RegExp(`Process stopped after ${boundary}`));
   assert.equal(closureWrites,0,'No native refresh before signed authorization survives restart');
   assert.deepEqual(steps.get(`${continuationReleaseId}/closure:retired:1`),expiredRetirement);
  }
  assert.equal((await resume()).status,'BROKER_CLOSURE_COMPLETE');
  assert.equal(closureWrites,1);assert.equal(approvalCalls,1);
  assert.ok(steps.get(`${continuationReleaseId}/closure:result`));
  assert.equal((await resume()).status,'BROKER_CLOSURE_COMPLETE');assert.equal(closureWrites,1);

  const forged=structuredClone(continued);forged.preparation.closureContinuation.currentTooling.treeSha256='0'.repeat(64);
  steps.set(`${continuationReleaseId}/closure:prepared:1`,{...savedRound,result:put(forged)});
  await assert.rejects(()=>runtime.authenticateRequest(request));
  steps.set(`${continuationReleaseId}/closure:prepared:1`,savedRound);
  assert.deepEqual(await runtime.authenticateRequest(request),{currentTooling:advanced.currentTooling,completed:true});
  env.GITHUB_SHA=C;
  // Earlier tooling must not authenticate closure executed by D.
  env.GITHUB_SHA='a61282bfebbf45002c164669838fd3dfb7b86220';
  await assert.rejects(()=>runtime.authenticateRequest(request));

}finally{fs.rmSync(path.join(HOSTED_RELEASE_ROOT,releaseId),{recursive:true,force:true});
 if(continuationReleaseId)fs.rmSync(path.join(HOSTED_RELEASE_ROOT,continuationReleaseId),{recursive:true,force:true});}
});
