#!/usr/bin/env node
import assert from 'node:assert/strict';
import {authenticatePreNativeClosureAbort} from './stage-b-pre-native-closure.mjs';
import {createBrokerKmsAuthorizationBoundary} from './stage-b-staged-broker-authorization.mjs';
import fs from 'node:fs';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {authenticateFailedReleaseTransitionAttempt,createReleaseCoordinatorStore,hydrateReleasePhaseMaterial,HOSTED_RELEASE_ROOT,
 releaseTransitionDispatchInputs,successorReleaseStartKey} from './production-release-coordinator.mjs';
import {brokerDigest,brokerExecutionCheckout,prepareBrokerStateRefresh} from './stage-b-staged-broker-contract.mjs';
import {PRODUCTION_ENVIRONMENT_APPROVAL} from './production-github-environment-approval.mjs';
import {createProductionAwsCommandRunner,PRODUCTION_AWS_CREDENTIAL_SOURCE} from './production-credential-source-contract.mjs';
import {ensureStageBPrivateDirectory,writeStageBPrivateFileAtomic} from './stage-b-artifact-contract.mjs';
import {runStagedBrokerRequest} from './run-stage-b-staged-broker.mjs';
import {produceConditionalOverlapAuthorization} from './production-cutover-conditional-workflow.mjs';
import {conditionalHash,assertConditionalDerivation,exactConditionalKeys} from './production-cutover-conditional-authorization.mjs';
import {assertConditionalProductionEnabled} from './production-green-stage-b-contract.mjs';
import {INDEPENDENT_REVIEW_V1,SOLO_OPERATOR_CONTROLLED_V1} from './production-cutover-human-policy.mjs';

const root=path.resolve(fileURLToPath(new URL('../..',import.meta.url)));
const operations=Object.freeze({registration:'authorize-registration',pruning:'authorize-pruning',policy:'authorize-policy',publication:'authorize-publication',cutover:'authorize-cutover',closure:'authorize-closure'});

export async function authorizeReleaseTransition({sourceSha,ticketId,releaseId,phase,preparationReference,authorizationRound,authorizationPolicyVersion=INDEPENDENT_REVIEW_V1,output},
 {env=process.env,run,
  ghRun=(args,options)=>execFileSync('gh',args,{encoding:'utf8',maxBuffer:8*1024*1024,...options}),runRequest=runStagedBrokerRequest,
  hydrateMaterial=hydrateReleasePhaseMaterial,createStore=createReleaseCoordinatorStore,authenticateAbort=authenticatePreNativeClosureAbort,fetchImpl=fetch}={}) {
 if(phase==='prepare-overlap-conditional') assertConditionalProductionEnabled();
 if(phase!=='prepare-overlap-conditional')assert.equal(authorizationPolicyVersion,INDEPENDENT_REVIEW_V1,'Solo policy is unavailable for broker phases');
 else assert.ok([INDEPENDENT_REVIEW_V1,SOLO_OPERATOR_CONTROLLED_V1].includes(authorizationPolicyVersion));
 run ||= createProductionAwsCommandRunner({credentialSource:PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER,env});
 assert.equal(env.GITHUB_ACTIONS,'true');assert.equal(env.GITHUB_WORKFLOW_REF,PRODUCTION_ENVIRONMENT_APPROVAL.stageBReleaseTransitionWorkflowRef);
 assert.equal(env.GITHUB_REPOSITORY,PRODUCTION_ENVIRONMENT_APPROVAL.repository);assert.equal(env.GITHUB_EVENT_NAME,'workflow_dispatch');assert.equal(env.GITHUB_RUN_ATTEMPT,'1');
 assert.match(sourceSha||'',/^[a-f0-9]{40}$/);assert.match(env.GITHUB_SHA||'',/^[a-f0-9]{40}$/);assert.match(releaseId||'',/^[a-f0-9]{64}$/);
 assert.match(preparationReference||'',/^[a-f0-9]{64}$/);assert.ok(Object.hasOwn(operations,phase)||phase==='prepare-overlap-conditional');assert.ok(Number.isSafeInteger(authorizationRound)&&authorizationRound>=0);
 assert.ok(path.isAbsolute(env.RUNNER_TEMP||''));
 assert.equal(env.RELEASE_ID,releaseId);assert.equal(env.RELEASE_PHASE,phase);assert.equal(env.RELEASE_PREPARATION_REFERENCE,preparationReference);assert.equal(env.RELEASE_AUTHORIZATION_ROUND,String(authorizationRound));
 const directory=path.join(HOSTED_RELEASE_ROOT,releaseId,phase==='closure'?'cutover':phase);
 ensureStageBPrivateDirectory({directory,repositoryRoot:root,create:true});
 const store=createStore({run,directory,repositoryRoot:root});
 if(phase==='prepare-overlap-conditional'){
  const prepared=store.getArtifact(preparationReference);
  exactConditionalKeys(prepared,['kind','schemaVersion','derivation','derivationSha256'],'Conditional preparation');
  assert.equal(prepared.kind,'CUTOVER_CONDITIONAL_PREPARATION_V1');assert.equal(prepared.schemaVersion,1);
  assertConditionalDerivation(prepared.derivation);assert.equal(prepared.derivationSha256,conditionalHash(prepared.derivation));
  const record=store.readStep(releaseId,'prepare-overlap-conditional:prepared');
  assert.ok(record);assert.equal(record.result,preparationReference);assert.equal(record.sourceSha,sourceSha);
  const authorization=await produceConditionalOverlapAuthorization({d:prepared.derivation,sourceSha,ticketId,releaseId,preparationReference,authorizationRound,authorizationPolicyVersion,env,fetchImpl});
  assert.equal(path.resolve(output),path.join(directory,'authorization.json'));
  const written=writeStageBPrivateFileAtomic({filePath:output,bytes:Buffer.from(`${JSON.stringify(authorization)}\n`),repositoryRoot:root,label:'Conditional production authorization'});
  return {authorizationPath:written.path,authorizationFileSha256:written.sha256,authorizationSha256:conditionalHash(authorization)};
 }
 const start=store.readStart(successorReleaseStartKey({sourceSha,ticketId,releaseId}))||store.readStart({sourceSha,ticketId});
 assert.ok(start,'Missing governed release start');
 const release=store.getArtifact(start.release),{releaseId:originalId,...identity}=release;
 assert.equal(originalId,releaseId);assert.equal(identity.ticketId,ticketId);assert.equal(identity.sourceSha,sourceSha);assert.equal(brokerDigest(identity),releaseId);
 const successor=Boolean(start.recovery);
 if(successor){assert.equal(start.recovery,release.recoveryReference);assert.match(release.toolingSha||'',/^[a-f0-9]{40}$/);}
 const preparationName=successor&&['cutover','closure'].includes(phase)&&authorizationRound>0
  ?`${phase}:prepared:${authorizationRound}`:`${phase}:prepared`;
 const record=store.readStep(releaseId,preparationName);assert.ok(record,'Missing exact transition preparation');
 assert.equal(record.result,preparationReference);assert.equal(record.sourceSha,sourceSha);assert.equal(record.name,preparationName);
 const assertSuccessorRoundActive=()=>{if(successor){
  assert.equal(store.readStep(releaseId,`${phase}:retired:${authorizationRound}`),null,'Successor preparation was retired');
  assert.equal(store.readStep(releaseId,`${phase}:approval-timeout:${authorizationRound}`),null,'Successor approval timed out');
  assert.equal(store.readStep(releaseId,`${phase}:approval-failed:${authorizationRound}`),null,'Successor approval failed');
 }};
 assertSuccessorRoundActive();
 const pending=store.readStep(releaseId,`${phase}:pending:${authorizationRound}`);
 if(pending){assert.equal(pending.prepared,preparationReference);assert.equal(pending.runId,env.GITHUB_RUN_ID);}
 const prepared=store.getArtifact(preparationReference);assert.equal(prepared.preparation.sourceSha,sourceSha);
 assert.equal(env.GITHUB_SHA,brokerExecutionCheckout(prepared.preparation).sourceSha,'Authorization workflow differs from authenticated preparation tooling');
 if(successor&&phase==='closure'){
  const continuation=prepared.preparation.closureContinuation;
  if(continuation){assert.equal(continuation.releaseId,releaseId);assert.equal(continuation.recoveryReference,start.recovery);
   assert.equal(continuation.releaseSourceSha,sourceSha);assert.equal(continuation.currentTooling.sourceSha,env.GITHUB_SHA);}
  for(let round=0;round<authorizationRound;round++){
   const old=store.readStep(releaseId,round?`closure:prepared:${round}`:'closure:prepared');
   if(!old){assert.equal(round,0,'Earlier continuation preparation is missing');continue;}
   assert.equal(old.releaseId,releaseId);assert.equal(old.sourceSha,sourceSha);
   assert.equal(old.name,round?`closure:prepared:${round}`:'closure:prepared');
   const oldPrepared=store.getArtifact(old.result),retired=store.readStep(releaseId,`closure:retired:${round}`);
   assert.equal(brokerDigest(oldPrepared),old.result);
   const timedOut=store.readStep(releaseId,`closure:approval-timeout:${round}`),failedRound=store.readStep(releaseId,`closure:approval-failed:${round}`);
   if(failedRound){
    assert.equal(timedOut,null);
    if(retired)assert.equal(retired.reason,'TOOLING_ADVANCED_AFTER_CAS');
    assert.equal(failedRound.releaseId,releaseId);assert.equal(failedRound.sourceSha,sourceSha);
    assert.equal(failedRound.name,`closure:approval-failed:${round}`);
    assert.ok(['failure','cancelled'].includes(failedRound.conclusion));
   }
   assert.ok(retired||timedOut||failedRound,'Earlier closure round remains active');
   for(const marker of [retired,timedOut,failedRound])if(marker)assert.equal(marker.prepared,old.result);
   const oldAttempt=store.readStep(releaseId,`closure:attempt:${round}`),oldSigned=store.readStep(releaseId,`closure:authorized:${round}`);
   if(oldAttempt||oldSigned){
    assert.equal(failedRound,null,'A failed approval cannot have a native attempt');
    assert.ok(['PRE_NATIVE_ABORTED','AUTHORIZATION_EXPIRED'].includes(retired?.reason),'Historical attempted round requires authenticated retirement');
    if(!oldAttempt)assert.equal(retired.reason,'AUTHORIZATION_EXPIRED');
    if(retired.reason==='PRE_NATIVE_ABORTED')assert.ok(retired.preNativeAbort);
    const cutover=store.readStep(releaseId,'cutover:result');
    const proof=await authenticateAbort({store,releaseId,release,sourceSha,round,prepared:oldPrepared,
     currentTooling:retired.reason==='PRE_NATIVE_ABORTED'?retired.preNativeAbort.currentTooling:continuation?.currentTooling||brokerExecutionCheckout(prepared.preparation),casResult:store.getArtifact(cutover.result),run,directory,
     verify:createBrokerKmsAuthorizationBoundary({run,githubRun:ghRun}).verify,allowMissingAttempt:!oldAttempt});
    if(retired.reason==='PRE_NATIVE_ABORTED')assert.deepEqual(proof,retired.preNativeAbort,'Historical pre-native abort proof differs');
   }
   const cutover=store.readStep(releaseId,'cutover:result');
   assert.equal(brokerDigest(oldPrepared.preparation),brokerDigest(prepareBrokerStateRefresh({preparation:store.getArtifact(cutover.prepared).preparation,
    authorization:store.getArtifact(cutover.authorization),casResult:store.getArtifact(cutover.result),
    ...(oldPrepared.preparation.closureContinuation?{closureContinuation:oldPrepared.preparation.closureContinuation}:{})})));
   const pendingOld=store.readStep(releaseId,`closure:pending:${round}`),dispatchOld=store.readStep(releaseId,`closure:dispatch:${round}`);
   if(timedOut&&pendingOld)assert.equal(timedOut.runId,pendingOld.runId);
   if(failedRound){assert.ok(pendingOld,'Failed closure round lacks its child');assert.ok(dispatchOld,'Failed closure round lacks its dispatch');
    assert.equal(pendingOld.prepared,old.result);assert.equal(pendingOld.runId,failedRound.runId);}
   if(dispatchOld&&!oldAttempt&&!oldSigned){
    assert.ok(pendingOld||timedOut);assert.equal((pendingOld||timedOut).prepared,old.result);
    const oldIdentity=dispatchOld.dispatch.identity,toolingSha=brokerExecutionCheckout(oldPrepared.preparation).sourceSha;
    assert.deepEqual(oldIdentity.inputs,releaseTransitionDispatchInputs({release,authorizationRound:round},'closure',old.result,oldPrepared.preparation));
    assert.equal(oldIdentity.repository,'T-ej2003/genuine-scan-main');assert.equal(oldIdentity.workflow,'authorize-production-stage-b-release-transition.yml');
    assert.equal(oldIdentity.workflowPath,'.github/workflows/authorize-production-stage-b-release-transition.yml');
    assert.equal(oldIdentity.ref,'main');assert.equal(oldIdentity.targetSha,toolingSha);
    const failed=authenticateFailedReleaseTransitionAttempt({run:ghRun,runId:(pendingOld||timedOut).runId,toolingSha,
     workflowId:oldIdentity.workflowId,beforeRunIds:dispatchOld.dispatch.beforeRunIds});
    if(retired?.runId)assert.equal(retired.runId,failed.runId);
    if(timedOut)assert.equal(failed.conclusion,'timed_out','Earlier timeout marker differs from GitHub conclusion');
    if(failedRound){assert.equal(failedRound.runId,failed.runId);assert.equal(failedRound.conclusion,failed.conclusion);}
   }else if(!oldAttempt&&!oldSigned)assert.equal(pendingOld,null);
  }
 }
 assert.match(prepared.materializationSha256||'',/^[a-f0-9]{64}$/);
 assert.equal(path.dirname(prepared.planPath),directory,'Saved plan escaped its immutable phase directory');
 assert.match(path.basename(prepared.planPath),/^[a-z0-9-]+\.(tfplan|json)$/);
 const canonicalPackage=path.join(directory,'broker-package.zip');
 const publishedPackage=path.join(HOSTED_RELEASE_ROOT,releaseId,'publication','broker-package.zip');
 const packagePath=prepared.brokerPackagePath===undefined?canonicalPackage:prepared.brokerPackagePath;
 if(prepared.brokerPackagePath!==undefined){
  assert.ok(['cutover','closure'].includes(phase),'Published package path is only valid for cutover and closure');
  assert.equal(packagePath,publishedPackage,'Prepared broker package path differs from this release publication');
 }
 const terraformDataDir=path.join(directory,'terraform'),files={package:packagePath,packageManifest:`${packagePath}.manifest.json`,tfvars:path.join(directory,'stage-b.tfvars'),backendMetadata:path.join(terraformDataDir,'terraform.tfstate')};
 await hydrateMaterial({reference:prepared.materializationSha256,prepared,files,planPath:prepared.planPath,store,repositoryRoot:root,run});
 let predecessor={};
 if(phase==='closure'){
  const cutover=store.readStep(releaseId,'cutover:result');assert.ok(cutover,'Closure requires completed cutover');
  assert.equal(cutover.sourceSha,sourceSha);
  predecessor={cutoverPreparation:store.getArtifact(cutover.prepared).preparation,
   cutoverAuthorization:store.getArtifact(cutover.authorization),casResult:store.getArtifact(cutover.result)};
  assert.equal(brokerDigest(prepared.preparation),brokerDigest(prepareBrokerStateRefresh({preparation:predecessor.cutoverPreparation,
   authorization:predecessor.cutoverAuthorization,casResult:predecessor.casResult,
   ...(prepared.preparation.closureContinuation?{closureContinuation:prepared.preparation.closureContinuation}:{})})));
 }
 const authorization=await runRequest({operation:operations[phase],files,directory,terraformDataDir,preparation:prepared.preparation,planPath:prepared.planPath,...predecessor});
 assertSuccessorRoundActive();
 assert.equal(authorization.schemaVersion,2);assert.equal(authorization.protectedEnvironmentApprovalEvidence.workflowRunId,env.GITHUB_RUN_ID);
 assert.equal(authorization.preparationSha256,brokerDigest(prepared.preparation));
 assert.equal(path.resolve(output),path.join(HOSTED_RELEASE_ROOT,releaseId,phase,'authorization.json'));
 ensureStageBPrivateDirectory({directory:path.dirname(output),repositoryRoot:root,create:false});
 const written=writeStageBPrivateFileAtomic({filePath:output,bytes:Buffer.from(`${JSON.stringify(authorization)}\n`),repositoryRoot:root,label:'Release transition authorization'});
 return {authorizationPath:written.path,authorizationFileSha256:written.sha256,authorizationSha256:brokerDigest(authorization)};
}

if(process.argv[1]===fileURLToPath(import.meta.url)){
 try{
  const argv=process.argv.slice(2),names=['source-sha','ticket-id','release-id','phase','preparation-reference','authorization-round','authorization-policy-version','output'];
  assert.equal(argv.length,names.length*2);const values={};
  for(let i=0;i<argv.length;i+=2){assert.ok(names.includes(argv[i].slice(2))&&argv[i].startsWith('--'));assert.equal(values[argv[i]],undefined);values[argv[i]]=argv[i+1];}
  assert.match(values['--authorization-round']||'',/^(?:0|[1-9][0-9]*)$/);
  const result=await authorizeReleaseTransition({sourceSha:values['--source-sha'],ticketId:values['--ticket-id'],releaseId:values['--release-id'],phase:values['--phase'],preparationReference:values['--preparation-reference'],authorizationRound:Number(values['--authorization-round']),authorizationPolicyVersion:values['--authorization-policy-version'],output:values['--output']});
  process.stdout.write(`${JSON.stringify(result)}\n`);
 }catch(error){process.stderr.write(`${error.message}\n`);process.exitCode=1;}
}
