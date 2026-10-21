import {assertQrVersionResolutionEvidence} from './production-qr-version-selector-resolution.mjs';
import {createConditionalPrepareContext} from './production-cutover-conditional-capability.mjs';
import assert from 'node:assert/strict';
import {parseConditionalJson} from './production-cutover-conditional-authorization.mjs';
import {performance} from 'node:perf_hooks';
import {authenticateConditionalBundle,assertConditionalWindow,conditionalHash,CONDITIONAL_PHASES,assertConditionalProductionEnabled} from './production-cutover-conditional-authorization.mjs';
import {assertConditionalFileCensus,assertConditionalLiveState,renderConditionalRuntime,assertConditionalRuntimeBytes} from './production-cutover-runtime-materialization.mjs';
import {SOLO_OPERATOR_POLICY} from './production-cutover-human-policy.mjs';
import {SOLO_SUSPENSION_SOURCE} from './production-cutover-solo-authority.mjs';

export {assertConditionalUnsignedEffect,conditionalRegistrationRequest,assertConditionalPrepareEffect} from './production-cutover-conditional-native.mjs';
// Production entry is deliberately closed. No environment variable or injected adapter can enable it.
export async function runConditionalProductionContinuation(options) {
  assertConditionalProductionEnabled();
  assert.ok(!Object.hasOwn(options,'adapters'),'Production continuation cannot accept caller-provided authorization adapters');
  const {createCanonicalConditionalAdapters}=await import('./production-cutover-conditional-composition.mjs');
  const {createReleaseCoordinatorStore}=await import('./production-release-evidence-store.mjs');
  const {createProductionAwsCommandRunner,PRODUCTION_AWS_CREDENTIAL_SOURCE}=await import('./production-credential-source-contract.mjs');
  const {createConditionalConsumptionJournal}=await import('./production-cutover-consumption-journal.mjs');
  const path=await import('node:path');
  const {createConditionalExecutor}=await import('./production-cutover-conditional-native.mjs');
  const execute=createConditionalExecutor(options.d);
  const store=createReleaseCoordinatorStore({run:createProductionAwsCommandRunner({credentialSource:PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE,profile:'mscqr-production-release-deployer',exec:execute}),directory:path.dirname(options.d.runtimeTemplate.rotationConfigFile),repositoryRoot:process.cwd()});
  const journal=createConditionalConsumptionJournal({store,rotationId:options.d.rotationId,predecessorStateSha256:options.d.predecessor.stateSha256,soloAuthority:{d:options.d,policy:SOLO_OPERATOR_POLICY,trust:SOLO_SUSPENSION_SOURCE}});
  const adapters=createCanonicalConditionalAdapters(options);
  return rehearseConditionalContinuation({...options,journal,adapters});
}

/** Non-production harness. All I/O is explicit; it never constructs AWS credentials or a native runner. */
export async function rehearseConditionalContinuation({d,envelopes,trust,workflowArtifact,journal,adapters,now=Date.now,monotonic=()=>performance.now(),budgetMs=780000,readTimeoutMs=30000,nativeTimeoutMs=60000}) {
  assert.ok(Number.isSafeInteger(readTimeoutMs)&&readTimeoutMs>0&&readTimeoutMs<=30000);
  assert.ok(Number.isSafeInteger(nativeTimeoutMs)&&nativeTimeoutMs>0&&nativeTimeoutMs<=60000);
  let aborted=false;
  const bounded=async(operation,ms=readTimeoutMs)=>{
    assert.equal(aborted,false,'Continuation already stopped');
    let timer;
    try {return await Promise.race([Promise.resolve().then(operation),new Promise((resolve,reject)=>{timer=setTimeout(()=>{aborted=true;reject(new Error('Conditional operation deadline exceeded'));},ms);})]);}
    finally{clearTimeout(timer);}
  };
  const authenticate=()=>authenticateConditionalBundle({d,envelopes,trust,workflowArtifact,now:now()});
  const binding=authenticate(); assert.ok(Number.isSafeInteger(budgetMs) && budgetMs>0 && budgetMs<=780000,'Root budget must retain a safety reserve');
  for(const method of ['observe','currentIdentity','establishVerifier','verifyVerifier','qr','root','verifyRoot','persistRuntime','adopt','verifyAdoption','successor','verifySuccessor','prepareOverlap','verifyReadiness']) assert.equal(typeof adapters[method],'function',`Missing ${method} adapter`);
  const live=async()=>{authenticate(); assertConditionalFileCensus(d); assertConditionalLiveState(d,await bounded(()=>adapters.observe()));};
  await live();
  const verifier=await bounded(()=>adapters.establishVerifier()); await bounded(()=>adapters.verifyVerifier(verifier));
  const qr=await bounded(()=>adapters.qr()); await live(); assertConditionalWindow(d,now(),budgetMs);
  const execution=await journal.claimExecution(binding);
  const receipts={}, outputs={}; let materialization,started;
  const check=async()=>{
    assert.equal(aborted,false,'Continuation already stopped');
    await live(); await bounded(()=>adapters.verifyVerifier(verifier));
    if(started!==undefined) assert.ok(monotonic()-started<budgetMs,'Root execution budget exhausted');
    if(materialization){
      const current=renderConditionalRuntime({d,rootBytes:outputs.ROOT_DROP,qr:qr.resolution,taskDefinition:qr.taskDefinition,secretMetadata:await bounded(()=>qr.readSecretMetadata()),now:now(),verifyRootSignature:adapters.verifyRoot});
      assertConditionalRuntimeBytes(materialization.bytes,current.bytes);
    }
  };
  for(const phase of CONDITIONAL_PHASES) {
    await check();
    if(phase!=='ROOT_DROP') {
      assert.ok(materialization,'Exact runtime is required');
      // Re-validate actual QR/root consumers and reconstruct all bytes before each dependent operation.
      const rebuilt=renderConditionalRuntime({d,rootBytes:outputs.ROOT_DROP,qr:qr.resolution,taskDefinition:qr.taskDefinition,secretMetadata:await bounded(()=>qr.readSecretMetadata()),now:now(),verifyRootSignature:adapters.verifyRoot});
      assertConditionalRuntimeBytes(materialization.bytes,rebuilt.bytes);
      if(phase==='ROTATION_SUCCESSOR'||phase==='PREPARE_OVERLAP') await adapters.verifyAdoption(outputs.INVENTORY_ADOPTION,materialization,receipts.INVENTORY_ADOPTION);
      if(phase==='PREPARE_OVERLAP') await adapters.verifySuccessor(outputs.ROTATION_SUCCESSOR,materialization,outputs.INVENTORY_ADOPTION,receipts.ROTATION_SUCCESSOR);
    }
    const dependencyHashes=Object.fromEntries(Object.entries(outputs).map(([key,value])=>[key,conditionalHash(value)]));
    const context={...binding,phase,runtimeFileSha256:materialization?.manifest.runtimeFileSha256||null,dependencyHashes,dependencyReceipts:Object.fromEntries(Object.entries(receipts).map(([key,value])=>[key,value.recordSha256]))};
    const token=await journal.claimPhase(execution,phase,context);
    const principal=await bounded(()=>adapters.currentIdentity(phase));
    if(phase==='PREPARE_OVERLAP') {
      // Parent authorization never hides native effects. The adapter must dispatch each permitted native call through this boundary.
      const authority=journal.createPrepareAuthority(token,{d,successor:outputs.ROTATION_SUCCESSOR,beforeDispatch:async()=>{await check();assert.equal(await bounded(()=>adapters.currentIdentity(phase)),principal,'Native executor identity changed');},principal,now,invokeNative:invoke=>bounded(invoke,nativeTimeoutMs)});
      const conditionalContext=createConditionalPrepareContext({authority,materialization});
      const {dispatch}=await import('./production-cutover-conditional-capability.mjs').then(module=>module.readConditionalPrepareContext(conditionalContext));
      const result=await adapters.prepareOverlap({materialization,executionId:journal.executionId,adoption:outputs.INVENTORY_ADOPTION,successor:outputs.ROTATION_SUCCESSOR,verifier,dispatch,conditionalContext});
      assert.ok(['COMPLETED_CONFIRMED','RECONCILED_COMPLETED'].includes(await journal.status('PREPARE_OVERLAP','REGISTER_TASK_DEFINITION')),'Exact registration completion required before readiness');
      await check();
      await adapters.verifyReadiness(result,materialization,outputs);
      await journal.persistReadiness(execution,result); return {readiness:result,materialization,receipts};
    }
    const signer=journal.createNativeSigner(token,{d,phase,trust,materialization,outputs,beforeDispatch:async()=>{await check();assert.equal(await bounded(()=>adapters.currentIdentity(phase)),principal,'Native signer identity changed');if(phase==='ROOT_DROP'){assertQrVersionResolutionEvidence(qr.resolution,{sourceSha:d.toolingSourceSha,changeTicket:d.ticketId,expectedSecretArn:d.predecessor.qrSecretArn,now:new Date(now()+budgetMs)});started=monotonic();}},principal,now,invokeNative:invoke=>bounded(invoke,nativeTimeoutMs)});
    const nativeSign=signer.sign;
    const output=phase==='ROOT_DROP'?await adapters.root({d,qr,nativeSign}):phase==='INVENTORY_ADOPTION'?await adapters.adopt(materialization,nativeSign):await adapters.successor(materialization,outputs.INVENTORY_ADOPTION,nativeSign);
    const nativeCompletion=signer.completion();
    assert.ok(nativeCompletion,'Canonical producer must use the claimed native Sign boundary');
    if(phase==='INVENTORY_ADOPTION') await adapters.verifyAdoption(output,materialization);
    if(phase==='ROTATION_SUCCESSOR') await adapters.verifySuccessor(output,materialization,outputs.INVENTORY_ADOPTION);
    outputs[phase]=output; receipts[phase]=await journal.persistEvidence(phase,output,nativeCompletion);
    if(phase==='ROOT_DROP') {
      materialization=renderConditionalRuntime({d,rootBytes:output,qr:qr.resolution,taskDefinition:qr.taskDefinition,secretMetadata:await bounded(()=>qr.readSecretMetadata()),now:now(),verifyRootSignature:adapters.verifyRoot});
      const persisted=await adapters.persistRuntime(materialization); assertConditionalRuntimeBytes(persisted,materialization.bytes);
      await journal.persistMaterialization(execution,materialization);
    }
  }
  throw new Error('Conditional continuation did not produce readiness');
}

export async function runConditionalContinuationCli(argv=process.argv.slice(2)) {
  assertConditionalProductionEnabled();
  const names=['derivation','derivation-sha256','authorizations','authorizations-sha256','workflow-run-id','workflow-artifact-id','qr-workflow-run-id'];
  const args={};assert.equal(argv.length,names.length*2);
  for(let index=0;index<argv.length;index+=2){const name=argv[index].slice(2);assert.ok(argv[index].startsWith('--')&&names.includes(name)&&!Object.hasOwn(args,name)&&argv[index+1]);args[name]=argv[index+1];}
  const {readStageBPrivateFileBytes}=await import('./stage-b-artifact-contract.mjs');
  const path=await import('node:path');
  const bound=name=>{const value=readStageBPrivateFileBytes({filePath:path.resolve(args[name]),repositoryRoot:process.cwd(),label:name});assert.equal(value.sha256,args[`${name}-sha256`]);return parseConditionalJson(value.bytes);};
  const d=bound('derivation'),envelopes=bound('authorizations');
  const {readStageBProtectedMainCheckout}=await import('./stage-b-deployment-identity.mjs');
  readStageBProtectedMainCheckout({expectedSourceSha:d.toolingSourceSha,requireCanonicalRepository:true});
  const {readGitHubApiToken}=await import('./production-qr-version-selector-resolution.mjs');
  const githubToken=readGitHubApiToken();
  const {authenticateConditionalWorkflowArtifact}=await import('./production-cutover-conditional-workflow.mjs');
  const workflowArtifact=await authenticateConditionalWorkflowArtifact({d,runId:args['workflow-run-id'],artifactId:args['workflow-artifact-id'],token:githubToken});
  assert.deepEqual(envelopes.PREPARE_OVERLAP,workflowArtifact.envelope);
  const {createProductionAwsCommandRunner,PRODUCTION_AWS_CREDENTIAL_SOURCE}=await import('./production-credential-source-contract.mjs');
  const {createConditionalExecutor}=await import('./production-cutover-conditional-native.mjs');
  const read=createProductionAwsCommandRunner({credentialSource:PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE,profile:'mscqr-production-release-deployer',exec:createConditionalExecutor(d)});
  const trust=Object.fromEntries(Object.entries(d.keys).map(([kind,key])=>{
    const publicKey=parseConditionalJson(read(['kms','get-public-key','--key-id',key.keyArn,'--output','json']));
    const policy=parseConditionalJson(read(['kms','get-key-policy','--key-id',key.keyArn,'--policy-name','default','--output','json']));
    return [kind,{keyArn:publicKey.KeyId,publicKeyDerBase64:publicKey.PublicKey,policySha256:conditionalHash(parseConditionalJson(policy.Policy))}];
  }));
  return runConditionalProductionContinuation({d,envelopes,trust,workflowArtifact,githubToken,qrWorkflowRunId:args['qr-workflow-run-id']});
}
