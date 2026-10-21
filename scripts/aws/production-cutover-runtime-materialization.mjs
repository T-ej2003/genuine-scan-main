import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {assertStageBArtifactPath,ensureStageBPrivateDirectory} from './stage-b-artifact-contract.mjs';
import {assertConditionalDerivation, assertConditionalWindow, conditionalHash, exactConditionalKeys,parseConditionalJson} from './production-cutover-conditional-authorization.mjs';
import {IMAGE_EVIDENCE_MAX_AGE_MS} from './production-green-stage-b-image-evidence.mjs';
import {STAGE_B_DEPLOYMENT_EVIDENCE_TTL_MS} from './stage-b-evidence-freshness.mjs';
import {assertRootDropEvidence} from './production-root-drop-evidence.mjs';
import {assertQrVersionResolutionEvidence, assertQrVersionResolutionCurrent} from './production-qr-version-selector-resolution.mjs';

export function assertConditionalFileCensus(d) {
  for (const entry of d.files) {
    assert.ok(fs.lstatSync(entry.path).isFile() && !fs.lstatSync(entry.path).isSymbolicLink(), 'Immutable census entry must be a regular file');
    assert.equal(fs.realpathSync(entry.path),entry.path,'Immutable census path contains a symlink');
    assert.equal(conditionalHash(fs.readFileSync(entry.path)),entry.fileSha256,'Immutable file changed');
  }
}

export function renderConditionalRuntime({d,rootBytes,qr,taskDefinition,secretMetadata,now=Date.now(),verifyRootSignature}) {
  assertConditionalDerivation(d); assertConditionalWindow(d,now); assertConditionalFileCensus(d);
  const root=parseConditionalJson(Buffer.from(rootBytes));
  assertRootDropEvidence(root, {sourceSha:d.historicalReleaseSha,rotationId:d.rotationId,imageAuthorizationSha256:d.artifacts.imageAuthorizationSha256,
    successorRecoveryAuthorizationSha256:null,administratorEvidenceSha256:d.artifacts.administratorFileSha256,administratorSignatureSha256:d.artifacts.administratorSignatureFileSha256,
    now,...(verifyRootSignature ? {verifySignature:verifyRootSignature} : {})});
  assertQrVersionResolutionEvidence(qr,{sourceSha:d.toolingSourceSha,changeTicket:d.ticketId,expectedSecretArn:d.predecessor.qrSecretArn,now:new Date(now)});
  assertQrVersionResolutionCurrent({taskDefinition,resolution:qr,secretMetadata});
  assert.equal(qr.taskDefinitionArn,d.predecessor.taskDefinitionArn); assert.equal(qr.taskDefinitionSha256,d.predecessor.taskDefinitionSha256);
  assert.equal(qr.versionId,d.predecessor.qrVersionId); assert.equal(qr.qrCurrentVersion,d.predecessor.qrCurrentVersion);
  const config={...d.runtimeTemplate,rootDropEvidenceSha256:conditionalHash(Buffer.from(rootBytes))};
  const bytes=Buffer.from(`${JSON.stringify(config,null,2)}\n`);
  const manifest={schemaVersion:1,kind:'CUTOVER_MATERIALIZATION_V1',generatedBy:'scripts/aws/production-cutover-runtime-materialization.mjs',protectedMainSha:d.toolingSourceSha,releaseSourceSha:d.historicalReleaseSha,readyToConsumeMfa:true,blockers:[],runtimeConfigSha256:conditionalHash(bytes),staticBindingSha256:conditionalHash(config),derivationSha256:conditionalHash(d),runtimeFileSha256:conditionalHash(bytes),rootFileSha256:conditionalHash(Buffer.from(rootBytes)),qrPayloadSha256:conditionalHash(qr),qrRunId:qr.workflowRunId};
  return {config,bytes,manifest};
}

export function assertConditionalRuntimeBytes(actual, expected) {
  assert.ok(Buffer.isBuffer(actual) && Buffer.isBuffer(expected),'Exact runtime bytes required');
  assert.ok(actual.equals(expected),'Materialized runtime differs from fixed derivation');
}

export function assertConditionalLiveState(d, observation) {
  // Only authoritative normalized values, never a cached `valid` flag, satisfy this census.
  exactConditionalKeys(observation,['toolingSourceSha','historicalReleaseSha','rotationId','backendImageDigest','broker','predecessor','inventory','artifacts','keys'],'Live observation');
  for (const key of ['toolingSourceSha','historicalReleaseSha','rotationId','backendImageDigest','broker','predecessor','inventory','artifacts','keys']) assert.deepEqual(observation[key],d[key],`Live ${key} differs`);
}

/** Uses the existing authenticated bootstrap recipe; it cannot seal a caller-provided runtime template. */
export async function prepareConditionalDerivation({runtimeInput,sealedInputs,read,execute}) {
  const {prepareProductionCutoverRuntime,rotationBindingsToPostPrepareTaskBindings}=await import('./production-cutover-runtime-bootstrap.mjs');
  const {writeStageBPrivateFilesAtomic}=await import('./stage-b-artifact-contract.mjs');
  const {execFileSync}=await import('node:child_process');
  const prepared=prepareProductionCutoverRuntime({...runtimeInput,immutablePreparation:true,constructAdapters:undefined});
  assert.equal(prepared.conditionalPreparation,true);assert.deepEqual(prepared.blockers,[],'Canonical immutable preparation failed');
  const r=prepared.runtimeTemplate;
  assert.equal(r.completedInventoryAdoptionRequired,true,'Conditional lane cannot run inventory');assert.ok(r.rotationSuccessor);
  const repositoryRoot=runtimeInput.repositoryRoot||process.cwd();
  writeStageBPrivateFilesAtomic({files:prepared.precomputedFiles,repositoryRoot});
  const run=execute||execFileSync;
  const {createProductionRotationInfrastructureAdapter}=await import('./production-cutover-production-adapters.mjs');
  const postPrepareTaskInput={...r.overlapTaskInput,secretBindings:{...r.overlapTaskInput.secretBindings,...rotationBindingsToPostPrepareTaskBindings(r)},postPrepare:true};
  const planned=createProductionRotationInfrastructureAdapter({run,releaseProfile:'mscqr-production-release-deployer',repositoryRoot,config:r}).preflight({sourceSha:r.sourceSha,rotationId:r.rotationId,secretBindings:postPrepareTaskInput.secretBindings});
  assert.equal(planned.alreadyConverged,true,'Conditional continuation cannot change infrastructure');
  const {conditionalToolPaths}=await import('./production-cutover-conditional-native.mjs');
  const tools=conditionalToolPaths(run);
  const runtimeFiles=[];
  const collect=value=>{if(!value||typeof value!=='object')return;for(const [key,item] of Object.entries(value)){if(typeof item==='string'&&/File$|Path$/.test(key)&&path.isAbsolute(item)&&fs.lstatSync(item,{throwIfNoEntry:false})?.isFile())runtimeFiles.push(item);else if(item&&typeof item==='object')collect(item);}};collect(r);
  const sourceFiles=String(run('git',['ls-files','package.json','package-lock.json','backend/package.json','backend/package-lock.json','scripts/aws','scripts/security','backend/scripts/security','infra/aws/terraform'],{cwd:repositoryRoot,encoding:'utf8'})).trim().split('\n').filter(Boolean).map(value=>path.resolve(repositoryRoot,value));
  const paths=[...new Set([...sourceFiles,...runtimeFiles,...sealedInputs.files.map(value=>value.path),...prepared.precomputedFiles.map(value=>value.filePath),r.rotationTerraformPlanFile,...Object.values(tools)])].sort();
  const d={...sealedInputs,toolingSourceSha:prepared.protectedMainSha,historicalReleaseSha:prepared.releaseSourceSha,imageReleaseSha:r.imageReleaseSha,rotationId:r.rotationId,backendImageDigest:r.overlapTaskInput.backendImage.split('@')[1],ticketId:r.ticket,
    runtimeTemplate:r,postPrepareTaskInput,
    files:paths.map(value=>({path:value,fileSha256:conditionalHash(fs.readFileSync(value))}))};
  d.predecessor={...d.predecessor,terraformPlanSha256:planned.planSha256,terraformConfigSha256:conditionalHash(d.files.filter(value=>value.path.includes('/infra/aws/terraform/')))};
  assertConditionalDerivation(d);assertConditionalFileCensus(d);assertConditionalFreshOutputs(d,repositoryRoot);assertConditionalPinnedWindow(d);
  const {readConditionalLiveObservation}=await import('./production-cutover-conditional-composition.mjs');
  assertConditionalLiveState(d,readConditionalLiveObservation({d,read,execute:run}));
  return {derivation:d,derivationSha256:conditionalHash(d),preparation:{kind:'CUTOVER_CONDITIONAL_PREPARATION_V1',schemaVersion:1,derivation:d,derivationSha256:conditionalHash(d)}};
}

/** Publish the sealed preparation through the existing encrypted coordinator store. */
export async function publishConditionalPreparation({runtimeInput,sealedInputs,read,execute,store}) {
  const {assertConditionalProductionEnabled}=await import('./production-green-stage-b-contract.mjs');
  assertConditionalProductionEnabled();
  const result=await prepareConditionalDerivation({runtimeInput,sealedInputs,read,execute});
  const {conditionalOperationId}=await import('./production-cutover-conditional-authorization.mjs');
  const releaseId=conditionalOperationId(result.derivation.rotationId,result.derivation.predecessor.stateSha256);
  const preparationReference=conditionalHash(result.preparation);
  await store.putArtifact(preparationReference,result.preparation);
  if(conditionalHash(await store.getArtifact(preparationReference))!==preparationReference)throw new Error('Conditional preparation persistence differs');
  const record={releaseId,sourceSha:result.derivation.historicalReleaseSha,name:'prepare-overlap-conditional:prepared',result:preparationReference};
  await store.writeStep(record);
  if(conditionalHash(await store.readStep(releaseId,record.name))!==conditionalHash(record))throw new Error('Conditional preparation reference differs');
  return {...result,releaseId,preparationReference};
}

export function assertConditionalFreshOutputs(d,repositoryRoot=process.cwd()) {
  const r=d.runtimeTemplate,directory=path.dirname(r.rotationConfigFile);
  const files=[r.rootDropEvidenceFile,r.rotationConfigFile,r.rotationStateFile,r.rotationFixtureFile,r.readinessEvidenceFile,
    ...['cutover-runtime-manifest.json','inventory-completed-adoption-evidence.json','rotation-successor-evidence.json'].map(name=>path.join(directory,name))];
  assert.equal(new Set(files).size,files.length,'Conditional output paths overlap');
  for(const filePath of files){
    assertStageBArtifactPath({artifactPath:filePath,repositoryRoot,label:'Conditional output'});
    ensureStageBPrivateDirectory({directory:path.dirname(filePath),repositoryRoot,create:false,label:'Conditional output directory'});
    assert.equal(fs.lstatSync(filePath,{throwIfNoEntry:false}),undefined,'Conditional output already exists; reconcile before a new execution');
    fs.accessSync(path.dirname(filePath),fs.constants.W_OK);
  }
}

export function assertConditionalPinnedWindow(d) {
  const read=p=>parseConditionalJson(fs.readFileSync(p)),r=d.runtimeTemplate;
  const image=read(r.imageAuthorizationFile);
  const approval=d.files.filter(entry=>entry.fileSha256===d.artifacts.stageBApprovalFileSha256);
  assert.equal(approval.length,1,'Exact Stage B approval input required');
  const deadlines=[Date.parse(read(r.iamEvidenceSignatureFile).signedAt)+STAGE_B_DEPLOYMENT_EVIDENCE_TTL_MS,
    Date.parse(read(r.releasePreflightAttestationSignatureFile).signedAt)+STAGE_B_DEPLOYMENT_EVIDENCE_TTL_MS,
    Date.parse(image.imageEvidence.observedAt)+IMAGE_EVIDENCE_MAX_AGE_MS,
    Date.parse(image.imageEvidenceSignature.signedAt)+IMAGE_EVIDENCE_MAX_AGE_MS,Date.parse(read(approval[0].path).expiresAt)];
  assert.ok(deadlines.every(Number.isSafeInteger)&&Date.parse(d.notAfter)<Math.min(...deadlines),'Conditional window outlives pinned evidence; refresh before authorizing');
}
