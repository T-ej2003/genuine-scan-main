import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import {brokerDigest} from '../aws/stage-b-staged-broker-contract.mjs';
import {STAGE_B_TERRAFORM_BACKEND_CONFIG} from '../aws/stage-b-terraform-backend-contract.mjs';
import {createHostedSuccessorRuntime} from '../aws/run-production-successor-release-coordinator.mjs';
import {HOSTED_RELEASE_ROOT} from '../aws/production-release-coordinator.mjs';
import {deriveStageBToolingInputTreeSha256} from '../aws/validate-stage-b-image-reuse.mjs';
import {ROOT_ATTESTATION_KEY_ALIAS_ARN,ROOT_ATTESTATION_SIGNING_ALGORITHM} from '../aws/production-root-attestation-key.mjs';
import {rig,ready,authorization as authorize} from './fixtures/staged-broker-runtime.mjs';

const A='29406b0ec537ac60618642bba20133dd0cf45529',C='7b40ee371b7751e19a413a4789c516c779af09d9';
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
 const artifacts=new Map(),steps=new Map();const store={putArtifact:(id,value)=>{assert.equal(brokerDigest(value),id);artifacts.set(id,value);},
  getArtifact:id=>{assert.ok(artifacts.has(id));return structuredClone(artifacts.get(id));},
  readStep:(id,name)=>steps.get(`${id}/${name}`)||null};
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
 const releaseId='d'.repeat(64),directory=path.join(HOSTED_RELEASE_ROOT,releaseId,'cutover');
 const run=args=>{if(args[0]!=='s3api'||args[1]!=='get-object')throw new Error('Unexpected AWS operation');
  const bytes=args.includes('env:/production/mscqr/production/rls-green/stage-b/terraform.tfstate')?currentBytes:Buffer.from('{}');
  fs.writeFileSync(args.at(-1),bytes,{mode:0o600});return '{}';};
 let imageObservation;
 const runtime=createHostedSuccessorRuntime({env,awsRun:run,ghRun:()=>{throw new Error('Unexpected GitHub call');},
  createStore:()=>store,authenticateTooling:(a,c)=>{assert.equal(a,A);assert.equal(c,C);},verifyImport:()=>true,
  readAuthority:()=>({preparation,authorization}),readReceipt:()=>result,
  verifyAuthorization:async()=>true,readVersion:()=>rigged.deps.getVersion('13'),readReviewedAlias:()=>preparation.alias,
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
  commandRun:(_command,_args,{env:commandEnv})=>{const metadata=path.join(commandEnv.TF_DATA_DIR,'terraform.tfstate');
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
 }finally{fs.rmSync(path.join(HOSTED_RELEASE_ROOT,releaseId),{recursive:true,force:true});}
});
