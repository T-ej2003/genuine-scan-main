#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {brokerDigest,assertBrokerPreparation,assertBrokerAuthorization,brokerTargetIdentity,brokerAliasIdentity} from './stage-b-staged-broker-contract.mjs';
import {createBrokerKmsAuthorizationBoundary} from './stage-b-staged-broker-authorization.mjs';
import {STAGE_B_TERRAFORM_BACKEND,readStageBTerraformStateIdentity} from './stage-b-terraform-backend-contract.mjs';
import {readStagedBrokerSourceAuthority,readStagedBrokerReceipt,normalizeBrokerAlias} from './stage-b-staged-broker-executor.mjs';
import {STAGE_B} from './production-green-stage-b-contract.mjs';
import {createReleaseCoordinatorStore,HOSTED_RELEASE_ROOT} from './production-release-coordinator.mjs';
import {createProductionAwsCommandRunner,productionGithubExecutable,PRODUCTION_AWS_CREDENTIAL_SOURCE} from './production-credential-source-contract.mjs';
import {ensureStageBPrivateDirectory,assertStageBPrivateFile} from './stage-b-artifact-contract.mjs';
import {readStageBProtectedMainCheckout} from './stage-b-deployment-identity.mjs';
import {assertImageEvidence,assertImageEvidenceReuseBridge,verifyImageEvidenceSignature} from './production-green-stage-b-image-evidence.mjs';
import {deriveStageBImageImpactReport} from './validate-stage-b-image-reuse.mjs';
import {createRootAttestationKmsSigner} from './production-root-attestation-signer.mjs';
import {createRootAttestationKmsVerifier,ROOT_ATTESTATION_KEY_ALIAS_ARN,ROOT_ATTESTATION_SIGNING_ALGORITHM} from './production-root-attestation-key.mjs';

const root=path.resolve(fileURLToPath(new URL('../..',import.meta.url)));
const importerArn='arn:aws:iam::368992683803:root';
const source={bucket:STAGE_B_TERRAFORM_BACKEND.bucketName,key:STAGE_B_TERRAFORM_BACKEND.stateKey};
const hash=value=>brokerDigest(value);

export function assertHistoricalStateImport(receipt,{releaseSourceSha,recoveryToolingSha,recoveryId,brokerVersion,publication,store,verifyImport}) {
 assert.deepEqual(Object.keys(receipt).sort(),['artifactReference','historical','importerArn','kind','publicationResultSha256','recoveryId','recoveryToolingSha','releaseSourceSha','signature']);
 const {signature,...body}=receipt,receiptSha256=hash(body);
 assert.deepEqual(Object.keys(signature||{}).sort(),['keyArn','receiptSha256','signatureBase64','signingAlgorithm']);
 assert.equal(signature.keyArn,ROOT_ATTESTATION_KEY_ALIAS_ARN);
 assert.equal(signature.signingAlgorithm,ROOT_ATTESTATION_SIGNING_ALGORITHM);
 assert.equal(signature.receiptSha256,receiptSha256);
 assert.match(signature.signatureBase64||'',/^[A-Za-z0-9+/]+={0,2}$/);
 assert.equal(typeof verifyImport,'function','Historical import requires independent root-signature verification');
 assert.equal(verifyImport({keyArn:signature.keyArn,signingAlgorithm:signature.signingAlgorithm,
  digest:Buffer.from(receiptSha256,'hex'),signature:Buffer.from(signature.signatureBase64,'base64')}),true,
 'Historical import root signature is invalid');
 assert.equal(receipt.kind,'STAGE_B_HISTORICAL_STATE_IMPORT');
 assert.equal(receipt.importerArn,importerArn);
 assert.equal(receipt.releaseSourceSha,releaseSourceSha);
 assert.equal(receipt.recoveryToolingSha,recoveryToolingSha);
 assert.equal(receipt.recoveryId,recoveryId);
 assert.equal(receipt.publicationResultSha256,hash(publication));
 assert.equal(publication.target.version,brokerVersion);
 assert.deepEqual(Object.keys(receipt.historical).sort(),['bucket','key','lineage','serial','sha256','versionId']);
 assert.equal(receipt.historical.bucket,source.bucket);assert.equal(receipt.historical.key,source.key);
 assert.match(receipt.historical.versionId,/^[A-Za-z0-9._-]+$/);
 assert.match(receipt.historical.sha256,/^[a-f0-9]{64}$/);
 assert.match(receipt.historical.lineage,/^[a-f0-9-]{36}$/);
 assert.ok(Number.isSafeInteger(receipt.historical.serial)&&receipt.historical.serial>=0);
 const artifact=store.getArtifact(receipt.artifactReference);
 assert.deepEqual(Object.keys(artifact).sort(),['base64','kind','sha256']);
 assert.equal(artifact.kind,'PRODUCTION_RELEASE_BINARY');
 const bytes=Buffer.from(artifact.base64,'base64');
 assert.equal(bytes.toString('base64'),artifact.base64,'Historical state encoding changed');
 assert.equal(hash(bytes),receipt.historical.sha256);
 assert.equal(artifact.sha256,receipt.historical.sha256);
 assert.ok(bytes.length>0&&bytes.length<=64*1024*1024);
 const state=JSON.parse(bytes);
 assert.equal(state.version,4);assert.equal(state.lineage,receipt.historical.lineage);
 assert.equal(state.serial,receipt.historical.serial);
 return bytes;
}

// The importer is a separate administrator operation. It reads one exact S3
// version and creates a write-once object in the existing encrypted store.
export async function importHistoricalStageBState({releaseSourceSha,recoveryToolingSha,recoveryId,brokerVersion,versionId,expectedSha256},
 {run,store,directory,verifyAuthorization,authenticateTooling=authenticateProtectedTooling,
  readAuthority=readStagedBrokerSourceAuthority,readReceipt=readStagedBrokerReceipt,
  signImport=createRootAttestationKmsSigner({run}),verifyImport=createRootAttestationKmsVerifier({run})}={}) {
 assert.match(releaseSourceSha||'',/^[a-f0-9]{40}$/);assert.match(recoveryToolingSha||'',/^[a-f0-9]{40}$/);
 assert.match(brokerVersion||'',/^[1-9][0-9]*$/);
 assert.match(recoveryId||'',/^[a-f0-9]{64}$/);assert.match(versionId||'',/^[A-Za-z0-9._-]+$/);
 assert.match(expectedSha256||'',/^[a-f0-9]{64}$/);
 assert.equal(typeof run,'function');assert.ok(store?.putArtifact&&store?.getArtifact);
 ensureStageBPrivateDirectory({directory,repositoryRoot:root,create:true});
 const caller=JSON.parse(run(['sts','get-caller-identity','--output','json','--no-cli-pager']));
 assert.equal(caller.Arn,importerArn,'Historical version import requires governed administrator identity');
 authenticateTooling(releaseSourceSha,recoveryToolingSha);
 const authority=readAuthority({run,sourceSha:releaseSourceSha,directory});
 assert.ok(authority,'Original publication source authority is missing');
 assertBrokerPreparation(authority.preparation);
 assert.equal(authority.preparation.sourceSha,releaseSourceSha);
 assert.equal(authority.preparation.purpose,'STAGE_B_BROKER_PUBLICATION');
 const publication=readReceipt({run,id:hash(authority.authorization),status:'PUBLISHED',directory});
 assert.equal(publication.sourceSha,releaseSourceSha);
 assert.equal(publication.preparationSha256,hash(authority.preparation));
 assert.equal(publication.authorizationSha256,hash(authority.authorization));
 assert.equal(publication.target.version,brokerVersion);
 assert.equal(typeof verifyAuthorization,'function');
 await assertBrokerAuthorization(authority.authorization,authority.preparation,{verify:verifyAuthorization,now:new Date(publication.authorizedAt)});
 assert.equal(authority.preparation.state.stateSha256,expectedSha256);
 const file=path.join(directory,`historical-state-import-${randomUUID()}.json`);
 try {
  run(['s3api','get-object','--bucket',source.bucket,'--key',source.key,'--version-id',versionId,
   '--expected-bucket-owner','368992683803','--no-cli-pager',file]);
  fs.chmodSync(file,0o600);
  assertStageBPrivateFile({filePath:file,repositoryRoot:root,label:'Historical Stage B state'});
  const bytes=fs.readFileSync(file);
  assert.equal(hash(bytes),expectedSha256,'Historical S3 version bytes differ from authenticated publication');
  const state=JSON.parse(bytes);
  assert.equal(state.version,4);assert.equal(state.lineage,authority.preparation.state.lineage);
  assert.equal(state.serial,authority.preparation.state.serial);
  const artifact={kind:'PRODUCTION_RELEASE_BINARY',sha256:hash(bytes),base64:bytes.toString('base64')};
  const artifactReference=hash(artifact);
  const body={kind:'STAGE_B_HISTORICAL_STATE_IMPORT',releaseSourceSha,recoveryToolingSha,recoveryId,
   publicationResultSha256:hash(publication),importerArn,
   historical:{...source,versionId,sha256:expectedSha256,lineage:state.lineage,serial:state.serial},artifactReference};
  const receiptSha256=hash(body),receipt={...body,signature:{keyArn:ROOT_ATTESTATION_KEY_ALIAS_ARN,
   signingAlgorithm:ROOT_ATTESTATION_SIGNING_ALGORITHM,receiptSha256,
   signatureBase64:signImport({keyArn:ROOT_ATTESTATION_KEY_ALIAS_ARN,
    signingAlgorithm:ROOT_ATTESTATION_SIGNING_ALGORITHM,digest:Buffer.from(receiptSha256,'hex')})}};
  await store.putArtifact(artifactReference,artifact);
  const reference=hash(receipt);await store.putArtifact(reference,receipt);
  assertHistoricalStateImport(store.getArtifact(reference),{releaseSourceSha,recoveryToolingSha,recoveryId,brokerVersion,publication,store,verifyImport});
  return {reference,sha256:expectedSha256,serial:state.serial};
 }finally{if(fs.existsSync(file))fs.unlinkSync(file);}
}

export function authenticateProtectedTooling(releaseSourceSha,recoveryToolingSha) {
 const checkout=readStageBProtectedMainCheckout({cwd:root,fetchOriginMain:true,expectedSourceSha:recoveryToolingSha,requireCanonicalRepository:true});
 assert.equal(checkout.currentHead,recoveryToolingSha);assert.equal(checkout.originMainHead,recoveryToolingSha);
 execFileSync('git',['merge-base','--is-ancestor',releaseSourceSha,recoveryToolingSha],{cwd:root,stdio:'ignore'});
 return true;
}

export async function publishSuccessorRecoveryRequest({releaseSourceSha,recoveryToolingSha,recoveryId,ticketId,
 brokerVersion,expectedAliasVersion,expectedAliasRevision,historicalImportReference,currentStateSha256,imageEvidencePath,imageSignaturePath},
 {run,store,directory,verifyImageSignature=verifyImageEvidenceSignature,readAuthority=readStagedBrokerSourceAuthority,
  readReceipt=readStagedBrokerReceipt,authenticateTooling=authenticateProtectedTooling,verifyAuthorization,
  readCurrentState=readStageBTerraformStateIdentity,readAlias,readVersion,
  verifyImport=createRootAttestationKmsVerifier({run})}={}) {
 assert.match(ticketId||'',/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/);
 for(const digest of [recoveryId,historicalImportReference,currentStateSha256])assert.match(digest||'',/^[a-f0-9]{64}$/);
 for(const version of [brokerVersion,expectedAliasVersion])assert.match(version||'',/^[1-9][0-9]*$/);
 assert.match(expectedAliasRevision||'',/^[A-Za-z0-9-]{1,128}$/);
 assert.equal(typeof run,'function');assert.ok(store?.putArtifact&&store?.getArtifact);
 assert.equal(JSON.parse(run(['sts','get-caller-identity','--output','json','--no-cli-pager'])).Arn,importerArn);
 authenticateTooling(releaseSourceSha,recoveryToolingSha);
 const authority=readAuthority({run,sourceSha:releaseSourceSha,directory});assert.ok(authority);
 const publication=readReceipt({run,id:hash(authority.authorization),status:'PUBLISHED',directory});
 assert.equal(authority.preparation.sourceSha,releaseSourceSha);
 assert.equal(publication.sourceSha,releaseSourceSha);
 assert.equal(typeof verifyAuthorization,'function');
 await assertBrokerAuthorization(authority.authorization,authority.preparation,
  {verify:verifyAuthorization,now:new Date(publication.authorizedAt)});
 assert.equal(publication.target.version,brokerVersion);
 assert.equal(publication.preparationSha256,hash(authority.preparation));
 assert.equal(publication.authorizationSha256,hash(authority.authorization));
 assert.equal(authority.preparation.alias.FunctionVersion,expectedAliasVersion);
 assert.equal(authority.preparation.alias.RevisionId,expectedAliasRevision);
 const liveAlias=normalizeBrokerAlias(readAlias?await readAlias():JSON.parse(run(['lambda','get-alias',
  '--function-name',STAGE_B.brokerFunctionArn,'--name','reviewed','--output','json','--no-cli-pager'])));
 assert.deepEqual(brokerAliasIdentity(liveAlias),brokerAliasIdentity(authority.preparation.alias));
 const liveVersion=readVersion?await readVersion(brokerVersion):JSON.parse(run(['lambda','get-function-configuration',
  '--function-name',STAGE_B.brokerFunctionArn,'--qualifier',brokerVersion,'--output','json','--no-cli-pager']));
 assert.deepEqual(brokerTargetIdentity(liveVersion,authority.preparation.packageSha256),publication.target);
 const historical=store.getArtifact(historicalImportReference);
 assertHistoricalStateImport(historical,{releaseSourceSha,recoveryToolingSha,recoveryId,brokerVersion,publication,store,verifyImport});
 const current=readCurrentState(run);
 assert.equal(current.stateSha256,currentStateSha256,'Current Terraform state changed before successor request');
 assert.equal(current.lineage,historical.historical.lineage);
 assert.ok(current.serial>historical.historical.serial,'Current Terraform state has not advanced from historical state');
 const imageReleaseSha=publication.target.configuration.Environment.Variables.BROKER_IMAGE_RELEASE_SHA;
 const expectedDirectory=path.join(HOSTED_RELEASE_ROOT,'historical-import');
 assert.equal(path.resolve(directory),expectedDirectory);
 assert.equal(path.resolve(imageEvidencePath),path.join(expectedDirectory,'image-evidence.json'));
 assert.equal(path.resolve(imageSignaturePath),path.join(expectedDirectory,'image-evidence-signature.json'));
 const binary={};
 for(const [name,file] of Object.entries({imageEvidence:imageEvidencePath,imageSignature:imageSignaturePath})){
  assertStageBPrivateFile({filePath:file,repositoryRoot:root,label:`Successor ${name}`});
  const bytes=fs.readFileSync(file);assert.ok(bytes.length>0&&bytes.length<=8*1024*1024);
  binary[name]={kind:'PRODUCTION_RELEASE_BINARY',sha256:hash(bytes),base64:bytes.toString('base64')};
 }
 const evidence=JSON.parse(Buffer.from(binary.imageEvidence.base64,'base64'));
 const signature=JSON.parse(Buffer.from(binary.imageSignature.base64,'base64'));
 assertImageEvidence(evidence,{signatureArtifact:signature,publicationSourceSha:evidence.publicationSourceSha||evidence.imageReleaseSha,
  currentSourceSha:releaseSourceSha,imageReleaseSha,workflowRunId:evidence.workflowRunId,
  artifactSha256:evidence.canonicalArtifactSha256,verifySignature:options=>verifyImageSignature({...options,run})});
 assertImageEvidenceReuseBridge(evidence,{currentSourceSha:releaseSourceSha,
  imageReuseEvidence:deriveStageBImageImpactReport({imageReleaseSha,toolingSha:releaseSourceSha})});
 const images=JSON.parse(publication.target.configuration.Environment.Variables.BROKER_IMAGES_JSON);
 for(const [name,field] of Object.entries({backend:'backendImageDigest',worker:'workerImageDigest',
  executor:'executorImageDigest',canary:'canaryImageDigest'}))
  assert.equal(evidence.images.find(image=>image.service===(name==='executor'?'rls-executor':name==='canary'?'rls-canary':name))?.digest,images[field]);
 const imageEvidenceReference=hash(binary.imageEvidence),imageSignatureReference=hash(binary.imageSignature);
 await store.putArtifact(imageEvidenceReference,binary.imageEvidence);
 await store.putArtifact(imageSignatureReference,binary.imageSignature);
 const request={kind:'STAGE_B_SUCCESSOR_CUTOVER_REQUEST',releaseSourceSha,recoveryToolingSha,recoveryId,ticketId,
  brokerVersion,expectedAliasVersion,expectedAliasRevision,historicalImportReference,currentStateSha256,
  publicationResultSha256:hash(publication),imageEvidenceReference,imageSignatureReference};
 const reference=hash(request);await store.putArtifact(reference,request);
 return {reference,recoveryId};
}

if(process.argv[1]===fileURLToPath(import.meta.url)){
 try{
  const argv=process.argv.slice(2),mode=argv[0];assert.ok(['import-historical','publish-request'].includes(mode));
  const common=['--release-source-sha','--recovery-tooling-sha','--recovery-id','--broker-version','--profile'];
  const names=mode==='import-historical'?[...common,'--version-id','--expected-sha256']
   :[...common,'--ticket-id','--expected-alias-version','--expected-alias-revision','--historical-import-reference','--current-state-sha256'];
  assert.equal(argv.length,1+names.length*2);const options={};
  for(let i=1;i<argv.length;i+=2){assert.ok(names.includes(argv[i]));assert.equal(options[argv[i]],undefined);options[argv[i]]=argv[i+1];}
  const directory=path.join(HOSTED_RELEASE_ROOT,'historical-import');
  ensureStageBPrivateDirectory({directory,repositoryRoot:root,create:true});
  const run=createProductionAwsCommandRunner({credentialSource:PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE,profile:options['--profile']});
  const gh=productionGithubExecutable(),githubRun=(args,options)=>execFileSync(gh,args,{encoding:'utf8',maxBuffer:8*1024*1024,...options});
  const verifyAuthorization=createBrokerKmsAuthorizationBoundary({run,githubRun}).verify;
  const store=createReleaseCoordinatorStore({run,directory,repositoryRoot:root});
  const commonInput={releaseSourceSha:options['--release-source-sha'],recoveryToolingSha:options['--recovery-tooling-sha'],
   recoveryId:options['--recovery-id'],brokerVersion:options['--broker-version']};
  const result=mode==='import-historical'
   ?await importHistoricalStageBState({...commonInput,versionId:options['--version-id'],expectedSha256:options['--expected-sha256']},
    {run,store,directory,verifyAuthorization})
   :await publishSuccessorRecoveryRequest({...commonInput,ticketId:options['--ticket-id'],
    expectedAliasVersion:options['--expected-alias-version'],expectedAliasRevision:options['--expected-alias-revision'],historicalImportReference:options['--historical-import-reference'],
    currentStateSha256:options['--current-state-sha256'],imageEvidencePath:path.join(directory,'image-evidence.json'),
    imageSignaturePath:path.join(directory,'image-evidence-signature.json')},{run,store,directory,verifyAuthorization});
  process.stdout.write(`${JSON.stringify(result)}\n`);
 }catch(error){process.stderr.write(`${error.message}\n`);process.exitCode=1;}
}
