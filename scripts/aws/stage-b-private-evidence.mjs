import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {brokerDigest} from './stage-b-staged-broker-contract.mjs';
import {createReleaseCoordinatorStore} from './production-release-evidence-store.mjs';
import {createProductionAwsCommandRunner,PRODUCTION_AWS_CREDENTIAL_SOURCE} from './production-credential-source-contract.mjs';
import {ensureStageBPrivateDirectory,ensureStageBPrivateFile,writeStageBPrivateFileAtomicExclusive} from './stage-b-artifact-contract.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const sha256=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
const workflows={prerequisite:'.github/workflows/produce-production-green-stage-b-prerequisite-bundle.yml',preparation:'.github/workflows/prepare-production-green-stage-b-state-reconciliation.yml'};
const fields=['schemaVersion','kind','sourceSha','workflowPath','workflowRunId','workflowRunAttempt','payloadSha256','payloadByteSize','evidenceSha256'];
const MAX_BYTES=64*1024*1024;

export function assertPrivateEvidenceReference(reference,{kind,sourceSha,workflowRunId,workflowRunAttempt='1'}={}){
 assert.deepEqual(Object.keys(reference||{}).sort(),fields.slice().sort(),'Private evidence reference schema');
 assert.equal(reference.schemaVersion,1);assert.equal(reference.kind,kind);assert.ok(Object.hasOwn(workflows,kind));
 assert.match(sourceSha||'',/^[a-f0-9]{40}$/);assert.equal(reference.sourceSha,sourceSha);
 assert.equal(reference.workflowPath,workflows[kind]);assert.match(String(workflowRunId||''),/^[1-9][0-9]*$/);
 assert.equal(reference.workflowRunId,String(workflowRunId));assert.equal(reference.workflowRunAttempt,String(workflowRunAttempt));assert.equal(reference.workflowRunAttempt,'1');
 assert.match(reference.payloadSha256||'',/^[a-f0-9]{64}$/);assert.match(reference.evidenceSha256||'',/^[a-f0-9]{64}$/);
 assert.ok(Number.isSafeInteger(reference.payloadByteSize)&&reference.payloadByteSize>0&&reference.payloadByteSize<=MAX_BYTES);
 return reference;
}

export function publishPrivateEvidence({bytes,kind,sourceSha,workflowRunId,store}){
 assert.ok(Buffer.isBuffer(bytes)&&bytes.length>0&&bytes.length<=MAX_BYTES);
 const identity={schemaVersion:1,kind,sourceSha,workflowPath:workflows[kind],workflowRunId:String(workflowRunId),workflowRunAttempt:'1',payloadSha256:sha256(bytes),payloadByteSize:bytes.length};
 const evidence={...identity,payloadBase64:bytes.toString('base64')};const evidenceSha256=brokerDigest(evidence);
 const reference=assertPrivateEvidenceReference({...identity,evidenceSha256},{kind,sourceSha,workflowRunId});
 store.putArtifact(evidenceSha256,evidence);
 assert.equal(brokerDigest(store.getArtifact(evidenceSha256)),evidenceSha256,'Private evidence write readback');
 return reference;
}

export function readPrivateEvidence({reference,kind,sourceSha,workflowRunId,workflowRunAttempt='1',store}){
 assertPrivateEvidenceReference(reference,{kind,sourceSha,workflowRunId,workflowRunAttempt});
 const evidence=store.getArtifact(reference.evidenceSha256);
 assert.equal(brokerDigest(evidence),reference.evidenceSha256,'Private evidence digest');
 const {payloadBase64,...identity}=evidence;
 const {evidenceSha256,...expected}=reference;assert.deepEqual(identity,expected,'Private evidence identity substitution');
 assert.equal(typeof payloadBase64,'string');assert.ok(payloadBase64.length<=Math.ceil(MAX_BYTES/3)*4);
 const bytes=Buffer.from(payloadBase64,'base64');assert.equal(bytes.toString('base64'),payloadBase64,'Private evidence encoding');
 assert.equal(bytes.length,reference.payloadByteSize);assert.equal(sha256(bytes),reference.payloadSha256,'Private evidence payload digest');
 return bytes;
}

export function privateEvidenceStore({run,directory}){
 ensureStageBPrivateDirectory({directory,repositoryRoot:root,create:true});
 return createReleaseCoordinatorStore({run,directory,repositoryRoot:root});
}

export function runPrivateEvidenceCli(argv=process.argv.slice(2),{env=process.env,run}={}){
 const args=new Map();for(let i=0;i<argv.length;i+=2){assert.ok(['--mode','--kind','--source-sha','--producer-run-id','--input','--output'].includes(argv[i])&&!args.has(argv[i])&&argv[i+1]);args.set(argv[i],argv[i+1]);}
 assert.equal(args.size,6);const mode=args.get('--mode'),kind=args.get('--kind'),sourceSha=args.get('--source-sha'),workflowRunId=args.get('--producer-run-id');
 assert.ok(['publish','read'].includes(mode));assert.ok(Object.hasOwn(workflows,kind));
 const output=path.resolve(args.get('--output'));const directory=path.dirname(output);
 const awsRun=run||createProductionAwsCommandRunner({credentialSource:PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER,env});
 const store=privateEvidenceStore({run:awsRun,directory});
 const input=ensureStageBPrivateFile({filePath:path.resolve(args.get('--input')),repositoryRoot:root,label:'Private evidence input'});
 let bytes;
 if(mode==='publish'){
  assert.equal(env.GITHUB_ACTIONS,'true');assert.equal(env.GITHUB_EVENT_NAME,'workflow_dispatch');assert.equal(env.GITHUB_REPOSITORY,'T-ej2003/genuine-scan-main');
  assert.equal(env.GITHUB_SHA,sourceSha);assert.equal(env.GITHUB_RUN_ID,workflowRunId);assert.equal(env.GITHUB_RUN_ATTEMPT,'1');
  assert.equal(env.GITHUB_WORKFLOW_REF,`${env.GITHUB_REPOSITORY}/${workflows[kind]}@refs/heads/main`);
  bytes=Buffer.from(`${JSON.stringify(publishPrivateEvidence({bytes:fs.readFileSync(input.path),kind,sourceSha,workflowRunId,store}))}\n`);
 }else bytes=readPrivateEvidence({reference:JSON.parse(fs.readFileSync(input.path)),kind,sourceSha,workflowRunId,store});
 return writeStageBPrivateFileAtomicExclusive({filePath:output,bytes,repositoryRoot:root,label:'Private evidence output'});
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
 try{runPrivateEvidenceCli();}catch{process.stderr.write('Private Stage B evidence authentication failed.\n');process.exitCode=1;}
}
