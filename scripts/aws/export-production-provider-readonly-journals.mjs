#!/usr/bin/env node
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {canonicalJson} from './production-green-stage-b-contract.mjs';
import {PROVIDER_READONLY_RECONCILIATION as C} from './production-provider-readonly-policy-reconciliation.mjs';
import {createProductionAwsCommandRunner, createProductionGithubCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE} from './production-credential-source-contract.mjs';
import {readStageBProtectedMainCheckout, readAuthenticatedGitHubProtectedMainIdentity} from './stage-b-deployment-identity.mjs';
import {fetchProductionEnvironmentApprovalEvidence, assertProductionEnvironmentActualReviewer, assertProductionEnvironmentApprovalFreshness} from './production-github-environment-approval.mjs';
import {encryptSecurityCatalogueTransport} from './production-security-rebaseline-transport.mjs';

const historical = Object.freeze({
  '4961bf0f8ad5a8d08c09622b74c484671e148010a669eb683f699f70032f08ae': 'd6f515fe393e0bcfda76e248aa8b3f2f3aae10e4',
  'daeb6710b40064667f5a722828ccc303945ec993b0bf8c0be93be2075adba888': 'e3b7fcce67be6c7151a6d082fc0aa23654d61764',
});
export const JOURNAL_EXPORT_KEYS = Object.freeze(Object.keys(historical).flatMap(id => ['reservation.json','write-attempt.json','terminal.json'].map(name => `${C.journalPrefix}${id}/${name}`)));
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
export const JOURNAL_EXPORT_REQUIREMENTS_SHA256 = hash(canonicalJson(JOURNAL_EXPORT_KEYS));
export function validateExportRequest(env, argv = []) {
  assert.equal(argv.length, 0, 'Export accepts no CLI overrides');
  assert.equal(env.GITHUB_ACTIONS, 'true'); assert.equal(env.GITHUB_REPOSITORY, 'T-ej2003/genuine-scan-main');
  assert.equal(env.GITHUB_WORKFLOW_REF, C.executionWorkflowRef); assert.equal(env.GITHUB_REF, 'refs/heads/main');
  assert.equal(env.GITHUB_EVENT_NAME, 'workflow_dispatch'); assert.equal(env.GITHUB_RUN_ATTEMPT, '1');
  assert.match(env.GITHUB_RUN_ID || '', /^[1-9][0-9]*$/); assert.match(env.SOURCE_SHA || '', /^[a-f0-9]{40}$/);
  assert.equal(env.GITHUB_SHA, env.SOURCE_SHA, 'Workflow revision must match export source');
  assert.equal(env.OPERATION, 'export-journals');
  for (const key of ['PREPARATION_JSON_BASE64','PREPARATION_FILE_SHA256','AUTHORIZATION_WORKFLOW_RUN_ID','AUTHORIZATION_WORKFLOW_RUN_ATTEMPT']) assert.ok(!env[key], 'Write inputs forbidden for export');
  const pem = Buffer.from(env.RECIPIENT_PUBLIC_KEY_BASE64 || '', 'base64').toString('utf8');
  const key = crypto.createPublicKey(pem); assert.equal(key.asymmetricKeyType, 'rsa'); assert.ok(key.asymmetricKeyDetails.modulusLength >= 3072);
  const fingerprint = hash(key.export({type:'spki',format:'der'}));
  assert.equal(fingerprint, env.RECIPIENT_PUBLIC_KEY_SHA256, 'Recipient fingerprint mismatch');
  return {pem,fingerprint};
}
export function validateJournalExportObject(key, bytes, metadata) {
  assert.ok(JOURNAL_EXPORT_KEYS.includes(key), 'Unapproved journal key');
  assert.ok(Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= 65536);
  assert.equal(metadata.ContentLength, bytes.length); assert.equal(metadata.ServerSideEncryption, 'AES256');
  assert.ok(typeof metadata.VersionId === 'string' && metadata.VersionId !== 'null' && metadata.VersionId.length > 0, 'Versioned evidence required');
  assert.match(metadata.ETag || '', /^"[a-f0-9-]+"$/);
  const value = JSON.parse(bytes.toString('utf8')), {recordSha256,...body} = value;
  assert.equal(recordSha256, hash(canonicalJson(body))); assert.ok(bytes.equals(Buffer.from(`${canonicalJson(value)}\n`)), 'Noncanonical journal');
  const [,id,name] = key.split('/');
  assert.equal(value.operationId,id); assert.equal(value.sourceSha,historical[id]); assert.equal(value.account,C.account); assert.equal(value.targetPolicyArn,C.policyArn);
  const kind = {'reservation.json':'RESERVATION','write-attempt.json':'WRITE_ATTEMPT','terminal.json':'TERMINAL'}[name];
  assert.equal(value.kind,`PRODUCTION_PROVIDER_READONLY_POLICY_RECONCILIATION_${kind}`);
  if (name === 'terminal.json') {assert.equal(value.status,'COMPLETED'); assert.equal(value.authorizationConsumed,true);}
  return {key,metadata,value,bytesSha256:hash(bytes)};
}
export async function exportProviderReadonlyJournals({env=process.env, argv=process.argv.slice(2), run, authenticateSource, approval} = {}) {
  const recipient = validateExportRequest(env,argv);
  const authSource = authenticateSource || (() => {readStageBProtectedMainCheckout({cwd:process.cwd(),expectedSourceSha:env.SOURCE_SHA,requireCanonicalRepository:true});readAuthenticatedGitHubProtectedMainIdentity({expectedSourceSha:env.SOURCE_SHA,githubRun:createProductionGithubCommandRunner()});});
  authSource();
  const approvalEvidence = await (approval || (() => fetchProductionEnvironmentApprovalEvidence({token:env.GH_TOKEN,repository:env.GITHUB_REPOSITORY,environment:'production',sourceSha:env.SOURCE_SHA,workflowRef:env.GITHUB_WORKFLOW_REF,eventName:env.GITHUB_EVENT_NAME,workflowRunId:env.GITHUB_RUN_ID,workflowRunAttempt:env.GITHUB_RUN_ATTEMPT,executionActor:env.GITHUB_ACTOR,requireActualApproval:true})))();
  assertProductionEnvironmentActualReviewer(approvalEvidence,{sourceSha:env.SOURCE_SHA,repository:env.GITHUB_REPOSITORY,executionActor:env.GITHUB_ACTOR});
  assertProductionEnvironmentApprovalFreshness(approvalEvidence);
  const aws = run || createProductionAwsCommandRunner({credentialSource:PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_POLICY_RECONCILER,env});
  const identity = JSON.parse(aws(['sts','get-caller-identity','--output','json','--no-cli-pager']));
  assert.equal(identity.Account,C.account); assert.match(identity.Arn,new RegExp(`^arn:aws:sts::${C.account}:assumed-role/${C.executorRoleName}/[^/]+$`));
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'mscqr-journal-export-'));fs.chmodSync(directory,0o700);
  try {
    const records=[];
    for (const [index,key] of JOURNAL_EXPORT_KEYS.entries()) {
      authSource(); const file=path.join(directory,`${index}.json`);
      const args=['s3api','get-object','--bucket',C.journalBucket,'--key',key,'--expected-bucket-owner',C.account,'--output','json','--no-cli-pager'];
      const metadata=JSON.parse(aws([...args,file]));fs.chmodSync(file,0o600);
      const record=validateJournalExportObject(key,fs.readFileSync(file),metadata);
      const verify=path.join(directory,`${index}-verify.json`);
      const observed=JSON.parse(aws([...args,verify]));fs.chmodSync(verify,0o600);
      assert.equal(observed.VersionId,metadata.VersionId); assert.equal(observed.ETag,metadata.ETag); assert.ok(fs.readFileSync(file).equals(fs.readFileSync(verify)), 'Journal changed during export');
      records.push(record);
    }
    authSource();
    const binding={sourceSha:env.SOURCE_SHA,candidateSourceSha:env.SOURCE_SHA,requirementsSha256:JOURNAL_EXPORT_REQUIREMENTS_SHA256};
    const evidence={schemaVersion:1,kind:'PROVIDER_READONLY_READ_ONLY_JOURNAL_EXPORT',sourceSha:env.SOURCE_SHA,workflowRef:env.GITHUB_WORKFLOW_REF,runId:env.GITHUB_RUN_ID,runAttempt:1,observedAt:new Date().toISOString(),identity,approvalEvidence,recipientFingerprint:recipient.fingerprint,bucket:C.journalBucket,records};
    const chunks=encryptSecurityCatalogueTransport(evidence,recipient.pem,binding);
    const out=path.join(env.RUNNER_TEMP,'provider-readonly-export');fs.mkdirSync(out,{mode:0o700});
    fs.writeFileSync(path.join(out,'encrypted-export.json'),JSON.stringify({binding,chunks})+'\n',{mode:0o600,flag:'wx'});
    return {status:'ENCRYPTED_READ_ONLY_EXPORT',objectCount:records.length};
  } finally {fs.rmSync(directory,{recursive:true,force:true});}
}
if (process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href) exportProviderReadonlyJournals().then(v=>console.log(JSON.stringify(v))).catch(()=>{console.error('Read-only journal export failed; no evidence published.');process.exitCode=1;});
