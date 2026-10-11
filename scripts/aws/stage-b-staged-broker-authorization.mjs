import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import JSZip from 'jszip';
import {readZipCentralDirectory,zipEntryBytes} from './package-production-green-stage-b-broker.mjs';
import { STAGE_B, STAGE_B_APPROVAL_ALGORITHM, canonicalJson } from './production-green-stage-b-contract.mjs';
import { brokerDigest, brokerExecutionCheckout, assertBrokerPreparation, assertBrokerAuthorization, receiptBoundCheckerDisclosure,assertBrokerReleaseAuthorizationContext } from './stage-b-staged-broker-contract.mjs';
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from './production-credential-source-contract.mjs';
import {PRODUCTION_ENVIRONMENT_APPROVAL,assertProductionEnvironmentApprovalIdentity,assertProductionEnvironmentApprovalFreshness,assertProductionEnvironmentActualReviewer,createProductionEnvironmentApprovalEvidence,fetchProductionEnvironmentApprovalEvidence,assertProductionEnvironmentApprovalEvidence} from './production-github-environment-approval.mjs';

export const brokerAuthorizationMessage = ({ signature, ...body }) => Buffer.from(canonicalJson(body));

export async function readBrokerProtectedEnvironmentApproval({sourceSha,env=process.env,fetchImpl=fetch,now=new Date()}) {
  if(env.GITHUB_ACTIONS!=='true')return null;
  assert.equal(env.GITHUB_WORKFLOW_REF,PRODUCTION_ENVIRONMENT_APPROVAL.stageBReleaseTransitionWorkflowRef,'Stage-B authorization requires its dedicated governed workflow');
  assert.equal(env.GITHUB_SHA,sourceSha);assert.equal(env.GITHUB_RUN_ATTEMPT,'1');
  const context={repository:env.GITHUB_REPOSITORY,environment:'production',sourceSha,workflowRef:env.GITHUB_WORKFLOW_REF,eventName:env.GITHUB_EVENT_NAME,
    workflowRunId:env.GITHUB_RUN_ID,workflowRunAttempt:env.GITHUB_RUN_ATTEMPT,executionActor:env.GITHUB_ACTOR,githubActions:env.GITHUB_ACTIONS,now};
  const approval=await fetchProductionEnvironmentApprovalEvidence({...context,token:env.GH_TOKEN,requireActualApproval:true,observedAt:now.toISOString()},{fetchImpl});
  assertProductionEnvironmentApprovalEvidence(approval,context);
  assertProductionEnvironmentActualReviewer(approval,context);
  assert.match(env.RELEASE_AUTHORIZATION_ROUND||'',/^(?:0|[1-9][0-9]*)$/);
  return {approval,release:{releaseId:env.RELEASE_ID,phase:env.RELEASE_PHASE,preparationReference:env.RELEASE_PREPARATION_REFERENCE,authorizationRound:Number(env.RELEASE_AUTHORIZATION_ROUND)}};
}

export function createBrokerProtectedEnvironmentAuthorization(preparation,{approval,release,now=new Date()}) {
  assertBrokerPreparation(preparation);
  assertBrokerReleaseAuthorizationContext(release,preparation);
  const executionSourceSha=brokerExecutionCheckout(preparation).sourceSha;
  assertProductionEnvironmentApprovalIdentity(approval,{sourceSha:executionSourceSha,repository:PRODUCTION_ENVIRONMENT_APPROVAL.repository});
  assertProductionEnvironmentApprovalFreshness(approval,{now});
  assert.equal(approval.workflowRef,PRODUCTION_ENVIRONMENT_APPROVAL.stageBReleaseTransitionWorkflowRef);
  assert.equal(approval.workflowRunAttempt,'1');
  const approvedBy=assertProductionEnvironmentActualReviewer(approval,{sourceSha:executionSourceSha,repository:approval.repository,executionActor:approval.executionActor});
  const independent=approvedBy.toLowerCase()!==approval.executionActor.toLowerCase(),disclosure=receiptBoundCheckerDisclosure(preparation);
  return {schemaVersion:2,purpose:preparation.purpose,preparationSha256:brokerDigest(preparation),sourceSha:preparation.sourceSha,
    nonce:randomBytes(32).toString('hex'),issuedAt:now.toISOString(),expiresAt:new Date(now.getTime()+30*60000).toISOString(),
    review:{approvedBy,checkerIndependent:independent,soleOperatorModel:!independent},release,protectedEnvironmentApprovalEvidence:approval,
    ...(disclosure?{recoveryDisclosure:disclosure}:{})};
}

export async function readBrokerProtectedEnvironmentAuthorization({workflowRunId,sourceSha,workflowSourceSha=sourceSha,run}) {
  assert.match(String(workflowRunId),/^[1-9][0-9]*$/);assert.match(sourceSha||'',/^[a-f0-9]{40}$/);assert.match(workflowSourceSha||'',/^[a-f0-9]{40}$/);assert.equal(typeof run,'function');
  const repository=PRODUCTION_ENVIRONMENT_APPROVAL.repository;
  const api=(suffix,...flags)=>JSON.parse(run(['api',`repos/${repository}/${suffix}`,...flags],{encoding:'utf8',maxBuffer:8*1024*1024}));
  const workflow=api(`actions/runs/${String(workflowRunId)}`);
  assert.equal(String(workflow.id),String(workflowRunId));assert.equal(workflow.repository?.full_name,repository);assert.equal(workflow.head_repository?.full_name,repository);
  assert.equal(workflow.path,'.github/workflows/authorize-production-stage-b-release-transition.yml');assert.equal(workflow.head_sha,workflowSourceSha);
  assert.equal(workflow.event,'workflow_dispatch');assert.equal(workflow.status,'completed');assert.equal(workflow.conclusion,'success');assert.equal(String(workflow.run_attempt),'1');
  const pages=api(`actions/runs/${workflow.id}/artifacts`,'--paginate','--slurp');assert.ok(Array.isArray(pages));
  const matches=pages.flatMap(page=>page.artifacts||[]).filter(a=>a.name==='production-stage-b-release-transition-authorization'&&a.expired===false&&String(a.workflow_run?.id)===String(workflowRunId)&&a.workflow_run?.head_sha===workflowSourceSha&&a.workflow_run?.repository_id===workflow.repository.id);
  assert.equal(matches.length,1,'Exact transition authorization artifact required');const artifact=matches[0];assert.ok(Number.isSafeInteger(artifact.id)&&artifact.id>0);
  assert.match(artifact.digest||'',/^sha256:[a-f0-9]{64}$/);
  const archive=Buffer.from(run(['api',`repos/${repository}/actions/artifacts/${artifact.id}/zip`],{encoding:null,maxBuffer:8*1024*1024}));
  assert.equal(`sha256:${createHash('sha256').update(archive).digest('hex')}`,artifact.digest);
  const members=readZipCentralDirectory(archive,{allowSingleMemberDataDescriptor:true});assert.equal(members.length,1);assert.equal(members[0].name,'authorization.json','Unexpected raw authorization ZIP member');assert.ok(members[0].uncompressedSize<=8*1024*1024,'Oversized authorization archive member');
  const zip=await JSZip.loadAsync(archive,{checkCRC32:true}),entries=Object.values(zip.files).filter(e=>!e.dir);
  assert.equal(entries.length,1);assert.equal(entries[0].name,'authorization.json');assert.notEqual(Number(entries[0].unixPermissions||0)&0o170000,0o120000);
  const bytes=await entries[0].async('uint8array');assert.ok(bytes.length<=8*1024*1024,'Oversized authorization payload');assert.equal(bytes.length,members[0].uncompressedSize,'Authorization ZIP member size differs');
  assert.deepEqual(Buffer.from(bytes),zipEntryBytes(archive,members[0]),'Authorization ZIP member interpretation differs');
  const authorization=JSON.parse(new TextDecoder('utf8',{fatal:true}).decode(bytes));
  assert.equal(authorization.schemaVersion,2);assert.equal(authorization.sourceSha,sourceSha);
  assert.equal(authorization.protectedEnvironmentApprovalEvidence.workflowRunId,String(workflowRunId));
  return {authorization,workflow};
}

export async function verifyBrokerProtectedEnvironmentAuthorization(authorization,{run}) {
  assert.equal(authorization.schemaVersion,2);assert.equal(typeof run,'function');
  const approval=authorization.protectedEnvironmentApprovalEvidence,repository=PRODUCTION_ENVIRONMENT_APPROVAL.repository;
  assertProductionEnvironmentApprovalIdentity(approval,{sourceSha:approval.sourceSha,repository});
  assert.equal(approval.workflowRef,PRODUCTION_ENVIRONMENT_APPROVAL.stageBReleaseTransitionWorkflowRef);assert.equal(approval.workflowRunAttempt,'1');
  const {authorization:downloaded,workflow}=await readBrokerProtectedEnvironmentAuthorization({workflowRunId:approval.workflowRunId,sourceSha:authorization.sourceSha,workflowSourceSha:approval.sourceSha,run});
  assert.equal(canonicalJson(downloaded),canonicalJson(authorization),'Authorization artifact substitution');
  const api=(suffix,...flags)=>JSON.parse(run(['api',`repos/${repository}/${suffix}`,...flags],{encoding:'utf8',maxBuffer:8*1024*1024}));
  const environment=api('environments/production'),approvals=api(`actions/runs/${workflow.id}/approvals`);
  const actual=approvals.flatMap(a=>a.state==='approved'?(a.environments||[]).filter(e=>e.id===environment.id&&e.name==='production').map(()=>({state:'approved',environmentId:environment.id,environmentName:'production',userId:a.user?.id,userLogin:a.user?.login})):[]);
  assert.equal(actual.length,1,'Exact protected production approval required');
  const observed=createProductionEnvironmentApprovalEvidence({environmentConfig:environment,repository,environment:'production',sourceSha:approval.sourceSha,
    workflowRef:approval.workflowRef,eventName:workflow.event,workflowRunId:approval.workflowRunId,workflowRunAttempt:'1',executionActor:workflow.actor?.login,observedAt:approval.observedAt,actualApproval:actual[0]});
  assert.equal(canonicalJson(observed),canonicalJson(approval),'Approval provenance substitution');return true;
}

// Same checker, key and algorithm as the existing Stage B approvals; distinct
// purpose prevents a runtime/RLS approval from authorizing infrastructure.
export async function signBrokerAuthorization(preparation, { makerIdentity, humanReviewId, makerCaller, caller, sign, verify, now = new Date() }) {
  assertBrokerPreparation(preparation);
  assert.equal(typeof makerCaller, 'function', 'Authenticated maker caller is required');
  const maker = await makerCaller();
  assert.equal(maker.Account, STAGE_B.account);
  assert.match(maker.Arn, /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[^/]+$/);
  assert.equal(makerIdentity, maker.Arn, 'Requested maker differs from authenticated release caller');
  const checkerIdentity = (await caller()).Arn;
  const recoveryDisclosure = receiptBoundCheckerDisclosure(preparation);
  const body = { schemaVersion: 1, purpose: preparation.purpose, preparationSha256: brokerDigest(preparation), sourceSha: preparation.sourceSha,
    nonce: randomBytes(32).toString('hex'), issuedAt: now.toISOString(), expiresAt: new Date(now.getTime() + 30 * 60000).toISOString(), review: { makerIdentity, checkerIdentity, humanReviewId },
    ...(recoveryDisclosure ? { recoveryDisclosure } : {}) };
  const signature = { keyArn: STAGE_B.approvalKmsKeyArn, algorithm: STAGE_B_APPROVAL_ALGORITHM, signatureBase64: 'cGVuZGluZw==' };
  // Validate identity and phase before reaching Sign, not only afterward.
  await assertBrokerAuthorization({ ...body, signature }, preparation, { now, verify: async () => true });
  signature.signatureBase64 = await sign(brokerAuthorizationMessage(body));
  const authorization = { ...body, signature };
  await assertBrokerAuthorization(authorization, preparation, { now, verify });
  return authorization;
}

export function createBrokerKmsAuthorizationBoundary({ run, githubRun }) {
  assert.equal(typeof run, 'function');
  const messageFile = (bytes, operation) => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'mscqr-broker-authorization-'));
    fs.chmodSync(directory, 0o700);
    try {
      // KMS RAW hashes SHA-256 internally; DIGEST binds the same complete message above its 4096-byte transport limit.
      const messageType = bytes.length > 4096 ? 'DIGEST' : 'RAW';
      const message = messageType === 'DIGEST' ? createHash('sha256').update(bytes).digest() : bytes;
      const file = path.join(directory, 'message'); fs.writeFileSync(file, message, { mode: 0o600, flag: 'wx' });
      return operation(file, messageType);
    } finally { fs.rmSync(directory, { recursive: true }); }
  };
  const json = args => JSON.parse(run([...args, '--output', 'json', '--no-cli-pager']));
  const common = ['--key-id', STAGE_B.approvalKmsKeyArn, '--signing-algorithm', STAGE_B_APPROVAL_ALGORITHM];
  return {
    caller: async () => json(['sts', 'get-caller-identity']),
    sign: async bytes => messageFile(bytes, (file, messageType) => json(['kms', 'sign', ...common, '--message-type', messageType, '--message', `fileb://${file}`]).Signature),
    verify: async authorization => authorization.schemaVersion===2
      ? verifyBrokerProtectedEnvironmentAuthorization(authorization,{run:githubRun})
      : messageFile(brokerAuthorizationMessage(authorization), (file, messageType) => json(['kms', 'verify', ...common, '--message-type', messageType, '--message', `fileb://${file}`, '--signature', authorization.signature.signatureBase64]).SignatureValid === true),
  };
}
export function createBrokerCheckerAuthorizationBoundary() {
  return createBrokerKmsAuthorizationBoundary({ run: createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.INHERITED_CHECKER_SESSION }) });
}
