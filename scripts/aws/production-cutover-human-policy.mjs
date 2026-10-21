import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {canonicalJson} from './production-green-stage-b-contract.mjs';

// Keep these fixed identities local: importing the environment adapter here cycles through Stage B.
const REPOSITORY='T-ej2003/genuine-scan-main';
const WORKFLOW_REF=`${REPOSITORY}/.github/workflows/authorize-production-stage-b-release-transition.yml@refs/heads/main`;

export const INDEPENDENT_REVIEW_V1='INDEPENDENT_REVIEW_V1';
export const SOLO_OPERATOR_CONTROLLED_V1='SOLO_OPERATOR_CONTROLLED_V1';
export const SOLO_OPERATOR_POLICY=Object.freeze({
  kind:SOLO_OPERATOR_CONTROLLED_V1,
  schemaVersion:1,
  enabled:false,
  githubUserId:183396573,
  githubLogin:'T-ej2003',
  checkerUserArn:'arn:aws:iam::368992683803:user/mscqr-production-checker-operator',
  repository:REPOSITORY,
  environment:'production',
  workflowRef:WORKFLOW_REF,
  toolingSourceSha:null,
  historicalReleaseSha:'475dc456ecda56e7f3386adeffa8c2e3dc632777',
  rotationId:'rotation-20260913011819-98b062c4',
  backendImageDigest:null,
  ticketId:'CHG-20261014-001',
  notAfter:null,
  eligiblePhases:Object.freeze(['INVENTORY_ADOPTION','ROTATION_SUCCESSOR','PREPARE_OVERLAP']),
});
export const soloPolicyHash=policy=>createHash('sha256').update(canonicalJson(policy)).digest('hex');

export function assertSoloOperatorPolicy(policy,{d,phase,now=Date.now()}) {
  assert.deepEqual(Object.keys(policy||{}).sort(),Object.keys(SOLO_OPERATOR_POLICY).sort(),'Solo policy fields differ');
  assert.equal(policy.kind,SOLO_OPERATOR_CONTROLLED_V1);assert.equal(policy.schemaVersion,1);
  assert.equal(policy.enabled,true,'Solo-operator policy remains disabled');
  assert.ok(['INVENTORY_ADOPTION','ROTATION_SUCCESSOR','PREPARE_OVERLAP'].includes(phase)&&policy.eligiblePhases.includes(phase),'Phase is ineligible for solo authorization');
  assert.equal(policy.repository,d.repository);assert.equal(policy.environment,'production');
  assert.equal(policy.workflowRef,WORKFLOW_REF);
  assert.equal(policy.toolingSourceSha,d.toolingSourceSha);assert.equal(policy.historicalReleaseSha,d.historicalReleaseSha);
  assert.equal(policy.rotationId,d.rotationId);assert.equal(policy.backendImageDigest,d.backendImageDigest);
  assert.equal(policy.ticketId,d.ticketId);
  assert.ok(Number.isSafeInteger(policy.githubUserId)&&policy.githubUserId>0&&/^[A-Za-z0-9-]+$/.test(policy.githubLogin));
  assert.equal(policy.checkerUserArn,'arn:aws:iam::368992683803:user/mscqr-production-checker-operator');
  const expires=Date.parse(policy.notAfter);
  assert.ok(Number.isSafeInteger(expires)&&new Date(expires).toISOString()===policy.notAfter&&now<expires,'Solo policy is expired');
  return soloPolicyHash(policy);
}

// Caller-supplied role names cannot establish a second human. The run and
// approval identities must come from the authenticated GitHub API responses.
export function assertConditionalHumanReview({evidence,run,phase,policyVersion=INDEPENDENT_REVIEW_V1,policy=SOLO_OPERATOR_POLICY,d,now}) {
  const actor=run?.actor,reviewer=evidence?.actualApproval;
  assert.ok(Number.isSafeInteger(actor?.id)&&actor.id>0 && /^[A-Za-z0-9-]+$/.test(actor.login||''),'Authenticated workflow actor identity required');
  assert.ok(Number.isSafeInteger(reviewer?.userId)&&reviewer.userId>0,'Authenticated actual reviewer identity required');
  assert.equal(actor.login.toLowerCase(),evidence.executionActor.toLowerCase(),'Workflow actor differs from approval evidence');
  assert.equal(evidence.workflowRef,WORKFLOW_REF);
  assert.equal(evidence.environment,'production');
  if(policyVersion===INDEPENDENT_REVIEW_V1) {
    assert.notEqual(actor.id,reviewer.userId,'Independent conditional approval cannot be self-reviewed');
    return Object.freeze({policyVersion,actorId:actor.id,reviewerId:reviewer.userId,selfAuthorized:false});
  }
  assert.equal(policyVersion,SOLO_OPERATOR_CONTROLLED_V1,'Unknown conditional authorization policy');
  assertSoloOperatorPolicy(policy,{d,phase,now});
  assert.equal(policy.repository,evidence.repository);assert.equal(policy.environment,evidence.environment);
  assert.equal(policy.workflowRef,evidence.workflowRef);
  assert.equal(actor.id,policy.githubUserId);assert.equal(reviewer.userId,policy.githubUserId);
  assert.equal(actor.login.toLowerCase(),policy.githubLogin.toLowerCase());
  assert.equal(reviewer.userLogin.toLowerCase(),policy.githubLogin.toLowerCase());
  return Object.freeze({policyVersion,actorId:actor.id,reviewerId:reviewer.userId,selfAuthorized:true});
}
