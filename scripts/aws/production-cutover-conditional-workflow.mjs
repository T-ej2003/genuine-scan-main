import assert from 'node:assert/strict';
import JSZip from 'jszip';
import {assertConditionalDerivation,assertConditionalPayload,conditionalHash,parseConditionalJson,exactConditionalKeys} from './production-cutover-conditional-authorization.mjs';
import {fetchProductionEnvironmentApprovalEvidence,assertProductionEnvironmentActualReviewer,assertProductionEnvironmentApprovalFreshness,PRODUCTION_ENVIRONMENT_APPROVAL} from './production-github-environment-approval.mjs';

const authenticated=new WeakSet();
export const isAuthenticatedConditionalWorkflowArtifact=value=>authenticated.has(value);

export async function authenticateConditionalWorkflowArtifact({d,runId,artifactId,token,fetchImpl=fetch,now=Date.now()}) {
  assertConditionalDerivation(d); assert.match(String(runId),/^[1-9][0-9]*$/); assert.match(String(artifactId),/^[1-9][0-9]*$/); assert.ok(token);
  const get=async suffix=>{
    const response=await fetchImpl(`https://api.github.com/repos/${d.repository}/${suffix}`,{headers:{Accept:'application/vnd.github+json',Authorization:`Bearer ${token}`}});
    assert.ok(response.ok, 'Conditional workflow API authentication failed'); return response;
  };
  const run=await (await get(`actions/runs/${runId}`)).json();
  assert.equal(String(run.id),String(runId)); assert.equal(run.head_sha,d.toolingSourceSha); assert.equal(run.run_attempt,1);
  assert.equal(run.path,'.github/workflows/authorize-production-stage-b-release-transition.yml'); assert.equal(run.event,'workflow_dispatch');
  assert.equal(run.status,'completed'); assert.equal(run.conclusion,'success'); assert.equal(run.repository.full_name,d.repository); assert.equal(run.head_repository.full_name,d.repository);
  const metadata=await (await get(`actions/artifacts/${artifactId}`)).json();
  assert.equal(String(metadata.id),String(artifactId)); assert.equal(metadata.name,'production-stage-b-conditional-overlap-authorization'); assert.equal(metadata.expired,false);
  assert.equal(String(metadata.workflow_run.id),String(runId)); assert.equal(metadata.workflow_run.head_sha,d.toolingSourceSha); assert.equal(metadata.workflow_run.repository_id,run.repository.id);
  assert.ok(metadata.size_in_bytes<=1024*1024); assert.match(metadata.digest,/^sha256:[a-f0-9]{64}$/);
  const bytes=Buffer.from(await (await get(`actions/artifacts/${artifactId}/zip`)).arrayBuffer());
  assert.ok(bytes.length<=1024*1024); assert.equal(`sha256:${conditionalHash(bytes)}`,metadata.digest);
  const zip=await JSZip.loadAsync(bytes); assert.deepEqual(Object.keys(zip.files),['authorization.json']);
  assert.ok(zip.files['authorization.json']._data.uncompressedSize<=1024*1024);
  const envelope=parseConditionalJson(await zip.files['authorization.json'].async('nodebuffer'));
  exactConditionalKeys(envelope,['payload','payloadSha256','workflowArtifactProvenance'],'Workflow authorization');
  assertConditionalPayload(envelope.payload,d,'PREPARE_OVERLAP',now); assert.equal(envelope.payloadSha256,conditionalHash(envelope.payload));
  const provenance=envelope.workflowArtifactProvenance;
  exactConditionalKeys(provenance,['workflowRunId','workflowRunAttempt','workflowRef','sourceSha','environmentApproval'],'Workflow provenance');
  assert.equal(provenance.workflowRunId,String(runId)); assert.equal(provenance.workflowRunAttempt,'1'); assert.equal(provenance.workflowRef,PRODUCTION_ENVIRONMENT_APPROVAL.stageBReleaseTransitionWorkflowRef); assert.equal(provenance.sourceSha,d.toolingSourceSha);
  const evidence=provenance.environmentApproval;
  assertProductionEnvironmentApprovalFreshness(evidence,{now:new Date(now)});
  const reviewer=assertProductionEnvironmentActualReviewer(evidence,{sourceSha:d.toolingSourceSha,repository:d.repository,executionActor:run.actor.login});
  assert.equal(evidence.workflowRunId,String(runId)); assert.equal(evidence.workflowRunAttempt,'1'); assert.equal(evidence.workflowRef,provenance.workflowRef);
  assert.ok(Date.parse(evidence.observedAt)>=Date.parse(run.created_at) && Date.parse(evidence.observedAt)<=Date.parse(run.updated_at),'Approval observation is outside producing run');
  const live=await fetchProductionEnvironmentApprovalEvidence({token,repository:d.repository,environment:'production',sourceSha:d.toolingSourceSha,workflowRef:provenance.workflowRef,eventName:'workflow_dispatch',workflowRunId:String(runId),workflowRunAttempt:'1',executionActor:run.actor.login,observedAt:new Date(now).toISOString(),requireActualApproval:true},{fetchImpl});
  assert.deepEqual(evidence.actualApproval,live.actualApproval); assert.deepEqual(evidence.configuredReviewers,live.configuredReviewers); assert.equal(evidence.environmentId,live.environmentId); assert.equal(evidence.preventSelfReview,live.preventSelfReview); assert.equal(evidence.canAdminsBypass,live.canAdminsBypass);
  assert.equal(envelope.payload.approvalProvenance,evidence.evidenceSha256); assert.ok(reviewer);
  const freeze=value=>{if(value && typeof value==='object'){Object.values(value).forEach(freeze);Object.freeze(value);}return value;};
  const result=freeze({provenance,derivationSha256:conditionalHash(d),payloadSha256:envelope.payloadSha256,phase:'prepare-overlap-conditional',sourceSha:d.toolingSourceSha,environmentApproval:evidence,envelope});
  authenticated.add(result); return result;
}

/** Isolated producer used by the existing protected workflow; no broker, Terraform or KMS operation. */
export async function produceConditionalOverlapAuthorization({d,sourceSha,ticketId,releaseId,preparationReference,authorizationRound,env=process.env,fetchImpl=fetch,now=Date.now()}) {
  assertConditionalDerivation(d);
  assert.equal(sourceSha,d.historicalReleaseSha);assert.equal(ticketId,d.ticketId);
  const {conditionalOperationId,CONDITIONAL_RULES,CONDITIONAL_EFFECTS,CONDITIONAL_PRINCIPALS}=await import('./production-cutover-conditional-authorization.mjs');
  assert.equal(releaseId,conditionalOperationId(d.rotationId,d.predecessor.stateSha256));assert.equal(authorizationRound,0);
  assert.match(preparationReference,/^[a-f0-9]{64}$/);
  assert.equal(env.GITHUB_ACTIONS,'true');assert.equal(env.GITHUB_SHA,d.toolingSourceSha);
  assert.equal(env.GITHUB_REPOSITORY,d.repository);assert.equal(env.GITHUB_EVENT_NAME,'workflow_dispatch');
  assert.equal(env.GITHUB_WORKFLOW_REF,PRODUCTION_ENVIRONMENT_APPROVAL.stageBReleaseTransitionWorkflowRef);
  assert.equal(env.GITHUB_RUN_ATTEMPT,'1');assert.match(env.GITHUB_RUN_ID,/^[1-9][0-9]*$/);
  for(const [name,value] of Object.entries({RELEASE_ID:releaseId,RELEASE_PHASE:'prepare-overlap-conditional',RELEASE_PREPARATION_REFERENCE:preparationReference,RELEASE_AUTHORIZATION_ROUND:'0'}))assert.equal(env[name],value);
  const branchResponse=await fetchImpl(`https://api.github.com/repos/${d.repository}/branches/main`,{headers:{Accept:'application/vnd.github+json',Authorization:`Bearer ${env.GH_TOKEN}`}});
  assert.ok(branchResponse.ok);const branch=await branchResponse.json();assert.equal(branch.protected,true);assert.equal(branch.commit.sha,d.toolingSourceSha,'Protected source changed');
  const {readBrokerProtectedEnvironmentApproval}=await import('./stage-b-staged-broker-authorization.mjs');
  const {approval}=await readBrokerProtectedEnvironmentApproval({sourceSha:d.toolingSourceSha,env,fetchImpl,now:new Date(now)});
  const payload={kind:'CUTOVER_CONDITIONAL_AUTHORIZATION_V1',schemaVersion:1,
    authorizationId:conditionalHash({phase:'PREPARE_OVERLAP',derivationSha256:conditionalHash(d),preparationReference,runId:env.GITHUB_RUN_ID}),
    phase:'PREPARE_OVERLAP',derivationSha256:conditionalHash(d),authority:'GITHUB_PRODUCTION_REVIEWER',executorPrincipal:CONDITIONAL_PRINCIPALS.release,
    dependencyRule:CONDITIONAL_RULES.PREPARE_OVERLAP,operationEnvelope:CONDITIONAL_EFFECTS.PREPARE_OVERLAP,
    notBefore:d.notBefore,notAfter:d.notAfter,maxDispatches:1,approvalProvenance:approval.evidenceSha256};
  assert.ok(now>=Date.parse(d.notBefore)-30*60*1000&&now<Date.parse(d.notAfter),'Issuance is outside the reviewed lead window');
  assertConditionalPayload(payload,d,'PREPARE_OVERLAP',Math.max(now,Date.parse(d.notBefore)));
  return {payload,payloadSha256:conditionalHash(payload),workflowArtifactProvenance:{workflowRunId:env.GITHUB_RUN_ID,workflowRunAttempt:'1',workflowRef:env.GITHUB_WORKFLOW_REF,sourceSha:d.toolingSourceSha,environmentApproval:approval}};
}
