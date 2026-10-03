import assert from "node:assert/strict";
import { createPinnedRootAttestationVerifier } from "./production-root-attestation-key.mjs";
import { canonicalSha256 } from "./production-green-stage-b-contract.mjs";
import { assertHistoricalRuntimeReference, assertHistoricalRuntimeRetention, verifyHistoricalRuntimeLive, historicalWorkerTasks } from "./production-historical-runtime-contract.mjs";
import { buildPermissionReportBinding, signedPermissionReportBindingSha256, createPermissionReportKmsVerifier, PERMISSION_REPORT_SIGNING_KEY_ARN, PERMISSION_REPORT_SIGNING_ALGORITHM, PERMISSION_REPORT_BINDING_DOMAIN, PERMISSION_REPORT_BINDING_SCHEMA_VERSION, PLAN_BOUND_PERMISSION_EVIDENCE_KIND } from "./validate-production-green-stage-b-permissions.mjs";
import { assertStageBDeploymentEvidenceFreshness } from "./stage-b-evidence-freshness.mjs";

// Portable projection of the EXISTING signed permission-report binding. The
// signature authenticates this compact claim directly; closure needs neither
// unsigned reconstruction nor the report's large IAM simulation census.
export function historicalRuntimeEvidence({ reference, report, signatureArtifact }) {
  assertHistoricalRuntimeReference(reference);
  assert.equal(report.historicalRuntimeAuthority?.referenceSha256, reference.referenceSha256);
  const binding = buildPermissionReportBinding({ report, canonicalPayloadSha256: signatureArtifact.canonicalPayloadSha256, reportFileSha256: signatureArtifact.reportFileSha256 });
  assert.equal(signedPermissionReportBindingSha256(binding), signatureArtifact.signedBindingSha256);
  return { schemaVersion: 1, reference, binding, signatureBase64: signatureArtifact.signatureBase64 };
}

export function authenticateHistoricalRuntimeEvidence({ evidence, sourceSha, retained = false, verify, run, now = new Date().toISOString() }) {
  assert.deepEqual(Object.keys(evidence || {}).sort(), ["binding", "reference", "schemaVersion", "signatureBase64"]);
  assert.equal(evidence.schemaVersion, 1); assertHistoricalRuntimeReference(evidence.reference);
  const binding = evidence.binding;
  assert.deepEqual(Object.keys(binding || {}).sort(), ["accountId", "canonicalPayloadSha256", "domain", "evidenceKind", "historicalRuntimeAuthority", "keyArn", "phase", "purpose", "region", "reportFileSha256", "schemaVersion", "signingAlgorithm"].sort());
  assert.equal(binding.domain, PERMISSION_REPORT_BINDING_DOMAIN); assert.equal(binding.schemaVersion, PERMISSION_REPORT_BINDING_SCHEMA_VERSION);
  assert.equal(binding.evidenceKind, PLAN_BOUND_PERMISSION_EVIDENCE_KIND); assert.equal(binding.phase, "plan-bound"); assert.equal(binding.purpose, "saved-plan-authorization");
  assert.equal(binding.accountId, "368992683803"); assert.equal(binding.region, "eu-west-2"); assert.equal(binding.keyArn, PERMISSION_REPORT_SIGNING_KEY_ARN); assert.equal(binding.signingAlgorithm, PERMISSION_REPORT_SIGNING_ALGORITHM);
  const authority = binding.historicalRuntimeAuthority;
  assert.deepEqual(Object.keys(authority || {}).sort(), ["approvedAt", "planApprovalReportSha256", "referenceAuditSha256", "referenceSha256", "sourceSha"].sort());
  for (const value of [authority.planApprovalReportSha256, authority.referenceAuditSha256, binding.canonicalPayloadSha256, binding.reportFileSha256]) assert.match(value || "", /^[a-f0-9]{64}$/);
  assert.equal(authority.referenceSha256, evidence.reference.referenceSha256); assert.equal(authority.sourceSha, evidence.reference.recoverySourceSha);
  assert.ok(Number.isFinite(Date.parse(authority.approvedAt)));
  for (const timestamp of [evidence.reference.runtime.createdAt, evidence.reference.registration.eventTime, evidence.reference.launch.eventTime]) assert.ok(Date.parse(authority.approvedAt) >= Date.parse(timestamp), "Historical authority predates its authenticated runtime");
  if (!retained) { assert.equal(authority.sourceSha, sourceSha); assertStageBDeploymentEvidenceFreshness(authority.approvedAt, { now, evidenceType: "Historical runtime Stage B approval" }); }
  assert.match(evidence.signatureBase64 || "", /^[A-Za-z0-9+/]+={0,2}$/);
  const verifier = verify || (run ? createPermissionReportKmsVerifier({ run }) : createPinnedRootAttestationVerifier());
  assert.equal(verifier({ keyArn: binding.keyArn, signingAlgorithm: binding.signingAlgorithm, digest: Buffer.from(signedPermissionReportBindingSha256(binding), "hex"), signature: Buffer.from(evidence.signatureBase64, "base64") }), true, "Historical runtime authority signature is invalid");
  return evidence.reference;
}

export function authenticateRetainedHistoricalRuntime({ state, reader, verify, run }) {
  if (!state.historicalRuntimeRetention) return undefined;
  const retention = assertHistoricalRuntimeRetention(state.historicalRuntimeRetention);
  assert.ok(retention.closure.generation <= state.generation);
  const evidence = { schemaVersion: 1, reference: retention.reference, ...retention.authority };
  delete evidence.referenceSha256;
  authenticateHistoricalRuntimeEvidence({ evidence, retained: true, verify, run });
  verifyHistoricalRuntimeLive({ reference: retention.reference, reader });
  return retention.reference;
}

export function historicalRuntimeRetention({ evidence, sourceSha, current, componentStateSha256, reader, verify, run, writerContext, now }) {
  const reference = authenticateHistoricalRuntimeEvidence({ evidence, sourceSha, retained: Boolean(current.historicalRuntimeRetention), verify, run, now });
  verifyHistoricalRuntimeLive({ reference, reader });
  if (current.historicalRuntimeRetention) {
    authenticateRetainedHistoricalRuntime({ state: current, reader, verify, run });
    assert.equal(current.historicalRuntimeRetention.reference.referenceSha256, reference.referenceSha256, "Historical baseline cannot be replaced");
    assert.equal(canonicalSha256(current.historicalRuntimeRetention.authority.binding), canonicalSha256(evidence.binding));
    return current.historicalRuntimeRetention;
  }
  assert.equal(current.generation, reference.bootstrap.generation); assert.equal(current.updatedByLane, "BOOTSTRAP"); assert.equal(current.normalDeploymentReceipt, undefined);
  assert.equal(componentStateSha256, reference.bootstrap.componentStateSha256, "Bootstrap predecessor changed before retention commit");
  assert.equal(current.githubRunId, reference.bootstrap.githubRunId); assert.equal(current.updatedByWorkflow, reference.bootstrap.workflow);
  return assertHistoricalRuntimeRetention({ schemaVersion: 1, status: "RETAINED", reference, authority: { referenceSha256: reference.referenceSha256, binding: evidence.binding, signatureBase64: evidence.signatureBase64 },
    closure: { sourceSha, workflow: writerContext.updatedByWorkflow, githubRunId: String(writerContext.githubRunId), generation: current.generation + 1 } });
}

export function verifyHistoricalRuntimeInventory({ reference, reader }) {
  verifyHistoricalRuntimeLive({ reference, reader });
  const arns = reader.listTasks("RUNNING");
  const tasks = [];
  for (let i = 0; i < arns.length; i += 100) {
    const response = reader.describeTasks(arns.slice(i, i + 100));
    assert.equal(response.failures?.length, 0); assert.equal(response.tasks?.length, arns.slice(i, i + 100).length);
    tasks.push(...response.tasks);
  }
  const workers = historicalWorkerTasks({ tasks, reader });
  assert.equal(workers.length, 1, "Historical retention cannot authorize a second worker");
  assert.equal(workers[0].taskArn, reference.runtime.taskArn);
  return true;
}
