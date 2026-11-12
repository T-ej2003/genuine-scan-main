import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import JSZip from "jszip";
import { createProductionEnvironmentApprovalEvidence, PRODUCTION_ENVIRONMENT_APPROVAL } from "../aws/production-github-environment-approval.mjs";
import { createIncidentDiagnosticAuthorization, assertIncidentDiagnosticAuthorization, incidentJournalPolicy, incidentSecretPolicy, incidentTaskDefinition, resolveIncidentDiagnosticAuthorization } from "../aws/production-incident-diagnostic-authorization.mjs";

const diagnosticSourceSha = "a".repeat(40);
const now = new Date("2026-11-12T14:00:00.000Z");
const approvalEvidence = createProductionEnvironmentApprovalEvidence({
  environmentConfig: { name: "production", id: 17, can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: { id: 7, login: "T-ej2003" } }] }] },
  repository: "T-ej2003/genuine-scan-main", environment: "production", sourceSha: diagnosticSourceSha,
  workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.incidentDiagnosticWorkflowRef, eventName: "workflow_dispatch",
  workflowRunId: "123456", workflowRunAttempt: "1", executionActor: "operator", observedAt: now.toISOString(),
  actualApproval: { state: "approved", environmentId: 17, environmentName: "production", userId: 7, userLogin: "T-ej2003" },
});
const imagePublication = { runId: "987654", artifactId: 7, artifactDigest: `sha256:${"c".repeat(64)}`,
  sourceSha: diagnosticSourceSha, image: `sha256:${"b".repeat(64)}` };
const value = createIncidentDiagnosticAuthorization({ diagnosticSourceSha, image: `sha256:${"b".repeat(64)}`,
  imagePublication, executionId: "11111111-1111-4111-8111-111111111111", approvalEvidence, issuedAt: now.toISOString() });
assert.equal(assertIncidentDiagnosticAuthorization(value, { now }), value);
assert.equal(value.journalPolicy.Statement.length, 2);
assert.deepEqual(value.journalPolicy, incidentJournalPolicy(value));
assert.deepEqual(value.executionSecretPolicy, incidentSecretPolicy(value));
assert.equal(value.journalPolicy.Statement[0].Action, "s3:PutObject");
assert.equal(value.journalPolicy.Statement[1].Action, "s3:GetObject");
const task = incidentTaskDefinition(value);
assert.deepEqual(task.containerDefinitions[0].entryPoint, ["node", "scripts/production-incident-diagnostic-task.mjs"]);
assert.match(value.taskDefinitionSha256, /^[a-f0-9]{64}$/);
assert.equal(task.containerDefinitions[0].readonlyRootFilesystem, true);
assert.equal(task.containerDefinitions[0].secrets.length, 2);
assert.equal(task.containerDefinitions[0].environment.length, 1);
for (const [field, replacement] of [["sourceSha", "c".repeat(40)], ["executionId", "22222222-2222-4222-8222-222222222222"],
  ["provisionSha256", "d".repeat(64)], ["image", `sha256:${"e".repeat(64)}`]]) {
  assert.throws(() => assertIncidentDiagnosticAuthorization({ ...value, [field]: replacement }, { now }), /altered|authorized/);
}
assert.throws(() => assertIncidentDiagnosticAuthorization(value, { now: new Date(value.expiresAt) }), /expired/);
const archive = new JSZip();
archive.file("authorization.json", JSON.stringify(value));
const bytes = await archive.generateAsync({ type: "nodebuffer" });
const archiveDigest = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
const workflow = { id: 123456, repository: { id: 9, full_name: "T-ej2003/genuine-scan-main" },
  head_repository: { full_name: "T-ej2003/genuine-scan-main" }, path: ".github/workflows/authorize-production-incident-diagnostic.yml",
  head_sha: diagnosticSourceSha, event: "workflow_dispatch", status: "completed", conclusion: "success", run_attempt: 1 };
const artifact = { id: 8, name: "production-incident-20261112-diagnostic-authorization", expired: false,
  digest: archiveDigest, workflow_run: { id: 123456, head_sha: diagnosticSourceSha, repository_id: 9 } };
const branch = { name: "main", protected: true, commit: { sha: diagnosticSourceSha } };
const publicationArchive = new JSZip();
const ref = `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${imagePublication.image}`;
publicationArchive.file("production-green-backend-image.jsonl", `${JSON.stringify({ service: "backend", image_tag: `${diagnosticSourceSha}-backend-only`, image_ref: ref })}\n`);
publicationArchive.file("backend-image-inspect.json", JSON.stringify([{ Config: { Labels: { "org.opencontainers.image.revision": diagnosticSourceSha }, Env: [`GIT_SHA=${diagnosticSourceSha}`, `RELEASE_GIT_SHA=${diagnosticSourceSha}`] } }]));
publicationArchive.file("backend.provenance.json", JSON.stringify({ subject: { imageRef: ref }, invocation: { sha: diagnosticSourceSha, runId: 987654 } }));
const publicationBytes = await publicationArchive.generateAsync({ type: "nodebuffer" });
imagePublication.artifactDigest = `sha256:${createHash("sha256").update(publicationBytes).digest("hex")}`;
const signedValue = createIncidentDiagnosticAuthorization({ diagnosticSourceSha, image: imagePublication.image, imagePublication,
  executionId: value.executionId, approvalEvidence, issuedAt: now.toISOString() });
archive.file("authorization.json", JSON.stringify(signedValue));
const signedBytes = await archive.generateAsync({ type: "nodebuffer" });
const signedArtifact = { ...artifact, digest: `sha256:${createHash("sha256").update(signedBytes).digest("hex")}` };
const publicationWorkflow = { ...workflow, id: 987654, path: ".github/workflows/production-green-backend-image-publish.yml" };
const publicationArtifact = { id: 7, name: "production-green-backend-image-evidence", expired: false,
  digest: imagePublication.artifactDigest, workflow_run: { id: 987654, head_sha: diagnosticSourceSha, repository_id: 9 } };
const run = (_program, args) => {
  const uri = args[1];
  if (uri.endsWith("/branches/main")) return JSON.stringify(branch);
  if (uri.endsWith("/zip")) return uri.includes("/7/") ? publicationBytes : signedBytes;
  if (uri.endsWith("/artifacts")) return JSON.stringify([{ artifacts: uri.includes("/987654/") ? [publicationArtifact] : [signedArtifact] }]);
  return JSON.stringify(uri.endsWith("/987654") ? publicationWorkflow : workflow);
};
assert.deepEqual((await resolveIncidentDiagnosticAuthorization({ runId: "123456", sourceSha: diagnosticSourceSha, run, now })).authorization, signedValue);
await assert.rejects(resolveIncidentDiagnosticAuthorization({ runId: "123456", sourceSha: diagnosticSourceSha, run: (program, args) =>
  args[1].endsWith("/zip") ? signedBytes : JSON.stringify(args[1].endsWith("/branches/main") ? branch
    : args[1].endsWith("/artifacts") ? [{ artifacts: [{ ...signedArtifact, digest: `sha256:${"0".repeat(64)}` }] }] : workflow), now }), /archive digest/);
console.log("incident diagnostic independent authorization contract passed");
