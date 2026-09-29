import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { PRODUCTION_ENVIRONMENT_APPROVAL, assertProductionEnvironmentActualReviewer, assertProductionEnvironmentApprovalEvidence } from "./production-github-environment-approval.mjs";
import { resolveReconcilerStateReconciliationAuthorization } from "./reconcile-production-initial-activation-reconciler-state.mjs";
import { createProductionGithubCommandRunner } from "./production-credential-source-contract.mjs";
import { assertStageBArtifactPath, ensureStageBPrivateDirectory, writeStageBPrivateFileAtomic } from "./stage-b-artifact-contract.mjs";
import { policySha256, signerLedgerAbsence, signerLedgerBucketPolicyPredecessor, signerLedgerBucketPolicySuccessor } from "./production-signer-ledger-absence-policy.mjs";

export const SIGNER_LEDGER_ABSENCE_OPERATION = "PRODUCTION_SIGNER_LEDGER_ABSENCE_READ";
export const SIGNER_LEDGER_ABSENCE_WORKFLOW = ".github/workflows/authorize-production-signer-ledger-absence.yml";
export const SIGNER_LEDGER_ABSENCE_ARTIFACT = "production-signer-ledger-absence-authorization";
const sha = value => crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
const fields = ["schemaVersion", "kind", "repository", "sourceSha", "account", "region", "purpose", "bucket", "key", "principal", "predecessorSha256", "successorSha256", "approval", "approvalSha256", "authorizationSha256"];

export function createSignerLedgerAbsenceAuthorization({ sourceSha, approval } = {}) {
  const body = {
    schemaVersion: 1, kind: "MSCQR_SIGNER_LEDGER_ABSENCE_AUTHORIZATION", repository: PRODUCTION_ENVIRONMENT_APPROVAL.repository,
    sourceSha, account: "368992683803", region: "eu-west-2", purpose: SIGNER_LEDGER_ABSENCE_OPERATION,
    bucket: signerLedgerAbsence.bucket, key: signerLedgerAbsence.key, principal: signerLedgerAbsence.principal,
    predecessorSha256: policySha256(signerLedgerBucketPolicyPredecessor()), successorSha256: policySha256(signerLedgerBucketPolicySuccessor()),
    approval, approvalSha256: approval?.evidenceSha256,
  };
  const authorization = { ...body, authorizationSha256: sha(body) };
  return assertSignerLedgerAbsenceAuthorization(authorization, { sourceSha });
}

export function assertSignerLedgerAbsenceAuthorization(value, { sourceSha, now = new Date() } = {}) {
  assert(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), [...fields].sort(), "Signer ledger absence authorization fields differ");
  const { authorizationSha256, ...body } = value;
  assert.equal(value.schemaVersion, 1); assert.equal(value.kind, "MSCQR_SIGNER_LEDGER_ABSENCE_AUTHORIZATION");
  assert.equal(value.repository, PRODUCTION_ENVIRONMENT_APPROVAL.repository);
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/); assert.equal(value.sourceSha, sourceSha);
  assert.equal(value.account, "368992683803"); assert.equal(value.region, "eu-west-2");
  assert.equal(value.purpose, SIGNER_LEDGER_ABSENCE_OPERATION);
  assert.equal(value.bucket, signerLedgerAbsence.bucket); assert.equal(value.key, signerLedgerAbsence.key);
  assert.equal(value.principal, signerLedgerAbsence.principal);
  assert.equal(value.predecessorSha256, policySha256(signerLedgerBucketPolicyPredecessor()));
  assert.equal(value.successorSha256, policySha256(signerLedgerBucketPolicySuccessor()));
  assert.equal(value.approvalSha256, value.approval?.evidenceSha256);
  assertProductionEnvironmentApprovalEvidence(value.approval, {
    sourceSha, repository: value.repository, environment: "production",
    workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.signerLedgerAbsenceWorkflowRef,
    eventName: "workflow_dispatch", workflowRunId: value.approval?.workflowRunId,
    workflowRunAttempt: value.approval?.workflowRunAttempt,
    executionActor: value.approval?.executionActor, githubActions: "true", now,
  });
  assertProductionEnvironmentActualReviewer(value.approval, { sourceSha, repository: value.repository, executionActor: value.approval.executionActor });
  assert.equal(authorizationSha256, sha(body), "Signer ledger absence authorization digest differs");
  return Object.freeze(value);
}

export function resolveSignerLedgerAbsenceAuthorization({ workflowRunId, workflowRunAttempt = "1", sourceSha, githubRun } = {}) {
  const reader = githubRun || createProductionGithubCommandRunner();
  let workflow;
  const authenticatedRun = (command, args, options) => {
    const result = reader(command, args, options);
    if (command === "gh" && args?.[1] === `repos/${PRODUCTION_ENVIRONMENT_APPROVAL.repository}/actions/runs/${workflowRunId}`) workflow = JSON.parse(result);
    return result;
  };
  const authorization = resolveReconcilerStateReconciliationAuthorization({ workflowRunId: String(workflowRunId), workflowRunAttempt: String(workflowRunAttempt), sourceSha,
    preparation: null, workflowPath: SIGNER_LEDGER_ABSENCE_WORKFLOW, artifactName: SIGNER_LEDGER_ABSENCE_ARTIFACT,
    filename: "authorization.json", assertAuthorization: (value, _preparation, options) => assertSignerLedgerAbsenceAuthorization(value, options), githubRun: authenticatedRun });
  assert.equal(authorization.approval.workflowRunId, String(workflowRunId));
  assert.equal(authorization.approval.workflowRunAttempt, String(workflowRunAttempt));
  assert.equal(authorization.approval.executionActor, workflow?.actor?.login, "Signer ledger approval actor differs from workflow execution actor");
  return authorization;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  const args = process.argv.slice(2), required = name => { const index = args.indexOf(name); const value = index < 0 ? null : args[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required`); return value; };
  const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
  const output = assertStageBArtifactPath({ artifactPath: path.resolve(required("--output")), repositoryRoot, label: "Signer ledger absence authorization", allowExisting: false });
  const approval = JSON.parse(fs.readFileSync(required("--approval"), "utf8"));
  const authorization = createSignerLedgerAbsenceAuthorization({ sourceSha: required("--source-sha"), approval });
  ensureStageBPrivateDirectory({ directory: path.dirname(output), repositoryRoot, label: "Signer ledger absence authorization directory" });
  writeStageBPrivateFileAtomic({ filePath: output, bytes: Buffer.from(`${JSON.stringify(authorization, null, 2)}\n`), repositoryRoot, label: "Signer ledger absence authorization" });
  process.stdout.write(`${JSON.stringify({ authorizationSha256: authorization.authorizationSha256 })}\n`);
}
