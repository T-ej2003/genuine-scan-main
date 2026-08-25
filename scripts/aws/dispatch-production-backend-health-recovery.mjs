#!/usr/bin/env node
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { BACKEND_HEALTH_RECOVERY } from "./production-backend-health-recovery-contract.mjs";
import { assertImageAuthorization, authorizedBackendDigest } from "./production-cutover-control-plane.mjs";
import { readStageBPrivateFileBytes } from "./stage-b-artifact-contract.mjs";
import { readFreshProtectedMainIdentity } from "./stage-b-deployment-identity.mjs";
import { assertFailedRecoveryEvidenceReference } from "./production-backend-failed-recovery-evidence-reference.mjs";

const REPOSITORY = "T-ej2003/genuine-scan-main";
const REPOSITORY_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const WORKFLOW = "release-gate.yml";
const MODE = "backend-health-recovery";
const MODE_KIND = BACKEND_HEALTH_RECOVERY.kind;
const SHA = /^[a-f0-9]{40}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const TASK_DEFINITION = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-backend:[1-9][0-9]*$/;
const ROLLBACK_DEPLOYMENT = /^arn:aws:ecs:eu-west-2:368992683803:service-deployment\/mscqr-prod-euw2-main\/mscqr-backend-servi-euw2\/[A-Za-z0-9_-]+$/;
const APPROVAL_FIELDS = ["ticket", "approvedBy", "approverRole", "reason", "verificationRef", "sourceSha", "currentTaskDefinitionArn", "recoveryImageDigest", "runtimeConsumabilitySha256"];
const ROLLBACK_APPROVAL_FIELDS = ["rollbackDeploymentArn", "rollbackTargetTaskDefinitionArn", "rollbackTargetDigest"];
const FAILED_HISTORY_APPROVAL_FIELD = "failedRecoveryEvidenceSha256";
const FAILED_HISTORY_REFERENCE_APPROVAL_FIELD = "failedRecoveryEvidenceReferenceSha256";
const BUNDLE_KIND = "BACKEND_HEALTH_RECOVERY_DISPATCH_BUNDLE";
const COMPONENTS = ["imageAuthorization", "approval", "runtimeConsumability", "failedRecoveryEvidenceReference"];
export const WORKFLOW_DISPATCH_PLATFORM_LIMIT = 65_535;
export const WORKFLOW_DISPATCH_INTERNAL_BUDGET = 60_000;

const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");

export function canonicalWorkflowJsonInput(bytes, label = "Workflow JSON input") {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0) throw new Error(`${label} is empty.`);
  let value;
  try { value = JSON.stringify(JSON.parse(bytes)); }
  catch (error) { throw new Error(`${label} is not valid JSON: ${error.message}`); }
  if (JSON.stringify(JSON.parse(value)) !== value) throw new Error(`${label} does not round-trip under the canonical workflow transport.`);
  const transportBytes = Buffer.from(value);
  return Object.freeze({ value, sha256: sha256(transportBytes), bytes: transportBytes });
}

export function parseBackendHealthRecoveryDispatchBundle(bytes, suppliedSha256, expected = {}) {
  if (!Buffer.isBuffer(bytes) || sha256(bytes) !== suppliedSha256) throw new Error("Recovery dispatch bundle bytes do not match their SHA-256.");
  const transport = canonicalWorkflowJsonInput(bytes, "Recovery dispatch bundle");
  if (!transport.bytes.equals(bytes)) throw new Error("Recovery dispatch bundle is not canonical transport JSON.");
  const value = JSON.parse(transport.value);
  if (value?.schemaVersion !== 3 || value.kind !== BUNDLE_KIND
    || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(["components", "currentTaskDefinitionArn", "kind", "recoveryImageDigest", "releaseMode", "schemaVersion", "service", "sourceSha"])
    || JSON.stringify(Object.keys(value.components || {}).sort()) !== JSON.stringify([...COMPONENTS].sort())) throw new Error("Recovery dispatch bundle schema is invalid.");
  for (const [field, expectedValue] of Object.entries(expected)) if (expectedValue != null && value[field] !== expectedValue) throw new Error(`Recovery dispatch bundle ${field} binding differs from the workflow transaction.`);
  const components = {};
  for (const name of COMPONENTS) {
    const component = value.components[name];
    if (!component || JSON.stringify(Object.keys(component).sort()) !== JSON.stringify(["json", "sha256"]) || typeof component.json !== "string"
      || !/^[a-f0-9]{64}$/.test(component.sha256 || "") || sha256(Buffer.from(component.json)) !== component.sha256
      || canonicalWorkflowJsonInput(Buffer.from(component.json), `Recovery ${name}`).value !== component.json) throw new Error(`Recovery dispatch bundle ${name} component is invalid.`);
    components[name] = Object.freeze({ value: component.json, bytes: Buffer.from(component.json), sha256: component.sha256 });
  }
  return Object.freeze({ value: Object.freeze(value), components: Object.freeze(components), sha256: suppliedSha256, bytes });
}

function assertBindings({ sourceSha, currentTaskDefinitionArn, recoveryImageDigest, service, releaseMode, imageAuthorization, imageValidation, approval, runtimeConsumability, failedRecoveryEvidenceReference }) {
  if (!SHA.test(sourceSha || "")) throw new Error("Recovery source SHA is invalid.");
  if (!TASK_DEFINITION.test(currentTaskDefinitionArn || "")) throw new Error("Recovery task definition is invalid.");
  if (!DIGEST.test(recoveryImageDigest || "")) throw new Error("Recovery image digest is invalid.");
  if (service !== BACKEND_HEALTH_RECOVERY.service) throw new Error("Recovery service differs from the protected contract.");
  if (releaseMode !== MODE_KIND) throw new Error("Recovery mode differs from the protected contract.");
  assertImageAuthorization(imageAuthorization, sourceSha, imageValidation);
  if (authorizedBackendDigest(imageAuthorization) !== recoveryImageDigest) throw new Error("Recovery image authorization is bound to a different digest.");
  const fields = JSON.stringify(Object.keys(approval || {}).sort());
  const historyFields = [FAILED_HISTORY_APPROVAL_FIELD, FAILED_HISTORY_REFERENCE_APPROVAL_FIELD];
  const allowedFields = [APPROVAL_FIELDS, [...APPROVAL_FIELDS, ...ROLLBACK_APPROVAL_FIELDS], [...APPROVAL_FIELDS, ...historyFields], [...APPROVAL_FIELDS, ...ROLLBACK_APPROVAL_FIELDS, ...historyFields]].map((value) => JSON.stringify([...value].sort()));
  if (!approval || !allowedFields.includes(fields)
    || approval.sourceSha !== sourceSha || approval.currentTaskDefinitionArn !== currentTaskDefinitionArn
    || approval.recoveryImageDigest !== recoveryImageDigest || approval.runtimeConsumabilitySha256 !== runtimeConsumability?.evidence?.evidenceSha256
    || !/^[a-f0-9]{64}$/.test(approval.runtimeConsumabilitySha256 || "")) throw new Error("Recovery approval is bound to a different recovery.");
  assertFailedRecoveryEvidenceReference(failedRecoveryEvidenceReference, { sourceSha });
  if (failedRecoveryEvidenceReference === null ? historyFields.some((field) => field in approval)
    : approval[FAILED_HISTORY_APPROVAL_FIELD] !== failedRecoveryEvidenceReference.evidenceEnvelopeSha256 || approval[FAILED_HISTORY_REFERENCE_APPROVAL_FIELD] !== failedRecoveryEvidenceReference.referenceSha256) throw new Error("Recovery approval is not bound to authenticated failed-recovery evidence.");
  if (ROLLBACK_APPROVAL_FIELDS.some((field) => field in approval)
    && (!ROLLBACK_DEPLOYMENT.test(approval.rollbackDeploymentArn || "") || approval.rollbackTargetTaskDefinitionArn !== currentTaskDefinitionArn
      || !DIGEST.test(approval.rollbackTargetDigest || ""))) throw new Error("Recovery rollback approval identity is invalid.");
}

export function measureWorkflowDispatchInputs(inputs) {
  const serialized = JSON.stringify(inputs);
  const characters = Array.from(serialized).length; const bytes = Buffer.byteLength(serialized);
  if (characters > WORKFLOW_DISPATCH_INTERNAL_BUDGET || bytes > WORKFLOW_DISPATCH_INTERNAL_BUDGET) throw new Error(`Recovery workflow_dispatch payload exceeds the ${WORKFLOW_DISPATCH_INTERNAL_BUDGET}-character internal budget.`);
  return Object.freeze({ characters, bytes, serialized });
}

export function buildBackendHealthRecoveryDispatch({ sourceSha, currentTaskDefinitionArn, recoveryImageDigest, service, releaseMode, imageAuthorizationBytes, imageValidation, approvalBytes, runtimeConsumabilityBytes, failedRecoveryEvidenceReferenceBytes } = {}) {
  const image = canonicalWorkflowJsonInput(imageAuthorizationBytes, "Recovery image authorization");
  const approval = canonicalWorkflowJsonInput(approvalBytes, "Recovery approval");
  const runtime = canonicalWorkflowJsonInput(runtimeConsumabilityBytes, "Recovery runtime consumability evidence");
  const failed = canonicalWorkflowJsonInput(failedRecoveryEvidenceReferenceBytes, "Immutable failed recovery evidence reference");
  assertBindings({ sourceSha, currentTaskDefinitionArn, recoveryImageDigest, service, releaseMode, imageAuthorization: JSON.parse(image.value), imageValidation, approval: JSON.parse(approval.value), runtimeConsumability: JSON.parse(runtime.value), failedRecoveryEvidenceReference: JSON.parse(failed.value) });
  const bundleBody = { schemaVersion: 3, kind: BUNDLE_KIND, sourceSha, currentTaskDefinitionArn, recoveryImageDigest, service, releaseMode, components: Object.fromEntries([["imageAuthorization", image], ["approval", approval], ["runtimeConsumability", runtime], ["failedRecoveryEvidenceReference", failed]].map(([name, component]) => [name, { json: component.value, sha256: component.sha256 }])) };
  const bundle = canonicalWorkflowJsonInput(Buffer.from(JSON.stringify(bundleBody)), "Recovery dispatch bundle");
  parseBackendHealthRecoveryDispatchBundle(bundle.bytes, bundle.sha256, { sourceSha, currentTaskDefinitionArn, recoveryImageDigest, service, releaseMode });
  const inputs = { git_ref: "main", target_sha: sourceSha, release_mode: MODE, backend_recovery_current_task_definition_arn: currentTaskDefinitionArn, backend_recovery_image_digest: recoveryImageDigest, backend_recovery_evidence_bundle_json: bundle.value, backend_recovery_evidence_bundle_sha256: bundle.sha256 };
  const payload = measureWorkflowDispatchInputs(inputs);
  const args = ["workflow", "run", WORKFLOW, "--repo", REPOSITORY, "--ref", "main", ...Object.entries(inputs).flatMap(([name, value]) => ["-f", `${name}=${value}`])];
  return Object.freeze({ args: Object.freeze(args), image, approval, runtime, failed, bundle, payload });
}

function options(argv) {
  const allowed = new Set(["--source-sha", "--current-task-definition", "--recovery-image-digest", "--service", "--release-mode", "--image-authorization", "--approval", "--runtime-consumability", "--failed-recovery-evidence-reference"]);
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index]; const value = argv[index + 1];
    if (!allowed.has(key) || !value || value.startsWith("--") || values.has(key)) throw new Error(`Invalid or duplicate recovery dispatch option: ${key || "<missing>"}`);
    values.set(key, value);
  }
  if (values.size !== allowed.size) throw new Error("Recovery dispatch requires every protected binding exactly once.");
  return Object.fromEntries([...values].map(([key, value]) => [key.slice(2), value]));
}

export function runCli(argv = process.argv.slice(2), { run = execFileSync, protectedMain = readFreshProtectedMainIdentity, imageValidation } = {}) {
  const values = options(argv);
  protectedMain({ cwd: REPOSITORY_ROOT, expectedSourceSha: values["source-sha"] });
  const imageAuthorizationBytes = readStageBPrivateFileBytes({ filePath: values["image-authorization"], repositoryRoot: REPOSITORY_ROOT, label: "Recovery image authorization" }).bytes;
  const approvalBytes = readStageBPrivateFileBytes({ filePath: values.approval, repositoryRoot: REPOSITORY_ROOT, label: "Recovery approval" }).bytes;
  const runtimeConsumabilityBytes = readStageBPrivateFileBytes({ filePath: values["runtime-consumability"], repositoryRoot: REPOSITORY_ROOT, label: "Recovery runtime consumability evidence" }).bytes;
  const failedRecoveryEvidenceReferenceBytes = readStageBPrivateFileBytes({ filePath: values["failed-recovery-evidence-reference"], repositoryRoot: REPOSITORY_ROOT, label: "Immutable failed recovery evidence reference" }).bytes;
  const dispatch = buildBackendHealthRecoveryDispatch({ sourceSha: values["source-sha"], currentTaskDefinitionArn: values["current-task-definition"], recoveryImageDigest: values["recovery-image-digest"], service: values.service, releaseMode: values["release-mode"], imageAuthorizationBytes, imageValidation, approvalBytes, runtimeConsumabilityBytes, failedRecoveryEvidenceReferenceBytes });
  run("gh", dispatch.args, { stdio: "inherit" });
  return { sourceSha: values["source-sha"], bundleTransportSha256: dispatch.bundle.sha256, imageTransportSha256: dispatch.image.sha256, approvalTransportSha256: dispatch.approval.sha256, runtimeTransportSha256: dispatch.runtime.sha256, failedRevisionReferenceTransportSha256: dispatch.failed.sha256, workflowDispatchPayloadCharacters: dispatch.payload.characters, dispatchCount: 1 };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { process.stdout.write(`${JSON.stringify(runCli())}\n`); }
  catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
