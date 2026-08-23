#!/usr/bin/env node
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { BACKEND_HEALTH_RECOVERY } from "./production-backend-health-recovery-contract.mjs";
import { assertImageAuthorization, authorizedBackendDigest } from "./production-cutover-control-plane.mjs";
import { readStageBPrivateFileBytes } from "./stage-b-artifact-contract.mjs";
import { readFreshProtectedMainIdentity } from "./stage-b-deployment-identity.mjs";

const REPOSITORY = "T-ej2003/genuine-scan-main";
const REPOSITORY_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const WORKFLOW = "release-gate.yml";
const MODE = "backend-health-recovery";
const MODE_KIND = BACKEND_HEALTH_RECOVERY.kind;
const SHA = /^[a-f0-9]{40}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const TASK_DEFINITION = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-backend:[1-9][0-9]*$/;
const APPROVAL_FIELDS = ["ticket", "approvedBy", "approverRole", "reason", "verificationRef", "sourceSha", "currentTaskDefinitionArn", "recoveryImageDigest"];

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

function assertBindings({ sourceSha, currentTaskDefinitionArn, recoveryImageDigest, service, releaseMode, imageAuthorization, imageValidation, approval }) {
  if (!SHA.test(sourceSha || "")) throw new Error("Recovery source SHA is invalid.");
  if (!TASK_DEFINITION.test(currentTaskDefinitionArn || "")) throw new Error("Recovery task definition is invalid.");
  if (!DIGEST.test(recoveryImageDigest || "")) throw new Error("Recovery image digest is invalid.");
  if (service !== BACKEND_HEALTH_RECOVERY.service) throw new Error("Recovery service differs from the protected contract.");
  if (releaseMode !== MODE_KIND) throw new Error("Recovery mode differs from the protected contract.");
  assertImageAuthorization(imageAuthorization, sourceSha, imageValidation);
  if (authorizedBackendDigest(imageAuthorization) !== recoveryImageDigest) throw new Error("Recovery image authorization is bound to a different digest.");
  if (!approval || JSON.stringify(Object.keys(approval).sort()) !== JSON.stringify([...APPROVAL_FIELDS].sort())
    || approval.sourceSha !== sourceSha || approval.currentTaskDefinitionArn !== currentTaskDefinitionArn
    || approval.recoveryImageDigest !== recoveryImageDigest) throw new Error("Recovery approval is bound to a different recovery.");
}

export function buildBackendHealthRecoveryDispatch({ sourceSha, currentTaskDefinitionArn, recoveryImageDigest, service, releaseMode, imageAuthorizationBytes, imageValidation, approvalBytes } = {}) {
  const image = canonicalWorkflowJsonInput(imageAuthorizationBytes, "Recovery image authorization");
  const approval = canonicalWorkflowJsonInput(approvalBytes, "Recovery approval");
  assertBindings({ sourceSha, currentTaskDefinitionArn, recoveryImageDigest, service, releaseMode, imageAuthorization: JSON.parse(image.value), imageValidation, approval: JSON.parse(approval.value) });
  const args = ["workflow", "run", WORKFLOW, "--repo", REPOSITORY, "--ref", "main",
    "-f", "git_ref=main", "-f", `target_sha=${sourceSha}`, "-f", `release_mode=${MODE}`,
    "-f", `backend_recovery_current_task_definition_arn=${currentTaskDefinitionArn}`,
    "-f", `backend_recovery_image_digest=${recoveryImageDigest}`,
    "-f", `backend_recovery_image_authorization_json=${image.value}`,
    "-f", `backend_recovery_image_authorization_sha256=${image.sha256}`,
    "-f", `backend_recovery_approval_json=${approval.value}`,
    "-f", `backend_recovery_approval_sha256=${approval.sha256}`];
  return Object.freeze({ args: Object.freeze(args), image, approval });
}

function options(argv) {
  const allowed = new Set(["--source-sha", "--current-task-definition", "--recovery-image-digest", "--service", "--release-mode", "--image-authorization", "--approval"]);
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
  const dispatch = buildBackendHealthRecoveryDispatch({ sourceSha: values["source-sha"], currentTaskDefinitionArn: values["current-task-definition"], recoveryImageDigest: values["recovery-image-digest"], service: values.service, releaseMode: values["release-mode"], imageAuthorizationBytes, imageValidation, approvalBytes });
  run("gh", dispatch.args, { stdio: "inherit" });
  return { sourceSha: values["source-sha"], imageTransportSha256: dispatch.image.sha256, approvalTransportSha256: dispatch.approval.sha256, dispatchCount: 1 };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { process.stdout.write(`${JSON.stringify(runCli())}\n`); }
  catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
