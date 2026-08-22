#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { assertImageAuthorization, authorizedBackendDigest } from "./production-cutover-control-plane.mjs";
import { createProductionCommandRunner } from "./production-cutover-production-adapters.mjs";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";
import { NORMAL_ACTIVATION, NORMAL_CANDIDATE_ARN, assertNormalActivationPolicy, assertNormalActivationPolicyDeltaOnly, buildNormalActivationPolicy, canonicalNormalActivationValue } from "./production-normal-backend-activation-policy.mjs";
import { stageBApprovalIdForReleaseSha } from "./production-green-stage-b-contract.mjs";
import { readBoundStageBPrivateJson } from "./stage-b-artifact-contract.mjs";
import { readStageBProtectedMainCheckout } from "./stage-b-deployment-identity.mjs";

export { NORMAL_ACTIVATION, assertNormalActivationPolicy, buildNormalActivationPolicy } from "./production-normal-backend-activation-policy.mjs";

const SHA = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const canonical = canonicalNormalActivationValue;

function backendResource(state) {
  const candidates = (state?.resources || []).filter(({ mode, type, name }) => mode === "managed" && type === "aws_ecs_task_definition" && name === "candidate")
    .flatMap(({ instances = [] }) => instances)
    .filter(({ index_key: key }) => key === "backend");
  if (candidates.length !== 1) throw new Error("Stage-B state must contain exactly one managed backend candidate instance.");
  return candidates[0].attributes;
}

export function deriveNormalBackendCandidate({ state, stateBytes = Buffer.from(JSON.stringify(state)), sourceSha, imageAuthorization, validateImageAuthorization = assertImageAuthorization } = {}) {
  if (!SHA.test(sourceSha || "")) throw new Error("Normal activation requires the exact protected source SHA.");
  validateImageAuthorization(imageAuthorization, sourceSha);
  if (state?.version !== 4 || state.lineage !== NORMAL_ACTIVATION.lineage || !Number.isInteger(state.serial) || state.serial < NORMAL_ACTIVATION.minimumSerial) throw new Error("Stage-B state identity is outside the production activation contract.");
  const attributes = backendResource(state);
  const targetArn = attributes?.arn;
  if (!NORMAL_CANDIDATE_ARN.test(targetArn || "") || attributes.family !== NORMAL_ACTIVATION.family) throw new Error("Stage-B backend candidate ARN/family is invalid.");
  if (state.outputs?.task_definition_arns?.value?.backend !== targetArn) throw new Error("Stage-B backend candidate output does not match the managed state resource.");
  const containers = JSON.parse(attributes.container_definitions || "null");
  const selected = Array.isArray(containers) ? containers.filter(({ name }) => name === NORMAL_ACTIVATION.container) : [];
  if (selected.length !== 1) throw new Error("Stage-B backend candidate must contain exactly one backend container.");
  const image = selected[0].image;
  const digest = /@(sha256:[a-f0-9]{64})$/.exec(image || "")?.[1];
  if (!digest || digest !== authorizedBackendDigest(imageAuthorization) || state.outputs?.bound_images?.value?.backend !== image) throw new Error("Stage-B backend candidate image is not bound to the current image authorization and state output.");
  const environment = new Map((selected[0].environment || []).map(({ name, value }) => [name, value]));
  if (environment.get("RELEASE_GIT_SHA") !== sourceSha || (environment.has("GIT_SHA") && environment.get("GIT_SHA") !== sourceSha)) throw new Error("Stage-B backend candidate source metadata is stale or mismatched.");
  const tags = attributes.tags_all || attributes.tags || {};
  if (tags.Environment !== "production" || tags.ManagedBy !== "Terraform" || tags.Component !== "full-rls-green-stage-b" || tags.MSCQRExecTarget !== "production-backend") throw new Error("Stage-B backend candidate tags are outside the reviewed contract.");
  return Object.freeze({ sourceSha, stateLineage: state.lineage, stateSerial: state.serial, stateSha256: sha256(stateBytes), targetArn, family: NORMAL_ACTIVATION.family, image, digest });
}

const parseJson = (run, args) => JSON.parse(run([...args, "--output", "json", "--no-cli-pager"]));
function readLivePolicy(run) {
  const metadata = parseJson(run, ["iam", "get-policy", "--policy-arn", NORMAL_ACTIVATION.policyArn]).Policy;
  if (!/^v[1-9][0-9]*$/.test(metadata?.DefaultVersionId || "")) throw new Error("FinalApplyWrite live policy has no valid default version.");
  const version = parseJson(run, ["iam", "get-policy-version", "--policy-arn", NORMAL_ACTIVATION.policyArn, "--version-id", metadata.DefaultVersionId]).PolicyVersion;
  return { document: normalizeIamPolicyDocument(version?.Document, "live FinalApplyWrite policy"), defaultVersionId: metadata.DefaultVersionId };
}

function readLiveState(run) {
  const bytes = Buffer.from(run(["s3", "cp", NORMAL_ACTIVATION.stateUrl, "-"]));
  return { bytes, state: JSON.parse(bytes) };
}

function assertReleaseReceipt(receipt, { sourceSha, imageAuthorization }) {
  const digest = authorizedBackendDigest(imageAuthorization);
  const copy = structuredClone(receipt);
  const claimed = copy?.receiptBundleSha256;
  delete copy.receiptBundleSha256;
  if (receipt?.schemaVersion !== 2 || receipt.environment !== "production" || receipt.releaseSha !== sourceSha || receipt.images?.backend !== `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${digest}` || receipt.approvalId !== stageBApprovalIdForReleaseSha(sourceSha) || !SHA256.test(claimed || "") || claimed !== sha256(`${JSON.stringify(copy)}\n`)) throw new Error("Production RLS release receipt is not bound to the normal backend activation.");
  return receipt.approvalId;
}

function assertService(service, expectedCurrentArn, targetArn) {
  if (service?.serviceArn !== NORMAL_ACTIVATION.serviceArn || service.clusterArn !== NORMAL_ACTIVATION.clusterArn || service.status !== "ACTIVE" || service.taskDefinition !== expectedCurrentArn || !Number.isInteger(service.desiredCount) || service.desiredCount < 1) throw new Error("Production backend service identity/current revision is invalid.");
  const deployments = service.deployments || [];
  if (deployments.length !== 1 || deployments[0]?.status !== "PRIMARY" || deployments[0]?.taskDefinition !== expectedCurrentArn || deployments[0]?.pendingCount !== 0 || deployments[0]?.runningCount !== service.desiredCount || (deployments[0]?.rolloutState && deployments[0].rolloutState !== "COMPLETED")) throw new Error("Production backend service changed or is not stable before activation.");
  return true;
}

function assertTaskDefinition(response, candidate) {
  const task = response?.taskDefinition;
  if (task?.taskDefinitionArn !== candidate.targetArn || task.family !== candidate.family || task.status !== "ACTIVE") throw new Error("Live backend candidate does not match authenticated Stage-B state.");
  const selected = (task.containerDefinitions || []).filter(({ name }) => name === NORMAL_ACTIVATION.container);
  if (selected.length !== 1 || selected[0].image !== candidate.image) throw new Error("Live backend candidate image differs from authenticated Stage-B state.");
  return true;
}

export function collectNormalActivationLiveEvidence({ run, sourceSha, imageAuthorization, expectedCurrentTaskDefinitionArn, validateImageAuthorization } = {}) {
  if (typeof run !== "function") throw new Error("Authenticated AWS command runner is required.");
  const caller = parseJson(run, ["sts", "get-caller-identity"]);
  if (caller.Account !== NORMAL_ACTIVATION.account || !new RegExp(`^arn:aws:sts::${NORMAL_ACTIVATION.account}:assumed-role/mscqr-production-release-deployer/[^/]+$`).test(caller.Arn || "")) throw new Error("Normal activation requires the canonical release-deployer session.");
  const liveState = readLiveState(run);
  const candidate = deriveNormalBackendCandidate({ state: liveState.state, stateBytes: liveState.bytes, sourceSha, imageAuthorization, ...(validateImageAuthorization ? { validateImageAuthorization } : {}) });
  const policy = readLivePolicy(run);
  assertNormalActivationPolicy(policy.document, candidate.targetArn);
  assertTaskDefinition(parseJson(run, ["ecs", "describe-task-definition", "--task-definition", candidate.targetArn, "--include", "TAGS"]), candidate);
  const service = parseJson(run, ["ecs", "describe-services", "--cluster", NORMAL_ACTIVATION.cluster, "--services", NORMAL_ACTIVATION.service]).services?.[0];
  const current = expectedCurrentTaskDefinitionArn || service?.taskDefinition;
  assertService(service, current, candidate.targetArn);
  return Object.freeze({ schemaVersion: 1, releaseMode: "normal", ...candidate, clusterArn: NORMAL_ACTIVATION.clusterArn, serviceArn: NORMAL_ACTIVATION.serviceArn, expectedCurrentTaskDefinitionArn: current, policyArn: NORMAL_ACTIVATION.policyArn, policyVersionId: policy.defaultVersionId, livePolicySha256: sha256(canonical(policy.document)) });
}

export function assertNormalActivationBinding(binding, expected) {
  if (canonical(binding) !== canonical(expected)) throw new Error("Normal activation binding is stale, modified, or replayed across live state.");
  return true;
}

export function convergeNormalActivationPolicy({ run, sourceSha } = {}) {
  if (typeof run !== "function" || !SHA.test(sourceSha || "")) throw new Error("Governed normal activation convergence inputs are invalid.");
  const caller = parseJson(run, ["sts", "get-caller-identity"]);
  if (caller.Account !== NORMAL_ACTIVATION.account || caller.Arn !== NORMAL_ACTIVATION.administratorArn) throw new Error("Normal activation IAM convergence requires the governed root administrator identity.");
  const liveState = readLiveState(run);
  const state = liveState.state;
  const attributes = backendResource(state);
  const targetArn = attributes?.arn;
  const containers = JSON.parse(attributes?.container_definitions || "null");
  const releaseSha = new Map((containers?.find(({ name }) => name === NORMAL_ACTIVATION.container)?.environment || []).map(({ name, value }) => [name, value])).get("RELEASE_GIT_SHA");
  if (state.lineage !== NORMAL_ACTIVATION.lineage || !Number.isInteger(state.serial) || state.serial < NORMAL_ACTIVATION.minimumSerial || state.outputs?.task_definition_arns?.value?.backend !== targetArn || releaseSha !== sourceSha || !NORMAL_CANDIDATE_ARN.test(targetArn || "")) throw new Error("Normal activation IAM convergence requires the current-source authenticated Stage-B candidate state.");
  const expected = buildNormalActivationPolicy(targetArn);
  const before = readLivePolicy(run);
  assertNormalActivationPolicyDeltaOnly(before.document);
  let iamWrites = 0;
  if (canonical(before.document) !== canonical(expected)) {
    const versions = parseJson(run, ["iam", "list-policy-versions", "--policy-arn", NORMAL_ACTIVATION.policyArn]).Versions || [];
    if (versions.length >= 5) {
      const oldest = versions.filter(({ IsDefaultVersion }) => !IsDefaultVersion).sort((a, b) => Date.parse(a.CreateDate) - Date.parse(b.CreateDate))[0];
      if (!oldest?.VersionId) throw new Error("FinalApplyWrite policy version retention cannot be reconciled safely.");
      run(["iam", "delete-policy-version", "--policy-arn", NORMAL_ACTIVATION.policyArn, "--version-id", oldest.VersionId, "--no-cli-pager"]); iamWrites += 1;
    }
    run(["iam", "create-policy-version", "--policy-arn", NORMAL_ACTIVATION.policyArn, "--policy-document", JSON.stringify(expected), "--set-as-default", "--no-cli-pager"]); iamWrites += 1;
  }
  const after = readLivePolicy(run);
  assertNormalActivationPolicy(after.document, targetArn);
  const context = ["aws:RequestedRegion=string:eu-west-2", `ecs:cluster=string:${NORMAL_ACTIVATION.clusterArn}`, `ecs:task-definition=string:${targetArn}`];
  const exact = parseJson(run, ["iam", "simulate-principal-policy", "--policy-source-arn", NORMAL_ACTIVATION.roleArn, "--action-names", "ecs:UpdateService", "--resource-arns", NORMAL_ACTIVATION.serviceArn, "--context-entries", ...context]).EvaluationResults?.[0]?.EvalDecision;
  const revision = Number(NORMAL_CANDIDATE_ARN.exec(targetArn)[1]);
  for (const adjacent of [revision - 1, revision + 1].filter((value) => value > 0)) {
    const adjacentArn = targetArn.replace(/:[1-9][0-9]*$/, `:${adjacent}`);
    const decision = parseJson(run, ["iam", "simulate-principal-policy", "--policy-source-arn", NORMAL_ACTIVATION.roleArn, "--action-names", "ecs:UpdateService", "--resource-arns", NORMAL_ACTIVATION.serviceArn, "--context-entries", ...context.slice(0, 2), `ecs:task-definition=string:${adjacentArn}`]).EvaluationResults?.[0]?.EvalDecision;
    if (decision !== "implicitDeny") throw new Error("Adjacent Stage-B candidate revision is unexpectedly authorized.");
  }
  if (exact !== "allowed") throw new Error("Exact Stage-B candidate revision is not authorized after IAM convergence.");
  return Object.freeze({ status: iamWrites ? "CONVERGED" : "ALREADY_CONVERGED", sourceSha, targetArn, stateLineage: state.lineage, stateSerial: state.serial, stateSha256: sha256(liveState.bytes), policyVersionId: after.defaultVersionId, iamWrites });
}

function writePrivateJson(file, value) {
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: "wx" });
}

export function executeNormalBackendActivation({ run, runScript = execFileSync, sourceSha, imageAuthorization, releaseReceipt, binding, metadataFile, deployScript = path.resolve("scripts/aws/deploy-ecs-service.sh") } = {}) {
  assertReleaseReceipt(releaseReceipt, { sourceSha, imageAuthorization });
  const fresh = collectNormalActivationLiveEvidence({ run, sourceSha, imageAuthorization, expectedCurrentTaskDefinitionArn: binding?.expectedCurrentTaskDefinitionArn });
  assertNormalActivationBinding(binding, fresh);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-normal-activation-"));
  const bindingFile = path.join(directory, "binding.json");
  try {
    writePrivateJson(bindingFile, binding);
    runScript(deployScript, [], { cwd: process.cwd(), encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: {
      ...process.env,
      AWS_REGION: NORMAL_ACTIVATION.region,
      CLUSTER_NAME: NORMAL_ACTIVATION.cluster,
      SERVICE_NAME: NORMAL_ACTIVATION.service,
      CONTAINER_NAME: NORMAL_ACTIVATION.container,
      EXISTING_TASK_DEFINITION_ARN: binding.targetArn,
      EXPECTED_CURRENT_TASK_DEFINITION_ARN: binding.expectedCurrentTaskDefinitionArn,
      EXPECTED_FAMILY: NORMAL_ACTIVATION.family,
      EXPECTED_IMAGE_DIGEST: binding.digest,
      EXPECTED_GIT_SHA: sourceSha,
      VERSION_URL: "https://www.mscqr.com/api/health",
      WAIT_FOR_STABLE: "true",
      ENABLE_EXECUTE_COMMAND: "true",
      PROPAGATE_TAGS: "TASK_DEFINITION",
      METADATA_FILE: metadataFile,
      MSCQR_GOVERNED_ORCHESTRATOR: "1",
      MSCQR_EXISTING_TASK_DEPLOYMENT_MODE: "normal-stage-b",
      NORMAL_ACTIVATION_BINDING_FILE: bindingFile,
      NORMAL_ACTIVATION_BINDING_SHA256: sha256(fs.readFileSync(bindingFile)),
    } });
    return Object.freeze({ status: binding.expectedCurrentTaskDefinitionArn === binding.targetArn ? "ALREADY_APPLIED_EXACT_TARGET" : "APPLIED_EXACT_TARGET", targetArn: binding.targetArn });
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

function parseArgs(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index]; const value = argv[index + 1];
    if (!key?.startsWith("--") || !value || value.startsWith("--") || values.has(key)) throw new Error(`Invalid or duplicate argument: ${key || "<missing>"}`);
    values.set(key, value);
  }
  return values;
}
const required = (values, name) => { const value = values.get(name); if (!value) throw new Error(`${name} is required.`); return value; };

export function runCli(argv = process.argv.slice(2)) {
  const values = parseArgs(argv);
  const mode = required(values, "--mode");
  const sourceSha = required(values, "--source-sha");
  if (mode === "converge-policy") {
    const checkout = readStageBProtectedMainCheckout({ cwd: process.cwd() });
    if (checkout.currentHead !== sourceSha) throw new Error("Normal activation convergence must run from exact protected main.");
    const result = convergeNormalActivationPolicy({ run: createProductionCommandRunner({ profile: required(values, "--admin-profile") }), sourceSha });
    process.stdout.write(`${JSON.stringify(result)}\n`);
    return result;
  }
  const imageAuthorization = readBoundStageBPrivateJson({ filePath: required(values, "--image-authorization"), expectedSha256: required(values, "--image-authorization-sha256"), label: "Normal release image authorization" });
  const run = createProductionCommandRunner();
  if (mode === "prepare") {
    const binding = collectNormalActivationLiveEvidence({ run, sourceSha, imageAuthorization });
    writePrivateJson(required(values, "--binding-out"), binding);
    process.stdout.write(`${JSON.stringify({ status: "AUTHORIZED", targetArn: binding.targetArn, stateSerial: binding.stateSerial })}\n`);
    return binding;
  }
  if (mode === "execute") {
    const binding = readBoundStageBPrivateJson({ filePath: required(values, "--binding"), expectedSha256: required(values, "--binding-sha256"), label: "Normal backend activation binding" });
    const receipt = readBoundStageBPrivateJson({ filePath: required(values, "--release-receipt"), expectedSha256: required(values, "--release-receipt-sha256"), label: "Production RLS release receipt" });
    const result = executeNormalBackendActivation({ run, sourceSha, imageAuthorization, releaseReceipt: receipt, binding, metadataFile: required(values, "--metadata-out") });
    process.stdout.write(`${JSON.stringify(result)}\n`);
    return result;
  }
  throw new Error("--mode must be converge-policy, prepare, or execute.");
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) runCli();
