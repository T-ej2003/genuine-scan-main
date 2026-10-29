#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { assertProtectedCheckout } from "./prepare-production-initial-activation-reconciler-installation.mjs";
import { assertGithubOidcReleaseDeployerEnvironment } from "./production-credential-source-contract.mjs";
import { assertProductionEnvironmentApprovalEvidence, assertProductionEnvironmentActualReviewer } from "./production-github-environment-approval.mjs";
import { verifyProductionReleaseImageAuthorization, createReleaseGateImageAuthorizationRunner } from "./verify-production-release-image-authorization.mjs";
import { verifyImageEvidenceSignature } from "./production-green-stage-b-image-evidence.mjs";
import { verifyB03IndependentCatalogue } from "./production-b03-completion.mjs";
import { canonicalJson, canonicalSha256, STAGE_B, stageBApprovalIdForReleaseSha } from "./production-green-stage-b-contract.mjs";
import { B03_BROKER } from "../../infra/aws/terraform/lambda/production-rls-approval-broker/b03-approval.mjs";
import { invokeProductionApprovalBroker, validateApprovalPublicationProof } from "./check-production-green-stage-b-approval-publication.mjs";
import { readStageBProtectedMainCheckout } from "./stage-b-deployment-identity.mjs";

const authenticateExecutionSource = (sourceSha, repositoryRoot) => {
  readStageBProtectedMainCheckout({ cwd: repositoryRoot, fetchOriginMain: true, expectedSourceSha: sourceSha, requireCanonicalRepository: true });
  assertProtectedCheckout({ sourceSha, repositoryRoot });
};

function authorizeB03Start({ sourceSha, authorization, approvalEvidence, releaseTrainRunId, environment, runner }) {
  assertGithubOidcReleaseDeployerEnvironment(environment);
  assert.match(String(releaseTrainRunId || ""), /^[1-9][0-9]*$/);
  assertProductionEnvironmentApprovalEvidence(approvalEvidence, { sourceSha, repository: "T-ej2003/genuine-scan-main", environment: "production",
    workflowRef: environment.GITHUB_WORKFLOW_REF, eventName: environment.GITHUB_EVENT_NAME, workflowRunId: environment.GITHUB_RUN_ID,
    workflowRunAttempt: environment.GITHUB_RUN_ATTEMPT, executionActor: environment.GITHUB_ACTOR, githubActions: environment.GITHUB_ACTIONS });
  assertProductionEnvironmentActualReviewer(approvalEvidence, { sourceSha, repository: "T-ej2003/genuine-scan-main", executionActor: environment.GITHUB_ACTOR });
  const identity = json(runner, ["sts", "get-caller-identity"]);
  assert.equal(identity.Account, STAGE_B.account);
  assert.match(identity.Arn || "", /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[^/]+$/);
  return verifyProductionReleaseImageAuthorization({ authorization, sourceSha,
    verifyImageEvidence: options => verifyImageEvidenceSignature({ ...options, run: runner }) });
}

// Initiation evidence is deliberately not a successful SQL-installation receipt.
export async function startProductionB03BrokerExecution({ sourceSha, authorization, approvalEvidence, releaseTrainRunId, request,
  environment = process.env, repositoryRoot = root, runner = createReleaseGateImageAuthorizationRunner(),
  authenticateSource = authenticateExecutionSource, authorize = authorizeB03Start, invoke = invokeProductionApprovalBroker, now = () => new Date() } = {}) {
  assert.ok(request && Object.keys(request).sort().join(",") === "approvalId,approvalSha256,operation,sourceSha");
  assert.equal(request.operation, B03_BROKER.mode); assert.equal(request.sourceSha, sourceSha);
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/); assert.match(request.approvalSha256 || "", /^[a-f0-9]{64}$/);
  assert.match(request.approvalId || "", new RegExp(`^APR-B03-${sourceSha}-[a-f0-9-]{16,64}$`));
  await authenticateSource(sourceSha, repositoryRoot);
  const images = await authorize({ sourceSha, authorization, approvalEvidence, releaseTrainRunId, environment, runner });
  assert.match(images.backend || "", /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-backend@sha256:[a-f0-9]{64}$/);
  let version;
  const validation = { ...request, operation: "validate-b03-approval" };
  const proof = await invoke(runner, validation, (response, invocation) => {
    validateApprovalPublicationProof(response, validation); version = invocation.ExecutedVersion;
    assert.match(version || "", /^[1-9][0-9]*$/);
    assert.equal(Object.keys(response).sort().join(","), "approvalContractSha256,approvalId,approvalSha256,backendImage,expiresAt,packageSha256,sourceSha,status,taskDefinitionArn");
    assert.equal(response.backendImage, images.backend);
    assert.match(response.taskDefinitionArn || "", /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-production-b03-incremental:[1-9][0-9]*$/);
    assert.match(response.packageSha256 || "", /^[a-f0-9]{64}$/);
    assert.ok(Date.parse(response.expiresAt) > now().getTime(), "B03 approval expired");
    return response;
  });
  await authenticateSource(sourceSha, repositoryRoot);
  assert.ok(Date.parse(proof.expiresAt) > now().getTime(), "B03 approval expired before execution");
  const started = await invoke(runner, request, (response, invocation) => {
    assert.equal(invocation.ExecutedVersion, version, "Broker alias changed between validation and execution");
    assert.equal(response.status, "started"); assert.equal(response.schemaVersion, 1);
    assert.equal(Object.keys(response).sort().join(","), "approvalContractSha256,approvalId,environment,event,mode,nonce,requestSha256,schemaVersion,status,taskArn,taskDefinitionArn");
    assert.equal(response.environment, "production"); assert.equal(response.event, "b03-broker-start");
    assert.equal(response.mode, B03_BROKER.mode); assert.equal(response.approvalId, request.approvalId);
    assert.equal(response.taskDefinitionArn, proof.taskDefinitionArn);
    assert.equal(response.approvalContractSha256, proof.approvalContractSha256);
    assert.match(response.taskArn || "", /^arn:aws:ecs:eu-west-2:368992683803:task\/mscqr-prod-euw2-main\/[a-f0-9]{32}$/);
    assert.match(response.requestSha256 || "", /^[a-f0-9]{64}$/);
    assert.match(response.nonce || "", /^[a-f0-9-]{16,64}$/);
    return response;
  });
  return { status: "STARTED_UNVERIFIED", sourceSha, backendImage: images.backend, brokerVersion: version,
    approvalSha256: request.approvalSha256, initiation: started };
}

const root = fileURLToPath(new URL("../../", import.meta.url));
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const json = (runner, args) => JSON.parse(runner([...args, "--region", "eu-west-2", "--output", "json", "--no-cli-pager"]));
const required = (args, name) => { const index = args.indexOf(name); const value = args[index + 1];
  if (index < 0 || !value || value.startsWith("--") || args.indexOf(name, index + 1) >= 0) throw new Error(`${name} is required exactly once`);
  return value; };

export async function completeProductionB03Release({ sourceSha, authorization, approvalEvidence, releaseTrainRunId, request, compatibilityReference,
  environment = process.env, repositoryRoot = root, runner = createReleaseGateImageAuthorizationRunner(), authenticateSource = authenticateExecutionSource,
  authorize = authorizeB03Start, independent = verifyB03IndependentCatalogue, invoke = invokeProductionApprovalBroker } = {}) {
  assert.ok(compatibilityReference, "An authenticated independent post-commit verification reference is required");
  assert.equal(request?.sourceSha, sourceSha); assert.equal(request?.operation, B03_BROKER.mode);
  await authenticateSource(sourceSha, repositoryRoot);
  const images = await authorize({ sourceSha, authorization, approvalEvidence, releaseTrainRunId, environment, runner });
  const status = await invoke(runner, { ...request, operation: "b03-completion-status" }, response => {
    assert.equal(response.status, "EXECUTION_VERIFIED"); assert.equal(response.execution.sourceSha, sourceSha);
    assert.equal(response.execution.backendImage, images.backend); return response.execution;
  });
  const verification = independent({ reference: compatibilityReference, execution: status, run: runner, repositoryRoot });
  await authenticateSource(sourceSha, repositoryRoot);
  const event = { ...request, operation: "b03-completion-record", workflowRunId: environment.GITHUB_RUN_ID,
    releaseTrainRunId: String(releaseTrainRunId), verification };
  const acknowledged = await invoke(runner, event, response => {
    assert.equal(response.status, "COMPLETION_VERIFIED"); assert.equal(response.completionSha256, canonicalSha256(response.completion));
    assert.equal(response.completion.workflowRunId, environment.GITHUB_RUN_ID);
    assert.equal(response.completion.releaseTrainRunId, String(releaseTrainRunId));
    assert.equal(canonicalJson(response.completion.execution), canonicalJson(status));
    assert.equal(canonicalJson(response.completion.verification), canonicalJson(verification));
    return response;
  });
  const receipt = { schemaVersion: 4, environment: "production", installationMode: "B03_INCREMENTAL_EXISTING_DATABASE", releaseSha: sourceSha,
    approvalId: stageBApprovalIdForReleaseSha(sourceSha), images: { backend: images.backend }, workflowRunId: environment.GITHUB_RUN_ID,
    releaseTrainRunId: String(releaseTrainRunId), b03Request: request,
    completion: acknowledged.completion, completionSha256: acknowledged.completionSha256 };
  return { ...receipt, receiptBundleSha256: canonicalSha256(receipt) };
}

// The legacy completion API cannot authenticate receipts and is deliberately disabled.
export async function applyProductionB03IncrementalRelease() {
  throw new Error("An authenticated independent post-commit verifier is required; use the complete CLI mode");
}

export function parseB03StartArguments(args) {
  const complete = args[args.indexOf("--mode") + 1] === "complete";
  const allowed = new Set([...(complete ? ["--compatibility-reference"] : []), "--mode", "--source-sha", "--authorization", "--authorization-sha256", "--approval-evidence", "--b03-request", "--release-train-run-id", "--output"]);
  assert.equal(args.length, allowed.size * 2);
  for (let i = 0; i < args.length; i += 2) assert.ok(allowed.has(args[i]), "Unsupported B03 execution option");
  for (const name of allowed) required(args, name);
  assert.ok(["start", "complete"].includes(required(args, "--mode")));
  return Object.fromEntries([...allowed].map(name => [name.slice(2), required(args, name)]));
}

export async function runB03StartCli(args, { start = startProductionB03BrokerExecution, complete = completeProductionB03Release } = {}) {
  const values = parseB03StartArguments(args);
  const bytes = fs.readFileSync(values.authorization);
  assert.equal(sha256(bytes), values["authorization-sha256"]);
  const requestBytes = fs.readFileSync(values["b03-request"]);
  assert.ok(requestBytes.length <= 2048, "Only a compact published B03 reference is accepted");
  const verificationBytes = values.mode === "complete" ? fs.readFileSync(values["compatibility-reference"]) : null;
  if (verificationBytes) assert.ok(verificationBytes.length <= 2048, "Only a compact independent verification reference is accepted");
  const result = await (values.mode === "complete" ? complete : start)({
    ...(verificationBytes ? { compatibilityReference: JSON.parse(verificationBytes) } : {}), sourceSha: values["source-sha"], authorization: JSON.parse(bytes),
    approvalEvidence: JSON.parse(fs.readFileSync(values["approval-evidence"], "utf8")),
    request: JSON.parse(requestBytes), releaseTrainRunId: values["release-train-run-id"] });
  fs.writeFileSync(values.output, `${JSON.stringify(result)}\n`, { mode: 0o600, flag: "wx" });
  return result;
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  runB03StartCli(process.argv.slice(2)).catch(() => {
    process.stderr.write("B03 broker execution or completion failed closed; reconcile authenticated evidence before retry.\n");
    process.exitCode = 1;
  });
}
