#!/usr/bin/env node
import fs from "node:fs";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createPinnedRootAttestationVerifier } from "./production-root-attestation-key.mjs";
import { runGovernedFrontendActivation, WEB_RELEASE } from "./production-web-release-contract.mjs";
import { authorizedBackendDigest } from "./production-cutover-control-plane.mjs";
import { verifyCoordinatedWebRelease } from "./verify-production-web-release-authorization.mjs";
import { createReleaseGateImageAuthorizationRunner } from "./verify-production-release-image-authorization.mjs";
import { verifyImageEvidenceSignature } from "./production-green-stage-b-image-evidence.mjs";
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { assertNormalBackendActivationEvidence, NORMAL_ACTIVATION } from "./production-normal-backend-activation.mjs";
import { assertProductionOverlapDeploymentReceipt, resolveProductionOverlapDeploymentReceipt } from "./production-overlap-deployment-receipt.mjs";
import { readFreshProtectedMainIdentity } from "./stage-b-deployment-identity.mjs";

export function createWebActivationAwsRunner({ env = process.env, exec = execFileSync } = {}) {
  if (env.MSCQR_AWS_CREDENTIAL_SOURCE !== PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER) throw new Error("Web activation requires the GitHub OIDC release-deployer credential source.");
  const run = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.GITHUB_OIDC_RELEASE_DEPLOYER, env, region: WEB_RELEASE.region, exec });
  return (args) => run([...args, "--output", "json", "--no-cli-pager"]);
}

export function createAwsFrontendActivationAdapters({ execute, env = process.env, exec = execFileSync, fetchImpl = fetch } = {}) {
  const run = execute || createWebActivationAwsRunner({ env, exec });
  const awsJson = (args) => JSON.parse(run(args));
  return Object.freeze({
    verifyBackendActivation: async ({ sourceSha, stageBAuthorization, backendActivationEvidence }) => {
      const expectedDigest = authorizedBackendDigest(stageBAuthorization);
      const service = awsJson(["ecs", "describe-services", "--cluster", NORMAL_ACTIVATION.cluster, "--services", NORMAL_ACTIVATION.service]).services?.[0];
      const taskArns = awsJson(["ecs", "list-tasks", "--cluster", NORMAL_ACTIVATION.cluster, "--service-name", NORMAL_ACTIVATION.service, "--desired-status", "RUNNING"]).taskArns || [];
      const tasks = taskArns.length ? awsJson(["ecs", "describe-tasks", "--cluster", NORMAL_ACTIVATION.cluster, "--tasks", ...taskArns]).tasks || [] : [];
      const health = await fetchImpl("https://www.mscqr.com/api/health/ready"); const body = health.ok ? await health.json() : null;
      if (backendActivationEvidence.operation === "rotation-overlap") assertOverlapBackendLiveReadback({ sourceSha, imageReleaseSha: stageBAuthorization.imageReleaseSha, expectedDigest, receipt: backendActivationEvidence, service, tasks, healthStatus: health.status, healthBody: body });
      else assertBackendActivationLiveReadback({ sourceSha, imageReleaseSha: stageBAuthorization.imageReleaseSha, expectedDigest, backendActivationEvidence, service, tasks, healthStatus: health.status, healthBody: body });
    },
    readService: async () => awsJson(["ecs", "describe-services", "--cluster", WEB_RELEASE.cluster, "--services", WEB_RELEASE.serviceName]).services?.[0],
    describeTaskDefinition: async (taskDefinition) => { const response = awsJson(["ecs", "describe-task-definition", "--task-definition", taskDefinition, "--include", "TAGS"]); return { ...response.taskDefinition, tags: response.tags || [] }; },
    registerTaskDefinition: async (candidate) => {
      const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-web-task-")); const file = path.join(directory, "task.json");
      try { fs.writeFileSync(file, JSON.stringify(candidate), { mode: 0o600, flag: "wx" }); return awsJson(["ecs", "register-task-definition", "--cli-input-json", `file://${file}`]); }
      finally { fs.rmSync(directory, { recursive: true, force: true }); }
    },
    updateService: async ({ cluster, service, taskDefinition }) => awsJson(["ecs", "update-service", "--cluster", cluster, "--service", service, "--task-definition", taskDefinition]),
    waitStable: async () => { run(["ecs", "wait", "services-stable", "--cluster", WEB_RELEASE.cluster, "--services", WEB_RELEASE.serviceName]); },
    verifyHealth: async ({ expectedTaskDefinitionArn, expectedImageRef }) => {
      const service = awsJson(["ecs", "describe-services", "--cluster", WEB_RELEASE.cluster, "--services", WEB_RELEASE.serviceName]).services?.[0];
      const taskArns = awsJson(["ecs", "list-tasks", "--cluster", WEB_RELEASE.cluster, "--service-name", WEB_RELEASE.serviceName, "--desired-status", "RUNNING"]).taskArns || [];
      const tasks = taskArns.length ? awsJson(["ecs", "describe-tasks", "--cluster", WEB_RELEASE.cluster, "--tasks", ...taskArns]).tasks || [] : [];
      const digest = expectedImageRef.split("@")[1];
      if (service?.taskDefinition !== expectedTaskDefinitionArn || service.desiredCount !== 2 || service.runningCount !== 2 || service.pendingCount !== 0 || tasks.length !== 2 || tasks.some((task) => task.taskDefinitionArn !== expectedTaskDefinitionArn || task.containers?.find(({ name }) => name === WEB_RELEASE.container)?.imageDigest !== digest)) throw new Error("Frontend ECS runtime does not match the authenticated candidate.");
      const [health, login] = await Promise.all([fetchImpl("https://www.mscqr.com/api/health/ready"), fetchImpl("https://www.mscqr.com/login")]);
      const body = health.ok ? await health.json() : null;
      return { ready: health.status === 200 && body?.status === "ready", loginStatus: login.status };
    },
  });
}

export function assertBackendActivationLiveReadback({ sourceSha, imageReleaseSha, expectedDigest, backendActivationEvidence, service, tasks, healthStatus, healthBody } = {}) {
  const primary = service?.deployments?.filter(({ status }) => status === "PRIMARY") || [];
  const backendContainers = (task) => (task?.containers || []).filter(({ name }) => name === NORMAL_ACTIVATION.container);
  const evidenceImageSha = backendActivationEvidence?.schemaVersion === 1 ? backendActivationEvidence.sourceSha : backendActivationEvidence?.imageReleaseSha;
  if (![1, 2].includes(backendActivationEvidence?.schemaVersion) || backendActivationEvidence.schemaVersion === 1 && Object.hasOwn(backendActivationEvidence, "imageReleaseSha") || backendActivationEvidence?.sourceSha !== sourceSha || evidenceImageSha !== imageReleaseSha || backendActivationEvidence.imageDigest !== expectedDigest || service?.taskDefinition !== backendActivationEvidence.targetArn || service.serviceArn !== NORMAL_ACTIVATION.serviceArn || service.clusterArn !== NORMAL_ACTIVATION.clusterArn || service.status !== "ACTIVE" || service.desiredCount !== 2 || service.runningCount !== 2 || service.pendingCount !== 0 || primary.length !== 1 || primary[0].taskDefinition !== service.taskDefinition || primary[0].rolloutState !== "COMPLETED" || !Array.isArray(tasks) || tasks.length !== 2 || tasks.some((task) => task.lastStatus !== "RUNNING" || task.taskDefinitionArn !== service.taskDefinition || backendContainers(task).length !== 1 || backendContainers(task)[0].imageDigest !== expectedDigest) || healthStatus !== 200 || healthBody?.status !== "ready" || healthBody.release?.gitSha !== imageReleaseSha) throw new Error("Backend activation is not the exact stable source-bound production release.");
  return true;
}

export function assertOverlapBackendLiveReadback({ sourceSha, imageReleaseSha, expectedDigest, receipt, service, tasks, healthStatus, healthBody } = {}) {
  assertProductionOverlapDeploymentReceipt(receipt);
  const primary = service?.deployments?.filter(({ status }) => status === "PRIMARY") || [];
  if (receipt.imageDigest !== expectedDigest || receipt.sourceSha !== receipt.deploymentSha || receipt.taskDefinitionArn !== service?.taskDefinition || service.serviceArn !== NORMAL_ACTIVATION.serviceArn || service.clusterArn !== NORMAL_ACTIVATION.clusterArn || service.status !== "ACTIVE" || service.desiredCount !== 2 || service.runningCount !== 2 || service.pendingCount !== 0 || primary.length !== 1 || primary[0].taskDefinition !== receipt.taskDefinitionArn || primary[0].rolloutState !== "COMPLETED" || !Array.isArray(tasks) || tasks.length !== 2 || tasks.some((task) => task.lastStatus !== "RUNNING" || task.taskDefinitionArn !== receipt.taskDefinitionArn || task.containers?.filter(({ name }) => name === NORMAL_ACTIVATION.container).length !== 1 || task.containers.find(({ name }) => name === NORMAL_ACTIVATION.container).imageDigest !== expectedDigest) || healthStatus !== 200 || healthBody?.status !== "ready" || healthBody.release?.gitSha !== imageReleaseSha || !/^[a-f0-9]{40}$/.test(sourceSha || "")) throw new Error("Backend overlap is not the exact stable authorized production release.");
  return true;
}

export function assertFrontendActivationAuthorized(coordinated) {
  if (coordinated?.webRequired !== true) throw new Error("Frontend activation is forbidden when authenticated Stage-B impact does not require web publication.");
  return true;
}

export function assertOverlapReleaseLineage(ancestor, descendant, cwd = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..")) {
  if (!/^[a-f0-9]{40}$/.test(ancestor || "") || !/^[a-f0-9]{40}$/.test(descendant || "")) throw new Error("Overlap release lineage is malformed.");
  try { execFileSync("git", ["merge-base", "--is-ancestor", ancestor, descendant], { cwd, stdio: "ignore" }); }
  catch { throw new Error("Overlap release is not an ancestor of the signed frontend target."); }
  return true;
}

export async function activateAuthenticatedWebRelease({ sourceSha, stageBAuthorization, webAuthorization, backendActivationEvidence, authenticatedOverlap, verifyWeb, verifyStageBImageEvidence, verifyCoordinated = verifyCoordinatedWebRelease, createAdapters = createAwsFrontendActivationAdapters, now } = {}) {
  const coordinated = await verifyCoordinated({ sourceSha, stageBAuthorization, webAuthorization, verifyWeb, verifyStageBImageEvidence });
  assertFrontendActivationAuthorized(coordinated);
  if (authenticatedOverlap) {
    if (backendActivationEvidence || authenticatedOverlap.workflow?.conclusion !== "success" || !Array.isArray(authenticatedOverlap.tailFailures) || authenticatedOverlap.tailFailures.some(({ conclusion }) => conclusion !== "skipped") || authenticatedOverlap.receipt?.imageDigest !== authorizedBackendDigest(stageBAuthorization) || authenticatedOverlap.workflowSourceSha !== authenticatedOverlap.expectedExecutionSourceSha || authenticatedOverlap.receipt?.rotationId !== authenticatedOverlap.expectedRotationId) throw new Error("Authenticated overlap does not bind a successful exact frontend release.");
    backendActivationEvidence = assertProductionOverlapDeploymentReceipt(authenticatedOverlap.receipt);
    assertOverlapReleaseLineage(backendActivationEvidence.sourceSha, sourceSha);
  } else assertNormalBackendActivationEvidence(backendActivationEvidence, { sourceSha, stageBAuthorization });
  const adapters = createAdapters();
  if (typeof adapters.verifyBackendActivation !== "function") throw new Error("Frontend activation requires the canonical backend activation readback.");
  await adapters.verifyBackendActivation({ sourceSha, stageBAuthorization, backendActivationEvidence });
  return runGovernedFrontendActivation({ sourceSha, webAuthorization, verifyWebAuthorization: verifyWeb, ...adapters, ...(now ? { now } : {}) });
}

function required(argv, name) { const index = argv.indexOf(name); const value = index < 0 ? undefined : argv[index + 1]; if (!value || value.startsWith("--") || argv.indexOf(name, index + 1) !== -1) throw new Error(`${name} is required exactly once.`); return value; }

export async function runCli(argv = process.argv.slice(2), deps = {}) {
  const overlap = argv.includes("--overlap-run-id");
  const allowed = new Set(overlap ? ["--source-sha", "--web-authorization", "--web-authorization-sha256", "--stage-b-authorization", "--stage-b-authorization-sha256", "--overlap-run-id", "--overlap-run-attempt", "--overlap-release-sha", "--overlap-rotation-id", "--tooling-sha"] : ["--source-sha", "--web-authorization", "--web-authorization-sha256", "--stage-b-authorization", "--stage-b-authorization-sha256", "--backend-activation-evidence", "--backend-activation-evidence-sha256"]);
  if (argv.length !== allowed.size * 2 || argv.some((arg, i) => i % 2 === 0 && !allowed.has(arg))) throw new Error("Web activation options are incomplete or unexpected.");
  const sourceSha = required(argv, "--source-sha"); const webBytes = fs.readFileSync(required(argv, "--web-authorization")); const webHash = required(argv, "--web-authorization-sha256"); const stageBBytes = fs.readFileSync(required(argv, "--stage-b-authorization")); const stageBHash = required(argv, "--stage-b-authorization-sha256");
  if (crypto.createHash("sha256").update(webBytes).digest("hex") !== webHash || crypto.createHash("sha256").update(stageBBytes).digest("hex") !== stageBHash) throw new Error("Release authorization bytes do not match their SHA-256.");
  let backendActivationEvidence; let authenticatedOverlap;
  if (overlap) {
    const expectedExecutionSourceSha = required(argv, "--tooling-sha"); const expectedRotationId = required(argv, "--overlap-rotation-id");
    if (!/^[a-f0-9]{40}$/.test(expectedExecutionSourceSha) || !/^[A-Za-z0-9._-]{8,128}$/.test(expectedRotationId)) throw new Error("Overlap execution identity is malformed.");
    (deps.protectedMain || readFreshProtectedMainIdentity)({ cwd: path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../.."), expectedSourceSha: expectedExecutionSourceSha });
    const resolved = (deps.resolveOverlap || resolveProductionOverlapDeploymentReceipt)({ workflowRunId: required(argv, "--overlap-run-id"), workflowRunAttempt: required(argv, "--overlap-run-attempt"), sourceSha: required(argv, "--overlap-release-sha"), executionSourceSha: expectedExecutionSourceSha, run: deps.githubRun || ((command, args) => execFileSync(command, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] })) });
    authenticatedOverlap = { ...resolved, expectedExecutionSourceSha, expectedRotationId };
  } else {
    const backendBytes = fs.readFileSync(required(argv, "--backend-activation-evidence")); const backendHash = required(argv, "--backend-activation-evidence-sha256");
    if (crypto.createHash("sha256").update(backendBytes).digest("hex") !== backendHash) throw new Error("Backend activation evidence bytes do not match their SHA-256.");
    backendActivationEvidence = JSON.parse(backendBytes);
  }
  const webAuthorization = JSON.parse(webBytes); const stageBAuthorization = JSON.parse(stageBBytes); const verifyWeb = deps.verifyWebAuthorization || createPinnedRootAttestationVerifier(); const releaseRun = deps.releaseRun || createReleaseGateImageAuthorizationRunner();
  return activateAuthenticatedWebRelease({ sourceSha, stageBAuthorization, webAuthorization, backendActivationEvidence, authenticatedOverlap, verifyWeb, verifyStageBImageEvidence: deps.verifyStageBImageEvidence || ((options) => verifyImageEvidenceSignature({ ...options, run: releaseRun })), verifyCoordinated: deps.verifyCoordinated || verifyCoordinatedWebRelease, createAdapters: deps.createAdapters || createAwsFrontendActivationAdapters, now: deps.now });
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) runCli().then((result) => process.stdout.write(`${JSON.stringify(result)}\n`)).catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
