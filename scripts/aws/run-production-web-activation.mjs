#!/usr/bin/env node
import fs from "node:fs";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { createPinnedRootAttestationVerifier } from "./production-root-attestation-key.mjs";
import { runGovernedFrontendActivation, WEB_RELEASE } from "./production-web-release-contract.mjs";
import { authorizedBackendDigest } from "./production-cutover-control-plane.mjs";
import { verifyCoordinatedWebRelease } from "./verify-production-web-release-authorization.mjs";
import { createReleaseGateImageAuthorizationRunner } from "./verify-production-release-image-authorization.mjs";
import { verifyImageEvidenceSignature } from "./production-green-stage-b-image-evidence.mjs";
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { assertNormalBackendActivationEvidence, NORMAL_ACTIVATION } from "./production-normal-backend-activation.mjs";

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
      assertBackendActivationLiveReadback({ sourceSha, expectedDigest, backendActivationEvidence, service, tasks, healthStatus: health.status, healthBody: body });
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

export function assertBackendActivationLiveReadback({ sourceSha, expectedDigest, backendActivationEvidence, service, tasks, healthStatus, healthBody } = {}) {
  const primary = service?.deployments?.filter(({ status }) => status === "PRIMARY") || [];
  const backendContainers = (task) => (task?.containers || []).filter(({ name }) => name === NORMAL_ACTIVATION.container);
  if (service?.taskDefinition !== backendActivationEvidence?.targetArn || service.serviceArn !== NORMAL_ACTIVATION.serviceArn || service.clusterArn !== NORMAL_ACTIVATION.clusterArn || service.status !== "ACTIVE" || service.desiredCount !== 2 || service.runningCount !== 2 || service.pendingCount !== 0 || primary.length !== 1 || primary[0].taskDefinition !== service.taskDefinition || primary[0].rolloutState !== "COMPLETED" || !Array.isArray(tasks) || tasks.length !== 2 || tasks.some((task) => task.lastStatus !== "RUNNING" || task.taskDefinitionArn !== service.taskDefinition || backendContainers(task).length !== 1 || backendContainers(task)[0].imageDigest !== expectedDigest) || healthStatus !== 200 || healthBody?.status !== "ready" || healthBody.release?.gitSha !== sourceSha) throw new Error("Backend activation is not the exact stable source-bound production release.");
  return true;
}

export function assertFrontendActivationAuthorized(coordinated) {
  if (coordinated?.webRequired !== true) throw new Error("Frontend activation is forbidden when authenticated Stage-B impact does not require web publication.");
  return true;
}

export async function activateAuthenticatedWebRelease({ sourceSha, stageBAuthorization, webAuthorization, backendActivationEvidence, verifyWeb, verifyStageBImageEvidence, verifyCoordinated = verifyCoordinatedWebRelease, createAdapters = createAwsFrontendActivationAdapters, now } = {}) {
  const coordinated = await verifyCoordinated({ sourceSha, stageBAuthorization, webAuthorization, verifyWeb, verifyStageBImageEvidence });
  assertFrontendActivationAuthorized(coordinated);
  assertNormalBackendActivationEvidence(backendActivationEvidence, { sourceSha, stageBAuthorization });
  const adapters = createAdapters();
  if (typeof adapters.verifyBackendActivation !== "function") throw new Error("Frontend activation requires the canonical backend activation readback.");
  await adapters.verifyBackendActivation({ sourceSha, stageBAuthorization, backendActivationEvidence });
  return runGovernedFrontendActivation({ sourceSha, webAuthorization, verifyWebAuthorization: verifyWeb, ...adapters, ...(now ? { now } : {}) });
}

function required(argv, name) { const index = argv.indexOf(name); const value = index < 0 ? undefined : argv[index + 1]; if (!value || value.startsWith("--") || argv.indexOf(name, index + 1) !== -1) throw new Error(`${name} is required exactly once.`); return value; }

export async function runCli(argv = process.argv.slice(2), deps = {}) {
  if (argv.length !== 14) throw new Error("Web activation accepts exactly seven options.");
  const sourceSha = required(argv, "--source-sha"); const webBytes = fs.readFileSync(required(argv, "--web-authorization")); const webHash = required(argv, "--web-authorization-sha256"); const stageBBytes = fs.readFileSync(required(argv, "--stage-b-authorization")); const stageBHash = required(argv, "--stage-b-authorization-sha256");
  if (crypto.createHash("sha256").update(webBytes).digest("hex") !== webHash || crypto.createHash("sha256").update(stageBBytes).digest("hex") !== stageBHash) throw new Error("Release authorization bytes do not match their SHA-256.");
  const backendBytes = fs.readFileSync(required(argv, "--backend-activation-evidence")); const backendHash = required(argv, "--backend-activation-evidence-sha256");
  if (crypto.createHash("sha256").update(backendBytes).digest("hex") !== backendHash) throw new Error("Backend activation evidence bytes do not match their SHA-256.");
  const webAuthorization = JSON.parse(webBytes); const stageBAuthorization = JSON.parse(stageBBytes); const backendActivationEvidence = JSON.parse(backendBytes); const verifyWeb = deps.verifyWebAuthorization || createPinnedRootAttestationVerifier(); const releaseRun = deps.releaseRun || createReleaseGateImageAuthorizationRunner();
  return activateAuthenticatedWebRelease({ sourceSha, stageBAuthorization, webAuthorization, backendActivationEvidence, verifyWeb, verifyStageBImageEvidence: deps.verifyStageBImageEvidence || ((options) => verifyImageEvidenceSignature({ ...options, run: releaseRun })), verifyCoordinated: deps.verifyCoordinated || verifyCoordinatedWebRelease, createAdapters: deps.createAdapters || createAwsFrontendActivationAdapters, now: deps.now });
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) runCli().then((result) => process.stdout.write(`${JSON.stringify(result)}\n`)).catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
