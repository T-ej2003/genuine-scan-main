#!/usr/bin/env node
import fs from "node:fs";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { createPinnedRootAttestationVerifier } from "./production-root-attestation-key.mjs";
import { runGovernedFrontendActivation, WEB_RELEASE } from "./production-web-release-contract.mjs";
import { verifyCoordinatedWebRelease } from "./verify-production-web-release-authorization.mjs";
import { createReleaseGateImageAuthorizationRunner } from "./verify-production-release-image-authorization.mjs";
import { verifyImageEvidenceSignature } from "./production-green-stage-b-image-evidence.mjs";

const run = (args) => execFileSync("aws", [...args, "--region", WEB_RELEASE.region, "--output", "json", "--no-cli-pager"], { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });

export function createAwsFrontendActivationAdapters({ execute = run, fetchImpl = fetch } = {}) {
  const awsJson = (args) => JSON.parse(execute(args));
  return Object.freeze({
    readService: async () => awsJson(["ecs", "describe-services", "--cluster", WEB_RELEASE.cluster, "--services", WEB_RELEASE.serviceName]).services?.[0],
    describeTaskDefinition: async (taskDefinition) => { const response = awsJson(["ecs", "describe-task-definition", "--task-definition", taskDefinition, "--include", "TAGS"]); return { ...response.taskDefinition, tags: response.tags || [] }; },
    registerTaskDefinition: async (candidate) => {
      const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-web-task-")); const file = path.join(directory, "task.json");
      try { fs.writeFileSync(file, JSON.stringify(candidate), { mode: 0o600, flag: "wx" }); return awsJson(["ecs", "register-task-definition", "--cli-input-json", `file://${file}`]); }
      finally { fs.rmSync(directory, { recursive: true, force: true }); }
    },
    updateService: async ({ cluster, service, taskDefinition }) => awsJson(["ecs", "update-service", "--cluster", cluster, "--service", service, "--task-definition", taskDefinition]),
    waitStable: async () => { execute(["ecs", "wait", "services-stable", "--cluster", WEB_RELEASE.cluster, "--services", WEB_RELEASE.serviceName]); },
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

function required(argv, name) { const index = argv.indexOf(name); const value = index < 0 ? undefined : argv[index + 1]; if (!value || value.startsWith("--") || argv.indexOf(name, index + 1) !== -1) throw new Error(`${name} is required exactly once.`); return value; }

export async function runCli(argv = process.argv.slice(2), deps = {}) {
  if (argv.length !== 10) throw new Error("Web activation accepts exactly five options.");
  const sourceSha = required(argv, "--source-sha"); const webBytes = fs.readFileSync(required(argv, "--web-authorization")); const webHash = required(argv, "--web-authorization-sha256"); const stageBBytes = fs.readFileSync(required(argv, "--stage-b-authorization")); const stageBHash = required(argv, "--stage-b-authorization-sha256");
  if (crypto.createHash("sha256").update(webBytes).digest("hex") !== webHash || crypto.createHash("sha256").update(stageBBytes).digest("hex") !== stageBHash) throw new Error("Release authorization bytes do not match their SHA-256.");
  const webAuthorization = JSON.parse(webBytes); const stageBAuthorization = JSON.parse(stageBBytes); const verifyWeb = deps.verifyWebAuthorization || createPinnedRootAttestationVerifier(); const releaseRun = deps.releaseRun || createReleaseGateImageAuthorizationRunner();
  await verifyCoordinatedWebRelease({ sourceSha, stageBAuthorization, webAuthorization, verifyWeb, verifyStageBImageEvidence: deps.verifyStageBImageEvidence || ((options) => verifyImageEvidenceSignature({ ...options, run: releaseRun })) });
  return runGovernedFrontendActivation({ sourceSha, webAuthorization, verifyWebAuthorization: verifyWeb, ...createAwsFrontendActivationAdapters(), ...deps });
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) runCli().then((result) => process.stdout.write(`${JSON.stringify(result)}\n`)).catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
