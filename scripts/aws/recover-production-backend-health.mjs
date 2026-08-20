#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { readStageBPrivateFileBytes, writeStageBPrivateFilesAtomic } from "./stage-b-artifact-contract.mjs";
import { readFreshProtectedMainIdentity } from "./stage-b-deployment-identity.mjs";
import { verifyImageEvidenceSignature } from "./production-green-stage-b-image-evidence.mjs";
import { canonicalSha256 } from "./stage-b-task-definition-recovery-contract.mjs";
import {
  BACKEND_HEALTH_RECOVERY,
  assertLegacyBackendRecoveryAuthorization,
  buildLegacyBackendRecoveryCandidate,
  createLegacyBackendRecoveryAuthorization,
  runLegacyBackendHealthRecovery,
} from "./production-backend-health-recovery-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const option = (argv, name) => { const index = argv.indexOf(name); return index < 0 ? undefined : argv[index + 1]; };
const required = (argv, name) => { const value = option(argv, name); if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };
const hex256 = /^[a-f0-9]{64}$/;
const digestPattern = /^sha256:[a-f0-9]{64}$/;

function readAuthenticatedJson(filePath, expectedSha256, label) {
  if (!hex256.test(expectedSha256 || "")) throw new Error(`${label} expected SHA-256 is invalid.`);
  const captured = readStageBPrivateFileBytes({ filePath: path.resolve(filePath), repositoryRoot: root, label });
  if (captured.sha256 !== expectedSha256) throw new Error(`${label} bytes do not match the prepared SHA-256.`);
  return { ...captured, value: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(captured.bytes)) };
}

const cleanEnv = (base = process.env, profile) => {
  const env = { ...base, AWS_REGION: BACKEND_HEALTH_RECOVERY.region, AWS_DEFAULT_REGION: BACKEND_HEALTH_RECOVERY.region };
  if (profile) env.AWS_PROFILE = profile;
  if (profile) for (const key of ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN", "AWS_DEFAULT_PROFILE"]) delete env[key];
  return env;
};

export async function runBackendHealthRecoveryCli(argv = process.argv.slice(2), deps = {}) {
  const sourceSha = required(argv, "--source-sha");
  const imageFile = required(argv, "--image-authorization");
  const imageSha = required(argv, "--image-authorization-sha256");
  const profile = option(argv, "--aws-profile");
  const env = cleanEnv(deps.baseEnv, profile);
  const verifyImageEvidence = deps.verifyImageEvidence || ((input) => verifyImageEvidenceSignature({ ...input, env }));
  const image = readAuthenticatedJson(imageFile, imageSha, "Backend recovery image authorization");
  const protectedMain = (deps.readProtectedMain || readFreshProtectedMainIdentity)({ cwd: root, expectedSourceSha: sourceSha, ...(deps.git ? { run: deps.git } : {}) });
  if (protectedMain.headSha !== sourceSha || protectedMain.freshRemoteMainSha !== sourceSha) throw new Error("Backend recovery requires the exact fresh protected-main source.");
  if (!deps.readProtectedMain && execFileSync("git", ["status", "--porcelain=v1"], { cwd: root, encoding: "utf8" }).trim()) throw new Error("Backend recovery requires a clean protected-main checkout.");

  if (argv.includes("--prepare")) {
    const approvalFile = required(argv, "--approval");
    const approvalSha = required(argv, "--approval-sha256");
    const approval = readAuthenticatedJson(approvalFile, approvalSha, "Backend recovery approval");
    const authorization = createLegacyBackendRecoveryAuthorization({
      sourceSha,
      currentTaskDefinitionArn: required(argv, "--current-task-definition"),
      recoveryImageDigest: required(argv, "--recovery-image-digest"),
      imageAuthorization: image.value,
      approval: approval.value,
    });
    assertLegacyBackendRecoveryAuthorization(authorization, {
      sourceSha,
      currentTaskDefinitionArn: authorization.currentTaskDefinitionArn,
      recoveryImageDigest: authorization.recoveryImageDigest,
      imageAuthorization: image.value,
      imageValidation: { verifyImageEvidence },
      executionActor: env.GITHUB_ACTOR,
    });
    const output = path.resolve(required(argv, "--output"));
    writeStageBPrivateFilesAtomic({ repositoryRoot: root, overwrite: false, files: [{ filePath: output, bytes: Buffer.from(`${JSON.stringify(authorization, null, 2)}\n`), label: "Backend recovery authorization" }] });
    return authorization;
  }

  if (!argv.includes("--execute")) throw new Error("Backend health recovery requires --prepare or --execute.");
  const authorization = readAuthenticatedJson(required(argv, "--authorization"), required(argv, "--authorization-sha256"), "Backend recovery authorization");
  assertLegacyBackendRecoveryAuthorization(authorization.value, {
    sourceSha,
    currentTaskDefinitionArn: authorization.value.currentTaskDefinitionArn,
    recoveryImageDigest: authorization.value.recoveryImageDigest,
    imageAuthorization: image.value,
    imageValidation: { verifyImageEvidence },
    executionActor: env.GITHUB_ACTOR,
  });
  const evidenceOut = path.resolve(required(argv, "--evidence-out"));
  const healthUrl = required(argv, "--health-url");
  if (!/^https:\/\//.test(healthUrl)) throw new Error("Backend recovery health URL must use HTTPS.");
  const run = deps.exec || ((command, args) => execFileSync(command, args, { cwd: root, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }));
  const aws = (args) => JSON.parse(run("aws", [...args, "--region", BACKEND_HEALTH_RECOVERY.region, "--output", "json", "--no-cli-pager"]));
  const caller = aws(["sts", "get-caller-identity"]);
  if (String(caller.Account) !== BACKEND_HEALTH_RECOVERY.account || !/^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\//.test(caller.Arn || "")) throw new Error("Backend recovery requires the exact production release-deployer identity.");
  const serviceResponse = aws(["ecs", "describe-services", "--cluster", BACKEND_HEALTH_RECOVERY.cluster, "--services", BACKEND_HEALTH_RECOVERY.service]);
  if (serviceResponse.failures?.length || serviceResponse.services?.length !== 1) throw new Error("Backend service readback is incomplete.");
  const service = serviceResponse.services[0];
  const currentTaskDefinition = aws(["ecs", "describe-task-definition", "--task-definition", authorization.value.currentTaskDefinitionArn, "--include", "TAGS"]);
  const currentImage = currentTaskDefinition.taskDefinition?.containerDefinitions?.find(({ name }) => name === BACKEND_HEALTH_RECOVERY.container)?.image;
  const currentDigest = String(currentImage || "").split("@").at(-1);
  const recoveryDigest = authorization.value.recoveryImageDigest;
  if (!digestPattern.test(currentDigest) || !digestPattern.test(recoveryDigest)) throw new Error("Current or recovery image digest is malformed.");
  const imageExists = (digest) => {
    try {
      const result = aws(["ecr", "describe-images", "--repository-name", BACKEND_HEALTH_RECOVERY.repository, "--image-ids", `imageDigest=${digest}`]);
      return result.imageDetails?.length === 1;
    } catch (error) {
      if (/ImageNotFoundException/.test(String(error.stderr || error.message))) return false;
      throw error;
    }
  };
  const repository = aws(["ecr", "describe-repositories", "--repository-names", BACKEND_HEALTH_RECOVERY.repository]).repositories?.[0];
  const stopped = aws(["ecs", "list-tasks", "--cluster", BACKEND_HEALTH_RECOVERY.cluster, "--service-name", BACKEND_HEALTH_RECOVERY.service, "--desired-status", "STOPPED", "--max-results", "100"]);
  const stoppedTasks = stopped.taskArns?.length ? aws(["ecs", "describe-tasks", "--cluster", BACKEND_HEALTH_RECOVERY.cluster, "--tasks", ...stopped.taskArns]).tasks || [] : [];
  const stoppedReasons = [
    ...(service.events || []).map(({ message }) => message),
    ...stoppedTasks.flatMap((task) => [task.stoppedReason, ...(task.containers || []).map(({ reason }) => reason)]),
  ].filter(Boolean);
  const candidate = buildLegacyBackendRecoveryCandidate({ currentTaskDefinition, recoveryImageDigest: recoveryDigest, imageReleaseSha: image.value.imageReleaseSha });
  const imageValidation = { verifyImageEvidence };
  const describe = async (arn) => aws(["ecs", "describe-task-definition", "--task-definition", arn, "--include", "TAGS"]);
  const census = async () => {
    const revisions = [];
    const seen = new Set();
    let nextToken;
    do {
      const args = ["ecs", "list-task-definitions", "--family-prefix", BACKEND_HEALTH_RECOVERY.family, "--status", "ACTIVE", "--sort", "DESC"];
      if (nextToken) args.push("--next-token", nextToken);
      const page = aws(args);
      for (const arn of page.taskDefinitionArns || []) revisions.push(await describe(arn));
      nextToken = page.nextToken;
      if (nextToken && seen.has(nextToken)) throw new Error("Legacy backend revision census repeated a pagination token.");
      if (nextToken) seen.add(nextToken);
    } while (nextToken);
    return revisions;
  };
  const readService = async () => {
    const response = aws(["ecs", "describe-services", "--cluster", BACKEND_HEALTH_RECOVERY.cluster, "--services", BACKEND_HEALTH_RECOVERY.service]);
    if (response.failures?.length || response.services?.length !== 1) throw new Error("Backend service reconciliation readback failed.");
    return response.services[0];
  };
  const result = await runLegacyBackendHealthRecovery({
    sourceSha, service, currentTaskDefinition, currentImageExists: imageExists(currentDigest), stoppedReasons,
    replacementImage: { exists: imageExists(recoveryDigest), immutable: repository?.imageTagMutability === "IMMUTABLE", signatureValid: true, attestationValid: true, provenanceValid: true, criticalFindings: 0, repository: BACKEND_HEALTH_RECOVERY.repository, digest: recoveryDigest },
    authorization: authorization.value, imageAuthorization: image.value, imageValidation, executionActor: process.env.GITHUB_ACTOR, candidate,
  }, {
    census,
    describe,
    register: async (payload) => aws(["ecs", "register-task-definition", "--cli-input-json", JSON.stringify(payload)]),
    readService,
    updateService: async (taskDefinition) => aws(["ecs", "update-service", "--cluster", BACKEND_HEALTH_RECOVERY.cluster, "--service", BACKEND_HEALTH_RECOVERY.service, "--task-definition", taskDefinition]),
    waitStable: async () => run("aws", ["ecs", "wait", "services-stable", "--cluster", BACKEND_HEALTH_RECOVERY.cluster, "--services", BACKEND_HEALTH_RECOVERY.service, "--region", BACKEND_HEALTH_RECOVERY.region, "--no-cli-pager"]),
    readRunningTasks: async () => {
      const listed = aws(["ecs", "list-tasks", "--cluster", BACKEND_HEALTH_RECOVERY.cluster, "--service-name", BACKEND_HEALTH_RECOVERY.service, "--desired-status", "RUNNING"]);
      if (!listed.taskArns?.length) return [];
      const tasks = aws(["ecs", "describe-tasks", "--cluster", BACKEND_HEALTH_RECOVERY.cluster, "--tasks", ...listed.taskArns]).tasks || [];
      return tasks.map((task) => ({ taskDefinitionArn: task.taskDefinitionArn, imageDigest: task.containers?.find(({ name }) => name === BACKEND_HEALTH_RECOVERY.container)?.imageDigest }));
    },
    verifyHealth: async () => { try { run("curl", ["--fail", "--silent", "--show-error", "--max-time", "20", healthUrl]); return true; } catch { return false; } },
  });
  const evidenceBody = { schemaVersion: 1, kind: "BACKEND_HEALTH_RECOVERY_EVIDENCE", sourceSha, authorizationSha256: authorization.sha256, imageAuthorizationSha256: image.sha256, account: BACKEND_HEALTH_RECOVERY.account, region: BACKEND_HEALTH_RECOVERY.region, ...result, generatedAt: new Date().toISOString() };
  const evidence = { ...evidenceBody, evidenceSha256: canonicalSha256(evidenceBody) };
  writeStageBPrivateFilesAtomic({ repositoryRoot: root, overwrite: false, files: [{ filePath: evidenceOut, bytes: Buffer.from(`${JSON.stringify(evidence, null, 2)}\n`), label: "Backend health recovery evidence" }] });
  return evidence;
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) runBackendHealthRecoveryCli().then((result) => process.stdout.write(`${JSON.stringify(result, null, 2)}\n`));
