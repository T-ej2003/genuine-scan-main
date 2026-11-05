#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { setTimeout as sleep } from "node:timers/promises";
import { canonicalJson, canonicalSha256, STAGE_B } from "./production-green-stage-b-contract.mjs";
import { appOnlyVerifierNetwork } from "./production-app-only-policy.mjs";
import { B01_PREREQUISITE } from "./production-b01-prerequisite-contract.mjs";
import { collectCompleteRlsProbeLogEvents } from "./probe-production-rls-catalogue.mjs";
import { createProductionAwsCommandRunner, createProductionGithubCommandRunner, productionAwsExecutable } from "./production-credential-source-contract.mjs";
import { authenticateRootAttestationKey, createPinnedRootAttestationVerifier, ROOT_ATTESTATION_KEY_ALIAS_ARN, ROOT_ATTESTATION_SIGNING_ALGORITHM } from "./production-root-attestation-key.mjs";
import { createRootAttestationKmsSigner } from "./production-root-attestation-signer.mjs";

// The existing e39 task reads only the migration ledger. D15 is the comparison
// target; its runtime source is deliberately not relabelled as D15.
export const LEDGER = Object.freeze({
  sourceSha: "d15b79e4779d64be4c6c7ec905caea1e91d410f2",
  runtimeSha: "e39bd21975965642f44f4e13b89b9f278e9d5886",
  database: "mscqr_production_rls_green_phase2",
  taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-c02-session-prerequisite:1",
  imageDigest: "sha256:0e1bb8f89bb3317f4fdf014a21a1d1ec8ede945aba5107f739ecc74216436907",
  commandSha256: "8ea6d40dc8f47e8d80a6763f929eae1eea615936a9e99445891d5e1c499b806a",
  cluster: STAGE_B.clusterArn,
  logGroup: "/ecs/mscqr-production/full-rls-green",
  logPrefix: "c02-ledger-readonly",
});
const root = fileURLToPath(new URL("../../", import.meta.url));
const hash = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const exact = (value, keys) => assert.deepEqual(Object.keys(value || {}).sort(), [...keys].sort());
const read = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const write = (file, value) => fs.writeFileSync(file, `${JSON.stringify(value)}\n`, { flag: "wx", mode: 0o600 });
const taskArnPattern = /^arn:aws:ecs:eu-west-2:368992683803:task\/mscqr-prod-euw2-main\/[a-f0-9]{32}$/;
export const ledgerStartedBy = (nonce) => { assert.match(nonce || "", /^[a-f0-9]{64}$/); return `d15-ledger-${nonce.slice(0, 24)}`; };
export function createPinnedAwsExecutor({ exec = execFileSync, executable = productionAwsExecutable() } = {}) {
  return (command, args, options) => { assert.equal(command, "aws"); return exec(executable, args, options); };
}
let awsRunner;
const aws = (args) => {
  awsRunner ??= createProductionAwsCommandRunner({ credentialSource: "named-profile", profile: "default", exec: createPinnedAwsExecutor() });
  return awsRunner(args);
};
const awsJson = (args) => JSON.parse(aws([...args, "--output", "json", "--no-cli-pager"]));

export function assertFixedLedgerDefinition(definition) {
  assert.equal(definition?.taskDefinitionArn, LEDGER.taskDefinitionArn);
  assert.equal(definition.status, "ACTIVE");
  assert.equal(definition.networkMode, "awsvpc");
  assert.equal(definition.taskRoleArn ?? null, null);
  assert.equal(definition.executionRoleArn, "arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-executor-execution");
  assert.equal(definition.cpu, "1024"); assert.equal(definition.memory, "2048");
  assert.deepEqual(definition.requiresCompatibilities, ["FARGATE"]);
  assert.deepEqual(definition.runtimePlatform, { cpuArchitecture: "X86_64", operatingSystemFamily: "LINUX" });
  assert.equal(definition.containerDefinitions?.length, 1);
  const c = definition.containerDefinitions[0];
  assert.equal(c.name, "production-c02-session-prerequisite");
  assert.equal(c.image, `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${LEDGER.imageDigest}`);
  assert.deepEqual(c.entryPoint, ["node"]);
  assert.equal(hash(JSON.stringify(c.command)), LEDGER.commandSha256, "Fixed ledger SQL/command changed");
  assert.deepEqual(c.environment, [{ name: "NODE_ENV", value: "production" }, { name: "RELEASE_GIT_SHA", value: LEDGER.runtimeSha }]);
  assert.equal(c.secrets?.length, 1); assert.equal(c.secrets[0].name, "MSCQR_C02_ADMIN_PASSWORD");
  assert.equal(c.secrets[0].valueFrom, B01_PREREQUISITE.administratorSecretArn);
  assert.equal(c.readonlyRootFilesystem, true);
  for (const key of ["privileged", "interactive", "pseudoTerminal"]) assert.equal(c[key], false);
  assert.deepEqual(c.logConfiguration, { logDriver: "awslogs", options: {
    "awslogs-group": LEDGER.logGroup, "awslogs-region": "eu-west-2", "awslogs-stream-prefix": LEDGER.logPrefix } });
  return true;
}

export function assertLedgerAuthorization(value, { toolingSourceSha, now = Date.now(), historical = false, minimumRemainingMs = 0, verify = createPinnedRootAttestationVerifier() } = {}) {
  exact(value, ["body", "authorizationSha256", "signatureBase64", "signingKeyAliasArn", "signingAlgorithm"]);
  const b = value.body;
  exact(b, ["kind", "sourceSha", "toolingSourceSha", "runtimeSourceSha", "database", "taskDefinitionArn", "imageDigest", "commandSha256", "nonce", "issuedAt", "expiresAt"]);
  assert.equal(b.kind, "D15_FIXED_MIGRATION_LEDGER_READBACK_AUTHORIZATION");
  assert.equal(b.sourceSha, LEDGER.sourceSha); assert.equal(b.toolingSourceSha, toolingSourceSha);
  assert.match(toolingSourceSha || "", /^[a-f0-9]{40}$/);
  assert.equal(b.runtimeSourceSha, LEDGER.runtimeSha); assert.equal(b.database, LEDGER.database);
  assert.equal(b.taskDefinitionArn, LEDGER.taskDefinitionArn); assert.equal(b.imageDigest, LEDGER.imageDigest);
  assert.equal(b.commandSha256, LEDGER.commandSha256);
  assert.match(b.nonce || "", /^[a-f0-9]{64}$/);
  const issued = Date.parse(b.issuedAt), expires = Date.parse(b.expiresAt);
  assert.ok(Number.isFinite(issued) && Number.isFinite(expires) && issued <= now && issued < expires
    && (historical || now + minimumRemainingMs < expires) && expires - issued <= 15 * 60_000);
  assert.equal(value.authorizationSha256, canonicalSha256(b));
  assert.equal(value.signingKeyAliasArn, ROOT_ATTESTATION_KEY_ALIAS_ARN);
  assert.equal(value.signingAlgorithm, ROOT_ATTESTATION_SIGNING_ALGORITHM);
  assert.ok(verify({ keyArn: value.signingKeyAliasArn, signingAlgorithm: value.signingAlgorithm,
    digest: Buffer.from(value.authorizationSha256, "hex"), signature: Buffer.from(value.signatureBase64, "base64") }), "Invalid root KMS authorization signature");
  return b;
}

export function d15MigrationChecksums(gitRun = createPinnedGitRunner()) {
  const files = gitRun(["ls-tree", "-r", "--name-only", LEDGER.sourceSha, "--", "backend/prisma/migrations"]).trim().split("\n")
    .filter((file) => file.endsWith("/migration.sql"));
  assert.equal(files.length, 57);
  assert.equal(new Set(files).size, files.length);
  const expected = new Map();
  for (const file of files) {
    assert.match(file, /^backend\/prisma\/migrations\/[A-Za-z0-9_-]{1,200}\/migration\.sql$/);
    const name = file.split("/")[3];
    expected.set(name, hash(gitRun(["show", `${LEDGER.sourceSha}:${file}`], { encoding: null })));
  }
  return expected;
}

export function assertLedgerEvidence(value, { gitRun = createPinnedGitRunner() } = {}) {
  exact(value, ["kind", "sourceSha", "database", "databaseRole", "sessionRole", "readOnly", "rows", "evidenceSha256"]);
  const { evidenceSha256, ...body } = value;
  assert.equal(hash(JSON.stringify(body)), evidenceSha256);
  assert.equal(body.kind, "PRODUCTION_MIGRATION_LEDGER_READ_ONLY");
  assert.equal(body.sourceSha, LEDGER.runtimeSha);
  assert.equal(body.database, LEDGER.database);
  assert.equal(body.databaseRole, "mscqr_prd_rls_phase2_migration");
  assert.equal(body.sessionRole, "mscqr_prod_admin"); assert.equal(body.readOnly, true);
  const expected = d15MigrationChecksums(gitRun);
  assert.equal(expected.size, 57); assert.equal(body.rows?.length, expected.size);
  assert.equal(new Set(body.rows.map((row) => row.migration_name)).size, expected.size);
  for (const row of body.rows) {
    exact(row, ["migration_name", "checksum", "finished", "rolled_back"]);
    assert.equal(row.checksum, expected.get(row.migration_name));
    assert.equal(row.finished, true); assert.equal(row.rolled_back, false);
  }
  return body;
}

export function authenticateLedgerLogPages(pages, createdAt, stoppedAt) {
  const messages = collectCompleteRlsProbeLogEvents(pages);
  const events = pages.flatMap((page) => page.events);
  assert.equal(events.length, 1, "Ambiguous or missing ledger output");
  assert.ok(events.every((event) => Number.isFinite(event.timestamp)
    && event.timestamp >= Date.parse(createdAt) && event.timestamp <= Date.parse(stoppedAt)), "Ledger log event outside native task window");
  const evidence = JSON.parse(messages[0]);
  assertLedgerEvidence(evidence);
  return { evidence, logEventsSha256: hash(canonicalJson(events)) };
}

export async function waitForLedgerLogPages(readPage, { wait = sleep, attempts = 12 } = {}) {
  for (let attempt = 0; attempt < attempts; attempt++) {
    const pages = []; let token;
    try {
      for (let i = 0; i < 100; i++) {
        const page = readPage(token);
        pages.push({ ...page, requestToken: token });
        if (page.nextForwardToken === token) break;
        token = page.nextForwardToken;
        assert.equal(typeof token, "string");
        assert.ok(i < 99, "Truncated ledger log");
      }
      if (pages.flatMap((page) => page.events || []).length > 0) return pages;
    } catch (error) {
      if (!String(error.stderr || "").includes("ResourceNotFoundException")) throw error;
    }
    if (attempt + 1 < attempts) await wait(5000);
  }
  throw new Error("Ledger output absent after bounded read-only log polling");
}

export function assertLedgerReceipt(value, authorization, { toolingSourceSha, now = Date.now(), verify = createPinnedRootAttestationVerifier() } = {}) {
  const request = assertLedgerAuthorization(authorization, { toolingSourceSha, now, historical: true, verify });
  exact(value, ["body", "receiptSha256", "signatureBase64", "signingKeyAliasArn", "signingAlgorithm"]);
  const b = value.body;
  exact(b, ["kind", "sourceSha", "toolingSourceSha", "runtimeSourceSha", "authorizationSha256", "nonce", "startedBy", "taskArn", "taskDefinitionArn", "createdAt", "startedAt", "stoppedAt", "database", "evidence", "logEventsSha256"]);
  assert.equal(b.kind, "D15_FIXED_MIGRATION_LEDGER_READBACK_RECEIPT");
  assert.equal(b.sourceSha, LEDGER.sourceSha); assert.equal(b.toolingSourceSha, toolingSourceSha);
  assert.equal(b.runtimeSourceSha, LEDGER.runtimeSha); assert.equal(b.authorizationSha256, authorization.authorizationSha256);
  assert.equal(b.nonce, request.nonce); assert.equal(b.database, LEDGER.database);
  assert.equal(b.startedBy, ledgerStartedBy(request.nonce));
  assert.equal(b.taskDefinitionArn, LEDGER.taskDefinitionArn);
  assert.match(b.taskArn || "", taskArnPattern);
  assert.match(b.logEventsSha256 || "", /^[a-f0-9]{64}$/);
  const created = Date.parse(b.createdAt), started = Date.parse(b.startedAt), stopped = Date.parse(b.stoppedAt);
  assert.ok(created >= Date.parse(request.issuedAt) && created <= started && started <= stopped && stopped <= now && stopped < Date.parse(request.expiresAt));
  assertLedgerEvidence(b.evidence);
  assert.equal(value.receiptSha256, canonicalSha256(b));
  assert.equal(value.signingKeyAliasArn, ROOT_ATTESTATION_KEY_ALIAS_ARN);
  assert.equal(value.signingAlgorithm, ROOT_ATTESTATION_SIGNING_ALGORITHM);
  assert.ok(verify({ keyArn: value.signingKeyAliasArn, signingAlgorithm: value.signingAlgorithm,
    digest: Buffer.from(value.receiptSha256, "hex"), signature: Buffer.from(value.signatureBase64, "base64") }), "Invalid root KMS receipt signature");
  return b;
}

export function assertLedgerIntent(intent, authorization) {
  exact(intent, ["authorizationSha256", "nonce", "startedBy", "createdAt"]);
  assert.equal(intent.authorizationSha256, authorization.authorizationSha256);
  assert.equal(intent.nonce, authorization.body.nonce);
  assert.equal(intent.startedBy, ledgerStartedBy(intent.nonce));
  const at = Date.parse(intent.createdAt);
  assert.ok(at >= Date.parse(authorization.body.issuedAt) && at < Date.parse(authorization.body.expiresAt));
  return intent;
}

export function assertLedgerTaskRecord(value, authorization) {
  exact(value, ["taskArn", "authorizationSha256"]);
  assert.match(value.taskArn || "", taskArnPattern);
  assert.equal(value.authorizationSha256, authorization.authorizationSha256);
  return value.taskArn;
}

export function createPinnedGitRunner({ exec = execFileSync, env = process.env } = {}) {
  return (args, { encoding = "utf8" } = {}) => {
    assert.ok(encoding === "utf8" || encoding === null);
    return exec("/usr/bin/git", ["-C", root, "-c", "core.fsmonitor=false", ...args], { encoding, maxBuffer: 8 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"],
    env: { HOME: "/nonexistent", PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C", GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null", GIT_NO_REPLACE_OBJECTS: "1" } });
  };
}

export function assertProtectedToolingSource({ requireCurrentMain = true, gitRun = createPinnedGitRunner(), githubRun = createProductionGithubCommandRunner() } = {}) {
  assert.equal(fs.realpathSync(gitRun(["rev-parse", "--show-toplevel"]).trim()), fs.realpathSync(root));
  const sha = gitRun(["rev-parse", "HEAD"]).trim();
  assert.match(sha, /^[a-f0-9]{40}$/);
  assert.equal(gitRun(["status", "--porcelain=v1", "--untracked-files=all"]).trim(), "");
  gitRun(["merge-base", "--is-ancestor", LEDGER.sourceSha, sha]);
  if (requireCurrentMain) {
    const current = JSON.parse(githubRun("gh", ["api", "repos/T-ej2003/genuine-scan-main/branches/main"]));
    assert.equal(current.name, "main");
    assert.equal(current._links?.self, "https://api.github.com/repos/T-ej2003/genuine-scan-main/branches/main");
    assert.equal(current.commit?.url, `https://api.github.com/repos/T-ej2003/genuine-scan-main/commits/${sha}`);
    assert.equal(current.commit?.sha, sha, "Tooling must be exact protected main");
  }
  return sha;
}

export function assertRootIdentity(id) {
  assert.equal(id?.Account, "368992683803"); assert.equal(id.Arn, "arn:aws:iam::368992683803:root");
  return true;
}

function rootRunner() {
  assertRootIdentity(awsJson(["sts", "get-caller-identity"]));
  authenticateRootAttestationKey({ run: aws });
  return aws;
}

function sign(body, label) {
  const digest = canonicalSha256(body);
  const signer = createRootAttestationKmsSigner({ run: createProductionAwsCommandRunner({ credentialSource: "named-profile",
    profile: "default", singleAttemptKmsSign: true, exec: createPinnedAwsExecutor() }) });
  const signatureBase64 = signer({ digest: Buffer.from(digest, "hex") });
  assert.match(signatureBase64 || "", /^[A-Za-z0-9+/]+={0,2}$/);
  return { body, [label]: digest, signatureBase64, signingKeyAliasArn: ROOT_ATTESTATION_KEY_ALIAS_ARN,
    signingAlgorithm: ROOT_ATTESTATION_SIGNING_ALGORITHM };
}

async function completeLedgerReadback({ authorization, request, toolingSourceSha, receiptPath, taskArn, intent }) {
  let task;
  for (let i = 0; i < 60; i++) {
    const result = awsJson(["ecs", "describe-tasks", "--cluster", LEDGER.cluster, "--tasks", taskArn]);
    assert.deepEqual(result.failures || [], []); assert.equal(result.tasks?.length, 1);
    task = result.tasks[0];
    if (task.lastStatus === "STOPPED") break;
    await sleep(5000);
  }
  assert.equal(task?.lastStatus, "STOPPED"); assert.equal(task.stopCode, "EssentialContainerExited");
  assert.equal(task.taskArn, taskArn); assert.equal(task.startedBy, intent.startedBy);
  assert.equal(task.taskDefinitionArn, LEDGER.taskDefinitionArn);
  assert.equal(task.clusterArn, LEDGER.cluster); assert.equal(task.launchType, "FARGATE");
  assert.equal(task.containers?.length, 1); assert.equal(task.containers[0].exitCode, 0);
  const { createdAt, startedAt, stoppedAt } = task;
  assert.ok(Date.parse(createdAt) >= Date.parse(intent.createdAt) && Date.parse(stoppedAt) < Date.parse(request.expiresAt));
  const stream = `${LEDGER.logPrefix}/production-c02-session-prerequisite/${taskArn.split("/").at(-1)}`;
  const pages = await waitForLedgerLogPages((token) => awsJson(["logs", "get-log-events", "--log-group-name", LEDGER.logGroup,
    "--log-stream-name", stream, "--start-from-head", "--limit", "10000", ...(token ? ["--next-token", token] : [])]));
  const { evidence, logEventsSha256 } = authenticateLedgerLogPages(pages, createdAt, stoppedAt);
  const body = { kind: "D15_FIXED_MIGRATION_LEDGER_READBACK_RECEIPT", sourceSha: LEDGER.sourceSha, toolingSourceSha,
    runtimeSourceSha: LEDGER.runtimeSha, authorizationSha256: authorization.authorizationSha256, nonce: request.nonce,
    startedBy: intent.startedBy, taskArn, taskDefinitionArn: LEDGER.taskDefinitionArn, createdAt, startedAt, stoppedAt,
    database: LEDGER.database, evidence, logEventsSha256 };
  write(`${receiptPath}.sign-intent`, { receiptSha256: canonicalSha256(body), taskArn });
  const receipt = sign(body, "receiptSha256");
  assertLedgerReceipt(receipt, authorization, { toolingSourceSha });
  write(receiptPath, receipt);
  return { status: "VERIFIED", receiptSha256: receipt.receiptSha256 };
}

async function main(mode, authPath, receiptPath) {
  assert.ok(["authorize", "run", "recover", "verify"].includes(mode));
  assert.ok(path.isAbsolute(authPath) && (!receiptPath || path.isAbsolute(receiptPath)));
  const toolingSourceSha = assertProtectedToolingSource({ requireCurrentMain: mode === "authorize" || mode === "run" });
  if (mode === "authorize") {
    assert.equal(receiptPath, undefined);
    assert.equal(fs.existsSync(authPath), false, "Authorization destination already exists");
    rootRunner();
    assertFixedLedgerDefinition(awsJson(["ecs", "describe-task-definition", "--task-definition", LEDGER.taskDefinitionArn]).taskDefinition);
    const issuedAt = new Date().toISOString();
    const body = { kind: "D15_FIXED_MIGRATION_LEDGER_READBACK_AUTHORIZATION", sourceSha: LEDGER.sourceSha, toolingSourceSha,
      runtimeSourceSha: LEDGER.runtimeSha, database: LEDGER.database, taskDefinitionArn: LEDGER.taskDefinitionArn,
      imageDigest: LEDGER.imageDigest, commandSha256: LEDGER.commandSha256, nonce: crypto.randomBytes(32).toString("hex"),
      issuedAt, expiresAt: new Date(Date.parse(issuedAt) + 15 * 60_000).toISOString() };
    const authorization = sign(body, "authorizationSha256");
    assertLedgerAuthorization(authorization, { toolingSourceSha });
    write(authPath, authorization);
    return { status: "AUTHORIZED", authorizationSha256: authorization.authorizationSha256 };
  }
  assert.ok(receiptPath);
  assert.notEqual(path.resolve(authPath), path.resolve(receiptPath));
  const authorization = read(authPath);
  const request = assertLedgerAuthorization(authorization, { toolingSourceSha,
    ...(mode === "run" ? { minimumRemainingMs: 7 * 60_000 } : { historical: true }) });
  if (mode === "verify") {
    const receipt = read(receiptPath);
    assertLedgerReceipt(receipt, authorization, { toolingSourceSha });
    return { status: "VERIFIED", receiptSha256: receipt.receiptSha256 };
  }
  rootRunner();
  assertFixedLedgerDefinition(awsJson(["ecs", "describe-task-definition", "--task-definition", LEDGER.taskDefinitionArn]).taskDefinition);
  const intentPath = `${receiptPath}.intent`;
  assert.equal(fs.existsSync(receiptPath), false, "Receipt already exists");
  if (mode === "recover") {
    const intent = assertLedgerIntent(read(intentPath), authorization);
    assert.equal(fs.existsSync(`${receiptPath}.sign-intent`), false, "KMS receipt signing already attempted; inspect audit before retry");
    assert.ok(fs.existsSync(`${receiptPath}.task`), "Task identity missing; reconcile RunTask via CloudTrail before any new authorization");
    const taskArn = assertLedgerTaskRecord(read(`${receiptPath}.task`), authorization);
    return completeLedgerReadback({ authorization, request, toolingSourceSha, receiptPath, taskArn, intent });
  }
  const intent = { authorizationSha256: authorization.authorizationSha256, nonce: request.nonce,
    startedBy: ledgerStartedBy(request.nonce), createdAt: new Date().toISOString() };
  assertLedgerIntent(intent, authorization);
  for (const file of [intentPath, `${receiptPath}.task`, `${receiptPath}.sign-intent`])
    assert.equal(fs.existsSync(file), false, "Existing execution evidence requires read-only recovery");
  write(intentPath, intent);
  const launch = { cluster: LEDGER.cluster, taskDefinition: LEDGER.taskDefinitionArn, launchType: "FARGATE", count: 1,
    enableExecuteCommand: false, clientToken: authorization.authorizationSha256, startedBy: intent.startedBy,
    networkConfiguration: appOnlyVerifierNetwork() };
  const response = awsJson(["ecs", "run-task", "--cli-input-json", JSON.stringify(launch)]);
  assert.deepEqual(response.failures || [], []); assert.equal(response.tasks?.length, 1);
  const taskArn = response.tasks[0].taskArn;
  assert.match(taskArn || "", taskArnPattern);
  write(`${receiptPath}.task`, { taskArn, authorizationSha256: authorization.authorizationSha256 });
  return completeLedgerReadback({ authorization, request, toolingSourceSha, receiptPath, taskArn, intent });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    assert.ok(process.argv.length === 4 || process.argv.length === 5);
    console.log(JSON.stringify(await main(...process.argv.slice(2))));
  } catch (error) {
    console.error(`D15 fixed ledger readback failed closed: ${error.message}`);
    process.exitCode = 1;
  }
}
