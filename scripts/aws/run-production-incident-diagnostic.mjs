#!/usr/bin/env node
// Fixed one-use November 12 diagnostic; execution requires the protected environment artifact.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { APP_ONLY } from "./production-app-only-contract.mjs";
import { appOnlyVerifierNetwork } from "./production-app-only-policy.mjs";
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { readFreshProtectedMainIdentity } from "./stage-b-deployment-identity.mjs";
import { canonicalJson, canonicalSha256 } from "./stage-b-task-definition-recovery-contract.mjs";
import { incidentTaskDefinition, resolveIncidentDiagnosticAuthorization } from "./production-incident-diagnostic-authorization.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const account = "368992683803";
const region = "eu-west-2";
const cluster = "mscqr-prod-euw2-main";
const bucket = "mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an";
const executionRole = "mscqr-production-full-rls-green-executor-execution";
const taskRole = "mscqr-production-full-rls-green-read-only-canary-task";
const secretPolicyName = "mscqr-incident-20261112-exact-canary-secret";
const journalPolicyName = "mscqr-incident-20261112-exact-journal";
const expectedCaller = `arn:aws:iam::${account}:user/mscqr-ops-admin`;
const json = (value) => `${JSON.stringify(value)}\n`;

export async function executeIncidentDiagnostic({ authorization, aws, protectedMain = readFreshProtectedMainIdentity,
  cleanCheckout = () => !execFileSync("git", ["status", "--porcelain=v1", "--untracked-files=all"], { cwd: root, encoding: "utf8" }).trim(),
  waitForStopped, readTerminal, now = () => new Date() } = {}) {
  assert.ok(authorization && aws && waitForStopped && readTerminal);
  protectedMain({ cwd: root, expectedSourceSha: authorization.diagnosticSourceSha });
  if (!cleanCheckout()) throw new Error("Diagnostic execution requires a clean protected-main checkout.");
  const call = (args) => aws(args);
  const caller = call(["sts", "get-caller-identity"]);
  assert.equal(caller.Account, account);
  assert.equal(caller.Arn, expectedCaller);
  if (now().getTime() >= Date.parse(authorization.expiresAt)) throw new Error("Diagnostic authorization expired before AWS mutation.");
  const image = call(["ecr", "describe-images", "--registry-id", account, "--repository-name", "mscqr-backend",
    "--image-ids", `imageTag=${authorization.diagnosticSourceSha}-backend-only`]).imageDetails;
  assert.equal(image?.length, 1);
  assert.equal(`sha256:${image[0].imageDigest.replace(/^sha256:/, "")}`, authorization.image);
  const instance = call(["rds", "describe-db-instances", "--db-instance-identifier", authorization.databaseInstance]).DBInstances;
  assert.equal(instance?.length, 1);
  assert.equal(instance[0].DbiResourceId, authorization.databaseResourceId);
  assert.equal(instance[0].EngineVersion, authorization.databaseVersion);
  assert.equal(instance[0].Endpoint.Address, authorization.databaseHostname);
  assert.equal(instance[0].DBInstanceStatus, "available");
  const service = call(["ecs", "describe-services", "--cluster", cluster, "--services", APP_ONLY.service]);
  assert.deepEqual(service.failures || [], []);
  assert.equal(service.services?.length, 1);
  assert.equal(service.services[0].runningCount, service.services[0].desiredCount);
  const current = call(["ecs", "describe-task-definition", "--task-definition", service.services[0].taskDefinition]).taskDefinition;
  assert.ok(current.containerDefinitions?.some((container) => container.secrets?.some((secret) =>
    secret.name === "DATABASE_URL" && secret.valueFrom?.startsWith(`arn:aws:secretsmanager:${region}:${account}:secret:mscqr/production/rls-green/phase2/`))));
  const policy = (role, name) => {
    try { return call(["iam", "get-role-policy", "--role-name", role, "--policy-name", name]).PolicyDocument; }
    catch (error) { if (String(error.stderr || "").includes("NoSuchEntity")) return null; throw error; }
  };
  if (policy(executionRole, secretPolicyName) || policy(taskRole, journalPolicyName)) throw new Error("Incident diagnostic IAM capability already exists; no overwrite allowed.");
  const definition = incidentTaskDefinition(authorization);
  assert.equal(canonicalSha256(definition), authorization.taskDefinitionSha256);
  const installed = [];
  let attemptedRun = false;
  let runRejected = false;
  let stopped = false;
  let taskArn = null;
  let terminal = null;
  let terminalSha256 = null;
  try {
    for (const [role, name, document] of [[executionRole, secretPolicyName, authorization.executionSecretPolicy],
      [taskRole, journalPolicyName, authorization.journalPolicy]]) {
      if (now().getTime() >= Date.parse(authorization.expiresAt)) throw new Error("Diagnostic approval expired during capability installation.");
      installed.push([role, name, document]);
      call(["iam", "put-role-policy", "--role-name", role, "--policy-name", name, "--policy-document", JSON.stringify(document)]);
      assert.equal(canonicalJson(policy(role, name)), canonicalJson(document), "Installed IAM capability differs from the reviewed document.");
    }
    const registered = call(["ecs", "register-task-definition", "--cli-input-json", JSON.stringify(definition)]).taskDefinition;
    assert.match(registered?.taskDefinitionArn || "", new RegExp(`^arn:aws:ecs:${region}:${account}:task-definition/${definition.family}:[1-9][0-9]*$`));
    assert.equal(registered.containerDefinitions?.[0]?.image, definition.containerDefinitions[0].image);
    assert.equal(registered.containerDefinitions?.[0]?.entryPoint?.join(" "), definition.containerDefinitions[0].entryPoint.join(" "));
    assert.equal(registered.executionRoleArn, definition.executionRoleArn);
    assert.equal(registered.taskRoleArn, definition.taskRoleArn);
    assert.deepEqual(registered.containerDefinitions?.[0]?.secrets, definition.containerDefinitions[0].secrets);
    assert.deepEqual(registered.containerDefinitions?.[0]?.environment, definition.containerDefinitions[0].environment);
    assert.equal(registered.containerDefinitions?.[0]?.readonlyRootFilesystem, true);
    assert.deepEqual(registered.containerDefinitions?.[0]?.logConfiguration, definition.containerDefinitions[0].logConfiguration);
    const request = { cluster: APP_ONLY.clusterArn, taskDefinition: registered.taskDefinitionArn, launchType: "FARGATE",
      count: 1, enableExecuteCommand: false, clientToken: canonicalSha256({ authorizationSha256: authorization.authorizationSha256,
        taskDefinitionArn: registered.taskDefinitionArn }), networkConfiguration: appOnlyVerifierNetwork() };
    if (now().getTime() >= Date.parse(authorization.expiresAt)) throw new Error("Diagnostic approval expired before task launch.");
    attemptedRun = true;
    const launched = call(["ecs", "run-task", "--cli-input-json", JSON.stringify(request)]);
    runRejected = Array.isArray(launched.tasks) && launched.tasks.length === 0;
    assert.deepEqual(launched.failures || [], []);
    assert.equal(launched.tasks?.length, 1);
    taskArn = launched.tasks[0].taskArn;
    assert.match(taskArn || "", new RegExp(`^arn:aws:ecs:${region}:${account}:task/${cluster}/[a-f0-9]{32}$`));
    await waitForStopped(taskArn);
    stopped = true;
    const observed = call(["ecs", "describe-tasks", "--cluster", cluster, "--tasks", taskArn]);
    assert.deepEqual(observed.failures || [], []);
    assert.equal(observed.tasks?.length, 1);
    assert.equal(observed.tasks[0].lastStatus, "STOPPED");
    assert.equal(observed.tasks[0].taskDefinitionArn, registered.taskDefinitionArn);
    const captured = await readTerminal(authorization);
    terminal = captured.terminal;
    terminalSha256 = captured.sha256;
    const taskInputSha256 = createHash("sha256").update(`${definition.containerDefinitions[0].environment[0].value}\n`).digest("hex");
    if (terminal.kind !== "INCIDENT_DIAGNOSTIC_TERMINAL" || terminal.status !== "COMPLETE"
        || terminal.executionId !== authorization.executionId || terminal.sourceSha !== authorization.sourceSha
        || terminal.diagnosticSourceSha !== authorization.diagnosticSourceSha
        || terminal.provisionSha256 !== authorization.provisionSha256 || terminal.querySha256 !== authorization.querySha256
        || terminal.teardownSha256 !== authorization.teardownSha256 || terminal.database !== authorization.database
        || terminal.taskInputSha256 !== taskInputSha256
        || observed.tasks[0].containers?.[0]?.exitCode !== 0) throw new Error("Diagnostic task or terminal receipt is incomplete.");
  } finally {
    // An ambiguous RunTask or unstopped task keeps the expiring capability in place for forensic review.
    if (!attemptedRun || runRejected || stopped) for (const [role, name, document] of installed.reverse()) {
      const found = policy(role, name);
      if (!found) continue;
      assert.equal(canonicalJson(found), canonicalJson(document), "IAM cleanup target differs from the reviewed document.");
      call(["iam", "delete-role-policy", "--role-name", role, "--policy-name", name]);
      if (policy(role, name)) throw new Error("Diagnostic IAM capability cleanup failed.");
    }
  }
  return { status: "COMPLETE", taskArn, terminalKey: `production-incident-20261112/${authorization.executionId}/terminal.json`,
    terminalSha256, authorizationSha256: authorization.authorizationSha256 };
}

async function main(argv = process.argv.slice(2)) {
  const [sourceSha, runId, attempt, profile] = argv;
  if (argv.length !== 4 || profile !== "mscqr-ops-admin") throw new Error("Exact source, authorization run/attempt, and mscqr-ops-admin profile are required.");
  const { authorization } = await resolveIncidentDiagnosticAuthorization({ runId, attempt, sourceSha });
  const runner = createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile, region });
  const aws = (args) => { const output = runner([...args, "--output", "json", "--no-cli-pager"]).trim(); return output ? JSON.parse(output) : {}; };
  const waitForStopped = async (taskArn) => runner(["ecs", "wait", "tasks-stopped", "--cluster", cluster, "--tasks", taskArn, "--no-cli-pager"]);
  const readTerminal = (approved) => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-incident-receipt-"));
    const output = path.join(directory, "terminal.json");
    try {
      runner(["s3api", "get-object", "--bucket", bucket, "--key", `production-incident-20261112/${approved.executionId}/terminal.json`, output, "--no-cli-pager"]);
      const bytes = fs.readFileSync(output);
      return { terminal: JSON.parse(bytes.toString("utf8")), sha256: createHash("sha256").update(bytes).digest("hex") };
    } finally { fs.rmSync(directory, { recursive: true, force: true }); }
  };
  const result = await executeIncidentDiagnostic({ authorization, aws, waitForStopped, readTerminal });
  process.stdout.write(json(result));
}

if (import.meta.url === new URL(process.argv[1], "file:").href) main().catch(() => {
  process.stderr.write(json({ status: "BLOCKED_OR_INDETERMINATE", reason: "incident-diagnostic-failed-closed" }));
  process.exitCode = 1;
});
