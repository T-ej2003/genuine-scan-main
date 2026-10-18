import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { APP_ONLY } from "../aws/production-app-only-contract.mjs";
import { APP_ONLY_VERIFIER, appOnlyVerifierNetwork } from "../aws/production-app-only-policy.mjs";
import { createAppOnlyRequirements } from "../aws/production-app-only-requirements.mjs";
import { buildAppOnlyVerifierDefinition } from "../aws/production-app-only-verifier-command.mjs";
import { canonicalSha256 } from "../aws/production-green-stage-b-contract.mjs";
import { authenticateFailedAppOnlyVerifierTask, readFailedAppOnlyVerifierDiagnostic,
  waitForFailedAppOnlyVerifierDiagnostic } from "../aws/production-app-only-verifier-diagnostic.mjs";
import { diagnosticReadOnlyAws, parseAppOnlyDiagnosticArgs } from "../aws/read-production-app-only-verifier-diagnostic.mjs";

const sourceSha = "a".repeat(40), currentSourceSha = "b".repeat(40);
const taskArn = `arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task/mscqr-prod-euw2-main/${"c".repeat(32)}`;
const definitionArn = `arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task-definition/${APP_ONLY_VERIFIER.family}:20`;

function fixture() {
  const identity = { sourceSha, candidateSourceSha: "d".repeat(40), candidateDigest: `sha256:${"1".repeat(64)}`,
    account: APP_ONLY.account, region: APP_ONLY.region, clusterArn: APP_ONLY.clusterArn, serviceArn: APP_ONLY.serviceArn,
    predecessorTaskDefinition: `arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task-definition/${APP_ONLY.family}:24`,
    predecessorBackendDigest: `sha256:${"2".repeat(64)}`, verifierImageDigest: `sha256:${"3".repeat(64)}`,
    databaseHostname: "reviewed.eu-west-2.rds.amazonaws.com" };
  const requirements = createAppOnlyRequirements({ repositoryRoot: process.cwd(), sourceSha,
    candidateSourceSha: identity.candidateSourceSha, packageChecksums: { fixture: true },
    catalogue: { routines: [{ schema: "app_auth", name: "fixed", arguments: "" }], tables: [{ name: "Example" }],
      policies: [{ table: "Example", name: "isolation" }], schemas: [{ name: "app_auth" }], roles: [{ name: "mscqr_prod_rls_canary_read" }] } });
  const databaseSecretArn = `arn:aws:secretsmanager:${APP_ONLY.region}:${APP_ONLY.account}:secret:${APP_ONLY_VERIFIER.databaseSecretName}-ABC123`;
  const definition = buildAppOnlyVerifierDefinition({ requirements, identity, repositoryRoot: process.cwd(), databaseSecretArn });
  const body = { schemaVersion: 1, kind: "APP_ONLY_VERIFIER_PREPARATION", sourceSha, eligible: false,
    identity, databaseSecretArn, predecessor: { taskDefinitionArn: identity.predecessorTaskDefinition },
    definitionSha256: canonicalSha256(definition.definition), verificationContractSha256: definition.verificationContractSha256,
    evidence: { requirements: requirements.requirementsSha256 }, networkSha256: canonicalSha256(appOnlyVerifierNetwork()) };
  const preparation = { ...body, preparationSha256: canonicalSha256(body) };
  const inputs = { schemaVersion: 1, kind: "APP_ONLY_VERIFIER_INPUTS", preparation, requirements };
  const chain = (kind, prepSha, events, execution = false) => {
    let previousSha256 = null;
    return events.map((event, index) => {
      const body = { schemaVersion: 1, kind: "APP_ONLY_EXECUTION_JOURNAL", sourceSha, preparationSha256: prepSha,
        sequence: index + 1, previousSha256, event: { schemaVersion: 1, kind,
          ...(execution ? {} : { sourceSha, preparationSha256: prepSha }), ...event } };
      const evidenceSha256 = canonicalSha256(body); previousSha256 = evidenceSha256;
      return { ...body, evidenceSha256 };
    });
  };
  const registration = chain("APP_ONLY_VERIFIER_REGISTRATION", preparation.preparationSha256, [
    { status: "REGISTRATION_INTENT" }, { status: "REGISTERED_READBACK_PENDING", taskDefinitionArn: definitionArn },
    { status: "REGISTERED_VERIFIED", taskDefinitionArn: definitionArn,
      definitionSha256: preparation.definitionSha256, verificationContractSha256: preparation.verificationContractSha256 }]);
  const permission = chain("APP_ONLY_PERMISSION_RESULT", "e".repeat(64), [
    { status: "PRE_MUTATION", writesAttempted: 0 },
    { status: "PUT_POLICY_INTENT", writesAttempted: 0, roleArn: `arn:aws:iam::${APP_ONLY.account}:role/${APP_ONLY_VERIFIER.roleName}` },
    { status: "VERIFIED", writesAttempted: 1, effective: { verified: true } }]);
  const fixed = { taskDefinitionArn: definitionArn, clientToken: canonicalSha256({ sourceSha, preparationSha256: preparation.preparationSha256 }),
    verificationContractSha256: preparation.verificationContractSha256 };
  const execution = chain("APP_ONLY_VERIFIER_EXECUTION", preparation.preparationSha256, [
    { status: "LAUNCH_INTENT", ...fixed }, { status: "LAUNCHED", ...fixed, taskArn },
    { status: "TASK_OUTCOME_REQUIRES_READBACK", ...fixed, taskArn }], true);
  const task = { taskArn, taskDefinitionArn: definitionArn, clusterArn: APP_ONLY.clusterArn, lastStatus: "STOPPED",
    stopCode: "EssentialContainerExited", enableExecuteCommand: false,
    containers: [{ name: "production-green-read-only-rls-canary", exitCode: 1, imageDigest: identity.verifierImageDigest }] };
  const calls = [];
  const run = diagnosticReadOnlyAws((args) => {
    calls.push(args);
    if (args[1] === "describe-task-definition") return JSON.stringify({ taskDefinition: { ...definition.definition,
      taskDefinitionArn: definitionArn, revision: 20, status: "ACTIVE" }, tags: [] });
    if (args[1] === "describe-tasks") return JSON.stringify({ tasks: [task], failures: [] });
    if (args[1] === "get-log-events") return JSON.stringify({ events: args.includes("--next-token") ? []
      : [{ message: JSON.stringify({ status: "APP_ONLY_DATABASE_VERIFICATION_FAILED", phase: "CATALOGUE",
        operation: "SUBSCRIPTION_PROJECTION_MISSING" }) }], nextForwardToken: "end" });
    assert.fail(`Unexpected AWS action ${args[1]}`);
  });
  const options = { inputs, registration, permission, execution, taskArn, run, repositoryRoot: process.cwd() };
  return { options, calls, task, inputs };
}

test("authenticated existing exit-1 task yields only its bounded catalogue code without a mutation", () => {
  const { options, calls, inputs } = fixture();
  const authenticated = authenticateFailedAppOnlyVerifierTask(options);
  const diagnostic = readFailedAppOnlyVerifierDiagnostic({ run: options.run, authenticated, inputs });
  assert.deepEqual({ verdict: diagnostic.verdict, phase: diagnostic.phase, operation: diagnostic.operation },
    { verdict: "FAIL", phase: "CATALOGUE", operation: "SUBSCRIPTION_PROJECTION_MISSING" });
  assert.equal(authenticated.stream, `app-only/production-green-read-only-rls-canary/${"c".repeat(32)}`);
  assert.ok(calls.every(([service, action]) => service === "ecs" && ["describe-task-definition", "describe-tasks"].includes(action)
    || service === "logs" && action === "get-log-events"));
  assert.throws(() => diagnosticReadOnlyAws(() => "")(["ecs", "run-task"]), /no AWS mutation/);
  assert.throws(() => diagnosticReadOnlyAws(() => "")(["ecs", "register-task-definition"]), /no AWS mutation/);
});

test("wrong source, task, definition, image, exit code and malformed journals fail before log read", () => {
  for (const mutate of [
    (f) => { f.options.taskArn = f.options.taskArn.replace(/c{32}$/, "f".repeat(32)); },
    (f) => { f.options.registration.pop(); },
    (f) => { f.options.execution[2].event.taskArn = taskArn.replace(/c{32}$/, "f".repeat(32)); },
    (f) => { f.options.execution[2].previousSha256 = "0".repeat(64); },
    (f) => { f.options.inputs.preparation.sourceSha = "f".repeat(40); },
    (f) => { f.task.taskDefinitionArn = definitionArn.replace(/:20$/, ":21"); },
    (f) => { f.task.containers[0].imageDigest = `sha256:${"f".repeat(64)}`; },
    (f) => { f.task.containers[0].exitCode = 0; },
  ]) {
    const f = fixture(); mutate(f);
    assert.throws(() => authenticateFailedAppOnlyVerifierTask(f.options));
    assert.ok(f.calls.every(([, action]) => action !== "get-log-events"));
  }
});

test("wrong stream, absent or extra output, secret-shaped fields and denied access fail closed", () => {
  for (const message of [null, "not json", JSON.stringify({ status: "APP_ONLY_DATABASE_VERIFICATION_FAILED", phase: "CATALOGUE", operation: "IDENTITY", secret: "x" }),
    JSON.stringify({ status: "APP_ONLY_DATABASE_VERIFICATION_FAILED", phase: "CATALOGUE" })]) {
    const f = fixture(), authenticated = authenticateFailedAppOnlyVerifierTask(f.options);
    const run = diagnosticReadOnlyAws((args) => args[1] === "get-log-events"
      ? JSON.stringify({ events: message === null ? [] : [{ message }], nextForwardToken: "end" }) : f.options.run(args));
    assert.throws(() => readFailedAppOnlyVerifierDiagnostic({ run, authenticated, inputs: f.inputs }));
  }
  const f = fixture(), authenticated = authenticateFailedAppOnlyVerifierTask(f.options);
  const denied = diagnosticReadOnlyAws((args) => { if (args[1] === "get-log-events") throw new Error("AccessDenied"); return f.options.run(args); });
  assert.throws(() => readFailedAppOnlyVerifierDiagnostic({ run: denied, authenticated, inputs: f.inputs }), /AccessDenied/);
  authenticated.stream += "-wrong";
  assert.throws(() => readFailedAppOnlyVerifierDiagnostic({ run: f.options.run, authenticated, inputs: f.inputs }));
});
test("fresh failed task waits for one bounded log event, but never retries access denial", async () => {
  const f = fixture(), authenticated = authenticateFailedAppOnlyVerifierTask(f.options);
  let reads = 0, waits = 0;
  const delayed = diagnosticReadOnlyAws((args) => args[1] === "get-log-events" && ++reads === 1
    ? JSON.stringify({ events: [], nextForwardToken: "end" }) : f.options.run(args));
  const result = await waitForFailedAppOnlyVerifierDiagnostic({ run: delayed, authenticated, inputs: f.inputs,
    wait: async (ms) => { assert.equal(ms, 5000); waits++; } });
  assert.equal(result.verdict, "FAIL"); assert.equal(waits, 1);
  let missingStreamReads = 0;
  const pendingStream = diagnosticReadOnlyAws((args) => {
    if (args[1] === "get-log-events" && ++missingStreamReads === 1) {
      const error = new Error("AWS command failed");
      error.stderr = "An error occurred (ResourceNotFoundException) when calling the GetLogEvents operation: The specified log stream does not exist.";
      throw error;
    }
    return f.options.run(args);
  });
  assert.equal((await waitForFailedAppOnlyVerifierDiagnostic({ run: pendingStream, authenticated, inputs: f.inputs,
    wait: async () => { waits++; } })).verdict, "FAIL");
  assert.equal(missingStreamReads, 3); assert.equal(waits, 2);
  await assert.rejects(waitForFailedAppOnlyVerifierDiagnostic({ run: diagnosticReadOnlyAws((args) => {
    if (args[1] === "get-log-events") throw new Error("AccessDenied"); return f.options.run(args);
  }), authenticated, inputs: f.inputs, wait: async () => { assert.fail("Denied reads cannot retry"); } }), /AccessDenied/);
  await assert.rejects(waitForFailedAppOnlyVerifierDiagnostic({ run: diagnosticReadOnlyAws((args) => {
    if (args[1] === "get-log-events") {
      const error = new Error("AWS command failed"); error.stderr = "An error occurred (AccessDeniedException) when calling the GetLogEvents operation:";
      throw error;
    }
    return f.options.run(args);
  }), authenticated, inputs: f.inputs, wait: async () => { assert.fail("Denied reads cannot retry"); } }), /AWS command failed/);
});

test("protected diagnostic mode is separate from registration and requires exact workflow identity", () => {
  const workflow = fs.readFileSync(".github/workflows/verify-production-app-only-compatibility-operation.yml", "utf8");
  assert.match(workflow, /verify:\n    if: inputs\.diagnostic_journal_reference == ''/);
  assert.match(workflow, /diagnostic:\n    if: inputs\.diagnostic_journal_reference != '' && inputs\.recovery_journal_reference == ''/);
  assert.match(workflow, /environment: production/);
  assert.match(workflow, /read-production-app-only-verifier-diagnostic\.mjs/);
  const env = { GITHUB_ACTIONS: "true", GITHUB_REPOSITORY: "T-ej2003/genuine-scan-main", GITHUB_REF: "refs/heads/main",
    GITHUB_EVENT_NAME: "workflow_dispatch", GITHUB_WORKFLOW_REF: "T-ej2003/genuine-scan-main/.github/workflows/verify-production-app-only-compatibility.yml@refs/heads/main",
    GITHUB_RUN_ATTEMPT: "1", GITHUB_RUN_ID: "123", GITHUB_SHA: currentSourceSha };
  const prep = { sourceSha, runId: "1", runAttempt: "1", artifactId: "2", artifactDigest: `sha256:${"1".repeat(64)}`, fileSha256: "2".repeat(64) };
  const journal = { sourceSha, runId: "3", artifactId: "4", artifactDigest: `sha256:${"3".repeat(64)}`,
    registrationJournalSha256: "4".repeat(64), permissionJournalSha256: "5".repeat(64), executionJournalSha256: "6".repeat(64), taskArn };
  const args = ["--source-sha", currentSourceSha, "--preparation-reference", JSON.stringify(prep),
    "--diagnostic-journal-reference", JSON.stringify(journal), "--approval", "/tmp/approval.json", "--approval-sha256", "7".repeat(64)];
  assert.equal(parseAppOnlyDiagnosticArgs(args, env).journalReference.taskArn, taskArn);
  assert.throws(() => parseAppOnlyDiagnosticArgs(args, { ...env, GITHUB_WORKFLOW_REF: "feature" }));
});
