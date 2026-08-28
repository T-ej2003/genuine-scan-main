import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import test from "node:test";
import JSZip from "jszip";
import { buildStageAApprovalKeyPolicy } from "../aws/production-stage-a-control-plane.mjs";
import { createProductionEnvironmentApprovalEvidence, PRODUCTION_ENVIRONMENT_APPROVAL } from "../aws/production-github-environment-approval.mjs";
import { assertStageAApprovalKeyReconciliationAuthorization, assertStageAApprovalKeyReconciliationPlan, createStageAApprovalKeyReconciliationAuthorization, executeStageAApprovalKeyReconciliation, materializeStageAReconciliationPlan, resolveStageAReconciliationAuthorizationArtifact, runCli, STAGE_A_RECONCILIATION_AUTHORIZATION } from "../aws/production-stage-a-approval-key-reconciliation-authorization.mjs";
import { canonicalSha256 } from "../aws/stage-b-task-definition-recovery-contract.mjs";
import { stageAStateSemanticSha256 } from "../aws/generate-production-green-stage-a-prerequisites.mjs";

const sha = (value) => crypto.createHash("sha256").update(value).digest("hex");
const sourceSha = "e".repeat(40);
const keyArn = "arn:aws:kms:eu-west-2:368992683803:key/437cdebd-95e7-4aba-8f0f-2ca08edb0478";
const beforePolicy = { Version: "2012-10-17", Statement: buildStageAApprovalKeyPolicy().Statement.filter(({ Sid }) => Sid !== "DenyNonCheckerApprovalSigning") };
const afterPolicy = buildStageAApprovalKeyPolicy();
const approvalEvidence = () => createProductionEnvironmentApprovalEvidence({ repository: "T-ej2003/genuine-scan-main", environment: "production", sourceSha, workflowRef: PRODUCTION_ENVIRONMENT_APPROVAL.stageAReconciliationWorkflowRef, eventName: "workflow_dispatch", workflowRunId: "1", workflowRunAttempt: "1", executionActor: "operator", observedAt: "2026-08-28T12:00:00.000Z", environmentConfig: { id: 1, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: { id: 1, login: "reviewer" } }] }] } });
const plan = ({ before = {}, after = {}, ...metadata } = {}) => ({ resource_changes: [{ address: "aws_kms_key.approval", type: "aws_kms_key", change: { actions: ["update"], before: { arn: keyArn, bypass_policy_lockout_safety_check: false, custom_key_store_id: "", customer_master_key_spec: "RSA_3072", deletion_window_in_days: 30, description: "Independent production RLS approval signing key", enable_key_rotation: false, id: "437cdebd-95e7-4aba-8f0f-2ca08edb0478", is_enabled: true, key_id: "437cdebd-95e7-4aba-8f0f-2ca08edb0478", key_usage: "SIGN_VERIFY", multi_region: false, region: "eu-west-2", rotation_period_in_days: 0, tags: { Component: "full-rls-green-stage-a", Environment: "production", ManagedBy: "Terraform", Stack: "production-green-stage-a" }, tags_all: { Component: "full-rls-green-stage-a", Environment: "production", ManagedBy: "Terraform", Stack: "production-green-stage-a" }, timeouts: null, xks_key_id: "", policy: JSON.stringify(beforePolicy), ...before }, after: { arn: keyArn, bypass_policy_lockout_safety_check: false, custom_key_store_id: "", customer_master_key_spec: "RSA_3072", deletion_window_in_days: 30, description: "Independent production RLS approval signing key", enable_key_rotation: false, id: "437cdebd-95e7-4aba-8f0f-2ca08edb0478", is_enabled: true, key_id: "437cdebd-95e7-4aba-8f0f-2ca08edb0478", key_usage: "SIGN_VERIFY", multi_region: false, region: "eu-west-2", rotation_period_in_days: 0, tags: { Component: "full-rls-green-stage-a", Environment: "production", ManagedBy: "Terraform", Stack: "production-green-stage-a" }, tags_all: { Component: "full-rls-green-stage-a", Environment: "production", ManagedBy: "Terraform", Stack: "production-green-stage-a" }, timeouts: null, xks_key_id: "", policy: JSON.stringify(afterPolicy), ...after }, before_unknown: null, after_unknown: {}, before_sensitive: { tags: {}, tags_all: {} }, after_sensitive: { tags: {}, tags_all: {} }, ...metadata } }] });
const state = (serial) => ({ version: 4, lineage: "02afb75a-f902-ab8a-f4c1-751d4aef7837", serial, resources: [] });
const temporaryDirectories = new Set();
test.afterEach(() => { for (const directory of temporaryDirectories) fs.rmSync(directory, { recursive: true, force: true }); temporaryDirectories.clear(); });
const fixture = (changes = {}) => {
  const renderedPlan = plan(changes); const renderedPlanBytes = Buffer.from(JSON.stringify(renderedPlan)); const beforeState = state(52); const afterState = state(53);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-a-executor-test-")); temporaryDirectories.add(directory); const executorSavedPlanPath = path.join(directory, "authorized.tfplan"); const savedPlanBytes = Buffer.from("saved");
  materializeStageAReconciliationPlan({ savedPlanBytes, expectedSha256: sha(savedPlanBytes), applyPlanPath: executorSavedPlanPath, repositoryRoot: process.cwd() });
  const authorization = createStageAApprovalKeyReconciliationAuthorization({ protectedEnvironmentApprovalEvidence: approvalEvidence(), sourceSha, savedPlanSha256: sha(savedPlanBytes), renderedPlanSha256: sha(renderedPlanBytes), renderedPlan, stageAStateLineage: beforeState.lineage, stageAStateSerial: beforeState.serial, stageAStateSha256: stageAStateSemanticSha256(beforeState), approvalKeyTerraformAddress: "aws_kms_key.approval", approvalKeyArn: keyArn, beforePolicySha256: canonicalSha256(beforePolicy), afterPolicySha256: canonicalSha256(afterPolicy) });
  return { authorization, renderedPlanBytes, beforeState, afterState, executorSavedPlanPath, savedPlanBytes };
};

test("protected environment evidence composes into an exact one-apply Stage-A authorization", () => {
  const { authorization } = fixture();
  assert.equal(assertStageAApprovalKeyReconciliationAuthorization(authorization, { sourceSha }), authorization);
  assert.equal(authorization.maxTerraformApplies, 1);
  assert.equal(authorization.planChangedAddresses[0], STAGE_A_RECONCILIATION_AUTHORIZATION.approvalKeyTerraformAddress);
});

test("governed executor binds the exact rendered and saved plans, state, policy and one apply", () => {
  const { authorization, renderedPlanBytes, beforeState, afterState, executorSavedPlanPath, savedPlanBytes } = fixture();
  let currentState = beforeState; let currentPolicy = beforePolicy; let applies = 0; const consumed = new Set();
  const result = executeStageAApprovalKeyReconciliation({ authorization, sourceSha, savedPlanBytes, renderedPlanBytes, executorSavedPlanPath,
    readState: () => Buffer.from(JSON.stringify(currentState)), readPolicy: () => currentPolicy,
    recordConsumption: ({ authorizationSha256 }) => { if (consumed.has(authorizationSha256)) throw new Error("authorization already consumed"); consumed.add(authorizationSha256); },
    applySavedPlan: () => { applies += 1; currentState = afterState; currentPolicy = afterPolicy; },
  });
  assert.equal(result.applied, true); assert.equal(applies, 1);
  assert.throws(() => executeStageAApprovalKeyReconciliation({ authorization, sourceSha, savedPlanBytes, renderedPlanBytes, executorSavedPlanPath, readState: () => Buffer.from(JSON.stringify(currentState)), readPolicy: () => currentPolicy, recordConsumption: ({ authorizationSha256 }) => { if (consumed.has(authorizationSha256)) throw new Error("authorization already consumed"); }, applySavedPlan: () => { applies += 1; } }), /state changed|policy changed|consumed/);
});

test("authorization rejects tampering and all non-exact mutation shapes", () => {
  const { authorization } = fixture();
  for (const [field, value] of [["sourceSha", "a".repeat(40)], ["planCreateCount", 1], ["planDeleteCount", 1], ["planReplaceCount", 1], ["planUpdateCount", 2], ["policyStatementsAdded", []], ["policyStatementsRemoved", ["AccountAdministration"]], ["policyStatementsModified", ["IndependentCheckerSigns"]]]) {
    const changed = { ...authorization, [field]: value }; const { authorizationSha256, ...body } = changed; changed.authorizationSha256 = canonicalSha256(body);
    assert.throws(() => assertStageAApprovalKeyReconciliationAuthorization(changed, { sourceSha }), /invalid|hash/i, field);
  }
  assert.throws(() => assertStageAApprovalKeyReconciliationAuthorization({ ...authorization, approvedBy: "issue prose" }, { sourceSha }), /schema/i);
});

test("executor never replans and rejects plan and policy substitutions before apply", () => {
  const { authorization, renderedPlanBytes, beforeState, afterState, executorSavedPlanPath, savedPlanBytes } = fixture();
  for (const mutation of [
    { savedPlanBytes: Buffer.from("other") },
    { renderedPlanBytes: Buffer.from("{}") },
    { readState: () => Buffer.from(JSON.stringify({ ...beforeState, serial: 53 })) },
    { readPolicy: () => afterPolicy },
  ]) {
    let applies = 0;
    assert.throws(() => executeStageAApprovalKeyReconciliation({ authorization, sourceSha, savedPlanBytes, renderedPlanBytes, executorSavedPlanPath, readState: () => Buffer.from(JSON.stringify(beforeState)), readPolicy: () => beforePolicy, recordConsumption: () => {}, applySavedPlan: () => { applies += 1; }, ...mutation }));
    assert.equal(applies, 0);
  }
});

test("approval-key authorization rejects every non-policy resource delta", () => {
  for (const changes of [
    { after: { description: "changed" } },
    { after: { enable_key_rotation: true } },
    { after: { deletion_window_in_days: 7 } },
    { after: { tags: { Owner: "different" } } },
    { after: { is_enabled: false } },
    { after: { key_usage: "ENCRYPT_DECRYPT" } },
    { after_unknown: { description: true } },
    { after_sensitive: { tags: true } },
  ]) {
    const exact = fixture(); const changedPlanBytes = Buffer.from(JSON.stringify(plan(changes))); const { authorization: exactAuthorization, beforeState, executorSavedPlanPath, savedPlanBytes } = exact;
    const { authorizationSha256: _ignored, ...authorizationBody } = { ...exactAuthorization, renderedPlanSha256: sha(changedPlanBytes) }; const authorization = { ...authorizationBody, authorizationSha256: canonicalSha256(authorizationBody) };
    let applies = 0;
    assert.throws(() => executeStageAApprovalKeyReconciliation({ authorization, sourceSha, savedPlanBytes, renderedPlanBytes: changedPlanBytes, executorSavedPlanPath, readState: () => Buffer.from(JSON.stringify(beforeState)), readPolicy: () => beforePolicy, recordConsumption: () => {}, applySavedPlan: () => { applies += 1; } }), /non-policy|unknown|sensitive/i);
    assert.equal(applies, 0);
  }
  const exact = fixture(); assert.doesNotThrow(() => assertStageAApprovalKeyReconciliationPlan(JSON.parse(exact.renderedPlanBytes), exact.authorization));
});

test("executor applies only the executor-owned authenticated plan after caller-path replacement", () => {
  const { authorization, renderedPlanBytes, beforeState, afterState, executorSavedPlanPath, savedPlanBytes } = fixture();
  const callerDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-a-caller-test-")); temporaryDirectories.add(callerDirectory); const callerPath = path.join(callerDirectory, "caller.tfplan"); fs.writeFileSync(callerPath, savedPlanBytes);
  const capturedCallerBytes = fs.readFileSync(callerPath); fs.rmSync(callerPath); fs.symlinkSync(path.join(callerDirectory, "missing.tfplan"), callerPath); let applied;
  let currentState = beforeState; let currentPolicy = beforePolicy;
  const result = executeStageAApprovalKeyReconciliation({ authorization, sourceSha, savedPlanBytes: capturedCallerBytes, renderedPlanBytes, executorSavedPlanPath, readState: () => Buffer.from(JSON.stringify(currentState)), readPolicy: () => currentPolicy, recordConsumption: () => {}, applySavedPlan: (artifact) => { applied = artifact; currentState = afterState; currentPolicy = afterPolicy; } });
  assert.equal(result.appliedPlanSha256, authorization.savedPlanSha256); assert.equal(applied.path, executorSavedPlanPath); assert.equal(applied.sha256, authorization.savedPlanSha256); assert.notEqual(applied.path, callerPath); assert.deepEqual(applied.bytes, savedPlanBytes);
  fs.writeFileSync(executorSavedPlanPath, Buffer.from("forged")); assert.throws(() => executeStageAApprovalKeyReconciliation({ authorization, sourceSha, savedPlanBytes, renderedPlanBytes, executorSavedPlanPath, readState: () => Buffer.from(JSON.stringify(beforeState)), readPolicy: () => beforePolicy, recordConsumption: () => {}, applySavedPlan: () => { throw new Error("apply must be unreachable"); } }), /executor-owned|authenticated plan/i);
});

test("authorization-only workflow gates on production and cannot deploy infrastructure", () => {
  const workflow = fs.readFileSync(path.resolve(".github/workflows/authorize-production-stage-a-reconciliation.yml"), "utf8");
  assert.match(workflow, /environment: production/);
  assert.match(workflow, /production-github-environment-approval\.mjs/);
  assert.match(workflow, /production-stage-a-approval-key-reconciliation-authorization\.mjs --authorize/);
  assert.doesNotMatch(workflow, /configure-aws-credentials|terraform (?:plan|apply)|update-service|register-task-definition|stage-b/i);
  const runBodies = [...workflow.matchAll(/^\s{8}run: \|\n((?:^\s{10}.*(?:\n|$))*)/gm)].map(([, body]) => body);
  assert.doesNotMatch(runBodies.join(""), /\$\{\{\s*inputs\./);
  for (const variable of ["SOURCE_SHA", "SAVED_PLAN_SHA256", "RENDERED_PLAN_SHA256", "STAGE_A_STATE_LINEAGE", "STAGE_A_STATE_SERIAL", "STAGE_A_STATE_SHA256", "APPROVAL_KEY_ARN", "BEFORE_POLICY_SHA256", "AFTER_POLICY_SHA256"]) assert.match(workflow, new RegExp(`${variable}: \\$\\{\\{ inputs\\.`));
  assert.match(workflow, /--source-sha "\$SOURCE_SHA"/); assert.match(workflow, /--saved-plan-sha256 "\$SAVED_PLAN_SHA256"/); assert.match(workflow, /--after-policy-sha256 "\$AFTER_POLICY_SHA256"/);
});

test("workflow dispatch values remain data at the quoted shell argument boundary", () => {
  const value = "$(printf INERT_SENTINEL) `printf ALSO_INERT`; printf 'not executed' #\nnext";
  const received = execFileSync("bash", ["-ceu", "node -e 'process.stdout.write(process.argv[1])' \"$VALUE\""], { encoding: "utf8", env: { ...process.env, VALUE: value } });
  assert.equal(received, value);
});

test("only the exact GitHub-run artifact can supply authorization bytes", async () => {
  const { authorization } = fixture(); const bytes = Buffer.from(`${JSON.stringify(authorization)}\n`); const archive = await new JSZip().file("authorization.json", bytes).generateAsync({ type: "nodebuffer" });
  const workflow = { id: 7, run_attempt: 2, path: ".github/workflows/authorize-production-stage-a-reconciliation.yml", event: "workflow_dispatch", head_sha: sourceSha, status: "completed", conclusion: "success", repository: { id: 1, full_name: "T-ej2003/genuine-scan-main" }, head_repository: { id: 1, full_name: "T-ej2003/genuine-scan-main" }, actor: { login: "operator" } };
  const artifact = { id: 9, name: "stage-a-approval-key-reconciliation-authorization", expired: false, digest: `sha256:${sha(archive)}`, workflow_run: { id: 7, head_sha: sourceSha, repository_id: 1 } };
  const run = (command, args) => command === "unzip" ? execFileSync(command, args, { encoding: "utf8" }) : args[1].endsWith("/actions/runs/7") ? JSON.stringify(workflow) : JSON.stringify([{ artifacts: [artifact] }]);
  const resolve = (overrides = {}) => resolveStageAReconciliationAuthorizationArtifact({ workflowRunId: "7", workflowRunAttempt: "2", sourceSha, run, download: (_id, file) => fs.writeFileSync(file, overrides.archive || archive) });
  assert.deepEqual(resolve().authorizationBytes, bytes);
  const symlinkArchive = await new JSZip().file("authorization.json", "target", { unixPermissions: 0o120777 }).generateAsync({ type: "nodebuffer", platform: "UNIX" });
  assert.throws(() => resolve({ archive: symlinkArchive }), /regular file|archive/i);
  for (const overrides of [{ archive: Buffer.from("forged") }]) assert.throws(() => resolve(overrides), /digest|archive/i);
  for (const mutate of [(x) => { x.workflow_run.id = 8; }, (x) => { x.expired = true; }, (x) => { x.name = "other"; }]) { const changed = structuredClone(artifact); mutate(changed); assert.throws(() => resolveStageAReconciliationAuthorizationArtifact({ workflowRunId: "7", workflowRunAttempt: "2", sourceSha, run: (command, args) => command === "unzip" ? execFileSync(command, args, { encoding: "utf8" }) : args[1].endsWith("/actions/runs/7") ? JSON.stringify(workflow) : JSON.stringify([{ artifacts: [changed] }]), download: (_id, file) => fs.writeFileSync(file, archive) }), /artifact|workflow/i); }
});

test("default artifact downloader uses binary gh stdout without shell or --output", async () => {
  const { authorization } = fixture(); const bytes = Buffer.from(`${JSON.stringify(authorization)}\n`); const archive = await new JSZip().file("authorization.json", bytes).generateAsync({ type: "nodebuffer" });
  const workflow = { id: 7, run_attempt: 2, path: ".github/workflows/authorize-production-stage-a-reconciliation.yml", event: "workflow_dispatch", head_sha: sourceSha, status: "completed", conclusion: "success", repository: { id: 1, full_name: "T-ej2003/genuine-scan-main" }, head_repository: { id: 1, full_name: "T-ej2003/genuine-scan-main" }, actor: { login: "operator" } };
  const artifact = { id: 9, name: "stage-a-approval-key-reconciliation-authorization", expired: false, digest: `sha256:${sha(archive)}`, workflow_run: { id: 7, head_sha: sourceSha, repository_id: 1 } }; const calls = [];
  const run = (command, args, options = {}) => {
    calls.push({ command, args, options });
    if (command === "gh") {
      assert.equal(args.includes("--output"), false);
      if (args[1] === `repos/T-ej2003/genuine-scan-main/actions/runs/7`) return JSON.stringify(workflow);
      if (args[1] === `repos/T-ej2003/genuine-scan-main/actions/runs/7/artifacts`) return JSON.stringify([{ artifacts: [artifact] }]);
      if (args[1] === `repos/T-ej2003/genuine-scan-main/actions/artifacts/9/zip`) { assert.equal(options.encoding, null); assert.equal(options.maxBuffer, 64 * 1024 * 1024); return archive; }
      throw new Error("unexpected gh invocation");
    }
    return execFileSync(command, args, { encoding: options.encoding === null ? null : "utf8", maxBuffer: options.maxBuffer });
  };
  const resolved = resolveStageAReconciliationAuthorizationArtifact({ workflowRunId: "7", workflowRunAttempt: "2", sourceSha, run });
  assert.deepEqual(resolved.authorizationBytes, bytes);
  const download = calls.find(({ command, args }) => command === "gh" && args[1]?.endsWith("/actions/artifacts/9/zip"));
  assert.ok(download); assert.equal(download.options.encoding, null); assert.equal(calls.some(({ command }) => ["sh", "bash", "zsh"].includes(command)), false);
  for (const failure of [
    (args, options) => { assert.equal(options.encoding, null); return Buffer.alloc(0); },
    () => Buffer.from("not-a-zip"),
    () => { throw new Error("gh failed"); },
    () => { throw new Error("ERR_CHILD_PROCESS_STDIO_MAXBUFFER"); },
  ]) {
    assert.throws(() => resolveStageAReconciliationAuthorizationArtifact({ workflowRunId: "7", workflowRunAttempt: "2", sourceSha, run: (command, args, options = {}) => {
      if (command === "gh" && args[1]?.endsWith("/actions/artifacts/9/zip")) return failure(args, options);
      return run(command, args, options);
    } }), /empty|binary|ZIP|digest|failed|MAXBUFFER|invalid/i);
  }
  const badArtifact = { ...artifact, id: "9;printf INERT" };
  assert.throws(() => resolveStageAReconciliationAuthorizationArtifact({ workflowRunId: "7", workflowRunAttempt: "2", sourceSha, run: (command, args, options = {}) => {
    if (command === "gh" && args[1]?.endsWith("/artifacts")) return JSON.stringify([{ artifacts: [badArtifact] }]);
    return run(command, args, options);
  } }), /artifact ID|invalid/i);
});

test("real --execute composition forwards binary options while retaining textual output", async () => {
  const { authorization, renderedPlanBytes, beforeState, afterState, savedPlanBytes } = fixture(); const bytes = Buffer.from(`${JSON.stringify(authorization)}\n`); const archive = await new JSZip().file("authorization.json", bytes).generateAsync({ type: "nodebuffer" });
  const workflow = { id: 1, run_attempt: 1, path: ".github/workflows/authorize-production-stage-a-reconciliation.yml", event: "workflow_dispatch", head_sha: sourceSha, status: "completed", conclusion: "success", repository: { id: 1, full_name: "T-ej2003/genuine-scan-main" }, head_repository: { id: 1, full_name: "T-ej2003/genuine-scan-main" }, actor: { login: "operator" } };
  const artifact = { id: 2, name: "stage-a-approval-key-reconciliation-authorization", expired: false, digest: `sha256:${sha(archive)}`, workflow_run: { id: 1, head_sha: sourceSha, repository_id: 1 } }; const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-a-cli-test-")); temporaryDirectories.add(directory); const savedPlanPath = path.join(directory, "caller.tfplan"); fs.writeFileSync(savedPlanPath, savedPlanBytes); const previousHome = process.env.HOME; process.env.HOME = directory; let currentState = beforeState; let currentPolicy = beforePolicy; const calls = [];
  const execBoundary = (command, args, options = {}) => {
    calls.push({ command, args, options });
    if (command === "gh") {
      if (args[1].endsWith("/actions/runs/1")) return JSON.stringify(workflow);
      if (args[1].endsWith("/actions/runs/1/artifacts")) return JSON.stringify([{ artifacts: [artifact] }]);
      if (args[1].endsWith("/actions/artifacts/2/zip")) { assert.equal(options.encoding, null); assert.equal(options.maxBuffer, 64 * 1024 * 1024); return archive; }
    }
    if (command === "unzip") {
      if (args[0] === "-Z1") return "authorization.json\n";
      if (args[0] === "-Z") return "-rw------- 1 operator operator 1 authorization.json\n";
      return bytes.toString("utf8");
    }
    assert.equal(options.encoding, "utf8");
    if (command === "terraform" && args.includes("show")) return renderedPlanBytes.toString("utf8");
    if (command === "terraform" && args.includes("state")) return JSON.stringify(currentState);
    if (command === "terraform" && args.includes("apply")) { currentState = afterState; currentPolicy = afterPolicy; return ""; }
    if (command === "aws") return JSON.stringify({ Policy: encodeURIComponent(JSON.stringify(currentPolicy)) });
    throw new Error(`unexpected command: ${command}`);
  };
  try {
    const result = await runCli(["--execute", "--source-sha", sourceSha, "--workflow-run-id", "1", "--workflow-run-attempt", "1", "--saved-plan", savedPlanPath], { execFileSync: execBoundary, readProtectedMain: () => ({ headSha: sourceSha, freshRemoteMainSha: sourceSha }) });
    assert.equal(result.applied, true); assert.equal(calls.filter(({ command, args }) => command === "gh" && args[1].endsWith("/zip")).length, 1); assert.equal(calls.some(({ command, args }) => command === "gh" && args.includes("--output")), false); assert.equal(calls.some(({ options }) => options.encoding === null), true); assert.equal(calls.filter(({ options }) => options.encoding === "utf8").length > 0, true);
  } finally { process.env.HOME = previousHome; }
});

test("an --execute runner that drops binary options fails closed", async () => {
  const { authorization } = fixture(); const bytes = Buffer.from(`${JSON.stringify(authorization)}\n`); const archive = await new JSZip().file("authorization.json", bytes).generateAsync({ type: "nodebuffer" }); const workflow = { id: 1, run_attempt: 1, path: ".github/workflows/authorize-production-stage-a-reconciliation.yml", event: "workflow_dispatch", head_sha: sourceSha, status: "completed", conclusion: "success", repository: { id: 1, full_name: "T-ej2003/genuine-scan-main" }, head_repository: { id: 1, full_name: "T-ej2003/genuine-scan-main" }, actor: { login: "operator" } }; const artifact = { id: 2, name: "stage-a-approval-key-reconciliation-authorization", expired: false, digest: `sha256:${sha(archive)}`, workflow_run: { id: 1, head_sha: sourceSha, repository_id: 1 } };
  const droppingRun = (command, args) => {
    if (command === "gh" && args[1].endsWith("/actions/runs/1")) return JSON.stringify(workflow);
    if (command === "gh" && args[1].endsWith("/actions/runs/1/artifacts")) return JSON.stringify([{ artifacts: [artifact] }]);
    if (command === "gh" && args[1].endsWith("/actions/artifacts/2/zip")) return archive.toString("utf8");
    throw new Error("unexpected command after binary download");
  };
  await assert.rejects(() => runCli(["--execute", "--source-sha", sourceSha, "--workflow-run-id", "1", "--workflow-run-attempt", "1", "--saved-plan", path.join(os.tmpdir(), "missing.tfplan")], { run: droppingRun, readProtectedMain: () => ({ headSha: sourceSha, freshRemoteMainSha: sourceSha }) }), /empty|binary|ZIP|digest|archive/i);
});
