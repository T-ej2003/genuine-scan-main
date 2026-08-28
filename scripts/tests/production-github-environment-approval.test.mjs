import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  assertProductionEnvironmentApprovalEvidence,
  assertProductionEnvironmentActualReviewer,
  assertProductionEnvironmentReviewer,
  createProductionEnvironmentApprovalEvidence,
  fetchProductionEnvironmentApprovalEvidence,
  runProductionEnvironmentApprovalCli,
} from "../aws/production-github-environment-approval.mjs";
import { readStageBPrivateFileBytes } from "../aws/stage-b-artifact-contract.mjs";

const sourceSha = "565f78be803558feb40a543ead464c5410738960";
const now = new Date("2026-08-20T18:00:00.000Z");
const context = { repository: "T-ej2003/genuine-scan-main", environment: "production", sourceSha, workflowRef: "T-ej2003/genuine-scan-main/.github/workflows/release-gate.yml@refs/heads/main", eventName: "workflow_dispatch", workflowRunId: "123", workflowRunAttempt: "1", executionActor: "alice", githubActions: "true", now };
const config = (overrides = {}) => ({ id: 14514600120, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 1, login: "bob" } }] }], ...overrides });
const evidence = (overrides = {}) => createProductionEnvironmentApprovalEvidence({ ...context, now: undefined, observedAt: now.toISOString(), environmentConfig: config(), ...overrides });

test("GitHub API evidence proves the exact configured-reviewer governance", async () => {
  let requested;
  const result = await fetchProductionEnvironmentApprovalEvidence({ ...context, observedAt: now.toISOString(), token: "fixture-token" }, { fetchImpl: async (url) => { requested = url; return { ok: true, json: async () => config() }; } });
  assert.equal(requested, "https://api.github.com/repos/T-ej2003/genuine-scan-main/environments/production");
  assert.equal(assertProductionEnvironmentApprovalEvidence(result, context), result);
  assert.equal(result.requiredReviewerCount, 1);
  assert.deepEqual(result.configuredReviewers, [{ type: "User", id: 1, name: "bob" }]);
  assert.equal(result.preventSelfReview, true);
  assert.equal(result.canAdminsBypass, false);
});

test("missing or malformed reviewers, admin bypass, and wrong environment fail closed", () => {
  for (const [environmentConfig, overrides, pattern] of [
    [config({ protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [] }] }), {}, /reviewer/],
    [config({ protection_rules: [{ type: "required_reviewers", reviewers: [{ type: "User", reviewer: { id: 1, login: "alice" } }] }] }), {}, /policy/],
    [config({ protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: { id: 1 } }] }] }), {}, /invalid required reviewer/],
    [config({ can_admins_bypass: true }), {}, /administrator bypass/],
    [{ ...config(), name: "staging" }, {}, /identity/],
    [config(), { repository: "attacker/repository" }, /identity/],
  ]) assert.throws(() => createProductionEnvironmentApprovalEvidence({ ...context, now: undefined, observedAt: now.toISOString(), environmentConfig, ...overrides }), pattern);
});

test("configured solo and independent reviewers follow GitHub's authenticated self-review policy", () => {
  const solo = evidence({ environmentConfig: config({ protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: { id: 1, login: "alice" } }] }] }) });
  assert.equal(assertProductionEnvironmentReviewer(solo, { approvedBy: "Alice", executionActor: "alice" }), "Alice");
  assert.equal(assertProductionEnvironmentReviewer(evidence(), { approvedBy: "bob", executionActor: "alice" }), "bob");
  assert.throws(() => assertProductionEnvironmentReviewer(solo, { approvedBy: "mallory", executionActor: "alice" }), /not a configured/);
  const selfBlocked = evidence({ environmentConfig: config({ protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 1, login: "alice" } }] }] }) });
  assert.throws(() => assertProductionEnvironmentReviewer(selfBlocked, { approvedBy: "alice", executionActor: "alice" }), /prevents self-review/);
});

test("P2 regression: configured reviewer text is not actual approval evidence", () => {
  assert.throws(() => assertProductionEnvironmentActualReviewer(evidence(), { sourceSha, repository: context.repository, executionActor: "alice" }), /actual approval/i);
});

test("actual environment approval identity comes from GitHub approval records", async () => {
  const actual = await fetchProductionEnvironmentApprovalEvidence({ ...context, token: "fixture-token", requireActualApproval: true }, { fetchImpl: async (url) => ({ ok: true, json: async () => url.endsWith("/approvals") ? [{ state: "approved", user: { id: 2, login: "actual-reviewer" }, environments: [{ id: 14514600120, name: "production" }] }] : config() }) });
  assert.equal(actual.schemaVersion, 3);
  assert.equal(actual.actualApproval.userLogin, "actual-reviewer");
  assert.throws(() => assertProductionEnvironmentActualReviewer({ ...actual, actualApproval: { ...actual.actualApproval, userLogin: "configured-only" } }, { sourceSha, repository: context.repository, executionActor: "alice" }), /hash|actual/i);
});

test("tamper, wrong bindings, and stale environment evidence fail closed", () => {
  const valid = evidence();
  for (const [changedEvidence, changedContext, pattern] of [
    [{ ...valid, requiredReviewerCount: 2 }, context, /protected recovery run/],
    [{ ...valid, configuredReviewers: [{ type: "User", id: 2, name: "mallory" }] }, context, /hash/],
    [valid, { ...context, repository: "attacker/repository" }, /protected recovery run/],
    [valid, { ...context, environment: "staging" }, /protected recovery run/],
    [valid, { ...context, sourceSha: "a".repeat(40) }, /protected recovery run/],
    [valid, { ...context, workflowRef: "T-ej2003/genuine-scan-main/.github/workflows/other.yml@refs/heads/main" }, /protected recovery run/],
    [valid, { ...context, eventName: "push" }, /protected recovery run/],
    [valid, { ...context, githubActions: "false" }, /protected recovery run/],
    [valid, { ...context, workflowRunId: "124" }, /protected recovery run/],
    [valid, { ...context, executionActor: "mallory" }, /protected recovery run/],
    [evidence({ observedAt: new Date(now.getTime() - 31 * 60 * 1000).toISOString() }), context, /stale/],
  ]) assert.throws(() => assertProductionEnvironmentApprovalEvidence(changedEvidence, changedContext), pattern);
});

test("workflow-shaped private directory publishes consumable evidence without touching its runner parent", async (t) => {
  const runnerTemp = fs.mkdtempSync(path.join(os.tmpdir(), "production-approval-runner-"));
  const runnerMode = fs.statSync(runnerTemp).mode & 0o777;
  const worktreeBefore = execFileSync("git", ["status", "--porcelain=v1"], { encoding: "utf8" });
  const directory = path.join(runnerTemp, "production-environment-approval");
  fs.mkdirSync(directory, { mode: 0o700 });
  const output = path.join(directory, "production-environment-approval.json");
  t.after(() => fs.rmSync(runnerTemp, { recursive: true, force: true }));
  const result = await runProductionEnvironmentApprovalCli([
    "--repository", context.repository, "--environment", context.environment, "--source-sha", sourceSha,
    "--workflow-ref", context.workflowRef, "--event-name", context.eventName, "--workflow-run-id", context.workflowRunId,
    "--workflow-run-attempt", context.workflowRunAttempt, "--execution-actor", context.executionActor, "--output", output,
  ], { env: { GITHUB_TOKEN: "fixture-token" }, fetchImpl: async () => ({ ok: true, json: async () => config() }) });
  const captured = readStageBPrivateFileBytes({ filePath: output, repositoryRoot: process.cwd(), label: "GitHub environment approval evidence" });
  assert.equal(JSON.parse(captured.bytes).evidenceSha256, result.evidenceSha256);
  assert.equal(fs.statSync(directory).mode & 0o777, 0o700);
  assert.equal(fs.statSync(runnerTemp).mode & 0o777, runnerMode);
  assert.equal(execFileSync("git", ["status", "--porcelain=v1"], { encoding: "utf8" }), worktreeBefore);
});

test("non-private and symlink approval evidence parents remain rejected", async (t) => {
  const runnerTemp = fs.mkdtempSync(path.join(os.tmpdir(), "production-approval-parent-"));
  const unsafe = path.join(runnerTemp, "unsafe");
  const target = path.join(runnerTemp, "target");
  fs.mkdirSync(unsafe, { mode: 0o755 });
  fs.mkdirSync(target, { mode: 0o700 });
  const linked = path.join(runnerTemp, "linked");
  fs.symlinkSync(target, linked);
  t.after(() => fs.rmSync(runnerTemp, { recursive: true, force: true }));
  const args = (output) => [
    "--repository", context.repository, "--environment", context.environment, "--source-sha", sourceSha,
    "--workflow-ref", context.workflowRef, "--event-name", context.eventName, "--workflow-run-id", context.workflowRunId,
    "--workflow-run-attempt", context.workflowRunAttempt, "--execution-actor", context.executionActor, "--output", output,
  ];
  let fetchCalls = 0;
  const deps = { env: { GITHUB_TOKEN: "fixture-token" }, fetchImpl: async () => { fetchCalls += 1; return { ok: true, json: async () => config() }; } };
  await assert.rejects(() => runProductionEnvironmentApprovalCli(args(path.join(unsafe, "evidence.json")), deps), /mode 0700/);
  await assert.rejects(() => runProductionEnvironmentApprovalCli(args(path.join(linked, "evidence.json")), deps), /symlink|non-symlink/);
  assert.equal(fetchCalls, 0);
});
