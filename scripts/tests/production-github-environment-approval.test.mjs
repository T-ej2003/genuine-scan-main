import assert from "node:assert/strict";
import test from "node:test";
import {
  assertProductionEnvironmentApprovalEvidence,
  createProductionEnvironmentApprovalEvidence,
  fetchProductionEnvironmentApprovalEvidence,
} from "../aws/production-github-environment-approval.mjs";

const sourceSha = "565f78be803558feb40a543ead464c5410738960";
const now = new Date("2026-08-20T18:00:00.000Z");
const context = { repository: "T-ej2003/genuine-scan-main", environment: "production", sourceSha, workflowRef: "T-ej2003/genuine-scan-main/.github/workflows/release-gate.yml@refs/heads/main", eventName: "workflow_dispatch", workflowRunId: "123", workflowRunAttempt: "1", executionActor: "alice", githubActions: "true", now };
const config = (overrides = {}) => ({ id: 14514600120, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 1 } }] }], ...overrides });
const evidence = (overrides = {}) => createProductionEnvironmentApprovalEvidence({ ...context, now: undefined, observedAt: now.toISOString(), environmentConfig: config(), ...overrides });

test("GitHub API evidence proves the exact non-bypassable independent-review configuration", async () => {
  let requested;
  const result = await fetchProductionEnvironmentApprovalEvidence({ ...context, observedAt: now.toISOString(), token: "fixture-token" }, { fetchImpl: async (url) => { requested = url; return { ok: true, json: async () => config() }; } });
  assert.equal(requested, "https://api.github.com/repos/T-ej2003/genuine-scan-main/environments/production");
  assert.equal(assertProductionEnvironmentApprovalEvidence(result, context), result);
  assert.equal(result.requiredReviewerCount, 1);
  assert.equal(result.preventSelfReview, true);
  assert.equal(result.canAdminsBypass, false);
});

test("missing reviewers, enabled self-review, admin bypass, and wrong environment fail closed", () => {
  for (const [environmentConfig, overrides, pattern] of [
    [config({ protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [] }] }), {}, /reviewer/],
    [config({ protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: { id: 1 } }] }] }), {}, /self-review/],
    [config({ can_admins_bypass: true }), {}, /administrator bypass/],
    [{ ...config(), name: "staging" }, {}, /identity/],
    [config(), { repository: "attacker/repository" }, /identity/],
  ]) assert.throws(() => createProductionEnvironmentApprovalEvidence({ ...context, now: undefined, observedAt: now.toISOString(), environmentConfig, ...overrides }), pattern);
});

test("tamper, wrong bindings, and stale environment evidence fail closed", () => {
  const valid = evidence();
  for (const [changedEvidence, changedContext, pattern] of [
    [{ ...valid, requiredReviewerCount: 2 }, context, /hash/],
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
