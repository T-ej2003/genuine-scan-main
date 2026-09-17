import assert from "node:assert/strict";
import { test } from "node:test";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { authenticateComponentIamAuthorization, authenticateComponentIamClosureAuthorization, createComponentIamAuthorization, componentIamAuthorization as contract } from "../aws/component-iam-authorization.mjs";
import { digest, documentBindings, installationCapabilitySet } from "../aws/component-iam-installation-contract.mjs";

// Runnable offline proof: node --test scripts/tests/component-iam-authorization.test.mjs
// Only GitHub transport/clock are injected; archive hashing and unzip run for real.
const now = Date.parse("2026-09-17T12:05:00Z");
const createdAt = "2026-09-17T12:00:00Z";
const input = { runId: "1234", sourceSha: "a".repeat(40), transitionId: "01234567-89ab-4cde-8f01-23456789abcd" };
const actor = { login: "T-ej2003", id: 183396573, type: "User" };
const bytesHash = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");

function zip(value, kind = "regular") {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "component-iam-auth-test-"));
  try {
    if (kind === "symlink") fs.symlinkSync("missing", path.join(directory, "authorization.json"));
    else fs.writeFileSync(path.join(directory, "authorization.json"), typeof value === "string" ? value : JSON.stringify(value));
    if (kind === "extra") fs.writeFileSync(path.join(directory, "extra.json"), "{}");
    execFileSync("/usr/bin/zip", ["-q", "-y", "archive.zip", "authorization.json", ...(kind === "extra" ? ["extra.json"] : [])], { cwd: directory });
    return fs.readFileSync(path.join(directory, "archive.zip"));
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

function fixture(change = () => {}) {
  const state = {
    branch: { name: "main", protected: true, commit: { sha: input.sourceSha } },
    run: { id: 1234, repository: { id: 42, full_name: contract.repository }, head_repository: { id: 42, full_name: contract.repository }, path: contract.workflow, head_branch: "main", head_sha: input.sourceSha, event: "workflow_dispatch", status: "completed", conclusion: "success", run_attempt: 1, actor: { ...actor }, triggering_actor: { ...actor }, created_at: createdAt },
    config: { id: 91, name: contract.environment, can_admins_bypass: false, deployment_branch_policy: { protected_branches: false, custom_branch_policies: true }, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: { ...actor } }] }] },
    branches: { total_count: 1, branch_policies: [{ name: "main", type: "branch" }] },
    approvals: [{ state: "approved", user: { ...actor }, environments: [{ id: 91, name: contract.environment }] }],
    authorization: createComponentIamAuthorization({ ...input, createdAt }, now),
    kind: "regular", now,
  };
  state.authorization = { ...state.authorization };
  state.expectedAuthorizationSha256 = digest(state.authorization);
  change(state);
  const archive = zip(state.authorization, state.kind);
  state.artifact = { id: 55, name: contract.artifact, expired: false, size_in_bytes: archive.length, digest: `sha256:${bytesHash(archive)}`, workflow_run: { id: 1234, head_sha: input.sourceSha, repository_id: 42 }, ...state.artifact };
  const calls = [];
  let branchesRead = 0;
  let runsRead = 0;
  const execute = (command, args, options) => {
    calls.push({ command, args, options });
    assert.equal(command, "gh");
    assert.deepEqual(args.slice(0, 3), ["api", "--hostname", "github.com"]);
    const suffix = args[3].replace(`repos/${contract.repository}/`, "");
    let result;
    if (suffix === "branches/main") result = ++branchesRead === 2 && state.finalBranch ? state.finalBranch : state.branch;
    else if (suffix.startsWith("compare/")) result = state.comparison || { status: "ahead", base_commit: { sha: input.sourceSha }, merge_base_commit: { sha: input.sourceSha } };
    else if (suffix === "actions/runs/1234") result = ++runsRead === 2 && state.finalRun ? state.finalRun : state.run;
    else if (suffix === `environments/${contract.environment}`) result = state.config;
    else if (suffix === `environments/${contract.environment}/deployment-branch-policies`) result = state.branches;
    else if (suffix === "actions/runs/1234/approvals") result = state.approvals;
    else if (suffix === "actions/runs/1234/artifacts") {
      assert.deepEqual(args.slice(4), ["--paginate", "--slurp"]);
      result = state.pages || [{ artifacts: [state.artifact] }];
    } else if (suffix === "actions/artifacts/55/zip") return state.download || archive;
    else throw new Error(`Unexpected endpoint ${suffix}`);
    return JSON.stringify(result);
  };
  const deps = { execute, now: () => state.now, env: { GH_TOKEN: "test-value", GH_HOST: "wrong.invalid", HTTPS_PROXY: "wrong.invalid", AWS_PROFILE: "forbidden", GH_CONFIG_DIR: "/wrong", NODE_OPTIONS: "forbidden" } };
  return { state, calls, authenticate: (expected = input) => authenticateComponentIamAuthorization(expected, deps), close: (expected = {}) => authenticateComponentIamClosureAuthorization({ ...input, expectedAuthorizationSha256: state.expectedAuthorizationSha256, ...expected }, deps) };
}

test("source-owned hashes and fixed run-created expiry; authenticated result and filtered child environment", () => {
  const { authenticate, calls } = fixture();
  const result = authenticate();
  assert.equal(result.runId, input.runId);
  assert.equal(result.purpose, "INSTALL");
  assert.deepEqual(result.actor, { login: actor.login, id: actor.id });
  assert.equal(result.environmentId, 91);
  assert.equal(result.expiresAt, "2026-09-17T12:30:00.000Z");
  assert.equal(result.documentBindingsSha256, digest(documentBindings()));
  assert.equal(result.capabilitySetSha256, digest(installationCapabilitySet()));
  assert.equal(result.authorizationSha256, digest(createComponentIamAuthorization({ ...input, createdAt }, now)));
  assert.equal(calls.filter(({ args }) => args[3].endsWith("branches/main")).length, 2);
  for (const { options } of calls) {
    assert.deepEqual(options.env, { GH_TOKEN: "test-value", GH_HOST: "github.com", GH_PROMPT_DISABLED: "1" });
    assert.equal(options.timeout, 30_000);
  }
});

const invalid = {
  "unprotected main": (s) => { s.branch.protected = false; },
  "stale main": (s) => { s.branch.commit.sha = "b".repeat(40); },
  "wrong branch": (s) => { s.branch.name = "other"; },
  "wrong run ID": (s) => { s.run.id = 1235; },
  "wrong repository": (s) => { s.run.repository.full_name = "other/repo"; },
  "fork": (s) => { s.run.head_repository.id = 43; },
  "fork name": (s) => { s.run.head_repository.full_name = "other/repo"; },
  "wrong workflow": (s) => { s.run.path = ".github/workflows/other.yml"; },
  "wrong event": (s) => { s.run.event = "push"; },
  "wrong run branch": (s) => { s.run.head_branch = "other"; },
  "wrong run source": (s) => { s.run.head_sha = "b".repeat(40); },
  "incomplete run": (s) => { s.run.status = "in_progress"; },
  "failed run": (s) => { s.run.conclusion = "failure"; },
  "rerun": (s) => { s.run.run_attempt = 2; },
  "wrong actor ID": (s) => { s.run.actor.id++; },
  "wrong actor login": (s) => { s.run.actor.login = "other"; },
  "bot actor": (s) => { s.run.actor.type = "Bot"; },
  "wrong triggering actor": (s) => { s.run.triggering_actor.id++; },
  "missing triggering actor": (s) => { delete s.run.triggering_actor; },
  "future run": (s) => { s.run.created_at = "2026-09-17T12:06:00Z"; },
  "expired at boundary": (s) => { s.now = Date.parse("2026-09-17T12:30:00Z"); },
  "invalid created timestamp": (s) => { s.run.created_at = "invalid"; },
  "wrong environment": (s) => { s.config.name = "production"; },
  "invalid environment ID": (s) => { s.config.id = 0; },
  "admin bypass": (s) => { s.config.can_admins_bypass = true; },
  "protected branches instead of main only": (s) => { s.config.deployment_branch_policy = { protected_branches: true, custom_branch_policies: false }; },
  "extra branch policy": (s) => { s.branches.branch_policies.push({ name: "other", type: "branch" }); },
  "truncated branch policy listing": (s) => { s.branches.total_count = 2; },
  "tag policy": (s) => { s.branches.branch_policies[0].type = "tag"; },
  "wildcard branch": (s) => { s.branches.branch_policies[0].name = "*"; },
  "self review forbidden": (s) => { s.config.protection_rules[0].prevent_self_review = true; },
  "missing reviewer rule": (s) => { s.config.protection_rules = []; },
  "duplicate reviewer rule": (s) => { s.config.protection_rules.push(s.config.protection_rules[0]); },
  "Team reviewer": (s) => { s.config.protection_rules[0].reviewers[0].type = "Team"; },
  "wrong required reviewer": (s) => { s.config.protection_rules[0].reviewers[0].reviewer.id++; },
  "extra required reviewer": (s) => { s.config.protection_rules[0].reviewers.push(s.config.protection_rules[0].reviewers[0]); },
  "missing approval": (s) => { s.approvals = []; },
  "duplicate approval": (s) => { s.approvals.push(s.approvals[0]); },
  "rejection": (s) => { s.approvals[0].state = "rejected"; },
  "wrong approving ID": (s) => { s.approvals[0].user.id++; },
  "wrong approving login": (s) => { s.approvals[0].user.login = "other"; },
  "Team approval": (s) => { s.approvals[0].user.type = "Team"; },
  "recreated environment": (s) => { s.approvals[0].environments[0].id++; },
  "wrong approval environment name": (s) => { s.approvals[0].environments[0].name = "other"; },
  "extra approval environment": (s) => { s.approvals[0].environments.push({ id: 92, name: "other" }); },
  "missing artifact": (s) => { s.pages = [{ artifacts: [] }]; },
  "malformed listing": (s) => { s.pages = {}; },
  "extra artifact page": (s) => { s.pages = [{ artifacts: [{}] }, { artifacts: [{}] }]; },
  "expired artifact": (s) => { s.artifact = { expired: true }; },
  "wrong artifact name": (s) => { s.artifact = { name: "other" }; },
  "wrong artifact provenance": (s) => { s.artifact = { workflow_run: { id: 1235, head_sha: input.sourceSha, repository_id: 42 } }; },
  "artifact hash mismatch": (s) => { s.artifact = { digest: `sha256:${"0".repeat(64)}` }; },
  "missing artifact hash": (s) => { s.artifact = { digest: undefined }; },
  "oversized artifact": (s) => { s.artifact = { size_in_bytes: 1024 * 1024 + 1 }; },
  "non-binary download": (s) => { s.download = "not binary"; },
  "extra zip member": (s) => { s.kind = "extra"; },
  "symlink zip member": (s) => { s.kind = "symlink"; },
  "malformed JSON": (s) => { s.authorization = "{"; },
  "array artifact": (s) => { s.authorization = []; },
  "unknown artifact field": (s) => { s.authorization.extra = true; },
  "missing artifact field": (s) => { delete s.authorization.expiresAt; },
  "wrong artifact run": (s) => { s.authorization.runId = "1235"; },
  "wrong artifact source": (s) => { s.authorization.sourceSha = "b".repeat(40); },
  "wrong transition": (s) => { s.authorization.transitionId = crypto.randomUUID(); },
  "wrong document hash": (s) => { s.authorization.documentBindingsSha256 = "b".repeat(64); },
  "wrong capability hash": (s) => { s.authorization.capabilitySetSha256 = "b".repeat(64); },
  "extended expiry": (s) => { s.authorization.expiresAt = "2026-09-17T12:31:00.000Z"; },
  "invalid expiry": (s) => { s.authorization.expiresAt = "invalid"; },
  "main advances during download": (s) => { s.finalBranch = { ...s.branch, commit: { sha: "b".repeat(40) } }; },
  "rerun during download": (s) => { s.finalRun = { ...s.run, run_attempt: 2 }; },
};
for (const [name, change] of Object.entries(invalid)) test(`rejects ${name}`, () => assert.throws(() => fixture(change).authenticate()));

test("malformed expected coordinates fail before any GitHub read", () => {
  for (const change of [{ runId: "1/dispatch" }, { sourceSha: "main" }, { transitionId: "not-a-uuid" }]) {
    const f = fixture();
    assert.throws(() => f.authenticate({ ...input, ...change }));
    assert.equal(f.calls.length, 0);
  }
});

test("a local artifact path never substitutes for authenticated transport", () => {
  let reads = 0;
  assert.throws(() => authenticateComponentIamAuthorization({ ...input, authorizationPath: "/tmp/unsigned.json" }, { execute: () => { reads++; throw new Error("offline"); } }), /GitHub authorization read failed/);
  assert.equal(reads, 1);
});

test("dispatch delegates only to the source-bound reusable authorizer", () => {
  const source = fs.readFileSync(new URL(`../../${contract.workflow}`, import.meta.url), "utf8");
  assert.match(source, /permissions:\n  contents: read\n/);
  assert.doesNotMatch(source, /aws-actions\/|capability_set_sha256:|expires_at:|actions: write/);
  assert.match(source, /uses: \.\/\.github\/workflows\/component-iam-authorization-publisher.yml/);
  assert.match(source, /id-token: write/);
});

test("cleanup authenticates expired original capabilities against ledger after main advances", () => {
  const f = fixture((s) => {
    s.now += 60 * 60 * 1000;
    s.branch.commit.sha = "b".repeat(40);
    // Simulate old source-owned documents/capabilities, now different on main.
    s.authorization.documentBindingsSha256 = "c".repeat(64);
    s.authorization.capabilitySetSha256 = "d".repeat(64);
    s.expectedAuthorizationSha256 = digest(s.authorization);
  });
  const result = f.close();
  assert.equal(result.purpose, "CLEANUP");
  assert.equal(result.authorizationSha256, f.state.expectedAuthorizationSha256);
  assert.equal(result.capabilitySetSha256, "d".repeat(64));
  assert(Date.parse(result.expiresAt) < f.state.now);
  assert.equal(f.calls.filter(({ args }) => args[3].includes("/compare/")).length, 2);
  assert.throws(() => f.authenticate(), /current main/);
});

test("cleanup accepts identical protected main but requires trusted ledger hash", () => {
  const f = fixture((s) => { s.comparison = { status: "identical", base_commit: { sha: input.sourceSha }, merge_base_commit: { sha: input.sourceSha } }; });
  assert.equal(f.close().purpose, "CLEANUP");
  assert.throws(() => f.close({ expectedAuthorizationSha256: undefined }), /Trusted ledger/);
  assert.throws(() => f.close({ expectedAuthorizationSha256: "f".repeat(64) }), /Trusted ledger/);
});

for (const [name, comparison] of Object.entries({
  behind: { status: "behind", base_commit: { sha: input.sourceSha }, merge_base_commit: { sha: input.sourceSha } },
  diverged: { status: "diverged", base_commit: { sha: input.sourceSha }, merge_base_commit: { sha: "b".repeat(40) } },
  "wrong merge base": { status: "ahead", base_commit: { sha: input.sourceSha }, merge_base_commit: { sha: "b".repeat(40) } },
  "wrong source": { status: "ahead", base_commit: { sha: "b".repeat(40) }, merge_base_commit: { sha: input.sourceSha } },
})) test(`cleanup rejects ${name}`, () => assert.throws(() => fixture((s) => { s.comparison = comparison; }).close()));

// All transport, actor, review, artifact and exact-binding failures apply equally
// to cleanup. Only expiry and advancing main intentionally differ.
for (const [name, change] of Object.entries(invalid).filter(([name]) => !["stale main", "expired at boundary", "main advances during download"].includes(name))) {
  test(`cleanup rejects ${name}`, () => assert.throws(() => fixture(change).close()));
}

test("cleanup permission cannot disable installation expiry", () => {
  const f = fixture((s) => { s.now += 60 * 60 * 1000; });
  assert.equal(f.close().purpose, "CLEANUP");
  assert.throws(() => f.authenticate({ ...input, purpose: "CLEANUP", allowExpired: true }), /expired/);
});
