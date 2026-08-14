import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import yaml from "js-yaml";
import {
  READ_ONLY_CHECKS,
  assertReadOnlyCheckPlan,
  assertReadOnlyMode,
  assertReadOnlySourceIdentity,
  canonicalSourceTreeSha256,
  runReadOnlyReadiness,
} from "../ci/production-readiness-orchestrator.mjs";

const workflowPath = path.resolve(".github/workflows/production-deploy.yml");
const workflowText = fs.readFileSync(workflowPath, "utf8");
const workflow = yaml.load(workflowText);
const sha = "a".repeat(40);
const cleanState = { remoteDefaultBranch: "main", shallow: false, mergeInProgress: false, rebaseInProgress: false, cherryPickInProgress: false };

test("production readiness is manually dispatched with an exact source SHA", () => {
  const dispatch = workflow.on?.workflow_dispatch || workflow[true]?.workflow_dispatch;
  assert(dispatch);
  assert.equal(dispatch.inputs.source_sha.required, true);
  assert.equal(dispatch.inputs.source_sha.type, "string");
  assert.match(workflowText, /--source-sha/);
  assert.match(workflowText, /scripts\/ci\/production-readiness-orchestrator\.mjs/);
});

test("workflow authorizes protected main before requested-source checkout or code execution", () => {
  const steps = workflow.jobs["read-only-readiness"].steps;
  const bootstrap = steps.find(({ name }) => /Authorize requested source/.test(name));
  const requestedCheckout = steps.find(({ name }) => /Checkout exact authorized source/.test(name));
  assert(bootstrap);
  assert(requestedCheckout);
  assert.ok(steps.indexOf(bootstrap) < steps.indexOf(requestedCheckout));
  assert.doesNotMatch(steps[steps.indexOf(bootstrap)].run, /npm|node|terraform|aws\b/);
  assert.ok(steps.findIndex(({ name }) => /Install dependencies/.test(name)) > steps.indexOf(bootstrap));
  assert.doesNotMatch(requestedCheckout.with.ref, /inputs\.source_sha/);
  assert.match(workflowText, /ref: main/);
  assert.match(workflowText, /trusted_main_sha/);
  assert.match(workflowText, /git cat-file -e/);
  assert.match(workflowText, /REQUESTED_SOURCE_SHA[\s\S]*origin\/main/);
});

test("workflow is read-only, serialized, and cannot reach mutation boundaries", () => {
  assert.deepEqual(workflow.permissions, { contents: "read" });
  assert.equal(workflow.concurrency["cancel-in-progress"], false);
  assert.equal(workflow.concurrency.group, "production-deploy");
  assert.doesNotMatch(workflowText, /configure-aws-credentials|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|id-token:\s*write/);
  assert.doesNotMatch(workflowText, /terraform\s+(?:apply|state\b)|ecs:(?:RegisterTaskDefinition|UpdateService|DeregisterTaskDefinition)|aws\s+ecs\s+(?:register-task-definition|update-service|deregister-task-definition)|PutSecretValue|MFA/i);
  assert.doesNotMatch(workflowText, /environment:\s*production\s*$/m);
  assert.match(workflowText, /MSCQR_DEPLOYMENT_MODE:\s*read-only/);
  assert.match(workflowText, /actions\/upload-artifact@v7/);
});

test("fixed orchestrator command set contains no mutation boundary", () => {
  assert.doesNotThrow(() => assertReadOnlyCheckPlan());
  assert.equal(READ_ONLY_CHECKS.some(({ command, args }) => /apply|state\b|register|update-service|deregister/i.test([command, ...args].join(" "))), false);
});

test("source identity rejects arbitrary, dirty, and mismatched checkouts", () => {
  const valid = { sourceSha: sha, currentHead: sha, originMainHead: sha, isAncestor: true, porcelainStatus: "", repositoryState: cleanState };
  assert.doesNotThrow(() => assertReadOnlySourceIdentity(valid));
  assert.throws(() => assertReadOnlySourceIdentity({ ...valid, sourceSha: "b".repeat(40) }), /does not equal/);
  assert.throws(() => assertReadOnlySourceIdentity({ ...valid, currentHead: "b".repeat(40) }), /does not equal/);
  assert.throws(() => assertReadOnlySourceIdentity({ ...valid, originMainHead: "b".repeat(40) }), /does not equal/);
  assert.throws(() => assertReadOnlySourceIdentity({ ...valid, porcelainStatus: " M tracked" }), /clean/);
  assert.throws(() => assertReadOnlySourceIdentity({ ...valid, repositoryState: { ...cleanState, shallow: true } }), /incomplete/);
});

test("lint enforcement and explicit base are passed to every readiness check", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-readiness-lint-test-"));
  const output = path.join(directory, "evidence", "readiness.json");
  const seen = [];
  const git = (args) => {
    if (args[0] === "rev-parse" && args[1] === "HEAD") return sha;
    if (args[0] === "rev-parse" && args[1] === "refs/remotes/origin/main") return sha;
    if (args[0] === "rev-parse" && args[1] === "--is-shallow-repository") return "false";
    if (args[0] === "symbolic-ref") return "refs/remotes/origin/main";
    if (args[0] === "merge-base") return "";
    if (args[0] === "status") return "";
    if (args[0] === "ls-tree") return "100644 blob deadbeef\tREADME.md";
    throw new Error("unexpected git fixture command: " + args.join(" "));
  };
  const report = runReadOnlyReadiness({
    cwd: process.cwd(),
    sourceSha: sha,
    outputPath: output,
    environment: { MSCQR_DEPLOYMENT_MODE: "read-only", MSCQR_TRUSTED_MAIN_SHA: sha },
    runGit: git,
    readGitBytes: () => Buffer.from("fixture"),
    run: (_command, _args, { environment }) => {
      seen.push(environment);
      return { status: 0, stdout: "", stderr: "", durationMs: 0 };
    },
    checks: [{ id: "lint", command: "npm", args: ["run", "lint:changed"] }],
  });
  assert.equal(report.readiness.status, "READ_ONLY_PROOF_COMPLETE");
  assert.equal(seen[0].ENFORCE_LINT_CHANGED, "true");
  assert.equal(seen[0].LINT_CHANGED_BASE_REF, "HEAD^");
  fs.rmSync(directory, { recursive: true, force: true });
});

test("a lint failure blocks readiness instead of becoming report-only success", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-readiness-lint-failure-"));
  const output = path.join(directory, "evidence", "readiness.json");
  const git = (args) => {
    if (args[0] === "rev-parse" && args[1] === "HEAD") return sha;
    if (args[0] === "rev-parse" && args[1] === "refs/remotes/origin/main") return sha;
    if (args[0] === "rev-parse" && args[1] === "--is-shallow-repository") return "false";
    if (args[0] === "symbolic-ref") return "refs/remotes/origin/main";
    if (args[0] === "merge-base") return "";
    if (args[0] === "status") return "";
    if (args[0] === "ls-tree") return "100644 blob deadbeef\tREADME.md";
    throw new Error("unexpected git fixture command: " + args.join(" "));
  };
  const report = runReadOnlyReadiness({
    cwd: process.cwd(),
    sourceSha: sha,
    outputPath: output,
    environment: { MSCQR_DEPLOYMENT_MODE: "read-only", MSCQR_TRUSTED_MAIN_SHA: sha },
    runGit: git,
    readGitBytes: () => Buffer.from("fixture"),
    run: () => ({ status: 1, stdout: "", stderr: "eslint violation", durationMs: 0 }),
    checks: [{ id: "lint", command: "npm", args: ["run", "lint:changed"] }],
  });
  assert.equal(report.readiness.status, "BLOCKED");
  assert.equal(report.readiness.blockedReason, "lint:CHECK_FAILED");
  fs.rmSync(directory, { recursive: true, force: true });
});

test("source tree identity is a canonical SHA-256 content identity, not a Git object id", () => {
  const first = canonicalSourceTreeSha256([{ mode: "100644", path: "a.js", blobSha256: "1".repeat(64) }]);
  const second = canonicalSourceTreeSha256([{ mode: "100644", path: "a.js", blobSha256: "2".repeat(64) }]);
  assert.match(first, /^[a-f0-9]{64}$/);
  assert.notEqual(first, second);
});

test("deployment mode is an executable kill switch", () => {
  assert.doesNotThrow(() => assertReadOnlyMode({ mode: "read-only", environment: { MSCQR_DEPLOYMENT_MODE: "read-only" } }));
  assert.throws(() => assertReadOnlyMode({ mode: "production", environment: { MSCQR_DEPLOYMENT_MODE: "read-only" } }), /read-only/);
  assert.throws(() => assertReadOnlyMode({ mode: "read-only", environment: { MSCQR_DEPLOYMENT_MODE: "production" } }), /read-only/);
});

test("workflow does not create an AWS identity or enable Phase 2 mutation", () => {
  assert.equal(workflow.jobs["read-only-readiness"].environment, undefined);
  assert.equal(workflow.jobs["read-only-readiness"].permissions, undefined);
  assert.match(workflowText, /read-only production readiness/i);
  assert.doesNotMatch(workflowText, /environment:\s*production\s*$/m);
});

test("read-only orchestrator writes a bounded success report without mutation commands", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-readiness-test-"));
  const output = path.join(directory, "evidence", "readiness.json");
  const git = (args) => {
    if (args[0] === "fetch") return "";
    if (args[0] === "rev-parse" && args[1] === "FETCH_HEAD") return sha;
    if (args[0] === "rev-parse" && args[1] === "HEAD") return sha;
    if (args[0] === "rev-parse" && args[1] === "refs/remotes/origin/main") return sha;
    if (args[0] === "rev-parse" && args[1] === "--is-shallow-repository") return "false";
    if (args[0] === "ls-tree") return "100644 blob deadbeef\tREADME.md";
    if (args[0] === "symbolic-ref") return "refs/remotes/origin/main";
    if (args[0] === "merge-base") return "";
    if (args[0] === "status") return "";
    throw new Error(`unexpected git fixture command: ${args.join(" ")}`);
  };
  const report = runReadOnlyReadiness({
    cwd: process.cwd(),
    sourceSha: sha,
    outputPath: output,
    environment: { MSCQR_DEPLOYMENT_MODE: "read-only", MSCQR_TRUSTED_MAIN_SHA: sha },
    runGit: git,
    readGitBytes: () => Buffer.from("fixture"),
    run: () => ({ status: 0, stdout: "", stderr: "", durationMs: 0 }),
    checks: READ_ONLY_CHECKS.slice(0, 1),
  });
  assert.equal(report.readiness.status, "READ_ONLY_PROOF_COMPLETE");
  assert.equal(report.mutationReachable, false);
  assert.equal(JSON.parse(fs.readFileSync(output, "utf8")).sourceSha, sha);
  assert.equal((fs.statSync(output).mode & 0o777), 0o600);
  fs.rmSync(directory, { recursive: true, force: true });
});
