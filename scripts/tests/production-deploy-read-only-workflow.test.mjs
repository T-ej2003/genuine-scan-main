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

test("normal production deployment is automatically triggered from protected main", () => {
  assert.ok(Object.hasOwn(workflow.on || workflow[true] || {}, "workflow_dispatch"));
  assert.ok(workflow.on?.push?.branches?.includes("main") || workflow[true]?.push?.branches?.includes("main"));
  assert.match(workflowText, /ref: '\$\{\{ github\.sha \}\}'/);
  assert.match(workflowText, /prepare-production-normal-deployment\.mjs/);
});

test("normal workflow rejects non-main dispatch and verifies exact protected source", () => {
  assert.equal(workflow.jobs.classify.if, "github.ref == 'refs/heads/main'");
  assert.match(workflowText, /test \"\$GITHUB_SHA\" = \"\$\(git rev-parse HEAD\)\"/);
  assert.match(workflowText, /git fetch --no-tags origin main/);
  assert.match(workflowText, /refs\/remotes\/origin\/main/);
  assert.match(workflowText, /refs\/remotes\/origin\/main/);
});

test("workflow is OIDC-only, serialized, and uses fixed production boundaries", () => {
  assert.deepEqual(workflow.permissions, { contents: "read", "id-token": "write" });
  assert.equal(workflow.concurrency["cancel-in-progress"], false);
  assert.equal(workflow.concurrency.group, "production-deploy");
  assert.match(workflowText, /configure-aws-credentials@v6/);
  assert.doesNotMatch(workflowText, /AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY/);
  assert.doesNotMatch(workflowText, /role-to-assume:\s*\$\{\{/);
  assert.match(workflowText, /368992683803/);
  assert.match(workflowText, /eu-west-2/);
  assert.match(workflowText, /environment: production/);
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

test("normal workflow has authenticated smoke and preserves the read-only orchestrator as a separate tool", () => {
  const normalRelease = fs.readFileSync(path.resolve("scripts/aws/production-normal-release.mjs"), "utf8");
  assert.match(workflowText, /node scripts\/aws\/production-normal-release\.mjs/);
  assert.match(normalRelease, /runNormalSmoke\(repositoryRoot\)/);
  assert.match(normalRelease, /executeAppOnlyActivation\(preparation/);
  assert.match(normalRelease, /executeNormalFrontendActivation\(/);
  assert.match(workflowText, /SMOKE_AUTHENTICATED_REQUIRED: "true"/);
  assert.doesNotMatch(workflowText, /scripts\/ci\/production-readiness-orchestrator\.mjs/);
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
