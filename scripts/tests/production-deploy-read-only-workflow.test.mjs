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

test("deployment mode is an executable kill switch", () => {
  assert.doesNotThrow(() => assertReadOnlyMode({ mode: "read-only", environment: { MSCQR_DEPLOYMENT_MODE: "read-only" } }));
  assert.throws(() => assertReadOnlyMode({ mode: "production", environment: { MSCQR_DEPLOYMENT_MODE: "read-only" } }), /read-only/);
  assert.throws(() => assertReadOnlyMode({ mode: "read-only", environment: { MSCQR_DEPLOYMENT_MODE: "production" } }), /read-only/);
});

test("workflow does not create an AWS identity or enable Phase 2 mutation", () => {
  assert.equal(workflow.jobs["read-only-readiness"].environment, undefined);
  assert.equal(workflow.jobs["read-only-readiness"].permissions, undefined);
  assert.match(workflowText, /read-only production readiness/i);
  assert.doesNotMatch(workflowText, /production-mutation|production-cutover|recover-stage-b-backend-task-definition|run-production-cutover/);
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
    if (args[0] === "rev-parse" && args[1] === `${sha}^{tree}`) return "tree-hash";
    if (args[0] === "symbolic-ref") return "refs/remotes/origin/main";
    if (args[0] === "merge-base") return "";
    if (args[0] === "status") return "";
    throw new Error(`unexpected git fixture command: ${args.join(" ")}`);
  };
  const report = runReadOnlyReadiness({
    cwd: process.cwd(),
    sourceSha: sha,
    outputPath: output,
    environment: { MSCQR_DEPLOYMENT_MODE: "read-only" },
    runGit: git,
    run: () => ({ status: 0, stdout: "", stderr: "", durationMs: 0 }),
    checks: READ_ONLY_CHECKS.slice(0, 1),
  });
  assert.equal(report.readiness.status, "READ_ONLY_PROOF_COMPLETE");
  assert.equal(report.mutationReachable, false);
  assert.equal(JSON.parse(fs.readFileSync(output, "utf8")).sourceSha, sha);
  assert.equal((fs.statSync(output).mode & 0o777), 0o600);
  fs.rmSync(directory, { recursive: true, force: true });
});
