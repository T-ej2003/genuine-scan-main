import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
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

test("normal deployment has one protected mutation job and leaves stronger lanes unchanged", () => {
  const bootstrap = yaml.load(fs.readFileSync(".github/workflows/bootstrap-production-component-deployment-state.yml", "utf8"));
  const activation = yaml.load(fs.readFileSync(".github/workflows/authorize-component-infrastructure-activation.yml", "utf8"));
  for (const [job, environment, command] of [
    [workflow.jobs.deploy, "production-normal-deploy", "production-normal-release.mjs"],
    [bootstrap.jobs.bootstrap, "production-component-state-bootstrap", "bootstrap-production-component-deployment-state.mjs"],
  ]) {
    // GitHub evaluates required reviewers before starting any environment job,
    // not through an application-created approval token or fabricated receipt.
    assert.equal(job.environment, environment);
    const credentials = job.steps.findIndex((step) => step.uses === "aws-actions/configure-aws-credentials@v6");
    const mutation = job.steps.findIndex((step) => step.run?.includes(command));
    assert(credentials >= 0 && mutation > credentials);
    assert.equal(job.steps[credentials].with["unset-current-credentials"], true);
    assert(job.steps.some((step) => step.run?.includes("refs/remotes/origin/main")));
  }
  assert.equal(bootstrap.jobs.bootstrap.if, "github.ref == 'refs/heads/main'");
  assert.equal(workflow.jobs.classify.environment, undefined);
  assert(workflow.jobs.deploy.needs.includes("classify"));
  assert.equal(workflow.jobs.deploy.if, "needs.classify.outputs.release_class == 'NORMAL_APPLICATION' || ((needs.classify.outputs.release_class == 'REVIEWED_BASELINE' || needs.classify.outputs.release_class == 'PRIVILEGED_PREREQUISITE_BACKEND') && (needs.classify.outputs.backend == 'true' || needs.classify.outputs.frontend == 'true'))");
  const coordinated = workflow.jobs.deploy.steps.find(({ name }) => name === "Execute coordinated normal component transaction");
  assert.equal(coordinated.if, "needs.classify.outputs.release_class == 'NORMAL_APPLICATION' && needs.classify.outputs.baseline != 'true' && steps.route.outputs.pending == 'true'");
  const directOnly = "needs.classify.outputs.baseline == 'true' || needs.classify.outputs.release_class == 'PRIVILEGED_PREREQUISITE_BACKEND'";
  assert.equal(workflow.jobs.deploy.steps.find(({ name }) => name === "Deploy backend").if, `steps.route.outputs.backend == 'true' && (${directOnly})`);
  assert.equal(workflow.jobs.deploy.steps.find(({ name }) => name === "Deploy frontend").if, `steps.route.outputs.frontend == 'true' && (${directOnly})`);
  assert.equal(workflow.jobs.deploy.steps.find(({ name }) => name === "Verify production health and authenticated smoke").if, directOnly);
  assert.equal(workflow.jobs.deploy.steps.find(({ name }) => name === "Roll back exact predecessors after failure").if, `failure() && (${directOnly})`);
  assert.equal(activation.jobs.authorize.environment, "production-component-infrastructure-activation");
  assert.equal(activation.jobs.authorize.if, "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'");
  assert.deepEqual(activation.permissions, { contents: "read" });
  assert(activation.jobs.authorize.steps.some((step) => step.run?.includes('test "$GITHUB_RUN_ATTEMPT" = 1')));
});

test("normal production deployment is automatically triggered from protected main", () => {
  assert.ok(workflow.on?.push?.branches?.includes("main") || workflow[true]?.push?.branches?.includes("main"));
  assert.match(workflowText, /ref: '\$\{\{ github\.sha \}\}'/);
  assert.match(workflowText, /classify-production-lane-a\.mjs/);
});

test("normal workflow rejects non-main dispatch and verifies exact protected source", () => {
  assert.equal(workflow.jobs.classify.if, "github.ref == 'refs/heads/main'");
  assert.match(workflowText, /test \"\$GITHUB_SHA\" = \"\$\(git rev-parse HEAD\)\"/);
  assert.match(workflowText, /git fetch --no-tags origin main/);
  assert.match(workflowText, /refs\/remotes\/origin\/main/);
  assert.match(workflowText, /refs\/remotes\/origin\/main/);
});

test("workflow is OIDC-only, serialized, and uses fixed production boundaries", () => {
  assert.deepEqual(workflow.permissions, { contents: "read", "pull-requests": "read" });
  assert.deepEqual(workflow.jobs.deploy.permissions, { contents: "read", "id-token": "write" });
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

test("normal workflow uses the canonical component transaction and no parallel authorization protocol", () => {
  assert.match(workflowText, /prepare-production-normal-deployment\.mjs/);
  assert.match(workflowText, /production-normal-release\.mjs/);
  assert.match(workflowText, /MSCQR_APP_ONLY_JOURNAL_DIR/);
  assert.doesNotMatch(workflowText, /authorization artifact/i);
});

test("normal workflow reconciles durable transaction state before deriving any new deployment route", () => {
  const steps = workflow.jobs.deploy.steps;
  const reconcile = steps.findIndex(({ name }) => name === "Reconcile and prepare component-state transaction");
  const legacy = steps.findIndex(({ name }) => name === "Authenticate live deployment baseline");
  const route = steps.findIndex(({ name }) => name === "Bind authoritative deployment route");
  const publish = steps.findIndex(({ name }) => name === "Publish immutable backend image");
  assert.ok(reconcile >= 0 && reconcile < legacy && legacy < route && route < publish);
  assert.equal(steps[reconcile].if, "needs.classify.outputs.release_class == 'NORMAL_APPLICATION' && needs.classify.outputs.baseline != 'true'");
  assert.equal(steps[legacy].if, undefined);
  assert.equal(steps[legacy].env.TRANSACTION_MODE, "${{ needs.classify.outputs.release_class == 'NORMAL_APPLICATION' && needs.classify.outputs.baseline != 'true' }}");
  assert.match(steps[legacy].run, /production-ecs-native-rollback\.mjs[\s\S]*if \[\[ "\$TRANSACTION_MODE" == "true" \]\]; then exit 0; fi[\s\S]*describe-task-definition/);
  assert.match(steps[reconcile].run, /production-normal-release\.mjs --reconcile[\s\S]*prepare-production-normal-deployment\.mjs/);
  assert.doesNotMatch(steps[legacy].run, /classify-production-lane-a\.mjs/);
  for (const name of ["Publish immutable backend image", "Bind backend digest", "Publish immutable frontend image", "Bind frontend digest"])
    assert.match(steps.find((step) => step.name === name).if, /^steps\.route\.outputs\.(?:backend|frontend) == 'true'$/);
});

test("workflow execution cannot prepare new work when reconciliation fails", (t) => {
  const step = workflow.jobs.deploy.steps.find(({ name }) => name === "Reconcile and prepare component-state transaction");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-normal-order-")), log = path.join(directory, "calls");
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  fs.writeFileSync(path.join(directory, "node"), `#!/bin/sh\nprintf '%s\\n' "$*" >> "$CALL_LOG"\nif [ "$FAIL_RECONCILE" = true ] && [ "$2" = --reconcile ]; then exit 42; fi\n`);
  fs.chmodSync(path.join(directory, "node"), 0o700);
  const run = (fail) => execFileSync("bash", ["-c", step.run], { stdio: ["ignore", "pipe", "pipe"], env: { ...process.env,
    PATH: `${directory}:${process.env.PATH}`, RUNNER_TEMP: directory, CALL_LOG: log, FAIL_RECONCILE: String(fail) } });
  assert.throws(() => run(true));
  assert.deepEqual(fs.readFileSync(log, "utf8").trim().split("\n"), ["scripts/aws/production-normal-release.mjs --reconcile"]);
  fs.writeFileSync(log, ""); run(false);
  assert.deepEqual(fs.readFileSync(log, "utf8").trim().split("\n"), [
    "scripts/aws/production-normal-release.mjs --reconcile",
    `scripts/aws/prepare-production-normal-deployment.mjs --output=${directory}/normal-component-deployment-plan.json`,
  ]);
});

test("authoritative route permits reconciliation-only closure and ignores stale event component outputs", (t) => {
  const step = workflow.jobs.deploy.steps.find(({ name }) => name === "Bind authoritative deployment route");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-normal-route-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const run = (classification, classified = { backend: "true", frontend: "false" }, planSourceSha = sha) => {
    const plan = path.join(directory, "normal-component-deployment-plan.json"), output = path.join(directory, `output-${Math.random()}`);
    fs.writeFileSync(plan, JSON.stringify({ schemaVersion: 1, kind: "NORMAL_COMPONENT_DEPLOYMENT_PREPARATION", sourceSha: planSourceSha, classification: { releaseClass: "NORMAL_APPLICATION", worker: false, database: false, ...classification } }));
    execFileSync("bash", ["-c", step.run], { stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, RUNNER_TEMP: directory, GITHUB_OUTPUT: output,
      GITHUB_SHA: sha, RELEASE_CLASS: "NORMAL_APPLICATION", BASELINE_MODE: "false", CLASSIFIED_BACKEND: classified.backend, CLASSIFIED_FRONTEND: classified.frontend } });
    return Object.fromEntries(fs.readFileSync(output, "utf8").trim().split("\n").map((line) => line.split("=")));
  };
  assert.deepEqual(run({ backend: false, frontend: false }), { backend: "false", frontend: "false", pending: "false" });
  assert.deepEqual(run({ backend: false, frontend: true }), { backend: "false", frontend: "true", pending: "true" });
  assert.throws(() => run({ backend: true, frontend: false, releaseClass: "SECURITY_INFRASTRUCTURE" }));
  assert.throws(() => run({ backend: true, frontend: false }, undefined, "b".repeat(40)));
});

test("the documented hostile protocol matrix accounts for every required interruption case", () => {
  const document = fs.readFileSync("documents/ops/NORMAL_PRODUCTION_DEPLOYMENT.md", "utf8");
  const matrix = document.slice(document.indexOf("The hostile interruption matrix"), document.indexOf("## Lane A"));
  const expected = [..."ABCDEFGHIJKLMNOPQRSTUVWXYZ"].map((value) => value).concat([...Array(20)].map((_, index) => `A${String.fromCharCode(65 + index)}`));
  const covered = new Set([...matrix.matchAll(/\b(?:A[A-T]|[A-Z])\b/g)].map(([value]) => value));
  assert.deepEqual([...covered].sort(), expected.sort());
});

test("authenticated committed-state or bounded legacy baseline precedes publication and rollback is failure-only", () => {
  const steps = workflow.jobs.deploy.steps;
  assert.ok(steps.findIndex(({ name }) => name === "Reconcile and prepare component-state transaction") < steps.findIndex(({ name }) => name === "Publish immutable backend image"));
  assert.ok(steps.findIndex(({ name }) => name === "Authenticate live deployment baseline") < steps.findIndex(({ name }) => name === "Publish immutable backend image"));
  assert.match(steps.find(({ name }) => name === "Roll back exact predecessors after failure").if, /^failure\(\).*PRIVILEGED_PREREQUISITE_BACKEND/);
  assert.match(steps.find(({ name }) => name === "Sign and attest published images").env.COSIGN_CERT_IDENTITY_REGEXP, /production-deploy\.yml/);
  assert.equal(workflow.jobs.deploy.environment, "production-normal-deploy");
  assert.equal(workflow.jobs.deploy.env.SMOKE_AUTHENTICATED_REQUIRED, "true");
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
  assert.match(workflowText, /node scripts\/smoke-release\.mjs/);
  assert.match(workflowText, /production-normal-release\.mjs/);
  assert.match(workflowText, /SMOKE_AUTHENTICATED_REQUIRED: "true"/);
  assert.doesNotMatch(workflowText, /scripts\/ci\/production-readiness-orchestrator\.mjs/);
});

test("frontend records immutable source metadata without requesting an unavailable version endpoint", () => {
  const step = workflow.jobs.deploy.steps.find(({ name }) => name === "Deploy frontend");
  assert.equal(step.env.ENV_UPDATES, "GIT_SHA,RELEASE_GIT_SHA");
  assert.equal(step.env.GIT_SHA, "${{ github.sha }}");
  assert.equal(step.env.RELEASE_GIT_SHA, "${{ github.sha }}");
  assert.equal(step.env.EXPECTED_GIT_SHA, undefined);
  assert.equal(step.env.VERSION_URL, undefined);
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
