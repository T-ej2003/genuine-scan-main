#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import yaml from "js-yaml";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const workflowPath = path.join(root, ".github/workflows/release-gate.yml");
const requiredSteps = [
  "Checkout authenticated execution source", "Verify exact clean main checkout", "Install dependencies deterministically",
  "Backend build and tests", "Frontend typecheck, tests, and build", "Disposable integration tests",
  "Full RLS verification and PostgreSQL 18.4 certification", "Authenticate production environment approval boundary",
  "Require enabled production OIDC source phase", "Configure AWS credentials via OIDC", "Verify AWS account",
  "Execute governed green backend health recovery with verified Terraform source", "Verify backend health",
  "Commit authenticated backend recovery component state",
];

export function assertBackendRecoveryWorkflowGraph(workflow) {
  assert.deepEqual(workflow?.on?.workflow_dispatch?.inputs?.release_mode?.options,
    ["normal", "backend-health-recovery", "rotation-overlap", "rotation-cleanup"]);
  assert.deepEqual(workflow?.concurrency, { group: "production-deploy", "cancel-in-progress": false });
  const resolve = workflow?.jobs?.["resolve-deploy-target"];
  const deploy = workflow?.jobs?.["deploy-production-ecs"];
  assert.ok(resolve && deploy && deploy.needs === "resolve-deploy-target");
  assert.equal(deploy.environment, "production");
  assert.equal(deploy.permissions["id-token"], "write");
  assert.equal(deploy["runs-on"], "ubuntu-24.04");
  assert.match(deploy.services?.postgres?.image || "", /^docker\.io\/library\/postgres@sha256:[a-f0-9]{64}$/);
  assert.match(deploy.services?.redis?.image || "", /^docker\.io\/library\/redis@sha256:[a-f0-9]{64}$/);
  assert.equal(deploy.env.AWS_ACCOUNT_ID_EXPECTED, "368992683803");
  assert.equal(deploy.env.AWS_REGION, "eu-west-2");
  assert.equal(deploy.env.PRODUCTION_RELEASE_ROLE_ARN, "arn:aws:iam::368992683803:role/mscqr-production-release-deployer");
  const steps = deploy.steps || [];
  let prior = -1;
  for (const name of requiredSteps) {
    const at = steps.findIndex((step) => step.name === name);
    assert.ok(at > prior, `Release Gate step is missing or out of order: ${name}`);
    prior = at;
  }
  for (const name of ["Disposable integration tests", "Full RLS verification and PostgreSQL 18.4 certification",
    "Authenticate production environment approval boundary", "Verify backend health"])
    assert.equal(steps.find((step) => step.name === name).if, undefined, `${name} must remain mandatory`);
  const recovery = steps.find((step) => step.name === requiredSteps.at(-3));
  assert.equal(recovery.if, "${{ inputs.release_mode == 'backend-health-recovery' && contains(inputs.backend_recovery_current_task_definition_arn, '/mscqr-production-rls-green-backend-candidate:') }}");
  assert.equal(steps.find((step) => step.name === requiredSteps.at(-1)).if,
    "${{ inputs.release_mode == 'backend-health-recovery' }}");
  assert.equal(steps.find((step) => step.name === "Configure AWS credentials via OIDC").with["role-to-assume"],
    "${{ env.PRODUCTION_RELEASE_ROLE_ARN }}");
  assert.match(steps.find((step) => step.name === "Authenticate production environment approval boundary").run || "",
    /--require-actual-approval/);
  for (const file of ["scripts/aws/extract-production-backend-recovery-dispatch-bundle.mjs",
    "scripts/aws/recover-production-green-backend-health.mjs", "scripts/aws/verify-production-smoke.sh",
    "scripts/aws/commit-production-component-recovery-state.mjs"])
    assert.ok(fs.statSync(path.join(root, file)).isFile(), `Release Gate consumer is missing: ${file}`);
  assert.match(recovery.run || "", /extract-production-backend-recovery-dispatch-bundle\.mjs[\s\S]*recover-production-green-backend-health\.mjs/);
  assert.match(fs.readFileSync(path.join(root, "scripts/aws/recover-production-green-backend-health.mjs"), "utf8"),
    /argv\.includes\("--certify-only"\)[\s\S]*certifyGreenBackendRecoveryPreDispatch/);
  assert.match(steps.find((step) => step.name === "Full RLS verification and PostgreSQL 18.4 certification").run || "",
    /npm run rls:full-verify[\s\S]*npm run rls:full-certify/);
  return true;
}

const run = (command, args, env = process.env) => execFileSync(command, args, { cwd: root, env,
  stdio: "inherit", timeout: 30 * 60_000 });

export function main(argv = process.argv.slice(2)) {
  const separator = argv.indexOf("--");
  const options = separator < 0 ? argv : argv.slice(0, separator);
  const liveArgs = separator < 0 ? [] : argv.slice(separator + 1);
  const value = (flag) => { const at = options.indexOf(flag); return at < 0 ? null : options[at + 1]; };
  const sourceSha = value("--source-sha");
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/, "Exact source SHA is required");
  assert.equal(execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim(), sourceSha);
  assert.equal(execFileSync("git", ["status", "--porcelain=v1"], { cwd: root, encoding: "utf8" }).trim(), "", "Certification requires a clean checkout");
  assertBackendRecoveryWorkflowGraph(yaml.load(fs.readFileSync(workflowPath, "utf8")));
  const adminUrl = value("--disposable-postgres-admin-url");
  assert.ok(adminUrl, "A disposable PostgreSQL 18.4 admin URL is required; database certification is NOT VERIFIED");
  const database = new URL(adminUrl);
  assert.equal(database.protocol, "postgresql:");
  assert.ok(["localhost", "127.0.0.1", "::1"].includes(database.hostname), "Certification database must be loopback-local");
  assert.equal(database.password, "", "Certification URL must not contain a password");
  const postgresVersion = execFileSync("psql", [adminUrl, "-Atqc", "SHOW server_version"],
    { cwd: root, encoding: "utf8", timeout: 15_000 }).trim();
  assert.match(postgresVersion, /^18\.4(?:\s|$)/, "Certification requires PostgreSQL 18.4");
  const env = { ...process.env, P2_TEST_DATABASE_REQUIRED: "true", P2_TEST_DB_PROTOCOL: "postgresql",
    P2_TEST_DB_USER: decodeURIComponent(database.username), P2_TEST_DB_HOST: database.hostname,
    P2_TEST_DB_PORT: database.port || "5432", P2_TEST_DB_NAME: database.pathname.slice(1),
    P2_TEST_DATABASE_ADMIN_URL: adminUrl, REDIS_URL: "redis://127.0.0.1:6379/0", REDIS_TLS: "false",
    MSCQR_FULL_RLS_CERTIFICATION_CONFIRM: "MSCQR_RUN_LOCAL_FULL_RLS_CERTIFICATION",
    MSCQR_FULL_RLS_CERTIFICATION_ADMIN_URL: adminUrl };
  for (const args of [
    ["run", "check:workflow-yaml"], ["--prefix", "backend", "run", "build"],
    ["--prefix", "backend", "test"], ["run", "typecheck"], ["test"], ["run", "build"],
    ["run", "test:integration:ci"], ["run", "rls:full-verify"], ["run", "rls:full-certify"],
    ["run", "stage-b:deployment-closure:pull-request"], ["run", "security:release-gate"],
  ]) run("npm", args, env);
  assert.equal(execFileSync("git", ["status", "--porcelain=v1"], { cwd: root, encoding: "utf8" }).trim(), "",
    "Certification modified the source checkout");
  if (options.includes("--source-only")) {
    assert.equal(liveArgs.length, 0, "Source-only certification cannot accept live recovery inputs");
    process.stdout.write(`${JSON.stringify({ status: "SOURCE_CERTIFIED", sourceSha,
      livePrerequisites: "NOT_VERIFIED", productionExecutionReady: false })}\n`);
    return;
  }
  assert.ok(liveArgs.length > 0, "Live recovery evidence and OIDC context are required; production prerequisites are NOT VERIFIED");
  run("node", ["scripts/aws/recover-production-green-backend-health.mjs", "--certify-only", ...liveArgs], env);
  process.stdout.write(`${JSON.stringify({ status: "READ_ONLY_PRE_DISPATCH_CERTIFIED", sourceSha,
    productionExecutionReady: false, reason: "Execution-time authorization, AWS state and journal CAS must be rechecked before mutation" })}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try { main(); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
