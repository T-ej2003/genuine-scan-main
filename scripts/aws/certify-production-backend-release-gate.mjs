#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import yaml from "js-yaml";
import { ciImageReference, readApprovedImages } from "../lib/container-image-identity.mjs";
import { assertSafeAdminUrl } from "../rls/certify-clean-room-database.mjs";
import { assertStageBCanonicalRepositoryUrl, readFreshProtectedMainIdentity } from "./stage-b-deployment-identity.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const workflowPath = path.join(root, ".github/workflows/release-gate.yml");
const requiredSameRunJobs = ["app-only-deployment-contract", "full-rls-package", "stage-b-deployment-closure",
  "security", "frontend", "backend", "integration", "docker"];
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
  const images = readApprovedImages();
  assert.equal(deploy.services?.postgres?.image, ciImageReference(images.postgres));
  assert.equal(deploy.services?.redis?.image, ciImageReference(images.redis));
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

export function assertSourceCertificationWorkflowGraph(workflow) {
  const job = workflow?.jobs?.["backend-recovery-certification"];
  assert.ok(job, "Source certification job is missing");
  assert.deepEqual(job.needs, requiredSameRunJobs);
  assert.deepEqual(job.permissions, { contents: "read" });
  assert.equal(job["runs-on"], "ubuntu-24.04");
  assert.equal(job.services?.postgres?.image, ciImageReference(readApprovedImages().postgres));
  assert.equal(job.services?.redis, undefined, "Duplicate Redis service is not required for RLS certification");
  assert.equal(job.steps?.find((step) => step.uses?.startsWith("actions/checkout@"))?.with?.["persist-credentials"], false);
  assert.match(job.steps?.find((step) => step.name === "Certify full RLS on disposable PostgreSQL 18.4")?.run || "",
    /timeout --kill-after=30s 120m npm run rls:full-certify/);
  return true;
}

const run = (command, args, env = process.env, timeout = 60_000) => execFileSync(command, args, { cwd: root, env,
  stdio: ["ignore", "inherit", "inherit"], timeout });

const sourceEnvironmentKeys = ["PATH", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL", "TZ", "CI", "GITHUB_ACTIONS"];

export function certificationSourceEnvironment(ambient = process.env) {
  return Object.fromEntries(sourceEnvironmentKeys.filter((key) => ambient[key] !== undefined)
    .map((key) => [key, ambient[key]]));
}

export function assertUnprivilegedSourceContext(env = process.env) {
  assert.equal(env.GITHUB_ACTIONS, "true", "Source checks require an isolated GitHub Actions runner");
  assert.equal(env.GITHUB_WORKFLOW, "Quality Gate", "Source checks require the Quality Gate workflow");
  assert.ok(["push", "pull_request"].includes(env.GITHUB_EVENT_NAME), "Source checks require a source-validation event");
  assert.ok(!Object.keys(env).some((key) => /^(?:AWS_|GH_TOKEN$|GITHUB_TOKEN$|GITHUB_APP_|ACTIONS_ID_TOKEN_)/i.test(key)),
    "Source checks cannot run with release credentials or privileged tokens");
}

export function disposablePostgresConnection(input, ambient = process.env) {
  // Accept only a literal TCP loopback endpoint; libpq URL options can redirect destructive certification.
  const match = /^postgresql:\/\/([a-z][a-z0-9_]*)@(localhost|127\.0\.0\.1|\[::1\]):([0-9]{1,5})\/([a-z][a-z0-9_]*)$/.exec(input || "");
  assert.ok(match, "Disposable PostgreSQL URL must be a literal loopback TCP endpoint with explicit user, port and database");
  const [, user, host, portText, name] = match;
  const port = Number(portText);
  assert.ok(port >= 1 && port <= 65535 && String(port) === portText, "Disposable PostgreSQL port is invalid");
  const url = `postgresql://${user}@${host === "localhost" ? "127.0.0.1" : host}:${port}/${name}`;
  // The existing full RLS guard compares an unbracketed IPv6 hostname; scope-check its IPv4 loopback equivalent.
  assertSafeAdminUrl(host === "[::1]" ? url.replace("@[::1]", "@127.0.0.1") : url);
  const env = certificationSourceEnvironment(ambient);
  return { url, user, host: host === "localhost" ? "127.0.0.1" : host, port: portText, name, env };
}

export function verifyDisposablePostgresVersion(connection, execute = execFileSync) {
  const version = execute("psql", [connection.url, "-X", "-Atqc", "SHOW server_version"],
    { cwd: root, env: connection.env, encoding: "utf8", timeout: 15_000 }).trim();
  assert.match(version, /^18\.4(?:\s|$)/, "Certification requires PostgreSQL 18.4");
}

export function main(argv = process.argv.slice(2)) {
  const separator = argv.indexOf("--");
  const options = separator < 0 ? argv : argv.slice(0, separator);
  const liveArgs = separator < 0 ? [] : argv.slice(separator + 1);
  const value = (flag) => { const at = options.indexOf(flag); return at < 0 ? null : options[at + 1]; };
  const sourceSha = value("--source-sha");
  assert.match(sourceSha || "", /^[a-f0-9]{40}$/, "Exact source SHA is required");
  assert.equal(execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim(), sourceSha);
  assert.equal(execFileSync("git", ["status", "--porcelain=v1"], { cwd: root, encoding: "utf8" }).trim(), "", "Certification requires a clean checkout");
  const sourceOnly = options.includes("--source-only");
  if (!sourceOnly) {
    assertStageBCanonicalRepositoryUrl(execFileSync("git", ["remote", "get-url", "origin"], { cwd: root, encoding: "utf8" }).trim());
    readFreshProtectedMainIdentity({ cwd: root, expectedSourceSha: sourceSha });
  }
  assertBackendRecoveryWorkflowGraph(yaml.load(fs.readFileSync(workflowPath, "utf8")));
  if (!sourceOnly) {
    assert.ok(liveArgs.length > 0, "Live recovery evidence and OIDC context are required; production prerequisites are NOT VERIFIED");
    run("node", ["scripts/aws/recover-production-green-backend-health.mjs", "--certify-only", ...liveArgs], process.env, 10 * 60_000);
    process.stdout.write(`${JSON.stringify({ status: "READ_ONLY_PRE_DISPATCH_CERTIFIED", sourceSha,
      productionExecutionReady: false, reason: "Execution-time authorization, AWS state and journal CAS must be rechecked before mutation" })}\n`);
    return;
  }
  assertUnprivilegedSourceContext();
  assert.equal(liveArgs.length, 0, "Source-only certification cannot accept live recovery inputs");
  assertSourceCertificationWorkflowGraph(yaml.load(fs.readFileSync(path.join(root, ".github/workflows/quality-gate.yml"), "utf8")));
  const adminUrl = value("--disposable-postgres-admin-url");
  assert.ok(adminUrl, "A disposable PostgreSQL 18.4 admin URL is required; database certification is NOT VERIFIED");
  const database = disposablePostgresConnection(adminUrl);
  verifyDisposablePostgresVersion(database);
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-source-cert-home-"));
  try {
    run("node", ["--test", "scripts/tests/certify-production-backend-release-gate.test.mjs",
      "scripts/tests/production-green-backend-health-recovery.test.mjs"], { ...database.env, HOME: home });
  } finally { fs.rmSync(home, { recursive: true, force: true }); }
  assert.equal(execFileSync("git", ["status", "--porcelain=v1"], { cwd: root, encoding: "utf8" }).trim(), "",
    "Certification modified the source checkout");
  assert.equal(execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim(), sourceSha,
    "Certification source changed during focused checks");
  process.stdout.write(`${JSON.stringify({ status: "SOURCE_GRAPH_CERTIFIED", sourceSha,
    requiredSameRunJobs,
    livePrerequisites: "NOT_VERIFIED", productionExecutionReady: false })}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try { main(); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
