#!/usr/bin/env node
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import yaml from "js-yaml";
import { RELEASE_PREREQUISITE_TRANSITIONS } from "./production-release-coordinator.mjs";
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
  "Prepare governed green backend recovery handoff", "Verify backend health",
  "Commit authenticated backend recovery component state",
];

export function assertBackendRecoveryWorkflowGraph(workflow, operation = yaml.load(fs.readFileSync(path.join(root, ".github/workflows/production-green-backend-recovery-operation.yml"), "utf8"))) {
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
  for (const name of ["Full RLS verification and PostgreSQL 18.4 certification",
    "Authenticate production environment approval boundary"])
    assert.equal(steps.find((step) => step.name === name).if, undefined, `${name} must remain mandatory`);
  for (const name of ["Backend build and tests", "Frontend typecheck, tests, and build",
    "Install Playwright browser", "Disposable integration tests"])
    assert.equal(steps.find((step) => step.name === name)?.if,
      "${{ inputs.release_mode != 'backend-health-recovery' }}",
      `${name} may be reused only by authenticated backend recovery`);
  const recovery = steps.find((step) => step.name === requiredSteps.at(-3));
  assert.equal(recovery.if, "${{ inputs.release_mode == 'backend-health-recovery' && contains(inputs.backend_recovery_current_task_definition_arn, '/mscqr-production-rls-green-backend-candidate:') }}");
  assert.equal(steps.find((step) => step.name === requiredSteps.at(-1)).if,
    "${{ inputs.release_mode == 'backend-health-recovery' && !contains(inputs.backend_recovery_current_task_definition_arn, '/mscqr-production-rls-green-backend-candidate:') }}");
  assert.equal(steps.find((step) => step.name === "Verify backend health").if,
    "${{ inputs.release_mode != 'backend-health-recovery' || !contains(inputs.backend_recovery_current_task_definition_arn, '/mscqr-production-rls-green-backend-candidate:') }}");
  assert.equal(steps.find((step) => step.name === "Configure AWS credentials via OIDC").with["role-to-assume"],
    "${{ env.PRODUCTION_RELEASE_ROLE_ARN }}");
  assert.match(steps.find((step) => step.name === "Authenticate production environment approval boundary").run || "",
    /--require-actual-approval/);
  for (const file of ["scripts/aws/extract-production-backend-recovery-dispatch-bundle.mjs",
    "scripts/aws/recover-production-green-backend-health.mjs", "scripts/aws/verify-production-smoke.sh",
    "scripts/aws/commit-production-component-recovery-state.mjs"])
    assert.ok(fs.statSync(path.join(root, file)).isFile(), `Release Gate consumer is missing: ${file}`);
  assert.match(recovery.run || "", /extract-production-backend-recovery-dispatch-bundle\.mjs[\s\S]*recover-production-green-backend-health\.mjs[\s\S]*--prepare-handoff/);
  const execution = workflow.jobs["execute-green-backend-recovery"];
  assert.deepEqual(execution?.needs, ["resolve-deploy-target", "deploy-production-ecs"]);
  const trust = JSON.parse(fs.readFileSync(path.join(root, "infra/aws/terraform/production-component-deployment-state/normal-deployer-trust-policy.json"), "utf8"));
  assert.equal(execution.uses, trust.Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:job_workflow_ref"][1]);
  assert.equal(execution.steps, undefined);
  assert.equal(execution.permissions["id-token"], "write");
  assert.equal(execution.with.source_sha, "${{ needs.resolve-deploy-target.outputs.deploy_sha }}");
  assert.equal(execution.with.approval_sha256, "${{ needs.deploy-production-ecs.outputs.green_approval_sha256 }}");
  const executeJob = operation.jobs?.["execute-green-backend-recovery"];
  assert.equal(executeJob?.environment, "production-normal-deploy");
  const executeSteps = executeJob.steps || [];
  const terraform = executeSteps.findIndex((step) => step.name === "Install pinned Terraform for approved runtime policy recheck");
  const assume = executeSteps.findIndex((step) => step.name === "Assume exact normal-deployer role through protected OIDC environment");
  const activate = executeSteps.findIndex((step) => step.name === "Execute one-use green backend recovery under normal-deployer");
  const smoke = executeSteps.findIndex((step) => step.name === "Verify recovered backend health");
  const commit = executeSteps.findIndex((step) => step.name === "Commit authenticated green recovery component state");
  assert.ok(terraform >= 0 && terraform < assume && activate > assume && smoke > activate && commit > smoke);
  assert.equal(executeSteps[terraform].uses, "hashicorp/setup-terraform@b9cd54a3c349d3f38e8881555d616ced269862dd");
  assert.equal(executeSteps[terraform].with.terraform_version, "1.15.8");
  assert.equal(executeSteps[terraform].with.terraform_wrapper, false);
  assert.equal(executeSteps[assume].with["role-to-assume"], "arn:aws:iam::368992683803:role/mscqr-production-normal-deployer");
  assert.match(executeSteps[activate].run || "", /--execute-handoff --credential-source github-oidc-normal-deployer/);
  assert.match(executeSteps[activate].run || "", /assumed-role\/mscqr-production-normal-deployer\/GitHubActions/);
  assert.equal(executeSteps[commit].env.MSCQR_AWS_CREDENTIAL_SOURCE, "github-oidc-normal-deployer");
  assert.match(fs.readFileSync(path.join(root, "scripts/aws/recover-production-green-backend-health.mjs"), "utf8"),
    /argv\.includes\("--certify-only"\)[\s\S]*certifyGreenBackendRecoveryPreDispatch/);
  assert.match(steps.find((step) => step.name === "Full RLS verification and PostgreSQL 18.4 certification").run || "",
    /backend-health-recovery[\s\S]*assert-backend-recovery-ci-certification\.mjs[\s\S]*else[\s\S]*npm run rls:full-verify[\s\S]*npm run rls:full-certify/);
  assert.ok(fs.statSync(path.join(root, "scripts/github/assert-backend-recovery-ci-certification.mjs")).isFile());
  return true;
}

// A non-authorizing graph check; AWS writes still require their native plan/approval gates.
export function assertApplicationReleaseWorkflowGraph({ train, gate, web, coordinatorAction, transitions = RELEASE_PREREQUISITE_TRANSITIONS, iamInstallation } = {}) {
  const read = file => yaml.load(fs.readFileSync(path.join(root, ".github/workflows", file), "utf8"));
  train ||= read("release-train.yml"); gate ||= read("release-gate.yml"); web ||= read("production-web-activation.yml");
  coordinatorAction ||= yaml.load(fs.readFileSync(path.join(root, ".github/actions/converge-stage-b-prerequisites/action.yml"), "utf8"));
  assert.equal(train.jobs.orchestrate.environment, "production");
  assert.equal(gate.jobs["deploy-production-ecs"].environment, "production");
  assert.equal(web.jobs.activate.environment, "production");
  assert.equal(train.jobs.orchestrate.if, undefined);
  assert.equal(web.jobs.activate.if, undefined);
  assert.equal(gate.jobs["deploy-production-ecs"].if, "${{ needs.resolve-deploy-target.outputs.deploy_sha != '' }}");
  assert.equal(train.jobs.orchestrate.env.B03_REQUIREMENTS_REFERENCE_JSON, "${{ inputs.b03_requirements_reference_json }}");
  assert.equal(train.jobs.orchestrate.env.DATABASE_INSTALL_MODE, "${{ inputs.database_install_mode }}");
  const upfront = train.jobs.gates.steps.find(step => step.name === "Validate B03 requirements before dispatching expensive gates");
  assert.ok(upfront?.run.includes("validateB03RequirementReferences"));
  assert.ok(train.jobs.gates.steps.indexOf(upfront) < train.jobs.gates.steps.findIndex(step => step.name === "Trigger required workflow gates"));
  const steps = gate.jobs["deploy-production-ecs"].steps;
  const sql = steps.findIndex(step => step.run?.includes("apply-production-b03-incremental-release.mjs"));
  const backend = steps.findIndex(step => step.name === "Prepare governed green backend recovery handoff");
  assert.ok(sql >= 0 && backend > sql, "Verified SQL must precede backend activation");
  const script = steps[sql].run;
  assert.match(script, /--mode "\$b03_mode"/); assert.match(script, /--compatibility-reference/);
  assert.match(script, /if \[\[ "\$b03_mode" == start \]\]/);
  const b03 = script.slice(script.indexOf('if [[ -n "$B03_APPROVAL_REFERENCE_JSON" ]]'), script.indexOf("elif [["));
  assert.ok(b03.includes("apply-production-b03-incremental-release.mjs"));
  assert.doesNotMatch(b03, /apply-production-rls|aws\s+ecs\s+run-task|register-task-definition/);
  const installationFile = "documents/ops/iam/MSCQRProductionGreenStageBB03RegistrationInstallation-v1.json";
  iamInstallation ||= JSON.parse(fs.readFileSync(path.join(root, installationFile), "utf8"));
  assert.equal(iamInstallation.kind, "BOUNDED_B03_REGISTRATION_IAM_INSTALLATION");
  assert.equal(iamInstallation.account, "368992683803"); assert.equal(iamInstallation.region, "eu-west-2");
  assert.equal(iamInstallation.executionPrincipal, "arn:aws:iam::368992683803:root");
  assert.equal(iamInstallation.operator, "T-ej2003");
  assert.equal(iamInstallation.roleArn, "arn:aws:iam::368992683803:role/mscqr-production-release-deployer");
  assert.equal(iamInstallation.policyName, "MSCQRProductionGreenStageBB03Registration");
  assert.equal(iamInstallation.policyArn, `arn:aws:iam::368992683803:policy/${iamInstallation.policyName}`);
  assert.equal(iamInstallation.policyFile, "documents/ops/iam/MSCQRProductionGreenStageBB03Registration-v1.json");
  assert.equal(iamInstallation.policyFileSha256, createHash("sha256").update(fs.readFileSync(path.join(root, iamInstallation.policyFile))).digest("hex"));
  assert.deepEqual(iamInstallation.mutatingActions, ["iam:CreatePolicy", "iam:AttachRolePolicy"]);
  assert.deepEqual(iamInstallation.requiredSimulationIds, ["b03-register", "b03-tag", "b03-pass-execution"]);
  assert.deepEqual(iamInstallation.forbiddenSimulationIds, ["b03-deny-runtask", "b03-deny-starttask", "b03-deny-administrator-secret-read"]);
  assert.equal(iamInstallation.beforeRegistration, true); assert.equal(iamInstallation.noExistingPolicyUpdates, true);
  assert.equal(iamInstallation.noTaskLaunchOrSecretRead, true);
  assert.equal(iamInstallation.automation, "MANUAL_ROOT_ADMIN_PROCEDURE_NOT_AUTOMATED_RECONCILER");
  const authenticateWeb = web.jobs.activate?.steps?.find(step => step.name === "Authenticate coordinated Stage-B and web evidence")
    || Object.values(web.jobs).flatMap(job => job.steps || []).find(step => step.name === "Authenticate coordinated Stage-B and web evidence");
  assert.equal(authenticateWeb?.env.BACKEND_ACTIVATION_EVIDENCE_JSON, "${{ inputs.backend_activation_evidence_json }}");
  // Derive scheduling edges from actual jobs.needs and sequential steps, not a proposed rollout list.
  const nodes = [], locations = new Map();
  const addWorkflow = (name, workflow) => {
    const ends = new Map();
    for (const [jobId, job] of Object.entries(workflow.jobs)) {
      const start = `${name}:${jobId}`;
      const node = { id: start, kind: "job", source: name, needs: [], uses: job.uses, condition: job.if };
      nodes.push(node);
      let previous = start;
      for (const [index, step] of (job.steps || []).entries()) {
        const id = `${start}:${index}`;
        nodes.push({ id, kind: "step", source: name, job: jobId, index, name: step.name, uses: step.uses, condition: step.if, needs: [previous] });
        if (step.name) {
          const key = `${start}:${step.name}`;
          assert.ok(!locations.has(key), `Ambiguous release step ${key}`);
          locations.set(key, { id, step });
        }
        previous = id;
      }
      ends.set(jobId, previous);
    }
    for (const [jobId, job] of Object.entries(workflow.jobs)) {
      const needs = job.needs === undefined ? [] : Array.isArray(job.needs) ? job.needs : [job.needs];
      assert.ok(needs.every(id => ends.has(id)), `Unknown ${name} job dependency`);
      nodes.find(node => node.id === `${name}:${jobId}`).needs = needs.map(id => ends.get(id));
    }
    return ends;
  };
  addWorkflow("train", train); addWorkflow("gate", gate); addWorkflow("web", web);
  const locate = (workflow, job, name) => {
    const value = locations.get(`${workflow}:${job}:${name}`);
    assert.notEqual(value?.step["continue-on-error"], true, "Mandatory release operation cannot continue on error");
    assert.ok(value, `Missing release operation ${workflow}/${job}/${name}`); return value;
  };
  const node = id => { const value = nodes.find(node => node.id === id); assert.ok(value, `Missing graph node ${id}`); return value; };
  const dependsOn = (id, predecessor, visited = new Set()) => {
    assert.ok(!visited.has(id), `Release dependency cycle at ${id}`);
    if (id === predecessor) return true;
    return node(id).needs.some(parent => dependsOn(parent, predecessor, new Set([...visited, id])));
  };
  const requireOrder = operations => {
    operations.slice(1).forEach((operation, index) => assert.ok(dependsOn(operation.id, operations[index].id),
      `Release operation is out of order: ${operation.step.name}`));
  };
  const trainOp = name => locate("train", "orchestrate", name);
  const converge = trainOp("Converge exact Stage B prerequisites");
  assert.equal(converge.step.uses, "./.github/actions/converge-stage-b-prerequisites");
  assert.equal(coordinatorAction.runs?.using, "composite");
  const actionEnds = addWorkflow("coordinator-action", { jobs: { run: { steps: coordinatorAction.runs.steps } } });
  node("coordinator-action:run").needs.push(converge.id);
  const command = locate("coordinator-action", "run", "Resume exact release coordinator");
  assert.match(command.step.run, /node scripts\/aws\/run-production-release-coordinator\.mjs/);
  assert.deepEqual(transitions, [
    ["registration", "prepare-registration", "register", "recover-registration"],
    ["pruning", "prepare-pruning", "prune", "recover-policy"],
    ["policy", "prepare-policy", "converge-policy", "recover-policy"],
    ["publication", "prepare-publication", "publish", "recover-publication"],
    ["cutover", "prepare-cutover", "cutover", "recover-cutover"],
    ["closure", null, "reconcile", "recover-reconciliation"],
  ], "Production coordinator phase operations/order changed");
  let previous = command.id;
  for (const [phase, prepare, execute, recover] of transitions) {
    const id = `coordinator:${phase}`;
    nodes.push({ id, kind: "coordinator-phase", source: "scripts/aws/production-release-coordinator.mjs", prepare, execute, recover, needs: [previous] });
    previous = id;
  }
  // The composite result cannot be consumed before its production phase loop returns.
  const next = nodes.find(n => n.source === "train" && n.needs.includes(converge.id));
  assert.ok(next, "Missing coordinator closure consumer");
  next.needs = next.needs.map(id => id === converge.id ? previous : id);
  assert.equal(actionEnds.get("run"), command.id, "Coordinator command must remain the final composite step");
  const closure = trainOp("Require authenticated prerequisite closure"), dispatch = trainOp("Trigger final Release Gate");
  assert.match(closure.step.run, /PREREQUISITES_CONVERGED/);
  assert.match(dispatch.step.run, /node scripts\/github\/dispatch-protected-main-release-gate\.mjs/);
  requireOrder([locate("train", "gates", "Wait for required workflow gates"), trainOp("Authenticate unchanged protected source"), converge, closure, dispatch]);
  node("gate:resolve-deploy-target").needs.push(dispatch.id);
  const gateOp = name => locate("gate", "deploy-production-ecs", name);
  const sqlOp = gateOp("Apply and verify checksum-bound production RLS package");
  assert.equal(sqlOp.id, locate("gate", "deploy-production-ecs", steps[sql].name).id);
  const startBranch = script.match(/if \[\[ "\$b03_mode" == start \]\]; then([\s\S]*?)\n\s*fi/);
  assert.match(startBranch?.[1] || "", /^\s*exit 1\s*$/m, "B03 initiation cannot continue to backend activation");
  requireOrder([locate("gate", "resolve-deploy-target", "Final required-gate sanity check"),
    gateOp("Authenticate production environment approval boundary"), gateOp("Authenticate normal release image authorization"), sqlOp,
    gateOp("Upload immutable production database receipt"), gateOp("Activate exact Stage-B backend candidate"),
    gateOp("Verify backend health"), gateOp("Activate authenticated frontend image"), gateOp("Verify production after frontend activation")]);
  assert.match(gateOp("Activate exact Stage-B backend candidate").step.run, /--mode execute/);
  assert.match(gateOp("Verify backend health").step.run, /verify-production-smoke\.sh/);
  assert.match(gateOp("Activate authenticated frontend image").step.run, /--backend-activation-evidence/);
  assert.match(gateOp("Verify production after frontend activation").step.run, /run-production-release-gate-smoke\.mjs/);
  for (const [operation, condition] of [
    [trainOp("Authenticate unchanged protected source"), undefined],
    [converge, "needs.gates.outputs.target_ref == 'main'"],
    [closure, "needs.gates.outputs.target_ref == 'main'"],
    [dispatch, "${{ !inputs.prerequisites_only && !inputs.trusted_terminal_cutover }}"],
    ...[sqlOp, gateOp("Upload immutable production database receipt"), gateOp("Activate exact Stage-B backend candidate"), gateOp("Verify production after frontend activation")]
      .map(operation => [operation, "${{ inputs.release_mode == 'normal' }}"]),
    [gateOp("Verify backend health"), "${{ inputs.release_mode != 'backend-health-recovery' || !contains(inputs.backend_recovery_current_task_definition_arn, '/mscqr-production-rls-green-backend-candidate:') }}"],
    [gateOp("Activate authenticated frontend image"), "${{ inputs.release_mode == 'normal' && steps.images.outputs.web_required == 'true' }}"],
  ]) assert.equal(operation.step.if, condition, `Release execution condition changed: ${operation.step.name}`);
  const webOp = locate("web", "activate", "Authenticate coordinated Stage-B and web evidence");
  assert.equal(webOp.step.if, undefined);
  assert.match(webOp.step.run, /--backend-activation-evidence/);
  node(webOp.id).needs.push(gateOp("Verify backend health").id);
  for (const value of nodes) for (const dependency of value.needs) { node(dependency); assert.ok(!dependsOn(dependency, value.id), "Release graph contains a cycle"); }
  return { nodes, productionExecutionReady: false,
    externalOperations: [
      { id: "bounded-registration-iam-installation", before: "coordinator:registration", source: installationFile, package: iamInstallation, status: "SEPARATE_PRIVILEGED_APPROVAL_REQUIRED" },
      { id: "c02-independent-verification", before: sqlOp.id, source: "scripts/aws/apply-production-c02-session-prerequisite.mjs", status: "SEPARATE_ROOT_APPROVAL_AND_RECEIPT_REQUIRED" },
      { id: "worker-activation", after: gateOp("Verify production after frontend activation").id, source: "infra/aws/terraform/production-support-email-worker/main.tf", status: "SEPARATE_STATE_LOCKED_PLAN_APPROVAL_REQUIRED" },
    ],
    liveOnly: ["separately approved B03 registration policy installation and native IAM verification", "fresh plans and exact-plan approvals", "native post-apply identity and broker CAS", "committed SQL catalogue", "running ECS digests, health and application smoke", "SMTP delivery monitoring"] };

}

export function assertSourceCertificationWorkflowGraph(workflow) {
  const job = workflow?.jobs?.["backend-recovery-certification"];
  assert.ok(job, "Source certification job is missing");
  assert.equal(job.if, undefined, "Source certification cannot be skipped");
  assert.deepEqual(job.needs, requiredSameRunJobs);
  assert.deepEqual(job.permissions, { contents: "read" });
  assert.equal(job["runs-on"], "ubuntu-24.04");
  assert.equal(job.services?.postgres?.image, ciImageReference(readApprovedImages().postgres));
  assert.equal(job.services?.redis, undefined, "Duplicate Redis service is not required for RLS certification");
  assert.equal(job.steps?.find((step) => step.uses?.startsWith("actions/checkout@"))?.with?.["persist-credentials"], false);
  const fullRls = job.steps?.find((step) => step.name === "Certify full RLS on disposable PostgreSQL 18.4");
  assert.equal(fullRls?.if, undefined, "Disposable PostgreSQL certification cannot be skipped");
  assert.match(fullRls?.run || "",
    /timeout --kill-after=30s 120m npm run rls:full-certify/);
  for (const name of ["backend", "frontend", "integration", "full-rls-package"])
    assert.equal(workflow?.jobs?.[name]?.if, undefined, `${name} cannot be skipped by source certification`);
  for (const [jobName, stepName, command] of [
    ["backend", "Backend quality contract", "npm run verify:ci:backend"],
    ["frontend", "Frontend quality contract", "npm run verify:ci:frontend"],
    ["frontend", "Playwright smoke suite", "npm run verify:ci:frontend:e2e"],
    ["integration", "Disposable system integration suite", "npm run test:integration:ci"],
    ["full-rls-package", "Full RLS verification", "npm run rls:full-verify"],
  ]) {
    const step = workflow.jobs[jobName].steps?.find((item) => item.name === stepName);
    assert.equal(step?.if, undefined, `${stepName} cannot be skipped`);
    assert.ok(step?.run?.includes(command), `${stepName} no longer runs ${command}`);
  }
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
  const releaseGraph = assertApplicationReleaseWorkflowGraph();
  if (options.includes("--graph-only")) {
    assert.ok(sourceOnly && liveArgs.length === 0, "Graph-only certification never authorizes live execution");
    process.stdout.write(`${JSON.stringify({ status: "SOURCE_GRAPH_CHECKED", sourceSha, ...releaseGraph })}\n`); return;
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
