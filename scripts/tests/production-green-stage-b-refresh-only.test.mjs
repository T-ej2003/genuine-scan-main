import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { acquireStageBRefreshPlan, createStageBRefreshDiagnostic, parseCli, redactStageBRefreshDiagnostic, runRefreshOnly, stageBRefreshRuntimeSensitiveValues } from "../refresh-production-green-stage-b.mjs";
import { assertStageBRefreshEvidence, assertStageBRefreshStateBinding, checkAddressesFromSource, classifyStageBRefreshResult, collectStageBTerraformCheckAddresses, inspectStageBRefreshChecks, isSupportedStageBTerraformVersion, normalizeStageBRefreshPlan, STAGE_B_EXPECTED_CHECK_ADDRESSES, STAGE_B_EXPECTED_VARIABLE_CHECK_ADDRESSES } from "../aws/stage-b-refresh-contract.mjs";
import { STAGE_B, STAGE_B_MODES } from "../aws/production-green-stage-b-contract.mjs";
import { STAGE_B_TASK_DEFINITION_FAMILIES } from "../aws/stage-b-reference-audit-contract.mjs";

const toolingSha = "8d9b8d820afa161d410490678661266d7c9e1345";
const toolingTreeSha256 = "a".repeat(64);
const image = (kind) => `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-${kind === "worker" ? "worker" : "backend"}@sha256:${kind[0].repeat(64)}`;
const bindingReport = () => ({
  tfvarsSha256: "t".repeat(64), bindingReportSha256: "b".repeat(64), imageEvidenceCanonicalSha256: "i".repeat(64), stateBackupSha256: "s".repeat(64), stateLineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", stateSerial: 76,
  images: Object.fromEntries(["backend", "worker", "executor", "canary", "readOnlyCanary"].map((kind) => [kind, { terraformVariable: kind === "readOnlyCanary" ? "read_only_canary_image" : `${kind}_image`, imageReference: image(kind === "readOnlyCanary" ? "canary" : kind), matchesEvidence: true, digestLength: 71 }])),
});
const state = { lineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", serial: 76, resources: [] };
const stateBytes = Buffer.from(JSON.stringify(state));
const stateHash = crypto.createHash("sha256").update(stateBytes).digest("hex");
const checkout = { mode: "production", toolingSha, currentHead: toolingSha, originMainHead: toolingSha, isAncestor: true, porcelainStatus: "", repositoryState: { remoteDefaultBranch: "main", shallow: false, mergeInProgress: false, rebaseInProgress: false, cherryPickInProgress: false } };
const outputsSource = 'output "task_definition_arns" {}\noutput "bound_images" {}\n';
const passingChecks = () => [...STAGE_B_EXPECTED_CHECK_ADDRESSES, ...STAGE_B_EXPECTED_VARIABLE_CHECK_ADDRESSES].map((address) => ({ address, status: "pass", instances: [{ address, status: "pass" }] }));
const noChangePlan = (terraform_version = "1.15.7") => ({ format_version: "1.2", terraform_version, complete: true, planned_values: { root_module: {} }, configuration: { root_module: {} }, prior_state: {}, errored: false, diagnostics: [], resource_changes: [{ address: "aws_lambda_function.broker", type: "aws_lambda_function", change: { actions: ["no-op"] } }], resource_drift: [], output_changes: {}, checks: passingChecks() });
const outputChange = (name, after) => ({ [name]: { actions: ["update"], before: {}, after, after_unknown: false, after_sensitive: false } });
const expectedImages = Object.fromEntries(Object.values(bindingReport().images).map((entry) => [entry.terraformVariable.replace(/_image$/, ""), entry.imageReference]));

function currentTaskDefinitionStateFixture() {
  const output = {};
  const resources = new Map();
  for (const [address, family] of Object.entries(STAGE_B_TASK_DEFINITION_FAMILIES)) {
    const match = /aws_ecs_task_definition\.(candidate|executor)\["([^"]+)"\]/.exec(address);
    const [, collection, key] = match;
    const arn = `arn:aws:ecs:${STAGE_B.region}:${STAGE_B.account}:task-definition/${family}:5`;
    const resource = resources.get(collection) || { mode: "managed", type: "aws_ecs_task_definition", name: collection, instances: [] };
    resource.instances.push({ index_key: key, attributes: { arn, family, revision: 5, network_mode: "awsvpc", requires_compatibilities: ["FARGATE"], cpu: 1024, memory: 2048, container_definitions: JSON.stringify([{ name: "main", image: "example", essential: true }]), volume: [] } });
    resources.set(collection, resource);
    if (collection === "candidate" && ["backend", "worker"].includes(key)) output[key] = arn;
    if (collection === "candidate" && key === "canary") output["full-rls-application-canary"] = arn;
    if (collection === "executor") output[key] = arn;
  }
  return { ...state, resources: [...resources.values()], outputs: { task_definition_arns: { value: output } } };
}

test("root-module check discovery covers all protected Terraform files", () => {
  const discovered = collectStageBTerraformCheckAddresses();
  assert.deepEqual(discovered, [...discovered].sort());
  assert.equal(discovered.includes("check.overlap_execution_role_secret_contract"), true);
  assert.equal(discovered.includes("check.production_only"), true);
  assert.equal(discovered.length, STAGE_B_EXPECTED_CHECK_ADDRESSES.length);
});
test("check parser discovers valid root blocks and ignores comments/strings", () => {
  assert.deepEqual(checkAddressesFromSource([
    '# check "commented" {}',
    'check "from_variables" {}',
    'local.value = "check \\\"inside-string\\\" {}"',
    'check "from_main" {}',
    'check "from_other_tf" {}',
  ].join("\n")), ["check.from_main", "check.from_other_tf", "check.from_variables"]);
});
test("check parser handles nested Terraform template expressions without brace corruption", () => {
  const interpolation = "${";
  const sources = [
    `locals { x = "${interpolation}format(\"}\", var.x)}" }\ncheck "real_contract" {}`,
    `locals { x = "${interpolation}format(\"{\", var.x)}" }\ncheck "real_contract" {}`,
    `locals { x = "${interpolation}jsonencode({ value = \"}\" })}" }\ncheck "real_contract" {}`,
    `locals { x = "${interpolation}var.x ? \"{\" : \"}\"}" }\ncheck "real_contract" {}`,
    `locals { x = "${interpolation}join(\",\", [\"a\", \"b\"])}" }\ncheck "real_contract" {}`,
    `locals { x = "${interpolation}replace(var.x, \"\\\"\", \"\")}" }\ncheck "real_contract" {}`,
    `locals { x = "${interpolation}foo(\"${interpolation}bar}\")}" }\ncheck "real_contract" {}`,
    `locals { x = "${interpolation}one}${interpolation}two}" }\ncheck "real_contract" {}`,
  ];
  for (const source of sources) assert.deepEqual(checkAddressesFromSource(source), ["check.real_contract"]);
});
test("check parser skips escaped interpolation, template directives, and nested strings", () => {
  const source = [
    'locals {',
    '  escaped = "$${not_an_interpolation}"',
    '  directive = "%{ if var.enabled }check \\"fake\\" {}%{ endif }"',
    '  nested = "${format(\"check \\\"fake\\\" { }\", var.x)}"',
    '}',
    'check "real_contract" {}',
  ].join("\n");
  assert.deepEqual(checkAddressesFromSource(source), ["check.real_contract"]);
});
test("check parser rejects malformed template strings", () => {
  for (const source of [
    'locals { x = "${format(\"}\", var.x)" }',
    'locals { x = "${format(\"}\", var.x)} }',
    'locals { x = "${format(\"}\", var.x)} }\ncheck "real_contract" {}',
  ]) assert.throws(() => checkAddressesFromSource(source), /unterminated|unmatched|unbalanced/);
});
test("duplicate root check declarations fail closed", () => assert.throws(() => checkAddressesFromSource('check "duplicate" {}\ncheck "duplicate" {}'), /Duplicate Stage B Terraform check block/));
test("unknown emitted checks remain rejected after full-source discovery", () => {
  const checks = [...passingChecks(), { address: "check.this_does_not_exist", status: "pass", instances: [{ address: "check.this_does_not_exist", status: "pass" }] }];
  const result = inspectStageBRefreshChecks({ checks });
  assert.equal(result.valid, false);
  assert.ok(result.unknownCheckCount >= 1);
});
test("the canonical overlap check is accepted when it passes", () => {
  const result = inspectStageBRefreshChecks({ checks: passingChecks() });
  assert.equal(result.valid, true);
  assert.equal(result.unknownCheckCount, 0);
  assert.equal(result.malformedCheckCount, 0);
});
test("a failing canonical overlap check remains a failed check", () => {
  const checks = passingChecks();
  const check = checks.find(({ address }) => address === "check.overlap_execution_role_secret_contract");
  check.status = "fail";
  check.instances[0].status = "fail";
  check.instances[0].problems = [{ message: "contract failed" }];
  const result = inspectStageBRefreshChecks({ checks });
  assert.equal(result.valid, false);
  assert.equal(result.failedCheckCount, 1);
  assert.match(result.failedChecks.at(-1).message, /contract failed/);
});
test("missing canonical overlap check remains rejected", () => {
  const checks = passingChecks().filter(({ address }) => address !== "check.overlap_execution_role_secret_contract");
  const result = inspectStageBRefreshChecks({ checks });
  assert.equal(result.valid, false);
  assert.ok(result.missingCheckCount >= 1);
});

function args(directory, tfvarsName = "production.tfvars") {
  const tfvarsPath = path.join(directory, tfvarsName); const reportPath = path.join(directory, "binding.json"); const metadataPath = path.join(directory, "terraform.tfstate"); const statePath = path.join(directory, "stage-b-state.json"); const outputPath = path.join(directory, "refresh-only.json");
  fs.writeFileSync(tfvarsPath, "account_id = \"368992683803\"\n", { mode: 0o600 }); fs.writeFileSync(reportPath, "{}\n", { mode: 0o600 }); fs.writeFileSync(metadataPath, "{}\n", { mode: 0o600 }); fs.writeFileSync(statePath, stateBytes, { mode: 0o600 }); fs.chmodSync(directory, 0o700); fs.chmodSync(metadataPath, 0o600); fs.chmodSync(statePath, 0o600);
  return ["--closure-mode", "production", "--tfvars", tfvarsPath, "--binding-report", reportPath, "--binding-report-sha256", bindingReport().bindingReportSha256, "--tooling-sha", toolingSha, "--tooling-tree-sha256", toolingTreeSha256, "--stage-b-state-backup", statePath, "--terraform-data-dir", directory, "--backend-metadata", metadataPath, "--output", outputPath];
}

function writeTemporaryPlan(terraformArgs) {
  const planPath = terraformArgs.find((value) => value.startsWith("-out=")).slice(5);
  fs.writeFileSync(planPath, "opaque terraform plan", { mode: 0o600 });
}

function validDeps(plan = noChangePlan()) {
  return { validateTfvarsBinding: () => ({ ...bindingReport(), stateBackupSha256: stateHash }), validateBackendMetadata: () => true, getProtectedMainCheckout: () => checkout, showWorkspace: ({ env }) => { assert.equal(env.TF_DATA_DIR, env.TF_DATA_DIR); return "default\n"; }, showPlanJson: () => ({ status: 0, stdout: JSON.stringify(plan), stderr: "" }), runTerraform: (terraformArgs) => { writeTemporaryPlan(terraformArgs); return { status: 0, stdout: "No changes.\n", stderr: "" }; } };
}

test("refresh-only rejects HCL at a JSON filename before Terraform", () => { const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-refresh-contract-")); let calls = 0; assert.throws(() => runRefreshOnly({ argv: args(directory, "production.json"), env: { TF_WORKSPACE: "default" }, deps: { runTerraform: () => { calls += 1; return { status: 0 }; } } }), /\.tfvars filename/); assert.equal(calls, 0); });
test("refresh-only rejects deployable plan output arguments", () => assert.throws(() => parseCli(["--closure-mode", "production", "-out=/private/tmp/plan.tfplan"]), /does not accept/));
test("refresh-only rejects backend metadata redirected outside the validated data directory", () => { const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-refresh-contract-")); const argv = args(directory); argv[argv.indexOf("--backend-metadata") + 1] = path.join(directory, "other", "terraform.tfstate"); assert.throws(() => runRefreshOnly({ argv, env: { TF_WORKSPACE: "default" }, deps: validDeps() }), /must be <terraform-data-dir>/); });
test("refresh-only rejects a conflicting ambient TF_DATA_DIR before Terraform", () => { const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-refresh-contract-")); assert.throws(() => runRefreshOnly({ argv: args(directory), env: { TF_WORKSPACE: "default", TF_DATA_DIR: path.join(directory, "stale") }, deps: validDeps() }), /conflicts with --terraform-data-dir/); });
test("refresh-only passes one exact Terraform environment to workspace and plan", () => { const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-refresh-contract-")); const environments = []; const result = runRefreshOnly({ argv: args(directory), env: { TF_WORKSPACE: "default" }, deps: { ...validDeps(), showWorkspace: ({ env }) => { environments.push(env); return "default\n"; }, runTerraform: (terraformArgs, { env }) => { environments.push(env); writeTemporaryPlan(terraformArgs); return { status: 0, stdout: "No changes.\n", stderr: "" }; } } }); assert.equal(result.status, "NO_CHANGES"); assert.equal(environments.length, 2); assert.equal(environments[0], environments[1]); });
test("refresh-only rejects a non-private Terraform data directory", () => { const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-refresh-contract-")); const argv = args(directory); fs.chmodSync(directory, 0o755); assert.throws(() => runRefreshOnly({ argv, env: { TF_WORKSPACE: "default" } }), /data directory must be private/); });
test("refresh-only rejects a symlinked Terraform data directory", () => { const parent = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-refresh-contract-")); const target = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-refresh-target-")); fs.symlinkSync(target, path.join(parent, "data"), "dir"); const argv = args(target); argv[argv.indexOf("--terraform-data-dir") + 1] = path.join(parent, "data"); assert.throws(() => runRefreshOnly({ argv, env: { TF_WORKSPACE: "default" } }), /non-symlink directory/); });
test("valid refresh-only invokes Terraform once and emits non-deployable JSON evidence", () => { const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-refresh-contract-")); let calls = 0; const result = runRefreshOnly({ argv: args(directory), env: { TF_WORKSPACE: "default" }, deps: { ...validDeps(), runTerraform: (terraformArgs) => { calls += 1; writeTemporaryPlan(terraformArgs); return { status: 0, stdout: "No changes.\n", stderr: "" }; } } }); const report = JSON.parse(fs.readFileSync(result.outputPath)); const expectedChecks = STAGE_B_EXPECTED_CHECK_ADDRESSES.length + STAGE_B_EXPECTED_VARIABLE_CHECK_ADDRESSES.length; assert.equal(calls, 1); assert.equal(result.status, "NO_CHANGES"); assert.equal(report.deployablePlan, false); assert.equal(report.acquisitionStatus, "valid"); assert.equal(report.terraformVersion, "1.15.7"); assert.equal(report.terraformVersionSha256, crypto.createHash("sha256").update(report.terraformVersion).digest("hex")); assert.equal(report.formatVersion, "1.2"); assert.equal(report.planCommandExitCode, 0); assert.equal(report.showCommandExitCode, 0); assert.match(report.refreshPlanSha256, /^[a-f0-9]{64}$/); assert.match(report.refreshPlanJsonSha256, /^[a-f0-9]{64}$/); assert.deepEqual(report.resourceChanges, { nonNoOp: 0, changes: [] }); assert.equal(report.checkCount, expectedChecks); assert.equal(report.infrastructureCheckCount, STAGE_B_EXPECTED_CHECK_ADDRESSES.length); assert.equal(report.variableCheckCount, STAGE_B_EXPECTED_VARIABLE_CHECK_ADDRESSES.length); assert.equal(report.passedCheckCount, expectedChecks); assert.equal(report.failedCheckCount, 0); assert.equal(report.malformedCheckCount, 0); assert.equal(report.missingCheckCount, 0); assert.equal(report.unknownCheckCount, 0); assert.equal(report.duplicateCheckCount, 0); assert.equal(report.emittedInstanceCount, expectedChecks); assert.equal(report.passedInstanceCount, expectedChecks); assert.equal(report.failedInstanceCount, 0); assert.equal(report.malformedInstanceCount, 0); assert.equal(report.duplicateCheckCount, 0); assert.match(report.instanceInventoryHash, /^[a-f0-9]{64}$/); assert.deepEqual(report.failedChecks, []); });

test("Terraform version validation follows the supported production range", () => {
  for (const version of ["1.6.0", "1.15.7", "1.99.0"]) {
    assert.equal(isSupportedStageBTerraformVersion(version), true);
    assert.equal(normalizeStageBRefreshPlan(noChangePlan(version)).terraform_version, version);
  }
  for (const version of ["1.5.9", "2.0.0", "", null, "1.15.7-rc.1", "not-semver"]) {
    assert.equal(isSupportedStageBTerraformVersion(version), false);
    assert.equal(classifyStageBRefreshResult({ plan: noChangePlan(version), bindingReport: bindingReport(), state, outputsSource }).status, "MALFORMED_RESULT");
  }
});
test("refresh evidence rejects a supported version that no longer matches its observed binding", () => { const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-refresh-contract-")); const result = runRefreshOnly({ argv: args(directory), env: { TF_WORKSPACE: "default" }, deps: validDeps() }); const report = JSON.parse(fs.readFileSync(result.outputPath)); report.terraformVersion = "1.6.0"; fs.writeFileSync(result.outputPath, `${JSON.stringify(report)}\n`, { mode: 0o600 }); assert.throws(() => assertStageBRefreshEvidence({ refreshReportPath: result.outputPath, bindingReport: bindingReport() }), /check or binding structure/); });

test("valid Terraform show JSON is acquired from the exact plan path", () => { const planPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-refresh-acquisition-")), "refresh.tfplan"); fs.writeFileSync(planPath, "opaque", { mode: 0o600 }); const seen = []; const result = acquireStageBRefreshPlan({ planPath, planResult: { status: 2 }, showOptions: {}, showPlanJson: (actualPath) => { seen.push(actualPath); return { status: 0, stdout: JSON.stringify(noChangePlan()), stderr: "diagnostic stream is kept separate" }; } }); assert.equal(result.acquisitionStatus, "valid"); assert.deepEqual(seen, [planPath]); });
test("failed plan command never invokes show and keeps an in-memory diagnostic capture", () => { let calls = 0; const result = acquireStageBRefreshPlan({ planPath: path.join(os.tmpdir(), "missing-refresh.tfplan"), planResult: { status: 1, stdout: "plan output", stderr: "Error: Invalid index" }, showPlanJson: () => { calls += 1; return { status: 0, stdout: "{}", stderr: "" }; } }); assert.equal(result.acquisitionStatus, "PLAN_COMMAND_FAILED"); assert.equal(result.diagnosticCapture.stderr, "Error: Invalid index"); assert.equal(calls, 0); });

test("abnormal plan termination preserves plan signal and error details without invoking show", () => {
  for (const planResult of [
    { status: null, stdout: "", stderr: "", signal: "SIGTERM" },
    { status: null, stdout: "", stderr: "", error: { message: "spawn terraform ENOENT", stack: "Error stack must not persist" } },
    { status: null, stdout: "", stderr: "provider failed", error: { message: "child failure" } },
  ]) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-refresh-plan-abnormal-"));
    let showCalls = 0;
    assert.throws(() => runRefreshOnly({ argv: args(directory), env: { TF_WORKSPACE: "default" }, deps: {
      ...validDeps(),
      runTerraform: () => planResult,
      showPlanJson: () => { showCalls += 1; return { status: 0, stdout: "unexpected show", stderr: "unexpected" }; },
    } }), /MALFORMED_RESULT/);
    const report = JSON.parse(fs.readFileSync(path.join(directory, "refresh-only.json"), "utf8"));
    const diagnostic = JSON.parse(fs.readFileSync(report.diagnosticArtifactPath, "utf8"));
    assert.equal(report.acquisitionStatus, "PLAN_COMMAND_FAILED");
    assert.equal(diagnostic.commandPhase, "refresh-only-plan");
    assert.equal(diagnostic.exitCode, null);
    assert.equal(showCalls, 0);
    assert.doesNotMatch(JSON.stringify(diagnostic), /Error stack must not persist|unexpected show/);
    if (planResult.signal) assert.equal(diagnostic.terminationSignal, "SIGTERM");
    if (planResult.error) assert.match(diagnostic.commandErrorExcerptRedacted, /spawn terraform ENOENT|child failure/);
    if (planResult.stderr) assert.match(diagnostic.stderrExcerptRedacted, /provider failed/);
  }
});

test("plan and show exit codes remain bound to their own command", () => {
  let showCalls = 0;
  const planFailure = acquireStageBRefreshPlan({ planPath: path.join(os.tmpdir(), "missing-refresh.tfplan"), planResult: { status: 1, stdout: "", stderr: "failed" }, showPlanJson: () => { showCalls += 1; return { status: 0, stdout: "{}", stderr: "" }; } });
  assert.equal(planFailure.planCommandExitCode, 1);
  assert.equal(planFailure.showCommandExitCode, null);
  const abnormalPlan = acquireStageBRefreshPlan({ planPath: path.join(os.tmpdir(), "missing-refresh.tfplan"), planResult: { status: null, stdout: "", stderr: "", signal: "SIGTERM" }, showPlanJson: () => { showCalls += 1; return { status: 0, stdout: "{}", stderr: "" }; } });
  assert.equal(abnormalPlan.planCommandExitCode, null);
  assert.equal(abnormalPlan.showCommandExitCode, null);
  assert.equal(showCalls, 0);
  const showPlanPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-refresh-show-exit-")), "refresh.tfplan");
  fs.writeFileSync(showPlanPath, "opaque", { mode: 0o600 });
  const showFailure = acquireStageBRefreshPlan({ planPath: showPlanPath, planResult: { status: 2 }, showPlanJson: () => ({ status: 1, stdout: "", stderr: "failed" }) });
  assert.equal(showFailure.planCommandExitCode, 2);
  assert.equal(showFailure.showCommandExitCode, 1);
  const abnormalShow = acquireStageBRefreshPlan({ planPath: showPlanPath, planResult: { status: 0 }, showPlanJson: () => ({ status: null, stdout: "", stderr: "", signal: "SIGTERM" }) });
  assert.equal(abnormalShow.planCommandExitCode, 0);
  assert.equal(abnormalShow.showCommandExitCode, null);
});

test("diagnostic hashes cover raw streams while termination metadata stays separate", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-refresh-diagnostic-hash-"));
  const rawStderr = "provider failed\n";
  assert.throws(() => runRefreshOnly({ argv: args(directory), env: { TF_WORKSPACE: "default" }, deps: { ...validDeps(), runTerraform: () => ({ status: null, stdout: "", stderr: rawStderr, signal: "SIGTERM", error: { message: "child process terminated", stack: "must not persist" } }) } }), /MALFORMED_RESULT/);
  const report = JSON.parse(fs.readFileSync(path.join(directory, "refresh-only.json"), "utf8"));
  const diagnostic = JSON.parse(fs.readFileSync(report.diagnosticArtifactPath, "utf8"));
  const rawHash = crypto.createHash("sha256").update(rawStderr).digest("hex");
  assert.equal(report.planCommandExitCode, null);
  assert.equal(report.showCommandExitCode, null);
  assert.equal(diagnostic.stderrSha256, rawHash);
  assert.notEqual(diagnostic.stderrSha256, crypto.createHash("sha256").update(`${rawStderr}SIGTERMchild process terminated`).digest("hex"));
  assert.equal(diagnostic.terminationSignal, "SIGTERM");
  assert.equal(diagnostic.commandErrorExcerptRedacted, "child process terminated");
  assert.match(diagnostic.stderrExcerptRedacted, /provider failed/);
  assert.doesNotMatch(JSON.stringify(diagnostic), /must not persist/);
});

test("runtime credential values are redacted transiently without changing raw hashes", () => {
  const keys = ["AWS_SESSION_TOKEN", "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECURITY_TOKEN"];
  for (const [index, key] of keys.entries()) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-refresh-runtime-secret-"));
    const sentinel = ["runtime", "credential", "sentinel", index].join("-");
    const rawStderr = `provider request failed: ${sentinel}`;
    const env = { TF_WORKSPACE: "default", [key]: sentinel, AWS_REGION: "eu-west-2" };
    assert.throws(() => runRefreshOnly({ argv: args(directory), env, deps: { ...validDeps(), runTerraform: () => ({ status: 1, stdout: "", stderr: rawStderr }) } }), /MALFORMED_RESULT/);
    const report = JSON.parse(fs.readFileSync(path.join(directory, "refresh-only.json"), "utf8"));
    const diagnostic = JSON.parse(fs.readFileSync(report.diagnosticArtifactPath, "utf8"));
    assert.equal(diagnostic.stderrSha256, crypto.createHash("sha256").update(rawStderr).digest("hex"));
    assert.doesNotMatch(JSON.stringify(diagnostic), new RegExp(sentinel));
    assert.match(diagnostic.stderrExcerptRedacted, /\[REDACTED\]/);
    assert.equal(Object.hasOwn(diagnostic, "sensitiveValues"), false);
  }
  const values = stageBRefreshRuntimeSensitiveValues({ AWS_REGION: "eu-west-2", PATH: "/bin", TF_DATA_DIR: "/tmp/data" });
  assert.deepEqual(values, []);
  assert.equal(redactStageBRefreshDiagnostic("region=eu-west-2", { sensitiveValues: values }), "region=eu-west-2");
});

test("diagnostic factory accepts only reviewed command phases", () => {
  assert.equal(createStageBRefreshDiagnostic({ commandPhase: "refresh-only-plan" }).commandPhase, "refresh-only-plan");
  assert.equal(createStageBRefreshDiagnostic({ commandPhase: "refresh-only-show" }).commandPhase, "refresh-only-show");
  assert.throws(() => createStageBRefreshDiagnostic({ commandPhase: "unexpected" }), /command phase/);
});

test("refresh diagnostic redaction removes credential material but preserves a bounded error summary", () => {
  const accessKey = ["AKIA", "IOSFODNN7EXAMPLE"].join("");
  const privateKey = ["-----BEGIN ", ["PRIVATE", "KEY"].join(" "), "-----\nfixture-private-key\n-----END ", ["PRIVATE", "KEY"].join(" "), "-----"].join("");
  const diagnostic = redactStageBRefreshDiagnostic([
    "Error: Invalid index",
    "password=fixture-password",
    "secret: fixture-secret",
    "token=fixture-token",
    `AWS_ACCESS_KEY_ID=${accessKey}`,
    "AWS_SECRET_ACCESS_KEY=fixture-secret-key",
    "AWS_SESSION_TOKEN=fixture-session-token",
    "Authorization: Bearer fixture-bearer-token",
    "arn:aws:secretsmanager:eu-west-2:368992683803:secret:fixture",
    privateKey,
    "known-tfvar-secret",
  ].join("\n"), { sensitiveValues: ["known-tfvar-secret"] });
  assert.match(diagnostic, /Invalid index/);
  for (const secret of ["fixture-password", "fixture-secret", "fixture-token", accessKey, "fixture-secret-key", "fixture-session-token", "fixture-bearer-token", "fixture-private-key", "known-tfvar-secret"]) assert.doesNotMatch(diagnostic, new RegExp(secret));
  assert.doesNotMatch(diagnostic, /arn:aws:(?:secretsmanager|ssm):/);
});

test("authorization redaction handles quoted structured headers without broad matching", () => {
  const credential = ["fixture", "-credential"].join("");
  const positive = [
    `Authorization: Bearer ${credential}`,
    `Authorization: Basic ${credential}`,
    `Authorization:"Bearer ${credential}"`,
    `Authorization: "Basic ${credential}"`,
    `"Authorization":"Bearer ${credential}"`,
    `'Authorization': 'Basic ${credential}'`,
    `Proxy-Authorization: Bearer ${credential}`,
    `"Proxy-Authorization":"Basic ${credential}"`,
    `Authorization: "Bearer ${credential}`,
  ];
  for (const value of positive) {
    const redacted = redactStageBRefreshDiagnostic(value);
    assert.doesNotMatch(redacted, new RegExp(credential));
    assert.match(redacted, /\[REDACTED\]/);
  }
  for (const value of [
    `AuthorizationStatus=Bearer ${credential}`,
    `authorization_mode=basic`,
    `MyAuthorization: Bearer ${credential}`,
    `Bearer ${credential}`,
  ]) {
    assert.equal(redactStageBRefreshDiagnostic(value), value);
  }
});

test("sensitive assignment redaction recognizes prefixed keys without substring false positives", () => {
  const positives = [
    "db_password", "db-password", "database_passwd", "client_secret", "github_token", "api_token",
    "service_access_key", "service_private_key", "foo_session_token", "foo_aws_access_key_id",
    "foo_aws_secret_access_key", "foo_aws_session_token",
  ];
  for (const [index, key] of positives.entries()) {
    const payload = `prefixed-secret-${index}`;
    const redacted = redactStageBRefreshDiagnostic(`${key} = "${payload}"`);
    assert.doesNotMatch(redacted, new RegExp(payload));
    assert.match(redacted, /\[REDACTED\]/);
  }
  const nonSensitiveKeys = [
    ["pass", "word", "less"].join(""), ["token", "izer"].join(""), ["secret", "ary"].join(""),
    ["access", "_keynote"].join(""), ["github", "_tokenizer"].join(""), ["private", "_keynote"].join(""), ["mon", "key"].join(""),
  ];
  for (const key of nonSensitiveKeys) {
    const value = `${key}=safe-value`;
    assert.equal(redactStageBRefreshDiagnostic(value), value);
  }
  assert.doesNotMatch(redactStageBRefreshDiagnostic("\"db_password\": 'unterminated-prefixed-secret'"), /unterminated-prefixed-secret/);
  assert.doesNotMatch(redactStageBRefreshDiagnostic("foo_aws_secret_access_key=at-eof-secret"), /at-eof-secret/);
});

test("refresh diagnostic redacts complete and truncated PEM blocks without consuming surrounding text", () => {
  const marker = (boundary, label) => ["-----", boundary, " ", label, "-----"].join("");
  const labels = ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "OPENSSH PRIVATE KEY", "AES-256 GCM PRIVATE KEY"];
  for (const label of labels) {
    const begin = marker("BEGIN", label);
    const end = marker("END", label);
    const complete = redactStageBRefreshDiagnostic(["before", begin, `payload-${label}`, end, "after"].join("\n"));
    assert.match(complete, /before/);
    assert.match(complete, /\[REDACTED_PRIVATE_KEY\]/);
    assert.match(complete, /after/);
    assert.doesNotMatch(complete, new RegExp(`payload-${label.replaceAll(" ", "\\s")}`));
  }
  const encryptedBegin = marker("BEGIN", "ENCRYPTED PRIVATE KEY");
  const truncated = redactStageBRefreshDiagnostic(["before", encryptedBegin, "truncated-encrypted-payload", "EOF"].join("\n"));
  assert.match(truncated, /before/);
  assert.match(truncated, /\[REDACTED_PRIVATE_KEY\]/);
  assert.doesNotMatch(truncated, /truncated-encrypted-payload|EOF/);
  for (const label of ["PUBLIC KEY", "CERTIFICATE"]) {
    const value = ["before", marker("BEGIN", label), "safe-payload", marker("END", label), "after"].join("\n");
    assert.equal(redactStageBRefreshDiagnostic(value), value);
  }
  assert.equal(redactStageBRefreshDiagnostic("PRIVATE KEY value"), "PRIVATE KEY value");
  for (const label of ["lowercase PRIVATE KEY", "RSA/PRIVATE KEY", " RSA PRIVATE KEY", `${"A".repeat(120)} PRIVATE KEY`]) {
    const value = ["-----BEGIN ", label, "-----payload"].join("");
    assert.equal(redactStageBRefreshDiagnostic(value), value);
  }
  assert.equal(redactStageBRefreshDiagnostic("x".repeat(100), { maxChars: 16 }).length <= 29, true);
});

test("malformed PEM headers never skip a later valid private-key block", () => {
  const marker = (boundary, label) => ["-----", boundary, " ", label, "-----"].join("");
  const validBlock = (label) => [marker("BEGIN", label), `payload-${label}`, marker("END", label)].join("\n");
  const cases = [
    ["PRIVATE KEY", "-----BEGIN garbage\n"],
    ["ENCRYPTED PRIVATE KEY", "-----BEGIN malformed\n"],
    ["RSA PRIVATE KEY", "-----BEGIN one\n-----BEGIN two\n"],
    ["DSA PRIVATE KEY", ["-----BEGIN ", "A".repeat(140), "\n"].join("")],
  ];
  for (const [label, malformed] of cases) {
    const diagnostic = redactStageBRefreshDiagnostic(["safe-before", malformed, validBlock(label), "safe-after"].join("\n"));
    assert.match(diagnostic, /safe-before/);
    assert.match(diagnostic, /\[REDACTED_PRIVATE_KEY\]/);
    assert.match(diagnostic, /safe-after/);
    assert.doesNotMatch(diagnostic, new RegExp(`payload-${label.replaceAll(" ", "\\s")}`));
  }
  const safe = "safe-before\n-----BEGIN malformed\nsafe-after";
  assert.equal(redactStageBRefreshDiagnostic(safe), safe);
});

test("refresh diagnostic assignment parsing handles quoted, escaped, unquoted, and adversarial values", () => {
  const backslashes = "\\".repeat(20000);
  const input = [
    "summary: useful",
    "token=plain-at-eof",
    "secret='quoted value'",
    `token="escaped${backslashes}value"`,
    `secret='${backslashes}`,
    "repeated-token-like text without assignments ".repeat(1000),
  ].join("\n");
  const redacted = redactStageBRefreshDiagnostic(input, { maxChars: 1024 });
  assert.match(redacted, /summary: useful/);
  assert.doesNotMatch(redacted, /plain-at-eof|quoted value|escaped|value/);
  assert.equal(redacted.length <= 1036, true);
});

test("diagnostic destination collisions fail before Terraform and preserve the existing artifact", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-refresh-collision-"));
  const diagnosticPath = path.join(directory, "terraform-plan-diagnostic.json");
  const existing = "existing forensic artifact\n";
  fs.writeFileSync(diagnosticPath, existing, { mode: 0o600 });
  let calls = 0;
  assert.throws(() => runRefreshOnly({ argv: args(directory), env: { TF_WORKSPACE: "default" }, deps: { ...validDeps(), runTerraform: () => { calls += 1; return { status: 1, stdout: "", stderr: "unexpected" }; } } }), /new absolute private output path|already exists|collision/i);
  assert.equal(calls, 0);
  assert.equal(fs.readFileSync(diagnosticPath, "utf8"), existing);
  assert.equal(fs.existsSync(path.join(directory, "refresh-only.json")), false);
  assert.deepEqual(fs.readdirSync(directory).filter((name) => name.startsWith(".stage-b-refresh-")), []);
});

test("report and diagnostic paths must differ before workspace or refresh Terraform", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-refresh-same-path-"));
  const outputPath = path.join(directory, "terraform-plan-diagnostic.json");
  const argv = args(directory);
  argv[argv.indexOf("--output") + 1] = outputPath;
  let workspaceCalls = 0;
  let refreshPlanCalls = 0;
  assert.throws(() => runRefreshOnly({ argv, env: { TF_WORKSPACE: "default" }, deps: { ...validDeps(), showWorkspace: () => { workspaceCalls += 1; return "default\n"; }, runTerraform: () => { refreshPlanCalls += 1; return { status: 1, stdout: "", stderr: "unexpected" }; } } }), /report path must differ from diagnostic artifact path/);
  assert.equal(workspaceCalls, 0);
  assert.equal(refreshPlanCalls, 0);
  assert.equal(fs.existsSync(outputPath), false);
  assert.deepEqual(fs.readdirSync(directory).filter((name) => name.startsWith(".stage-b-refresh-")), []);
});

test("failed plan command writes a private bounded diagnostic without raw stderr or retry", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-refresh-diagnostic-"));
  const stderr = "Error: Invalid index\npassword=fixture-password\nAWS_SESSION_TOKEN=fixture-session-token";
  let calls = 0;
  assert.throws(() => runRefreshOnly({ argv: args(directory), env: { TF_WORKSPACE: "default" }, deps: { ...validDeps(), runTerraform: () => { calls += 1; return { status: 1, stdout: "plan stdout", stderr }; } } }), /MALFORMED_RESULT/);
  const report = JSON.parse(fs.readFileSync(path.join(directory, "refresh-only.json"), "utf8"));
  const diagnosticPath = report.diagnosticArtifactPath;
  const diagnostic = JSON.parse(fs.readFileSync(diagnosticPath, "utf8"));
  assert.equal(report.status, "MALFORMED_RESULT");
  assert.equal(report.deployablePlan, false);
  assert.equal(report.terraformExitCode, 1);
  assert.equal(calls, 1);
  assert.match(report.diagnosticArtifactSha256, /^[a-f0-9]{64}$/);
  assert.equal(report.diagnosticArtifactSha256, crypto.createHash("sha256").update(fs.readFileSync(diagnosticPath)).digest("hex"));
  assert.equal(fs.statSync(diagnosticPath).mode & 0o777, 0o600);
  assert.equal(diagnostic.exitCode, 1);
  assert.equal(diagnostic.stderrSha256, crypto.createHash("sha256").update(stderr).digest("hex"));
  assert.match(diagnostic.stderrExcerptRedacted, /Invalid index/);
  assert.doesNotMatch(JSON.stringify(diagnostic), /fixture-password|fixture-session-token/);
  assert.equal(Object.hasOwn(diagnostic, "stderr"), false);
  assert.deepEqual(fs.readdirSync(directory).filter((name) => name.startsWith(".stage-b-refresh-")), []);
});

test("show command failure writes a private diagnostic and preserves the show exit code", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-refresh-diagnostic-"));
  assert.throws(() => runRefreshOnly({ argv: args(directory), env: { TF_WORKSPACE: "default" }, deps: { ...validDeps(), showPlanJson: () => ({ status: 1, stdout: "show stdout", stderr: "Error: provider diagnostic" }) } }), /MALFORMED_RESULT/);
  const report = JSON.parse(fs.readFileSync(path.join(directory, "refresh-only.json"), "utf8"));
  const diagnostic = JSON.parse(fs.readFileSync(report.diagnosticArtifactPath, "utf8"));
  assert.equal(report.acquisitionStatus, "SHOW_COMMAND_FAILED");
  assert.equal(diagnostic.commandPhase, "refresh-only-show");
  assert.equal(diagnostic.showExitCode, 1);
  assert.match(diagnostic.stdoutExcerptRedacted, /show stdout/);
  assert.match(diagnostic.stderrExcerptRedacted, /provider diagnostic/);
  assert.deepEqual(fs.readdirSync(directory).filter((name) => name.startsWith(".stage-b-refresh-")), []);
});

test("abnormal show termination preserves show stderr, signal, and error instead of plan diagnostics", () => {
  for (const shown of [
    { status: null, stdout: "show output", stderr: "show killed", signal: "SIGTERM" },
    { status: null, stdout: "", stderr: "", error: { message: "spawn failure" } },
    undefined,
  ]) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-refresh-show-abnormal-"));
    assert.throws(() => runRefreshOnly({ argv: args(directory), env: { TF_WORKSPACE: "default" }, deps: { ...validDeps(), showPlanJson: () => shown } }), /MALFORMED_RESULT/);
    const report = JSON.parse(fs.readFileSync(path.join(directory, "refresh-only.json"), "utf8"));
    const diagnostic = JSON.parse(fs.readFileSync(report.diagnosticArtifactPath, "utf8"));
    assert.equal(report.acquisitionStatus, "SHOW_COMMAND_FAILED");
    assert.equal(report.planCommandExitCode, 0);
    assert.equal(diagnostic.showExitCode, null);
    assert.equal(diagnostic.commandPhase, "refresh-only-show");
    assert.doesNotMatch(JSON.stringify(diagnostic), /No changes/);
    if (shown?.signal) assert.equal(diagnostic.terminationSignal, "SIGTERM");
    if (shown?.error) assert.match(diagnostic.commandErrorExcerptRedacted, /spawn failure/);
    if (!shown) assert.match(diagnostic.commandErrorExcerptRedacted, /no command result/);
    assert.deepEqual(fs.readdirSync(directory).filter((name) => name.startsWith(".stage-b-refresh-")), []);
  }
});
test("missing, empty, and wrong plan paths fail before classification", () => { const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-refresh-acquisition-")); const missing = acquireStageBRefreshPlan({ planPath: path.join(directory, "missing.tfplan"), planResult: { status: 2 }, showPlanJson: () => ({ status: 0, stdout: "{}", stderr: "" }) }); assert.equal(missing.acquisitionStatus, "PLAN_FILE_MISSING"); const emptyPath = path.join(directory, "empty.tfplan"); fs.writeFileSync(emptyPath, "", { mode: 0o600 }); const empty = acquireStageBRefreshPlan({ planPath: emptyPath, planResult: { status: 2 }, showPlanJson: () => ({ status: 0, stdout: "{}", stderr: "" }) }); assert.equal(empty.acquisitionStatus, "PLAN_FILE_EMPTY"); });
test("valid plan shape narrowly normalizes omitted zero-change collections", () => { const plan = noChangePlan(); delete plan.resource_changes; delete plan.output_changes; assert.equal(classifyStageBRefreshResult({ plan, terraformExitCode: 0, bindingReport: bindingReport(), state, outputsSource }).status, "NO_CHANGES"); assert.equal(classifyStageBRefreshResult({ plan, terraformExitCode: 2, bindingReport: bindingReport(), state, outputsSource }).status, "NO_CHANGES"); });
test("state JSON and incomplete plan envelopes remain malformed", () => { for (const plan of [{ version: 4, terraform_version: "1.15.7", resources: [] }, { format_version: "1.2", terraform_version: "1.15.7", planned_values: {}, checks: passingChecks() }, { ...noChangePlan(), diagnostics: {} }]) assert.equal(classifyStageBRefreshResult({ plan, bindingReport: bindingReport(), state, outputsSource }).status, "MALFORMED_RESULT"); });
for (const [label, showResult, expected] of [["show failure", { status: 1, stdout: "", stderr: "failed" }, "SHOW_COMMAND_FAILED"], ["empty stdout", { status: 0, stdout: "", stderr: "" }, "SHOW_OUTPUT_EMPTY"], ["non-JSON stdout", { status: 0, stdout: "No changes.", stderr: "" }, "SHOW_OUTPUT_NOT_JSON"], ["wrapper JSON", { status: 0, stdout: JSON.stringify({ status: "NO_CHANGES", resourceChanges: [] }), stderr: "" }, "MALFORMED_RESULT"], ["diagnostic JSON", { status: 0, stdout: JSON.stringify({ diagnostics: [{ severity: "error", summary: "invalid", detail: "invalid" }] }), stderr: "" }, "TERRAFORM_DIAGNOSTIC_RESULT"], ["errored plan", { status: 0, stdout: JSON.stringify({ errored: true }), stderr: "" }, "TERRAFORM_ERRORED_PLAN"], ["truncated plan", { status: 0, stdout: "{", stderr: "" }, "SHOW_OUTPUT_NOT_JSON"]]) test(`${label} fails closed`, () => { const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-refresh-acquisition-")); const planPath = path.join(directory, "refresh.tfplan"); fs.writeFileSync(planPath, "opaque", { mode: 0o600 }); const result = acquireStageBRefreshPlan({ planPath, planResult: { status: 2 }, showPlanJson: () => showResult }); assert.equal(result.acquisitionStatus, expected); assert.ok(result.diagnosticCapture); });

test("exact no-change refresh passes", () => assert.equal(classifyStageBRefreshResult({ plan: noChangePlan(), bindingReport: bindingReport(), state, outputsSource }).status, "NO_CHANGES"));
test("Terraform detailed exit 2 with a complete empty semantic change set is no change", () => assert.equal(classifyStageBRefreshResult({ plan: noChangePlan(), terraformExitCode: 2, bindingReport: bindingReport(), state, outputsSource }).status, "NO_CHANGES"));
test("Terraform detailed exit 2 remains blocked for resource, drift, output, failed-check, and unknown changes", () => {
  const cases = [
    ["resource change", (plan) => { plan.resource_changes = [{ address: "aws_lambda_function.broker", change: { actions: ["update"] } }]; }, "RESOURCE_DRIFT"],
    ["resource drift", (plan) => { plan.resource_drift = [{ address: "aws_lambda_function.broker", change: { actions: ["update"] } }]; }, "RESOURCE_DRIFT"],
    ["output change", (plan) => { plan.output_changes = outputChange("bound_images", { ...expectedImages, backend: "wrong" }); }, "OUTPUT_DRIFT"],
    ["failed check", (plan) => { plan.checks[0].status = "fail"; }, "FAILED_CHECK"],
    ["unknown change", (plan) => { plan.resource_changes = [{ address: "aws_lambda_function.broker", change: { actions: ["read"] } }]; }, "RESOURCE_DRIFT"],
  ];
  for (const [label, mutate, expected] of cases) {
    const plan = noChangePlan();
    mutate(plan);
    assert.equal(classifyStageBRefreshResult({ plan, terraformExitCode: 2, bindingReport: bindingReport(), state, outputsSource }).status, expected, label);
  }
});
test("Terraform detailed exit 2 rejects incomplete or errored plan evidence", () => {
  for (const mutate of [(plan) => { plan.complete = false; }, (plan) => { plan.errored = true; }]) {
    const plan = noChangePlan();
    mutate(plan);
    assert.equal(classifyStageBRefreshResult({ plan, terraformExitCode: 2, bindingReport: bindingReport(), state, outputsSource }).status, "MALFORMED_RESULT");
  }
});
test("Terraform exit 1 remains blocked", () => assert.equal(classifyStageBRefreshResult({ plan: noChangePlan(), terraformExitCode: 1, bindingReport: bindingReport(), state, outputsSource }).status, "FAILED_CHECK"));
test("all source-defined checks and variable validations pass before no-change classification", () => { const result = classifyStageBRefreshResult({ plan: noChangePlan(), bindingReport: bindingReport(), state, outputsSource }); const expectedChecks = STAGE_B_EXPECTED_CHECK_ADDRESSES.length + STAGE_B_EXPECTED_VARIABLE_CHECK_ADDRESSES.length; assert.equal(result.checkCount, expectedChecks); assert.equal(result.infrastructureCheckCount, STAGE_B_EXPECTED_CHECK_ADDRESSES.length); assert.equal(result.variableCheckCount, STAGE_B_EXPECTED_VARIABLE_CHECK_ADDRESSES.length); assert.equal(result.passedCheckCount, expectedChecks); assert.equal(result.failedCheckCount, 0); assert.equal(result.malformedCheckCount, 0); assert.equal(result.missingCheckCount, 0); assert.equal(result.unknownCheckCount, 0); assert.equal(result.duplicateCheckCount, 0); assert.deepEqual(result.failedChecks, []); });
test("Terraform JSON display addresses are normalized for checks and instances", () => { const checks = passingChecks().map((check) => ({ ...check, address: { kind: check.address.split(".")[0], name: check.address.slice(check.address.indexOf(".") + 1), to_display: check.address }, instances: [{ ...check.instances[0], address: { to_display: check.address } }] })); assert.equal(classifyStageBRefreshResult({ plan: { ...noChangePlan(), checks }, bindingReport: bindingReport(), state, outputsSource }).status, "NO_CHANGES"); });
test("check address parser accepts direct strings and reviewed to_string forms", () => { assert.equal(inspectStageBRefreshChecks({ checks: passingChecks() }).valid, true); const checks = passingChecks().map((check) => ({ ...check, address: { kind: check.address.split(".")[0], name: check.address.slice(check.address.indexOf(".") + 1), to_string: check.address }, instances: [{ ...check.instances[0], address: { to_display: check.address } }] })); assert.equal(inspectStageBRefreshChecks({ checks }).valid, true); });
test("top-level rendered-only addresses preserve the legacy and Terraform shapes", () => { for (const rendered of [{ to_string: "check.production_only" }, { to_display: "check.production_only" }, { to_display: "check.production_only", to_string: "check.production_only" }, { to_string: "var.retained_candidate_task_definitions" }, { to_display: "var.retained_candidate_task_definitions" }]) { const target = Object.values(rendered)[0].startsWith("var.") ? "var.retained_candidate_task_definitions" : "check.production_only"; const checks = passingChecks().map((check) => check.address === target ? { ...check, address: rendered } : check); assert.equal(inspectStageBRefreshChecks({ checks }).valid, true); } const instanceChecks = passingChecks().map((check) => ({ ...check, instances: [{ ...check.instances[0], address: { to_string: check.address } }] })); assert.equal(inspectStageBRefreshChecks({ checks: instanceChecks }).valid, true); });
test("preserved Terraform 1.15.7 full-check fixture passes", () => { const fixture = JSON.parse(fs.readFileSync(path.join(path.dirname(new URL(import.meta.url).pathname), "fixtures/production-green-stage-b-refresh-terraform-1.15.7.json"))); const result = inspectStageBRefreshChecks({ checks: fixture.checks }); const expectedChecks = STAGE_B_EXPECTED_CHECK_ADDRESSES.length + STAGE_B_EXPECTED_VARIABLE_CHECK_ADDRESSES.length; assert.deepEqual({ checkCount: result.checkCount, infrastructureCheckCount: result.infrastructureCheckCount, variableCheckCount: result.variableCheckCount, passedCheckCount: result.passedCheckCount, failedCheckCount: result.failedCheckCount, malformedCheckCount: result.malformedCheckCount, missingCheckCount: result.missingCheckCount, unknownCheckCount: result.unknownCheckCount, duplicateCheckCount: result.duplicateCheckCount, emittedInstanceCount: result.emittedInstanceCount, passedInstanceCount: result.passedInstanceCount, failedInstanceCount: result.failedInstanceCount, malformedInstanceCount: result.malformedInstanceCount, duplicateInstanceCount: result.duplicateInstanceCount }, { checkCount: expectedChecks, infrastructureCheckCount: STAGE_B_EXPECTED_CHECK_ADDRESSES.length, variableCheckCount: STAGE_B_EXPECTED_VARIABLE_CHECK_ADDRESSES.length, passedCheckCount: expectedChecks, failedCheckCount: 0, malformedCheckCount: 0, missingCheckCount: 0, unknownCheckCount: 0, duplicateCheckCount: 0, emittedInstanceCount: expectedChecks, passedInstanceCount: expectedChecks, failedInstanceCount: 0, malformedInstanceCount: 0, duplicateInstanceCount: 0 }); assert.equal(result.valid, true); assert.equal(classifyStageBRefreshResult({ plan: normalizeStageBRefreshPlan(fixture), bindingReport: bindingReport(), state, outputsSource }).status, "NO_CHANGES"); const bytes = fs.readFileSync(path.join(path.dirname(new URL(import.meta.url).pathname), "fixtures/production-green-stage-b-refresh-terraform-1.15.7.json")); assert.equal(JSON.stringify(JSON.parse(bytes)), JSON.stringify(JSON.parse(Buffer.from(bytes)))); });
test("conflicting rendered addresses, kinds, prefixes, and missing names fail closed", () => { const base = passingChecks(); for (const address of [{ kind: "check", name: "production_only", to_display: "check.immutable_images", to_string: "check.production_only" }, { kind: "resource", name: "production_only", to_display: "resource.production_only" }, { kind: "check", name: "", to_display: "check.production_only" }, { to_display: "resource.production_only" }, { to_string: " " }, { to_display: "" }, { to_string: "check..production_only" }]) { const checks = [...base]; checks[0] = { ...checks[0], address }; const result = inspectStageBRefreshChecks({ checks }); assert.equal(result.valid, false); assert.ok(result.malformedCheckCount > 0); } });
test("missing variable validation and unknown inventory fail closed", () => { for (const checks of [passingChecks().filter(({ address }) => address !== "var.retained_executor_task_definitions"), [...passingChecks(), { address: "var.unknown", status: "pass", instances: [{ address: "var.unknown", status: "pass", problems: [] }] }]]) { const result = inspectStageBRefreshChecks({ checks }); assert.equal(result.valid, false); assert.ok(result.malformedCheckCount > 0); } });
for (const status of ["fail", "error", "unknown"]) test(`top-level check status ${status} fails closed`, () => { const checks = passingChecks(); checks[0].status = status; const result = classifyStageBRefreshResult({ plan: { ...noChangePlan(), checks }, bindingReport: bindingReport(), state, outputsSource }); assert.equal(result.status, "FAILED_CHECK"); assert.equal(result.failedCheckCount, 1); });
test("failed check instance blocks output reconciliation", () => { const checks = passingChecks(); checks[0].instances[0].status = "fail"; checks[0].instances[0].problems = [{ message: "binding mismatch" }]; const result = classifyStageBRefreshResult({ plan: { ...noChangePlan(), output_changes: outputChange("bound_images", expectedImages), checks }, bindingReport: bindingReport(), state, outputsSource }); assert.equal(result.status, "FAILED_CHECK"); assert.equal(result.failedCheckCount, 1); assert.match(result.failedChecks[0].message, /binding mismatch|check/); });
test("Terraform check problems are optional when omitted, but malformed when present with the wrong type", () => { const omitted = inspectStageBRefreshChecks({ checks: passingChecks() }); assert.equal(omitted.valid, true); const malformed = passingChecks(); malformed[0].instances[0].problems = null; const result = inspectStageBRefreshChecks({ checks: malformed }); assert.equal(result.valid, false); assert.equal(result.malformedInstanceCount, 1); });
test("duplicate instance identities fail closed without weakening top-level inventory", () => { const checks = passingChecks(); checks[0].instances = [{ address: checks[0].address, status: "pass" }, { address: checks[0].address, status: "pass" }]; const result = inspectStageBRefreshChecks({ checks }); assert.equal(result.valid, false); assert.equal(result.emittedInstanceCount, passingChecks().length + 1); assert.equal(result.duplicateInstanceCount, 1); });
test("missing, malformed, unknown, and duplicate check inventory fails closed", () => { for (const checks of [[], passingChecks().slice(1), [{ status: "pass", instances: [] }, ...passingChecks().slice(1)], [{ ...passingChecks()[0], address: "check.unknown" }, ...passingChecks().slice(1)], [...passingChecks(), passingChecks()[0]]]) { const result = classifyStageBRefreshResult({ plan: { ...noChangePlan(), checks }, bindingReport: bindingReport(), state, outputsSource }); assert.equal(result.status, "FAILED_CHECK"); assert.ok(result.malformedCheckCount > 0); } });
test("missing plan.checks fails even with a successful Terraform exit and no drift", () => { const plan = noChangePlan(); delete plan.checks; const result = classifyStageBRefreshResult({ plan, terraformExitCode: 0, bindingReport: bindingReport(), state, outputsSource }); assert.equal(result.status, "FAILED_CHECK"); assert.equal(result.malformedCheckCount, 1); });
test("human No changes text cannot override a failed JSON check", () => { const checks = passingChecks(); checks[0].status = "fail"; const result = classifyStageBRefreshResult({ plan: { ...noChangePlan(), checks }, terraformExitCode: 0, terraformOutput: "No changes.", bindingReport: bindingReport(), state, outputsSource }); assert.equal(result.status, "FAILED_CHECK"); });
for (const terraformExitCode of [0, 2]) test(`failed JSON check blocks Terraform exit code ${terraformExitCode}`, () => { const checks = passingChecks(); checks[0].status = "fail"; const result = classifyStageBRefreshResult({ plan: { ...noChangePlan(), checks }, terraformExitCode, bindingReport: bindingReport(), state, outputsSource }); assert.equal(result.status, "FAILED_CHECK"); });
test("bound_images update matching signed evidence passes", () => assert.equal(classifyStageBRefreshResult({ plan: { ...noChangePlan(), output_changes: outputChange("bound_images", expectedImages) }, bindingReport: bindingReport(), state, outputsSource }).status, "REVIEWED_OUTPUT_RECONCILIATION"));
test("wrong, missing, or extra image bindings fail", () => { const wrong = { ...expectedImages, backend: "wrong" }; assert.equal(classifyStageBRefreshResult({ plan: { ...noChangePlan(), output_changes: outputChange("bound_images", wrong) }, bindingReport: bindingReport(), state, outputsSource }).status, "OUTPUT_DRIFT"); const missing = { ...expectedImages }; delete missing.worker; assert.equal(classifyStageBRefreshResult({ plan: { ...noChangePlan(), output_changes: outputChange("bound_images", missing) }, bindingReport: bindingReport(), state, outputsSource }).status, "OUTPUT_DRIFT"); const extra = { ...expectedImages, extra: "unexpected" }; assert.equal(classifyStageBRefreshResult({ plan: { ...noChangePlan(), output_changes: outputChange("bound_images", extra) }, bindingReport: bindingReport(), state, outputsSource }).status, "OUTPUT_DRIFT"); });
test("unexpected output name fails", () => assert.equal(classifyStageBRefreshResult({ plan: { ...noChangePlan(), output_changes: outputChange("unknown", {}) }, bindingReport: bindingReport(), state, outputsSource }).status, "OUTPUT_DRIFT"));
test("task_definition_arns is reviewed when an empty state has an exact planned mapping", () => assert.equal(classifyStageBRefreshResult({ plan: { ...noChangePlan(), output_changes: { task_definition_arns: { actions: ["create"], before: null, after: {}, after_unknown: false, after_sensitive: false } } }, bindingReport: bindingReport(), state, outputsSource }).status, "REVIEWED_OUTPUT_RECONCILIATION"));
test("unknown task-definition state fails closed", () => assert.equal(classifyStageBRefreshResult({ plan: { ...noChangePlan(), output_changes: { task_definition_arns: { actions: ["create"], after: {}, after_unknown: false } } }, bindingReport: bindingReport(), state: { ...state, resources: [{ type: "aws_ecs_task_definition", name: "candidate", instances: [{}] }] }, outputsSource }).status, "MALFORMED_RESULT"));
test("canonical current task-definition state reconciles to the exact Terraform output mapping", () => {
  const current = currentTaskDefinitionStateFixture();
  const result = classifyStageBRefreshResult({ plan: noChangePlan(), bindingReport: bindingReport(), state: current, outputsSource });
  assert.equal(result.status, "NO_CHANGES");
  assert.equal(result.taskDefinitionOutputClassification, "STATE_OUTPUT_ALREADY_CONVERGED");
  assert.deepEqual(result.taskDefinitionArns, current.outputs.task_definition_arns.value);
});
test("valid current resources authorize a planned output correction when state output is absent", () => {
  const current = currentTaskDefinitionStateFixture();
  delete current.outputs;
  const mapping = currentTaskDefinitionStateFixture().outputs.task_definition_arns.value;
  const result = classifyStageBRefreshResult({ plan: { ...noChangePlan(), output_changes: { task_definition_arns: { actions: ["create"], before: null, after: mapping, after_unknown: false, after_sensitive: false } } }, bindingReport: bindingReport(), state: current, outputsSource });
  assert.equal(result.status, "REVIEWED_OUTPUT_RECONCILIATION");
  assert.equal(result.taskDefinitionOutputClassification, "REVIEWED_OUTPUT_RECONCILIATION");
  assert.deepEqual(result.taskDefinitionArns, mapping);
});
test("valid current resources authorize stale or empty predecessor output correction", () => {
  const canonical = currentTaskDefinitionStateFixture();
  const mapping = canonical.outputs.task_definition_arns.value;
  for (const before of [{}, { backend: mapping.backend.replace(":5", ":4") }]) {
    const current = { ...canonical, outputs: { task_definition_arns: { value: before } } };
    const result = classifyStageBRefreshResult({ plan: { ...noChangePlan(), output_changes: { task_definition_arns: { actions: ["update"], before, after: mapping, after_unknown: false, after_sensitive: false } } }, bindingReport: bindingReport(), state: current, outputsSource });
    assert.equal(result.status, "REVIEWED_OUTPUT_RECONCILIATION");
  }
});
test("planned task_definition_arns output must match the resource-derived mapping", () => {
  const canonical = currentTaskDefinitionStateFixture();
  const mapping = canonical.outputs.task_definition_arns.value;
  for (const after of [
    { ...mapping, extra: mapping.backend },
    Object.fromEntries(Object.entries(mapping).filter(([key]) => key !== "worker")),
    { ...mapping, worker: mapping.backend },
    { ...mapping, backend: mapping.backend.replace("368992683803", "000000000000") },
    { ...mapping, backend: mapping.backend.replace("eu-west-2", "us-east-1") },
    { ...mapping, backend: mapping.backend.replace("mscqr-production-rls-green-backend-candidate", "wrong-family") },
  ]) {
    const result = classifyStageBRefreshResult({ plan: { ...noChangePlan(), output_changes: { task_definition_arns: { actions: ["update"], before: {}, after, after_unknown: false, after_sensitive: false } } }, bindingReport: bindingReport(), state: { ...canonical, outputs: {} }, outputsSource });
    assert.equal(result.status, "OUTPUT_DRIFT");
    assert.equal(result.taskDefinitionOutputClassification, "OUTPUT_RECONCILIATION_INVALID");
  }
});
test("malicious predecessor keys and non-reviewed output actions fail closed", () => {
  const canonical = currentTaskDefinitionStateFixture();
  const mapping = canonical.outputs.task_definition_arns.value;
  const malicious = classifyStageBRefreshResult({ plan: { ...noChangePlan(), output_changes: { task_definition_arns: { actions: ["update"], before: { fake: mapping.backend }, after: mapping, after_unknown: false, after_sensitive: false } } }, bindingReport: bindingReport(), state: { ...canonical, outputs: {} }, outputsSource });
  assert.equal(malicious.status, "OUTPUT_DRIFT");
  const preserved = { ...mapping, fake: mapping.backend };
  const maliciousState = { ...canonical, outputs: { task_definition_arns: { value: preserved } } };
  const preservedResult = classifyStageBRefreshResult({ plan: { ...noChangePlan(), output_changes: { task_definition_arns: { actions: ["update"], before: preserved, after: preserved, after_unknown: false, after_sensitive: false } } }, bindingReport: bindingReport(), state: maliciousState, outputsSource });
  assert.equal(preservedResult.status, "OUTPUT_DRIFT");
  const actions = classifyStageBRefreshResult({ plan: { ...noChangePlan(), output_changes: { task_definition_arns: { actions: ["create", "update"], before: {}, after: mapping, after_unknown: false, after_sensitive: false } } }, bindingReport: bindingReport(), state: { ...canonical, outputs: {} }, outputsSource });
  assert.equal(actions.status, "OUTPUT_DRIFT");
});
test("task-definition output correction cannot accompany resource drift", () => {
  const canonical = currentTaskDefinitionStateFixture();
  const mapping = canonical.outputs.task_definition_arns.value;
  const result = classifyStageBRefreshResult({ plan: { ...noChangePlan(), resource_changes: [{ address: "aws_lambda_function.broker", type: "aws_lambda_function", change: { actions: ["update"] } }], output_changes: { task_definition_arns: { actions: ["update"], before: {}, after: mapping, after_unknown: false, after_sensitive: false } } }, bindingReport: bindingReport(), state: { ...canonical, outputs: {} }, outputsSource });
  assert.equal(result.status, "RESOURCE_DRIFT");
});
test("current task-definition reconciliation rejects malformed or non-canonical state", () => {
  const cases = [
    ["unknown collection", (candidate) => candidate.resources.push({ mode: "managed", type: "aws_ecs_task_definition", name: "fake", instances: [] })],
    ["wrong account", (candidate) => { candidate.resources[0].instances[0].attributes.arn = candidate.resources[0].instances[0].attributes.arn.replace(STAGE_B.account, "000000000000"); }],
    ["wrong region", (candidate) => { candidate.resources[0].instances[0].attributes.arn = candidate.resources[0].instances[0].attributes.arn.replace(STAGE_B.region, "us-east-1"); }],
    ["wrong candidate family", (candidate) => { candidate.resources[0].instances[0].attributes.family = "wrong-family"; }],
    ["wrong executor family", (candidate) => { candidate.resources[1].instances[0].attributes.family = "wrong-family"; }],
    ["candidate output mismatch", (candidate) => { candidate.outputs.task_definition_arns.value.backend = candidate.outputs.task_definition_arns.value.worker; }],
    ["executor output mismatch", (candidate) => { candidate.outputs.task_definition_arns.value[STAGE_B_MODES[0]] = candidate.outputs.task_definition_arns.value[STAGE_B_MODES[1]]; }],
    ["missing candidate", (candidate) => { candidate.resources = candidate.resources.filter(({ name }) => name !== "candidate"); }],
    ["missing executor", (candidate) => { candidate.resources = candidate.resources.filter(({ name }) => name !== "executor"); }],
    ["malformed ARN", (candidate) => { candidate.resources[0].instances[0].attributes.arn = "not-an-arn"; }],
    ["duplicate ARN", (candidate) => { candidate.resources[0].instances[1].attributes.arn = candidate.resources[0].instances[0].attributes.arn; }],
    ["duplicate ARN with matching output", (candidate) => { const arn = candidate.resources[0].instances[0].attributes.arn; candidate.resources[0].instances[1].attributes.arn = arn; candidate.outputs.task_definition_arns.value.worker = arn; }],
    ["extra output", (candidate) => { candidate.outputs.task_definition_arns.value.extra = candidate.outputs.task_definition_arns.value.backend; }],
    ["arbitrary output key", (candidate) => { candidate.outputs.task_definition_arns.value.arbitrary = candidate.outputs.task_definition_arns.value.backend; }],
    ["stale revision", (candidate) => { candidate.outputs.task_definition_arns.value.backend = candidate.outputs.task_definition_arns.value.backend.replace(":5", ":4"); }],
    ["empty output", (candidate) => { candidate.outputs.task_definition_arns.value = {}; }],
  ];
  for (const [label, mutate] of cases) {
    const candidate = structuredClone(currentTaskDefinitionStateFixture());
    mutate(candidate);
    const result = classifyStageBRefreshResult({ plan: noChangePlan(), bindingReport: bindingReport(), state: candidate, outputsSource });
    assert.notEqual(result.status, "NO_CHANGES", label);
    assert.notEqual(result.status, "REVIEWED_OUTPUT_RECONCILIATION", label);
  }
});
test("current task-definition reconciliation is order independent and serial independent after binding validation", () => {
  const current = currentTaskDefinitionStateFixture();
  current.resources.reverse();
  current.resources.forEach((resource) => resource.instances.reverse());
  current.serial = 94;
  const result = classifyStageBRefreshResult({ plan: noChangePlan(), bindingReport: bindingReport(), state: current, outputsSource });
  assert.equal(result.status, "NO_CHANGES");
});
for (const action of ["update", "create", "delete", "replace", "create-delete"]) test(`resource ${action} fails closed`, () => assert.equal(classifyStageBRefreshResult({ plan: { ...noChangePlan(), resource_changes: [{ address: "aws_lambda_function.broker", type: "aws_lambda_function", change: { actions: [action] } }] }, bindingReport: bindingReport(), state, outputsSource }).status, "RESOURCE_DRIFT"));
test("failed checks and provider failures remain distinct", () => { assert.equal(classifyStageBRefreshResult({ plan: undefined, terraformExitCode: 1, bindingReport: bindingReport(), state, outputsSource }).status, "FAILED_CHECK"); assert.equal(classifyStageBRefreshResult({ plan: undefined, terraformExitCode: 3, bindingReport: bindingReport(), state, outputsSource }).status, "PROVIDER_OR_BACKEND_FAILURE"); });
test("human No changes text cannot override structural resource drift", () => assert.equal(classifyStageBRefreshResult({ plan: { ...noChangePlan(), resource_changes: [{ address: "aws_lambda_function.broker", change: { actions: ["update"] } }] }, terraformOutput: "No changes.", bindingReport: bindingReport(), state, outputsSource }).status, "RESOURCE_DRIFT"));
test("malformed JSON fails closed", () => assert.equal(classifyStageBRefreshResult({ plan: { resource_changes: [], output_changes: null }, bindingReport: bindingReport(), state, outputsSource }).status, "MALFORMED_RESULT"));
test("refresh evidence rejects non-allowlisted status", () => { const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-refresh-contract-")); const reportPath = path.join(directory, "refresh.json"); fs.writeFileSync(reportPath, JSON.stringify({ schemaVersion: 1, status: "RESOURCE_DRIFT", deployablePlan: false }), { mode: 0o600 }); assert.throws(() => assertStageBRefreshEvidence({ refreshReportPath: reportPath, bindingReport: bindingReport() }), /not an approved/); });
test("stale state serial invalidates refresh state evidence", () => { const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-refresh-contract-")); const statePath = path.join(directory, "state.json"); const bytes = Buffer.from(JSON.stringify({ ...state, serial: 75 })); fs.writeFileSync(statePath, bytes, { mode: 0o600 }); assert.throws(() => assertStageBRefreshStateBinding({ stateBackupPath: statePath, bindingReport: { ...bindingReport(), stateBackupSha256: crypto.createHash("sha256").update(bytes).digest("hex") } }), /identity does not match/); });
test("refresh state binding requires numeric non-negative serials on both operands", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-refresh-serial-"));
  for (const [stateSerial, bindingSerial] of [[78, 78], [-1, -1], ["78", "78"], [78, "78"], ["78", 78], [Number.MAX_SAFE_INTEGER + 1, Number.MAX_SAFE_INTEGER + 1], [78.5, 78.5]]) {
    const stateBytes = Buffer.from(JSON.stringify({ ...state, serial: stateSerial }));
    const statePath = path.join(directory, `${String(stateSerial).replace(/[^a-z0-9]/gi, "_")}-${String(bindingSerial).replace(/[^a-z0-9]/gi, "_")}.json`);
    fs.writeFileSync(statePath, stateBytes, { mode: 0o600 });
    const binding = { ...bindingReport(), stateSerial: bindingSerial, stateBackupSha256: crypto.createHash("sha256").update(stateBytes).digest("hex") };
    if (stateSerial === 78 && bindingSerial === 78) assert.doesNotThrow(() => assertStageBRefreshStateBinding({ stateBackupPath: statePath, bindingReport: binding }));
    else assert.throws(() => assertStageBRefreshStateBinding({ stateBackupPath: statePath, bindingReport: binding }), /serial|identity/);
  }
});
test("mismatched tfvars or image evidence invalidates refresh evidence", () => { const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-refresh-contract-")); const reportPath = path.join(directory, "refresh.json"); const checks = passingChecks(); const checkProof = inspectStageBRefreshChecks({ checks }); fs.writeFileSync(reportPath, JSON.stringify({ schemaVersion: 1, status: "NO_CHANGES", deployablePlan: false, acquisitionStatus: "valid", terraformVersion: "1.15.7", terraformVersionSha256: crypto.createHash("sha256").update("1.15.7").digest("hex"), formatVersion: "1.2", planCommandExitCode: 0, showCommandExitCode: 0, refreshPlanPath: path.join(directory, ".stage-b-refresh", "refresh-only.tfplan"), refreshPlanSha256: "a".repeat(64), refreshPlanJsonSha256: "b".repeat(64), showStdoutSha256: "b".repeat(64), showStderrSha256: "c".repeat(64), toolingSha, toolingTreeSha256, tfvarsSha256: "wrong", imageEvidenceSha256: bindingReport().imageEvidenceCanonicalSha256, stageAStateSha256: "a".repeat(64), stageAStateLineage: "02afb75a-f902-ab8a-f4c1-751d4aef7837", stageAStateSerial: 35, stageBStateSha256: bindingReport().stateBackupSha256, stageBStateLineage: bindingReport().stateLineage, stageBStateSerial: bindingReport().stateSerial, backendMetadataPath: path.join(directory, "terraform.tfstate"), backendMetadataMode: "0600", privateModeValidated: true, terraformDataDir: directory, workspace: "default", checkCount: checkProof.checkCount, infrastructureCheckCount: checkProof.infrastructureCheckCount, variableCheckCount: checkProof.variableCheckCount, passedCheckCount: checkProof.passedCheckCount, failedCheckCount: checkProof.failedCheckCount, malformedCheckCount: checkProof.malformedCheckCount, missingCheckCount: checkProof.missingCheckCount, unknownCheckCount: checkProof.unknownCheckCount, duplicateCheckCount: checkProof.duplicateCheckCount, checkInventoryHash: checkProof.checkInventoryHash, emittedInstanceCount: checkProof.emittedInstanceCount, passedInstanceCount: checkProof.passedInstanceCount, failedInstanceCount: checkProof.failedInstanceCount, malformedInstanceCount: checkProof.malformedInstanceCount, duplicateInstanceCount: checkProof.duplicateInstanceCount, instanceInventoryHash: checkProof.instanceInventoryHash, failedChecks: [], checks, resourceChanges: { nonNoOp: 0, changes: [] }, outputChanges: [] }), { mode: 0o600 }); assert.throws(() => assertStageBRefreshEvidence({ refreshReportPath: reportPath, bindingReport: bindingReport(), expectedTfvarsSha256: bindingReport().tfvarsSha256 }), /tfvarsSha256/); });
