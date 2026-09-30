import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import yaml from "js-yaml";
import { ensureStageBPrivateDirectory, readStageBPrivateFileBytes, writeStageBPrivateFileExclusive } from "../aws/stage-b-artifact-contract.mjs";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../..");
const read = (name) => fs.readFileSync(path.join(root, ".github/workflows", name), "utf8");
const parse = (name) => yaml.load(read(name));

test("Stage B state reconciliation workflows are protected, artifact-bound, and fail closed", () => {
  const names = ["prepare-production-green-stage-b-state-reconciliation.yml", "authorize-production-green-stage-b-state-reconciliation.yml", "execute-production-green-stage-b-state-reconciliation.yml"];
  const [prepare, authorize, execute] = names.map(parse);
  for (const [workflow, source] of [[prepare, read(names[0])], [authorize, read(names[1])], [execute, read(names[2])]]) {
    assert.deepEqual(Object.keys(workflow.on), ["workflow_dispatch"]);
    assert.equal(workflow.concurrency.group, "production-deploy"); assert.equal(workflow.concurrency["cancel-in-progress"], false);
    assert.doesNotMatch(source, /continue-on-error|set \+e|\|\| true/);
  }
  assert.deepEqual(prepare.permissions, { actions: "read", contents: "read", "id-token": "write" });
  assert.deepEqual(authorize.permissions, { actions: "read", contents: "read" });
  assert.deepEqual(execute.permissions, { actions: "read", contents: "read", "id-token": "write" });
  assert.equal(prepare.jobs.prepare.environment, "production");
  assert.equal(execute.jobs.execute.environment, "production");
  assert.ok(Object.keys(prepare.on.workflow_dispatch.inputs).length <= 10);
  assert.ok(Object.keys(authorize.on.workflow_dispatch.inputs).length <= 10);
  assert.ok(Object.keys(execute.on.workflow_dispatch.inputs).length <= 10);
  for (const name of ["prerequisite_bundle_artifact_id", "prerequisite_bundle_artifact_digest", "release_preflight_workflow_run_id", "release_preflight_workflow_run_attempt", "release_preflight_artifact_id", "release_preflight_artifact_digest"]) assert.equal(prepare.on.workflow_dispatch.inputs[name]?.required, true);
  assert.doesNotMatch(read(names[0]), /tfvars_base64|binding_base64|base64 --decode/);
  assert.match(read(names[0]), /PRODUCER_ARTIFACT/); assert.match(read(names[0]), /PRODUCER_DIGEST/); assert.match(read(names[0]), /select\(\(\.id\|tostring\) == \$id/);
  for (const workflow of [authorize, execute]) for (const name of ["preparation_workflow_run_id", "preparation_workflow_run_attempt"]) assert.equal(workflow.on.workflow_dispatch.inputs[name]?.required, true);
  for (const name of ["authorization_workflow_run_id", "authorization_workflow_run_attempt"]) assert.equal(execute.on.workflow_dispatch.inputs[name]?.required, true);
  const source = read(names[2]);
  assert.match(source, /preparation-bundle\.zip/); assert.match(source, /authorization\.zip/); assert.match(source, /sha256:\$\(sha256sum "\$d\/preparation\.zip"/); assert.match(source, /test "\$\(unzip -Z1 "\$d\/authorization\.zip"\)" = authorization\.json/);
  assert.match(source, /install -m 600 \/dev\/null "\$d\/authorization\.json"/);
  assert.doesNotMatch(source, /saved_plan_base64|preparation_base64|release_preflight_base64|release_preflight_workflow_path/);
  assert.match(read(names[0]), /produce-production-green-stage-b-release-preflight\.yml/);
});

test("execution workflow creates the complete private staging hierarchy before reconciliation", () => {
  const workflow = parse("execute-production-green-stage-b-state-reconciliation.yml");
  const steps = workflow.jobs.execute.steps;
  const authenticate = steps.find((step) => step.name === "Authenticate protected source and exact preparation artifact").run;
  const authorization = steps.find((step) => step.name === "Download authenticated authorization artifact").run;
  const setup = authenticate.split("\n").map((line) => line.trim()).find((line) => line.startsWith("umask 077; d="));
  assert.equal(setup, 'umask 077; d="$RUNNER_TEMP/stage-b-state-reconciliation"; install -d -m 700 "$d" "$d/terraform-data"');
  assert.match(authorization, /^set -euo pipefail\numask 077$/m);

  const runnerTemp = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-execution-workflow-"));
  const staging = path.join(runnerTemp, "stage-b-state-reconciliation");
  const terraformData = path.join(staging, "terraform-data");
  try {
    assert.equal(fs.existsSync(staging), false);
    execFileSync("/bin/bash", ["-c", setup], { env: { ...process.env, RUNNER_TEMP: runnerTemp } });
    assert.equal(fs.statSync(staging).mode & 0o777, 0o700);
    assert.equal(fs.statSync(terraformData).mode & 0o777, 0o700);
    assert.equal(ensureStageBPrivateDirectory({ directory: staging, repositoryRoot: root }), staging);

    const savedPlan = path.join(staging, "refresh.tfplan");
    writeStageBPrivateFileExclusive({ filePath: savedPlan, bytes: Buffer.from("saved-plan"), repositoryRoot: root, label: "Saved refresh-only plan" });
    assert.equal(readStageBPrivateFileBytes({ filePath: savedPlan, repositoryRoot: root }).sha256.length, 64);

    const result = path.join(staging, "result.json");
    writeStageBPrivateFileExclusive({ filePath: result, bytes: Buffer.from("{}\n"), repositoryRoot: root, label: "Stage B state reconciliation result" });
    assert.equal(fs.statSync(result).mode & 0o777, 0o600);
    assert.equal(readStageBPrivateFileBytes({ filePath: result, repositoryRoot: root }).bytes.toString(), "{}\n");

    fs.chmodSync(staging, 0o755);
    assert.throws(() => ensureStageBPrivateDirectory({ directory: staging, repositoryRoot: root, label: "Stage B state reconciliation result output" }), /mode 0700/);
    fs.chmodSync(staging, 0o700);
    fs.chmodSync(result, 0o644);
    assert.throws(() => readStageBPrivateFileBytes({ filePath: result, repositoryRoot: root, label: "Stage B state reconciliation result" }), /mode 0600/);
  } finally {
    fs.rmSync(runnerTemp, { recursive: true, force: true });
  }
});

test("the canonical release-preflight producer is real, source-bound, and artifact-backed", () => {
  const name = "produce-production-green-stage-b-release-preflight.yml";
  const workflow = parse(name); const source = read(name);
  assert.deepEqual(Object.keys(workflow.on.workflow_dispatch.inputs).sort(), ["binding_sha256", "image_authorization_artifact_digest", "image_authorization_artifact_id", "image_authorization_workflow_run_attempt", "image_authorization_workflow_run_id", "source_sha", "tfvars_sha256"]);
  assert.deepEqual(workflow.permissions, { actions: "read", contents: "read", "id-token": "write" });
  assert.equal(workflow.jobs.produce.environment, "production");
  assert.match(source, /produce-production-green-stage-b-release-preflight\.mjs/);
  assert.match(source, /produce-production-green-stage-b-state-reconciliation-image-authorization\.yml/); assert.match(source, /production-green-stage-b-state-reconciliation-image-authorization/);
  assert.doesNotMatch(source, /release-gate\.yml/);
  assert.match(source, /conclusion.*success/); assert.match(source, /expired.*false/); assert.match(source, /sha256sum/);
  assert.match(source, /unzip -Z1.*image-authorization\.json/); assert.match(source, /install -m 600/);
  assert.doesNotMatch(source, /authorization_base64|raw filesystem path/);
});

test("state-only image-authorization producer is protected, independently authenticates its payload, and cannot deploy", () => {
  const name = "produce-production-green-stage-b-state-reconciliation-image-authorization.yml";
  const workflow = parse(name); const source = read(name);
  assert.deepEqual(Object.keys(workflow.on.workflow_dispatch.inputs).sort(), ["image_authorization_base64", "image_authorization_sha256", "source_sha"]);
  assert.deepEqual(workflow.permissions, { contents: "read", "id-token": "write" });
  assert.equal(workflow.concurrency.group, "production-deploy"); assert.equal(workflow.concurrency["cancel-in-progress"], false);
  assert.equal(workflow.jobs.produce.environment, "production");
  assert.match(source, /GITHUB_RUN_ATTEMPT/); assert.match(source, /GITHUB_TOKEN: \$\{\{ github\.token \}\}/); assert.match(source, /gh api repos\/\$GITHUB_REPOSITORY\/branches\/main --jq \.commit\.sha/);
  assert.match(source, /IMAGE_AUTHORIZATION_SHA256/); assert.match(source, /base64 --decode/); assert.match(source, /test "\$\{#IMAGE_AUTHORIZATION_BASE64\}" -le 32768/);
  assert.match(source, /verify-production-release-image-authorization\.mjs/); assert.match(source, /github-oidc-release-deployer/);
  assert.match(source, /production-green-stage-b-state-reconciliation-image-authorization/); assert.match(source, /retention-days: 1/);
  assert.doesNotMatch(source, /terraform|ecs|apply-production|publish-ecs-images|kms:Sign|release-gate\.yml/);
});

test("state-reconciliation prerequisite runbook names the non-deploy image-authorization handoff", () => {
  const runbook = fs.readFileSync(path.join(root, "documents/ops/iam/PRODUCTION_GREEN_STAGE_B_PREREQUISITE_BUNDLE.md"), "utf8");
  assert.match(runbook, /produce-production-green-stage-b-state-reconciliation-image-authorization\.yml/);
  assert.match(runbook, /production-green-stage-b-state-reconciliation-image-authorization/);
  assert.doesNotMatch(runbook, /Release Gate image-authorization artifact/);
});

test("reconciliation readers authenticate and consume private JSON directly", () => {
  const reconcile = fs.readFileSync(path.join(root, "scripts/aws/reconcile-production-green-stage-b-state.mjs"), "utf8");
  const authorize = fs.readFileSync(path.join(root, "scripts/aws/authorize-production-green-stage-b-state-reconciliation.mjs"), "utf8");
  assert.match(reconcile, /--release-preflight-sha256/);
  assert.match(reconcile, /--authorization-file-sha256/);
  assert.doesNotMatch(reconcile, /readBoundStageBPrivateJson\([^;]+\)\.value/);
  assert.doesNotMatch(authorize, /readBoundStageBPrivateJson\([^;]+\)\.value/);
  assert.match(read("prepare-production-green-stage-b-state-reconciliation.yml"), /--release-preflight-sha256/);
  assert.match(read("execute-production-green-stage-b-state-reconciliation.yml"), /--release-preflight-sha256/);
  assert.match(read("execute-production-green-stage-b-state-reconciliation.yml"), /--authorization-file-sha256/);
  assert.match(read("produce-production-green-stage-b-release-preflight.yml"), /GITHUB_TOKEN: \$\{\{ github\.token \}\}/);
  assert.match(reconcile, /path\.join\(path\.dirname\(data\), "prerequisites"\)/);
  assert.equal((reconcile.match(/outputDirectory: prerequisiteMaterializationDirectory/g) || []).length, 2);
});

test("every specialized reconciliation subprocess uses streaming or file-backed output", () => {
  const reconcile = fs.readFileSync(path.join(root, "scripts/aws/reconcile-production-green-stage-b-state.mjs"), "utf8");
  assert.match(reconcile, /captureStageBTerraformJson/);
  assert.match(reconcile, /stdio: \["ignore", "inherit", "inherit"\]/);
  assert.doesNotMatch(reconcile, /execFileSync|stdio: \["ignore", "pipe", "pipe"\]|maxBuffer/);
  assert.doesNotMatch(reconcile, /terraform\(\["show", "-json"/);
  assert.match(reconcile, /const plan = renderPlan\(saved, env\)/);
  assert.match(reconcile, /const normalPlan = renderPlan\(sourcePlanPath, env\)/);
  assert.match(reconcile, /return renderPlan\(output, env\)/);
});

test("the prerequisite producer is source-bound and transports generated inputs by authenticated artifact", () => {
  const name = "produce-production-green-stage-b-prerequisite-bundle.yml";
  const workflow = parse(name); const source = read(name); const producer = fs.readFileSync(path.join(root, "scripts/aws/produce-production-green-stage-b-prerequisite-bundle.mjs"), "utf8");
  assert.deepEqual(Object.keys(workflow.on), ["workflow_dispatch"]);
  assert.deepEqual(Object.keys(workflow.on.workflow_dispatch.inputs).sort(), ["image_authorization_artifact_digest", "image_authorization_artifact_id", "image_authorization_workflow_run_attempt", "image_authorization_workflow_run_id", "source_sha", "ticket_id"]);
  assert.deepEqual(workflow.permissions, { actions: "read", contents: "read", "id-token": "write" });
  assert.equal(workflow.jobs.produce.environment, "production");
  assert.match(source, /produce-production-green-stage-b-prerequisite-bundle\.mjs[\s\\]+--source-sha/);
  assert.match(source, /production-green-stage-b-state-reconciliation-prerequisites/);
  assert.match(source, /prerequisite-bundle\.zip/);
  assert.match(source, /GITHUB_RUN_ATTEMPT/); assert.match(producer, /GITHUB_WORKFLOW_REF/); assert.match(producer, /GITHUB_RUN_ATTEMPT/);
  assert.match(source, /produce-production-green-stage-b-state-reconciliation-image-authorization\.yml/); assert.match(source, /IMAGE_ARTIFACT/); assert.match(source, /IMAGE_DIGEST/);
  assert.doesNotMatch(source, /(?:tfvars|binding|release_preflight|saved_plan|preparation)_base64|raw filesystem/);
  assert.match(producer, /stage-b\.tfvars/); assert.match(producer, /stage-b-tfvars-binding\.json/);
});
