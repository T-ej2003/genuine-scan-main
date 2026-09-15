import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import yaml from "js-yaml";

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
  for (const name of ["tfvars_base64", "binding_base64", "release_preflight_workflow_run_id", "release_preflight_workflow_run_attempt", "release_preflight_artifact_id", "release_preflight_artifact_digest"]) assert.equal(prepare.on.workflow_dispatch.inputs[name]?.required, true);
  for (const workflow of [authorize, execute]) for (const name of ["preparation_workflow_run_id", "preparation_workflow_run_attempt"]) assert.equal(workflow.on.workflow_dispatch.inputs[name]?.required, true);
  for (const name of ["authorization_workflow_run_id", "authorization_workflow_run_attempt"]) assert.equal(execute.on.workflow_dispatch.inputs[name]?.required, true);
  const source = read(names[2]);
  assert.match(source, /preparation-bundle\.zip/); assert.match(source, /authorization\.zip/); assert.match(source, /sha256:\$\(sha256sum "\$d\/preparation\.zip"/); assert.match(source, /test "\$\(unzip -Z1 "\$d\/authorization\.zip"\)" = authorization\.json/);
  assert.match(source, /install -m 600 \/dev\/null "\$d\/authorization\.json"/);
  assert.doesNotMatch(source, /saved_plan_base64|preparation_base64|release_preflight_base64|release_preflight_workflow_path/);
  assert.match(read(names[0]), /produce-production-green-stage-b-release-preflight\.yml/);
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
  assert.match(source, /GITHUB_RUN_ATTEMPT/); assert.match(source, /git fetch --no-tags origin main/);
  assert.match(source, /IMAGE_AUTHORIZATION_SHA256/); assert.match(source, /base64 --decode/); assert.match(source, /test "\$\{#IMAGE_AUTHORIZATION_BASE64\}" -le 32768/);
  assert.match(source, /verify-production-release-image-authorization\.mjs/); assert.match(source, /github-oidc-release-deployer/);
  assert.match(source, /production-green-stage-b-state-reconciliation-image-authorization/); assert.match(source, /retention-days: 1/);
  assert.doesNotMatch(source, /terraform|ecs|apply-production|publish-ecs-images|kms:Sign|release-gate\.yml/);
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
});

test("the prerequisite producer is a single source-bound four-member producer", () => {
  const name = "produce-production-green-stage-b-prerequisite-bundle.yml";
  const workflow = parse(name); const source = read(name); const producer = fs.readFileSync(path.join(root, "scripts/aws/produce-production-green-stage-b-prerequisite-bundle.mjs"), "utf8");
  assert.deepEqual(Object.keys(workflow.on), ["workflow_dispatch"]);
  assert.deepEqual(Object.keys(workflow.on.workflow_dispatch.inputs).sort(), ["source_sha", "ticket_id"]);
  assert.deepEqual(workflow.permissions, { actions: "read", contents: "read", "id-token": "write" });
  assert.equal(workflow.jobs.produce.environment, "production");
  assert.match(source, /produce-production-green-stage-b-prerequisite-bundle\.mjs --source-sha/);
  assert.match(source, /production-green-stage-b-state-reconciliation-prerequisites/);
  assert.match(source, /prerequisite-bundle\.zip/);
  assert.match(source, /GITHUB_RUN_ATTEMPT/); assert.match(producer, /GITHUB_WORKFLOW_REF/); assert.match(producer, /GITHUB_RUN_ATTEMPT/);
  assert.doesNotMatch(source, /(?:tfvars|binding|release_preflight|saved_plan|preparation)_base64|raw filesystem|artifact_id/);
});
