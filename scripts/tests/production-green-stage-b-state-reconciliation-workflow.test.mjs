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
