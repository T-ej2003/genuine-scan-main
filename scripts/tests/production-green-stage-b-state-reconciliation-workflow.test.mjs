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
  assert.ok(Object.keys(prepare.on.workflow_dispatch.inputs).length <= 10);
  assert.ok(Object.keys(authorize.on.workflow_dispatch.inputs).length <= 10);
  assert.ok(Object.keys(execute.on.workflow_dispatch.inputs).length <= 10);
  for (const name of ["tfvars_base64", "tfvars_sha256", "binding_base64", "binding_sha256", "release_preflight_base64", "release_preflight_sha256"]) assert.equal(prepare.on.workflow_dispatch.inputs[name]?.required, true);
  for (const workflow of [authorize, execute]) for (const name of ["preparation_workflow_run_id", "preparation_workflow_run_attempt"]) assert.equal(workflow.on.workflow_dispatch.inputs[name]?.required, true);
  for (const name of ["authorization_workflow_run_id", "authorization_workflow_run_attempt"]) assert.equal(execute.on.workflow_dispatch.inputs[name]?.required, true);
  const source = read(names[2]);
  assert.match(source, /preparation-bundle\.zip/); assert.match(source, /authorization\.zip/); assert.match(source, /sha256:\$\(sha256sum "\$d\/preparation\.zip"/); assert.match(source, /test "\$\(unzip -Z1 "\$d\/authorization\.zip"\)" = authorization\.json/);
  assert.doesNotMatch(source, /saved_plan_base64|preparation_base64|tfvars_base64/);
});
