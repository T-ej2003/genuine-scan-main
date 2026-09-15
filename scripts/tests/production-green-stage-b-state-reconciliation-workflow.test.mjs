import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import yaml from "js-yaml";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../..");
const read = (name) => fs.readFileSync(path.join(root, ".github/workflows", name), "utf8");
const parse = (name) => yaml.load(read(name));

test("Stage B state reconciliation workflows are protected, exact, and fail closed", () => {
  const authorize = parse("authorize-production-green-stage-b-state-reconciliation.yml");
  const execute = parse("execute-production-green-stage-b-state-reconciliation.yml");
  for (const [workflow, source] of [[authorize, read("authorize-production-green-stage-b-state-reconciliation.yml")], [execute, read("execute-production-green-stage-b-state-reconciliation.yml")]]) {
    assert.deepEqual(Object.keys(workflow.on), ["workflow_dispatch"]);
    assert.equal(workflow.concurrency.group, "production-deploy"); assert.equal(workflow.concurrency["cancel-in-progress"], false);
    assert.match(source, /environment: production/); assert.doesNotMatch(source, /continue-on-error|set \+e|\|\| true/);
  }
  assert.deepEqual(authorize.permissions, { actions: "read", contents: "read" });
  assert.deepEqual(execute.permissions, { actions: "read", contents: "read", "id-token": "write" });
  const inputs = execute.on.workflow_dispatch.inputs;
  for (const name of ["preparation_base64", "preparation_sha256", "saved_plan_base64", "saved_plan_sha256", "tfvars_base64", "tfvars_sha256", "binding_base64", "binding_sha256", "release_preflight_base64", "release_preflight_sha256", "authorization_workflow_run_id", "authorization_workflow_run_attempt"]) assert.equal(inputs[name]?.required, true);
  const source = read("execute-production-green-stage-b-state-reconciliation.yml");
  for (const name of ["PREPARATION_SHA256", "PLAN_SHA256", "TFVARS_SHA256", "BINDING_SHA256", "PREFLIGHT_SHA256"]) assert.match(source, new RegExp(`\\$${name}`));
  assert.match(source, /sha256:\$\(sha256sum "\$d\/authorization\.zip"/); assert.match(source, /test "\$\(unzip -Z1 "\$d\/authorization\.zip"\)" = authorization\.json/);
});
