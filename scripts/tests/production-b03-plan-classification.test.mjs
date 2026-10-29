import { fixture, source } from "./fixtures/production-b03-plan.mjs";
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { assertStageBPlan, assertStageBPlanCapture } from "../plan-production-green-stage-b.mjs";
import { B03_TASK_ADDRESS } from "../aws/production-b03-plan-contract.mjs";

const options = { terraformConfiguration: fs.readFileSync("infra/aws/terraform/production-green-stage-b/main.tf", "utf8") };
test("canonical classifier and capture recognize the fixed B03 executor create and retained no-op", () => {
  const plan = fixture();
  assert.equal(assertStageBPlan(plan, options).classifiedResources[0].classification, "b03-fixed-executor");
  assert.equal(assertStageBPlanCapture(plan, options).unclassifiedResources.length, 0);
  const change = plan.resource_changes[0];
  change.change.after.arn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-b03-incremental:1";
  change.change.actions = ["no-op"]; change.change.before = structuredClone(change.change.after); delete change.change.after_unknown;
  assert.equal(assertStageBPlan(plan, options).actionCounts["no-op"], 1);
});

for (const [name, mutate] of Object.entries({
  "wrong address": p => p.resource_changes[0].address = "aws_ecs_task_definition.b03[1]",
  "wrong family": p => p.resource_changes[0].change.after.family = "other",
  "source drift": p => p.variables.tooling_sha.value = "5".repeat(40),
  "wrong account": p => p.variables.account_id.value = "111111111111",
  "wrong region": p => p.variables.aws_region.value = "us-east-1",
  "image substitution": p => p.variables.backend_image.value = p.variables.backend_image.value.replace("a".repeat(64), "b".repeat(64)),
  "role escalation": p => p.resource_changes[0].change.after.task_role_arn = "arn:aws:iam::368992683803:role/admin",
  "command override": p => { const c = JSON.parse(p.resource_changes[0].change.after.container_definitions); c[0].command = ["sh"]; p.resource_changes[0].change.after.container_definitions = JSON.stringify(c); },
  "unknown executable": p => p.resource_changes[0].change.after_unknown.container_definitions = true,
  "unclassified field": p => p.resource_changes[0].change.after.new_execution_flag = true,
  "destruction": p => p.resource_changes[0].change.actions = ["delete"],
  "replacement": p => p.resource_changes[0].change.actions = ["create", "delete"],
  "duplicate": p => p.resource_changes.push(structuredClone(p.resource_changes[0])),
  "missing executor": p => p.resource_changes = [],
  "undeclared volume behavior": p => p.resource_changes[0].change.after.volume[0].unreviewed_mount = null,
  "module substitution": p => p.resource_changes[0].module = "module.other",
})) test(`B03 plan rejects ${name}`, () => {
  const plan = fixture(); mutate(plan); assert.throws(() => assertStageBPlan(plan, options));
});

test("B03 accepts structural provider markers while rejecting unknown executable values", () => {
  const p = fixture();
  Object.assign(p.resource_changes[0].change.after_unknown, { runtime_platform: [{}], volume: [{}], container_definitions: false });
  assert.doesNotThrow(() => assertStageBPlan(p, options));
  p.resource_changes[0].change.after_unknown.volume[0].name = true;
  assert.throws(() => assertStageBPlan(p, options));
});
