import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { classifyStageBPlan } from "../aws/stage-b-deployment-contract.mjs";

const fixturePath = "scripts/tests/fixtures/production-green-stage-b-production-shaped.plan.json";
const fixture = JSON.parse(fs.readFileSync(fixturePath, "utf8"));

test("production-shaped Stage B plan is fully classified with zero destroys", () => {
  const result = classifyStageBPlan(fixture, { strict: false });
  assert.deepEqual(result.actionCounts, { "no-op": 58, create: 12, update: 3 });
  assert.deepEqual(result.unclassifiedResources, []);
});

test("unknown resources fail before apply classification", () => {
  const plan = structuredClone(fixture);
  plan.resource_changes.push(
    { address: "aws_iam_policy.other", type: "aws_iam_policy", change: { actions: ["update"], before: {}, after: {} } },
    { address: "aws_ecs_service.other", type: "aws_ecs_service", change: { actions: ["update"], before: {}, after: {} } },
  );
  assert.throws(() => classifyStageBPlan(plan, { strict: false }), (error) => /no exact contract layer/.test(error.message) && /aws_ecs_service\.other/.test(error.message));
});

test("destructive actions fail closed", () => {
  const plan = structuredClone(fixture);
  plan.resource_changes.find((change) => change.address === "aws_iam_policy.broker").change.actions = ["delete"];
  assert.throws(() => classifyStageBPlan(plan, { strict: false }), /unsupported/);
});

test("broker policy and attachment are exact contract entries", () => {
  const policy = fixture.resource_changes.find((change) => change.address === "aws_iam_policy.broker");
  const attachment = fixture.resource_changes.find((change) => change.address === "aws_iam_role_policy_attachment.broker");
  assert.equal(policy.type, "aws_iam_policy");
  assert.deepEqual(policy.change.actions, ["update"]);
  assert.equal(attachment.type, "aws_iam_role_policy_attachment");
  assert.deepEqual(attachment.change.actions, ["no-op"]);
});
