import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { canonicalizeEcsTaskDefinition, normalizeEcsTaskDefinitionReadback } from "./ecs-task-definition-readback.mjs";

const fixture = JSON.parse(readFileSync(new URL("../../../../../scripts/tests/fixtures/mscqr-backend-47.task-definition.json", import.meta.url)));
const base = () => ({ family: "reviewed", containerDefinitions: [{ name: "reviewed", image: "example@sha256:abc", logConfiguration: { logDriver: "awslogs", options: { "awslogs-group": "/ecs/reviewed" } } }] });
const equivalent = (expected, readback) => canonicalizeEcsTaskDefinition(expected) === canonicalizeEcsTaskDefinition(readback);

test("canonical ECS readback accepts only the empty awslogs secretOptions default", () => {
  const omitted = base();
  const empty = base();
  empty.containerDefinitions[0].logConfiguration.secretOptions = [];
  assert.equal(equivalent(omitted, empty), true);
  assert.equal(equivalent(empty, omitted), true);
  assert.equal(equivalent(omitted, omitted), true);
  assert.equal(equivalent(empty, empty), true);
});

test("production-shaped ECS fixture normalizes an empty awslogs secretOptions default", () => {
  const readback = fixture.taskDefinition;
  const reviewed = structuredClone(readback);
  delete reviewed.containerDefinitions[0].logConfiguration.secretOptions;
  assert.equal(readback.containerDefinitions[0].logConfiguration.secretOptions.length, 0);
  assert.equal(equivalent(reviewed, readback), true);
});

test("canonical ECS readback preserves non-empty awslogs secretOptions", () => {
  const omitted = base();
  const expected = base();
  expected.containerDefinitions[0].logConfiguration.secretOptions = [{ name: "token", valueFrom: "arn:aws:secretsmanager:eu-west-2:111122223333:secret:reviewed" }];
  const differentValue = structuredClone(expected);
  differentValue.containerDefinitions[0].logConfiguration.secretOptions[0].valueFrom += "-changed";
  const differentName = structuredClone(expected);
  differentName.containerDefinitions[0].logConfiguration.secretOptions[0].name = "other";
  const additionalOption = structuredClone(expected);
  additionalOption.containerDefinitions[0].logConfiguration.secretOptions.push({ name: "second", valueFrom: "arn:aws:secretsmanager:eu-west-2:111122223333:secret:second" });
  const reversed = structuredClone(additionalOption);
  reversed.containerDefinitions[0].logConfiguration.secretOptions.reverse();
  assert.deepEqual(normalizeEcsTaskDefinitionReadback(expected).containerDefinitions[0].logConfiguration.secretOptions, expected.containerDefinitions[0].logConfiguration.secretOptions);
  assert.equal(equivalent(omitted, expected), false);
  assert.equal(equivalent(expected, omitted), false);
  assert.equal(equivalent(expected, differentValue), false);
  assert.equal(equivalent(expected, differentName), false);
  assert.equal(equivalent(expected, additionalOption), false);
  assert.equal(equivalent(additionalOption, reversed), false);
});
