import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { canonicalizeEcsTaskDefinition, normalizeEcsTaskDefinitionReadback } from "./ecs-task-definition-readback.mjs";

const fixture = JSON.parse(readFileSync(new URL("../../../../../scripts/tests/fixtures/mscqr-backend-47.task-definition.json", import.meta.url)));
const productionCapture = readFileSync(new URL("../../../../../documents/ops/evidence/aws-elasticache-rightsize-inventory-20260603T184059Z/07-ecs-services-and-taskdefs.txt", import.meta.url), "utf8");
const base = () => ({ family: "reviewed", containerDefinitions: [{ name: "reviewed", image: "example@sha256:abc", logConfiguration: { logDriver: "awslogs", options: { "awslogs-group": "/ecs/reviewed" } } }] });
const equivalent = (expected, readback) => canonicalizeEcsTaskDefinition(expected) === canonicalizeEcsTaskDefinition(readback);

test("canonical ECS readback normalizes only the proven AWS default materializations", () => {
  const defaults = [
    ["task enableFaultInjection false", (definition) => { definition.enableFaultInjection = false; }],
    ["container cpu zero", (definition) => { definition.containerDefinitions[0].cpu = 0; }],
    ["empty environment", (definition) => { definition.containerDefinitions[0].environment = []; }],
    ["empty environmentFiles", (definition) => { definition.containerDefinitions[0].environmentFiles = []; }],
    ["empty mountPoints", (definition) => { definition.containerDefinitions[0].mountPoints = []; }],
    ["empty portMappings", (definition) => { definition.containerDefinitions[0].portMappings = []; }],
    ["empty systemControls", (definition) => { definition.containerDefinitions[0].systemControls = []; }],
    ["empty ulimits", (definition) => { definition.containerDefinitions[0].ulimits = []; }],
    ["empty volumesFrom", (definition) => { definition.containerDefinitions[0].volumesFrom = []; }],
    ["empty log secretOptions", (definition) => { definition.containerDefinitions[0].logConfiguration.secretOptions = []; }],
    ["empty placementConstraints", (definition) => { definition.placementConstraints = []; }],
    ["empty volumes", (definition) => { definition.volumes = []; }],
  ];
  for (const [label, materialize] of defaults) {
    const expected = base();
    const readback = base();
    materialize(readback);
    assert.equal(equivalent(expected, readback), true, label);
  }
});

test("fault-injection normalization is symmetric for false and preserves true", () => {
  const omitted = base();
  const falseValue = base(); falseValue.enableFaultInjection = false;
  const trueValue = base(); trueValue.enableFaultInjection = true;
  assert.equal(equivalent(omitted, falseValue), true);
  assert.equal(equivalent(falseValue, omitted), true);
  assert.equal(equivalent(falseValue, falseValue), true);
  assert.equal(equivalent(omitted, trueValue), false);
  assert.equal(equivalent(falseValue, trueValue), false);
  assert.equal(equivalent(trueValue, falseValue), false);
  assert.equal(equivalent(trueValue, omitted), false);
});

test("canonical ECS readback accepts only the empty awslogs secretOptions default", () => {
  const omitted = base();
  const empty = base();
  empty.containerDefinitions[0].logConfiguration.secretOptions = [];
  assert.equal(equivalent(omitted, empty), true);
  assert.equal(equivalent(empty, omitted), true);
  assert.equal(equivalent(omitted, omitted), true);
  assert.equal(equivalent(empty, empty), true);
});

test("independent production-shaped ECS evidence contains and normalizes AWS defaults", () => {
  const readback = fixture.taskDefinition;
  const reviewed = structuredClone(readback);
  delete reviewed.containerDefinitions[0].logConfiguration.secretOptions;
  delete reviewed.enableFaultInjection;
  assert.match(productionCapture, /"enableFaultInjection": false/);
  assert.equal(readback.containerDefinitions[0].logConfiguration.secretOptions.length, 0);
  assert.equal(readback.enableFaultInjection, false);
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

test("canonical ECS readback rejects every non-default executable drift", () => {
  const expected = {
    ...base(),
    networkMode: "awsvpc",
    taskRoleArn: "arn:aws:iam::111122223333:role/task",
    executionRoleArn: "arn:aws:iam::111122223333:role/execution",
    runtimePlatform: { operatingSystemFamily: "LINUX", cpuArchitecture: "X86_64" },
  };
  expected.containerDefinitions[0].command = ["node", "reviewed.mjs"];
  expected.containerDefinitions[0].environment = [{ name: "RELEASE_GIT_SHA", value: "reviewed" }];
  expected.containerDefinitions[0].secrets = [{ name: "DATABASE_URL", valueFrom: "arn:aws:secretsmanager:eu-west-2:111122223333:secret:reviewed" }];
  const changes = [
    ["fault injection true", (definition) => { definition.enableFaultInjection = true; }],
    ["non-empty secretOptions", (definition) => { definition.containerDefinitions[0].logConfiguration.secretOptions = [{ name: "token", valueFrom: "arn:aws:secretsmanager:eu-west-2:111122223333:secret:reviewed" }]; }],
    ["runtime platform", (definition) => { definition.runtimePlatform.cpuArchitecture = "ARM64"; }],
    ["task role", (definition) => { definition.taskRoleArn += "-changed"; }],
    ["execution role", (definition) => { definition.executionRoleArn += "-changed"; }],
    ["image", (definition) => { definition.containerDefinitions[0].image = "example@sha256:changed"; }],
    ["command", (definition) => { definition.containerDefinitions[0].command = ["node", "changed.mjs"]; }],
    ["environment", (definition) => { definition.containerDefinitions[0].environment[0].value = "changed"; }],
    ["secrets", (definition) => { definition.containerDefinitions[0].secrets[0].valueFrom += "-changed"; }],
    ["network mode", (definition) => { definition.networkMode = "bridge"; }],
  ];
  for (const [label, change] of changes) {
    const readback = structuredClone(expected);
    change(readback);
    assert.equal(equivalent(expected, readback), false, label);
  }
});
