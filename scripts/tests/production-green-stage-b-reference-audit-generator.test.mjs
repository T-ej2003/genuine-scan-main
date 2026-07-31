import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import test from "node:test";
import { assertStageBPlan } from "../plan-production-green-stage-b.mjs";
import { STAGE_B_MODES } from "../aws/production-green-stage-b-contract.mjs";
import {
  createAwsReader,
  generateReferenceAudit,
} from "../aws/generate-production-green-stage-b-reference-audit.mjs";
import { STAGE_B_TASK_DEFINITION_FAMILIES } from "../aws/stage-b-reference-audit-contract.mjs";

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const planSha256 = "a".repeat(64);
const packageChecksum = "b".repeat(64);
const callerArn = "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test-session";
const brokerFunctionArn = "arn:aws:lambda:eu-west-2:368992683803:function:mscqr-production-rls-approval-broker:reviewed";
const clusterArn = "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main";
const oldArnFor = (family) => `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:1`;
const newArnFor = (family) => `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:2`;
const familyForMode = (mode) => mode === "full-rls-application-canary"
  ? STAGE_B_TASK_DEFINITION_FAMILIES['aws_ecs_task_definition.candidate["canary"]']
  : `mscqr-production-full-rls-green-${mode}`;

function makeFixture({ mutatePlan, mutateReader, packageValue = packageChecksum } = {}) {
  const changes = Object.entries(STAGE_B_TASK_DEFINITION_FAMILIES).map(([address, family]) => ({
    address,
    type: "aws_ecs_task_definition",
    change: {
      actions: ["delete", "create"],
      before: { family, arn: oldArnFor(family) },
      after: { family },
      replace_paths: [["container_definitions"]],
    },
  }));
  const plan = { resource_changes: changes };
  mutatePlan?.(plan);
  const planBytes = Buffer.from(JSON.stringify(plan));
  const actualPlanSha = sha256(planBytes);
  const brokerTaskDefinitions = Object.fromEntries(STAGE_B_MODES.map((mode) => {
    const family = familyForMode(mode);
    return [mode, newArnFor(family)];
  }));
  const baseConfig = {
    FunctionArn: brokerFunctionArn,
    Version: "2",
    Environment: {
      Variables: {
        BROKER_TASK_DEFINITIONS_JSON: JSON.stringify(brokerTaskDefinitions),
        BROKER_APPROVAL_EXPECTED_JSON: JSON.stringify({ packageChecksumSha256: packageValue }),
      },
    },
  };
  const reader = {
    getCallerIdentity: () => ({ Arn: callerArn }),
    listServices: () => [],
    describeServices: () => ({ services: [] }),
    listTasks: () => [],
    describeTasks: () => ({ tasks: [] }),
    describeTaskDefinition: (reference) => {
      const family = reference.includes("task-definition/") ? reference.split("task-definition/")[1].replace(/:[0-9]+$/, "") : reference;
      const revision = reference.includes(":1") ? 1 : 2;
      return { taskDefinition: { taskDefinitionArn: `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:${revision}`, family, revision, status: "ACTIVE" } };
    },
    getFunctionConfiguration: () => structuredClone(baseConfig),
  };
  mutateReader?.(reader);
  return {
    plan,
    planBytes,
    planJsonSha256: actualPlanSha,
    reader,
    options: {
      region: "eu-west-2",
      clusterArn,
      brokerFunctionArn,
      expectedPackageChecksumSha256: packageChecksum,
      callerArn,
      auditedAt: "2026-07-31T14:00:00.000Z",
    },
  };
}

function generate(fixture, overrides = {}) {
  return generateReferenceAudit({
    plan: fixture.plan,
    planBytes: fixture.planBytes,
    planJsonSha256: fixture.planJsonSha256,
    reader: fixture.reader,
    ...fixture.options,
    ...overrides,
  });
}

test("exact 12-family allowlist passes and output is deterministic", () => {
  const fixture = makeFixture();
  const first = generate(fixture);
  const second = generate(fixture);
  assert.equal(first.oldTaskDefinitions.length, 12);
  assert.deepEqual([...first.oldTaskDefinitions.map((item) => item.family)].sort(), [...Object.values(STAGE_B_TASK_DEFINITION_FAMILIES)].sort());
  assert.deepEqual(first, second);
});

test("unknown 13th family fails closed", () => {
  const fixture = makeFixture({ mutatePlan: (plan) => plan.resource_changes.push({
    address: 'aws_ecs_task_definition.other["unknown"]',
    type: "aws_ecs_task_definition",
    change: { actions: ["create"], after: { family: "mscqr-production-unknown" }, before: null },
  }) });
  assert.throws(() => generate(fixture), /unknown Stage B task-definition family/);
});

test("missing expected family fails closed", () => {
  const missing = "mscqr-production-full-rls-green-read-only-canary";
  const fixture = makeFixture({ mutateReader: (reader) => {
    const original = reader.describeTaskDefinition;
    reader.describeTaskDefinition = (reference) => reference === missing ? {} : original(reference);
  } });
  assert.throws(() => generate(fixture), /response is malformed/);
});

test("duplicate family fails closed", () => {
  const fixture = makeFixture({ mutatePlan: (plan) => plan.resource_changes.push(structuredClone(plan.resource_changes[0])) });
  assert.throws(() => generate(fixture), /duplicate Stage B task-definition family/);
});

for (const [label, mutateReader, expected] of [
  ["service", (reader, oldArn) => { reader.listServices = () => ["arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/stage-b"]; reader.describeServices = () => ({ services: [{ serviceName: "stage-b", taskDefinition: oldArn, runningCount: 0, pendingCount: 0, status: "ACTIVE" }] }); }, /Superseded task definition remains referenced/],
  ["running task", (reader, oldArn) => { reader.listTasks = (status) => status === "RUNNING" ? ["arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/run"] : []; reader.describeTasks = () => ({ tasks: [{ taskArn: "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/run", taskDefinitionArn: oldArn, lastStatus: "RUNNING", desiredStatus: "RUNNING", group: "service:stage-b" }] }); }, /Superseded task definition remains referenced/],
  ["pending task", (reader, oldArn) => { reader.listTasks = (status) => status === "PENDING" ? ["arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/pending"] : []; reader.describeTasks = () => ({ tasks: [{ taskArn: "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/pending", taskDefinitionArn: oldArn, lastStatus: "PENDING", desiredStatus: "PENDING", group: "service:stage-b" }] }); }, /Superseded task definition remains referenced/],
]) {
  test(`${label} reference to an old revision fails`, () => {
    const oldArn = oldArnFor(Object.values(STAGE_B_TASK_DEFINITION_FAMILIES)[0]);
    const fixture = makeFixture({ mutateReader: (reader) => mutateReader(reader, oldArn) });
    assert.throws(() => generate(fixture), expected);
  });
}

test("zero service, running-task, and pending-task references passes", () => {
  const audit = generate(makeFixture());
  assert.deepEqual(audit.services, []);
  assert.deepEqual(audit.runningTasks, []);
  assert.deepEqual(audit.pendingTasks, []);
  assert.equal(audit.allOldRevisionsUnreferenced, true);
});

test("missing and stale plan SHA values fail closed", () => {
  const fixture = makeFixture();
  assert.throws(() => generate(fixture, { planJsonSha256: "" }), /missing or malformed/);
  assert.throws(() => generate(fixture, { planJsonSha256: "0".repeat(64) }), /does not match/);
});

test("broker package checksum mismatch fails closed", () => {
  const fixture = makeFixture({ packageValue: "c".repeat(64) });
  assert.throws(() => generate(fixture), /package checksum/);
});

test("broker references to superseded revisions and unknown families fail closed", () => {
  const fixture = makeFixture({ mutateReader: (reader) => {
    const original = reader.getFunctionConfiguration;
    reader.getFunctionConfiguration = () => {
      const config = original();
      const variables = config.Environment.Variables;
      const taskDefinitions = JSON.parse(variables.BROKER_TASK_DEFINITIONS_JSON);
      taskDefinitions["full-rls-admin-bootstrap"] = oldArnFor(familyForMode("full-rls-admin-bootstrap"));
      variables.BROKER_TASK_DEFINITIONS_JSON = JSON.stringify(taskDefinitions);
      return config;
    };
  } });
  assert.throws(() => generate(fixture), /superseded task definition/);
  const unknown = makeFixture({ mutateReader: (reader) => {
    const original = reader.getFunctionConfiguration;
    reader.getFunctionConfiguration = () => {
      const config = original();
      const variables = config.Environment.Variables;
      const taskDefinitions = JSON.parse(variables.BROKER_TASK_DEFINITIONS_JSON);
      taskDefinitions["full-rls-admin-bootstrap"] = newArnFor("mscqr-production-unknown");
      variables.BROKER_TASK_DEFINITIONS_JSON = JSON.stringify(taskDefinitions);
      return config;
    };
  } });
  assert.throws(() => generate(unknown), /unexpected/);
});

test("malformed AWS responses fail closed", () => {
  const fixture = makeFixture({ mutateReader: (reader) => { reader.listTasks = () => null; } });
  assert.throws(() => generate(fixture), /task listing is malformed/);
});

test("generated audit is accepted by the existing Stage B plan validator", () => {
  const fixture = makeFixture();
  const audit = generate(fixture);
  const auditBytes = Buffer.from(JSON.stringify(audit));
  assert.doesNotThrow(() => assertStageBPlan(fixture.plan, {
    referenceAudit: audit,
    referenceAuditBytes: auditBytes,
    referenceAuditSha256: sha256(auditBytes),
    planJsonBytes: fixture.planBytes,
    planJsonSha256: fixture.planJsonSha256,
  }));
});

test("AWS reader uses argv arrays and only read-only commands", () => {
  const calls = [];
  const responses = {
    "sts get-caller-identity": { Arn: callerArn },
    "ecs list-services": { serviceArns: [] },
    "ecs describe-services": { services: [] },
    "ecs list-tasks": { taskArns: [] },
    "ecs describe-tasks": { tasks: [] },
    "ecs describe-task-definition": { taskDefinition: { taskDefinitionArn: oldArnFor("x"), family: "x", revision: 1, status: "ACTIVE" } },
    "lambda get-function-configuration": {},
  };
  const reader = createAwsReader({
    region: "eu-west-2",
    clusterArn,
    run: (args) => { calls.push(args); return JSON.stringify(responses[args.slice(0, 2).join(" ")] || {}); },
  });
  reader.getCallerIdentity(); reader.listServices(); reader.describeServices([]); reader.listTasks("RUNNING"); reader.describeTasks([]); reader.describeTaskDefinition("safe"); reader.getFunctionConfiguration(brokerFunctionArn);
  assert.deepEqual(new Set(calls.map((args) => args.slice(0, 2).join(" "))), new Set(Object.keys(responses)));
  assert.ok(calls.every((args) => args.every((value) => !/[;&|`$()]/.test(value))));
  const source = fs.readFileSync("scripts/aws/generate-production-green-stage-b-reference-audit.mjs", "utf8");
  assert.equal(source.includes("shell: true"), false);
  assert.equal(source.includes("child_process.exec("), false);
  assert.doesNotMatch(source, /iam\s+(?:put|create|delete|attach|detach)|ecs\s+(?:run|stop|update|delete|register)|lambda\s+(?:update|publish|delete|invoke)/);
  const injectedCluster = `${clusterArn};touch /tmp/should-not-run`;
  const injectedCalls = [];
  createAwsReader({
    region: "eu-west-2",
    clusterArn: injectedCluster,
    run: (args) => { injectedCalls.push(args); return JSON.stringify({ serviceArns: [] }); },
  }).listServices();
  assert.equal(injectedCalls[0].includes(injectedCluster), true);
  assert.equal(injectedCalls[0].includes("touch"), false);
});
