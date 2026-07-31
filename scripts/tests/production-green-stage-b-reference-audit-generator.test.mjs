import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import test from "node:test";
import { assertStageBPlan } from "../plan-production-green-stage-b.mjs";
import { STAGE_B_MODES } from "../aws/production-green-stage-b-contract.mjs";
import {
  createAwsReader,
  generateReferenceAudit,
  batch,
  parseCli,
} from "../aws/generate-production-green-stage-b-reference-audit.mjs";
import {
  STAGE_B_REFERENCE_AUDIT_CLOCK_SKEW_MS,
  STAGE_B_REFERENCE_AUDIT_MAX_AGE_MS,
  STAGE_B_TASK_DEFINITION_FAMILIES,
} from "../aws/stage-b-reference-audit-contract.mjs";

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const planSha256 = "a".repeat(64);
const packageChecksum = "b".repeat(64);
const callerArn = "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test-session";
const brokerFunctionArn = "arn:aws:lambda:eu-west-2:368992683803:function:mscqr-production-rls-approval-broker:reviewed";
const clusterArn = "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main";
const now = new Date("2026-07-31T14:05:00.000Z");
const oldArnFor = (family) => `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:1`;
const newArnFor = (family) => `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:2`;
const backendAddress = 'aws_ecs_task_definition.candidate["backend"]';
const readOnlyCanaryAddress = 'aws_ecs_task_definition.candidate["read_only_canary"]';
const readOnlyCanaryFamily = STAGE_B_TASK_DEFINITION_FAMILIES[readOnlyCanaryAddress];
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
    describeServices: () => ({ services: [], failures: [] }),
    listTasks: () => [],
    describeTasks: () => ({ tasks: [], failures: [] }),
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
      now,
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

function makeCreateOnlyFixture({ mutatePlan, mutateReader } = {}) {
  return makeFixture({
    mutatePlan: (plan) => {
      const change = plan.resource_changes.find((item) => item.address === readOnlyCanaryAddress);
      change.change.actions = ["create"];
      change.change.before = null;
      delete change.change.replace_paths;
      mutatePlan?.(plan);
    },
    mutateReader,
  });
}

function makeMixedFixture({ mutatePlan, mutateReader } = {}) {
  return makeCreateOnlyFixture({
    mutatePlan: (plan) => {
      const change = plan.resource_changes.find((item) => item.address === backendAddress);
      change.change.actions = ["no-op"];
      mutatePlan?.(plan);
    },
    mutateReader,
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
  const fixture = makeFixture({ mutatePlan: (plan) => {
    plan.resource_changes = plan.resource_changes.filter((item) => item.address !== readOnlyCanaryAddress);
  } });
  assert.throws(() => generate(fixture), /missing exact Stage B task-definition families/);
});

test("duplicate family fails closed", () => {
  const fixture = makeFixture({ mutatePlan: (plan) => plan.resource_changes.push(structuredClone(plan.resource_changes[0])) });
  assert.throws(() => generate(fixture), /duplicate Stage B task-definition family/);
});

for (const [label, mutateReader, expected] of [
  ["service", (reader, oldArn) => { reader.listServices = () => ["arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/stage-b"]; reader.describeServices = () => ({ services: [{ serviceArn: "arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/stage-b", serviceName: "stage-b", taskDefinition: oldArn, runningCount: 0, pendingCount: 0, status: "ACTIVE" }], failures: [] }); }, /Superseded task definition remains referenced/],
  ["running task", (reader, oldArn) => { reader.listTasks = (status) => status === "RUNNING" ? ["arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/run"] : []; reader.describeTasks = () => ({ tasks: [{ taskArn: "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/run", taskDefinitionArn: oldArn, lastStatus: "RUNNING", desiredStatus: "RUNNING", group: "service:stage-b" }], failures: [] }); }, /Superseded task definition remains referenced/],
  ["pending task", (reader, oldArn) => { reader.listTasks = (status) => status === "PENDING" ? ["arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/pending"] : []; reader.describeTasks = () => ({ tasks: [{ taskArn: "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/pending", taskDefinitionArn: oldArn, lastStatus: "PENDING", desiredStatus: "PENDING", group: "service:stage-b" }], failures: [] }); }, /Superseded task definition remains referenced/],
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

test("allowlisted create-only family passes and is recorded explicitly", () => {
  const audit = generate(makeCreateOnlyFixture());
  assert.equal(audit.oldTaskDefinitions.length, 11);
  assert.deepEqual(audit.createOnlyTaskDefinitions, [{
    terraformAddress: readOnlyCanaryAddress,
    family: readOnlyCanaryFamily,
    proposedFamily: readOnlyCanaryFamily,
    classification: "create-only",
    priorTaskDefinitionArn: null,
    serviceReferences: [],
    runningTaskReferences: [],
    pendingTaskReferences: [],
    brokerReferenceModes: [],
  }]);
});

test("create-only family is not sent to DescribeTaskDefinition", () => {
  const fixture = makeCreateOnlyFixture();
  const calls = [];
  const original = fixture.reader.describeTaskDefinition;
  fixture.reader.describeTaskDefinition = (reference) => {
    calls.push(reference);
    return original(reference);
  };
  generate(fixture);
  assert.equal(calls.length, 11);
  assert.equal(calls.some((reference) => reference.includes(readOnlyCanaryFamily)), false);
});

test("create-only family with an unexpected prior ARN fails closed", () => {
  const fixture = makeCreateOnlyFixture({ mutatePlan: (plan) => {
    const change = plan.resource_changes.find((item) => item.address === readOnlyCanaryAddress);
    change.change.before = { family: readOnlyCanaryFamily, arn: oldArnFor(readOnlyCanaryFamily) };
  } });
  assert.throws(() => generate(fixture), /create-only task definition unexpectedly has a prior ARN/);
});

test("rollover family missing its prior ARN fails closed", () => {
  const fixture = makeFixture({ mutatePlan: (plan) => {
    const change = plan.resource_changes.find((item) => item.address !== readOnlyCanaryAddress);
    change.change.before = { family: change.change.before.family };
  } });
  assert.throws(() => generate(fixture), /rollover is missing its prior task-definition ARN/);
});

test("the 11 rollover live-reference checks remain enforced with a create-only family", () => {
  const rolloverFamily = Object.values(STAGE_B_TASK_DEFINITION_FAMILIES).find((family) => family !== readOnlyCanaryFamily);
  const fixture = makeCreateOnlyFixture({ mutateReader: (reader) => {
    reader.listServices = () => [serviceArnFor(0)];
    reader.describeServices = () => ({ services: [serviceRecord(serviceArnFor(0), 0, oldArnFor(rolloverFamily))], failures: [] });
  } });
  assert.throws(() => generate(fixture), /Superseded task definition remains referenced/);
});

test("create-only family live references fail closed", () => {
  const fixture = makeCreateOnlyFixture({ mutateReader: (reader) => {
    reader.listServices = () => [serviceArnFor(0)];
    reader.describeServices = () => ({ services: [serviceRecord(serviceArnFor(0), 0, newArnFor(readOnlyCanaryFamily))], failures: [] });
  } });
  assert.throws(() => generate(fixture), /Create-only task-definition family remains referenced/);
});

test("mixed rollover, create-only, and no-op plan classifications pass", () => {
  const audit = generate(makeMixedFixture());
  assert.equal(audit.oldTaskDefinitions.length, 10);
  assert.equal(audit.createOnlyTaskDefinitions.length, 1);
  assert.deepEqual(audit.noOpTaskDefinitions, [{
    terraformAddress: backendAddress,
    family: STAGE_B_TASK_DEFINITION_FAMILIES[backendAddress],
    proposedFamily: STAGE_B_TASK_DEFINITION_FAMILIES[backendAddress],
    classification: "no-op",
    priorTaskDefinitionArn: oldArnFor(STAGE_B_TASK_DEFINITION_FAMILIES[backendAddress]),
    serviceReferences: [],
    runningTaskReferences: [],
    pendingTaskReferences: [],
    brokerReferenceModes: [],
  }]);
});

test("no-op with a valid prior ARN passes", () => {
  assert.doesNotThrow(() => generate(makeMixedFixture()));
});

test("no-op without a prior ARN fails closed", () => {
  const fixture = makeMixedFixture({ mutatePlan: (plan) => {
    const change = plan.resource_changes.find((item) => item.address === backendAddress);
    change.change.before = { family: change.change.before.family };
  } });
  assert.throws(() => generate(fixture), /no-op task definition is missing its prior ARN/);
});

test("no-op family mismatch fails closed", () => {
  const fixture = makeMixedFixture({ mutatePlan: (plan) => {
    const change = plan.resource_changes.find((item) => item.address === backendAddress);
    change.change.before.family = readOnlyCanaryFamily;
  } });
  assert.throws(() => generate(fixture), /no-op task-definition family mismatch/);
});

test("batching is stable, non-mutating, bounded, and empty-safe", () => {
  const input = [1, 2, 3, 4, 5];
  assert.deepEqual(batch(input, 2), [[1, 2], [3, 4], [5]]);
  assert.deepEqual(input, [1, 2, 3, 4, 5]);
  assert.deepEqual(batch([], 10), []);
  assert.throws(() => batch(input, 0), /positive integer/);
  assert.throws(() => batch(input, 1.5), /positive integer/);
});

test("generator enforces current, maximum-age, and future-skew timestamps", () => {
  const fixture = makeFixture();
  assert.doesNotThrow(() => generate(fixture, { auditedAt: new Date(now.getTime() - STAGE_B_REFERENCE_AUDIT_MAX_AGE_MS).toISOString() }));
  assert.doesNotThrow(() => generate(fixture, { auditedAt: new Date(now.getTime() + STAGE_B_REFERENCE_AUDIT_CLOCK_SKEW_MS).toISOString() }));
  assert.throws(() => generate(fixture, { auditedAt: new Date(now.getTime() - STAGE_B_REFERENCE_AUDIT_MAX_AGE_MS - 1).toISOString() }), /expired/);
  assert.throws(() => generate(fixture, { auditedAt: new Date(now.getTime() + STAGE_B_REFERENCE_AUDIT_CLOCK_SKEW_MS + 1).toISOString() }), /future/);
  assert.throws(() => generate(fixture, { auditedAt: "not-a-timestamp" }), /malformed/);
  const staleCliValue = parseCli([
    "--plan-json", "/tmp/plan.json", "--plan-sha256", planSha256, "--output", "/tmp/audit.json",
    "--region", "eu-west-2", "--cluster-arn", clusterArn, "--broker-function", brokerFunctionArn,
    "--expected-package-checksum-sha256", packageChecksum, "--audited-at", "2026-07-31T13:00:00.000Z",
  ]).auditedAt;
  assert.throws(() => generate(fixture, { auditedAt: staleCliValue }), /expired/);
});

const serviceArnFor = (index) => `arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/stage-b-${index}`;
const taskArnFor = (status, index) => `arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/${status.toLowerCase()}-${index}`;
const currentTaskDefinition = newArnFor(Object.values(STAGE_B_TASK_DEFINITION_FAMILIES)[0]);
const serviceRecord = (arn, index, taskDefinition = currentTaskDefinition) => ({ serviceArn: arn, serviceName: `stage-b-${index}`, taskDefinition, runningCount: 0, pendingCount: 0, status: "ACTIVE" });
const taskRecord = (arn, status, taskDefinitionArn = currentTaskDefinition) => ({ taskArn: arn, taskDefinitionArn, lastStatus: status, desiredStatus: status, group: "service:stage-b" });

test("DescribeServices uses batches of at most 10 and accepts an exact complete multi-batch response", () => {
  const fixture = makeFixture();
  const listed = Array.from({ length: 25 }, (_, index) => serviceArnFor(index));
  const calls = [];
  fixture.reader.listServices = () => listed;
  fixture.reader.describeServices = (arns) => {
    calls.push([...arns]);
    return { services: arns.map((arn, index) => serviceRecord(arn, listed.indexOf(arn) + index)), failures: [] };
  };
  const audit = generate(fixture);
  assert.deepEqual(calls.map((items) => items.length), [10, 10, 5]);
  assert.equal(audit.services.length, 25);
});

test("empty service list makes no DescribeServices call", () => {
  const fixture = makeFixture();
  fixture.reader.describeServices = () => { throw new Error("must not be called"); };
  assert.doesNotThrow(() => generate(fixture));
});

for (const [name, response, expected] of [
  ["partial", { services: [serviceRecord(serviceArnFor(0), 0)], failures: [] }, /incomplete/],
  ["non-empty failures", { services: [], failures: [{ arn: serviceArnFor(0), reason: "MISSING" }] }, /contains failures/],
  ["malformed failures", { services: [], failures: [{}] }, /malformed failure/],
  ["duplicate", { services: [serviceRecord(serviceArnFor(0), 0), serviceRecord(serviceArnFor(0), 0)], failures: [] }, /duplicate service/],
  ["unexpected", { services: [serviceRecord(serviceArnFor(9), 9)], failures: [] }, /unexpected service/],
  ["missing required data", { services: [{ serviceArn: serviceArnFor(0), serviceName: "stage-b-0" }], failures: [] }, /incomplete/],
]) {
  test(`DescribeServices rejects ${name} responses`, () => {
    const fixture = makeFixture();
    fixture.reader.listServices = () => name === "partial" ? [serviceArnFor(0), serviceArnFor(1)] : [serviceArnFor(0)];
    fixture.reader.describeServices = () => response;
    assert.throws(() => generate(fixture), expected);
  });
}

test("DescribeTasks uses batches of at most 100 for running and pending tasks", () => {
  const fixture = makeFixture();
  const listed = {
    RUNNING: Array.from({ length: 101 }, (_, index) => taskArnFor("RUNNING", index)),
    PENDING: Array.from({ length: 101 }, (_, index) => taskArnFor("PENDING", index)),
  };
  const calls = { RUNNING: [], PENDING: [] };
  fixture.reader.listTasks = (status) => listed[status];
  fixture.reader.describeTasks = (arns) => {
    const status = arns[0].includes("running") ? "RUNNING" : "PENDING";
    calls[status].push([...arns]);
    return { tasks: arns.map((arn) => taskRecord(arn, status)), failures: [] };
  };
  const audit = generate(fixture);
  assert.deepEqual(calls.RUNNING.map((items) => items.length), [100, 1]);
  assert.deepEqual(calls.PENDING.map((items) => items.length), [100, 1]);
  assert.equal(audit.runningTasks.length, 101);
  assert.equal(audit.pendingTasks.length, 101);
});

test("empty task lists make no DescribeTasks calls", () => {
  const fixture = makeFixture();
  fixture.reader.describeTasks = () => { throw new Error("must not be called"); };
  assert.doesNotThrow(() => generate(fixture));
});

for (const [name, response, expected] of [
  ["partial", { tasks: [], failures: [] }, /incomplete/],
  ["non-empty failures", { tasks: [], failures: [{ arn: taskArnFor("RUNNING", 0), reason: "MISSING" }] }, /contains failures/],
  ["malformed failures", { tasks: [], failures: [{}] }, /malformed failure/],
  ["duplicate", { tasks: [taskRecord(taskArnFor("RUNNING", 0), "RUNNING"), taskRecord(taskArnFor("RUNNING", 0), "RUNNING")], failures: [] }, /duplicate task/],
  ["unexpected", { tasks: [taskRecord(taskArnFor("RUNNING", 1), "RUNNING")], failures: [] }, /unexpected task/],
  ["malformed task-definition reference", { tasks: [taskRecord(taskArnFor("RUNNING", 0), "RUNNING", "not-an-arn")], failures: [] }, /not a valid ECS task-definition ARN/],
]) {
  test(`DescribeTasks rejects ${name} responses`, () => {
    const fixture = makeFixture();
    fixture.reader.listTasks = (status) => status === "RUNNING" ? [taskArnFor("RUNNING", 0)] : [];
    fixture.reader.describeTasks = () => response;
    assert.throws(() => generate(fixture), expected);
  });
}

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
    now,
  }));
});

test("create-only audit is accepted by the existing Stage B plan validator", () => {
  const fixture = makeCreateOnlyFixture();
  const audit = generate(fixture);
  const auditBytes = Buffer.from(JSON.stringify(audit));
  assert.doesNotThrow(() => assertStageBPlan(fixture.plan, {
    referenceAudit: audit,
    referenceAuditBytes: auditBytes,
    referenceAuditSha256: sha256(auditBytes),
    planJsonBytes: fixture.planBytes,
    planJsonSha256: fixture.planJsonSha256,
    now,
  }));
});

test("AWS reader uses argv arrays and only read-only commands", () => {
  const calls = [];
  const responses = {
    "sts get-caller-identity": { Arn: callerArn },
    "ecs list-services": { serviceArns: [] },
    "ecs describe-services": { services: [], failures: [] },
    "ecs list-tasks": { taskArns: [] },
    "ecs describe-tasks": { tasks: [], failures: [] },
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
