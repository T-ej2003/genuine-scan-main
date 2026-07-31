import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
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
  assertStageBAtomicBrokerPlan,
  assertStageBAtomicBrokerPackagePlan,
  assertStageBBrokerTaskDefinitionMapping,
  STAGE_B_REFERENCE_AUDIT_CLOCK_SKEW_MS,
  STAGE_B_REFERENCE_AUDIT_MAX_AGE_MS,
  STAGE_B_TASK_DEFINITION_FAMILIES,
} from "../aws/stage-b-reference-audit-contract.mjs";

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const planSha256 = "a".repeat(64);
const packageBytes = Buffer.from("stage-b-broker-zip-fixture-v1");
const packageChecksum = sha256(Buffer.from("stage-b-full-rls-release-package-fixture-v1"));
const brokerZipFileSha256 = sha256(packageBytes);
const packageSourceCodeHash = crypto.createHash("sha256").update(packageBytes).digest("base64");
const packageDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-stage-b-audit-"));
const packagePath = path.join(packageDirectory, "broker.zip");
fs.writeFileSync(packagePath, packageBytes, { mode: 0o600 });
const callerArn = "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test-session";
const brokerFunctionArn = "arn:aws:lambda:eu-west-2:368992683803:function:mscqr-production-rls-approval-broker:reviewed";
const clusterArn = "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main";
const now = new Date("2026-07-31T14:05:00.000Z");
const terraformConfigurationSource = fs.readFileSync("infra/aws/terraform/production-green-stage-b/main.tf", "utf8");
const oldArnFor = (family) => `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:1`;
const newArnFor = (family) => `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:2`;
const backendAddress = 'aws_ecs_task_definition.candidate["backend"]';
const canaryAddress = 'aws_ecs_task_definition.candidate["canary"]';
const readOnlyCanaryAddress = 'aws_ecs_task_definition.candidate["read_only_canary"]';
const executorCollectionAddress = "aws_ecs_task_definition.executor";
const readOnlyCanaryFamily = STAGE_B_TASK_DEFINITION_FAMILIES[readOnlyCanaryAddress];
const executorAddressForMode = (mode) => `${executorCollectionAddress}["${mode}"]`;
const taskDefinitionAddressForMode = (mode) => mode === "full-rls-application-canary" ? canaryAddress : executorAddressForMode(mode);
const familyForMode = (mode) => mode === "full-rls-application-canary"
  ? STAGE_B_TASK_DEFINITION_FAMILIES['aws_ecs_task_definition.candidate["canary"]']
  : `mscqr-production-full-rls-green-${mode}`;

function makeFixture({ mutatePlan, mutateReader, packageValue = packageChecksum, terraformConfiguration = terraformConfigurationSource } = {}) {
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
  const plan = {
    variables: {
      package_checksum_sha256: { value: packageChecksum },
      broker_package_path: { value: packagePath },
    },
    resource_changes: changes,
  };
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
      terraformConfiguration,
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

function validateBrokerPlan(fixture, audit) {
  const auditBytes = Buffer.from(JSON.stringify(audit));
  assert.doesNotThrow(() => assertStageBPlan(fixture.plan, {
    referenceAudit: audit,
    referenceAuditBytes: auditBytes,
    referenceAuditSha256: sha256(auditBytes),
    planJsonBytes: fixture.planBytes,
    planJsonSha256: fixture.planJsonSha256,
    terraformConfiguration: fixture.options.terraformConfiguration,
    now,
  }));
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

function addBrokerAtomicPlanContract(plan, taskDefinitionAddress = canaryAddress, relevantAddress = taskDefinitionAddress, { omitExecutorCollectionDependency = false } = {}) {
  const executorTarget = taskDefinitionAddress.startsWith(`${executorCollectionAddress}[`);
  plan.configuration = {
    root_module: {
      resources: [
        {
          address: "aws_lambda_function.broker",
          type: "aws_lambda_function",
          expressions: {
            environment: [{ variables: { references: ["local.broker_task_definition_arns", "local.broker_approval_expected"] } }],
            filename: { references: ["var.broker_package_path"] },
            source_code_hash: { references: ["var.broker_package_path"] },
          },
        },
        {
          address: executorCollectionAddress,
          type: "aws_ecs_task_definition",
          for_each_expression: { references: ["local.executor_definitions"] },
          expressions: { family: { references: ["each.value.family"] } },
        },
        {
          address: canaryAddress,
          type: "aws_ecs_task_definition",
        },
      ],
    },
  };
  plan.planned_values = {
    root_module: {
      resources: Object.entries(STAGE_B_TASK_DEFINITION_FAMILIES).map(([address, family]) => ({
        address,
        type: "aws_ecs_task_definition",
        index: address.match(/\["([^"]+)"\]$/)?.[1],
        values: { family },
        identity: { family },
      })),
    },
  };
  plan.relevant_attributes = executorTarget && !omitExecutorCollectionDependency
    ? [{ resource: executorCollectionAddress, attribute: [] }]
    : [{ resource: relevantAddress, attribute: ["arn"] }];
}

function makeAtomicBrokerFixture({ mode = "full-rls-application-canary", packageValue = packageChecksum, brokerActions = ["update"], includeBrokerChange = true, taskDefinitionAddress = taskDefinitionAddressForMode(mode), relevantAddress = taskDefinitionAddress, omitExecutorCollectionDependency = false, terraformConfiguration = terraformConfigurationSource, mutatePlan, mutateReader } = {}) {
  return makeFixture({
    packageValue,
    terraformConfiguration,
    mutatePlan: (plan) => {
      addBrokerAtomicPlanContract(plan, taskDefinitionAddress, relevantAddress, { omitExecutorCollectionDependency });
      if (includeBrokerChange) plan.resource_changes.push({
        address: "aws_lambda_function.broker",
        type: "aws_lambda_function",
        change: {
          actions: brokerActions,
          before: {
            filename: "/private/tmp/old-broker.zip",
            source_code_hash: "old-source-code-hash",
            environment: [{ variables: { BROKER_APPROVAL_EXPECTED_JSON: JSON.stringify({ packageChecksumSha256: packageValue }) } }],
          },
          after: {
            filename: packagePath,
            source_code_hash: packageSourceCodeHash,
            ...(JSON.stringify(brokerActions) === JSON.stringify(["create"])
              ? { environment: [{ variables: { BROKER_APPROVAL_EXPECTED_JSON: JSON.stringify({ packageChecksumSha256: packageChecksum }) } }] }
              : {}),
          },
          after_unknown: { environment: [{ variables: true }] },
        },
      });
      mutatePlan?.(plan);
    },
    mutateReader: (reader) => {
      const original = reader.getFunctionConfiguration;
      reader.getFunctionConfiguration = () => {
        const config = original();
        const variables = config.Environment.Variables;
        const taskDefinitions = JSON.parse(variables.BROKER_TASK_DEFINITIONS_JSON);
        taskDefinitions[mode] = oldArnFor(familyForMode(mode));
        variables.BROKER_TASK_DEFINITIONS_JSON = JSON.stringify(taskDefinitions);
        return config;
      };
      mutateReader?.(reader);
    },
  });
}

function makeInitialBrokerCreateFixture({ mutatePlan } = {}) {
  return makeAtomicBrokerFixture({
    brokerActions: ["create"],
    mutatePlan: (plan) => {
      for (const change of plan.resource_changes.filter((item) => item.type === "aws_ecs_task_definition")) {
        change.change.actions = ["create"];
        change.change.before = null;
        delete change.change.replace_paths;
      }
      mutatePlan?.(plan);
    },
  });
}

function withBrokerMapping(mapping) {
  return terraformConfigurationSource.replace(
    /  broker_task_definition_arns = merge\([\s\S]*?\n  \)\n  broker_template_hashes/,
    `  broker_task_definition_arns = ${mapping}\n  broker_template_hashes`,
  );
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
  assert.throws(() => generate(fixture), /Stale broker release checksum requires a planned broker update/);
});

test("valid atomic broker package checksum transition passes and is recorded", () => {
  const staleChecksum = "c".repeat(64);
  const fixture = makeAtomicBrokerFixture({ packageValue: staleChecksum });
  const audit = generate(fixture);
  assert.equal(audit.broker.releasePackageChecksumSha256, staleChecksum);
  assert.notEqual(audit.broker.brokerZipFileSha256, audit.broker.plannedReleasePackageChecksumSha256);
  assert.deepEqual(audit.plannedAtomicPackageChecksumTransition, {
    brokerTerraformAddress: "aws_lambda_function.broker",
    brokerEnvironmentReference: "local.broker_approval_expected",
    packageInputReference: "var.package_checksum_sha256",
    packagePath,
    liveReleasePackageChecksumSha256: staleChecksum,
    planBeforeReleasePackageChecksumSha256: staleChecksum,
    plannedReleasePackageChecksumSha256: packageChecksum,
    brokerZipFileSha256,
    plannedBrokerSourceCodeHashBase64: packageSourceCodeHash,
    planJsonSha256: fixture.planJsonSha256,
    transition: "plannedAtomicPackageChecksumTransition",
  });
  const auditBytes = Buffer.from(JSON.stringify(audit));
  assert.doesNotThrow(() => assertStageBPlan(fixture.plan, {
    referenceAudit: audit,
    referenceAuditBytes: auditBytes,
    referenceAuditSha256: sha256(auditBytes),
    planJsonBytes: fixture.planBytes,
    planJsonSha256: fixture.planJsonSha256,
    terraformConfiguration: fixture.options.terraformConfiguration,
    now,
  }));
});

test("live checksum already matching the planned checksum passes without a transition", () => {
  const audit = generate(makeAtomicBrokerFixture());
  assert.equal(audit.plannedAtomicPackageChecksumTransition, null);
});

test("broker no-op with a stale checksum fails closed", () => {
  assert.throws(
    () => generate(makeAtomicBrokerFixture({ packageValue: "c".repeat(64), brokerActions: ["no-op"] })),
    /broker actions/,
  );
});

test("broker update with the wrong planned checksum fails closed", () => {
  assert.throws(
    () => generate(makeAtomicBrokerFixture({
      packageValue: "c".repeat(64),
      mutatePlan: (plan) => { plan.variables.package_checksum_sha256.value = "d".repeat(64); },
    })),
    /checksum does not match the exact plan input|package bytes|source_code_hash/,
  );
});

test("broker update with a missing planned checksum fails closed", () => {
  assert.throws(
    () => generate(makeAtomicBrokerFixture({
      packageValue: "c".repeat(64),
      mutatePlan: (plan) => { delete plan.variables.package_checksum_sha256; },
    })),
    /checksum is missing or malformed|exact plan input/,
  );
});

test("broker update with the wrong source_code_hash fails closed", () => {
  assert.throws(
    () => generate(makeAtomicBrokerFixture({
      packageValue: "c".repeat(64),
      mutatePlan: (plan) => {
        plan.resource_changes.find((item) => item.address === "aws_lambda_function.broker").change.after.source_code_hash = "wrong";
      },
    })),
    /source_code_hash/,
  );
});

test("broker update with package bytes that do not match the checksum fails closed", () => {
  assert.throws(
    () => generate(makeAtomicBrokerFixture({
      packageValue: "c".repeat(64),
      mutatePlan: (plan) => { plan.variables.package_checksum_sha256.value = "d".repeat(64); },
    })),
    /package bytes|checksum does not match/,
  );
});

test("live checksum not matching the plan before-value fails closed", () => {
  assert.throws(
    () => generate(makeAtomicBrokerFixture({
      packageValue: "c".repeat(64),
      mutatePlan: (plan) => {
        const broker = plan.resource_changes.find((item) => item.address === "aws_lambda_function.broker");
        broker.change.before.environment[0].variables.BROKER_APPROVAL_EXPECTED_JSON = JSON.stringify({ packageChecksumSha256: "d".repeat(64) });
      },
    })),
    /before-value/,
  );
});

test("missing broker approval local reference fails closed", () => {
  assert.throws(
    () => generate(makeAtomicBrokerFixture({
      packageValue: "c".repeat(64),
      mutatePlan: (plan) => {
        plan.configuration.root_module.resources[0].expressions.environment[0].variables.references = ["local.broker_task_definition_arns"];
      },
    })),
    /approval local reference/,
  );
});

test("provider-unknown broker environment after-value passes only with the full plan proof", () => {
  const fixture = makeAtomicBrokerFixture({ packageValue: "c".repeat(64) });
  assert.deepEqual(fixture.plan.resource_changes.find((item) => item.address === "aws_lambda_function.broker").change.after_unknown, { environment: [{ variables: true }] });
  assert.doesNotThrow(() => generate(fixture));
});

test("atomic package transition plan SHA binding remains enforced", () => {
  const fixture = makeAtomicBrokerFixture({ packageValue: "c".repeat(64) });
  const audit = generate(fixture);
  audit.plannedAtomicPackageChecksumTransition.planJsonSha256 = "0".repeat(64);
  const auditBytes = Buffer.from(JSON.stringify(audit));
  assert.throws(() => assertStageBPlan(fixture.plan, {
    referenceAudit: audit,
    referenceAuditBytes: auditBytes,
    referenceAuditSha256: sha256(auditBytes),
    planJsonBytes: fixture.planBytes,
    planJsonSha256: fixture.planJsonSha256,
    terraformConfiguration: fixture.options.terraformConfiguration,
    now,
  }), /planJsonSha256 does not match broker evidence/);
});

test("broker update without a reference audit fails closed", () => {
  const fixture = makeAtomicBrokerFixture();
  assert.throws(() => assertStageBPlan(fixture.plan, {
    planJsonBytes: fixture.planBytes,
    planJsonSha256: fixture.planJsonSha256,
    terraformConfiguration: fixture.options.terraformConfiguration,
    now,
  }), /explicit plan-bound reference audit/);
});

test("broker update with audit missing broker evidence fails closed", () => {
  const fixture = makeAtomicBrokerFixture();
  const audit = generate(fixture);
  delete audit.broker;
  assert.throws(() => assertStageBPlan(fixture.plan, {
    referenceAudit: audit,
    referenceAuditBytes: Buffer.from(JSON.stringify(audit)),
    referenceAuditSha256: sha256(Buffer.from(JSON.stringify(audit))),
    planJsonBytes: fixture.planBytes,
    planJsonSha256: fixture.planJsonSha256,
    terraformConfiguration: fixture.options.terraformConfiguration,
    now,
  }), /broker update reference audit evidence is missing/);
});

test("broker update with stale audit fails closed", () => {
  const fixture = makeAtomicBrokerFixture();
  const audit = generate(fixture);
  audit.auditedAt = "2026-07-31T13:00:00.000Z";
  assert.throws(() => assertStageBPlan(fixture.plan, {
    referenceAudit: audit,
    referenceAuditBytes: Buffer.from(JSON.stringify(audit)),
    referenceAuditSha256: sha256(Buffer.from(JSON.stringify(audit))),
    planJsonBytes: fixture.planBytes,
    planJsonSha256: fixture.planJsonSha256,
    terraformConfiguration: fixture.options.terraformConfiguration,
    now,
  }), /expired/);
});

test("broker update with wrong audit plan binding fails closed", () => {
  const fixture = makeAtomicBrokerFixture();
  const audit = generate(fixture);
  audit.planJsonSha256 = "0".repeat(64);
  assert.throws(() => assertStageBPlan(fixture.plan, {
    referenceAudit: audit,
    referenceAuditBytes: Buffer.from(JSON.stringify(audit)),
    referenceAuditSha256: sha256(Buffer.from(JSON.stringify(audit))),
    planJsonBytes: fixture.planBytes,
    planJsonSha256: fixture.planJsonSha256,
    terraformConfiguration: fixture.options.terraformConfiguration,
    now,
  }), /bound to a different plan JSON/);
});

test("complete broker update audit evidence passes", () => {
  const fixture = makeAtomicBrokerFixture();
  validateBrokerPlan(fixture, generate(fixture));
});

test("initial broker create passes with plan-only package proof", () => {
  const fixture = makeInitialBrokerCreateFixture();
  assert.doesNotThrow(() => assertStageBPlan(fixture.plan, { terraformConfiguration: fixture.options.terraformConfiguration }));
});

test("initial broker create does not require a reference audit", () => {
  const fixture = makeInitialBrokerCreateFixture();
  assert.doesNotThrow(() => assertStageBPlan(fixture.plan, { terraformConfiguration: fixture.options.terraformConfiguration }));
});

test("initial broker create rejects a wrong ZIP source_code_hash", () => {
  const fixture = makeInitialBrokerCreateFixture({
    mutatePlan: (plan) => {
      plan.resource_changes.find((item) => item.address === "aws_lambda_function.broker").change.after.source_code_hash = "wrong";
    },
  });
  assert.throws(() => assertStageBPlan(fixture.plan, { terraformConfiguration: fixture.options.terraformConfiguration }), /source_code_hash/);
});

test("initial broker create rejects a wrong release-package checksum", () => {
  const fixture = makeInitialBrokerCreateFixture({
    mutatePlan: (plan) => { plan.variables.package_checksum_sha256.value = "d".repeat(64); },
  });
  assert.throws(() => assertStageBPlan(fixture.plan, { terraformConfiguration: fixture.options.terraformConfiguration }), /approval JSON does not match/);
});

test("initial broker create rejects a missing broker approval mapping", () => {
  const fixture = makeInitialBrokerCreateFixture({
    mutatePlan: (plan) => { plan.configuration.root_module.resources[0].expressions.environment[0].variables.references = ["local.broker_task_definition_arns"]; },
  });
  assert.throws(() => assertStageBPlan(fixture.plan, { terraformConfiguration: fixture.options.terraformConfiguration }), /approval local reference/);
});

test("broker no-op remains accepted without update-only audit proof", () => {
  const fixture = makeInitialBrokerCreateFixture({
    mutatePlan: (plan) => { plan.resource_changes.find((item) => item.address === "aws_lambda_function.broker").change.actions = ["no-op"]; },
  });
  assert.doesNotThrow(() => assertStageBPlan(fixture.plan, { terraformConfiguration: fixture.options.terraformConfiguration }));
});

test("unsupported broker delete and replacement actions fail closed", () => {
  for (const actions of [["delete"], ["delete", "create"]]) {
    const fixture = makeAtomicBrokerFixture({ brokerActions: actions });
    assert.throws(() => assertStageBPlan(fixture.plan, { terraformConfiguration: fixture.options.terraformConfiguration }), /unsupported/);
  }
  const malformed = makeAtomicBrokerFixture({ brokerActions: [] });
  assert.throws(() => assertStageBPlan(malformed.plan, { terraformConfiguration: malformed.options.terraformConfiguration }), /missing or malformed/);
});

test("broker ZIP checksum and source_code_hash are independently validated", () => {
  const fixture = makeAtomicBrokerFixture();
  const audit = generate(fixture);
  audit.broker.brokerZipFileSha256 = "0".repeat(64);
  audit.plannedAtomicPackageChecksumTransition = null;
  const auditBytes = Buffer.from(JSON.stringify(audit));
  assert.throws(() => assertStageBPlan(fixture.plan, {
    referenceAudit: audit,
    referenceAuditBytes: auditBytes,
    referenceAuditSha256: sha256(auditBytes),
    planJsonBytes: fixture.planBytes,
    planJsonSha256: fixture.planJsonSha256,
    terraformConfiguration: fixture.options.terraformConfiguration,
    now,
  }), /ZIP checksum/);
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

test("atomic broker rollover in the same plan passes and is recorded explicitly", () => {
  const fixture = makeAtomicBrokerFixture();
  const audit = generate(fixture);
  assert.equal(audit.allOldRevisionsUnreferenced, false);
  assert.deepEqual(audit.plannedAtomicBrokerRollovers, [{
    brokerTerraformAddress: "aws_lambda_function.broker",
    taskDefinitionTerraformAddress: canaryAddress,
    mode: "full-rls-application-canary",
    family: familyForMode("full-rls-application-canary"),
    oldTaskDefinitionArn: oldArnFor(familyForMode("full-rls-application-canary")),
    brokerEnvironmentReference: "local.broker_task_definition_arns",
    taskDefinitionArnReference: `${canaryAddress}.arn`,
    planJsonSha256: fixture.planJsonSha256,
  }]);
  const canary = audit.oldTaskDefinitions.find((entry) => entry.terraformAddress === canaryAddress);
  assert.deepEqual(canary.brokerReferenceModes, ["full-rls-application-canary"]);
  assert.equal(canary.brokerReferenceStatus, "planned-atomic-broker-rollover-v1");
  const auditBytes = Buffer.from(JSON.stringify(audit));
  assert.doesNotThrow(() => assertStageBPlan(fixture.plan, {
    referenceAudit: audit,
    referenceAuditBytes: auditBytes,
    referenceAuditSha256: sha256(auditBytes),
    planJsonBytes: fixture.planBytes,
    planJsonSha256: fixture.planJsonSha256,
    terraformConfiguration: fixture.options.terraformConfiguration,
    now,
  }));
});

test("executor admin-bootstrap atomic rollover passes with a collection dependency", () => {
  const mode = "full-rls-admin-bootstrap";
  const fixture = makeAtomicBrokerFixture({ mode });
  const audit = generate(fixture);
  assert.deepEqual(audit.plannedAtomicBrokerRollovers.map((item) => item.mode), [mode]);
});

test("another executor mode passes with the same collection dependency proof", () => {
  const mode = "full-rls-role-verify";
  const fixture = makeAtomicBrokerFixture({ mode });
  const audit = generate(fixture);
  assert.deepEqual(audit.plannedAtomicBrokerRollovers.map((item) => item.mode), [mode]);
});

test("executor collection dependency is accepted only for the matching mode", () => {
  const mode = "full-rls-admin-bootstrap";
  const fixture = makeAtomicBrokerFixture({ mode });
  assert.doesNotThrow(() => assertStageBAtomicBrokerPlan(
    fixture.plan,
    executorAddressForMode(mode),
    mode,
    fixture.options.terraformConfiguration,
  ));
  assert.throws(
    () => assertStageBAtomicBrokerPlan(
      fixture.plan,
      executorAddressForMode("full-rls-role-verify"),
      mode,
      fixture.options.terraformConfiguration,
    ),
    /task-definition mode does not match/,
  );
});

test("missing executor collection dependency fails closed", () => {
  assert.throws(
    () => generate(makeAtomicBrokerFixture({ mode: "full-rls-admin-bootstrap", omitExecutorCollectionDependency: true })),
    /collection dependency/,
  );
});

test("complete broker mode mapping passes", () => {
  const fixture = makeAtomicBrokerFixture({ mode: "full-rls-admin-bootstrap" });
  assert.doesNotThrow(() => assertStageBBrokerTaskDefinitionMapping(fixture.plan, fixture.options.terraformConfiguration));
});

test("broker mode mapping accepts supported plans without identity metadata", () => {
  const fixture = makeAtomicBrokerFixture({ mode: "full-rls-admin-bootstrap" });
  for (const resource of fixture.plan.planned_values.root_module.resources) delete resource.identity;
  assert.doesNotThrow(() => assertStageBBrokerTaskDefinitionMapping(fixture.plan, fixture.options.terraformConfiguration));
});

test("swapped executor mode mappings fail closed", () => {
  const swapped = `merge(
    { full-rls-admin-bootstrap = aws_ecs_task_definition.executor["full-rls-role-verify"].arn,
      full-rls-role-verify = aws_ecs_task_definition.executor["full-rls-admin-bootstrap"].arn },
    { full-rls-application-canary = aws_ecs_task_definition.candidate["canary"].arn }
  )`;
  assert.throws(
    () => generate(makeAtomicBrokerFixture({ mode: "full-rls-admin-bootstrap", terraformConfiguration: withBrokerMapping(swapped) })),
    /per-mode mapping/,
  );
});

test("duplicate executor target mappings fail closed", () => {
  const duplicate = `merge(
    { full-rls-admin-bootstrap = aws_ecs_task_definition.executor["full-rls-admin-bootstrap"].arn,
      full-rls-role-verify = aws_ecs_task_definition.executor["full-rls-admin-bootstrap"].arn },
    { full-rls-application-canary = aws_ecs_task_definition.candidate["canary"].arn }
  )`;
  assert.throws(
    () => generate(makeAtomicBrokerFixture({ mode: "full-rls-admin-bootstrap", terraformConfiguration: withBrokerMapping(duplicate) })),
    /per-mode mapping/,
  );
});

test("missing and unexpected executor modes fail closed", () => {
  const missing = `merge(
    { full-rls-admin-bootstrap = aws_ecs_task_definition.executor["full-rls-admin-bootstrap"].arn },
    { full-rls-application-canary = aws_ecs_task_definition.candidate["canary"].arn }
  )`;
  const unexpected = `merge(
    { unexpected = aws_ecs_task_definition.executor["full-rls-admin-bootstrap"].arn },
    { full-rls-application-canary = aws_ecs_task_definition.candidate["canary"].arn }
  )`;
  assert.throws(() => generate(makeAtomicBrokerFixture({ mode: "full-rls-admin-bootstrap", terraformConfiguration: withBrokerMapping(missing) })), /per-mode mapping/);
  assert.throws(() => generate(makeAtomicBrokerFixture({ mode: "full-rls-admin-bootstrap", terraformConfiguration: withBrokerMapping(unexpected) })), /per-mode mapping/);
});

test("collection-only executor dependency without the exact mapping fails closed", () => {
  const collectionOnly = `merge(
    { for mode, task in aws_ecs_task_definition.executor : mode => task },
    { full-rls-application-canary = aws_ecs_task_definition.candidate["canary"].arn }
  )`;
  assert.throws(
    () => generate(makeAtomicBrokerFixture({ mode: "full-rls-admin-bootstrap", terraformConfiguration: withBrokerMapping(collectionOnly) })),
    /per-mode mapping/,
  );
});

test("broker no-op with a superseded ARN fails closed", () => {
  assert.throws(() => generate(makeAtomicBrokerFixture({ brokerActions: ["no-op"] })), /requires aws_lambda_function\.broker actions/);
});

test("broker update without a task-definition reference fails closed", () => {
  const fixture = makeAtomicBrokerFixture({ mutatePlan: (plan) => { delete plan.configuration; delete plan.relevant_attributes; } });
  assert.throws(() => generate(fixture), /Terraform reference to local\.broker_task_definition_arns/);
});

test("broker update referencing the wrong family fails closed", () => {
  const fixture = makeAtomicBrokerFixture({ mutateReader: (reader) => {
    const original = reader.getFunctionConfiguration;
    reader.getFunctionConfiguration = () => {
      const config = original();
      const variables = config.Environment.Variables;
      const taskDefinitions = JSON.parse(variables.BROKER_TASK_DEFINITIONS_JSON);
      taskDefinitions["full-rls-application-canary"] = oldArnFor(familyForMode("full-rls-admin-bootstrap"));
      variables.BROKER_TASK_DEFINITIONS_JSON = JSON.stringify(taskDefinitions);
      return config;
    };
  } });
  assert.throws(() => generate(fixture), /family is unexpected/);
});

test("live broker ARN must match the rollover before ARN", () => {
  const fixture = makeAtomicBrokerFixture({ mutatePlan: (plan) => {
    plan.resource_changes.find((item) => item.address === canaryAddress).change.before.arn = newArnFor(familyForMode("full-rls-application-canary"));
  } });
  assert.throws(() => generate(fixture), /does not match the rollover before ARN/);
});

test("unrelated superseded broker reference fails closed", () => {
  const fixture = makeAtomicBrokerFixture({ mutateReader: (reader) => {
    const original = reader.getFunctionConfiguration;
    reader.getFunctionConfiguration = () => {
      const config = original();
      const variables = config.Environment.Variables;
      const taskDefinitions = JSON.parse(variables.BROKER_TASK_DEFINITIONS_JSON);
      taskDefinitions["full-rls-application-canary"] = oldArnFor(familyForMode("full-rls-admin-bootstrap"));
      variables.BROKER_TASK_DEFINITIONS_JSON = JSON.stringify(taskDefinitions);
      return config;
    };
  } });
  assert.throws(() => generate(fixture), /family is unexpected/);
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
