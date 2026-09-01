import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import {
  STAGE_B_ECS_READ_ACTIONS,
  createAwsReader,
  observeStageBBrokerApprovalBindings,
  observeStageBEcs,
} from "../aws/production-green-stage-b-ecs-observations.mjs";
import { STAGE_B, STAGE_B_BROKER_TASK_DEFINITION_FAMILIES, STAGE_B_MODES } from "../aws/production-green-stage-b-contract.mjs";
import { STAGE_B_TASK_DEFINITION_FAMILY_NAMES } from "../aws/stage-b-reference-audit-contract.mjs";

const family = STAGE_B_TASK_DEFINITION_FAMILY_NAMES[0];
const definitionArn = `arn:aws:ecs:${STAGE_B.region}:${STAGE_B.account}:task-definition/${family}:1`;
const serviceArn = `arn:aws:ecs:${STAGE_B.region}:${STAGE_B.account}:service/mscqr-prod-euw2-main/stage-b`;
const taskArn = (status) => `arn:aws:ecs:${STAGE_B.region}:${STAGE_B.account}:task/mscqr-prod-euw2-main/${status.toLowerCase()}`;

function reader(overrides = {}) {
  const base = {
    listServices: () => [serviceArn],
    describeServices: () => ({ services: [{ serviceArn, serviceName: "stage-b", taskDefinition: definitionArn, runningCount: 1, pendingCount: 0, status: "ACTIVE" }], failures: [] }),
    listTasks: () => [taskArn("RUNNING")],
    describeTasks: (arns) => ({ tasks: arns.map((arn) => ({ taskArn: arn, taskDefinitionArn: definitionArn, lastStatus: "RUNNING", desiredStatus: "RUNNING", group: "service:stage-b" })), failures: [] }),
    describeTaskDefinition: () => ({ taskDefinition: { taskDefinitionArn: definitionArn, family, revision: 1, status: "ACTIVE" } }),
  };
  return { ...base, ...overrides };
}

const brokerTaskDefinitions = Object.fromEntries(STAGE_B_MODES.map((mode) => [mode, `arn:aws:ecs:${STAGE_B.region}:${STAGE_B.account}:task-definition/${STAGE_B_BROKER_TASK_DEFINITION_FAMILIES[mode]}:4`]));
function brokerReader(overrides = {}) {
  return reader({
    getAlias: () => ({ AliasArn: STAGE_B.brokerAliasArn, Name: STAGE_B.brokerAliasQualifier, FunctionVersion: "4" }),
    getFunctionConfiguration: (functionArn, qualifier) => ({ FunctionArn: `${functionArn}:${qualifier}`, Version: qualifier, Environment: { Variables: { BROKER_TASK_DEFINITIONS_JSON: JSON.stringify(brokerTaskDefinitions) } } }),
    describeTaskDefinition: (arn) => ({ taskDefinition: { taskDefinitionArn: arn, family: arn.match(/task-definition\/([^:]+)/)[1], revision: 4, status: "ACTIVE" } }),
    ...overrides,
  });
}

test("release-deployer broker observation captures one alias-resolved version and every exact task definition", () => {
  const observed = observeStageBBrokerApprovalBindings({ reader: brokerReader(), now: () => new Date("2026-08-31T10:00:00.000Z") });
  assert.equal(observed.configuration.Version, "4");
  assert.equal(observed.alias.FunctionVersion, "4");
  assert.equal(observed.observedAt, "2026-08-31T10:00:00.000Z");
  assert.deepEqual(Object.keys(observed.taskDefinitions).sort(), [...STAGE_B_MODES].sort());
});

test("release-deployer captures approval-observation time after every live read", () => {
  const calls = [];
  const observed = observeStageBBrokerApprovalBindings({
    reader: brokerReader({
      getAlias: () => { calls.push("alias"); return { AliasArn: STAGE_B.brokerAliasArn, Name: STAGE_B.brokerAliasQualifier, FunctionVersion: "4" }; },
      getFunctionConfiguration: (functionArn, qualifier) => { calls.push("configuration"); return { FunctionArn: `${functionArn}:${qualifier}`, Version: qualifier, Environment: { Variables: { BROKER_TASK_DEFINITIONS_JSON: JSON.stringify(brokerTaskDefinitions) } } }; },
      describeTaskDefinition: (arn) => { calls.push(`task:${arn}`); return { taskDefinition: { taskDefinitionArn: arn, family: arn.match(/task-definition\/([^:]+)/)[1], revision: 4, status: "ACTIVE" } }; },
    }),
    now: () => {
      assert.equal(calls.length, STAGE_B_MODES.length + 4);
      return new Date("2026-08-31T10:00:00.000Z");
    },
  });
  assert.equal(observed.observedAt, "2026-08-31T10:00:00.000Z");
});

test("release-deployer broker observation rejects alias movement and an incomplete task map", () => {
  let aliases = 0;
  assert.throws(() => observeStageBBrokerApprovalBindings({ reader: brokerReader({ getAlias: () => ({ AliasArn: STAGE_B.brokerAliasArn, Name: STAGE_B.brokerAliasQualifier, FunctionVersion: String(++aliases === 1 ? 4 : 5) }) }) }), /changed|version/i);
  aliases = 0;
  assert.throws(() => observeStageBBrokerApprovalBindings({ reader: brokerReader({ getAlias: () => ({ AliasArn: STAGE_B.brokerAliasArn, Name: STAGE_B.brokerAliasQualifier, FunctionVersion: String(++aliases < 3 ? 4 : 5) }) }) }), /changed|version/i);
  assert.throws(() => observeStageBBrokerApprovalBindings({ reader: brokerReader({ getFunctionConfiguration: () => ({ FunctionArn: STAGE_B.brokerFunctionArn, Version: "4", Environment: { Variables: { BROKER_TASK_DEFINITIONS_JSON: "{}" } } }) }) }), /task-definition map/i);
});

test("release-deployer broker observation rejects weighted reviewed-alias routing", () => {
  assert.throws(() => observeStageBBrokerApprovalBindings({ reader: brokerReader({
    getAlias: () => ({ AliasArn: STAGE_B.brokerAliasArn, Name: STAGE_B.brokerAliasQualifier, FunctionVersion: "4", RoutingConfig: { AdditionalVersionWeights: { "5": 0.01 } } }),
  }) }), /routing|unreviewed/i);
});

test("final alias revalidation rejects routing changes and accepts canonical empty routing", () => {
  for (const finalRouting of [
    { AdditionalVersionWeights: { "5": 0.01 } },
    { AdditionalVersionWeights: { "5": 0.01, "6": 0.02 } },
    { unexpected: true },
  ]) {
    let reads = 0;
    assert.throws(() => observeStageBBrokerApprovalBindings({ reader: brokerReader({
      getAlias: () => ({ AliasArn: STAGE_B.brokerAliasArn, Name: STAGE_B.brokerAliasQualifier, FunctionVersion: "4", ...(reads++ === 2 ? { RoutingConfig: finalRouting } : {}) }),
    }) }), /routing|unreviewed/i);
  }
  let reads = 0;
  assert.doesNotThrow(() => observeStageBBrokerApprovalBindings({ reader: brokerReader({
    getAlias: () => ({ AliasArn: STAGE_B.brokerAliasArn, Name: STAGE_B.brokerAliasQualifier, FunctionVersion: "4", ...(reads++ === 2 ? { RoutingConfig: { AdditionalVersionWeights: {} } } : {}) }),
  }) }));
});

test("the source-controlled companion policy contains audit reads plus the Stage A cluster read and no mutation", () => {
  const policy = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionGreenStageBReferenceAuditReadOnly-v1.json", "utf8"));
  const actions = policy.Statement.flatMap((statement) => Array.isArray(statement.Action) ? statement.Action : [statement.Action]).filter((action) => action.startsWith("ecs:"));
  for (const action of [...STAGE_B_ECS_READ_ACTIONS, "ecs:DescribeClusters"]) assert.equal(actions.includes(action), true, action);
  assert.equal(actions.some((action) => /RunTask|StartTask|StopTask|UpdateService|RegisterTaskDefinition|DeregisterTaskDefinition/.test(action)), false);
});

test("the canonical helper completes service and RUNNING observations", () => {
  const calls = [];
  const observations = observeStageBEcs({ reader: reader({
    describeTaskDefinition: (arn) => { calls.push(arn); return { taskDefinition: { taskDefinitionArn: arn, family, revision: 1, status: "ACTIVE" } }; },
  }) });
  assert.equal(observations.services.length, 1);
  assert.equal(observations.runningTasks.length, 1);
  assert.equal(observations.pendingTasks.length, 0);
  assert.equal(observations.transitionalTasks.length, 0);
  assert.deepEqual(calls, [definitionArn]);
});

test("PENDING is partitioned from the active desired-RUNNING discovery set", () => {
  const pending = taskArn("PENDING");
  const observations = observeStageBEcs({ reader: reader({
    listTasks: () => [pending],
    describeTasks: () => ({ tasks: [{ taskArn: pending, taskDefinitionArn: definitionArn, lastStatus: "PENDING", desiredStatus: "RUNNING", group: "service:stage-b" }], failures: [] }),
  }) });
  assert.deepEqual(observations.runningTasks, []);
  assert.equal(observations.pendingTasks.length, 1);
  assert.equal(observations.pendingTasks[0].taskArn, pending);
});

test("transitional active tasks remain explicitly recorded", () => {
  const activating = taskArn("ACTIVATING");
  const observations = observeStageBEcs({ reader: reader({
    listTasks: () => [activating],
    describeTasks: () => ({ tasks: [{ taskArn: activating, taskDefinitionArn: definitionArn, lastStatus: "ACTIVATING", desiredStatus: "RUNNING", group: "service:stage-b" }], failures: [] }),
  }) });
  assert.equal(observations.transitionalTasks.length, 1);
  assert.equal(observations.transitionalTasks[0].lastStatus, "ACTIVATING");
});

test("a missing ListServices permission fails before DescribeServices", () => {
  let described = false;
  assert.throws(() => observeStageBEcs({ reader: reader({ listServices: () => { throw new Error("AWS read failed: listServices"); }, describeServices: () => { described = true; return {}; } }) }), /listServices/);
  assert.equal(described, false);
});

test("a missing ListTasks permission fails deterministically", () => {
  assert.throws(() => observeStageBEcs({ reader: reader({ listTasks: () => { throw new Error("AWS read failed: listTasks"); } }) }), /listTasks/);
});

test("empty service and task lists are explicit and do not cause secondary Describe calls", () => {
  let described = false;
  const result = observeStageBEcs({ reader: reader({
    listServices: () => [],
    listTasks: () => [],
    describeServices: () => { described = true; return {}; },
    describeTasks: () => { described = true; return {}; },
  }) });
  assert.deepEqual(result.services, []);
  assert.deepEqual(result.runningTasks, []);
  assert.deepEqual(result.pendingTasks, []);
  assert.equal(described, false);
});

test("pagination is fully consumed by the AWS reader", () => {
  const calls = [];
  const result = createAwsReader({
    region: STAGE_B.region,
    clusterArn: STAGE_B.clusterArn,
    run: (args) => {
      calls.push(args);
      return JSON.stringify(args.includes("--starting-token") ? { serviceArns: [serviceArn] } : { serviceArns: [], NextToken: "page-2" });
    },
  }).listServices();
  assert.deepEqual(result, [serviceArn]);
  assert.equal(calls.length, 2);
  assert.equal(calls[1][calls[1].indexOf("--starting-token") + 1], "page-2");
});

test("pagination errors fail closed", () => {
  assert.throws(() => createAwsReader({
    region: STAGE_B.region,
    clusterArn: STAGE_B.clusterArn,
    run: () => JSON.stringify({ serviceArns: [], NextToken: 42 }),
  }).listServices(), /pagination token is malformed/);
});

test("AccessDenied is not converted into an empty observation", () => {
  assert.throws(() => observeStageBEcs({ reader: reader({ listServices: () => { throw new Error("AWS read failed: listServices"); } }) }), /AWS read failed/);
});

test("unknown services, task-definition families, regions, and clusters fail closed", () => {
  assert.throws(() => observeStageBEcs({ reader: reader({ listServices: () => ["arn:aws:ecs:eu-west-2:368992683803:service/other-cluster/service"] }) }), /unknown Stage B\/production ARN/);
  const unknownDefinitionArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-unknown:1";
  assert.throws(() => observeStageBEcs({ reader: reader({
    describeServices: () => ({ services: [{ serviceArn, serviceName: "stage-b", taskDefinition: unknownDefinitionArn, runningCount: 0, pendingCount: 0, status: "ACTIVE" }], failures: [] }),
    listTasks: () => [],
    describeTaskDefinition: () => ({ taskDefinition: { taskDefinitionArn: unknownDefinitionArn, family: "mscqr-production-unknown", revision: 1, status: "ACTIVE" } }),
  }) }), /unknown reserved Stage B family/);
  assert.throws(() => createAwsReader({ region: "us-east-1", clusterArn: STAGE_B.clusterArn, run: () => "{}" }), /exact production region and cluster/);
  assert.throws(() => createAwsReader({ region: STAGE_B.region, clusterArn: "arn:aws:ecs:eu-west-2:368992683803:cluster/other", run: () => "{}" }), /exact production region and cluster/);
});

test("unrelated shared-cluster workloads remain visible but are not Stage B scoped", () => {
  const unrelatedFamily = "mscqr-backend";
  const unrelatedDefinitionArn = `arn:aws:ecs:${STAGE_B.region}:${STAGE_B.account}:task-definition/${unrelatedFamily}:46`;
  const unrelatedServiceArn = `arn:aws:ecs:${STAGE_B.region}:${STAGE_B.account}:service/mscqr-prod-euw2-main/mscqr-backend-servie-euw2`;
  const unrelatedTaskArn = `arn:aws:ecs:${STAGE_B.region}:${STAGE_B.account}:task/mscqr-prod-euw2-main/blue-task`;
  const observations = observeStageBEcs({ reader: reader({
    listServices: () => [unrelatedServiceArn],
    describeServices: () => ({ services: [{ serviceArn: unrelatedServiceArn, serviceName: "mscqr-backend-servie-euw2", taskDefinition: unrelatedDefinitionArn, runningCount: 1, pendingCount: 0, status: "ACTIVE" }], failures: [] }),
    listTasks: () => [unrelatedTaskArn],
    describeTasks: () => ({ tasks: [{ taskArn: unrelatedTaskArn, taskDefinitionArn: unrelatedDefinitionArn, lastStatus: "RUNNING", desiredStatus: "RUNNING", group: "service:mscqr-backend" }], failures: [] }),
    describeTaskDefinition: () => ({ taskDefinition: { taskDefinitionArn: unrelatedDefinitionArn, family: unrelatedFamily, revision: 46, status: "ACTIVE" } }),
  }) });
  assert.equal(observations.services[0].stageBScoped, false);
  assert.equal(observations.runningTasks[0].stageBScoped, false);
  assert.equal(observations.taskDefinitions[0].stageBScoped, false);
});

test("unknown reserved Stage B families fail closed", () => {
  const unknownDefinitionArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-unknown:1";
  assert.throws(() => observeStageBEcs({ reader: reader({
    describeServices: () => ({ services: [{ serviceArn, serviceName: "stage-b", taskDefinition: unknownDefinitionArn, runningCount: 0, pendingCount: 0, status: "ACTIVE" }], failures: [] }),
    listTasks: () => [],
    describeTaskDefinition: () => ({ taskDefinition: { taskDefinitionArn: unknownDefinitionArn, family: "mscqr-production-unknown", revision: 1, status: "ACTIVE" } }),
  }) }), /unknown reserved Stage B family/);
});

test("the AWS reader never issues a PENDING desired-status request", () => {
  const readerInstance = createAwsReader({ region: STAGE_B.region, clusterArn: STAGE_B.clusterArn, run: () => JSON.stringify({ taskArns: [] }) });
  assert.throws(() => readerInstance.listTasks("PENDING"), /only permits desiredStatus=RUNNING/);
});

test("reference audit imports the canonical helper", () => {
  const source = fs.readFileSync("scripts/aws/generate-production-green-stage-b-reference-audit.mjs", "utf8");
  assert.match(source, /production-green-stage-b-ecs-observations\.mjs/);
  assert.match(source, /observeStageBEcs\(\{ reader, region, clusterArn \}\)/);
  const postApplySource = fs.readFileSync("scripts/aws/verify-production-green-stage-b-ecs-observations.mjs", "utf8");
  assert.match(postApplySource, /production-green-stage-b-ecs-observations\.mjs/);
  assert.match(postApplySource, /observeStageBEcs\(\{ reader, region: STAGE_B\.region, clusterArn: STAGE_B\.clusterArn \}\)/);
});
