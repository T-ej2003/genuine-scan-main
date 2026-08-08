import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import test from "node:test";
import {
  classifyStageBPlan,
} from "../aws/stage-b-deployment-contract.mjs";
import { assertStageBPlan } from "../plan-production-green-stage-b.mjs";
import { STAGE_B } from "../aws/production-green-stage-b-contract.mjs";
import { STAGE_B_TASK_DEFINITION_FAMILIES } from "../aws/stage-b-reference-audit-contract.mjs";
import {
  createStageBPlanCaptureReport,
  assertStageBPlanCaptureReport,
  createStageBPlanApprovalReport,
  assertStageBPlanApprovalReport,
  stageBPlanHashes,
} from "../aws/stage-b-plan-approval-contract.mjs";

const image = (character) => `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${character.repeat(64)}`;
const variables = {
  backend_image: { value: image("1") },
  worker_image: { value: image("2") },
  executor_image: { value: image("3") },
  canary_image: { value: image("4") },
  read_only_canary_image: { value: image("5") },
  image_release_sha: { value: "a".repeat(40) },
  source_contract_sha256: { value: "b".repeat(64) },
  migration_set_digest: { value: "c".repeat(64) },
  package_checksum_sha256: { value: "d".repeat(64) },
};
const terraformConfiguration = fs.readFileSync("infra/aws/terraform/production-green-stage-b/main.tf", "utf8");
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");

function taskChange(address, index) {
  const family = STAGE_B_TASK_DEFINITION_FAMILIES[address];
  const key = /\["([^\"]+)"\]$/.exec(address)?.[1];
  const executor = address.startsWith("aws_ecs_task_definition.executor[");
  const imageVariable = executor ? "executor_image" : `${key}_image`;
  const containerName = executor
    ? "production-rls-executor"
    : key === "canary" ? "production-green-canary" : key === "read_only_canary" ? "production-green-read-only-rls-canary" : key;
  const mutableEnvironment = executor
    ? ["RELEASE_GIT_SHA", "MSCQR_FULL_RLS_SOURCE_CONTRACT_SHA256", "MSCQR_FULL_RLS_MIGRATION_SET_DIGEST", "MSCQR_FULL_RLS_PACKAGE_CHECKSUM_SHA256"]
    : key === "canary" ? ["RELEASE_GIT_SHA", "MSCQR_FULL_RLS_SOURCE_CONTRACT_SHA256", "MSCQR_FULL_RLS_MIGRATION_SET_DIGEST"]
      : ["RELEASE_GIT_SHA"].filter(() => key !== "read_only_canary");
  const before = {
    family,
    arn: `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:${index}`,
    network_mode: "awsvpc",
    requires_compatibilities: ["FARGATE"],
    cpu: executor || key === "canary" ? "1024" : key === "read_only_canary" ? "256" : key === "worker" ? "512" : "1024",
    memory: executor || key === "canary" ? "2048" : key === "read_only_canary" ? "512" : key === "worker" ? "1024" : "2048",
    execution_role_arn: `arn:aws:iam::368992683803:role/${family}-execution`,
    task_role_arn: `arn:aws:iam::368992683803:role/${family}-task`,
    runtime_platform: { operating_system_family: "LINUX", cpu_architecture: "X86_64" },
    volumes: [{ name: "tmp" }],
    tags: { Component: "full-rls-green-stage-b", Environment: "production", ManagedBy: "Terraform" },
  };
  const environment = mutableEnvironment.map((name) => ({ name, value: `old-${name}` }));
  const after = structuredClone(before);
  after.arn = `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:${index + 1}`;
  after.container_definitions = JSON.stringify([{ name: containerName, image: variables[imageVariable].value, environment: mutableEnvironment.map((name) => ({ name, value: variables[{ RELEASE_GIT_SHA: "image_release_sha", MSCQR_FULL_RLS_SOURCE_CONTRACT_SHA256: "source_contract_sha256", MSCQR_FULL_RLS_MIGRATION_SET_DIGEST: "migration_set_digest", MSCQR_FULL_RLS_PACKAGE_CHECKSUM_SHA256: "package_checksum_sha256" }[name]].value })) }]);
  before.container_definitions = JSON.stringify([{ name: containerName, image: image("f"), environment }]);
  return { address, mode: "managed", type: "aws_ecs_task_definition", change: { actions: ["create", "delete"], replace_paths: [["container_definitions"]], before, after } };
}

function rotationPlan() {
  return {
    variables,
    resource_changes: Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES).map((address, index) => taskChange(address, index + 1)),
  };
}

function rolloverAudit(plan, auditedAt = "2026-08-08T00:00:00.000Z") {
  const oldTaskDefinitions = plan.resource_changes.filter((change) => change.type === "aws_ecs_task_definition").map((change) => ({
    terraformAddress: change.address,
    oldTaskDefinitionArn: change.change.before.arn,
    family: STAGE_B_TASK_DEFINITION_FAMILIES[change.address],
    proposedFamily: STAGE_B_TASK_DEFINITION_FAMILIES[change.address],
    classification: "rollover",
    replacePaths: [["container_definitions"]],
    serviceReferences: [],
    runningTaskReferences: [],
    pendingTaskReferences: [],
    brokerReferenceModes: [],
    brokerReferenceStatus: "not-referenced-by-broker-v1",
    rollbackArn: change.change.before.arn,
    sameFamilyAsReplacement: true,
  }));
  return {
    schemaVersion: 1,
    auditedAt,
    callerArn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/test",
    clusterArn: STAGE_B.clusterArn,
    planJsonSha256: "",
    oldTaskDefinitions,
    retainedTaskDefinitions: [],
    newestRetainedTaskDefinitions: [],
    createOnlyTaskDefinitions: [],
    noOpTaskDefinitions: [],
    currentTaskDefinitions: { currentCreates: 0, currentNoOps: 0, currentRollovers: 12, total: 12 },
    services: [],
    runningTasks: [],
    pendingTasks: [],
    transitionalTasks: [],
    taskDefinitions: [],
    allOldRevisionsUnreferenced: true,
  };
}

function addBrokerMappingMetadata(plan) {
  plan.configuration = { root_module: { resources: [{
    address: "aws_ecs_task_definition.executor",
    type: "aws_ecs_task_definition",
    for_each_expression: { references: ["local.executor_definitions"] },
    expressions: { family: { references: ["each.value.family"] } },
  }] } };
  plan.planned_values = { root_module: { resources: Object.entries(STAGE_B_TASK_DEFINITION_FAMILIES).map(([address, family]) => ({
    address,
    type: "aws_ecs_task_definition",
    index: /\["([^\"]+)"\]$/.exec(address)?.[1],
    values: { family },
  })) } };
  return plan;
}

test("exact twelve ECS task-definition rotations form the explicit normal rotation profile", () => {
  const result = classifyStageBPlan(rotationPlan(), { strict: true });
  assert.equal(result.planProfile, "ECS_TASK_DEFINITION_ROTATION");
  assert.equal(result.taskDefinitionRotations.length, 12);
  assert.deepEqual(result.actionCounts, { replacement: 12 });
  assert.deepEqual(result.unclassifiedResources, []);
});

test("rotation metadata is carried into plan capture evidence", () => {
  const plan = rotationPlan();
  const classification = classifyStageBPlan(plan, { strict: true });
  const hashes = Object.fromEntries(["savedPlanSha256", "planJsonSha256", "canonicalPlanFileSha256", "logicalCanonicalPlanJsonSha256"].map((key) => [key, "2".repeat(64)]));
  const report = createStageBPlanCaptureReport({
    toolingSha: "e".repeat(40), toolingTreeSha256: "f".repeat(64), refreshReportSha256: "1".repeat(64),
    hashes,
    capturedAt: "2026-08-08T00:00:00.000Z", stageBLineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", stageBSerial: 78,
    terraformVersion: "1.15.7", terraformFormatVersion: "1.2", planProfile: classification.planProfile,
    taskDefinitionRotations: classification.taskDefinitionRotations,
    classification: { noOp: 0, create: 0, update: 0, destroy: 0, replacement: 12, unclassified: 0 },
  });
  const bytes = Buffer.from(`${JSON.stringify(report, null, 2)}\n`);
  assert.equal(report.planProfile, "ECS_TASK_DEFINITION_ROTATION");
  assert.doesNotThrow(() => assertStageBPlanCaptureReport(report, { captureReportBytes: bytes, hashes, stageBLineage: report.stageBLineage, stageBSerial: report.stageBSerial }));
});

test("the twelve rollover entries preserve classification through audit binding and PLAN_APPROVED", () => {
  const plan = rotationPlan();
  plan.resource_changes.push({
    address: "aws_lambda_alias.reviewed",
    type: "aws_lambda_alias",
    change: {
      actions: ["update"],
      before: { name: "reviewed", function_name: "mscqr-production-rls-approval-broker", function_version: "2" },
      after: { name: "reviewed", function_name: "mscqr-production-rls-approval-broker", function_version: "3" },
    },
  });
  addBrokerMappingMetadata(plan);
  const planBytes = Buffer.from(JSON.stringify(plan));
  const audit = rolloverAudit(plan);
  audit.planJsonSha256 = sha256(planBytes);
  const auditBytes = Buffer.from(JSON.stringify(audit));
  const planResult = assertStageBPlan(plan, {
    terraformConfiguration,
    referenceAudit: audit,
    referenceAuditBytes: auditBytes,
    referenceAuditSha256: sha256(auditBytes),
    planJsonBytes: planBytes,
    planJsonSha256: sha256(planBytes),
    trustedCallerArn: audit.callerArn,
    now: new Date("2026-08-08T00:10:00.000Z"),
  });
  assert.equal(planResult.taskDefinitions.currentRotations.length, 12);
  assert.deepEqual(audit.oldTaskDefinitions.map((entry) => entry.classification), Array(12).fill("rollover"));

  const hashes = stageBPlanHashes({ savedPlanBytes: Buffer.from("saved-plan"), planJsonBytes: planBytes, canonicalPlanJsonBytes: planBytes });
  const capture = createStageBPlanCaptureReport({
    toolingSha: "a".repeat(40), toolingTreeSha256: "b".repeat(64), refreshReportSha256: "c".repeat(64), hashes,
    capturedAt: "2026-08-08T00:11:00.000Z", stageBLineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", stageBSerial: 78,
    terraformVersion: "1.15.7", terraformFormatVersion: "1.2", planProfile: planResult.planProfile,
    taskDefinitionRotations: planResult.taskDefinitions.currentRotations,
    classification: { noOp: 0, create: 0, update: 1, destroy: 0, replacement: 12, unclassified: 0 },
  });
  const captureBytes = Buffer.from(`${JSON.stringify(capture, null, 2)}\n`);
  assert.doesNotThrow(() => assertStageBPlanCaptureReport(capture, { captureReportBytes: captureBytes, hashes, stageBLineage: capture.stageBLineage, stageBSerial: capture.stageBSerial }));
  const approval = createStageBPlanApprovalReport({
    captureReportSha256: sha256(captureBytes), referenceAuditPath: "/private/tmp/rotation-audit.json", referenceAuditSha256: sha256(auditBytes),
    referenceAuditCallerArn: audit.callerArn, referenceAuditAt: audit.auditedAt, toolingSha: capture.toolingSha,
    toolingTreeSha256: capture.toolingTreeSha256, refreshReportSha256: capture.refreshReportSha256, stageBLineage: capture.stageBLineage,
    stageBSerial: capture.stageBSerial, hashes, logicalCanonicalPlanJsonSha256: hashes.logicalCanonicalPlanJsonSha256,
    approvedAt: "2026-08-08T00:12:00.000Z", classification: capture.classification, planProfile: capture.planProfile,
    taskDefinitionRotations: capture.taskDefinitionRotations,
  });
  const approvalBytes = Buffer.from(`${JSON.stringify(approval, null, 2)}\n`);
  assert.doesNotThrow(() => assertStageBPlanApprovalReport(approval, {
    approvalReportBytes: approvalBytes, captureReport: capture, captureReportBytes: captureBytes, referenceAudit: audit,
    referenceAuditBytes: auditBytes, hashes, logicalCanonicalPlanJsonSha256: hashes.logicalCanonicalPlanJsonSha256,
    referenceAuditSha256: sha256(auditBytes), trustedCallerArn: audit.callerArn,
    stageBLineage: capture.stageBLineage, stageBSerial: capture.stageBSerial,
  }));
});

test("missing or non-rollover audit classifications fail closed", () => {
  const plan = rotationPlan();
  const planBytes = Buffer.from(JSON.stringify(plan));
  for (const classification of [undefined, "create-only", "no-op", "unknown"]) {
    const audit = rolloverAudit(plan);
    if (classification === undefined) delete audit.oldTaskDefinitions[0].classification;
    else audit.oldTaskDefinitions[0].classification = classification;
    audit.planJsonSha256 = sha256(planBytes);
    const auditBytes = Buffer.from(JSON.stringify(audit));
    assert.throws(() => assertStageBPlan(plan, {
      terraformConfiguration, referenceAudit: audit, referenceAuditBytes: auditBytes, referenceAuditSha256: sha256(auditBytes),
      planJsonBytes: planBytes, planJsonSha256: sha256(planBytes), trustedCallerArn: audit.callerArn,
      now: new Date("2026-08-08T00:10:00.000Z"),
    }), /rollover classification|does not match the exact plan/);
  }
});

test("rotation contract rejects delete-only and unknown task-definition actions", () => {
  for (const mutate of [
    (plan) => { plan.resource_changes[0].change.actions = ["delete"]; },
    (plan) => { plan.resource_changes[0].address = 'aws_ecs_task_definition.candidate["unknown"]'; },
    (plan) => { plan.resource_changes[0].change.replace_paths = [["cpu"]]; },
    (plan) => { plan.resource_changes[0].change.after.cpu = "2048"; },
    (plan) => { plan.resource_changes[0].change.after.arn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/other-family:99"; },
    (plan) => { plan.resource_changes[0].change.after.container_definitions = JSON.stringify([{ name: "backend", image: image("9"), environment: [] }]); },
  ]) {
    const plan = rotationPlan();
    mutate(plan);
    assert.throws(() => classifyStageBPlan(plan, { strict: true }), /Stage B|unsupported/);
  }
});

test("recovery does not authorize an extra ECS address", () => {
  const plan = rotationPlan();
  plan.resource_changes.push({ address: 'aws_ecs_task_definition.executor["unexpected"]', type: "aws_ecs_task_definition", change: { actions: ["create", "delete"] } });
  assert.throws(() => classifyStageBPlan(plan, { strict: true }), /unknown Stage B task-definition family|unsupported/);
});
