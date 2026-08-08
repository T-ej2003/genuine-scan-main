import assert from "node:assert/strict";
import test from "node:test";
import { classifyStageBPlan } from "../aws/stage-b-deployment-contract.mjs";
import { STAGE_B_TASK_DEFINITION_FAMILIES } from "../aws/stage-b-reference-audit-contract.mjs";

const digest = (character) => `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr/backend@sha256:${character.repeat(64)}`;
const variables = {
  backend_image: { value: digest("1") }, worker_image: { value: digest("2") }, executor_image: { value: digest("3") },
  canary_image: { value: digest("4") }, read_only_canary_image: { value: digest("5") },
  image_release_sha: { value: "a".repeat(40) }, source_contract_sha256: { value: "b".repeat(64) },
  migration_set_digest: { value: "c".repeat(64) }, package_checksum_sha256: { value: "d".repeat(64) },
};

function rotationChange(address, revision) {
  const family = STAGE_B_TASK_DEFINITION_FAMILIES[address];
  const key = /\["([^\"]+)"\]$/.exec(address)?.[1];
  const executor = address.startsWith("aws_ecs_task_definition.executor[");
  const imageVariable = executor ? "executor_image" : `${key}_image`;
  const before = {
    family,
    arn: `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:${revision}`,
    network_mode: "awsvpc",
    requires_compatibilities: ["FARGATE"],
    cpu: "1024",
    memory: "2048",
    execution_role_arn: `arn:aws:iam::368992683803:role/${family}-execution`,
    task_role_arn: `arn:aws:iam::368992683803:role/${family}-task`,
    runtime_platform: { operating_system_family: "LINUX", cpu_architecture: "X86_64" },
    volume: [],
    ipc_mode: "",
    pid_mode: "",
    tags: { ManagedBy: "Terraform" },
  };
  const provenance = executor
    ? ["RELEASE_GIT_SHA", "MSCQR_FULL_RLS_SOURCE_CONTRACT_SHA256", "MSCQR_FULL_RLS_MIGRATION_SET_DIGEST", "MSCQR_FULL_RLS_PACKAGE_CHECKSUM_SHA256"]
    : ["RELEASE_GIT_SHA"];
  const values = { RELEASE_GIT_SHA: variables.image_release_sha.value, MSCQR_FULL_RLS_SOURCE_CONTRACT_SHA256: variables.source_contract_sha256.value, MSCQR_FULL_RLS_MIGRATION_SET_DIGEST: variables.migration_set_digest.value, MSCQR_FULL_RLS_PACKAGE_CHECKSUM_SHA256: variables.package_checksum_sha256.value };
  const after = structuredClone(before);
  after.arn = `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:${revision + 1}`;
  before.container_definitions = JSON.stringify([{ name: key, image: digest("f"), environment: provenance.map((name) => ({ name, value: `old-${name}` })) }]);
  after.container_definitions = JSON.stringify([{ name: key, image: variables[imageVariable].value, environment: provenance.map((name) => ({ name, value: values[name] })) }]);
  return { address, mode: "managed", type: "aws_ecs_task_definition", change: { actions: ["create", "delete"], replace_paths: [["container_definitions"]], before, after } };
}

const alias = (actions = ["no-op"]) => ({ address: "aws_lambda_alias.reviewed", type: "aws_lambda_alias", change: {
  actions,
  before: { name: "reviewed", function_name: "mscqr-production-rls-approval-broker", function_version: "2" },
  after: { name: "reviewed", function_name: "mscqr-production-rls-approval-broker", function_version: actions[0] === "update" ? "3" : "2" },
} });
const rotationPlan = () => ({ variables, resource_changes: Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES).map((address, index) => rotationChange(address, index + 1)) });

test("offline happy paths use exact address/action profiles", () => {
  assert.equal(classifyStageBPlan({ resource_changes: [alias()] }, { strict: true }).planProfile, "BASELINE");
  assert.equal(classifyStageBPlan({ resource_changes: [alias(["update"])] }, { strict: true }).actionCounts.update, 1);
  assert.equal(classifyStageBPlan(rotationPlan(), { strict: true }).planProfile, "ECS_TASK_DEFINITION_ROTATION");
  const combined = rotationPlan();
  combined.resource_changes.push(alias(["update"]));
  const combinedResult = classifyStageBPlan(combined, { strict: true });
  assert.equal(combinedResult.actionCounts.replacement, 12);
  assert.equal(combinedResult.actionCounts.update, 1);
});

test("offline unsafe plan fixtures fail closed", () => {
  const cases = {
    UNKNOWN_RESOURCE: (plan) => plan.resource_changes.push({ address: "aws_ecs_service.unknown", type: "aws_ecs_service", change: { actions: ["update"] } }),
    UNKNOWN_MODULE: (plan) => { plan.resource_changes[0].address = 'module.unknown.aws_ecs_task_definition.candidate["backend"]'; },
    DATA_SOURCE_SUBSTITUTION: (plan) => { plan.resource_changes[0].address = 'data.aws_ecs_task_definition.candidate["backend"]'; },
    UNKNOWN_TASK_FAMILY: (plan) => { plan.resource_changes[0].address = 'aws_ecs_task_definition.candidate["unknown"]'; },
    DESTROY_ONLY: (plan) => { plan.resource_changes.push({ ...alias(["delete"]), address: "aws_lambda_alias.reviewed" }); },
    UNEXPECTED_REPLACEMENT_FIELD: (plan) => { plan.resource_changes[0].change.replace_paths = [["cpu"]]; },
    IMAGE_DIGEST_MISMATCH: (plan) => { plan.resource_changes[0].change.after.container_definitions = JSON.stringify([{ name: "backend", image: "latest", environment: [] }]); },
    ROLE_ARN_CHANGE: (plan) => { plan.resource_changes[0].change.after.task_role_arn = "arn:aws:iam::368992683803:role/unapproved"; },
    CPU_CHANGE: (plan) => { plan.resource_changes[0].change.after.cpu = "2048"; },
    MEMORY_CHANGE: (plan) => { plan.resource_changes[0].change.after.memory = "4096"; },
    NETWORK_MODE_CHANGE: (plan) => { plan.resource_changes[0].change.after.network_mode = "bridge"; },
    SECRET_SOURCE_CHANGE: (plan) => { plan.resource_changes[0].change.after.container_definitions = JSON.stringify([{ name: "backend", image: variables.backend_image.value, secrets: [{ name: "NEW", valueFrom: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:new" }], environment: [] }]); },
  };
  for (const [name, mutate] of Object.entries(cases)) {
    const plan = rotationPlan();
    mutate(plan);
    assert.throws(() => classifyStageBPlan(plan, { strict: true }), undefined, name);
  }
});
