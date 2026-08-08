import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import {
  assertStageBPlanSemanticCompleteness,
  censusStageBPlanSemantics,
  STAGE_B_PLAN_SEMANTIC_PROFILES,
  STAGE_B_SUPPORTED_PLAN_PROFILES,
} from "../aws/stage-b-plan-semantic-contract.mjs";
import { assertStageBProviderSemanticSnapshot, STAGE_B_PROVIDER_SEMANTIC_SNAPSHOT } from "../aws/stage-b-provider-semantic-snapshot.mjs";
import { assertRecoveryPlanDelta } from "../aws/stage-b-partial-apply-recovery-contract.mjs";
import { classifyStageBPlan } from "../aws/stage-b-deployment-contract.mjs";
import { STAGE_B_TASK_DEFINITION_FAMILIES } from "../aws/stage-b-reference-audit-contract.mjs";

const addresses = Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES);
const image = (n) => `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr@sha256:${String(n).repeat(64)}`;
const ref = (references) => ({ references });
const envNames = [
  "BROKER_APPROVAL_EXPECTED_JSON", "BROKER_APPROVAL_SECRET_ARN", "BROKER_CLUSTER_ARN",
  "BROKER_EXECUTOR_SECURITY_GROUP_ID", "BROKER_IMAGES_JSON", "BROKER_PRIVATE_SUBNETS_JSON",
  "BROKER_RECEIPT_BUCKET", "BROKER_REPLAY_TABLE", "BROKER_TASK_DEFINITIONS_JSON", "BROKER_TASK_TEMPLATE_HASHES_JSON",
];

function taskChange(address, index) {
  const family = STAGE_B_TASK_DEFINITION_FAMILIES[address];
  const key = /\["([^\"]+)"\]$/.exec(address)?.[1];
  const executor = address.includes(".executor[");
  const withVolume = !["worker", "read_only_canary"].includes(key);
  const beforeArn = `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:${index}`;
  const before = {
    arn: beforeArn,
    arn_without_revision: `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}`,
    container_definitions: JSON.stringify([{ name: key, image: image("f"), environment: [{ name: "stable", value: "same" }], mountPoints: [], portMappings: [], systemControls: [], volumesFrom: [] }]),
    cpu: executor ? "1024" : "512",
    enable_fault_injection: false,
    ephemeral_storage: [],
    execution_role_arn: `arn:aws:iam::368992683803:role/${family}-execution`,
    family,
    id: beforeArn,
    ipc_mode: "",
    memory: executor ? "2048" : "1024",
    network_mode: "awsvpc",
    pid_mode: "",
    placement_constraints: [],
    proxy_configuration: [],
    region: "eu-west-2",
    requires_compatibilities: ["FARGATE"],
    revision: index,
    runtime_platform: { operating_system_family: "LINUX", cpu_architecture: "X86_64" },
    skip_destroy: true,
    tags: { Environment: "production" },
    tags_all: { Environment: "production" },
    task_role_arn: `arn:aws:iam::368992683803:role/${family}-task`,
    track_latest: false,
    volume: withVolume ? [{ configure_at_launch: false, name: "tmp", host_path: "", docker_volume_configuration: [], efs_volume_configuration: [], fsx_windows_file_server_volume_configuration: [], s3files_volume_configuration: [] }] : [],
  };
  const after = structuredClone(before);
  after.container_definitions = JSON.stringify([{ name: key, image: image("a"), environment: [{ name: "stable", value: "same" }] }]);
  after.ipc_mode = null;
  after.pid_mode = null;
  for (const field of ["arn", "arn_without_revision", "enable_fault_injection", "id", "revision"]) delete after[field];
  if (withVolume) delete after.volume[0].configure_at_launch;
  const afterUnknown = {
    arn: true,
    arn_without_revision: true,
    enable_fault_injection: true,
    ephemeral_storage: [{}],
    id: true,
    placement_constraints: [],
    proxy_configuration: [],
    requires_compatibilities: [false],
    revision: true,
    runtime_platform: [{}],
    tags: {},
    tags_all: {},
    volume: withVolume ? [{ configure_at_launch: true, docker_volume_configuration: [], efs_volume_configuration: [], fsx_windows_file_server_volume_configuration: [], s3files_volume_configuration: [] }] : [],
  };
  const sensitive = { requires_compatibilities: [false] };
  return { address, mode: "managed", type: "aws_ecs_task_definition", change: { actions: ["create", "delete"], replace_paths: [["container_definitions"]], before, after, after_unknown: afterUnknown, before_sensitive: sensitive, after_sensitive: sensitive } };
}

function configuration() {
  const candidate = {
    address: "aws_ecs_task_definition.candidate",
    type: "aws_ecs_task_definition",
    expressions: {
      container_definitions: ref(["each.value.containerDefinitions", "each.value"]),
      cpu: ref(["each.value.cpu", "each.value"]),
      execution_role_arn: ref(["aws_iam_role.execution", "each.key"]),
      family: ref(["each.value.family", "each.value"]),
      memory: ref(["each.value.memory", "each.value"]),
      network_mode: ref(["each.value.networkMode", "each.value"]),
      requires_compatibilities: ref(["each.value.requiresCompatibilities", "each.value"]),
      tags: ref(["local.tags"]),
      task_role_arn: ref(["aws_iam_role.task", "each.key"]),
    },
  };
  const executor = structuredClone(candidate);
  executor.address = "aws_ecs_task_definition.executor";
  executor.expressions.execution_role_arn = ref(["aws_iam_role.execution[\"executor\"].arn", "aws_iam_role.execution[\"executor\"]", "aws_iam_role.execution"]);
  executor.expressions.task_role_arn = ref(["var.stage_a_executor_task_role_arn"]);
  return {
    root_module: { resources: [
      candidate,
      executor,
      { address: "aws_iam_policy.broker", type: "aws_iam_policy", expressions: { policy: ref(["local.broker_runtime_policy"]), tags: ref(["local.tags"]) } },
      { address: "aws_lambda_function.broker", type: "aws_lambda_function", expressions: {
        environment: [{ variables: ref(["aws_dynamodb_table.replay.name", "aws_dynamodb_table.replay", "var.receipt_bucket_arn", "var.ecs_cluster_arn", "var.approval_secret_arn", "var.stage_a_executor_security_group_id", "var.private_subnet_ids", "local.broker_task_definition_arns", "local.broker_template_hashes", "local.broker_approval_expected", "local.broker_images"]) }],
        filename: ref(["var.broker_package_path"]), role: ref(["var.stage_a_broker_role_arn"]), publish: { constant_value: true }, source_code_hash: ref(["var.broker_package_path"]), tags: ref(["local.tags"]),
      } },
      { address: "aws_lambda_alias.reviewed", type: "aws_lambda_alias", expressions: {
        function_name: ref(["aws_lambda_function.broker.function_name", "aws_lambda_function.broker"]),
        function_version: ref(["aws_lambda_function.broker.version", "aws_lambda_function.broker"]),
      } },
    ] },
  };
}

function brokerChanges() {
  const policy = { address: "aws_iam_policy.broker", mode: "managed", type: "aws_iam_policy", change: { actions: ["update"], before: { policy: "old" }, after: {}, after_unknown: { policy: true }, before_sensitive: {}, after_sensitive: {} } };
  const before = { architectures: ["x86_64"], environment: [{ variables: Object.fromEntries(envNames.map((name) => [name, `old-${name}`])) }], filename: "old.zip", last_modified: "old", qualified_arn: "old", qualified_invoke_arn: "old", version: 2 };
  const after = { architectures: ["x86_64"], environment: [{}], filename: "new.zip" };
  const lambda = { address: "aws_lambda_function.broker", mode: "managed", type: "aws_lambda_function", change: { actions: ["update"], before, after, after_unknown: { architectures: [false], environment: [{ variables: true }], last_modified: true, qualified_arn: true, qualified_invoke_arn: true, version: true }, before_sensitive: { architectures: [false] }, after_sensitive: { architectures: [false] } } };
  const alias = { address: "aws_lambda_alias.reviewed", mode: "managed", type: "aws_lambda_alias", change: { actions: ["update"], before: { function_version: "2", routing_config: [] }, after: { routing_config: [] }, after_unknown: { function_version: true, routing_config: [] }, before_sensitive: { routing_config: [] }, after_sensitive: { routing_config: [] } } };
  return [policy, lambda, alias];
}

function plan() {
  return { configuration: configuration(), resource_changes: [...addresses.map((address, index) => taskChange(address, index + 1)), ...brokerChanges()] };
}

function baselinePlan() {
  const value = JSON.parse(fs.readFileSync("scripts/tests/fixtures/production-green-stage-b-production-shaped.plan.json", "utf8"));
  value.configuration = configuration();
  const tags = { Component: "full-rls-green-stage-b", Environment: "production", ManagedBy: "Terraform" };
  const policy = value.resource_changes.find((change) => change.address === "aws_iam_policy.broker");
  policy.change = { actions: ["create"], before: null, after: { name: "mscqr-production-rls-approval-broker-runtime", path: "/", tags }, after_unknown: { arn: true, attachment_count: true, id: true, policy: true, policy_id: true }, before_sensitive: {}, after_sensitive: {} };
  const lambda = value.resource_changes.find((change) => change.address === "aws_lambda_function.broker");
  lambda.change = {
    actions: ["create"],
    before: null,
    after: {
      function_name: "mscqr-production-rls-approval-broker", role: "arn:aws:iam::368992683803:role/mscqr-production-rls-approval-broker",
      handler: "index.handler", runtime: "nodejs24.x", filename: "/private/tmp/broker.zip", source_code_hash: "baseline-source-code-hash",
      timeout: 30, publish: true, environment: [{}], tags,
    },
    after_unknown: { architectures: [true], arn: true, environment: [{ variables: true }], id: true, invoke_arn: true, last_modified: true, qualified_arn: true, qualified_invoke_arn: true, response_streaming_invoke_arn: true, signing_job_arn: true, signing_profile_version_arn: true, source_code_size: true, version: true },
    before_sensitive: {}, after_sensitive: { architectures: [true] },
  };
  const alias = value.resource_changes.find((change) => change.address === "aws_lambda_alias.reviewed");
  alias.change = {
    actions: ["create"], before: null,
    after: { name: "reviewed", function_name: "mscqr-production-rls-approval-broker" },
    after_unknown: { arn: true, function_version: true, id: true, invoke_arn: true }, before_sensitive: {}, after_sensitive: {},
  };
  for (const change of value.resource_changes) if (change.change?.actions?.some((action) => action !== "no-op")) change.mode = "managed";
  return value;
}

function baselineEcsChange(value) {
  return value.resource_changes.find((change) => addresses.includes(change.address));
}

function mutate(mutator, expected = /UNCLASSIFIED/) {
  const value = structuredClone(plan());
  mutator(value);
  assert.throws(() => assertStageBPlanSemanticCompleteness(value), expected);
}

function mutateRecovery(mutator) {
  const value = structuredClone(plan());
  mutator(value);
  assert.throws(() => assertRecoveryPlanDelta(value, { currentObservedEvidence: {
    protectedSourceSha: "a".repeat(40),
    terraformLineage: "4e438e59-8b8b-194d-030c-5ede0c26344a",
    terraformSerial: 78,
    refreshReportSha256: "b".repeat(64),
    terraformAddress: "aws_lambda_alias.reviewed",
    resourceMode: "managed",
    resourceModule: null,
    resourceType: "aws_lambda_alias",
    resourceName: "reviewed",
    functionName: "mscqr-production-rls-approval-broker",
    aliasName: "reviewed",
    stateVersion: "3",
    liveVersion: "2",
    configuredDesiredVersion: "3",
    changedAttributes: ["function_version"],
    routingConfigurationChanged: false,
    descriptionChanged: false,
    functionIdentityChanged: false,
    aliasIdentityChanged: false,
    additionalManagedResourceDrift: false,
  } }), /exact attested alias live-to-configured update/);
}

test("real-plan-shaped semantic census has zero unclassified semantics", () => {
  const census = assertStageBPlanSemanticCompleteness(plan());
  assert.deepEqual(census.counts, {
    nonNoopResources: 15,
    resourceActions: 15,
    changedPaths: 114,
    afterUnknownPaths: 77,
    replacePaths: 12,
    configurationReferences: 117,
    unclassifiedResourceActions: 0,
    unclassifiedChangedPaths: 0,
    unclassifiedAfterUnknownPaths: 0,
    unclassifiedReplacePaths: 0,
    unclassifiedConfigurationReferences: 0,
    unfaithfulProviderComputedFields: 0,
  });
  assert.equal(new Set(census.resources.map((item) => item.classification)).size, 4);
  assert.equal(census.resources.filter((item) => item.classification === "ECS_REVIEWED_ROLLOVER").length, 12);
  assert.equal(census.resources.filter((item) => item.classification === "REVIEWED_RECOVERY_ALIAS_UPDATE").length, 1);
});

test("baseline production-shaped fixture has an exact initial-create profile", () => {
  const census = assertStageBPlanSemanticCompleteness(baselinePlan());
  assert.deepEqual(census.counts, {
    nonNoopResources: 15,
    resourceActions: 15,
    changedPaths: 139,
    afterUnknownPaths: 82,
    replacePaths: 0,
    configurationReferences: 117,
    unclassifiedResourceActions: 0,
    unclassifiedChangedPaths: 0,
    unclassifiedAfterUnknownPaths: 0,
    unclassifiedReplacePaths: 0,
    unclassifiedConfigurationReferences: 0,
    unfaithfulProviderComputedFields: 0,
  });
  assert.equal(census.resources.filter((item) => item.classification === STAGE_B_PLAN_SEMANTIC_PROFILES.ECS_INITIAL_CREATE).length, 12);
  assert.equal(census.resources.filter((item) => item.classification === STAGE_B_PLAN_SEMANTIC_PROFILES.ECS_REVIEWED_ROLLOVER).length, 0);
  assert.equal(census.resources.filter((item) => item.classification === STAGE_B_PLAN_SEMANTIC_PROFILES.BROKER_POLICY_INITIAL_CREATE).length, 1);
  assert.equal(census.resources.filter((item) => item.classification === STAGE_B_PLAN_SEMANTIC_PROFILES.BROKER_FUNCTION_INITIAL_CREATE).length, 1);
  assert.equal(census.resources.filter((item) => item.classification === STAGE_B_PLAN_SEMANTIC_PROFILES.BROKER_ALIAS_INITIAL_CREATE).length, 1);
});

test("baseline initial-create semantics fail closed on action, identity, path, and reference drift", () => {
  const mutateBaseline = (mutator, expected = /UNCLASSIFIED/) => {
    const value = baselinePlan();
    mutator(value);
    assert.throws(() => assertStageBPlanSemanticCompleteness(value), expected);
  };
  mutateBaseline((value) => { baselineEcsChange(value).address = 'aws_ecs_task_definition.candidate["unknown"]'; }, /UNCLASSIFIED_RESOURCE_ACTION/);
  mutateBaseline((value) => { baselineEcsChange(value).module = "module.untrusted"; }, /UNCLASSIFIED_RESOURCE_ACTION/);
  mutateBaseline((value) => { baselineEcsChange(value).mode = "data"; }, /UNCLASSIFIED_RESOURCE_ACTION/);
  mutateBaseline((value) => { baselineEcsChange(value).type = "aws_lambda_function"; }, /UNCLASSIFIED_RESOURCE_ACTION/);
  mutateBaseline((value) => { baselineEcsChange(value).change.actions = ["delete"]; }, /UNCLASSIFIED_RESOURCE_ACTION/);
  mutateBaseline((value) => { baselineEcsChange(value).change.actions = ["create", "delete"]; }, /UNCLASSIFIED_/);
  mutateBaseline((value) => { value.resource_changes.push(structuredClone(baselineEcsChange(value))); }, /UNCLASSIFIED_RESOURCE_ACTION/);
  mutateBaseline((value) => { baselineEcsChange(value).change.after.unreviewed = true; }, /UNCLASSIFIED_CHANGED_PATH/);
  mutateBaseline((value) => { baselineEcsChange(value).change.after_unknown = { unreviewed: true }; }, /UNFAITHFUL_PROVIDER_COMPUTED_FIELDS|UNCLASSIFIED_AFTER_UNKNOWN/);
  mutateBaseline((value) => { value.configuration.root_module.resources.find((item) => item.address === "aws_ecs_task_definition.candidate").expressions.family.references = ["var.unreviewed"]; }, /UNCLASSIFIED_CONFIGURATION_REFERENCES/);
  mutateBaseline((value) => { baselineEcsChange(value).change.replace_paths = [["cpu"]]; }, /UNCLASSIFIED_REPLACE_PATH/);
});

test("baseline broker creates are atomic and broker mutations cannot consume recovery authorization", () => {
  for (const address of ["aws_iam_policy.broker", "aws_lambda_function.broker", "aws_lambda_alias.reviewed"]) {
    const value = baselinePlan();
    value.resource_changes.find((change) => change.address === address).change.actions = ["update"];
    assert.throws(() => assertStageBPlanSemanticCompleteness(value), /UNCLASSIFIED_RESOURCE_ACTION/);
  }
  for (const actions of [["create"], ["update"]]) {
    const value = actions[0] === "create" ? baselinePlan() : plan();
    for (const address of ["aws_iam_policy.broker", "aws_lambda_function.broker", "aws_lambda_alias.reviewed"]) value.resource_changes.find((change) => change.address === address).change.actions = actions;
    assert.doesNotThrow(() => assertStageBPlanSemanticCompleteness(value));
  }
  for (const actions of [["create", "delete"], ["delete", "create"], ["read"], ["create", "update"]]) {
    const value = baselinePlan();
    value.resource_changes.find((change) => change.address === "aws_iam_policy.broker").change.actions = actions;
    assert.throws(() => assertStageBPlanSemanticCompleteness(value), /UNCLASSIFIED_RESOURCE_ACTION/);
  }
  mutateRecovery((value) => { value.resource_changes.find((change) => change.address === "aws_lambda_alias.reviewed").change.actions = ["create"]; });
});

test("append-only create/no-op retry remains represented without broadening broker profiles", () => {
  const value = plan();
  const taskChanges = value.resource_changes.filter((change) => addresses.includes(change.address));
  for (const change of taskChanges.slice(0, -1)) {
    change.change.actions = ["create"];
    change.change.before = null;
    delete change.change.replace_paths;
  }
  taskChanges.at(-1).change.actions = ["no-op"];
  for (const address of ["aws_iam_policy.broker", "aws_lambda_function.broker", "aws_lambda_alias.reviewed"]) {
    value.resource_changes.find((change) => change.address === address).change.actions = ["no-op"];
  }
  const census = assertStageBPlanSemanticCompleteness(value);
  assert.equal(census.resources.filter((item) => item.classification === STAGE_B_PLAN_SEMANTIC_PROFILES.ECS_INITIAL_CREATE).length, 11);
  assert.equal(census.resources.filter((item) => item.address.startsWith("aws_")).length, 11);
  for (const [key, count] of Object.entries(census.counts)) if (key.startsWith("unclassified") || key.startsWith("unfaithful")) assert.equal(count, 0, key);
});

test("supported profile matrix is explicit and includes baseline broker creation", () => {
  assert.deepEqual(STAGE_B_SUPPORTED_PLAN_PROFILES.map(({ profile }) => profile), [
    "BASELINE_INITIAL_CREATE", "ROLLOVER_RECOVERY", "NO_CHANGE_OR_APPEND_ONLY_RETRY",
  ]);
  assert.deepEqual(STAGE_B_SUPPORTED_PLAN_PROFILES[0].brokerPolicyActions, [["create"]]);
  assert.deepEqual(STAGE_B_SUPPORTED_PLAN_PROFILES[0].brokerFunctionActions, [["create"]]);
  assert.deepEqual(STAGE_B_SUPPORTED_PLAN_PROFILES[0].brokerAliasActions, [["create"]]);
});

test("baseline broker profiles reject non-root, unknown, and partial semantic shapes", () => {
  const mutateBaseline = (mutator, expected = /UNCLASSIFIED/) => {
    const value = baselinePlan();
    mutator(value);
    assert.throws(() => assertStageBPlanSemanticCompleteness(value), expected);
  };
  mutateBaseline((value) => { value.resource_changes.find((change) => change.address === "aws_iam_policy.broker").change.after.unreviewed = true; }, /UNCLASSIFIED_CHANGED_PATH/);
  mutateBaseline((value) => { value.resource_changes.find((change) => change.address === "aws_lambda_function.broker").change.after_unknown.timeout = true; }, /UNFAITHFUL_PROVIDER_COMPUTED_FIELDS|UNCLASSIFIED_AFTER_UNKNOWN/);
  mutateBaseline((value) => { value.configuration.root_module.resources.find((item) => item.address === "aws_lambda_alias.reviewed").expressions.function_version.references = ["aws_lambda_function.other.version"]; }, /UNCLASSIFIED_CONFIGURATION_REFERENCES/);
  mutateBaseline((value) => { value.resource_changes.find((change) => change.address === "aws_iam_policy.broker").module = "module.untrusted"; }, /UNCLASSIFIED_RESOURCE_ACTION/);
  mutateBaseline((value) => { value.resource_changes.find((change) => change.address === "aws_iam_policy.broker").mode = "data"; }, /UNCLASSIFIED_RESOURCE_ACTION/);
  mutateBaseline((value) => { value.resource_changes.push(structuredClone(value.resource_changes.find((change) => change.address === "aws_iam_policy.broker"))); }, /UNCLASSIFIED_RESOURCE_ACTION/);
});

test("initial broker computed environment uses only the reviewed structural placeholder", () => {
  const mutateBaseline = (mutator, expected = /UNCLASSIFIED/) => {
    const value = baselinePlan();
    mutator(value);
    assert.throws(() => assertStageBPlanSemanticCompleteness(value), expected);
  };
  assert.doesNotThrow(() => assertStageBPlanSemanticCompleteness(baselinePlan()));
  const concrete = baselinePlan();
  const concreteChange = concrete.resource_changes.find((change) => change.address === "aws_lambda_function.broker").change;
  concreteChange.after.environment = [{ variables: { BROKER_TASK_DEFINITIONS_JSON: "concrete" } }];
  delete concreteChange.after_unknown.environment;
  assert.throws(() => assertStageBPlanSemanticCompleteness(concrete), /UNFAITHFUL_PROVIDER_COMPUTED_FIELDS/);
  mutateBaseline((value) => { delete value.resource_changes.find((change) => change.address === "aws_lambda_function.broker").change.after_unknown.environment[0].variables; }, /UNFAITHFUL_PROVIDER_COMPUTED_FIELDS|UNCLASSIFIED_CHANGED_PATH/);
  mutateBaseline((value) => { value.resource_changes.find((change) => change.address === "aws_lambda_function.broker").change.after_unknown.environment[0].unexpected = true; }, /UNFAITHFUL_PROVIDER_COMPUTED_FIELDS|UNCLASSIFIED_(?:AFTER_UNKNOWN|CHANGED_PATH)/);
  mutateBaseline((value) => { value.resource_changes.find((change) => change.address === "aws_lambda_function.broker").change.after.environment[0].unexpected = {}; }, /UNCLASSIFIED_CHANGED_PATH/);
  mutateBaseline((value) => { value.resource_changes.find((change) => change.address === "aws_lambda_function.broker").change.after.environment.push({}); }, /UNCLASSIFIED_CHANGED_PATH/);
  mutateBaseline((value) => { const change = value.resource_changes.find((item) => item.address === "aws_lambda_function.broker").change; change.after.environment = [{ variables: { BROKER_TASK_DEFINITIONS_JSON: "concrete" } }]; }, /UNFAITHFUL_PROVIDER_COMPUTED_FIELDS|UNCLASSIFIED_CHANGED_PATH/);
  mutateBaseline((value) => { const change = value.resource_changes.find((item) => item.address === "aws_lambda_function.broker").change; change.after.environment = [{ variables: {} }]; change.after_unknown.environment = [{ variables: true }]; }, /UNFAITHFUL_PROVIDER_COMPUTED_FIELDS|UNCLASSIFIED_CHANGED_PATH/);
});

test("locked provider semantic snapshot is independently validated", () => {
  assert.doesNotThrow(() => assertStageBProviderSemanticSnapshot());
  const mutated = structuredClone(STAGE_B_PROVIDER_SEMANTIC_SNAPSHOT);
  mutated.resources.aws_iam_policy.attributes.find((entry) => entry.attributePath === "arn").computed = false;
  assert.throws(() => assertStageBProviderSemanticSnapshot(mutated), /PROVIDER_SCHEMA_SEMANTICS_CHANGED/);
  const missing = structuredClone(STAGE_B_PROVIDER_SEMANTIC_SNAPSHOT);
  missing.resources.aws_lambda_alias.attributes = missing.resources.aws_lambda_alias.attributes.filter((entry) => entry.attributePath !== "invoke_arn");
  assert.throws(() => assertStageBProviderSemanticSnapshot(missing), /PROVIDER_SCHEMA_SEMANTICS_CHANGED/);
});

test("baseline provider-computed fidelity covers all fifteen created resources", () => {
  const value = baselinePlan();
  const initial = value.resource_changes.filter((change) => change.change?.actions?.[0] === "create" && change.change.actions.length === 1);
  assert.equal(initial.length, 15);
  assert.equal(initial.filter((change) => change.type === "aws_ecs_task_definition").length, 12);
  assert.deepEqual(new Set(initial.map((change) => change.address)), new Set([
    ...addresses,
    "aws_iam_policy.broker", "aws_lambda_function.broker", "aws_lambda_alias.reviewed",
  ]));
  for (const change of initial) {
    const mutated = structuredClone(value);
    const target = mutated.resource_changes.find((candidate) => candidate.address === change.address);
    target.change.after_unknown.unreviewed_provider_field = true;
    assert.throws(() => assertStageBPlanSemanticCompleteness(mutated), /UNFAITHFUL_PROVIDER_COMPUTED_FIELDS|UNCLASSIFIED_AFTER_UNKNOWN/);
  }
  const concreteIdentifier = structuredClone(value);
  const policy = concreteIdentifier.resource_changes.find((change) => change.address === "aws_iam_policy.broker").change;
  policy.after.arn = "arn:aws:iam::368992683803:policy/synthesized";
  assert.throws(() => assertStageBPlanSemanticCompleteness(concreteIdentifier), /UNFAITHFUL_PROVIDER_COMPUTED_FIELDS/);
});

test("semantic census exposes recursive changed, unknown, sensitive and reference paths", () => {
  const census = censusStageBPlanSemantics(plan());
  const alias = census.resources.find((item) => item.address === "aws_lambda_alias.reviewed");
  assert.deepEqual(alias.changedPaths, [{ path: "function_version", classification: "REVIEWED_COMPUTED_CHANGE" }]);
  assert.deepEqual(alias.afterUnknownPaths, [{ path: "function_version", classification: "REVIEWED_COMPUTED_CHANGE" }]);
  assert.deepEqual(alias.configurationReferences[1], { field: "function_version", references: ["aws_lambda_function.broker", "aws_lambda_function.broker.version"].sort(), classification: "REVIEWED_COMPUTED_CHANGE" });
  assert.equal(census.resources.find((item) => item.address.includes('candidate["backend"]')).changedPaths.some((item) => item.path === "volume[0].configure_at_launch"), true);
});

test("future resource/action/replacement drift fails closed", () => {
  mutate((value) => value.resource_changes.push({ address: "aws_lambda_function.unknown", mode: "managed", type: "aws_lambda_function", change: { actions: ["update"], before: {}, after: {} } }), /UNCLASSIFIED_RESOURCE_ACTION/);
  mutate((value) => { value.resource_changes.find((item) => item.address === "aws_iam_policy.broker").change.actions = ["create"]; }, /UNCLASSIFIED_RESOURCE_ACTION/);
  mutate((value) => { value.resource_changes[0].change.actions = ["delete"]; }, /UNCLASSIFIED_RESOURCE_ACTION/);
  mutate((value) => { value.resource_changes[0].change.replace_paths = [["cpu"]]; }, /UNCLASSIFIED_REPLACE_PATH/);
  mutate((value) => { value.resource_changes[0].module = "module.untrusted"; }, /UNCLASSIFIED_RESOURCE_ACTION/);
  mutate((value) => { value.resource_changes[0].mode = "data"; }, /UNCLASSIFIED_RESOURCE_ACTION/);
  mutate((value) => { value.resource_changes.push(structuredClone(value.resource_changes[0])); }, /UNCLASSIFIED_RESOURCE_ACTION/);
});

test("future unknown and reference drift fails closed", () => {
  mutate((value) => { value.resource_changes.find((item) => item.address === "aws_lambda_alias.reviewed").change.after_unknown.name = true; }, /UNCLASSIFIED_AFTER_UNKNOWN/);
  mutate((value) => { value.resource_changes.find((item) => item.address === "aws_ecs_task_definition.candidate[\"backend\"]").change.after_unknown.cpu = true; }, /UNCLASSIFIED_AFTER_UNKNOWN/);
  mutate((value) => { value.resource_changes.find((item) => item.address === "aws_lambda_function.broker").change.after_unknown.timeout = true; }, /UNCLASSIFIED_AFTER_UNKNOWN/);
  mutate((value) => { value.resource_changes.find((item) => item.address === "aws_iam_policy.broker").change.after_unknown.name = true; }, /UNCLASSIFIED_AFTER_UNKNOWN/);
  mutate((value) => { value.configuration.root_module.resources.find((item) => item.address === "aws_lambda_alias.reviewed").expressions.function_version.references = ["var.lambda_version"]; }, /UNCLASSIFIED_CONFIGURATION_REFERENCES/);
  mutate((value) => { value.configuration.root_module.resources.find((item) => item.address === "aws_lambda_alias.reviewed").expressions.function_version.references.push("aws_lambda_function.other.version"); }, /UNCLASSIFIED_CONFIGURATION_REFERENCES/);
  mutate((value) => { value.resource_changes.find((item) => item.address === "aws_lambda_function.broker").change.after_unknown.version = false; }, /UNCLASSIFIED_COMPUTED_CHANGE/);
  mutate((value) => { value.resource_changes.find((item) => item.address === "aws_lambda_alias.reviewed").change.after.function_version = "3"; }, /UNCLASSIFIED_COMPUTED_CHANGE/);
  mutate((value) => { value.resource_changes = value.resource_changes.filter((item) => item.address !== "aws_lambda_function.broker"); }, /UNCLASSIFIED_(?:COMPUTED_CHANGE|RESOURCE_ACTION)/);
});

test("stable ECS security domains are validated before equality", () => {
  mutate((value) => { const change = value.resource_changes[0].change; change.before.volume[0].host_path = "/tmp"; change.after.volume[0].host_path = "/tmp"; }, /UNCLASSIFIED_CHANGED_PATH/);
  mutate((value) => { const change = value.resource_changes[0].change; change.before.volume[0].configure_at_launch = true; change.after.volume[0].configure_at_launch = true; }, /UNCLASSIFIED_CHANGED_PATH/);
  mutate((value) => { const change = value.resource_changes[0].change; change.before.ipc_mode = "host"; change.after.ipc_mode = "host"; }, /UNCLASSIFIED_CHANGED_PATH/);
  mutate((value) => { const change = value.resource_changes[0].change; change.before.pid_mode = "task"; change.after.pid_mode = "task"; }, /UNCLASSIFIED_CHANGED_PATH/);
  mutate((value) => { value.resource_changes[0].change.after.cpu = "999"; }, /UNCLASSIFIED_CHANGED_PATH/);
  mutate((value) => { value.resource_changes[0].change.after.memory = "999"; }, /UNCLASSIFIED_CHANGED_PATH/);
  mutate((value) => { value.resource_changes[0].change.after.execution_role_arn = "bad"; }, /UNCLASSIFIED_CHANGED_PATH/);
  mutate((value) => { value.resource_changes[0].change.after.network_mode = "bridge"; }, /UNCLASSIFIED_CHANGED_PATH/);
  mutate((value) => { value.resource_changes[0].change.after_sensitive.cpu = true; }, /UNCLASSIFIED_(?:BEFORE|AFTER)_SENSITIVE_PATH/);
});

test("computed alias requires same-plan published broker and exact configuration identity", () => {
  mutate((value) => { value.resource_changes.find((item) => item.address === "aws_lambda_function.broker").change.actions = ["no-op"]; }, /UNCLASSIFIED_(?:COMPUTED_CHANGE|RESOURCE_ACTION)/);
  mutate((value) => { value.configuration.root_module.resources.find((item) => item.address === "aws_lambda_function.broker").expressions.publish.constant_value = false; }, /UNCLASSIFIED_CONFIGURATION_REFERENCES/);
  mutateRecovery((value) => { const alias = value.resource_changes.find((item) => item.address === "aws_lambda_alias.reviewed"); alias.change.after.function_version = "wrong"; delete alias.change.after_unknown.function_version; });
});

test("semantic census feeds the normal offline action classifier without widening recovery", () => {
  const value = plan();
  assertStageBPlanSemanticCompleteness(value);
  const classification = classifyStageBPlan(value, { strict: false });
  assert.equal(classification.taskDefinitionRotations.length, 12);
  assert.equal(classification.actionCounts.replacement, 12);
  assert.equal(classification.actionCounts.update, 3);
  assert.equal(classification.actionCounts.destroy || 0, 0);
});
