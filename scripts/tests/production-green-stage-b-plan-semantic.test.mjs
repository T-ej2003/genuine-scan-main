import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import {
  assertStageBPlanSemanticCompleteness,
  assertStageBTypedRepresentationManifestComplete,
  censusStageBPlanSemantics,
  initialRepresentationOnlyPaths,
  STAGE_B_PLAN_SEMANTIC_PROFILES,
  STAGE_B_SUPPORTED_PLAN_PROFILES,
} from "../aws/stage-b-plan-semantic-contract.mjs";
import {
  assertStageBProviderResourceShapeUniverse,
  assertStageBProviderSemanticSnapshot,
  STAGE_B_PROVIDER_RESOURCE_SCHEMA_COMPLETE,
  STAGE_B_PROVIDER_RESOURCE_SHAPE_UNIVERSE,
  STAGE_B_PROVIDER_SEMANTIC_SNAPSHOT,
} from "../aws/stage-b-provider-semantic-snapshot.mjs";
import { assertRecoveryPlanDelta } from "../aws/stage-b-partial-apply-recovery-contract.mjs";
import { assertStageBBrokerFunctionUpdate, classifyStageBPlan, STAGE_B_BROKER_PUBLISH_PROVIDER_METADATA_FIELDS, STAGE_B_BROKER_PUBLISH_PROVIDER_UNKNOWN_METADATA_FIELDS } from "../aws/stage-b-deployment-contract.mjs";
import { STAGE_B_TASK_DEFINITION_FAMILIES } from "../aws/stage-b-reference-audit-contract.mjs";
import { STAGE_B } from "../aws/production-green-stage-b-contract.mjs";

const addresses = Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES);
const BROKER_INITIAL_ADDRESSES = new Set(["aws_iam_policy.broker", "aws_lambda_function.broker", "aws_lambda_alias.reviewed"]);
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
    runtime_platform: [{ operating_system_family: "LINUX", cpu_architecture: "X86_64" }],
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
  const before = { architectures: ["x86_64"], environment: [{ variables: Object.fromEntries(envNames.map((name) => [name, `old-${name}`])) }], filename: "old.zip", source_code_hash: "old-source-code-hash", code_sha256: "old-code-sha", source_code_size: 100, last_modified: "old", qualified_arn: "old", qualified_invoke_arn: "old", version: 2 };
  const after = { architectures: ["x86_64"], environment: [{}], filename: "new.zip", source_code_hash: "new-source-code-hash" };
  const lambda = { address: "aws_lambda_function.broker", mode: "managed", type: "aws_lambda_function", change: { actions: ["update"], before, after, after_unknown: { architectures: [false], code_sha256: true, environment: [{ variables: true }], last_modified: true, qualified_arn: true, qualified_invoke_arn: true, source_code_size: true, version: true }, before_sensitive: { architectures: [false] }, after_sensitive: { architectures: [false] } } };
  const alias = { address: "aws_lambda_alias.reviewed", mode: "managed", type: "aws_lambda_alias", change: { actions: ["update"], before: { function_version: "2", routing_config: [] }, after: { routing_config: [] }, after_unknown: { function_version: true, routing_config: [] }, before_sensitive: { routing_config: [] }, after_sensitive: { routing_config: [] } } };
  return [policy, lambda, alias];
}

function plan() {
  return { configuration: configuration(), resource_changes: [...addresses.map((address, index) => taskChange(address, index + 1)), ...brokerChanges()] };
}

function recoveryPlan() {
  const value = structuredClone(plan());
  value.variables = {
    stage_b_recovery_only: { value: true },
    stage_b_recovery_alias_target_version: { value: "3" },
  };
  value.resource_changes = [value.resource_changes.find((item) => item.address === "aws_lambda_alias.reviewed")];
  const alias = value.resource_changes[0];
  alias.change.after.function_version = "3";
  delete alias.change.after_unknown.function_version;
  value.configuration.root_module.resources.find((item) => item.address === "aws_lambda_alias.reviewed")
    .expressions.function_version = ref([
      "aws_lambda_function.broker",
      "aws_lambda_function.broker.version",
      "var.stage_b_recovery_alias_target_version",
      "var.stage_b_recovery_only",
    ]);
  return value;
}

function productionForensicPlan() {
  const value = structuredClone(plan());
  const change = value.resource_changes.find((item) => item.address === "aws_lambda_function.broker").change;
  change.before.filename = "/private/tmp/stage-b-release.axLefW/broker.zip";
  change.after.filename = "/private/tmp/stage-b-artifacts-ebe6dc8.nqJe40/broker.zip";
  change.before.source_code_hash = "ae1k3DKou3501fyfAJR7SZNJRtiqM2gNtSY+Q30DkQo=";
  change.after.source_code_hash = change.before.source_code_hash;
  change.before.code_sha256 = change.before.source_code_hash;
  change.after.code_sha256 = change.before.code_sha256;
  change.before.source_code_size = 5086022;
  change.after.source_code_size = change.before.source_code_size;
  delete change.after_unknown.code_sha256;
  delete change.after_unknown.source_code_size;
  return value;
}

function baselinePlan() {
  const value = JSON.parse(fs.readFileSync("scripts/tests/fixtures/production-green-stage-b-production-shaped.plan.json", "utf8"));
  value.configuration = configuration();
  const tags = { Component: "full-rls-green-stage-b", Environment: "production", ManagedBy: "Terraform" };
  const policy = value.resource_changes.find((change) => change.address === "aws_iam_policy.broker");
  policy.change = { actions: ["create"], before: null, after: { description: null, name: "mscqr-production-rls-approval-broker-runtime", name_prefix: null, path: "/", tags, tags_all: { ...tags } }, after_unknown: { arn: true, attachment_count: true, id: true, policy: true, policy_id: true, tags: {}, tags_all: {} }, before_sensitive: {}, after_sensitive: {} };
  const lambda = value.resource_changes.find((change) => change.address === "aws_lambda_function.broker");
  lambda.change = {
    actions: ["create"],
    before: null,
    after: {
      function_name: "mscqr-production-rls-approval-broker", role: "arn:aws:iam::368992683803:role/mscqr-production-rls-approval-broker",
      handler: "index.handler", runtime: "nodejs24.x", filename: "/private/tmp/broker.zip", source_code_hash: "baseline-source-code-hash",
      memory_size: 128, package_type: "Zip", reserved_concurrent_executions: -1, skip_destroy: false, timeout: 30, publish: true, region: "eu-west-2",
      environment: [{}], tags, tags_all: { ...tags },
    },
    after_unknown: { architectures: [true], arn: true, code_sha256: true, environment: [{ variables: true }], id: true, invoke_arn: true, last_modified: true, qualified_arn: true, qualified_invoke_arn: true, response_streaming_invoke_arn: true, signing_job_arn: true, signing_profile_version_arn: true, source_code_size: true, version: true },
    before_sensitive: {}, after_sensitive: { architectures: [true] },
  };
  const alias = value.resource_changes.find((change) => change.address === "aws_lambda_alias.reviewed");
  alias.change = {
    actions: ["create"], before: null,
    after: { description: null, name: "reviewed", function_name: "mscqr-production-rls-approval-broker", region: "eu-west-2", routing_config: [], timeouts: null },
    after_unknown: { arn: true, function_version: true, id: true, invoke_arn: true, routing_config: [] }, before_sensitive: {}, after_sensitive: {},
  };
  for (const [index, change] of value.resource_changes.filter((item) => addresses.includes(item.address)).entries()) {
    const typed = taskChange(change.address, index + 1).change;
    for (const field of ["ephemeral_storage", "ipc_mode", "network_mode", "pid_mode", "placement_constraints", "proxy_configuration", "region", "skip_destroy", "tags_all", "track_latest", "volume"]) {
      if (typed.after[field] !== undefined && field !== "tags_all") change.change.after[field] = structuredClone(typed.after[field]);
    }
    change.change.after.tags_all = { ...tags };
    for (const field of ["ephemeral_storage", "placement_constraints", "proxy_configuration", "requires_compatibilities", "runtime_platform", "tags", "tags_all", "volume"]) {
      if (typed.after_unknown[field] !== undefined) change.change.after_unknown[field] = structuredClone(typed.after_unknown[field]);
    }
  }
  for (const change of value.resource_changes) if (change.change?.actions?.some((action) => action !== "no-op")) change.mode = "managed";
  return value;
}

function canonicalBrokerPolicy() {
  const taskDefinitionArn = (family) => `arn:aws:ecs:${STAGE_B.region}:${STAGE_B.account}:task-definition/${family}:1`;
  const executorFamilies = addresses.filter((address) => address.includes(".executor[")).map((address) => STAGE_B_TASK_DEFINITION_FAMILIES[address]);
  return {
    Version: "2012-10-17",
    Statement: [
      { Sid: "RunOnlyApprovedExecutorAndCanaryRevisions", Effect: "Allow", Action: ["ecs:RunTask"], Resource: [STAGE_B_TASK_DEFINITION_FAMILIES['aws_ecs_task_definition.candidate["canary"]'], ...executorFamilies].map(taskDefinitionArn) },
      { Sid: "PassOnlyApprovedTaskRoles", Effect: "Allow", Action: ["iam:PassRole"], Resource: [STAGE_B.executorRoleArn, STAGE_B.executorExecutionRoleArn, "arn:aws:iam::368992683803:role/mscqr-production-rls-green-canary-task", "arn:aws:iam::368992683803:role/mscqr-production-rls-green-canary-execution"], Condition: { StringEquals: { "iam:PassedToService": "ecs-tasks.amazonaws.com" } } },
      { Sid: "ClaimOnlyStageBReplayRows", Effect: "Allow", Action: ["dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:UpdateItem"], Resource: "arn:aws:dynamodb:eu-west-2:368992683803:table/mscqr-production-rls-stage-b-replay" },
      { Sid: "ReadOnlyStageAApproval", Effect: "Allow", Action: ["secretsmanager:GetSecretValue"], Resource: STAGE_B.approvalSecretArn },
      { Sid: "VerifyOnlyStageAApprovalKey", Effect: "Allow", Action: ["kms:Verify"], Resource: STAGE_B.approvalKmsKeyArn },
      { Sid: "WriteOnlyBrokerReceipts", Effect: "Allow", Action: ["s3:PutObject"], Resource: `arn:aws:s3:::${STAGE_B.receiptBucket}/rls-broker-receipts/*` },
      { Sid: "WriteOnlyStageABrokerLogs", Effect: "Allow", Action: ["logs:CreateLogStream", "logs:PutLogEvents"], Resource: "arn:aws:logs:eu-west-2:368992683803:log-group:/aws/lambda/mscqr-production-rls-approval-broker:log-stream:*" },
    ],
  };
}

function resolvedBrokerEnvironment() {
  const taskDefinitions = Object.fromEntries([
    ["full-rls-application-canary", STAGE_B_TASK_DEFINITION_FAMILIES['aws_ecs_task_definition.candidate["canary"]']],
    ...addresses.filter((address) => address.includes(".executor[")).map((address) => [address.match(/\["([^"]+)"\]$/)[1], STAGE_B_TASK_DEFINITION_FAMILIES[address]]),
  ].map(([mode, family]) => [mode, `arn:aws:ecs:${STAGE_B.region}:${STAGE_B.account}:task-definition/${family}:1`]));
  return {
    BROKER_APPROVAL_EXPECTED_JSON: JSON.stringify({ releaseSha: "a".repeat(40), sourceContractSha256: "b".repeat(64), migrationSetDigest: "c".repeat(64), packageChecksumSha256: "d".repeat(64), deploymentId: "phase2", greenDatabaseName: "mscqr_production_rls_green_phase2", administratorIdentity: "mscqr_prod_admin", databaseSecurityGroupId: STAGE_B.databaseSecurityGroupId, executorSecurityGroupId: STAGE_B.executorSecurityGroupId }),
    BROKER_APPROVAL_SECRET_ARN: STAGE_B.approvalSecretArn,
    BROKER_CLUSTER_ARN: STAGE_B.clusterArn,
    BROKER_EXECUTOR_SECURITY_GROUP_ID: STAGE_B.executorSecurityGroupId,
    BROKER_IMAGES_JSON: JSON.stringify({ backendImageDigest: image("1"), workerImageDigest: image("2"), executorImageDigest: image("3"), canaryImageDigest: image("4") }),
    BROKER_PRIVATE_SUBNETS_JSON: JSON.stringify(STAGE_B.privateSubnetIds),
    BROKER_RECEIPT_BUCKET: STAGE_B.receiptBucket,
    BROKER_REPLAY_TABLE: "mscqr-production-rls-stage-b-replay",
    BROKER_TASK_DEFINITIONS_JSON: JSON.stringify(taskDefinitions),
    BROKER_TASK_TEMPLATE_HASHES_JSON: JSON.stringify({ backend: "e".repeat(64), worker: "f".repeat(64), executor: "1".repeat(64), canary: "2".repeat(64) }),
  };
}

function dependencyResolvedRetryPlan() {
  const value = baselinePlan();
  for (const change of value.resource_changes.filter((item) => addresses.includes(item.address))) {
    change.change.actions = ["no-op"];
    change.change.before = structuredClone(change.change.after);
    delete change.change.after_unknown;
  }
  const policy = value.resource_changes.find((change) => change.address === "aws_iam_policy.broker").change;
  policy.after.policy = JSON.stringify(canonicalBrokerPolicy());
  policy.after_unknown.policy = false;
  const lambda = value.resource_changes.find((change) => change.address === "aws_lambda_function.broker").change;
  lambda.after.environment = [{ variables: resolvedBrokerEnvironment() }];
  lambda.after_unknown.environment = [{ variables: false }];
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
    changedPaths: 117,
    afterUnknownPaths: 79,
    replacePaths: 12,
    configurationReferences: 117,
    unclassifiedResourceActions: 0,
    unclassifiedChangedPaths: 0,
    unclassifiedAfterUnknownPaths: 0,
    unclassifiedReplacePaths: 0,
    unclassifiedConfigurationReferences: 0,
    unfaithfulProviderComputedFields: 0,
    unmodeledTypedAfterFields: 0,
    unmodeledAfterUnknownMarkers: 0,
    unmodeledEmptyStructures: 0,
    missingTypedRepresentationClassifications: 0,
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
    changedPaths: 386,
    afterUnknownPaths: 93,
    replacePaths: 0,
    configurationReferences: 117,
    unclassifiedResourceActions: 0,
    unclassifiedChangedPaths: 0,
    unclassifiedAfterUnknownPaths: 0,
    unclassifiedReplacePaths: 0,
    unclassifiedConfigurationReferences: 0,
    unfaithfulProviderComputedFields: 0,
    unmodeledTypedAfterFields: 0,
    unmodeledAfterUnknownMarkers: 0,
    unmodeledEmptyStructures: 0,
    missingTypedRepresentationClassifications: 0,
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

test("baseline ECS runtime platform uses the provider list shape and indexed semantic paths", () => {
  const value = baselinePlan();
  const ecs = value.resource_changes.filter((change) => addresses.includes(change.address));
  assert.equal(ecs.length, 12);
  for (const change of ecs) {
    assert.deepEqual(change.change.after.runtime_platform, [{ operating_system_family: "LINUX", cpu_architecture: "X86_64" }]);
    assert.doesNotThrow(() => assertStageBPlanSemanticCompleteness(structuredClone(value)));
  }
  const census = assertStageBPlanSemanticCompleteness(value);
  for (const resource of census.resources.filter((item) => addresses.includes(item.address))) {
    assert.deepEqual(resource.changedPaths.filter(({ path }) => path.startsWith("runtime_platform")), [
      { path: "runtime_platform[0].cpu_architecture", classification: "REVIEWED_CONCRETE_CHANGE" },
      { path: "runtime_platform[0].operating_system_family", classification: "REVIEWED_CONCRETE_CHANGE" },
    ]);
  }
});

test("baseline runtime platform rejects object, unindexed, extra, and multi-element shapes", () => {
  const mutateBaseline = (mutator) => {
    const value = baselinePlan();
    mutator(value.resource_changes.filter((change) => addresses.includes(change.address))[0]);
    assert.throws(() => assertStageBPlanSemanticCompleteness(value), /UNFAITHFUL_SUPPORTED_PROFILE_FIXTURES|UNCLASSIFIED_CHANGED_PATH/);
  };
  mutateBaseline((change) => { change.change.after.runtime_platform = { operating_system_family: "LINUX", cpu_architecture: "X86_64" }; });
  mutateBaseline((change) => { change.change.after.runtime_platform[0].unexpected = "value"; });
  mutateBaseline((change) => { change.change.after.runtime_platform.push({ operating_system_family: "LINUX", cpu_architecture: "X86_64" }); });
  mutateBaseline((change) => { delete change.change.after.runtime_platform; });
  mutateBaseline((change) => { change.change.after.runtime_platform[0].operating_system_family = "WINDOWS_SERVER_2022_CORE"; });
  mutateBaseline((change) => { change.change.after.runtime_platform[0].cpu_architecture = "ARM64"; });
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
    change.change.after.runtime_platform = [{ operating_system_family: "LINUX", cpu_architecture: "X86_64" }];
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

test("dependency-resolved partial initial apply retry permits only exact concrete broker values", () => {
  const retry = dependencyResolvedRetryPlan();
  const census = assertStageBPlanSemanticCompleteness(retry);
  assert.equal(census.resources.length, 3);
  assert.deepEqual(census.resources.map((item) => item.classification).sort(), [
    STAGE_B_PLAN_SEMANTIC_PROFILES.BROKER_ALIAS_INITIAL_CREATE,
    STAGE_B_PLAN_SEMANTIC_PROFILES.BROKER_FUNCTION_INITIAL_CREATE,
    STAGE_B_PLAN_SEMANTIC_PROFILES.BROKER_POLICY_INITIAL_CREATE,
  ].sort());
  const policy = structuredClone(retry);
  const policyDocument = canonicalBrokerPolicy();
  policyDocument.Statement[0].Action = ["iam:DeleteRole"];
  policy.resource_changes.find((change) => change.address === "aws_iam_policy.broker").change.after.policy = JSON.stringify(policyDocument);
  assert.throws(() => assertStageBPlanSemanticCompleteness(policy), /UNCLASSIFIED_CHANGED_PATH/);
  for (const mutatePolicy of [
    (document) => { document.Statement[0].Resource[0] = "arn:aws:ecs:eu-west-2:368992683803:task-definition/unrelated:1"; },
    (document) => { document.Statement[0].Resource = "*"; },
    (document) => { document.Statement.pop(); },
  ]) {
    const invalidPolicy = structuredClone(retry);
    const document = canonicalBrokerPolicy();
    mutatePolicy(document);
    invalidPolicy.resource_changes.find((change) => change.address === "aws_iam_policy.broker").change.after.policy = JSON.stringify(document);
    assert.throws(() => assertStageBPlanSemanticCompleteness(invalidPolicy), /UNCLASSIFIED_CHANGED_PATH/);
  }
  const environment = structuredClone(retry);
  const variables = environment.resource_changes.find((change) => change.address === "aws_lambda_function.broker").change.after.environment[0].variables;
  variables.BROKER_TASK_DEFINITIONS_JSON = JSON.stringify({ ...JSON.parse(variables.BROKER_TASK_DEFINITIONS_JSON), "full-rls-application-canary": "arn:aws:ecs:eu-west-2:368992683803:task-definition/unrelated:1" });
  assert.throws(() => assertStageBPlanSemanticCompleteness(environment), /UNCLASSIFIED_CHANGED_PATH/);
  for (const mutateEnvironment of [
    (value) => { delete value.BROKER_TASK_DEFINITIONS_JSON; },
    (value) => { value.UNEXPECTED = "nope"; },
  ]) {
    const invalidEnvironment = structuredClone(retry);
    const target = invalidEnvironment.resource_changes.find((change) => change.address === "aws_lambda_function.broker").change.after.environment[0].variables;
    mutateEnvironment(target);
    assert.throws(() => assertStageBPlanSemanticCompleteness(invalidEnvironment), /UNCLASSIFIED_CHANGED_PATH/);
  }
});

test("dependency-computed broker paths resolve independently", () => {
  const policyResolved = dependencyResolvedRetryPlan();
  const lambda = policyResolved.resource_changes.find((change) => change.address === "aws_lambda_function.broker").change;
  lambda.after.environment = [{}];
  lambda.after_unknown.environment = [{ variables: true }];
  assert.doesNotThrow(() => assertStageBPlanSemanticCompleteness(policyResolved));

  const environmentResolved = dependencyResolvedRetryPlan();
  const policy = environmentResolved.resource_changes.find((change) => change.address === "aws_iam_policy.broker").change;
  delete policy.after.policy;
  policy.after_unknown.policy = true;
  assert.doesNotThrow(() => assertStageBPlanSemanticCompleteness(environmentResolved));
});

test("dependency-computed broker values require exactly one resolved representation", () => {
  const policyMissing = dependencyResolvedRetryPlan();
  const policyChange = policyMissing.resource_changes.find((change) => change.address === "aws_iam_policy.broker").change;
  delete policyChange.after.policy;
  delete policyChange.after_unknown.policy;
  assert.throws(() => assertStageBPlanSemanticCompleteness(policyMissing), /UNFAITHFUL_PROVIDER_COMPUTED_FIELDS/);
  const policyBoth = dependencyResolvedRetryPlan();
  policyBoth.resource_changes.find((change) => change.address === "aws_iam_policy.broker").change.after_unknown.policy = true;
  assert.throws(() => assertStageBPlanSemanticCompleteness(policyBoth), /UNFAITHFUL_PROVIDER_COMPUTED_FIELDS/);
  const providerIdentifierConcrete = dependencyResolvedRetryPlan();
  providerIdentifierConcrete.resource_changes.find((change) => change.address === "aws_iam_policy.broker").change.after.arn = "arn:aws:iam::368992683803:policy/mscqr-production-rls-approval-broker-runtime";
  assert.throws(() => assertStageBPlanSemanticCompleteness(providerIdentifierConcrete), /UNFAITHFUL_PROVIDER_COMPUTED_FIELDS/);
  const providerIdentifierMissing = dependencyResolvedRetryPlan();
  delete providerIdentifierMissing.resource_changes.find((change) => change.address === "aws_iam_policy.broker").change.after_unknown.arn;
  assert.throws(() => assertStageBPlanSemanticCompleteness(providerIdentifierMissing), /UNFAITHFUL_PROVIDER_COMPUTED_FIELDS/);
  const environmentMissing = dependencyResolvedRetryPlan();
  const lambda = environmentMissing.resource_changes.find((change) => change.address === "aws_lambda_function.broker").change;
  delete lambda.after.environment;
  delete lambda.after_unknown.environment;
  assert.throws(() => assertStageBPlanSemanticCompleteness(environmentMissing), /UNCLASSIFIED_CHANGED_PATH/);
  const environmentBoth = dependencyResolvedRetryPlan();
  environmentBoth.resource_changes.find((change) => change.address === "aws_lambda_function.broker").change.after_unknown.environment = [{ variables: true }];
  assert.throws(() => assertStageBPlanSemanticCompleteness(environmentBoth), /UNCLASSIFIED_CHANGED_PATH/);
});

test("typed Terraform envelope admits exact nulls, false markers, and resolved dependencies only", () => {
  const retry = dependencyResolvedRetryPlan();
  const census = assertStageBPlanSemanticCompleteness(retry);
  const policyCensus = census.resources.find((item) => item.address === "aws_iam_policy.broker");
  const lambdaCensus = census.resources.find((item) => item.address === "aws_lambda_function.broker");
  assert.equal(policyCensus.afterUnknownPaths.some(({ path }) => path === "policy"), false);
  assert.equal(lambdaCensus.afterUnknownPaths.some(({ path }) => path === "environment[0].variables"), false);

  const rejectBaseline = (mutator, expected = /UNFAITHFUL|UNCLASSIFIED|UNMODELED/) => {
    const value = baselinePlan();
    mutator(value);
    assert.throws(() => assertStageBPlanSemanticCompleteness(value), expected);
  };
  rejectBaseline((value) => { value.resource_changes.find((item) => item.address === "aws_iam_policy.broker").change.after.description = "unexpected"; });
  rejectBaseline((value) => { value.resource_changes.find((item) => item.address === "aws_iam_policy.broker").change.after.name_prefix = "unexpected"; });
  rejectBaseline((value) => { value.resource_changes.find((item) => item.address === "aws_iam_policy.broker").change.after.unreviewed = null; });
  rejectBaseline((value) => { value.resource_changes.find((item) => item.address === "aws_lambda_alias.reviewed").change.after.routing_config = [{ additional_version_weights: { other: 1 } }]; });
  rejectBaseline((value) => { value.resource_changes.find((item) => item.address === "aws_lambda_alias.reviewed").change.after.timeouts = { create: "1m" }; });

  const contradictoryPolicy = structuredClone(retry);
  contradictoryPolicy.resource_changes.find((item) => item.address === "aws_iam_policy.broker").change.after_unknown.policy = true;
  assert.throws(() => assertStageBPlanSemanticCompleteness(contradictoryPolicy), /UNFAITHFUL|UNCLASSIFIED/);
  const contradictoryEnvironment = structuredClone(retry);
  contradictoryEnvironment.resource_changes.find((item) => item.address === "aws_lambda_function.broker").change.after_unknown.environment = [{ variables: true }];
  assert.throws(() => assertStageBPlanSemanticCompleteness(contradictoryEnvironment), /UNFAITHFUL|UNCLASSIFIED/);
});

test("supported profile matrix is explicit and includes baseline broker creation", () => {
  assert.deepEqual(STAGE_B_SUPPORTED_PLAN_PROFILES.map(({ profile }) => profile), [
    "BASELINE_INITIAL_CREATE", "ROLLOVER_RECOVERY", "RECOVERY_ALIAS_ONLY", "NO_CHANGE_OR_APPEND_ONLY_RETRY",
  ]);
  assert.deepEqual(STAGE_B_SUPPORTED_PLAN_PROFILES[0].brokerPolicyActions, [["create"]]);
  assert.deepEqual(STAGE_B_SUPPORTED_PLAN_PROFILES[0].brokerFunctionActions, [["create"]]);
  assert.deepEqual(STAGE_B_SUPPORTED_PLAN_PROFILES[0].brokerAliasActions, [["create"]]);
  assert.deepEqual(STAGE_B_SUPPORTED_PLAN_PROFILES[3].brokerPolicyActions, [["create"], ["no-op"]]);
});

test("recovery-only semantic profile contains only the exact concrete alias target", () => {
  const census = assertStageBPlanSemanticCompleteness(recoveryPlan());
  assert.equal(census.counts.unclassifiedConfigurationReferences, 0);
  assert.deepEqual(census.resources[0].configurationReferences, [{
    field: "function_name",
    references: ["aws_lambda_function.broker", "aws_lambda_function.broker.function_name"].sort(),
    classification: "STABLE_REQUIRED",
  }, {
    field: "function_version",
    references: [
      "aws_lambda_function.broker",
      "aws_lambda_function.broker.version",
      "var.stage_b_recovery_alias_target_version",
      "var.stage_b_recovery_only",
    ],
    classification: "REVIEWED_CONCRETE_CHANGE",
  }]);
});

test("recovery alias reference classification is profile-bound and fail-closed", () => {
  const normalWithRecoveryReference = plan();
  normalWithRecoveryReference.configuration.root_module.resources.find((item) => item.address === "aws_lambda_alias.reviewed")
    .expressions.function_version = ref(["var.stage_b_recovery_alias_target_version"]);
  assert.throws(() => assertStageBPlanSemanticCompleteness(normalWithRecoveryReference), /UNCLASSIFIED_CONFIGURATION_REFERENCES/);

  for (const references of [
    ["var.other_version"],
    ["aws_lambda_function.other.version"],
    ["var.stage_b_recovery_alias_target_version", "aws_lambda_function.broker.version"],
    [
      "aws_lambda_function.broker",
      "aws_lambda_function.broker.version",
      "var.stage_b_recovery_alias_target_version",
      "var.stage_b_recovery_only",
      "var.unreviewed",
    ],
  ]) {
    const invalid = recoveryPlan();
    invalid.configuration.root_module.resources.find((item) => item.address === "aws_lambda_alias.reviewed")
      .expressions.function_version = ref(references);
    assert.throws(() => assertStageBPlanSemanticCompleteness(invalid), /UNCLASSIFIED_CONFIGURATION_REFERENCES/);
  }

  const recoveryWithNormalReference = recoveryPlan();
  recoveryWithNormalReference.configuration.root_module.resources.find((item) => item.address === "aws_lambda_alias.reviewed")
    .expressions.function_version = ref(["aws_lambda_function.broker.version"]);
  assert.throws(() => assertStageBPlanSemanticCompleteness(recoveryWithNormalReference), /UNCLASSIFIED_CONFIGURATION_REFERENCES/);
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
  assert.throws(() => assertStageBPlanSemanticCompleteness(concrete), /UNFAITHFUL_PROVIDER_COMPUTED_FIELDS|UNCLASSIFIED_CHANGED_PATH/);
  mutateBaseline((value) => { delete value.resource_changes.find((change) => change.address === "aws_lambda_function.broker").change.after_unknown.environment[0].variables; }, /UNFAITHFUL_PROVIDER_COMPUTED_FIELDS|UNCLASSIFIED_(?:AFTER_UNKNOWN|CHANGED_PATH)/);
  mutateBaseline((value) => { value.resource_changes.find((change) => change.address === "aws_lambda_function.broker").change.after_unknown.environment[0].unexpected = true; }, /UNFAITHFUL_PROVIDER_COMPUTED_FIELDS|UNCLASSIFIED_(?:AFTER_UNKNOWN|CHANGED_PATH)/);
  mutateBaseline((value) => { value.resource_changes.find((change) => change.address === "aws_lambda_function.broker").change.after.environment[0].unexpected = {}; }, /UNFAITHFUL_(?:PROVIDER_COMPUTED_FIELDS|SUPPORTED_PROFILE_FIXTURES)|UNCLASSIFIED_CHANGED_PATH/);
  mutateBaseline((value) => { value.resource_changes.find((change) => change.address === "aws_lambda_function.broker").change.after.environment.push({}); }, /UNFAITHFUL_(?:PROVIDER_COMPUTED_FIELDS|SUPPORTED_PROFILE_FIXTURES)|UNCLASSIFIED_CHANGED_PATH/);
  mutateBaseline((value) => { const change = value.resource_changes.find((item) => item.address === "aws_lambda_function.broker").change; change.after.environment = [{ variables: { BROKER_TASK_DEFINITIONS_JSON: "concrete" } }]; }, /UNFAITHFUL_PROVIDER_COMPUTED_FIELDS|UNCLASSIFIED_CHANGED_PATH/);
  mutateBaseline((value) => { const change = value.resource_changes.find((item) => item.address === "aws_lambda_function.broker").change; change.after.environment = [{ variables: {} }]; change.after_unknown.environment = [{ variables: true }]; }, /UNFAITHFUL_PROVIDER_COMPUTED_FIELDS|UNCLASSIFIED_CHANGED_PATH/);
});

test("initial broker Lambda uses exact default and optional-computed provider shapes", () => {
  const lambdaChange = (value) => value.resource_changes.find((change) => change.address === "aws_lambda_function.broker").change;
  assert.doesNotThrow(() => assertStageBPlanSemanticCompleteness(baselinePlan()));
  for (const mutate of [
    (change) => { delete change.after.memory_size; },
    (change) => { change.after.memory_size = 256; },
    (change) => { delete change.after.package_type; },
    (change) => { change.after.package_type = "Image"; },
    (change) => { change.after.reserved_concurrent_executions = 1; },
    (change) => { change.after.skip_destroy = true; },
    (change) => { delete change.after.code_sha256; delete change.after_unknown.code_sha256; },
    (change) => { change.after.code_sha256 = "provider-output"; delete change.after_unknown.code_sha256; },
    (change) => { delete change.after.source_code_hash; change.after_unknown.source_code_hash = true; },
    (change) => { change.after.tags_all.ManagedBy = "unreviewed"; },
    (change) => { delete change.after.region; },
    (change) => { change.after_unknown.unreviewed_optional = true; },
  ]) {
    const value = baselinePlan();
    mutate(lambdaChange(value));
    assert.throws(() => assertStageBPlanSemanticCompleteness(value), /UNFAITHFUL_PROVIDER_COMPUTED_FIELDS|UNCLASSIFIED_/);
  }
});

test("initial representation-only changed paths derive from the typed manifest", () => {
  assert.deepEqual([...initialRepresentationOnlyPaths("aws_lambda_function")].sort(), [
    "capacity_provider_config", "code_signing_config_arn", "dead_letter_config", "description", "durable_config",
    "ephemeral_storage", "file_system_config", "image_config", "image_uri", "kms_key_arn", "layers", "logging_config", "memory_size",
    "package_type", "publish_to", "region", "replace_security_groups_on_destroy", "replacement_security_group_ids",
    "reserved_concurrent_executions", "s3_bucket", "s3_key", "s3_object_version", "skip_destroy", "snap_start",
    "source_kms_key_arn", "tags_all", "tenancy_config", "timeouts", "tracing_config", "use_resource_timeout_for_propagation", "vpc_config",
  ].sort());
  assert.deepEqual([...initialRepresentationOnlyPaths("aws_lambda_alias")].sort(), ["description", "region", "routing_config", "timeouts"].sort());
  assert.deepEqual([...initialRepresentationOnlyPaths("aws_iam_policy")].sort(), ["delay_after_policy_creation_in_ms", "description", "name_prefix", "tags_all"].sort());
  const census = assertStageBPlanSemanticCompleteness(baselinePlan());
  for (const resource of census.resources.filter(({ address }) => BROKER_INITIAL_ADDRESSES.has(address))) {
    for (const { path, classification } of resource.changedPaths) {
      const field = /^([^.[\]]+)/.exec(path)?.[1];
      if (initialRepresentationOnlyPaths(resource.type).has(field)) assert.equal(classification, "REVIEWED_PROVIDER_NORMALIZATION");
    }
  }
});

test("locked provider semantic snapshot is independently validated", () => {
  assert.doesNotThrow(() => assertStageBProviderSemanticSnapshot());
  const mutated = structuredClone(STAGE_B_PROVIDER_SEMANTIC_SNAPSHOT);
  mutated.resources.aws_iam_policy.attributes.find((entry) => entry.attributePath === "arn").computed = false;
  assert.throws(() => assertStageBProviderSemanticSnapshot(mutated), /PROVIDER_SCHEMA_SEMANTICS_CHANGED/);
  const missing = structuredClone(STAGE_B_PROVIDER_SEMANTIC_SNAPSHOT);
  missing.resources.aws_lambda_alias.attributes = missing.resources.aws_lambda_alias.attributes.filter((entry) => entry.attributePath !== "invoke_arn");
  assert.throws(() => assertStageBProviderSemanticSnapshot(missing), /PROVIDER_SCHEMA_SEMANTICS_CHANGED/);
  const wrongNesting = structuredClone(STAGE_B_PROVIDER_SEMANTIC_SNAPSHOT);
  wrongNesting.resources.aws_ecs_task_definition.blocks.find((entry) => entry.blockPath === "runtime_platform").nestingMode = "single";
  assert.throws(() => assertStageBProviderSemanticSnapshot(wrongNesting), /PROVIDER_SCHEMA_NESTING_CHANGED/);
});

test("typed representation manifest exhaustively disposes every provider top-level shape", () => {
  assert.deepEqual(assertStageBTypedRepresentationManifestComplete(), { missingTypedRepresentationClassifications: 0 });
});

test("complete provider resource shape universe matches extracted AWS 6.56.0 evidence", () => {
  const evidence = JSON.parse(fs.readFileSync("scripts/tests/fixtures/stage-b-provider-6.56.0-resource-shape.json", "utf8"));
  assert.doesNotThrow(() => assertStageBProviderResourceShapeUniverse());
  assert.deepEqual(STAGE_B_PROVIDER_RESOURCE_SHAPE_UNIVERSE, evidence);
  for (const type of ["aws_iam_policy", "aws_lambda_function", "aws_lambda_alias", "aws_ecs_task_definition"]) {
    assert.equal(STAGE_B_PROVIDER_RESOURCE_SCHEMA_COMPLETE[type], true);
    assert.ok(STAGE_B_PROVIDER_RESOURCE_SHAPE_UNIVERSE.resources[type].attributes.length > 0);
    assert.ok(STAGE_B_PROVIDER_RESOURCE_SHAPE_UNIVERSE.resources[type].blocks.every((block) => typeof block.nestingMode === "string"));
  }
});

test("provider-known Lambda unset fields are representation-valid but meaningful values fail", () => {
  const value = baselinePlan();
  const lambda = value.resource_changes.find((change) => change.address === "aws_lambda_function.broker");
  lambda.change.after.description = null;
  assert.doesNotThrow(() => assertStageBPlanSemanticCompleteness(value));
  lambda.change.after.description = "unexpected";
  assert.throws(() => assertStageBPlanSemanticCompleteness(value), /UNFAITHFUL_PROVIDER_COMPUTED_FIELDS|UNCLASSIFIED_CHANGED_PATH/);
});

test("supported nested blocks retain their provider JSON shapes", () => {
  const baseline = baselinePlan();
  for (const change of baseline.resource_changes.filter((item) => addresses.includes(item.address))) {
    assert.ok(Array.isArray(change.change.after.runtime_platform));
    assert.equal(change.change.after.runtime_platform.length, 1);
  }
  const rollover = plan();
  const task = rollover.resource_changes.find((item) => addresses.includes(item.address));
  assert.ok(Array.isArray(task.change.before.runtime_platform));
  assert.ok(Array.isArray(task.change.after.runtime_platform));
  assert.ok(Array.isArray(task.change.after.ephemeral_storage));
  assert.ok(Array.isArray(task.change.after.placement_constraints));
  assert.ok(Array.isArray(task.change.after.proxy_configuration));
  assert.ok(Array.isArray(task.change.after.volume));
  assert.ok(Array.isArray(rollover.resource_changes.find((item) => item.address === "aws_lambda_function.broker").change.after.environment));
  assert.ok(Array.isArray(rollover.resource_changes.find((item) => item.address === "aws_lambda_alias.reviewed").change.after.routing_config));
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
  mutate((value) => { value.resource_changes.find((item) => item.address === "aws_lambda_function.broker").change.after_unknown.version = false; }, /UNCLASSIFIED_COMPUTED_CHANGE|UNFAITHFUL_PROVIDER_COMPUTED_FIELDS/);
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

test("broker publish updates admit source-bound package digest and exact provider code metadata", () => {
  const census = assertStageBPlanSemanticCompleteness(plan());
  const broker = census.resources.find((item) => item.address === "aws_lambda_function.broker");
  assert.deepEqual(broker.changedPaths.find(({ path }) => path === "source_code_hash"), {
    path: "source_code_hash", classification: "CONFIGURATION_BOUND_PACKAGE_DIGEST",
  });
  const invalid = structuredClone(plan());
  invalid.configuration.root_module.resources.find((item) => item.address === "aws_lambda_function.broker").expressions.source_code_hash = ref(["var.other_package_path"]);
  assert.throws(() => assertStageBPlanSemanticCompleteness(invalid), /UNCLASSIFIED_CONFIGURATION_REFERENCES/);

  const metadata = structuredClone(plan());
  const change = metadata.resource_changes.find((item) => item.address === "aws_lambda_function.broker").change;
  assert.deepEqual(STAGE_B_BROKER_PUBLISH_PROVIDER_METADATA_FIELDS, ["code_sha256", "source_code_size", "last_modified", "qualified_arn", "qualified_invoke_arn", "version"]);
  assert.deepEqual(STAGE_B_BROKER_PUBLISH_PROVIDER_UNKNOWN_METADATA_FIELDS, STAGE_B_BROKER_PUBLISH_PROVIDER_METADATA_FIELDS);
  assert.doesNotThrow(() => assertStageBPlanSemanticCompleteness(metadata));
  assert.doesNotThrow(() => assertStageBBrokerFunctionUpdate(metadata.resource_changes.find((item) => item.address === "aws_lambda_function.broker")));
  const metadataCensus = assertStageBPlanSemanticCompleteness(metadata);
  assert.equal(metadataCensus.resources.find((item) => item.address === "aws_lambda_function.broker").changedPaths.filter(({ path }) => STAGE_B_BROKER_PUBLISH_PROVIDER_METADATA_FIELDS.includes(path)).every(({ classification }) => classification === "PROVIDER_COMPUTED_CODE_METADATA" || classification === "DIAGNOSTIC_ONLY"), true);

  const unauthorized = structuredClone(metadata);
  unauthorized.resource_changes.find((item) => item.address === "aws_lambda_function.broker").change.after.invoke_arn = "changed";
  assert.throws(() => assertStageBPlanSemanticCompleteness(unauthorized), /UNCLASSIFIED_CHANGED_PATH/);
  assert.throws(() => assertStageBBrokerFunctionUpdate(unauthorized.resource_changes.find((item) => item.address === "aws_lambda_function.broker")), /unsupported mutable field/);

  const concreteMetadata = structuredClone(metadata);
  const concreteChange = concreteMetadata.resource_changes.find((item) => item.address === "aws_lambda_function.broker").change;
  concreteChange.after.code_sha256 = "future-code-sha";
  delete concreteChange.after_unknown.code_sha256;
  assert.throws(() => assertStageBPlanSemanticCompleteness(concreteMetadata), /UNFAITHFUL_PROVIDER_COMPUTED_FIELDS/);
  const concreteSize = structuredClone(metadata);
  const concreteSizeChange = concreteSize.resource_changes.find((item) => item.address === "aws_lambda_function.broker").change;
  concreteSizeChange.after.source_code_size = 200;
  delete concreteSizeChange.after_unknown.source_code_size;
  assert.throws(() => assertStageBPlanSemanticCompleteness(concreteSize), /UNFAITHFUL_PROVIDER_COMPUTED_FIELDS/);

  const stable = structuredClone(metadata);
  const stableChange = stable.resource_changes.find((item) => item.address === "aws_lambda_function.broker").change;
  stableChange.after.code_sha256 = stableChange.before.code_sha256;
  stableChange.after.source_code_size = stableChange.before.source_code_size;
  delete stableChange.after_unknown.code_sha256;
  delete stableChange.after_unknown.source_code_size;
  assert.doesNotThrow(() => assertStageBPlanSemanticCompleteness(stable));
  assert.doesNotThrow(() => assertStageBBrokerFunctionUpdate(stable.resource_changes.find((item) => item.address === "aws_lambda_function.broker")));

  assert.doesNotThrow(() => assertStageBPlanSemanticCompleteness(productionForensicPlan()));
  const malformed = structuredClone(productionForensicPlan());
  const malformedChange = malformed.resource_changes.find((item) => item.address === "aws_lambda_function.broker").change;
  malformedChange.after.code_sha256 = 42;
  assert.throws(() => assertStageBPlanSemanticCompleteness(malformed), /UNFAITHFUL_PROVIDER_COMPUTED_FIELDS/);
  const missing = structuredClone(productionForensicPlan());
  const missingChange = missing.resource_changes.find((item) => item.address === "aws_lambda_function.broker").change;
  delete missingChange.after.code_sha256;
  assert.throws(() => assertStageBPlanSemanticCompleteness(missing), /UNFAITHFUL_PROVIDER_COMPUTED_FIELDS/);
  const contradiction = structuredClone(productionForensicPlan());
  const contradictionChange = contradiction.resource_changes.find((item) => item.address === "aws_lambda_function.broker").change;
  contradictionChange.after_unknown.code_sha256 = true;
  assert.throws(() => assertStageBPlanSemanticCompleteness(contradiction), /UNFAITHFUL_PROVIDER_COMPUTED_FIELDS/);
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
