import { STAGE_B, canonicalJson } from "./production-green-stage-b-contract.mjs";
import { assertStageBImportedBackendRolloverActions, assertStageBTaskDefinitionRotation, isStageBTaskDefinitionRotationActionsValue, STAGE_B_TASK_DEFINITION_FAMILIES } from "./stage-b-reference-audit-contract.mjs";

const exactActions = (actual, expected) => JSON.stringify(actual) === JSON.stringify(expected);
const exactJson = (left, right) => JSON.stringify(left) === JSON.stringify(right);
const taskDefinitionAddress = /^(aws_ecs_task_definition\.(candidate|executor))\["([^"]+)"\]$/;
const retainedTaskDefinitionAddress = /^aws_ecs_task_definition\.(candidate|executor)_retained\["([a-f0-9]{7,40})-([^"]+)"\]$/;
const importedBackendCandidateAddress = 'aws_ecs_task_definition.candidate["backend"]';
const importedBackendCandidateFamily = STAGE_B_TASK_DEFINITION_FAMILIES[importedBackendCandidateAddress];
const importedBackendCandidateArn = `arn:aws:ecs:${STAGE_B.region}:${STAGE_B.account}:task-definition/${importedBackendCandidateFamily}:9`;
export const STAGE_B_IMPORTED_BACKEND_METADATA_NORMALIZATION = "imported-backend-task-definition-metadata-normalization";
export const STAGE_B_IMPORTED_BACKEND_CANDIDATE_ADDRESS = importedBackendCandidateAddress;
const policyAddress = "aws_iam_policy.broker";
const attachmentAddress = "aws_iam_role_policy_attachment.broker";
const legacyInlineAddress = "aws_iam_role_policy.broker";

const stageBLogNames = Object.freeze({
  backend: "/ecs/mscqr-production/rls-green-backend",
  worker: "/ecs/mscqr-production/rls-green-worker",
  canary: "/ecs/mscqr-production/rls-green-canary",
  read_only_canary: "/ecs/mscqr-production/rls-green-read-only-canary",
});

const taskRoleNames = Object.freeze({
  backend: "mscqr-production-rls-green-backend-task",
  worker: "mscqr-production-rls-green-worker-task",
  canary: "mscqr-production-rls-green-canary-task",
  read_only_canary: "mscqr-production-full-rls-green-read-only-canary-task",
});

const executionRoleNames = Object.freeze({
  backend: "mscqr-production-rls-green-backend-execution",
  worker: "mscqr-production-rls-green-worker-execution",
  executor: "mscqr-production-full-rls-green-executor-execution",
  canary: "mscqr-production-rls-green-canary-execution",
  read_only_canary: "mscqr-production-full-rls-green-read-only-canary-execution",
});

const executionPolicyKeys = new Set(Object.keys(executionRoleNames));
const candidateStoragePolicyKeys = new Set(["backend", "worker", "canary"]);

export const STAGE_B_BACKEND_ECS_EXEC_INLINE_POLICY = Object.freeze({
  address: "aws_iam_role_policy.backend_ecs_exec",
  role: "mscqr-production-rls-green-backend-task",
  name: "stage-b-backend-ecs-exec-ssm-channels",
  document: Object.freeze({
    Version: "2012-10-17",
    Statement: Object.freeze([Object.freeze({
      Sid: "AllowEcsExecMessageChannels",
      Effect: "Allow",
      Action: Object.freeze([
        "ssmmessages:CreateControlChannel",
        "ssmmessages:CreateDataChannel",
        "ssmmessages:OpenControlChannel",
        "ssmmessages:OpenDataChannel",
      ]),
      Resource: "*",
    })]),
  }),
});

export function assertStageBBackendEcsExecPolicyChange(change, { strict = true } = {}) {
  if (change?.address !== STAGE_B_BACKEND_ECS_EXEC_INLINE_POLICY.address || change?.type !== "aws_iam_role_policy"
    || !["create", "no-op"].some((action) => exactActions(change.change?.actions, [action]))) {
    throw new Error("Stage B backend ECS Exec inline policy is outside the exact contract.");
  }
  const before = change.change?.before;
  const after = change.change?.after;
  if (exactActions(change.change?.actions, ["create"]) && before !== null && before !== undefined) {
    throw new Error("Stage B backend ECS Exec inline policy create has an unexpected predecessor.");
  }
  if (exactActions(change.change?.actions, ["no-op"]) && (!after || Object.keys(after).length === 0)) return true;
  if (!after || after.name !== STAGE_B_BACKEND_ECS_EXEC_INLINE_POLICY.name || after.role !== STAGE_B_BACKEND_ECS_EXEC_INLINE_POLICY.role) {
    throw new Error("Stage B backend ECS Exec inline policy identity is outside the exact contract.");
  }
  let document;
  try { document = JSON.parse(after.policy); } catch { throw new Error("Stage B backend ECS Exec inline policy document is malformed."); }
  if (canonicalJson(document) !== canonicalJson(STAGE_B_BACKEND_ECS_EXEC_INLINE_POLICY.document)) {
    throw new Error("Stage B backend ECS Exec inline policy document is outside the exact SSM-channel contract.");
  }
  if (strict && (document.Statement.length !== 1 || document.Statement[0].Condition !== undefined || document.Statement[0].NotAction !== undefined || document.Statement[0].NotResource !== undefined)) {
    throw new Error("Stage B backend ECS Exec inline policy contains an unsupported privilege form.");
  }
  return true;
}

export const STAGE_B_NORMAL_STATIC_RESOURCE_ADDRESSES = Object.freeze([
  ...Object.keys(stageBLogNames).map((key) => `aws_cloudwatch_log_group.stage_b["${key}"]`),
  ...Object.keys(executionRoleNames).map((key) => `aws_iam_role.execution["${key}"]`),
  ...Object.keys(taskRoleNames).map((key) => `aws_iam_role.task["${key}"]`),
  ...Object.keys(executionRoleNames).map((key) => `aws_iam_role_policy.execution["${key}"]`),
  ...[...candidateStoragePolicyKeys].map((key) => `aws_iam_role_policy.candidate_object_storage["${key}"]`),
  "aws_iam_role_policy.backend_ecs_exec",
  "aws_iam_role_policy.executor_runtime",
  "aws_dynamodb_table.replay",
  "aws_iam_policy.broker",
  "aws_iam_role_policy_attachment.broker",
  "aws_lambda_function.broker",
  "aws_lambda_alias.reviewed",
  "aws_lambda_permission.release_deployer",
].sort());

export const STAGE_B_BROKER_POLICY_STATEMENTS = Object.freeze([
  Object.freeze(["RunOnlyApprovedExecutorAndCanaryRevisions", Object.freeze(["ecs:RunTask"])]),
  Object.freeze(["RunOnlyApprovedPreDeploymentInventory", Object.freeze(["ecs:RunTask"])]),
  Object.freeze(["DescribeOnlyPreDeploymentInventoryTaskDefinitions", Object.freeze(["ecs:DescribeTaskDefinition"])]),
  Object.freeze(["ReadAndStopOnlyPreDeploymentInventory", Object.freeze(["ecs:DescribeTasks", "ecs:StopTask"])]),
  Object.freeze(["TagOnlyPreDeploymentInventoryTasks", Object.freeze(["ecs:TagResource"])]),
  Object.freeze(["PassOnlyApprovedTaskRoles", Object.freeze(["iam:PassRole"])]),
  Object.freeze(["ClaimOnlyStageBReplayRows", Object.freeze(["dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:UpdateItem"])]),
  Object.freeze(["ReadOnlyStageAApproval", Object.freeze(["secretsmanager:GetSecretValue"])]),
  Object.freeze(["VerifyOnlyStageAApprovalKey", Object.freeze(["kms:Verify"])]),
  Object.freeze(["WriteOnlyBrokerReceipts", Object.freeze(["s3:PutObject"])]),
  Object.freeze(["WriteOnlyStageABrokerLogs", Object.freeze(["logs:CreateLogStream", "logs:PutLogEvents"])]),
  Object.freeze(["ReadOnlyPreDeploymentInventoryLogs", Object.freeze(["logs:DescribeLogStreams", "logs:GetLogEvents"])]),
]);

export const STAGE_B_BROKER_POLICY = Object.freeze({
  roleName: "mscqr-production-rls-approval-broker",
  name: "mscqr-production-rls-approval-broker-runtime",
  arn: "arn:aws:iam::368992683803:policy/mscqr-production-rls-approval-broker-runtime",
});

const brokerTaskDefinitionFamilies = Object.freeze(Object.entries(STAGE_B_TASK_DEFINITION_FAMILIES)
  .filter(([address]) => address.includes(".executor[") || address.endsWith('candidate["canary"]'))
  .map(([, family]) => family));
const sortedBrokerTaskDefinitionFamilies = Object.freeze([...brokerTaskDefinitionFamilies].sort());
const brokerTaskDefinitionPattern = new RegExp(`^arn:aws:ecs:${STAGE_B.region}:${STAGE_B.account}:task-definition/(?:${brokerTaskDefinitionFamilies.join("|")}):[1-9][0-9]*$`);
const inventoryTaskDefinitionPattern = new RegExp(`^arn:aws:ecs:${STAGE_B.region}:${STAGE_B.account}:task-definition/${STAGE_B.inventoryTaskDefinitionFamily}:[1-9][0-9]*$`);

const brokerPassRoleArns = Object.freeze([
  STAGE_B.executorRoleArn,
  STAGE_B.executorExecutionRoleArn,
  `arn:aws:iam::${STAGE_B.account}:role/${executionRoleNames.canary}`,
  `arn:aws:iam::${STAGE_B.account}:role/${taskRoleNames.canary}`,
  `arn:aws:iam::${STAGE_B.account}:role/${taskRoleNames.backend}`,
  `arn:aws:iam::${STAGE_B.account}:role/${executionRoleNames.backend}`,
]);

const brokerPolicyResources = Object.freeze({
  RunOnlyApprovedExecutorAndCanaryRevisions: (resource) => Array.isArray(resource)
    && resource.length === brokerTaskDefinitionFamilies.length
    && [...resource].sort().every((arn, index) => arn === `arn:aws:ecs:${STAGE_B.region}:${STAGE_B.account}:task-definition/${sortedBrokerTaskDefinitionFamilies[index]}:${String(arn).split(":").pop()}`
      && brokerTaskDefinitionPattern.test(arn)),
  RunOnlyApprovedPreDeploymentInventory: (resource) => Array.isArray(resource) && resource.length === 1 && (inventoryTaskDefinitionPattern.test(resource[0]) || resource[0] === `arn:aws:ecs:${STAGE_B.region}:${STAGE_B.account}:task-definition/${STAGE_B.inventoryTaskDefinitionFamily}:*`),
  DescribeOnlyPreDeploymentInventoryTaskDefinitions: (resource) => resource === "*",
  ReadAndStopOnlyPreDeploymentInventory: (resource) => Array.isArray(resource) && resource.length === 1 && resource[0] === `arn:aws:ecs:${STAGE_B.region}:${STAGE_B.account}:task/mscqr-prod-euw2-main/*`,
  TagOnlyPreDeploymentInventoryTasks: (resource) => resource === `arn:aws:ecs:${STAGE_B.region}:${STAGE_B.account}:task/mscqr-prod-euw2-main/*`,
  PassOnlyApprovedTaskRoles: (resource) => Array.isArray(resource) && JSON.stringify([...resource].sort()) === JSON.stringify([...brokerPassRoleArns].sort()),
  ClaimOnlyStageBReplayRows: (resource) => resource === `arn:aws:dynamodb:${STAGE_B.region}:${STAGE_B.account}:table/mscqr-production-rls-stage-b-replay`,
  ReadOnlyStageAApproval: (resource) => resource === STAGE_B.approvalSecretArn,
  VerifyOnlyStageAApprovalKey: (resource) => resource === STAGE_B.approvalKmsKeyArn,
  WriteOnlyBrokerReceipts: (resource) => resource === `arn:aws:s3:::${STAGE_B.receiptBucket}/rls-broker-receipts/*`,
  WriteOnlyStageABrokerLogs: (resource) => resource === `arn:aws:logs:${STAGE_B.region}:${STAGE_B.account}:log-group:/aws/lambda/mscqr-production-rls-approval-broker:log-stream:*`,
  ReadOnlyPreDeploymentInventoryLogs: (resource) => resource === `arn:aws:logs:${STAGE_B.region}:${STAGE_B.account}:log-group:${STAGE_B.inventoryLogGroupName}:log-stream:*`,
});

const brokerPolicyConditions = Object.freeze({
  RunOnlyApprovedExecutorAndCanaryRevisions: null,
  RunOnlyApprovedPreDeploymentInventory: null,
  DescribeOnlyPreDeploymentInventoryTaskDefinitions: { StringEquals: { "aws:RequestedRegion": STAGE_B.region } },
  ReadAndStopOnlyPreDeploymentInventory: null,
  TagOnlyPreDeploymentInventoryTasks: null,
  PassOnlyApprovedTaskRoles: { StringEquals: { "iam:PassedToService": "ecs-tasks.amazonaws.com" } },
  ClaimOnlyStageBReplayRows: null,
  ReadOnlyStageAApproval: null,
  VerifyOnlyStageAApprovalKey: null,
  WriteOnlyBrokerReceipts: null,
  WriteOnlyStageABrokerLogs: null,
  ReadOnlyPreDeploymentInventoryLogs: null,
});

export const STAGE_B_RESOURCE_ACTION_MATRIX = Object.freeze({
  "aws_cloudwatch_log_group.stage_b[*]": Object.freeze({ type: "aws_cloudwatch_log_group", actions: Object.freeze([["create"], ["no-op"]]), identity: "exact Stage B log-group name" }),
  "aws_iam_role.execution[*]": Object.freeze({ type: "aws_iam_role", actions: Object.freeze([["create"], ["no-op"]]), identity: "exact execution-role name and account" }),
  "aws_iam_role.task[*]": Object.freeze({ type: "aws_iam_role", actions: Object.freeze([["create"], ["no-op"]]), identity: "exact task-role name and account" }),
  "aws_iam_role_policy.execution[*]": Object.freeze({ type: "aws_iam_role_policy", actions: Object.freeze([["create"], ["no-op"]]), identity: "exact execution role and policy name" }),
  "aws_iam_role_policy.candidate_object_storage[*]": Object.freeze({ type: "aws_iam_role_policy", actions: Object.freeze([["create"], ["no-op"]]), identity: "exact candidate task role and policy name" }),
  "aws_iam_role_policy.backend_ecs_exec": Object.freeze({ type: "aws_iam_role_policy", actions: Object.freeze([["create"], ["no-op"]]), identity: "exact backend task role and ECS Exec SSM-channel policy name" }),
  "aws_iam_role_policy.executor_runtime": Object.freeze({ type: "aws_iam_role_policy", actions: Object.freeze([["create"], ["no-op"]]), identity: "exact Stage A executor task role and policy name" }),
  "aws_ecs_task_definition.candidate[*]": Object.freeze({ type: "aws_ecs_task_definition", actions: Object.freeze([["create"], ["no-op"], ["create", "delete"], ["delete", "create"]]), identity: "exact current candidate family/address; replacement only for reviewed container-definition rotation" }),
  "aws_ecs_task_definition.executor[*]": Object.freeze({ type: "aws_ecs_task_definition", actions: Object.freeze([["create"], ["no-op"], ["create", "delete"], ["delete", "create"]]), identity: "exact current executor family/address; replacement only for reviewed container-definition rotation" }),
  "aws_ecs_task_definition.candidate_retained[*]": Object.freeze({ type: "aws_ecs_task_definition", actions: Object.freeze([["no-op"]]), identity: "exact revision-keyed retained candidate" }),
  "aws_ecs_task_definition.executor_retained[*]": Object.freeze({ type: "aws_ecs_task_definition", actions: Object.freeze([["no-op"]]), identity: "exact revision-keyed retained executor" }),
  "aws_dynamodb_table.replay": Object.freeze({ type: "aws_dynamodb_table", actions: Object.freeze([["create"], ["no-op"]]), identity: "exact replay table ARN/name" }),
  "aws_iam_policy.broker": Object.freeze({ type: "aws_iam_policy", actions: Object.freeze([["no-op"], ["update"]]), identity: "exact broker managed policy and canonical document" }),
  "aws_iam_role_policy_attachment.broker": Object.freeze({ type: "aws_iam_role_policy_attachment", actions: Object.freeze([["no-op"]]), identity: "exact broker role/policy attachment" }),
  "aws_lambda_function.broker": Object.freeze({ type: "aws_lambda_function", actions: Object.freeze([["create"], ["update"], ["no-op"]]), identity: "exact broker function" }),
  "aws_lambda_alias.reviewed": Object.freeze({ type: "aws_lambda_alias", actions: Object.freeze([["create"], ["update"], ["no-op"]]), identity: "exact reviewed alias" }),
  "aws_lambda_permission.release_deployer": Object.freeze({ type: "aws_lambda_permission", actions: Object.freeze([["create"], ["no-op"]]), identity: "exact reviewed-alias release permission" }),
});

export function assertStageBClosureMatrixCoverage({ declarations, matrixBases }) {
  for (const declaration of declarations) {
    if (!matrixBases.includes(declaration)) throw new Error(`Terraform resource has no closure matrix entry: ${declaration}`);
  }
  for (const contractPattern of Object.keys(STAGE_B_RESOURCE_ACTION_MATRIX)) {
    const base = contractPattern.split("[")[0];
    if (!matrixBases.includes(base)) throw new Error(`Shared classifier contract has no closure matrix entry: ${base}`);
  }
  return true;
}

function assertKnown(value, expected, label, strict) {
  if (value === undefined || value === null) {
    if (strict) throw new Error(`${label} is missing from the Terraform plan.`);
    return;
  }
  if (value !== expected) throw new Error(`${label} is outside the exact Stage B contract.`);
}

function assertIamArn(value, expected, label, strict) {
  if (value === undefined || value === null) {
    if (strict) throw new Error(`${label} is missing from the Terraform plan.`);
    return;
  }
  if (value !== expected) throw new Error(`${label} is outside the exact Stage B contract.`);
}

export function assertStageBImportedBackendMetadataNormalization(change, { terraformConfiguration } = {}) {
  if (change?.address !== importedBackendCandidateAddress || change?.type !== "aws_ecs_task_definition"
    || !exactActions(change.change?.actions, ["update"])
    || (change.change?.replace_paths !== undefined && (!Array.isArray(change.change.replace_paths) || change.change.replace_paths.length !== 0))) {
    throw new Error("Imported Stage B backend metadata normalization requires the exact reviewed task-definition rotation or in-place backend update.");
  }
  const before = change.change?.before;
  const after = change.change?.after;
  if (!before || !after || before.skip_destroy !== null || after.skip_destroy !== true
    || before.arn !== importedBackendCandidateArn || after.arn !== importedBackendCandidateArn
    || before.family !== importedBackendCandidateFamily || after.family !== importedBackendCandidateFamily
    || before.id !== importedBackendCandidateFamily || after.id !== importedBackendCandidateFamily
    || before.revision !== 9 || after.revision !== 9) {
    throw new Error("Imported Stage B backend metadata normalization is not bound to canonical revision :9 or an exact reviewed task-definition rotation.");
  }
  for (const field of ["container_definitions", "cpu", "memory", "network_mode", "requires_compatibilities", "execution_role_arn", "task_role_arn", "runtime_platform", "volume"]) {
    if (before[field] === undefined || after[field] === undefined) throw new Error(`Imported Stage B backend metadata normalization is missing ${field}.`);
  }
  for (const [name, value] of [["before_unknown", change.change.before_unknown], ["after_unknown", change.change.after_unknown]]) {
    if (value !== undefined && (!value || Array.isArray(value) || typeof value !== "object" || Object.keys(value).length !== 0)) {
      throw new Error(`Imported Stage B backend metadata normalization has unknown ${name} paths.`);
    }
  }
  const beforeComparable = { ...before };
  const afterComparable = { ...after };
  delete beforeComparable.skip_destroy;
  delete afterComparable.skip_destroy;
  if (canonicalJson(beforeComparable) !== canonicalJson(afterComparable)) {
    throw new Error("Imported Stage B backend metadata normalization contains an unrelated field change.");
  }
  if (typeof terraformConfiguration !== "string") throw new Error("Imported Stage B backend metadata normalization requires protected Terraform configuration.");
  const resourceStart = terraformConfiguration.indexOf('resource "aws_ecs_task_definition" "candidate" {');
  const nextResource = resourceStart < 0 ? -1 : terraformConfiguration.indexOf("\nresource \"", resourceStart + 1);
  const resourceBlock = resourceStart < 0 ? "" : terraformConfiguration.slice(resourceStart, nextResource < 0 ? undefined : nextResource);
  if (!/^\s*skip_destroy\s*=\s*true\s*$/m.test(resourceBlock)) {
    throw new Error("Imported Stage B backend metadata normalization requires protected skip_destroy=true configuration.");
  }
  return { address: change.address, type: change.type, actions: [...change.change.actions], classification: STAGE_B_IMPORTED_BACKEND_METADATA_NORMALIZATION };
}

function normalizedPolicyShape(document) {
  if (!document || document.Version !== "2012-10-17" || !Array.isArray(document.Statement)) throw new Error("Broker managed-policy document is malformed.");
  const expected = new Map(STAGE_B_BROKER_POLICY_STATEMENTS);
  const actual = document.Statement.map((statement) => {
    if (!statement || statement.Effect !== "Allow" || !statement.Sid || !Array.isArray(statement.Action) || statement.NotAction || statement.NotResource) {
      throw new Error("Broker managed-policy document contains an unsupported statement.");
    }
    if (statement.Resource === "*" && statement.Sid !== "DescribeOnlyPreDeploymentInventoryTaskDefinitions") {
      throw new Error("Broker managed-policy document contains a wildcard resource.");
    }
    const actions = [...statement.Action].sort();
    const expectedActions = expected.get(statement.Sid);
    if (!expectedActions || JSON.stringify(actions) !== JSON.stringify([...expectedActions].sort())) throw new Error("Broker managed-policy document differs from the canonical runtime contract.");
    if (!brokerPolicyResources[statement.Sid]?.(statement.Resource)) throw new Error(`Broker managed-policy resource differs from the canonical runtime contract: ${statement.Sid}`);
    if (canonicalJson(statement.Condition ?? null) !== canonicalJson(brokerPolicyConditions[statement.Sid])) throw new Error(`Broker managed-policy condition differs from the canonical runtime contract: ${statement.Sid}`);
    expected.delete(statement.Sid);
    return { Sid: statement.Sid, Effect: statement.Effect, Action: actions, Resource: statement.Resource, Condition: statement.Condition };
  });
  if (expected.size !== 0 || actual.length !== STAGE_B_BROKER_POLICY_STATEMENTS.length) throw new Error("Broker managed-policy document is missing a canonical statement.");
  return canonicalJson(actual.sort((left, right) => left.Sid.localeCompare(right.Sid)));
}

export function assertStageBBrokerPolicyDocument(document) {
  normalizedPolicyShape(document);
  return true;
}

function hclStringAssignments(source, name) {
  const assignments = [];
  let blockComment = false;
  let offset = 0;
  for (const rawLine of source.split("\n")) {
    let line = "";
    let quoted = false;
    for (let index = 0; index < rawLine.length; index += 1) {
      if (blockComment) {
        if (rawLine.startsWith("*/", index)) { blockComment = false; index += 1; }
        continue;
      }
      if (!quoted && rawLine.startsWith("/*", index)) { blockComment = true; index += 1; continue; }
      if (!quoted && (rawLine[index] === "#" || rawLine.startsWith("//", index))) break;
      line += rawLine[index];
      if (rawLine[index] === "\\" && quoted) { index += 1; line += rawLine[index] || ""; continue; }
      if (rawLine[index] === '"') quoted = !quoted;
    }
    const match = line.match(new RegExp(`^\\s*${name}\\s*=\\s*"([^"\\\\]*)"\\s*,?\\s*$`));
    if (match) assignments.push({ value: match[1], index: offset + line.search(/\S/) });
    offset += rawLine.length + 1;
  }
  if (blockComment) throw new Error("Broker managed-policy Terraform source contains an unterminated block comment.");
  return assignments;
}

export function assertStageBTerraformBrokerPolicySource(terraformConfiguration, strict = true) {
  if (!strict) return;
  if (typeof terraformConfiguration !== "string") throw new Error("Broker managed-policy source contract is missing.");
  if (!/resource "aws_iam_policy" "broker"[\s\S]*?name\s*=\s*"mscqr-production-rls-approval-broker-runtime"[\s\S]*?path\s*=\s*"\/"[\s\S]*?policy\s*=\s*jsonencode\(local\.broker_runtime_policy\)/.test(terraformConfiguration)) {
    throw new Error("Broker managed-policy Terraform identity/source contract is missing.");
  }
  const start = terraformConfiguration.indexOf("broker_runtime_policy = {");
  const end = terraformConfiguration.indexOf("\n  broker_template_hashes =", start);
  const source = start >= 0 && end > start ? terraformConfiguration.slice(start, end) : "";
  const statements = hclStringAssignments(source, "Sid");
  const expectedSids = STAGE_B_BROKER_POLICY_STATEMENTS.map(([sid]) => sid);
  if (JSON.stringify(statements.map(({ value }) => value)) !== JSON.stringify(expectedSids)) throw new Error("Broker managed-policy source Sid assignments are missing, duplicated, or out of contract.");
  for (let index = 0; index < STAGE_B_BROKER_POLICY_STATEMENTS.length; index += 1) {
    const [sid, actions] = STAGE_B_BROKER_POLICY_STATEMENTS[index];
    const statementStart = statements[index].index;
    const nextStatement = statements[index + 1]?.index ?? source.length;
    const statement = source.slice(statementStart, nextStatement);
    const actionValues = statement.match(/Action\s*=\s*\[([^\]]+)\]/)?.[1].match(/"([^"]+)"/g)?.map((value) => value.slice(1, -1)).sort();
    const effects = hclStringAssignments(statement, "Effect").map(({ value }) => value);
    if (JSON.stringify(effects) !== JSON.stringify(["Allow"]) || JSON.stringify(actionValues) !== JSON.stringify([...actions].sort())) throw new Error(`Broker managed-policy source statement is not canonical: ${sid}`);
  }
  const sourceResourceExpressions = {
    RunOnlyApprovedExecutorAndCanaryRevisions: "Resource = values(local.active_broker_task_definition_arns)",
    RunOnlyApprovedPreDeploymentInventory: "Resource = [\"arn:aws:ecs:${var.aws_region}:${var.account_id}:task-definition/mscqr-production-rls-green-predeployment-inventory:*\"]",
    DescribeOnlyPreDeploymentInventoryTaskDefinitions: "Resource = \"*\"",
    ReadAndStopOnlyPreDeploymentInventory: "Resource = [\n          \"arn:aws:ecs:${var.aws_region}:${var.account_id}:task/${local.ecs_cluster_name}/*\",\n        ]",
    TagOnlyPreDeploymentInventoryTasks: "Resource = \"arn:aws:ecs:${var.aws_region}:${var.account_id}:task/${local.ecs_cluster_name}/*\"",
    PassOnlyApprovedTaskRoles: "Resource = [var.stage_a_executor_task_role_arn, aws_iam_role.execution[\"executor\"].arn, aws_iam_role.task[\"canary\"].arn, aws_iam_role.execution[\"canary\"].arn, aws_iam_role.task[\"backend\"].arn, aws_iam_role.execution[\"backend\"].arn]",
    ClaimOnlyStageBReplayRows: "Resource = aws_dynamodb_table.replay.arn",
    ReadOnlyStageAApproval: "Resource = var.approval_secret_arn",
    VerifyOnlyStageAApprovalKey: "Resource = var.approval_kms_key_arn",
    WriteOnlyBrokerReceipts: "Resource = \"${var.receipt_bucket_arn}/rls-broker-receipts/*\"",
    WriteOnlyStageABrokerLogs: "Resource = \"${trimsuffix(var.stage_a_broker_log_group_arn, \":*\")}:log-stream:*\"",
    ReadOnlyPreDeploymentInventoryLogs: "Resource = \"${trimsuffix(local.execution_log_group_arns[\"backend\"], \":*\")}:log-stream:*\"",
  };
  for (const [sid, expression] of Object.entries(sourceResourceExpressions)) {
    const statementIndex = STAGE_B_BROKER_POLICY_STATEMENTS.findIndex(([candidate]) => candidate === sid);
    const statementStart = statements[statementIndex].index;
    const nextStatement = statements[statementIndex + 1]?.index ?? source.length;
    const statement = source.slice(statementStart, nextStatement >= 0 ? nextStatement : source.length).replace(/\s+/g, " ");
    if (!statement.includes(expression.replace(/\s+/g, " "))) throw new Error(`Broker managed-policy source resource is not canonical: ${sid}`);
    const expectedCondition = brokerPolicyConditions[sid];
    if (expectedCondition) {
      const conditionExpression = sid === "PassOnlyApprovedTaskRoles"
        ? 'Condition = { StringEquals = { "iam:PassedToService" = "ecs-tasks.amazonaws.com" } }'
        : 'Condition = { StringEquals = { "aws:RequestedRegion" = var.aws_region } }';
      if (!statement.includes(conditionExpression)) throw new Error(`Broker managed-policy source condition is not canonical: ${sid}`);
    }
    if (!expectedCondition && /\bCondition\s*=/.test(statement)) throw new Error(`Broker managed-policy source contains an unexpected condition: ${sid}`);
  }
  const sourceWithoutApprovedWildcard = source.replace(/Sid\s*=\s*"DescribeOnlyPreDeploymentInventoryTaskDefinitions"[\s\S]*?Resource\s*=\s*"\*"/, "");
  if (/NotAction|NotResource|Resource\s*=\s*"\*"/.test(sourceWithoutApprovedWildcard)) throw new Error("Broker managed-policy source contains an unsupported wildcard contract.");
}

function assertBrokerPolicyChange(change, { strict, terraformConfiguration, validateActions = true, allowBrokerPolicyCreate = false }) {
  const actions = change.change?.actions;
  if (change.type !== "aws_iam_policy") throw new Error(`Stage B broker managed policy resource type is outside the exact contract: ${change.type}.`);
  if (validateActions && (!exactActions(actions, ["no-op"]) && !exactActions(actions, ["update"]) && !(allowBrokerPolicyCreate && exactActions(actions, ["create"])))) throw new Error(`Stage B broker managed policy has unsupported actions: ${JSON.stringify(actions)}.`);
  const before = change.change?.before || {};
  const after = change.change?.after || {};
  for (const [value, label] of [[before.name, "Broker managed-policy name"], [after.name, "Broker managed-policy name"], [before.path, "Broker managed-policy path"], [after.path, "Broker managed-policy path"]]) {
    if (value !== undefined) assertKnown(value, label.includes("path") ? "/" : STAGE_B_BROKER_POLICY.name, label, true);
  }
  for (const [value, label] of [[before.arn, "Broker managed-policy before ARN"], [after.arn, "Broker managed-policy after ARN"], [before.id, "Broker managed-policy before ID"], [after.id, "Broker managed-policy after ID"]]) {
    if (value !== undefined) assertIamArn(value, STAGE_B_BROKER_POLICY.arn, label, true);
  }
  if (typeof after.policy === "string") normalizedPolicyShape(JSON.parse(after.policy));
  else if (after_unknown_policy(change) !== true) throw new Error("Broker managed-policy document is missing or unprovable.");
  assertStageBTerraformBrokerPolicySource(terraformConfiguration, strict);
  return exactActions(actions, ["update"]) ? "broker-managed-policy-update" : exactActions(actions, ["create"]) ? "broker-managed-policy-create" : "broker-managed-policy-no-op";
}

function after_unknown_policy(change) {
  return change.change?.after_unknown?.policy;
}

function assertBrokerAttachmentChange(change, { strict, validateActions = true }) {
  if (change.type !== "aws_iam_role_policy_attachment") throw new Error(`Stage B broker attachment resource type is outside the exact contract: ${change.type}.`);
  if (validateActions && !exactActions(change.change?.actions, ["no-op"])) throw new Error(`Stage B broker attachment has unsupported actions: ${JSON.stringify(change.change?.actions)}.`);
  const before = change.change?.before || {};
  const after = change.change?.after || {};
  for (const value of [before.role, after.role]) if (value !== undefined) assertKnown(value, STAGE_B_BROKER_POLICY.roleName, "Broker attachment role", strict);
  for (const value of [before.policy_arn, after.policy_arn]) if (value !== undefined) assertIamArn(value, STAGE_B_BROKER_POLICY.arn, "Broker attachment policy ARN", strict);
  return "broker-managed-policy-attachment-no-op";
}

function assertRoleIdentity(change, roleName, strict) {
  const values = [change.change?.before, change.change?.after].filter(Boolean);
  for (const value of values) {
    assertKnown(value.name, roleName, "Stage B IAM role name", strict);
    if (value.arn !== undefined) assertIamArn(value.arn, `arn:aws:iam::${STAGE_B.account}:role/${roleName}`, "Stage B IAM role ARN", strict);
  }
}

function assertPolicyRoleIdentity(change, roleName, policyName, strict) {
  for (const value of [change.change?.before, change.change?.after].filter(Boolean)) {
    assertKnown(value.name, policyName, "Stage B inline policy name", strict);
    assertKnown(value.role, roleName, "Stage B inline policy role", strict);
  }
}

function assertStageBResourceIdentity(change, kind, key, strict) {
  const after = change.change?.after || {};
  if (kind === "log") assertKnown(after.name, stageBLogNames[key], "Stage B log-group name", strict);
  if (kind === "execution-role") assertRoleIdentity(change, executionRoleNames[key], strict);
  if (kind === "task-role") assertRoleIdentity(change, taskRoleNames[key], strict);
  if (kind === "execution-policy") assertPolicyRoleIdentity(change, executionRoleNames[key], "stage-b-exact-image-logs-and-secrets", strict);
  if (kind === "candidate-storage-policy") assertPolicyRoleIdentity(change, taskRoleNames[key], "stage-b-object-storage", strict);
  if (kind === "backend-ecs-exec-policy") assertPolicyRoleIdentity(change, taskRoleNames.backend, "stage-b-backend-ecs-exec-ssm-channels", strict);
  if (kind === "executor-runtime-policy") assertPolicyRoleIdentity(change, "mscqr-production-full-rls-green-executor-task", "stage-b-executor-runtime", strict);
  if (kind === "replay") {
    assertKnown(after.name, "mscqr-production-rls-stage-b-replay", "Stage B replay table name", strict);
    if (after.arn !== undefined) assertIamArn(after.arn, `arn:aws:dynamodb:${STAGE_B.region}:${STAGE_B.account}:table/mscqr-production-rls-stage-b-replay`, "Stage B replay table ARN", strict);
  }
  if (kind === "broker-function") assertKnown(after.function_name, "mscqr-production-rls-approval-broker", "Stage B broker function name", strict);
  if (kind === "broker-alias") {
    assertKnown(after.name, STAGE_B.brokerAliasQualifier, "Stage B broker alias name", strict);
    assertKnown(after.function_name, "mscqr-production-rls-approval-broker", "Stage B broker alias function", strict);
  }
  if (kind === "release-permission") {
    assertKnown(after.statement_id, "OnlyProtectedReleaseRoleMayInvokeReviewedAlias", "Stage B Lambda permission statement", strict);
    assertKnown(after.action, "lambda:InvokeFunction", "Stage B Lambda permission action", strict);
    assertKnown(after.qualifier, STAGE_B.brokerAliasQualifier, "Stage B Lambda permission qualifier", strict);
    assertKnown(after.principal, `arn:aws:iam::${STAGE_B.account}:role/mscqr-production-release-deployer`, "Stage B Lambda permission principal", strict);
  }
}

const STAGE_B_BROKER_PUBLISH_PROVIDER_METADATA = Object.freeze({
  code_sha256: Object.freeze({ unknown: true, stable: true, type: "string" }),
  source_code_size: Object.freeze({ unknown: true, stable: true, type: "number" }),
  last_modified: Object.freeze({ unknown: true, stable: false, type: "string" }),
  qualified_arn: Object.freeze({ unknown: true, stable: false, type: "arn" }),
  qualified_invoke_arn: Object.freeze({ unknown: true, stable: false, type: "arn" }),
  version: Object.freeze({ unknown: true, stable: true, type: "string" }),
});
export const STAGE_B_BROKER_PUBLISH_PROVIDER_METADATA_FIELDS = Object.freeze(Object.keys(STAGE_B_BROKER_PUBLISH_PROVIDER_METADATA));
export const STAGE_B_BROKER_PUBLISH_PROVIDER_UNKNOWN_METADATA_FIELDS = Object.freeze(
  Object.entries(STAGE_B_BROKER_PUBLISH_PROVIDER_METADATA)
    .filter(([, representation]) => representation.unknown)
    .map(([field]) => field),
);
export const STAGE_B_BROKER_PUBLISH_PROVIDER_STABLE_METADATA_FIELDS = Object.freeze(
  Object.entries(STAGE_B_BROKER_PUBLISH_PROVIDER_METADATA)
    .filter(([, representation]) => representation.stable)
    .map(([field]) => field),
);
const brokerFunctionAllowedChangedFields = new Set([
  "environment", "filename", "source_code_hash", "timeout", ...STAGE_B_BROKER_PUBLISH_PROVIDER_METADATA_FIELDS,
]);

export const STAGE_B_REVIEWED_BROKER_TIMEOUT_SECONDS = Object.freeze({ before: 30, after: 180 });

export function assertReviewedBrokerTimeoutTransition(change) {
  if (change?.address !== "aws_lambda_function.broker" || change?.type !== "aws_lambda_function"
    || !exactActions(change.change?.actions, ["update"])
    || change.change?.before?.timeout !== STAGE_B_REVIEWED_BROKER_TIMEOUT_SECONDS.before
    || change.change?.after?.timeout !== STAGE_B_REVIEWED_BROKER_TIMEOUT_SECONDS.after) {
    throw new Error("Stage B broker timeout is outside the exact reviewed 30-to-180-second transition.");
  }
  return true;
}

function validProviderMetadataValue(value, type) {
  if (type === "number") return typeof value === "number" && Number.isFinite(value);
  if (type === "arn") return typeof value === "string" && /^arn:[^:\s]+:[^:\s]+:[^:\s]*:[^:\s]*:.+$/.test(value);
  return typeof value === "string" && value.length > 0;
}

export function assertStageBBrokerPublishProviderMetadataRepresentation(change) {
  if (change?.address !== "aws_lambda_function.broker" || !exactActions(change.change?.actions, ["update"])) return true;
  const before = change.change?.before || {};
  const after = change.change?.after || {};
  const afterUnknown = change.change?.after_unknown || {};
  for (const field of STAGE_B_BROKER_PUBLISH_PROVIDER_METADATA_FIELDS) {
    const rule = STAGE_B_BROKER_PUBLISH_PROVIDER_METADATA[field];
    const beforeValue = before[field];
    const afterValue = after[field];
    const marker = afterUnknown[field];
    if (marker !== undefined && marker !== false && marker !== true) throw new Error(`UNFAITHFUL_PROVIDER_COMPUTED_FIELDS: ${change.address}.${field}`);
    if (marker === true) {
      if (afterValue !== undefined && afterValue !== null) throw new Error(`UNFAITHFUL_PROVIDER_COMPUTED_FIELDS: ${change.address}.${field}`);
      continue;
    }
    if (!rule.stable || beforeValue === undefined || beforeValue === null || afterValue === undefined || afterValue === null
      || !exactJson(beforeValue, afterValue) || !validProviderMetadataValue(afterValue, rule.type)) {
      throw new Error(`UNFAITHFUL_PROVIDER_COMPUTED_FIELDS: ${change.address}.${field}`);
    }
  }
  return true;
}

export function assertStageBBrokerFunctionUpdate(change) {
  if (change?.address !== "aws_lambda_function.broker" || change?.type !== "aws_lambda_function" || !exactActions(change.change?.actions, ["update"])) {
    throw new Error("Stage B broker function must be the exact root-managed update.");
  }
  const before = change.change?.before || {};
  const after = change.change?.after || {};
  for (const value of [before.function_name, after.function_name]) if (value !== undefined && value !== STAGE_B.brokerFunctionArn.split(":function:")[1]) {
    throw new Error("Stage B broker function identity is outside the exact contract.");
  }
  const changed = [...new Set([...Object.keys(before), ...Object.keys(after)])]
    .filter((key) => JSON.stringify(before[key]) !== JSON.stringify(after[key]));
  const unsupported = changed.find((key) => !brokerFunctionAllowedChangedFields.has(key));
  if (unsupported) throw new Error(`Stage B broker function update contains an unsupported mutable field: ${unsupported}.`);
  if (changed.includes("timeout")) assertReviewedBrokerTimeoutTransition(change);
  assertStageBBrokerPublishProviderMetadataRepresentation(change);
  return true;
}

export function assertStageBPlanResourceChange(change, { strict = true, terraformConfiguration, validateActions = true, allowBrokerPolicyCreate = false, plan } = {}) {
  const address = change?.address || "<missing address>";
  const type = change?.type || "<missing type>";
  const actions = change?.change?.actions || [];
  if (address === legacyInlineAddress) throw new Error(`Stage B resource rejected: ${address} ${type} ${JSON.stringify(actions)}; legacy inline broker policy is forbidden.`);

  const task = taskDefinitionAddress.exec(address);
  if (task && Object.hasOwn(STAGE_B_TASK_DEFINITION_FAMILIES, address)) {
    if (type !== "aws_ecs_task_definition") throw new Error(`Stage B resource rejected at address ${address} ${type}; resource type does not match the exact task-definition contract.`);
    if (address === importedBackendCandidateAddress && exactActions(actions, ["update"])) {
      return assertStageBImportedBackendMetadataNormalization(change, { terraformConfiguration });
    }
    if (validateActions && (!exactActions(actions, ["create"]) && !exactActions(actions, ["no-op"]) && !isStageBTaskDefinitionRotationActionsValue(actions))) throw new Error(`Stage B resource rejected: ${address} ${type} ${JSON.stringify(actions)}; current task definitions permit only create, no-op, or an exact reviewed container-definition rotation.`);
    const rotation = isStageBTaskDefinitionRotationActionsValue(actions) ? assertStageBTaskDefinitionRotation(change, plan, { strict }) : undefined;
    return { address, type, actions, classification: rotation ? "current-task-definition-rotation" : "current-task-definition", ...(rotation ? { rotation } : {}) };
  }
  const retainedPrefix = address.startsWith("aws_ecs_task_definition.candidate_retained[") || address.startsWith("aws_ecs_task_definition.executor_retained[");
  if (retainedTaskDefinitionAddress.test(address) || retainedPrefix) {
    if (type !== "aws_ecs_task_definition") throw new Error(`Stage B resource rejected at address ${address} ${type}; resource type does not match the exact retained task-definition contract.`);
    if (!retainedTaskDefinitionAddress.test(address)) throw new Error(`Stage B resource rejected at address ${address}; retained task-definition address must be revision-keyed.`);
    if (validateActions && !exactActions(actions, ["no-op"])) throw new Error(`Stage B resource rejected: ${address} ${type} ${JSON.stringify(actions)}; retained task definitions are append-only no-op only.`);
    return { address, type, actions, classification: "retained-task-definition-no-op" };
  }
  if (address === policyAddress) return { address, type, actions, classification: assertBrokerPolicyChange(change, { strict, terraformConfiguration, validateActions, allowBrokerPolicyCreate }) };
  if (address === attachmentAddress) return { address, type, actions, classification: assertBrokerAttachmentChange(change, { strict, validateActions }) };

  let kind;
  let key;
  let actionContract;
  if ((key = /^aws_cloudwatch_log_group\.stage_b\["([^"]+)"\]$/.exec(address)?.[1]) && stageBLogNames[key]) { kind = "log"; actionContract = [["create"], ["no-op"]]; }
  else if ((key = /^aws_iam_role\.execution\["([^"]+)"\]$/.exec(address)?.[1]) && executionRoleNames[key]) { kind = "execution-role"; actionContract = [["create"], ["no-op"]]; }
  else if ((key = /^aws_iam_role\.task\["([^"]+)"\]$/.exec(address)?.[1]) && taskRoleNames[key]) { kind = "task-role"; actionContract = [["create"], ["no-op"]]; }
  else if ((key = /^aws_iam_role_policy\.execution\["([^"]+)"\]$/.exec(address)?.[1]) && executionPolicyKeys.has(key)) { kind = "execution-policy"; actionContract = [["create"], ["no-op"]]; }
  else if ((key = /^aws_iam_role_policy\.candidate_object_storage\["([^"]+)"\]$/.exec(address)?.[1]) && candidateStoragePolicyKeys.has(key)) { kind = "candidate-storage-policy"; actionContract = [["create"], ["no-op"]]; }
  else if (address === "aws_iam_role_policy.backend_ecs_exec") { kind = "backend-ecs-exec-policy"; actionContract = [["create"], ["no-op"]]; }
  else if (address === "aws_iam_role_policy.executor_runtime") { kind = "executor-runtime-policy"; actionContract = [["create"], ["no-op"]]; }
  else if (address === "aws_dynamodb_table.replay") { kind = "replay"; actionContract = [["create"], ["no-op"]]; }
  else if (address === "aws_lambda_function.broker") { kind = "broker-function"; actionContract = [["create"], ["update"], ["no-op"]]; }
  else if (address === "aws_lambda_alias.reviewed") { kind = "broker-alias"; actionContract = [["create"], ["update"], ["no-op"]]; }
  else if (address === "aws_lambda_permission.release_deployer") { kind = "release-permission"; actionContract = [["create"], ["no-op"]]; }
  else if (address.startsWith("aws_ecs_task_definition.")) throw new Error(`Stage B resource rejected at address ${address} ${type} ${JSON.stringify(actions)}; unknown Stage B task-definition family or address.`);
  else throw new Error(`Stage B resource rejected at address ${address} ${type} ${JSON.stringify(actions)}; no exact contract layer exists.`);

  if (type !== ({ log: "aws_cloudwatch_log_group", "execution-role": "aws_iam_role", "task-role": "aws_iam_role", "execution-policy": "aws_iam_role_policy", "candidate-storage-policy": "aws_iam_role_policy", "backend-ecs-exec-policy": "aws_iam_role_policy", "executor-runtime-policy": "aws_iam_role_policy", replay: "aws_dynamodb_table", "broker-function": "aws_lambda_function", "broker-alias": "aws_lambda_alias", "release-permission": "aws_lambda_permission" })[kind]) throw new Error(`Stage B resource rejected: ${address} ${type} ${JSON.stringify(actions)}; resource type does not match the exact contract.`);
  if (!Array.isArray(change.change?.actions) || change.change.actions.length === 0) throw new Error(`Stage B resource rejected at address ${address} ${type}; actions are missing or malformed.`);
  if (validateActions && !actionContract.some((expected) => exactActions(actions, expected))) throw new Error(`Stage B resource rejected at address ${address} ${type} ${JSON.stringify(actions)}; unsupported lifecycle action.`);
  assertStageBResourceIdentity(change, kind, key, strict);
  if (kind === "backend-ecs-exec-policy") assertStageBBackendEcsExecPolicyChange(change, { strict });
  return { address, type, actions, classification: kind === "broker-function" ? "broker-function-mutation" : kind === "broker-alias" ? "broker-alias-mutation" : kind === "release-permission" ? "broker-release-permission" : `${kind}-${exactActions(actions, ["create"]) ? "create" : "no-op"}` };
}

export function classifyStageBPlan(plan, options = {}) {
  const classifiedResources = [];
  const errors = [];
  for (const change of plan?.resource_changes || []) {
    try {
      classifiedResources.push(assertStageBPlanResourceChange(change, { ...options, plan }));
    } catch (error) {
      errors.push(error instanceof Error ? error.message : String(error));
    }
  }
  if (errors.length) throw new Error(`Stage B plan contains unsupported resources:\n${errors.map((error, index) => `${index + 1}. ${error}`).join("\n")}`);
  const unclassifiedResources = classifiedResources.filter((item) => !item.classification).map((item) => item.address);
  if (unclassifiedResources.length) throw new Error(`Stage B plan contains unclassified resources: ${unclassifiedResources.join(", ")}`);
  const actionCounts = classifiedResources.reduce((counts, item) => {
    const action = isStageBTaskDefinitionRotationActionsValue(item.actions) ? "replacement" : item.actions.join(",");
    counts[action] = (counts[action] || 0) + 1;
    return counts;
  }, {});
  const taskDefinitionRotations = classifiedResources.filter((item) => item.rotation).map((item) => item.rotation);
  const planProfile = classifiedResources.some(({ classification }) => classification === STAGE_B_IMPORTED_BACKEND_METADATA_NORMALIZATION)
    ? "IMPORTED_BACKEND_METADATA_NORMALIZATION"
    : taskDefinitionRotations.length ? "ECS_TASK_DEFINITION_ROTATION" : "BASELINE";
  if (planProfile === "IMPORTED_BACKEND_METADATA_NORMALIZATION" && taskDefinitionRotations.length > 0) assertStageBImportedBackendRolloverActions(plan?.resource_changes);
  return {
    classifiedResources,
    unclassifiedResources,
    actionCounts,
    taskDefinitionRotations,
    planProfile,
  };
}
