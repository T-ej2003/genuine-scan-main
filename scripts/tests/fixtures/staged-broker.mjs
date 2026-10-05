import { STAGE_B } from "../../aws/production-green-stage-b-contract.mjs";
import { STAGE_B_TASK_DEFINITION_FAMILIES } from "../../aws/stage-b-reference-audit-contract.mjs";
const addresses = Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES);
const image = n => `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr@sha256:${String(n).repeat(64)}`;
export function canonicalBrokerPolicy() {
  const taskDefinitionArn = (family) => `arn:aws:ecs:${STAGE_B.region}:${STAGE_B.account}:task-definition/${family}:1`;
  const executorFamilies = addresses.filter((address) => address.includes(".executor[")).map((address) => STAGE_B_TASK_DEFINITION_FAMILIES[address]);
  return {
    Version: "2012-10-17",
    Statement: [
      { Sid: "RunOnlyApprovedExecutorAndCanaryRevisions", Effect: "Allow", Action: ["ecs:RunTask"], Resource: [STAGE_B_TASK_DEFINITION_FAMILIES['aws_ecs_task_definition.candidate["canary"]'], ...executorFamilies].map(taskDefinitionArn) },
      { Sid: "RunOnlyApprovedPreDeploymentInventory", Effect: "Allow", Action: ["ecs:RunTask"], Resource: [taskDefinitionArn(STAGE_B.inventoryTaskDefinitionFamily)] },
      { Sid: "DescribeOnlyPreDeploymentInventoryTaskDefinitions", Effect: "Allow", Action: ["ecs:DescribeTaskDefinition"], Resource: "*", Condition: { StringEquals: { "aws:RequestedRegion": "eu-west-2" } } },
      { Sid: "ReadAndStopOnlyPreDeploymentInventory", Effect: "Allow", Action: ["ecs:DescribeTasks", "ecs:StopTask"], Resource: [`arn:aws:ecs:${STAGE_B.region}:${STAGE_B.account}:task/mscqr-prod-euw2-main/*`] },
      { Sid: "TagOnlyPreDeploymentInventoryTasks", Effect: "Allow", Action: ["ecs:TagResource"], Resource: `arn:aws:ecs:${STAGE_B.region}:${STAGE_B.account}:task/mscqr-prod-euw2-main/*` },
      { Sid: "PassOnlyApprovedTaskRoles", Effect: "Allow", Action: ["iam:PassRole"], Resource: [STAGE_B.executorRoleArn, STAGE_B.executorExecutionRoleArn, "arn:aws:iam::368992683803:role/mscqr-production-rls-green-canary-task", "arn:aws:iam::368992683803:role/mscqr-production-rls-green-canary-execution", "arn:aws:iam::368992683803:role/mscqr-production-rls-green-backend-task", "arn:aws:iam::368992683803:role/mscqr-production-rls-green-backend-execution"], Condition: { StringEquals: { "iam:PassedToService": "ecs-tasks.amazonaws.com" } } },
      { Sid: "AuthenticateOnlyArchivedInventoryOutcome", Effect: "Allow", Action: ["cloudtrail:LookupEvents"], Resource: "*", Condition: { StringEquals: { "aws:RequestedRegion": "eu-west-2" } } },
    { Sid: "ClaimOnlyStageBReplayRows", Effect: "Allow", Action: ["dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:UpdateItem", "dynamodb:GetItem", "dynamodb:TransactWriteItems", "dynamodb:ConditionCheckItem"], Resource: "arn:aws:dynamodb:eu-west-2:368992683803:table/mscqr-production-rls-stage-b-replay" },
      { Sid: "ReadOnlyStageAApproval", Effect: "Allow", Action: ["secretsmanager:GetSecretValue"], Resource: STAGE_B.approvalSecretArn },
      { Sid: "VerifyOnlyStageAApprovalKey", Effect: "Allow", Action: ["kms:Verify"], Resource: STAGE_B.approvalKmsKeyArn },
      { Sid: "WriteOnlyBrokerReceipts", Effect: "Allow", Action: ["s3:PutObject"], Resource: `arn:aws:s3:::${STAGE_B.receiptBucket}/rls-broker-receipts/*` },
      { Sid: "WriteOnlyStageABrokerLogs", Effect: "Allow", Action: ["logs:CreateLogStream", "logs:PutLogEvents"], Resource: "arn:aws:logs:eu-west-2:368992683803:log-group:/aws/lambda/mscqr-production-rls-approval-broker:log-stream:*" },
      { Sid: "ReadOnlyPreDeploymentInventoryLogs", Effect: "Allow", Action: ["logs:DescribeLogStreams", "logs:GetLogEvents"], Resource: `arn:aws:logs:${STAGE_B.region}:${STAGE_B.account}:log-group:${STAGE_B.inventoryLogGroupName}:log-stream:*` },
    ],
  };
}

export function resolvedBrokerEnvironment() {
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
    BROKER_IMAGE_RELEASE_SHA: "9".repeat(40),
    BROKER_PRIVATE_SUBNETS_JSON: JSON.stringify(STAGE_B.privateSubnetIds),
    BROKER_RECEIPT_BUCKET: STAGE_B.receiptBucket,
    BROKER_REPLAY_TABLE: "mscqr-production-rls-stage-b-replay",
    BROKER_TASK_DEFINITIONS_JSON: JSON.stringify(taskDefinitions),
    BROKER_TASK_TEMPLATE_HASHES_JSON: JSON.stringify({ backend: "e".repeat(64), worker: "f".repeat(64), executor: "1".repeat(64), canary: "2".repeat(64) }),
  };
}
