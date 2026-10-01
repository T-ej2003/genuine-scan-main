import { ECSClient, DescribeTaskDefinitionCommand, DescribeTasksCommand, ListTasksCommand, RunTaskCommand, StopTaskCommand } from "@aws-sdk/client-ecs";
import { EC2Client, AuthorizeSecurityGroupIngressCommand, DescribeSecurityGroupRulesCommand, RevokeSecurityGroupIngressCommand } from "@aws-sdk/client-ec2";
import { GetObjectCommand, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { KMSClient, VerifyCommand } from "@aws-sdk/client-kms";
import { verifyVictoriaRecoveryAuthorization, victoriaRecoveryImplementationSha256 } from "../../../../../scripts/aws/victoria-recovery-authorization.mjs";

const REGION = "eu-west-2";
const ACCOUNT = "368992683803";
const OPERATION = "VICTORIA_FAILED_ONBOARDING_RECOVERY_V1";
const TARGET = "victoria@mscqr.com";
const DATABASE = "mscqr_production";
const FAMILY = "mscqr-production-victoria-recovery";
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const s3 = new S3Client({ region: REGION });
const ecs = new ECSClient({ region: REGION });
const ec2 = new EC2Client({ region: REGION });
const kms = new KMSClient({ region: REGION });

const required = (name) => {
  const value = process.env[name];
  if (!value) throw new Error(`${name}_MISSING`);
  return value;
};
async function activeRecoveryTasks(cluster) {
  const [pending, running] = await Promise.all(["PENDING", "RUNNING"].map((desiredStatus) =>
    ecs.send(new ListTasksCommand({ cluster, family: FAMILY, desiredStatus }))));
  return [...new Set([...(pending.taskArns || []), ...(running.taskArns || [])])];
}
const readJson = async (bucket, key) => JSON.parse(await (await s3.send(new GetObjectCommand({ Bucket: bucket, Key: key }))).Body.transformToString());

export async function handler(event) {
  const isCleanup = event?.phase === "cleanup";
  if (!event || Object.keys(event).sort().join(",") !== (isCleanup ? "nonce,operation,phase,sourceSha" : "nonce,operation,sourceSha")
      || event.operation !== OPERATION || !uuid.test(event.nonce || "") || !/^[a-f0-9]{40}$/.test(event.sourceSha || "")) {
    throw new Error("RECOVERY_BROKER_REQUEST_INVALID");
  }
  const bucket = required("EVIDENCE_BUCKET");
  if (isCleanup) return cleanup({ event, bucket });
  const keyArn = required("SIGNING_KEY_ARN");
  const taskRoleArn = required("TASK_ROLE_ARN");
  const executionRoleArn = required("EXECUTION_ROLE_ARN");
  const databaseHost = required("ACTIVE_DATABASE_HOST");
  const cluster = required("ECS_CLUSTER_ARN");
  const subnets = JSON.parse(required("PRIVATE_SUBNET_IDS"));
  const securityGroups = JSON.parse(required("RECOVERY_SECURITY_GROUP_IDS"));
  const databaseSecurityGroup = required("DATABASE_SECURITY_GROUP_ID");
  const recoverySecurityGroup = required("RECOVERY_SECURITY_GROUP_ID");
  if ((await activeRecoveryTasks(cluster)).length) throw new Error("RECOVERY_TASK_ALREADY_ACTIVE");
  const authKey = `authorizations/${event.nonce}.json`;
  const authorization = await readJson(bucket, authKey);
  const taskDefinition = authorization.executorTaskDefinition;
  const described = await ecs.send(new DescribeTaskDefinitionCommand({ taskDefinition, include: ["TAGS"] }));
  const definition = described.taskDefinition;
  const container = definition?.containerDefinitions?.length === 1 ? definition.containerDefinitions[0] : null;
  const expectedEntryPoint = ["node", "/app/backend/scripts/victoria-failed-onboarding-recovery.mjs"];
  if (definition?.family !== FAMILY || definition.taskRoleArn !== taskRoleArn || definition.executionRoleArn !== executionRoleArn
      || definition.networkMode !== "awsvpc" || definition.cpu !== "512" || definition.memory !== "1024"
      || definition.requiresCompatibilities?.length !== 1 || definition.requiresCompatibilities[0] !== "FARGATE"
      || !container || container.name !== "recovery" || container.user !== "1000"
      || container.image !== authorization.executorImage || JSON.stringify(container.entryPoint) !== JSON.stringify(expectedEntryPoint)
      || (container.command || []).length !== 0 || container.privileged === true || container.readonlyRootFilesystem !== true
      || (container.portMappings || []).length !== 0 || (container.secrets || []).length !== 0
      || JSON.stringify(container.mountPoints) !== JSON.stringify([{ sourceVolume: "tmp", containerPath: "/tmp", readOnly: false }])
      || JSON.stringify(container.environment) !== JSON.stringify([
        { name: "VICTORIA_RDS_HOST", value: databaseHost },
        { name: "VICTORIA_RECOVERY_EVIDENCE_BUCKET", value: bucket },
        { name: "VICTORIA_RECOVERY_SIGNING_KEY_ARN", value: keyArn },
      ]) || JSON.stringify(definition.volumes) !== JSON.stringify([{ name: "tmp" }])) {
    throw new Error("RECOVERY_TASK_DEFINITION_BINDING_INVALID");
  }
  const verify = async ({ keyId, message, signature }) => (await kms.send(new VerifyCommand({
    KeyId: keyId, Message: message, MessageType: "RAW", Signature: signature, SigningAlgorithm: "RSASSA_PSS_SHA_256",
  }))).SignatureValid === true;
  const verified = await verifyVictoriaRecoveryAuthorization(authorization, {
    sourceSha: event.sourceSha,
    implementationSha256: victoriaRecoveryImplementationSha256(),
    executorImage: container.image,
    executorTaskDefinition: definition.taskDefinitionArn,
    signingKeyArn: keyArn,
    operator: authorization.operator,
    approvedBy: authorization.approvedBy,
    approvalWorkflowRunId: authorization.approvalWorkflowRunId,
    approvalWorkflowRunAttempt: authorization.approvalWorkflowRunAttempt,
  }, { verify });
  if (verified.operation !== OPERATION || verified.targetEmail !== TARGET || verified.targetDatabase !== DATABASE
      || verified.environment !== "production-victoria-recovery") throw new Error("RECOVERY_OPERATION_BINDING_INVALID");
  const receipt = Buffer.from(JSON.stringify({ operation: OPERATION, sourceSha: event.sourceSha, nonce: event.nonce,
    implementationSha256: verified.implementationSha256, taskDefinition: definition.taskDefinitionArn, submittedAt: new Date().toISOString() }));
  await s3.send(new PutObjectCommand({ Bucket: bucket, Key: `invocations/${event.nonce}.json`, Body: receipt,
    IfNoneMatch: "*", ServerSideEncryption: "aws:kms", ContentType: "application/json" }));
  const existingRules = await ec2.send(new DescribeSecurityGroupRulesCommand({ Filters: [
    { Name: "group-id", Values: [databaseSecurityGroup] },
  ] }));
  if ((existingRules.SecurityGroupRules || []).some((rule) => !rule.IsEgress && rule.GroupId === databaseSecurityGroup
      && rule.IpProtocol === "tcp" && rule.FromPort === 5432 && rule.ToPort === 5432
      && rule.ReferencedGroupInfo?.GroupId === recoverySecurityGroup)) throw new Error("RECOVERY_NETWORK_RULE_ALREADY_PRESENT");
  const ingress = await ec2.send(new AuthorizeSecurityGroupIngressCommand({
    GroupId: databaseSecurityGroup,
    IpPermissions: [{ IpProtocol: "tcp", FromPort: 5432, ToPort: 5432, UserIdGroupPairs: [{ GroupId: recoverySecurityGroup, Description: `Temporary ${OPERATION}` }] }],
    TagSpecifications: [{ ResourceType: "security-group-rule", Tags: [{ Key: "Operation", Value: OPERATION }, { Key: "Target", Value: TARGET }, { Key: "AuthorizationNonce", Value: event.nonce }, { Key: "SourceSha", Value: event.sourceSha }] }],
  }));
  if (ingress.SecurityGroupRules?.length !== 1) throw new Error("RECOVERY_NETWORK_AUTHORITY_CREATE_FAILED");
  let response;
  let taskLaunched = false;
  try {
    response = await ecs.send(new RunTaskCommand({
    cluster, taskDefinition: definition.taskDefinitionArn, launchType: "FARGATE", count: 1,
    startedBy: event.nonce,
    enableExecuteCommand: false,
    networkConfiguration: { awsvpcConfiguration: { subnets, securityGroups, assignPublicIp: "DISABLED" } },
    overrides: { containerOverrides: [{ name: "recovery", environment: [{ name: "VICTORIA_RECOVERY_AUTHORIZATION_KEY", value: authKey }] }] },
    tags: [{ key: "Operation", value: OPERATION }, { key: "AuthorizationNonce", value: event.nonce }, { key: "SourceSha", value: event.sourceSha }],
    }));
    taskLaunched = response.tasks?.length === 1 && Boolean(response.tasks[0].taskArn);
    if (!taskLaunched || response.failures?.length) throw new Error("RECOVERY_TASK_LAUNCH_FAILED");
  } catch (error) {
    if (taskLaunched) throw new Error("RECOVERY_PARTIAL_LAUNCH_REQUIRES_CLEANUP");
    try {
      await ec2.send(new RevokeSecurityGroupIngressCommand({ GroupId: databaseSecurityGroup, SecurityGroupRuleIds: [ingress.SecurityGroupRules[0].SecurityGroupRuleId] }));
    } catch {
      throw new Error("RECOVERY_LAUNCH_FAILED_NETWORK_CLEANUP_FAILED");
    }
    throw error;
  }
  const taskArn = response.tasks[0].taskArn;
  await s3.send(new PutObjectCommand({ Bucket: bucket, Key: `tasks/${event.nonce}.json`, Body: JSON.stringify({ operation: OPERATION,
    sourceSha: event.sourceSha, nonce: event.nonce, taskArn, taskDefinition: definition.taskDefinitionArn }),
    IfNoneMatch: "*", ServerSideEncryption: "aws:kms", ContentType: "application/json" }));
  return { operation: OPERATION, sourceSha: event.sourceSha, nonce: event.nonce, taskArn };
}

async function cleanup({ event, bucket }) {
  const cluster = required("ECS_CLUSTER_ARN");
  const databaseSecurityGroup = required("DATABASE_SECURITY_GROUP_ID");
  const recoverySecurityGroup = required("RECOVERY_SECURITY_GROUP_ID");
  let taskCleanupFailed = false;
  let taskArns = [];
  try {
    const activeForNonce = await Promise.all(["PENDING", "RUNNING"].map((desiredStatus) =>
      ecs.send(new ListTasksCommand({ cluster, family: FAMILY, startedBy: event.nonce, desiredStatus }))));
    taskArns = [...new Set(activeForNonce.flatMap(({ taskArns: listed = [] }) => listed))];
    if (taskArns.length > 1) taskCleanupFailed = true;
    if (taskArns.length === 1) {
      const response = await ecs.send(new DescribeTasksCommand({ cluster, tasks: taskArns, include: ["TAGS"] }));
      const task = response.tasks?.[0];
      const tags = Object.fromEntries((task?.tags || []).map(({ key, value }) => [key, value]));
      if (task?.clusterArn !== cluster || task.group !== `family:${FAMILY}` || tags.Operation !== OPERATION
          || tags.SourceSha !== event.sourceSha || tags.AuthorizationNonce !== event.nonce) taskCleanupFailed = true;
      else {
        try { await ecs.send(new StopTaskCommand({ cluster, task: task.taskArn, reason: OPERATION })); }
        catch { taskCleanupFailed = true; }
      }
    }
    const stopDeadline = Date.now() + 45_000;
    for (;;) {
      const active = await activeRecoveryTasks(cluster);
      if (active.some((taskArn) => !taskArns.includes(taskArn))) taskCleanupFailed = true;
      if (!active.some((taskArn) => taskArns.includes(taskArn))) break;
      if (Date.now() >= stopDeadline) { taskCleanupFailed = true; break; }
      await new Promise((resolve) => setTimeout(resolve, 2000));
    }
  } catch { taskCleanupFailed = true; }
  let networkAuthorityRevoked = false;
  try {
    const rules = await ec2.send(new DescribeSecurityGroupRulesCommand({ Filters: [
      { Name: "group-id", Values: [databaseSecurityGroup] },
    ] }));
    const matches = (rules.SecurityGroupRules || []).filter((rule) => !rule.IsEgress && rule.GroupId === databaseSecurityGroup
      && rule.IpProtocol === "tcp" && rule.FromPort === 5432 && rule.ToPort === 5432
      && rule.ReferencedGroupInfo?.GroupId === recoverySecurityGroup);
    if (matches.length > 1) taskCleanupFailed = true;
    if (matches.length) await ec2.send(new RevokeSecurityGroupIngressCommand({
      GroupId: databaseSecurityGroup, SecurityGroupRuleIds: matches.map(({ SecurityGroupRuleId }) => SecurityGroupRuleId),
    }));
    const after = await ec2.send(new DescribeSecurityGroupRulesCommand({ Filters: [
      { Name: "group-id", Values: [databaseSecurityGroup] },
    ] }));
    networkAuthorityRevoked = !(after.SecurityGroupRules || []).some((rule) => !rule.IsEgress && rule.GroupId === databaseSecurityGroup
      && rule.IpProtocol === "tcp" && rule.FromPort === 5432 && rule.ToPort === 5432
      && rule.ReferencedGroupInfo?.GroupId === recoverySecurityGroup);
  } catch { taskCleanupFailed = true; }
  if (!networkAuthorityRevoked) taskCleanupFailed = true;
  let stoppedTaskCount = 0;
  try {
    const stopped = await ecs.send(new ListTasksCommand({ cluster, startedBy: event.nonce, desiredStatus: "STOPPED" }));
    stoppedTaskCount = stopped.taskArns?.length || 0;
    if (stoppedTaskCount > 1) taskCleanupFailed = true;
    if (stoppedTaskCount === 1) {
      const response = await ecs.send(new DescribeTasksCommand({ cluster, tasks: stopped.taskArns, include: ["TAGS"] }));
      const task = response.tasks?.[0];
      const tags = Object.fromEntries((task?.tags || []).map(({ key, value }) => [key, value]));
      if (task?.lastStatus !== "STOPPED" || task.clusterArn !== cluster || task.group !== `family:${FAMILY}`
          || tags.Operation !== OPERATION || tags.SourceSha !== event.sourceSha || tags.AuthorizationNonce !== event.nonce) taskCleanupFailed = true;
    }
  } catch { taskCleanupFailed = true; }
  const taskStopped = !taskCleanupFailed && stoppedTaskCount <= 1;
  const cleanupComplete = networkAuthorityRevoked && taskStopped;
  const receipt = Buffer.from(JSON.stringify({ operation: OPERATION, sourceSha: event.sourceSha, nonce: event.nonce,
    networkAuthorityRevoked, taskStopped, stoppedTaskCount, cleanedAt: new Date().toISOString() }));
  await s3.send(new PutObjectCommand({ Bucket: bucket, Key: `cleanups/${event.nonce}.json`, Body: receipt,
    ServerSideEncryption: "aws:kms", ContentType: "application/json" }));
  if (!cleanupComplete) throw new Error("RECOVERY_CLEANUP_INCOMPLETE_EVIDENCE_PERSISTED");
  return { operation: OPERATION, sourceSha: event.sourceSha, nonce: event.nonce, networkAuthorityRevoked: true, taskStopped: true };
}
