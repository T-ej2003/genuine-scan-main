import crypto from "node:crypto";
const { assertBrokerRequest, hasCompleteStageBTaskMaps, STAGE_B, STAGE_B_MODES, validateStageBApproval } = await import(
  process.env.AWS_LAMBDA_FUNCTION_NAME ? "./stage-b-contract.mjs" : "../../../../../scripts/aws/production-green-stage-b-contract.mjs"
);

const taskArnPattern = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-production-(?:full-rls-green|rls-green)-(?:[a-z0-9-]+):[1-9][0-9]*$/;
const exact = (left, right) => JSON.stringify(left) === JSON.stringify(right);
const brokerReceipt = (value) => ({ ...value, receiptSha256: crypto.createHash("sha256").update(`${JSON.stringify(value)}\n`).digest("hex") });

export function validateBrokerConfiguration(config) {
  if (!config || config.clusterArn !== STAGE_B.clusterArn || config.approvalSecretArn !== STAGE_B.approvalSecretArn
      || config.executorSecurityGroupId !== STAGE_B.executorSecurityGroupId || !Array.isArray(config.privateSubnetIds)
      || [...config.privateSubnetIds].sort().join(",") !== [...STAGE_B.privateSubnetIds].sort().join(",")
      || !hasCompleteStageBTaskMaps(config.taskDefinitionArns, config.templateHashes)
      || STAGE_B_MODES.some((mode) => !taskArnPattern.test(config.taskDefinitionArns[mode] || ""))) {
    throw new Error("Stage B broker configuration is outside the reviewed contract.");
  }
  return config;
}

export function createHandler({ config, readApproval, verifySignature, claimApproval, releaseApproval = async () => {}, markLaunchUncertain = async () => {}, recordTaskStarted = async () => {}, runTask, writeReceipt = async () => {}, now = () => new Date() }) {
  validateBrokerConfiguration(config);
  return async (event, context = {}) => {
    const request = assertBrokerRequest(event);
    const approval = await validateStageBApproval(await readApproval(STAGE_B.approvalSecretArn), {
      ...config.approvalExpected,
      images: config.images,
    }, { now: now(), verifySignature, allowExpiredRollback: request.mode === "full-rls-rollback", requestedMode: request.mode });
    if (approval.approval.approvalId !== request.approvalId || !exact(approval.approval.taskDefinitionTemplateHashes, config.templateHashes)
        || !exact(approval.approval.taskDefinitionArns, config.taskDefinitionArns)) {
      throw new Error("Stage B broker request is not bound to the signed approval.");
    }
    const taskDefinition = config.taskDefinitionArns[request.mode];
    await claimApproval({ approvalId: approval.approval.approvalId, nonce: approval.approval.nonce, mode: request.mode, expiresAt: approval.approval.expiresAt });
    const networkConfiguration = { awsvpcConfiguration: {
      subnets: [...config.privateSubnetIds].sort(), securityGroups: [STAGE_B.executorSecurityGroupId], assignPublicIp: "DISABLED",
    } };
    let response;
    try {
      response = await runTask({ cluster: STAGE_B.clusterArn, taskDefinition, launchType: "FARGATE", count: 1, networkConfiguration });
    } catch {
      await markLaunchUncertain({ approvalId: approval.approval.approvalId, nonce: approval.approval.nonce, mode: request.mode });
      throw new Error("Stage B broker launch outcome is uncertain; the approval remains blocked pending reviewed ECS reconciliation.");
    }
    if ((response.failures || []).length || response.tasks?.length !== 1) {
      await releaseApproval({ approvalId: approval.approval.approvalId, nonce: approval.approval.nonce, mode: request.mode });
      throw new Error("Stage B broker did not start exactly one fixed task; the approval claim was released.");
    }
    const taskArn = response.tasks[0]?.taskArn;
    if (!String(taskArn).startsWith(STAGE_B.clusterArn.replace(":cluster/", ":task/") + "/")) throw new Error("Stage B broker task escaped the approved cluster.");
    await recordTaskStarted({ approvalId: approval.approval.approvalId, nonce: approval.approval.nonce, mode: request.mode, taskArn });
    const receipt = brokerReceipt({ schemaVersion: 1, environment: "production", event: "stage-b-broker-start", approvalId: request.approvalId, mode: request.mode, taskArn, taskDefinitionArn: taskDefinition, approvalContractSha256: approval.approvalContractSha256, completedAt: now().toISOString(), nonce: crypto.randomUUID() });
    await writeReceipt(receipt);
    return { status: "started", mode: request.mode, approvalId: request.approvalId, taskArn, taskDefinitionArn: taskDefinition, approvalContractSha256: approval.approvalContractSha256 };
  };
}

const parse = (name, fallback) => JSON.parse(process.env[name] || fallback);
const runtimeConfig = () => ({
  clusterArn: process.env.BROKER_CLUSTER_ARN,
  approvalSecretArn: process.env.BROKER_APPROVAL_SECRET_ARN,
  executorSecurityGroupId: process.env.BROKER_EXECUTOR_SECURITY_GROUP_ID,
  privateSubnetIds: parse("BROKER_PRIVATE_SUBNETS_JSON", "[]"),
  taskDefinitionArns: parse("BROKER_TASK_DEFINITIONS_JSON", "{}"),
  templateHashes: parse("BROKER_TASK_TEMPLATE_HASHES_JSON", "{}"),
  approvalExpected: parse("BROKER_APPROVAL_EXPECTED_JSON", "{}"),
  images: parse("BROKER_IMAGES_JSON", "{}"),
  replayTable: process.env.BROKER_REPLAY_TABLE,
  receiptBucket: process.env.BROKER_RECEIPT_BUCKET,
});

export async function handler(event, context) {
  const config = runtimeConfig();
  if (!/^[A-Za-z0-9._-]{3,255}$/.test(config.replayTable || "") || config.receiptBucket !== STAGE_B.receiptBucket) throw new Error("Stage B broker storage is outside the reviewed contract.");
  const [{ ECSClient, RunTaskCommand }, { SecretsManagerClient, GetSecretValueCommand }, { KMSClient, VerifyCommand }, { DynamoDBClient, PutItemCommand, DeleteItemCommand, UpdateItemCommand }, { S3Client, PutObjectCommand }] = await Promise.all([
    import("@aws-sdk/client-ecs"), import("@aws-sdk/client-secrets-manager"), import("@aws-sdk/client-kms"), import("@aws-sdk/client-dynamodb"), import("@aws-sdk/client-s3"),
  ]);
  const ecs = new ECSClient({ region: STAGE_B.region }); const secrets = new SecretsManagerClient({ region: STAGE_B.region });
  const kms = new KMSClient({ region: STAGE_B.region }); const dynamo = new DynamoDBClient({ region: STAGE_B.region }); const s3 = new S3Client({ region: STAGE_B.region });
  return createHandler({
    config,
    readApproval: async (id) => {
      const response = await secrets.send(new GetSecretValueCommand({ SecretId: id, VersionStage: "AWSCURRENT" }));
      if (!response.SecretString) throw new Error("Stage B approval artifact is missing.");
      return response.SecretString;
    },
    verifySignature: async ({ keyId, message, signature }) => (await kms.send(new VerifyCommand({ KeyId: keyId, Message: message, MessageType: "RAW", Signature: signature, SigningAlgorithm: "RSASSA_PSS_SHA_256" }))).SignatureValid === true,
    claimApproval: async ({ approvalId, nonce, mode, expiresAt }) => dynamo.send(new PutItemCommand({
      TableName: config.replayTable, Item: { approvalMode: { S: `${approvalId}#${mode}` }, approvalNonce: { S: nonce }, launchState: { S: "claimed" }, expiresAt: { N: String(Math.floor(Date.parse(expiresAt) / 1000)) } }, ConditionExpression: "attribute_not_exists(approvalMode)",
    })),
    releaseApproval: ({ approvalId, nonce, mode }) => dynamo.send(new DeleteItemCommand({
      TableName: config.replayTable, Key: { approvalMode: { S: `${approvalId}#${mode}` } }, ConditionExpression: "approvalNonce = :nonce AND launchState = :claimed", ExpressionAttributeValues: { ":nonce": { S: nonce }, ":claimed": { S: "claimed" } },
    })),
    markLaunchUncertain: ({ approvalId, nonce, mode }) => dynamo.send(new UpdateItemCommand({
      TableName: config.replayTable, Key: { approvalMode: { S: `${approvalId}#${mode}` } }, UpdateExpression: "SET launchState = :state", ConditionExpression: "approvalNonce = :nonce AND launchState = :claimed", ExpressionAttributeValues: { ":nonce": { S: nonce }, ":claimed": { S: "claimed" }, ":state": { S: "launch-uncertain" } },
    })),
    recordTaskStarted: ({ approvalId, nonce, mode, taskArn }) => dynamo.send(new UpdateItemCommand({
      TableName: config.replayTable, Key: { approvalMode: { S: `${approvalId}#${mode}` } }, UpdateExpression: "SET launchState = :state, taskArn = :taskArn", ConditionExpression: "approvalNonce = :nonce AND launchState = :claimed", ExpressionAttributeValues: { ":nonce": { S: nonce }, ":claimed": { S: "claimed" }, ":state": { S: "started" }, ":taskArn": { S: taskArn } },
    })),
    runTask: (request) => ecs.send(new RunTaskCommand(request)),
    writeReceipt: (receipt) => s3.send(new PutObjectCommand({ Bucket: config.receiptBucket, Key: `rls-broker-receipts/${receipt.approvalId}/${receipt.mode}/${receipt.nonce}.json`, Body: `${JSON.stringify(receipt)}\n`, ContentType: "application/json", ServerSideEncryption: "AES256", IfNoneMatch: "*" })),
  })(event, context);
}
