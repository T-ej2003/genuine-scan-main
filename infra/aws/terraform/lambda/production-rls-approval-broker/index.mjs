const { validateProductionRlsApproval } = await import(
  process.env.AWS_LAMBDA_FUNCTION_NAME
    ? "./production-rls-approval.mjs"
    : "../../../../../backend/scripts/production-rls-approval.mjs"
);

const modes = new Set([
  "full-rls-capability-preflight",
  "full-rls-admin-bootstrap",
  "full-rls-role-provision",
  "full-rls-role-verify",
  "full-rls-admin-ownership",
  "full-rls-runtime-policy",
  "full-rls-verification",
  "full-rls-application-canary",
  "full-rls-rollback",
]);

export function validateBrokerEvent(event) {
  if (!event || typeof event !== "object" || Array.isArray(event)
      || Object.keys(event).sort().join(",") !== "approvalId,mode"
      || !modes.has(event.mode)
      || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{5,127}$/.test(event.approvalId || "")) {
    throw new Error("Production RLS broker request is outside the reviewed contract.");
  }
  return event;
}

export function createHandler({ config, readApproval, runTask, verifySignature, audit = () => {}, now }) {
  return async (event, context = {}) => {
    const request = validateBrokerEvent(event);
    const taskDefinition = config.taskDefinitionArns?.[request.mode];
    if (!/^arn:aws:ecs:eu-west-2:368992683803:cluster\/mscqr-prod-euw2-main$/.test(config.clusterArn || "")
        || !new RegExp(`^arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-full-rls-green-${request.mode.replace("full-rls-", "")}:[1-9][0-9]*$`).test(taskDefinition || "")
        || !/^arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr\/production\/rls-green\/phase2\/approval-[A-Za-z0-9]{6}$/.test(config.approvalSecretArn || "")
        || !Array.isArray(config.subnets) || !config.subnets.length || config.subnets.some((value) => !/^subnet-[a-f0-9]+$/.test(value))
        || !Array.isArray(config.securityGroups) || config.securityGroups.length !== 1 || !/^sg-[a-f0-9]+$/.test(config.securityGroups[0])) {
      throw new Error("Production RLS broker configuration is outside the reviewed contract.");
    }
    const rawApproval = await readApproval(config.approvalSecretArn);
    const approval = await validateProductionRlsApproval(rawApproval, config.approvalExpected, {
      verifySignature,
      allowExpiredRollback: request.mode === "full-rls-rollback",
      ...(now ? { now } : {}),
    });
    if (approval.approval.approvalId !== request.approvalId) {
      throw new Error("Production RLS broker approval ID mismatch.");
    }
    audit({
      event: "production_rls_approval_broker",
      outcome: "accepted",
      mode: request.mode,
      approvalId: request.approvalId,
      checkerIdentity: approval.approval.independentCheckerIdentity,
      requestId: context.awsRequestId || "unavailable",
    });
    const response = await runTask({
      cluster: config.clusterArn,
      taskDefinition,
      launchType: "FARGATE",
      count: 1,
      networkConfiguration: {
        awsvpcConfiguration: {
          subnets: config.subnets,
          securityGroups: config.securityGroups,
          assignPublicIp: "DISABLED",
        },
      },
    });
    if ((response.failures || []).length || response.tasks?.length !== 1) {
      throw new Error("Production RLS broker did not start exactly one reviewed task.");
    }
    const taskArn = response.tasks[0]?.taskArn;
    if (typeof taskArn !== "string" || !taskArn.startsWith(config.clusterArn.replace(":cluster/", ":task/") + "/")) {
      throw new Error("Production RLS broker started a task outside the reviewed cluster.");
    }
    return {
      status: "started",
      mode: request.mode,
      approvalId: request.approvalId,
      approvalContractSha256: approval.approvalContractSha256,
      taskArn,
      taskDefinitionArn: taskDefinition,
    };
  };
}

const config = () => ({
  clusterArn: process.env.BROKER_CLUSTER_ARN,
  taskDefinitionArns: JSON.parse(process.env.BROKER_TASK_DEFINITIONS_JSON || "{}"),
  approvalSecretArn: process.env.BROKER_APPROVAL_SECRET_ARN,
  subnets: JSON.parse(process.env.BROKER_PRIVATE_SUBNETS_JSON || "[]"),
  securityGroups: JSON.parse(process.env.BROKER_SECURITY_GROUPS_JSON || "[]"),
  approvalExpected: {
    releaseSha: process.env.RELEASE_GIT_SHA,
    sourceContractSha256: process.env.MSCQR_FULL_RLS_SOURCE_CONTRACT_SHA256,
    migrationSetDigest: process.env.MSCQR_FULL_RLS_MIGRATION_SET_DIGEST,
    deploymentId: "phase2",
    greenDatabase: "mscqr_production_rls_green_phase2",
    administratorIdentity: "mscqr_prod_admin",
    kmsKeyArn: process.env.BROKER_APPROVAL_KMS_KEY_ARN,
  },
});

export async function handler(event, context) {
  const [{ ECSClient, RunTaskCommand }, { SecretsManagerClient, GetSecretValueCommand }, { KMSClient, VerifyCommand }] =
    await Promise.all([
      import("@aws-sdk/client-ecs"),
      import("@aws-sdk/client-secrets-manager"),
      import("@aws-sdk/client-kms"),
    ]);
  const ecs = new ECSClient({ region: "eu-west-2" });
  const secrets = new SecretsManagerClient({ region: "eu-west-2" });
  const kms = new KMSClient({ region: "eu-west-2" });
  return createHandler({
    config: config(),
    readApproval: async (secretId) => {
      const response = await secrets.send(new GetSecretValueCommand({ SecretId: secretId, VersionStage: "AWSCURRENT" }));
      if (!response.SecretString) throw new Error("Production RLS approval artifact is missing.");
      return response.SecretString;
    },
    verifySignature: async ({ keyId, message, signature }) => {
      const response = await kms.send(new VerifyCommand({
        KeyId: keyId,
        Message: message,
        MessageType: "RAW",
        Signature: signature,
        SigningAlgorithm: "RSASSA_PSS_SHA_256",
      }));
      return response.SignatureValid === true;
    },
    runTask: (request) => ecs.send(new RunTaskCommand(request)),
    audit: (record) => console.info(JSON.stringify(record)),
  })(event, context);
}
