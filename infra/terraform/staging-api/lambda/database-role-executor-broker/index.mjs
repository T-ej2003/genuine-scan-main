export const BLUE_EXECUTOR_MODES = Object.freeze([
  "probe", "provision", "verify",
  "rls-shared-apply", "rls-shared-verify", "rls-shared-rollback",
]);
const ALLOWED_MODES = new Set(BLUE_EXECUTOR_MODES);
export const MUTATING_MODE_CONFIRMATIONS = Object.freeze({
  provision: "MSCQR_PROVISION_STAGING_DATABASE_ROLE_CREDENTIALS",
  "rls-shared-apply": "MSCQR_APPLY_STAGING_RLS_SHARED_BATCH_PHASE",
  "rls-shared-rollback": "MSCQR_ROLLBACK_STAGING_RLS_SHARED_BATCH_PHASE",
});

export function validateBrokerEvent(event) {
  if (!event || typeof event !== "object" || Array.isArray(event) || !Object.hasOwn(event, "mode")) {
    throw new Error("Request must contain the reviewed mode fields.");
  }
  if (typeof event.mode !== "string" || !ALLOWED_MODES.has(event.mode)) throw new Error("Mode is outside the reviewed executor set.");
  const expectedConfirmation = MUTATING_MODE_CONFIRMATIONS[event.mode];
  const expectedKeys = expectedConfirmation ? ["confirmation", "mode"] : ["mode"];
  if (Object.keys(event).sort().join(",") !== expectedKeys.join(",")) throw new Error("Request contains unreviewed fields.");
  if (expectedConfirmation && event.confirmation !== expectedConfirmation) throw new Error("Mutating executor mode requires its distinct exact confirmation.");
  return event.mode;
}

export function fixedRunTaskRequest(mode, config, confirmation) {
  validateBrokerEvent({ mode, ...(confirmation === undefined ? {} : { confirmation }) });
  return {
    cluster: config.clusterArn,
    taskDefinition: config.taskDefinitionArn,
    launchType: "FARGATE",
    count: 1,
    networkConfiguration: {
      awsvpcConfiguration: {
        subnets: [...config.subnets],
        securityGroups: [...config.securityGroups],
        assignPublicIp: "DISABLED",
      },
    },
    overrides: {
      containerOverrides: [{ name: "db-admin", environment: [{ name: "MSCQR_VPC_EXECUTOR_MODE", value: mode }] }],
    },
  };
}

export function createBrokerHandler({ runTask, config, audit = () => {} }) {
  return async (event, context = {}) => {
    const record = (outcome, mode, reason) => audit({
      event: "database_role_executor_broker",
      outcome,
      mode,
      reason,
      requestId: typeof context.awsRequestId === "string" ? context.awsRequestId : "unavailable",
    });
    if (!/^arn:aws:ecs:eu-west-2:368992683803:cluster\/mscqr-staging-euw2-main$/.test(config.clusterArn || "")
        || !/^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-staging-database-role-admin:[1-9][0-9]*$/.test(config.taskDefinitionArn || "")
        || !Array.isArray(config.subnets) || !config.subnets.length || config.subnets.some((value) => !/^subnet-[a-f0-9]+$/.test(value))
        || !Array.isArray(config.securityGroups) || !config.securityGroups.length || config.securityGroups.some((value) => !/^sg-[a-f0-9]+$/.test(value))
        || !/^[a-f0-9]{64}$/.test(config.executorContractSha256 || "")
        || !/^[a-f0-9]{64}$/.test(config.brokerSourceSha256 || "")) {
      record("blocked", "untrusted", "configuration");
      throw new Error("Broker immutable configuration is outside the reviewed staging contract.");
    }
    let mode;
    try { mode = validateBrokerEvent(event); }
    catch (error) { record("blocked", "untrusted", "request"); throw error; }
    record("accepted", mode, "validated");
    let response;
    try { response = await runTask(fixedRunTaskRequest(mode, config, event.confirmation)); }
    catch { record("blocked", mode, "run-task"); throw new Error("Reviewed disposable task launch failed; detail suppressed."); }
    if ((response?.failures || []).length || response?.tasks?.length !== 1) {
      record("blocked", mode, "task-count");
      throw new Error("Reviewed disposable task did not start exactly once.");
    }
    const taskArn = response.tasks[0]?.taskArn;
    const prefix = `${config.clusterArn.replace(":cluster/", ":task/")}/`;
    if (typeof taskArn !== "string" || !taskArn.startsWith(prefix)) {
      record("blocked", mode, "task-identity");
      throw new Error("Started task ARN is outside the reviewed staging cluster.");
    }
    record("started", mode, "single-task");
    return {
      status: "started", taskArn,
      taskDefinitionArn: config.taskDefinitionArn,
      executorContractSha256: config.executorContractSha256,
      brokerSourceSha256: config.brokerSourceSha256,
    };
  };
}

const configFromEnvironment = () => ({
  clusterArn: process.env.BROKER_CLUSTER_ARN,
  taskDefinitionArn: process.env.BROKER_TASK_DEFINITION_ARN,
  subnets: JSON.parse(process.env.BROKER_PRIVATE_SUBNETS_JSON || "[]"),
  securityGroups: JSON.parse(process.env.BROKER_SECURITY_GROUPS_JSON || "[]"),
  executorContractSha256: process.env.BROKER_EXECUTOR_CONTRACT_SHA256,
  brokerSourceSha256: process.env.BROKER_SOURCE_SHA256,
});

export async function handler(event, context) {
  const { ECSClient, RunTaskCommand } = await import("@aws-sdk/client-ecs");
  const client = new ECSClient({ region: "eu-west-2" });
  return createBrokerHandler({
    runTask: (request) => client.send(new RunTaskCommand(request)),
    config: configFromEnvironment(),
    audit: (record) => console.info(JSON.stringify(record)),
  })(event, context);
}
