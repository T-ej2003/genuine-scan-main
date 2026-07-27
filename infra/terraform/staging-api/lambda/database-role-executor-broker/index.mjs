export const BLUE_EXECUTOR_MODES = Object.freeze([
  "probe", "provision", "verify",
]);
export const GREEN_EXECUTOR_MODES = Object.freeze([
  "full-rls-capability-preflight",
  "full-rls-role-provision",
  "full-rls-role-verify",
  "full-rls-admin-bootstrap",
  "full-rls-admin-ownership",
  "full-rls-runtime-policy",
  "full-rls-verification",
  "full-rls-rollback",
]);
const ALLOWED_MODES = new Set([...BLUE_EXECUTOR_MODES, ...GREEN_EXECUTOR_MODES]);
export const MUTATING_MODE_CONFIRMATIONS = Object.freeze({
  provision: "MSCQR_PROVISION_STAGING_DATABASE_ROLE_CREDENTIALS",
});
export const GREEN_MUTATING_MODE_CONFIRMATIONS = Object.freeze({
  "full-rls-role-provision": "MSCQR_STAGING_GREEN_PROVISION_RUNTIME_ROLES",
  "full-rls-admin-bootstrap": "MSCQR_STAGING_GREEN_CREATE_AND_BOOTSTRAP_DATABASE",
  "full-rls-admin-ownership": "MSCQR_STAGING_GREEN_INSTALL_OWNERSHIP_GRANTS",
  "full-rls-runtime-policy": "MSCQR_STAGING_GREEN_INSTALL_RUNTIME_POLICIES",
  "full-rls-rollback": "MSCQR_STAGING_GREEN_ROLLBACK_EXACT_PACKAGE",
});

export function validateBrokerEvent(event) {
  if (!event || typeof event !== "object" || Array.isArray(event) || !Object.hasOwn(event, "mode")) {
    throw new Error("Request must contain the reviewed mode fields.");
  }
  if (typeof event.mode !== "string" || !ALLOWED_MODES.has(event.mode)) throw new Error("Mode is outside the reviewed executor set.");
  const expectedConfirmation = MUTATING_MODE_CONFIRMATIONS[event.mode]
    || GREEN_MUTATING_MODE_CONFIRMATIONS[event.mode];
  const expectedKeys = expectedConfirmation ? ["confirmation", "mode"] : ["mode"];
  if (Object.keys(event).sort().join(",") !== expectedKeys.join(",")) throw new Error("Request contains unreviewed fields.");
  if (expectedConfirmation && event.confirmation !== expectedConfirmation) throw new Error("Mutating executor mode requires its distinct exact confirmation.");
  return event.mode;
}

export function fixedRunTaskRequest(mode, config, confirmation) {
  validateBrokerEvent({ mode, ...(confirmation === undefined ? {} : { confirmation }) });
  const greenTaskDefinition = config.greenTaskDefinitionArns?.[mode];
  const green = GREEN_EXECUTOR_MODES.includes(mode);
  return {
    cluster: config.clusterArn,
    taskDefinition: green ? greenTaskDefinition : config.taskDefinitionArn,
    launchType: "FARGATE",
    count: 1,
    networkConfiguration: {
      awsvpcConfiguration: {
        subnets: [...config.subnets],
        securityGroups: [...config.securityGroups],
        assignPublicIp: "DISABLED",
      },
    },
    ...(green ? {} : { overrides: {
      containerOverrides: [{ name: "db-admin", environment: [{ name: "MSCQR_VPC_EXECUTOR_MODE", value: mode }] }],
    } }),
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
    const greenTaskDefinitions = Object.entries(config.greenTaskDefinitionArns || {});
    if (!/^arn:aws:ecs:eu-west-2:368992683803:cluster\/mscqr-staging-euw2-main$/.test(config.clusterArn || "")
        || !/^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-staging-database-role-admin:[1-9][0-9]*$/.test(config.taskDefinitionArn || "")
        || greenTaskDefinitions.length !== GREEN_EXECUTOR_MODES.length
        || greenTaskDefinitions.some(([mode, arn]) =>
          !GREEN_EXECUTOR_MODES.includes(mode)
          || !new RegExp(`^arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-staging-full-rls-green-${mode.replace("full-rls-", "")}:[1-9][0-9]*$`).test(arn)
        )
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
    const request = fixedRunTaskRequest(mode, config, event.confirmation);
    let response;
    try { response = await runTask(request); }
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
      taskDefinitionArn: request.taskDefinition,
      executor: GREEN_EXECUTOR_MODES.includes(mode) ? "green" : "blue",
      executorContractSha256: config.executorContractSha256,
      brokerSourceSha256: config.brokerSourceSha256,
    };
  };
}

const configFromEnvironment = () => ({
  clusterArn: process.env.BROKER_CLUSTER_ARN,
  taskDefinitionArn: process.env.BROKER_TASK_DEFINITION_ARN,
  greenTaskDefinitionArns: JSON.parse(process.env.BROKER_GREEN_TASK_DEFINITIONS_JSON || "{}"),
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
