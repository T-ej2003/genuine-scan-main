const ALLOWED_MODES = new Set(["probe", "provision", "verify"]);

export function validateBrokerEvent(event) {
  if (!event || typeof event !== "object" || Array.isArray(event) || Object.keys(event).length !== 1 || !Object.hasOwn(event, "mode")) {
    throw new Error("Request must contain exactly one field: mode.");
  }
  if (typeof event.mode !== "string" || !ALLOWED_MODES.has(event.mode)) throw new Error("Mode must be probe, provision, or verify.");
  return event.mode;
}

export function fixedRunTaskRequest(mode, config) {
  validateBrokerEvent({ mode });
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

export function createBrokerHandler({ runTask, config }) {
  return async (event) => {
    const mode = validateBrokerEvent(event);
    const response = await runTask(fixedRunTaskRequest(mode, config));
    if ((response?.failures || []).length || response?.tasks?.length !== 1) throw new Error("Reviewed disposable task did not start exactly once.");
    const taskArn = response.tasks[0]?.taskArn;
    const prefix = `${config.clusterArn.replace(":cluster/", ":task/")}/`;
    if (typeof taskArn !== "string" || !taskArn.startsWith(prefix)) throw new Error("Started task ARN is outside the reviewed staging cluster.");
    return { status: "started", taskArn };
  };
}

const configFromEnvironment = () => ({
  clusterArn: process.env.BROKER_CLUSTER_ARN,
  taskDefinitionArn: process.env.BROKER_TASK_DEFINITION_ARN,
  subnets: JSON.parse(process.env.BROKER_PRIVATE_SUBNETS_JSON || "[]"),
  securityGroups: JSON.parse(process.env.BROKER_SECURITY_GROUPS_JSON || "[]"),
});

export async function handler(event) {
  const { ECSClient, RunTaskCommand } = await import("@aws-sdk/client-ecs");
  const client = new ECSClient({ region: "eu-west-2" });
  return createBrokerHandler({ runTask: (request) => client.send(new RunTaskCommand(request)), config: configFromEnvironment() })(event);
}
