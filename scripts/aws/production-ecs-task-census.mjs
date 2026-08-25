const TASK_ARN = /^arn:aws:ecs:eu-west-2:368992683803:task\/([^/]+)\/[a-f0-9]{32}$/;

export const ECS_TASK_CENSUS = Object.freeze({ pageSize: 100, describeBatchSize: 100, maxPages: 10, maxTasks: 1_000 });

export async function collectEcsServiceTaskArns({ aws, cluster, service, desiredStatus } = {}) {
  if (typeof aws !== "function" || !/^[A-Za-z0-9_-]{1,255}$/.test(cluster || "") || !/^[A-Za-z0-9_-]{1,255}$/.test(service || "")
    || !["RUNNING", "STOPPED"].includes(desiredStatus)) throw new Error("ECS task census inputs are invalid.");
  const taskArns = new Set(); const tokens = new Set(); let nextToken;
  for (let page = 0; page < ECS_TASK_CENSUS.maxPages; page += 1) {
    const args = ["ecs", "list-tasks", "--cluster", cluster, "--service-name", service, "--desired-status", desiredStatus,
      "--page-size", String(ECS_TASK_CENSUS.pageSize), "--max-items", String(ECS_TASK_CENSUS.pageSize)];
    if (nextToken) args.push("--starting-token", nextToken);
    const response = await aws(args);
    if (!response || typeof response !== "object" || Array.isArray(response) || !Array.isArray(response.taskArns)) throw new Error("ECS task census page is malformed.");
    if (Object.hasOwn(response, "nextToken")) throw new Error("ECS task census pagination token is malformed or cyclic.");
    for (const arn of response.taskArns) {
      if (!TASK_ARN.test(arn || "") || TASK_ARN.exec(arn)[1] !== cluster) throw new Error("ECS task census returned an invalid task ARN.");
      taskArns.add(arn);
      if (taskArns.size > ECS_TASK_CENSUS.maxTasks) throw new Error("ECS task census exceeds the bounded task limit.");
    }
    const token = response.NextToken;
    if (token === undefined || token === null) return Object.freeze([...taskArns].sort());
    if (typeof token !== "string" || !token || tokens.has(token)) throw new Error("ECS task census pagination token is malformed or cyclic.");
    tokens.add(token); nextToken = token;
  }
  throw new Error("ECS task census exceeds the bounded page limit.");
}

export async function describeEcsTasks({ aws, cluster, taskArns, includeTags = false } = {}) {
  if (typeof aws !== "function" || !/^[A-Za-z0-9_-]{1,255}$/.test(cluster || "") || !Array.isArray(taskArns)) throw new Error("ECS task description inputs are invalid.");
  const requested = [...new Set(taskArns)].sort();
  if (requested.length !== taskArns.length || requested.length > ECS_TASK_CENSUS.maxTasks
    || requested.some((arn) => !TASK_ARN.test(arn) || TASK_ARN.exec(arn)[1] !== cluster)) throw new Error("ECS task description identities are malformed or duplicated.");
  const tasks = new Map();
  for (let offset = 0; offset < requested.length; offset += ECS_TASK_CENSUS.describeBatchSize) {
    const batch = requested.slice(offset, offset + ECS_TASK_CENSUS.describeBatchSize);
    const response = await aws(["ecs", "describe-tasks", "--cluster", cluster, "--tasks", ...batch, ...(includeTags ? ["--include", "TAGS"] : [])]);
    if (!response || !Array.isArray(response.tasks) || !Array.isArray(response.failures) || response.failures.length) throw new Error("ECS task description readback is incomplete.");
    const returned = new Set();
    for (const task of response.tasks) {
      if (!batch.includes(task?.taskArn) || returned.has(task.taskArn) || tasks.has(task.taskArn)) throw new Error("ECS task description readback is conflicting or duplicated.");
      returned.add(task.taskArn); tasks.set(task.taskArn, task);
    }
    if (returned.size !== batch.length) throw new Error("ECS task description readback omitted requested tasks.");
  }
  return Object.freeze([...tasks.values()].sort((left, right) => left.taskArn.localeCompare(right.taskArn)));
}

export async function collectEcsServiceTasks(input = {}) {
  const taskArns = await collectEcsServiceTaskArns(input);
  return describeEcsTasks({ aws: input.aws, cluster: input.cluster, taskArns, includeTags: input.includeTags });
}
