import { execFileSync } from "node:child_process";
import { STAGE_B } from "./production-green-stage-b-contract.mjs";
import { STAGE_B_TASK_DEFINITION_FAMILY_NAMES } from "./stage-b-reference-audit-contract.mjs";

export const STAGE_B_ECS_READ_ACTIONS = Object.freeze([
  "ecs:ListServices",
  "ecs:DescribeServices",
  "ecs:ListTasks",
  "ecs:DescribeTasks",
  "ecs:DescribeTaskDefinition",
]);

const taskDefinitionArnPattern = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/([A-Za-z0-9_-]+):([1-9][0-9]*)$/;
const serviceArnPattern = /^arn:aws:ecs:eu-west-2:368992683803:service\/mscqr-prod-euw2-main\/([A-Za-z0-9_-]+)$/;
const taskArnPattern = /^arn:aws:ecs:eu-west-2:368992683803:task\/mscqr-prod-euw2-main\/([A-Za-z0-9_-]+)$/;

const requireObject = (value, label) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} is malformed.`);
  return value;
};

const requireArray = (value, label) => {
  if (!Array.isArray(value)) throw new Error(`${label} is malformed.`);
  return value;
};

export function batch(items, size) {
  if (!Array.isArray(items)) throw new TypeError("Batch input must be an array.");
  if (!Number.isInteger(size) || size < 1) throw new RangeError("Batch size must be a positive integer.");
  const batches = [];
  for (let index = 0; index < items.length; index += size) batches.push(items.slice(index, index + size));
  return batches;
}

function validateArns(arns, pattern, label) {
  requireArray(arns, label);
  if (!arns.every((arn) => typeof arn === "string" && pattern.test(arn))) throw new Error(`${label} contains an unknown Stage B ARN.`);
  if (new Set(arns).size !== arns.length) throw new Error(`${label} contains duplicate ARNs.`);
  return arns;
}

function validateFailure(failure, label) {
  requireObject(failure, label);
  if (typeof failure.arn !== "string" || !failure.arn || typeof failure.reason !== "string" || !failure.reason) {
    throw new Error(`${label} contains a malformed failure.`);
  }
}

function describeServices(reader, serviceArns) {
  validateArns(serviceArns, serviceArnPattern, "ECS service listing");
  const described = [];
  for (const serviceBatch of batch(serviceArns, 10)) {
    const response = requireObject(reader.describeServices(serviceBatch), "ECS service description");
    const services = requireArray(response.services, "ECS service description services");
    const failures = requireArray(response.failures, "ECS service description failures");
    failures.forEach((failure) => validateFailure(failure, "ECS service description failures"));
    if (failures.length) throw new Error("ECS service description contains failures.");
    described.push(...services);
  }
  const expected = new Set(serviceArns);
  const returned = new Set();
  for (const service of described) {
    requireObject(service, "ECS service description");
    if (typeof service.serviceArn !== "string" || typeof service.serviceName !== "string" || typeof service.taskDefinition !== "string") {
      throw new Error("ECS service description is incomplete.");
    }
    if (!serviceArnPattern.test(service.serviceArn) || !expected.has(service.serviceArn)) throw new Error("ECS service description contains an unexpected service.");
    if (returned.has(service.serviceArn)) throw new Error("ECS service description contains a duplicate service.");
    returned.add(service.serviceArn);
  }
  if (returned.size !== expected.size) throw new Error("ECS service description is incomplete.");
  return [...described].sort((left, right) => left.serviceArn.localeCompare(right.serviceArn)).map((service) => ({
    serviceName: service.serviceName,
    taskDefinition: service.taskDefinition,
    runningCount: service.runningCount,
    pendingCount: service.pendingCount,
    status: service.status,
  }));
}

function describeTasks(reader, status, taskArns) {
  validateArns(taskArns, taskArnPattern, `ECS ${status.toLowerCase()} task listing`);
  const described = [];
  for (const taskBatch of batch(taskArns, 100)) {
    const response = requireObject(reader.describeTasks(taskBatch), `ECS ${status.toLowerCase()} task description`);
    const tasks = requireArray(response.tasks, `ECS ${status.toLowerCase()} task description tasks`);
    const failures = requireArray(response.failures, `ECS ${status.toLowerCase()} task description failures`);
    failures.forEach((failure) => validateFailure(failure, `ECS ${status.toLowerCase()} task description failures`));
    if (failures.length) throw new Error(`ECS ${status.toLowerCase()} task description contains failures.`);
    described.push(...tasks);
  }
  const expected = new Set(taskArns);
  const returned = new Set();
  for (const task of described) {
    requireObject(task, `ECS ${status.toLowerCase()} task description`);
    if (typeof task.taskArn !== "string" || typeof task.taskDefinitionArn !== "string" || typeof task.lastStatus !== "string" || typeof task.desiredStatus !== "string" || typeof task.group !== "string") {
      throw new Error(`ECS ${status.toLowerCase()} task description is incomplete.`);
    }
    if (!taskArnPattern.test(task.taskArn) || !expected.has(task.taskArn)) throw new Error(`ECS ${status.toLowerCase()} task description contains an unexpected task.`);
    if (returned.has(task.taskArn)) throw new Error(`ECS ${status.toLowerCase()} task description contains a duplicate task.`);
    returned.add(task.taskArn);
  }
  if (returned.size !== expected.size) throw new Error(`ECS ${status.toLowerCase()} task description is incomplete.`);
  return [...described].sort((left, right) => left.taskArn.localeCompare(right.taskArn)).map((task) => ({
    taskArn: task.taskArn,
    taskDefinitionArn: task.taskDefinitionArn,
    lastStatus: task.lastStatus,
    desiredStatus: task.desiredStatus,
    group: task.group,
  }));
}

function describeReferencedTaskDefinitions(reader, references) {
  const unique = [...new Set(references)].sort();
  return unique.map((arn) => {
    if (!taskDefinitionArnPattern.test(arn)) throw new Error("ECS observation contains an ARN that is not a valid ECS task-definition ARN.");
    const requestedFamily = taskDefinitionArnPattern.exec(arn)[1];
    if (!STAGE_B_TASK_DEFINITION_FAMILY_NAMES.includes(requestedFamily)) throw new Error(`ECS task-definition family is outside the Stage B contract: ${requestedFamily}`);
    const response = requireObject(reader.describeTaskDefinition(arn), "ECS task-definition description");
    const taskDefinition = requireObject(response.taskDefinition, "ECS task-definition description taskDefinition");
    const match = taskDefinitionArnPattern.exec(taskDefinition.taskDefinitionArn || "");
    if (!match || taskDefinition.taskDefinitionArn !== arn || taskDefinition.family !== match[1] || Number(taskDefinition.revision) !== Number(match[2]) || taskDefinition.status !== "ACTIVE") {
      throw new Error(`ECS task-definition observation is incomplete: ${arn}`);
    }
    if (!STAGE_B_TASK_DEFINITION_FAMILY_NAMES.includes(taskDefinition.family)) throw new Error(`ECS task-definition family is outside the Stage B contract: ${taskDefinition.family}`);
    return { arn, family: taskDefinition.family, revision: Number(taskDefinition.revision), status: taskDefinition.status };
  });
}

export function observeStageBEcs({ reader, region = STAGE_B.region, clusterArn = STAGE_B.clusterArn }) {
  if (!reader) throw new Error("Stage B ECS observation reader is required.");
  if (region !== STAGE_B.region || clusterArn !== STAGE_B.clusterArn) throw new Error("Stage B ECS observation requires the exact production region and cluster.");
  const serviceArns = validateArns(reader.listServices(), serviceArnPattern, "ECS service listing");
  const services = describeServices(reader, serviceArns);
  const readTasks = (status) => describeTasks(reader, status, validateArns(reader.listTasks(status), taskArnPattern, `ECS ${status.toLowerCase()} task listing`));
  const runningTasks = readTasks("RUNNING");
  const pendingTasks = readTasks("PENDING");
  const references = [
    ...services.map((service) => service.taskDefinition),
    ...runningTasks.map((task) => task.taskDefinitionArn),
    ...pendingTasks.map((task) => task.taskDefinitionArn),
  ];
  return { services, runningTasks, pendingTasks, taskDefinitions: describeReferencedTaskDefinitions(reader, references) };
}

const COMMANDS = Object.freeze({
  caller: ["sts", "get-caller-identity"],
  listServices: ["ecs", "list-services"],
  describeServices: ["ecs", "describe-services"],
  listTasks: ["ecs", "list-tasks"],
  describeTasks: ["ecs", "describe-tasks"],
  describeTaskDefinition: ["ecs", "describe-task-definition"],
  getFunctionConfiguration: ["lambda", "get-function-configuration"],
});

function parseJson(value, label) {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${label} is missing.`);
  try { return JSON.parse(value); } catch { throw new Error(`${label} is malformed JSON.`); }
}

function createAwsReader({ region, clusterArn, run = (args) => execFileSync("aws", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) }) {
  if (region !== STAGE_B.region || clusterArn !== STAGE_B.clusterArn) throw new Error("Stage B ECS reader requires the exact production region and cluster.");
  const call = (name, args) => {
    try { return parseJson(run([...COMMANDS[name], ...args, "--region", region, "--output", "json", "--no-cli-pager"]), `AWS ${name}`); }
    catch (error) {
      if (error instanceof Error && /malformed|missing/.test(error.message)) throw error;
      throw new Error(`AWS read failed: ${name}`);
    }
  };
  const listAll = (name, args, key) => {
    const values = [];
    let nextToken;
    do {
      const response = call(name, nextToken ? [...args, "--starting-token", nextToken] : args);
      values.push(...requireArray(response[key], `AWS ${name} ${key}`));
      const next = response.nextToken;
      if (next !== undefined && (typeof next !== "string" || !next)) throw new Error(`AWS ${name} pagination token is malformed.`);
      if (nextToken && next === nextToken) throw new Error(`AWS ${name} pagination did not advance.`);
      nextToken = next;
    } while (nextToken);
    return values;
  };
  return {
    getCallerIdentity: () => call("caller", []),
    listServices: () => listAll("listServices", ["--cluster", clusterArn], "serviceArns"),
    describeServices: (serviceArns) => call("describeServices", ["--cluster", clusterArn, "--services", ...serviceArns]),
    listTasks: (status) => listAll("listTasks", ["--cluster", clusterArn, "--desired-status", status], "taskArns"),
    describeTasks: (taskArns) => call("describeTasks", ["--cluster", clusterArn, "--tasks", ...taskArns]),
    describeTaskDefinition: (taskDefinition) => call("describeTaskDefinition", ["--task-definition", taskDefinition]),
    getFunctionConfiguration: (functionArn) => call("getFunctionConfiguration", ["--function-name", functionArn]),
  };
}

export { createAwsReader };
