#!/usr/bin/env node
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { STAGE_B, STAGE_B_MODES } from "./production-green-stage-b-contract.mjs";
import {
  STAGE_B_REFERENCE_AUDIT_SCHEMA_VERSION,
  STAGE_B_TASK_DEFINITION_FAMILIES,
  STAGE_B_TASK_DEFINITION_FAMILY_NAMES,
} from "./stage-b-reference-audit-contract.mjs";

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const taskDefinitionArnPattern = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/([A-Za-z0-9_-]+):([1-9][0-9]*)$/;
const assumedReleaseRolePattern = /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-release-deployer\/[A-Za-z0-9+=,.@_-]{2,64}$/;
const exactReplacePaths = (paths) => JSON.stringify(paths) === JSON.stringify([["container_definitions"]]);
const sorted = (items, key) => [...items].sort((left, right) => String(key(left)).localeCompare(String(key(right))));

const familyFromArn = (value, label) => {
  const match = taskDefinitionArnPattern.exec(value || "");
  if (!match) throw new Error(`${label} is not a valid ECS task-definition ARN.`);
  return { arn: value, family: match[1], revision: Number(match[2]) };
};

const expectedBrokerFamily = (mode) => mode === "full-rls-application-canary"
  ? STAGE_B_TASK_DEFINITION_FAMILIES['aws_ecs_task_definition.candidate["canary"]']
  : `mscqr-production-full-rls-green-${mode}`;

function parseJson(value, label) {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${label} is missing.`);
  try {
    return JSON.parse(value);
  } catch {
    throw new Error(`${label} is malformed JSON.`);
  }
}

function requireArray(value, label) {
  if (!Array.isArray(value)) throw new Error(`${label} is malformed.`);
  return value;
}

function requireObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} is malformed.`);
  return value;
}

function observedFamily(value, label) {
  const { family } = familyFromArn(value, label);
  if (family.startsWith("mscqr-production-") && !STAGE_B_TASK_DEFINITION_FAMILY_NAMES.includes(family)) {
    throw new Error(`${label} contains an unknown Stage B task-definition family.`);
  }
  return family;
}

function normalizeEnvironment(config) {
  const environment = Array.isArray(config?.Environment) ? config.Environment[0] : config?.Environment;
  const variables = environment?.Variables;
  return requireObject(variables, "broker Lambda environment variables");
}

function planTaskDefinitions(plan) {
  const changes = requireArray(plan?.resource_changes, "Terraform plan resource_changes");
  const seenFamilies = new Set();
  const rolloverByAddress = new Map();
  for (const change of changes.filter((item) => item?.type === "aws_ecs_task_definition")) {
    const address = change.address;
    const before = change.change?.before || {};
    const after = change.change?.after || {};
    const family = after.family || before.family;
    if (typeof family !== "string" || !family) throw new Error(`Terraform plan task-definition family is missing: ${address}`);
    if (!Object.values(STAGE_B_TASK_DEFINITION_FAMILIES).includes(family)) throw new Error(`Terraform plan contains an unknown Stage B task-definition family: ${family}`);
    if (seenFamilies.has(family)) throw new Error(`Terraform plan contains a duplicate Stage B task-definition family: ${family}`);
    seenFamilies.add(family);
    if (STAGE_B_TASK_DEFINITION_FAMILIES[address] !== family) throw new Error(`Terraform plan task-definition address does not match its exact family: ${address}`);
    if (after.family !== family) throw new Error(`Terraform plan proposed task-definition family is unresolved: ${address}`);
    const actions = requireArray(change.change?.actions, `Terraform plan actions for ${address}`);
    if (actions.includes("delete")) {
      if (JSON.stringify(actions) !== JSON.stringify(["delete", "create"]) || !exactReplacePaths(change.change?.replace_paths)) {
        throw new Error(`Terraform plan task-definition rollover is outside the reviewed contract: ${address}`);
      }
      const oldArn = before.arn || before.id;
      const old = familyFromArn(oldArn, `${address} old task definition`);
      if (old.family !== family) throw new Error(`Terraform plan old task-definition family mismatch: ${address}`);
      rolloverByAddress.set(address, { address, family, oldArn, replacePaths: change.change.replace_paths, proposedFamily: after.family });
    }
  }
  return rolloverByAddress;
}

function ensurePlanHash(planBytes, expectedPlanSha256) {
  if (!Buffer.isBuffer(planBytes) || planBytes.length === 0) throw new Error("Terraform plan JSON is missing.");
  if (!/^[a-f0-9]{64}$/.test(expectedPlanSha256 || "")) throw new Error("Terraform plan SHA-256 is missing or malformed.");
  const actual = sha256(planBytes);
  if (actual !== expectedPlanSha256) throw new Error("Terraform plan SHA-256 does not match the supplied plan JSON.");
  return actual;
}

function validateCaller(callerArn) {
  if (!assumedReleaseRolePattern.test(callerArn || "")) throw new Error("Caller is not the MFA-backed production release-deployer role.");
  return callerArn;
}

function validateTaskDefinitionResponse(response, expectedFamily, label) {
  const taskDefinition = requireObject(response?.taskDefinition, `${label} response`);
  const identity = familyFromArn(taskDefinition.taskDefinitionArn, `${label} taskDefinitionArn`);
  if (identity.family !== expectedFamily || taskDefinition.family !== expectedFamily || taskDefinition.revision !== identity.revision) {
    throw new Error(`${label} does not match its exact expected task-definition family.`);
  }
  if (typeof taskDefinition.status !== "string" || !taskDefinition.status) throw new Error(`${label} status is missing.`);
  return { family: expectedFamily, arn: identity.arn, revision: identity.revision, status: taskDefinition.status };
}

function validateBrokerConfiguration(config, brokerFunctionArn, expectedPackageChecksum, oldArns) {
  const normalizedConfigArn = String(config?.FunctionArn || "").replace(/:(?:reviewed|[1-9][0-9]*)$/, "");
  const normalizedExpectedArn = String(brokerFunctionArn).replace(/:(?:reviewed|[1-9][0-9]*)$/, "");
  if (!normalizedConfigArn || normalizedConfigArn !== normalizedExpectedArn) throw new Error("Broker Lambda identity does not match the expected function.");
  if (typeof config.Version !== "string" || !/^[1-9][0-9]*$/.test(config.Version)) throw new Error("Broker Lambda version is missing or malformed.");
  const variables = normalizeEnvironment(config);
  const taskDefinitions = requireObject(parseJson(variables.BROKER_TASK_DEFINITIONS_JSON, "BROKER_TASK_DEFINITIONS_JSON"), "BROKER_TASK_DEFINITIONS_JSON");
  const expectedModes = [...STAGE_B_MODES].sort();
  if (JSON.stringify(Object.keys(taskDefinitions).sort()) !== JSON.stringify(expectedModes)) throw new Error("Broker task-definition mode set is not exact.");
  const brokerReferences = new Map();
  for (const mode of expectedModes) {
    const identity = familyFromArn(taskDefinitions[mode], `broker task definition for ${mode}`);
    if (identity.family !== expectedBrokerFamily(mode)) throw new Error(`Broker task definition family is unexpected for ${mode}.`);
    brokerReferences.set(identity.arn, mode);
  }
  for (const oldArn of oldArns) {
    if (brokerReferences.has(oldArn)) throw new Error(`Broker Lambda still references superseded task definition ${oldArn}.`);
  }
  const approvalExpected = requireObject(parseJson(variables.BROKER_APPROVAL_EXPECTED_JSON, "BROKER_APPROVAL_EXPECTED_JSON"), "BROKER_APPROVAL_EXPECTED_JSON");
  if (approvalExpected.packageChecksumSha256 !== expectedPackageChecksum) throw new Error("Broker package checksum does not match the expected release package.");
  return {
    functionArn: normalizedConfigArn,
    functionVersion: config.Version,
    aliasArn: brokerFunctionArn,
    aliasVersion: config.Version,
    taskDefinitionModes: expectedModes,
  };
}

function referenceNames(items, oldArns, arnKey, nameKey) {
  const references = new Map(oldArns.map((arn) => [arn, []]));
  for (const item of items) {
    const arn = item[arnKey];
    if (references.has(arn)) references.get(arn).push(item[nameKey]);
  }
  return references;
}

export function generateReferenceAudit({
  plan,
  planBytes,
  planJsonSha256,
  region,
  clusterArn,
  brokerFunctionArn,
  expectedPackageChecksumSha256,
  reader,
  callerArn,
  auditedAt = new Date().toISOString(),
}) {
  if (!reader) throw new Error("Read-only AWS reader is required.");
  if (region !== "eu-west-2") throw new Error("Stage B requires AWS region eu-west-2.");
  if (clusterArn !== STAGE_B.clusterArn) throw new Error("ECS cluster ARN is outside the exact Stage B contract.");
  if (brokerFunctionArn !== STAGE_B.brokerAliasArn) throw new Error("Broker Lambda alias ARN is outside the exact Stage B contract.");
  if (!/^[a-f0-9]{64}$/.test(expectedPackageChecksumSha256 || "")) throw new Error("Expected broker package checksum is missing or malformed.");
  if (!Number.isFinite(Date.parse(auditedAt))) throw new Error("Audit timestamp is malformed.");
  const planSha = ensurePlanHash(planBytes, planJsonSha256);
  const rolloverByAddress = planTaskDefinitions(plan);
  const observedCallerArn = validateCaller(callerArn || reader.getCallerIdentity()?.Arn);

  const taskDefinitions = new Map();
  for (const family of STAGE_B_TASK_DEFINITION_FAMILY_NAMES) {
    const response = reader.describeTaskDefinition(family);
    taskDefinitions.set(family, validateTaskDefinitionResponse(response, family, `Stage B family ${family}`));
  }
  const oldDefinitions = [];
  for (const rollover of [...rolloverByAddress.values()].sort((left, right) => left.address.localeCompare(right.address))) {
    const described = validateTaskDefinitionResponse(reader.describeTaskDefinition(rollover.oldArn), rollover.family, `${rollover.address} old task definition`);
    oldDefinitions.push({ ...rollover, currentStatus: described.status, rollbackArn: described.arn });
  }
  const oldArns = oldDefinitions.map((entry) => entry.oldArn);

  const serviceArns = requireArray(reader.listServices(), "ECS service listing");
  if (!serviceArns.every((arn) => typeof arn === "string" && arn.startsWith("arn:aws:ecs:"))) throw new Error("ECS service listing is malformed.");
  const serviceResponse = serviceArns.length ? reader.describeServices(serviceArns) : { services: [] };
  const services = sorted(requireArray(serviceResponse?.services, "ECS service description"), (item) => item.serviceName).map((service) => {
    if (typeof service.serviceName !== "string" || typeof service.taskDefinition !== "string") throw new Error("ECS service description is incomplete.");
    observedFamily(service.taskDefinition, `ECS service ${service.serviceName} task definition`);
    return {
      serviceName: service.serviceName,
      taskDefinition: service.taskDefinition,
      runningCount: service.runningCount,
      pendingCount: service.pendingCount,
      status: service.status,
    };
  });

  const readTasks = (status) => {
    const taskArns = requireArray(reader.listTasks(status), `ECS ${status.toLowerCase()} task listing`);
    if (!taskArns.every((arn) => typeof arn === "string" && arn.startsWith("arn:aws:ecs:"))) throw new Error(`ECS ${status.toLowerCase()} task listing is malformed.`);
    const response = taskArns.length ? reader.describeTasks(taskArns) : { tasks: [] };
    const tasks = requireArray(response?.tasks, `ECS ${status.toLowerCase()} task description`);
    if (tasks.length !== taskArns.length) throw new Error(`ECS ${status.toLowerCase()} task description is incomplete.`);
    return sorted(tasks.map((task) => {
      if (typeof task.taskArn !== "string" || typeof task.taskDefinitionArn !== "string" || typeof task.lastStatus !== "string" || typeof task.desiredStatus !== "string" || typeof task.group !== "string") {
        throw new Error(`ECS ${status.toLowerCase()} task description is incomplete.`);
      }
      observedFamily(task.taskDefinitionArn, `${status} task ${task.taskArn} task definition`);
      return { taskArn: task.taskArn, taskDefinitionArn: task.taskDefinitionArn, lastStatus: task.lastStatus, desiredStatus: task.desiredStatus, group: task.group };
    }), (item) => item.taskArn);
  };
  const runningTasks = readTasks("RUNNING");
  const pendingTasks = readTasks("PENDING");
  const broker = validateBrokerConfiguration(reader.getFunctionConfiguration(brokerFunctionArn), brokerFunctionArn, expectedPackageChecksumSha256, oldArns);
  const serviceReferences = referenceNames(services, oldArns, "taskDefinition", "serviceName");
  const runningReferences = referenceNames(runningTasks, oldArns, "taskDefinitionArn", "taskArn");
  const pendingReferences = referenceNames(pendingTasks, oldArns, "taskDefinitionArn", "taskArn");
  const brokerReferences = new Map(oldArns.map((arn) => [arn, []]));

  const auditedOldDefinitions = oldDefinitions.map((entry) => {
    const serviceRefs = [...(serviceReferences.get(entry.oldArn) || [])].sort();
    const runningRefs = [...(runningReferences.get(entry.oldArn) || [])].sort();
    const pendingRefs = [...(pendingReferences.get(entry.oldArn) || [])].sort();
    const brokerRefs = [...(brokerReferences.get(entry.oldArn) || [])].sort();
    if (serviceRefs.length || runningRefs.length || pendingRefs.length || brokerRefs.length) throw new Error(`Superseded task definition remains referenced: ${entry.address}`);
    return {
      terraformAddress: entry.address,
      oldTaskDefinitionArn: entry.oldArn,
      family: entry.family,
      proposedFamily: entry.proposedFamily,
      replacePaths: entry.replacePaths,
      currentStatus: entry.currentStatus,
      serviceReferences: serviceRefs,
      runningTaskReferences: runningRefs,
      pendingTaskReferences: pendingRefs,
      brokerReferenceModes: brokerRefs,
      brokerReferenceStatus: "not-referenced-by-broker-v1",
      rollbackArn: entry.rollbackArn,
      sameFamilyAsReplacement: entry.family === entry.proposedFamily,
    };
  });

  return {
    schemaVersion: STAGE_B_REFERENCE_AUDIT_SCHEMA_VERSION,
    auditedAt,
    callerArn: observedCallerArn,
    clusterArn,
    broker,
    services,
    runningTasks,
    pendingTasks,
    allOldRevisionsUnreferenced: true,
    noServiceDeploymentObserved: true,
    noTaskExecutionObserved: true,
    oldTaskDefinitions: auditedOldDefinitions,
    planJsonSha256: planSha,
  };
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

export function createAwsReader({ region, clusterArn, run = (args) => execFileSync("aws", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }) }) {
  const call = (name, args) => {
    try {
      return parseJson(run([...COMMANDS[name], ...args, "--region", region, "--output", "json"]), `AWS ${name}`);
    } catch (error) {
      if (error instanceof Error && /malformed|missing/.test(error.message)) throw error;
      throw new Error(`AWS read failed: ${name}`);
    }
  };
  return {
    getCallerIdentity: () => call("caller", []),
    listServices: () => call("listServices", ["--cluster", clusterArn]).serviceArns,
    describeServices: (serviceArns) => call("describeServices", ["--cluster", clusterArn, "--services", ...serviceArns]),
    listTasks: (status) => call("listTasks", ["--cluster", clusterArn, "--desired-status", status]).taskArns,
    describeTasks: (taskArns) => call("describeTasks", ["--cluster", clusterArn, "--tasks", ...taskArns]),
    describeTaskDefinition: (taskDefinition) => call("describeTaskDefinition", ["--task-definition", taskDefinition]),
    getFunctionConfiguration: (functionArn) => call("getFunctionConfiguration", ["--function-name", functionArn]),
  };
}

function readOption(argv, option) {
  const index = argv.indexOf(option);
  return index === -1 ? undefined : argv[index + 1];
}

function requireOption(argv, option) {
  const value = readOption(argv, option);
  if (!value || value.startsWith("--")) throw new Error(`${option} is required.`);
  return value;
}

export function parseCli(argv) {
  const planJsonPath = requireOption(argv, "--plan-json");
  const planJsonSha256 = requireOption(argv, "--plan-sha256");
  const outputPath = requireOption(argv, "--output");
  const region = requireOption(argv, "--region");
  const clusterArn = requireOption(argv, "--cluster-arn");
  const brokerFunctionArn = requireOption(argv, "--broker-function");
  const expectedPackageChecksumSha256 = requireOption(argv, "--expected-package-checksum-sha256");
  if (!path.isAbsolute(planJsonPath) || !path.isAbsolute(outputPath)) throw new Error("Plan and output paths must be absolute.");
  return { planJsonPath, planJsonSha256, outputPath, region, clusterArn, brokerFunctionArn, expectedPackageChecksumSha256, auditedAt: readOption(argv, "--audited-at") || new Date().toISOString() };
}

export async function runCli(argv = process.argv.slice(2)) {
  const options = parseCli(argv);
  const planBytes = fs.readFileSync(options.planJsonPath);
  const plan = parseJson(planBytes.toString("utf8"), "Terraform plan JSON");
  const reader = createAwsReader(options);
  const audit = generateReferenceAudit({ ...options, plan, planBytes, reader, callerArn: reader.getCallerIdentity().Arn });
  fs.mkdirSync(path.dirname(options.outputPath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(options.outputPath, `${JSON.stringify(audit, null, 2)}\n`, { mode: 0o600 });
  return { outputPath: options.outputPath, auditSha256: sha256(fs.readFileSync(options.outputPath)), planJsonSha256: audit.planJsonSha256 };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  runCli().then((result) => process.stdout.write(`${JSON.stringify({ status: "generated", ...result })}\n`)).catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
