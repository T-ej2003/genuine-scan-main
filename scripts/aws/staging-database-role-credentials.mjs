#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import {
  STAGING_DATABASE_ROLE_CONTEXT as C,
  assertApplyGate,
  assertActiveReviewedBackendDatabaseConsumer,
  assertDatabaseRoleOperatorIdentity,
  assertExpectedAwsIdentity,
  assertReviewedDatabaseConsumers,
  assertRollbackTarget,
  assertRlsRouteFlagsFalse,
  assertRuntimeIdentity,
  assertSafeStagingHttpUrl,
  assertServiceStable,
  assertStagingOnlyName,
  assertTaskDefinitionOnlyDatabaseSecretChanged,
  assertVpcExecutorConfirmation,
  assertVpcExecutorTopology,
  createPrivateEvidenceDirectory,
  createRestrictiveTempDirectory,
  extractRlsRouteFlags,
  findDatabaseUrlSecret,
  inventoryDatabaseConsumers,
  mergeTaskDefinitions,
  mutateTaskDefinitionDatabaseSecret,
  redactSensitiveText,
  sanitizedTaskDefinitionDiff,
  securelyRemoveDirectory,
  taskDefinitionRegistrationPayload,
  writeEvidenceChecksums,
  writeSanitizedEvidence,
} from "../lib/staging-database-role-credentials-core.mjs";

const ROOT = path.resolve(import.meta.dirname, "../..");
const APPLY = process.argv.includes("--apply");
const PROBE = process.argv.includes("--probe");
const COMMAND = process.argv.slice(2).find((item) => !item.startsWith("--")) || "discover";
const ADMIN_TASK_ARN = process.env.MSCQR_STAGING_DB_ADMIN_TASK_DEFINITION_ARN || "";
const activeTemporaryDirectories = new Set();
let interrupted = false;

export function usage() {
  return `Usage: staging-database-role-credentials.mjs <discover|provision|verify|cutover|rollback> [--probe|--apply]\n\n` +
    `Default is read-only discovery. Provision/verify use only a reviewed disposable ECS admin task in the staging VPC.\n` +
    `The Mac controller never runs psql or receives a database secret value.\n`;
}

function run(command, args, { allowFailure = false } = {}) {
  const result = spawnSync(command, args, { encoding: "utf8", maxBuffer: 32 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"] });
  if (result.error) throw new Error(`${command} failed to start.`);
  if (!allowFailure && result.status !== 0) throw new Error(`${command} failed; command output was suppressed.`);
  return result;
}
function awsJson(args, options = {}) {
  const result = run("aws", [...args, "--region", C.region, "--output", "json"], options);
  try { return JSON.parse(result.stdout || "{}"); } catch { throw new Error("AWS CLI returned invalid JSON."); }
}
function tempDirectory(prefix = "mscqr-staging-db-controller-") {
  const directory = createRestrictiveTempDirectory(prefix); activeTemporaryDirectories.add(directory); return directory;
}
function cleanup(directory) { if (directory) { securelyRemoveDirectory(directory); activeTemporaryDirectories.delete(directory); } }
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) process.once(signal, () => {
  interrupted = true;
  for (const directory of activeTemporaryDirectories) try { securelyRemoveDirectory(directory); } catch { /* evidence remains fail-closed */ }
  process.stderr.write(`${JSON.stringify({ status: "blocked", phase: "controller-interrupted", failureClassification: signal, recovery: "Inspect the disposable task result and run the documented recovery command before retrying." })}\n`);
  process.exit(128 + (signal === "SIGINT" ? 2 : signal === "SIGHUP" ? 1 : 15));
});

function discoverBase() {
  const identity = awsJson(["sts", "get-caller-identity"]);
  assertExpectedAwsIdentity(identity, { ...process.env, AWS_REGION: C.region });
  const response = awsJson(["ecs", "describe-services", "--cluster", C.cluster, "--services", C.service]);
  const service = response.services?.[0];
  if (!service || response.failures?.length) throw new Error("Reviewed staging ECS service was not found.");
  assertStagingOnlyName("ECS cluster", C.cluster); assertStagingOnlyName("ECS service", service.serviceName);
  const taskArn = assertRollbackTarget(service.taskDefinition);
  const described = awsJson(["ecs", "describe-task-definition", "--task-definition", taskArn, "--include", "TAGS"]);
  assertRlsRouteFlagsFalse(extractRlsRouteFlags(described.taskDefinition));
  return { identity, service, taskArn, taskDefinition: described.taskDefinition, tags: described.tags || [], adminSecretId: findDatabaseUrlSecret(described.taskDefinition) };
}

function listAll(args, resultKey) {
  const values = []; let token = "";
  do { const page = awsJson(token ? [...args, "--starting-token", token] : args); values.push(...(page[resultKey] || [])); token = page.nextToken || page.NextToken || ""; } while (token);
  return values;
}

function databaseConsumerInventory(base, { expectedClassification = null, preservedAdminSecretId = base.adminSecretId, appSecretArn = "" } = {}) {
  const arns = listAll(["ecs", "list-task-definitions", "--status", "ACTIVE", "--sort", "DESC", "--family-prefix", "mscqr-staging"], "taskDefinitionArns");
  const clusterServices = listAll(["ecs", "list-services", "--cluster", C.cluster], "serviceArns");
  const services = [];
  for (let i = 0; i < clusterServices.length; i += 10) services.push(...(awsJson(["ecs", "describe-services", "--cluster", C.cluster, "--services", ...clusterServices.slice(i, i + 10)]).services || []));
  if (!services.some((value) => value.serviceName === base.service.serviceName)) services.push(base.service);
  const scheduledTargets = [];
  for (const rule of listAll(["events", "list-rules", "--name-prefix", "mscqr-staging"], "Rules")) {
    for (const target of awsJson(["events", "list-targets-by-rule", "--rule", rule.Name]).Targets || []) {
      if (target.EcsParameters?.TaskDefinitionArn) scheduledTargets.push({ scheduleName: rule.Name, taskDefinition: target.EcsParameters.TaskDefinitionArn });
    }
  }
  const references = [...arns, ...services.map((value) => value.taskDefinition), ...scheduledTargets.map((value) => value.taskDefinition)].filter(Boolean);
  const describedByReference = new Map([...new Set(references)].map((reference) => [reference, awsJson(["ecs", "describe-task-definition", "--task-definition", reference]).taskDefinition]));
  const describedDefinitions = [...describedByReference.values()];
  const definitions = mergeTaskDefinitions(base.taskDefinition, describedDefinitions);
  const canonicalReference = (reference) => describedByReference.get(reference)?.taskDefinitionArn || reference;
  const activeServices = services.map((value) => ({ serviceName: value.serviceName, taskDefinition: canonicalReference(value.taskDefinition) }));
  const activeSchedules = scheduledTargets.map((value) => ({ ...value, taskDefinition: canonicalReference(value.taskDefinition) }));
  const inventoriedSecretIds = definitions.flatMap((definition) => (definition.containerDefinitions || []).flatMap((container) => (container.secrets || []).map((secret) => secret.valueFrom).filter(Boolean)));
  const uniqueMatchingSecret = (fragment) => {
    const matches = [...new Set(inventoriedSecretIds.filter((secretId) => secretId.includes(`:secret:mscqr/staging/database-url/${fragment}-`)))];
    if (matches.length > 1) throw new Error(`Multiple ${fragment} database-role secret identifiers require review.`);
    return matches[0] || "";
  };
  const discoveredAppSecretArn = appSecretArn || uniqueMatchingSecret("app");
  const rlsReadSecretArn = uniqueMatchingSecret("rls-read");
  const consumers = inventoryDatabaseConsumers(definitions, activeServices, activeSchedules, [preservedAdminSecretId], discoveredAppSecretArn ? [discoveredAppSecretArn] : [], rlsReadSecretArn ? [rlsReadSecretArn] : []);
  const reviewed = consumers.map((consumer) => {
    let requiredRole = "no-runtime-credential";
    if (consumer.service === C.service && consumer.container === C.backendContainer && consumer.variable === "DATABASE_URL") requiredRole = C.roles.app;
    else if (consumer.schedule && /migrat/i.test(`${consumer.family}/${consumer.container}/${consumer.schedule}`) && consumer.variable === "DATABASE_URL") requiredRole = C.roles.migrator;
    return { taskDefinitionArn: consumer.taskDefinitionArn, container: consumer.container, variable: consumer.variable, requiredRole };
  });
  assertReviewedDatabaseConsumers(consumers.filter((item) => item.service || item.schedule), reviewed);
  assertActiveReviewedBackendDatabaseConsumer(consumers, { expectedClassification });
  return { consumers, reviewed };
}

function executorPlan(base) {
  assertVpcExecutorConfirmation();
  const arn = assertRollbackTarget(ADMIN_TASK_ARN);
  const described = awsJson(["ecs", "describe-task-definition", "--task-definition", arn, "--include", "TAGS"]);
  const definition = described.taskDefinition;
  const backend = base.taskDefinition.containerDefinitions.find((item) => item.name === C.backendContainer);
  const admin = definition.containerDefinitions?.find((item) => item.name === "db-admin");
  if (!admin || definition.containerDefinitions.length !== 1) throw new Error("Admin task must contain exactly one db-admin container.");
  if (admin.image !== backend.image) throw new Error("Admin task image must exactly match the reviewed staging backend image.");
  if (!(admin.command || []).join(" ").includes("staging-database-role-vpc-executor.mjs")) throw new Error("Admin task does not use the reviewed VPC executor entrypoint.");
  const dbSecrets = (admin.secrets || []).filter((item) => item.name === "DATABASE_URL");
  if (dbSecrets.length !== 1 || dbSecrets[0].valueFrom !== base.adminSecretId) throw new Error("Admin task must receive only the preserved staging admin DATABASE_URL secret reference.");
  const network = base.service.networkConfiguration;
  const topology = assertVpcExecutorTopology({ cluster: C.cluster, service: C.service, taskDefinition: arn, networkConfiguration: network, subnets: network.awsvpcConfiguration.subnets, securityGroups: network.awsvpcConfiguration.securityGroups });
  return { arn, definition, topology };
}

function runExecutor(base, mode) {
  const executor = executorPlan(base);
  const directory = tempDirectory();
  try {
    const requestFile = path.join(directory, "broker-request.json");
    const responseFile = path.join(directory, "broker-response.json");
    fs.writeFileSync(requestFile, JSON.stringify({ mode }), { mode: 0o600, flag: "wx" });
    const invoked = run("aws", ["lambda", "invoke", "--function-name", C.brokerFunction, "--cli-binary-format", "raw-in-base64-out", "--payload", `fileb://${requestFile}`, responseFile, "--region", C.region, "--output", "json"]);
    let metadata; let started;
    try { metadata = JSON.parse(invoked.stdout || "{}"); started = JSON.parse(fs.readFileSync(responseFile, "utf8")); } catch { throw new Error("Broker returned invalid JSON."); }
    if (metadata.FunctionError || metadata.StatusCode !== 200 || Object.keys(started).sort().join(",") !== "status,taskArn" || started.status !== "started") throw new Error("Broker refused or failed to start the reviewed executor.");
    const taskArn = started.taskArn;
    const expectedTaskPrefix = `arn:aws:ecs:${C.region}:${C.accountId}:task/${C.cluster}/`;
    if (typeof taskArn !== "string" || !taskArn.startsWith(expectedTaskPrefix)) throw new Error("Broker returned a task outside the reviewed staging cluster.");
    run("aws", ["ecs", "wait", "tasks-stopped", "--cluster", C.cluster, "--tasks", taskArn, "--region", C.region]);
    const stopped = awsJson(["ecs", "describe-tasks", "--cluster", C.cluster, "--tasks", taskArn]).tasks?.[0];
    const container = stopped?.containers?.find((item) => item.name === "db-admin");
    if (container?.exitCode !== 0) throw Object.assign(new Error("VPC executor blocked; inspect sanitized task logs and follow recovery instructions."), { code: "VPC_EXECUTOR_FAILED" });
    return { mechanism: "lambda-brokered-disposable-ecs-admin-task", brokerFunction: C.brokerFunction, taskArn, exitCode: container.exitCode, topology: executor.topology };
  } finally { cleanup(directory); }
}

function evidenceDirectory() { fs.mkdirSync(path.join(ROOT, "scratch"), { recursive: true }); return createPrivateEvidenceDirectory(path.join(ROOT, "scratch")); }
export function executorModeForCommand(command) {
  if (command === "provision") return "provision";
  if (command === "verify") return "verify";
  throw new Error("Unsupported executor command.");
}
function provisionOrVerify(command) {
  const base = discoverBase();
  if (APPLY || PROBE) assertDatabaseRoleOperatorIdentity(base.identity, { ...process.env, AWS_REGION: C.region });
  const inventory = databaseConsumerInventory(base); const plan = executorPlan(base);
  if (!APPLY && !PROBE) return { status: `${command}_dry_run_requires_reachability_probe`, mutatesPostgres: false, mutatesSecretsManager: false, executor: plan.topology, consumerInventory: inventory, probeCommand: `MSCQR_STAGING_VPC_EXECUTOR=disposable-ecs-admin-task MSCQR_STAGING_DB_ADMIN_TASK_DEFINITION_ARN=${plan.arn} scripts/aws/${command === "provision" ? "provision-staging-database-role-credentials.sh" : "verify-staging-database-role-permissions.sh"} --probe` };
  if (PROBE) return { status: `${command}_reachability_probe_passed`, mutatesPostgres: false, mutatesSecretsManager: false, result: runExecutor(base, "probe"), consumerInventory: inventory };
  assertApplyGate({ apply: true, envName: command === "provision" ? "MSCQR_STAGING_DATABASE_CREDENTIALS_CONFIRM" : "MSCQR_STAGING_DATABASE_VERIFY_CONFIRM", confirmation: command === "provision" ? "MSCQR_PROVISION_STAGING_DATABASE_ROLE_CREDENTIALS" : "MSCQR_VERIFY_STAGING_DATABASE_ROLE_CREDENTIALS" });
  const result = runExecutor(base, executorModeForCommand(command));
  const evidence = evidenceDirectory(); writeSanitizedEvidence(evidence, `${command}-controller-summary.json`, { phase: command, result, consumerInventory: inventory }); writeEvidenceChecksums(evidence);
  return { status: `${command}_vpc_executor_complete`, result, evidenceDirectory: path.relative(ROOT, evidence) };
}

function healthCheck() { const url = assertSafeStagingHttpUrl(process.env.MSCQR_STAGING_HEALTH_URL || "", "Staging health URL"); const result = run("curl", ["--fail", "--silent", "--show-error", "--max-time", "20", url], { allowFailure: true }); if (result.status) throw new Error("Staging health endpoint failed."); return true; }
function smokeChecks() { const urls=String(process.env.MSCQR_STAGING_REPRESENTATIVE_SMOKE_URLS||"").split(",").map(v=>v.trim()).filter(Boolean); if(!urls.length) throw new Error("Representative credential-free staging smoke URLs are required."); return urls.map((value,index)=>{ const url=assertSafeStagingHttpUrl(value,`Representative smoke URL ${index+1}`); const result=run("curl",["--fail","--silent","--show-error","--max-time","20",url],{allowFailure:true}); if(result.status) throw new Error(`Representative smoke ${index+1} failed.`); return {url,passed:true}; }); }
function runtimeIdentity() { const tasks=awsJson(["ecs","list-tasks","--cluster",C.cluster,"--service-name",C.service,"--desired-status","RUNNING"]).taskArns||[]; if(tasks.length!==1) throw new Error("Expected one stable backend task for identity proof."); const command=`node -e "const{PrismaClient}=require('@prisma/client');const p=new PrismaClient();p.\\$queryRawUnsafe('SELECT current_database() AS database_name,current_user AS database_user').then(r=>console.log(JSON.stringify(r[0]))).finally(()=>p.\\$disconnect())"`; const result=run("aws",["ecs","execute-command","--cluster",C.cluster,"--task",tasks[0],"--container",C.backendContainer,"--interactive","--command",command,"--region",C.region],{allowFailure:true}); if(result.status) throw new Error("Sanitized runtime database identity proof failed."); const match=result.stdout.match(/\{"database_name":"([^"]+)","database_user":"([^"]+)"\}/); if(!match) throw new Error("Runtime identity output was missing."); const identity={databaseName:match[1],databaseUser:match[2]}; assertRuntimeIdentity(identity); return identity; }
function rollbackService(previousArn) { awsJson(["ecs", "update-service", "--cluster", C.cluster, "--service", C.service, "--task-definition", previousArn]); run("aws", ["ecs", "wait", "services-stable", "--cluster", C.cluster, "--services", C.service, "--region", C.region]); healthCheck(); }
function cutover() {
  const base = discoverBase(); const inventory = databaseConsumerInventory(base, { expectedClassification: "admin" }); runExecutor(base, "verify"); healthCheck();
  const previousTaskDefinitionArn = base.taskArn;
  const preservedAdminSecretId = base.adminSecretId;
  const app = awsJson(["secretsmanager", "describe-secret", "--secret-id", C.secretNames.app]);
  const current = Object.entries(app.VersionIdsToStages || {}).find(([, stages]) => stages.includes("AWSCURRENT"))?.[0];
  if (!current) throw new Error("App secret has no AWSCURRENT version.");
  const payload = mutateTaskDefinitionDatabaseSecret({ taskDefinition: base.taskDefinition, tags: base.tags, appSecretArn: app.ARN });
  const before = taskDefinitionRegistrationPayload(base.taskDefinition, base.tags); assertTaskDefinitionOnlyDatabaseSecretChanged({ before, after: payload, appSecretArn: app.ARN });
  const diff = sanitizedTaskDefinitionDiff({ before, after: payload });
  if (!APPLY) return { status: "cutover_dry_run_ready", executor: executorPlan(base).topology, consumerInventory: inventory, appSecretCurrentVersionId: current, proposedDiff: diff, mutatesAws: false };
  assertApplyGate({ apply: true, envName: "MSCQR_STAGING_ECS_DATABASE_ROLE_CUTOVER_CONFIRM", confirmation: "MSCQR_CUTOVER_STAGING_ECS_TO_APP_DATABASE_ROLE" });
  const evidence = evidenceDirectory(); let newArn = ""; let serviceUpdated = false;
  try {
    const directory = tempDirectory("mscqr-staging-db-cutover-");
    try { const file = path.join(directory, "task-definition.json"); fs.writeFileSync(file, JSON.stringify(payload), { mode: 0o600, flag: "wx" }); newArn = assertRollbackTarget(awsJson(["ecs", "register-task-definition", "--cli-input-json", `file://${file}`]).taskDefinition?.taskDefinitionArn); } finally { cleanup(directory); }
    if (process.env.MSCQR_TEST_FAILURE_PHASE === "ecs-registration") throw new Error("Injected ECS registration failure.");
    awsJson(["ecs", "update-service", "--cluster", C.cluster, "--service", C.service, "--task-definition", newArn]); serviceUpdated = true;
    if (process.env.MSCQR_TEST_FAILURE_PHASE === "ecs-service-update") throw new Error("Injected ECS service update failure.");
    run("aws", ["ecs", "wait", "services-stable", "--cluster", C.cluster, "--services", C.service, "--region", C.region]);
    const service = awsJson(["ecs", "describe-services", "--cluster", C.cluster, "--services", C.service]).services?.[0]; assertServiceStable(service, newArn); healthCheck(); const identity=runtimeIdentity(); const smokes=smokeChecks();
    const postCutoverBase = discoverBase();
    const postCutoverInventory = databaseConsumerInventory(postCutoverBase, { expectedClassification: "app", preservedAdminSecretId, appSecretArn: app.ARN });
    writeSanitizedEvidence(evidence, "cutover-result.json", { status: "healthy", previousTaskDefinitionArn, newTaskDefinitionArn: newArn, appSecretCurrentVersionId: current, runtimeIdentity:identity, smokeChecks:smokes, consumerInventory: postCutoverInventory }); writeEvidenceChecksums(evidence);
    return { status: "cutover_complete", previousTaskDefinitionArn, newTaskDefinitionArn: newArn, evidenceDirectory: path.relative(ROOT, evidence) };
  } catch (error) {
    let rollbackResult = "not_required"; if (serviceUpdated) try { rollbackService(previousTaskDefinitionArn); rollbackResult = "restored"; } catch { rollbackResult = "operator_recovery_required"; }
    writeSanitizedEvidence(evidence, "cutover-failure.json", { phase: newArn ? "ecs-service-update" : "ecs-registration", failureClassification: error.code || "ECS_CUTOVER_FAILURE", previousTaskDefinitionArn, newTaskDefinitionArn: newArn || null, rollbackResult }); writeEvidenceChecksums(evidence); throw error;
  }
}

function rollback() { discoverBase(); const previous = assertRollbackTarget(process.env.PREVIOUS_TASK_DEFINITION_ARN || ""); if (!APPLY) return { status: "rollback_dry_run_ready", targetTaskDefinitionArn: previous, mutatesAws: false }; assertApplyGate({ apply: true, envName: "MSCQR_STAGING_ECS_DATABASE_ROLE_ROLLBACK_CONFIRM", confirmation: "MSCQR_ROLLBACK_STAGING_ECS_DATABASE_ROLE" }); rollbackService(previous); return { status: "rollback_complete", targetTaskDefinitionArn: previous }; }
export function execute() {
  if (process.argv.includes("--help")) return { status: "help", usage: usage() };
  if (interrupted) throw new Error("Controller was interrupted.");
  if (COMMAND === "discover") { const base = discoverBase(); return { status: "discovery_complete", mutatesAws: false, accountId: base.identity.Account, region: C.region, cluster: C.cluster, service: C.service, taskDefinitionArn: base.taskArn, executor: executorPlan(base).topology, consumerInventory: databaseConsumerInventory(base), routeFlags: extractRlsRouteFlags(base.taskDefinition) }; }
  if (COMMAND === "provision" || COMMAND === "verify") return provisionOrVerify(COMMAND);
  if (COMMAND === "cutover") return cutover();
  if (COMMAND === "rollback") return rollback();
  throw new Error(`Unknown command: ${COMMAND}`);
}
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(import.meta.filename)) try { console.log(JSON.stringify(execute(), null, 2)); } catch (error) { console.error(JSON.stringify({ status: "blocked", reason: redactSensitiveText(error.message), code: error.code || "STAGING_DATABASE_ROLE_WORKFLOW_FAILED" }, null, 2)); process.exitCode = 2; }
