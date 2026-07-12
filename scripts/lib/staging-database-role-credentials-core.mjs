import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";

export const STAGING_DATABASE_ROLE_CONTEXT = Object.freeze({
  accountId: "368992683803",
  region: "eu-west-2",
  databaseName: "mscqr_staging",
  databaseIdentifier: "mscqr-staging-db",
  cluster: "mscqr-staging-euw2-main",
  service: "mscqr-staging-backend-service-euw2",
  operatorRole: "mscqr-staging-database-role-operator",
  backendContainer: "backend",
  runtimeAdminRole: "mscqr_staging_admin",
  ownerRole: "mscqr_staging_owner",
  roles: Object.freeze({
    app: "mscqr_staging_app",
    migrator: "mscqr_staging_migrator",
    rlsRead: "mscqr_staging_rls_read",
  }),
  secretNames: Object.freeze({
    app: "mscqr/staging/database-url/app",
    migrator: "mscqr/staging/database-url/migrator",
    rlsRead: "mscqr/staging/database-url/rls-read",
  }),
  routeFlags: Object.freeze([
    "MSCQR_STAGING_RLS_BATCHES_READ_ENABLED",
    "MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED",
    "MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED",
  ]),
  expectedPublicApplicationRelations: 78,
});

export const REVIEWED_RLS_READ_TABLES = Object.freeze([
  "Organization", "Licensee", "User", "ManufacturerLicenseeLink", "Batch", "InventoryStatusRollup",
  "QRCode", "PrintJob", "PrintSession", "PrintItem", "PrinterRegistration", "Printer",
  "PrinterAttestation", "PrinterAgentSession", "PrinterProfile", "PrinterProfileSnapshot",
]);

const forbiddenMarkers = ["prod", "production", "live", "primary"];
const privilegedRoleAttributes = ["rolsuper", "rolcreatedb", "rolcreaterole", "rolreplication", "rolbypassrls"];
const roleNamePattern = /^[a-z][a-z0-9_]{0,62}$/;
const safeHostPattern = /^[a-z0-9.-]+$/i;
const safeDatabasePattern = /^[a-zA-Z0-9_-]{1,63}$/;
const safeArnPattern = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-(?:staging|stg)[A-Za-z0-9_\-/]*:\d+$/;

export class StagingDatabaseRoleSafetyError extends Error {
  constructor(message, code = "STAGING_DATABASE_ROLE_SAFETY") {
    super(message);
    this.name = "StagingDatabaseRoleSafetyError";
    this.code = code;
  }
}

const toText = (value) => String(value ?? "").trim();
const lowered = (value) => toText(value).toLowerCase();
const clone = (value) => JSON.parse(JSON.stringify(value));

export function containsForbiddenEnvironmentMarker(value) {
  const text = lowered(value);
  return forbiddenMarkers.some((marker) => text.includes(marker));
}

export function assertStagingOnlyName(label, value, { requireStagingMarker = true } = {}) {
  const text = toText(value);
  if (!text) throw new StagingDatabaseRoleSafetyError(`${label} is required.`);
  if (containsForbiddenEnvironmentMarker(text)) {
    throw new StagingDatabaseRoleSafetyError(`${label} is production-like and is refused.`);
  }
  if (requireStagingMarker && !/(?:staging|stg)/i.test(text)) {
    throw new StagingDatabaseRoleSafetyError(`${label} must clearly identify staging.`);
  }
  return text;
}

export function assertSafeDatabaseName(databaseName) {
  const text = toText(databaseName);
  if (!safeDatabasePattern.test(text)) {
    throw new StagingDatabaseRoleSafetyError("Database name has unsafe characters.");
  }
  if (containsForbiddenEnvironmentMarker(text)) {
    throw new StagingDatabaseRoleSafetyError("Database name is production-like and is refused.");
  }
  if (text !== STAGING_DATABASE_ROLE_CONTEXT.databaseName) {
    throw new StagingDatabaseRoleSafetyError(`Database name must be ${STAGING_DATABASE_ROLE_CONTEXT.databaseName}.`);
  }
  return text;
}

export function assertSafeRoleName(roleName) {
  const text = toText(roleName);
  if (!roleNamePattern.test(text)) throw new StagingDatabaseRoleSafetyError(`Unsafe PostgreSQL role name: ${text || "<empty>"}.`);
  return text;
}

export function assertSafeStagingHttpUrl(value, label = "Health URL") {
  let parsed;
  try {
    parsed = new URL(toText(value));
  } catch {
    throw new StagingDatabaseRoleSafetyError(`${label} must be a valid HTTP(S) URL.`);
  }
  if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password) {
    throw new StagingDatabaseRoleSafetyError(`${label} must be a credential-free HTTP(S) URL.`);
  }
  assertStagingOnlyName(`${label} hostname`, parsed.hostname);
  return parsed.toString();
}

export function assertExpectedAwsIdentity(identity, env = process.env) {
  const account = toText(identity?.Account);
  const arn = toText(identity?.Arn);
  const region = toText(env.AWS_REGION || env.AWS_DEFAULT_REGION || STAGING_DATABASE_ROLE_CONTEXT.region);
  if (region !== STAGING_DATABASE_ROLE_CONTEXT.region) {
    throw new StagingDatabaseRoleSafetyError(`AWS region must be ${STAGING_DATABASE_ROLE_CONTEXT.region}.`);
  }
  if (account !== STAGING_DATABASE_ROLE_CONTEXT.accountId) {
    throw new StagingDatabaseRoleSafetyError("AWS account is not the reviewed staging account.");
  }
  if (/\broot\b/i.test(arn) || /:user\//i.test(arn) || containsForbiddenEnvironmentMarker(arn)) {
    throw new StagingDatabaseRoleSafetyError("AWS identity is not an approved non-production assumed staging role.");
  }
  if (!/:assumed-role\/[A-Za-z0-9+=,.@_\-/]+/i.test(arn) || !/(?:staging|stg)/i.test(arn)) {
    throw new StagingDatabaseRoleSafetyError("AWS identity must be an assumed staging role.");
  }
  return { account, arn, region };
}

export function assertDatabaseRoleOperatorIdentity(identity, env = process.env) {
  const expected = assertExpectedAwsIdentity(identity, env);
  const assumedRolePrefix = `arn:aws:sts::${STAGING_DATABASE_ROLE_CONTEXT.accountId}:assumed-role/${STAGING_DATABASE_ROLE_CONTEXT.operatorRole}/`;
  if (!expected.arn.startsWith(assumedRolePrefix) || expected.arn.length === assumedRolePrefix.length) {
    throw new StagingDatabaseRoleSafetyError(`Probe, provision, and verify execution require assumed role ${STAGING_DATABASE_ROLE_CONTEXT.operatorRole}.`, "DATABASE_ROLE_OPERATOR_IDENTITY_REQUIRED");
  }
  return expected;
}

export function parsePostgresUrl(raw, label = "PostgreSQL URL") {
  let parsed;
  try {
    parsed = new URL(toText(raw));
  } catch {
    throw new StagingDatabaseRoleSafetyError(`${label} must be a valid PostgreSQL URL; its value was not printed.`);
  }
  if (!["postgres:", "postgresql:"].includes(parsed.protocol)) {
    throw new StagingDatabaseRoleSafetyError(`${label} must use postgres or postgresql.`);
  }
  const username = decodeURIComponent(parsed.username || "");
  const password = decodeURIComponent(parsed.password || "");
  const databaseName = decodeURIComponent(parsed.pathname.replace(/^\//, ""));
  if (!username || !password || !databaseName || !parsed.hostname) {
    throw new StagingDatabaseRoleSafetyError(`${label} must contain host, database, username, and password; its value was not printed.`);
  }
  if (!safeHostPattern.test(parsed.hostname)) throw new StagingDatabaseRoleSafetyError(`${label} hostname has unsafe characters.`);
  if (!safeDatabasePattern.test(databaseName)) throw new StagingDatabaseRoleSafetyError(`${label} database name has unsafe characters.`);
  if (!roleNamePattern.test(username)) throw new StagingDatabaseRoleSafetyError(`${label} username has unsafe characters.`);
  const port = Number(parsed.port || "5432");
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new StagingDatabaseRoleSafetyError(`${label} port is invalid.`);
  return {
    protocol: parsed.protocol,
    host: parsed.hostname.toLowerCase(),
    port,
    databaseName,
    username,
    password,
    sslmode: parsed.searchParams.get("sslmode") || "require",
  };
}

export function sanitizeConnectionMetadata(rawUrl) {
  const connection = parsePostgresUrl(rawUrl);
  return {
    protocol: connection.protocol.replace(":", ""),
    host: connection.host,
    port: connection.port,
    databaseName: connection.databaseName,
    username: connection.username,
    sslmode: connection.sslmode,
    passwordPresent: Boolean(connection.password),
  };
}

export function buildStagingDatabaseUrl({ username, password, host, port, databaseName, sslmode = "require" }) {
  const safeUsername = assertSafeRoleName(username);
  const safeHost = toText(host).toLowerCase();
  if (!safeHostPattern.test(safeHost)) throw new StagingDatabaseRoleSafetyError("Database host has unsafe characters.");
  assertStagingOnlyName("Database host", safeHost);
  const safeDatabaseName = assertSafeDatabaseName(databaseName);
  const safePort = Number(port);
  if (!Number.isInteger(safePort) || safePort < 1 || safePort > 65535) {
    throw new StagingDatabaseRoleSafetyError("Database port is invalid.");
  }
  if (!password || /[\r\n]/.test(password)) throw new StagingDatabaseRoleSafetyError("Generated database password is invalid.");
  const url = new URL(`postgresql://${safeHost}:${safePort}/${safeDatabaseName}`);
  url.username = safeUsername;
  url.password = password;
  url.searchParams.set("sslmode", sslmode);
  return url.toString();
}

export function safeUrlPreview(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    const authentication = parsed.username || parsed.password ? "<redacted>@" : "";
    return `${parsed.protocol}//${authentication}${parsed.host}${parsed.pathname}${parsed.search}`;
  } catch {
    return "<unparseable-url-redacted>";
  }
}

export function redactSensitiveText(value, sensitiveValues = []) {
  let output = String(value ?? "");
  for (const sensitive of sensitiveValues.filter(Boolean)) {
    output = output.split(String(sensitive)).join("<redacted>");
  }
  output = output
    .replace(/\b(?:postgres|postgresql):\/\/[^\s'"`@/]+(?::[^\s'"`@]*)?@[^\s'"`]+/gi, "postgresql://<redacted>@<redacted>")
    .replace(/\b(password|secret|token)\s*=\s*[^\s,;]+/gi, "$1=<redacted>")
    .replace(/\b(AKIA|ASIA)[A-Z0-9]{16}\b/g, "<redacted-aws-access-key>");
  return output;
}

export function generateRolePassword(randomBytes = crypto.randomBytes) {
  const entropy = randomBytes(48);
  if (!Buffer.isBuffer(entropy) || entropy.length < 32) {
    throw new StagingDatabaseRoleSafetyError("Password generator did not provide at least 32 random bytes.");
  }
  const password = entropy.toString("base64url");
  if (password.length < 43 || /[\r\n]/.test(password)) {
    throw new StagingDatabaseRoleSafetyError("Password generator produced an unsafe value.");
  }
  return password;
}

export function classifyPostgresPermissionDenial(result) {
  const status = Number(result?.status);
  const output = `${result?.stdout || ""}\n${result?.stderr || ""}`;
  if (status === 0) return { expected: false, kind: "operation_succeeded" };
  if (/permission denied|must be superuser|must be owner|not permitted|insufficient privilege/i.test(output)) {
    return { expected: true, kind: "permission_denied" };
  }
  if (/could not connect|connection (?:refused|timed out|failed)|no route to host|server closed|ssl|password authentication failed/i.test(output)) {
    return { expected: false, kind: "infrastructure_failure" };
  }
  return { expected: false, kind: "unexpected_failure" };
}

export function assertExpectedPermissionDenial(result, label) {
  const classification = classifyPostgresPermissionDenial(result);
  if (!classification.expected) {
    throw new StagingDatabaseRoleSafetyError(
      `${label} did not produce the expected PostgreSQL permission denial (${classification.kind}).`,
      "POSTGRES_PERMISSION_TEST_FAILED",
    );
  }
  return { label, result: classification.kind };
}

export function extractSecretString(secretResponse, label) {
  const raw = toText(secretResponse?.SecretString ?? secretResponse);
  if (!raw) throw new StagingDatabaseRoleSafetyError(`${label} did not return a SecretString.`);
  try {
    const parsed = JSON.parse(raw);
    if (typeof parsed === "string") return parsed;
    for (const key of ["DATABASE_URL", "databaseUrl", "database_url", "url", "value"]) {
      if (typeof parsed?.[key] === "string" && parsed[key].trim()) return parsed[key].trim();
    }
  } catch {
    // A plain SecretString PostgreSQL URL is the expected legacy shape.
  }
  return raw;
}

export function assertApplyGate({ apply, env = process.env, envName, confirmation }) {
  if (!apply) throw new StagingDatabaseRoleSafetyError("This operation is dry-run by default. Pass --apply after review.");
  if (env[envName] !== confirmation) {
    throw new StagingDatabaseRoleSafetyError(`Set ${envName}=${confirmation} to authorize this staging-only mutation.`);
  }
}

export function assertVpcExecutorConfirmation(env = process.env) {
  if (env.MSCQR_STAGING_VPC_EXECUTOR !== "disposable-ecs-admin-task") {
    throw new StagingDatabaseRoleSafetyError(
      "Refusing PostgreSQL work without MSCQR_STAGING_VPC_EXECUTOR=disposable-ecs-admin-task; local PostgreSQL execution is never supported.",
      "VPC_EXECUTOR_UNRESOLVED",
    );
  }
}

export function assertVpcExecutorTopology({ cluster, service, taskDefinition, networkConfiguration, subnets = [], securityGroups = [] }) {
  assertStagingOnlyName("VPC executor cluster", cluster);
  assertStagingOnlyName("VPC executor service", service);
  assertRollbackTarget(taskDefinition);
  if (!Array.isArray(networkConfiguration?.awsvpcConfiguration?.subnets) ||
      !Array.isArray(networkConfiguration?.awsvpcConfiguration?.securityGroups)) {
    throw new StagingDatabaseRoleSafetyError("VPC executor must use the reviewed awsvpc network configuration.", "VPC_EXECUTOR_UNRESOLVED");
  }
  const actualSubnets = [...networkConfiguration.awsvpcConfiguration.subnets].sort();
  const actualGroups = [...networkConfiguration.awsvpcConfiguration.securityGroups].sort();
  if (actualSubnets.length < 2 || JSON.stringify(actualSubnets) !== JSON.stringify([...subnets].sort())) {
    throw new StagingDatabaseRoleSafetyError("VPC executor subnets do not exactly match the reviewed staging backend private subnets.", "VPC_EXECUTOR_TOPOLOGY");
  }
  if (actualGroups.length < 1 || JSON.stringify(actualGroups) !== JSON.stringify([...securityGroups].sort())) {
    throw new StagingDatabaseRoleSafetyError("VPC executor security groups do not exactly match the reviewed staging backend security groups.", "VPC_EXECUTOR_TOPOLOGY");
  }
  if (networkConfiguration.awsvpcConfiguration.assignPublicIp !== "DISABLED") {
    throw new StagingDatabaseRoleSafetyError("VPC executor public IP must be disabled.", "VPC_EXECUTOR_TOPOLOGY");
  }
  return { mechanism: "disposable-ecs-admin-task", cluster, service, taskDefinition, subnets: actualSubnets, securityGroups: actualGroups, assignPublicIp: "DISABLED" };
}

export function taskDefinitionReferenceParts(reference) {
  const value = toText(reference);
  const resource = value.includes("task-definition/") ? value.split("task-definition/").at(-1) : value;
  const match = resource.match(/^([^/:]+)(?::(\d+))?$/);
  if (!match) return { reference: value, family: "", revision: null };
  return { reference: value, family: match[1], revision: match[2] ? Number(match[2]) : null };
}

export function taskDefinitionMatchesReference(definition, reference) {
  const expected = taskDefinitionReferenceParts(reference);
  const actualRevision = definition?.revision ?? taskDefinitionReferenceParts(definition?.taskDefinitionArn).revision;
  return Boolean(expected.family) && definition?.family === expected.family &&
    (expected.revision === null || Number(actualRevision) === expected.revision);
}

export function mergeTaskDefinitions(...groups) {
  const definitions = new Map();
  for (const definition of groups.flat()) {
    if (!definition?.taskDefinitionArn) continue;
    const key = taskDefinitionReferenceParts(definition.taskDefinitionArn);
    if (!key.family || key.revision === null) throw new StagingDatabaseRoleSafetyError("Task definition inventory contains an unresolved reference.", "TASK_DEFINITION_UNRESOLVED");
    definitions.set(`${key.family}:${key.revision}`, definition);
  }
  return [...definitions.values()];
}

export function inventoryDatabaseConsumers(taskDefinitions, services = [], scheduledTargets = [], adminSecretIds = [], appSecretIds = [], rlsReadSecretIds = []) {
  const adminIds = new Set((adminSecretIds || []).map(toText).filter(Boolean));
  const appIds = new Set((appSecretIds || []).map(toText).filter(Boolean));
  const rlsReadIds = new Set((rlsReadSecretIds || []).map(toText).filter(Boolean));
  const classifiedIds = [...adminIds, ...appIds, ...rlsReadIds];
  if (new Set(classifiedIds).size !== classifiedIds.length) {
    throw new StagingDatabaseRoleSafetyError("Admin, app, and RLS-read database secret identifiers must be distinct.", "DATABASE_SECRET_CLASSIFICATION_AMBIGUOUS");
  }
  const consumers = [];
  for (const definition of mergeTaskDefinitions(taskDefinitions || [])) {
    const arn = toText(definition.taskDefinitionArn);
    assertRollbackTarget(arn);
    const activeContexts = [
      ...services.filter((service) => taskDefinitionMatchesReference(definition, service.taskDefinition)).map((service) => ({ service: service.serviceName, schedule: null })),
      ...scheduledTargets.filter((target) => taskDefinitionMatchesReference(definition, target.taskDefinition)).map((target) => ({ service: null, schedule: target.scheduleName })),
    ];
    const contexts = activeContexts.length ? activeContexts : [{ service: null, schedule: null }];
    for (const container of definition.containerDefinitions || []) {
      for (const secret of container.secrets || []) {
        if (!["DATABASE_URL", "RLS_READ_DATABASE_URL"].includes(secret?.name) && !adminIds.has(secret?.valueFrom)) continue;
        for (const context of contexts) consumers.push({
          taskDefinitionArn: arn, family: definition.family, ...context, container: container.name,
          variable: secret.name, secretId: secret.valueFrom,
          classification: adminIds.has(secret.valueFrom) ? "admin" : appIds.has(secret.valueFrom) ? "app" : rlsReadIds.has(secret.valueFrom) ? "rls-read" : "review-required",
        });
      }
    }
  }
  return consumers.sort((a, b) => `${a.family}/${a.service}/${a.schedule}/${a.container}/${a.variable}`.localeCompare(`${b.family}/${b.service}/${b.schedule}/${b.container}/${b.variable}`));
}

export function assertActiveReviewedBackendDatabaseConsumer(consumers, { expectedClassification = null } = {}) {
  const active = (consumers || []).filter((consumer) => consumer.service || consumer.schedule);
  const matches = active.filter((consumer) => consumer.service === STAGING_DATABASE_ROLE_CONTEXT.service && consumer.container === STAGING_DATABASE_ROLE_CONTEXT.backendContainer && consumer.variable === "DATABASE_URL");
  if (matches.length !== 1) throw new StagingDatabaseRoleSafetyError("Expected exactly one active reviewed staging backend service DATABASE_URL consumer.", "ACTIVE_BACKEND_DATABASE_CONSUMER_INVARIANT");
  if (active.some((consumer) => consumer !== matches[0] && ["DATABASE_URL", "RLS_READ_DATABASE_URL"].includes(consumer.variable))) {
    throw new StagingDatabaseRoleSafetyError("An additional active database consumer blocks the staging database-role workflow.", "ACTIVE_DATABASE_CONSUMER_INVARIANT");
  }
  const allowed = expectedClassification ? [expectedClassification] : ["admin", "app"];
  if (!allowed.includes(matches[0].classification)) throw new StagingDatabaseRoleSafetyError(`Active reviewed backend DATABASE_URL must be classified as ${allowed.join(" or ")}.`, "ACTIVE_BACKEND_DATABASE_CLASSIFICATION");
  return matches[0];
}

export function assertReviewedDatabaseConsumers(consumers, reviewed) {
  const approved = new Map((reviewed || []).map((entry) => [`${entry.taskDefinitionArn}|${entry.container}|${entry.variable}`, entry.requiredRole]));
  for (const consumer of consumers) {
    const key = `${consumer.taskDefinitionArn}|${consumer.container}|${consumer.variable}`;
    const requiredRole = approved.get(key);
    if (!requiredRole) throw new StagingDatabaseRoleSafetyError(`Unreviewed database consumer blocks cutover: ${consumer.family}/${consumer.container}/${consumer.variable}.`, "UNREVIEWED_DATABASE_CONSUMER");
    if ((consumer.service || consumer.schedule) && requiredRole === "no-runtime-credential") {
      throw new StagingDatabaseRoleSafetyError(`Active database consumer has no approved runtime credential: ${consumer.family}/${consumer.container}/${consumer.variable}.`, "UNREVIEWED_DATABASE_CONSUMER");
    }
    if (consumer.classification === "admin" && requiredRole !== "mscqr_staging_app" && requiredRole !== "mscqr_staging_migrator") {
      throw new StagingDatabaseRoleSafetyError(`Admin-secret consumer lacks an approved replacement role: ${consumer.family}/${consumer.container}.`, "ADMIN_SECRET_CONSUMER");
    }
    if (requiredRole === STAGING_DATABASE_ROLE_CONTEXT.roles.migrator && consumer.service) {
      throw new StagingDatabaseRoleSafetyError("Migrator credentials must never be injected into a long-running ECS service.", "MIGRATOR_RUNTIME_FORBIDDEN");
    }
  }
  return true;
}

export const CREDENTIAL_WORKFLOW_PHASES = Object.freeze([
  "inventory", "reachability", "capture-secret-metadata", "password-transaction", "pending-versions",
  "role-verification", "promote-versions", "consumer-cutover", "complete",
]);

export function recoveryInstruction({ mode, phase, rollbackResult }) {
  if (rollbackResult === "restored") return "Old working state restored; inspect sanitized evidence before retrying from discovery.";
  if (mode === "first-time") return `Blocked in ${phase}: run the reviewed VPC recovery task to confirm all target roles are PASSWORD NULL and remove AWSPENDING labels from failed versions; preserve every version.`;
  return `Blocked in ${phase}: run the reviewed VPC recovery task with captured prior AWSCURRENT version IDs to restore database passwords and version stages; preserve every version.`;
}

export function simulateCredentialWorkflowFailure(failurePhase, mode = "rotation", { compensationSucceeds = true } = {}) {
  const supported = new Set([
    "first-role-password-assignment", "password-transaction-commit", "first-secret-pending-version",
    "second-secret-pending-version", "role-verification", "first-version-promotion",
    "ecs-registration", "ecs-service-update", "ecs-post-cutover-inventory",
  ]);
  if (!supported.has(failurePhase)) throw new StagingDatabaseRoleSafetyError("Unsupported failure-injection phase.");
  if (!["first-time", "rotation"].includes(mode)) throw new StagingDatabaseRoleSafetyError("Provisioning mode must be first-time or rotation.");
  const transactionRolledBack = failurePhase === "first-role-password-assignment";
  const ecsOnly = failurePhase.startsWith("ecs-");
  const rollbackResult = transactionRolledBack || compensationSucceeds ? "restored" : "operator_recovery_required";
  return {
    failurePhase,
    mode,
    databaseState: transactionRolledBack ? "unchanged" : rollbackResult === "restored" ? (mode === "first-time" ? "password-null" : "previous-passwords") : "blocked-unknown",
    secretState: ecsOnly ? "unchanged" : rollbackResult === "restored" ? "prior-current-preserved-failed-pending-unstaged" : "prior-current-preserved-recovery-required",
    ecsState: ["ecs-service-update", "ecs-post-cutover-inventory"].includes(failurePhase) ? (rollbackResult === "restored" ? "previous-task-definition" : "recovery-required") : "unchanged",
    rollbackResult,
    recovery: recoveryInstruction({ mode, phase: failurePhase, rollbackResult }),
  };
}

export function extractBackendContainer(taskDefinition, containerName = STAGING_DATABASE_ROLE_CONTEXT.backendContainer) {
  const containers = taskDefinition?.containerDefinitions;
  if (!Array.isArray(containers)) throw new StagingDatabaseRoleSafetyError("Task definition has no container definitions.");
  const matches = containers.filter((container) => container?.name === containerName);
  if (matches.length !== 1) throw new StagingDatabaseRoleSafetyError(`Expected exactly one ${containerName} container definition.`);
  return matches[0];
}

export function extractRlsRouteFlags(taskDefinition, containerName = STAGING_DATABASE_ROLE_CONTEXT.backendContainer) {
  const container = extractBackendContainer(taskDefinition, containerName);
  const environment = new Map((container.environment || []).map((entry) => [entry?.name, entry?.value]));
  return Object.fromEntries(STAGING_DATABASE_ROLE_CONTEXT.routeFlags.map((name) => [name, environment.get(name)]));
}

export function assertRlsRouteFlagsFalse(flags) {
  for (const name of STAGING_DATABASE_ROLE_CONTEXT.routeFlags) {
    if (flags?.[name] !== "false") {
      throw new StagingDatabaseRoleSafetyError(`${name} must be explicitly false.`);
    }
  }
  return true;
}

export function findDatabaseUrlSecret(taskDefinition, containerName = STAGING_DATABASE_ROLE_CONTEXT.backendContainer) {
  const container = extractBackendContainer(taskDefinition, containerName);
  const matches = (container.secrets || []).filter((entry) => entry?.name === "DATABASE_URL" && toText(entry.valueFrom));
  if (matches.length !== 1) throw new StagingDatabaseRoleSafetyError("Expected exactly one backend DATABASE_URL secret reference.");
  const crossContainerMatches = (taskDefinition.containerDefinitions || [])
    .filter((entry) => entry?.name !== containerName)
    .flatMap((entry) => (entry.secrets || []).filter((secret) => secret?.name === "DATABASE_URL"));
  if (crossContainerMatches.length > 0) {
    throw new StagingDatabaseRoleSafetyError("Refusing task definition with an additional DATABASE_URL consumer outside backend.");
  }
  assertStagingOnlyName("Current DATABASE_URL secret reference", matches[0].valueFrom);
  return matches[0].valueFrom;
}

export function taskDefinitionRegistrationPayload(taskDefinition, tags = []) {
  const source = clone(taskDefinition || {});
  if (!source.family || !Array.isArray(source.containerDefinitions)) {
    throw new StagingDatabaseRoleSafetyError("ECS describe-task-definition response is incomplete.");
  }
  const payload = {};
  for (const key of [
    "family", "taskRoleArn", "executionRoleArn", "networkMode", "containerDefinitions", "volumes",
    "placementConstraints", "requiresCompatibilities", "cpu", "memory", "pidMode", "ipcMode",
    "proxyConfiguration", "inferenceAccelerators", "ephemeralStorage", "runtimePlatform",
  ]) {
    if (source[key] !== undefined && source[key] !== null) payload[key] = source[key];
  }
  if (Array.isArray(tags) && tags.length > 0) payload.tags = clone(tags);
  return payload;
}

export function assertTaskDefinitionOnlyDatabaseSecretChanged({ before, after, containerName = STAGING_DATABASE_ROLE_CONTEXT.backendContainer, appSecretArn }) {
  const expected = clone(before);
  const expectedContainer = extractBackendContainer(expected, containerName);
  const expectedSecret = (expectedContainer.secrets || []).filter((entry) => entry?.name === "DATABASE_URL");
  if (expectedSecret.length !== 1) throw new StagingDatabaseRoleSafetyError("Cannot establish expected DATABASE_URL mutation path.");
  expectedSecret[0].valueFrom = appSecretArn;
  if (JSON.stringify(expected) !== JSON.stringify(after)) {
    throw new StagingDatabaseRoleSafetyError("Task definition drift detected: only backend DATABASE_URL may change.", "TASK_DEFINITION_DRIFT");
  }
  assertRlsRouteFlagsFalse(extractRlsRouteFlags(after, containerName));
  return true;
}

export function mutateTaskDefinitionDatabaseSecret({ taskDefinition, tags = [], appSecretArn, containerName = STAGING_DATABASE_ROLE_CONTEXT.backendContainer }) {
  assertStagingOnlyName("Target app secret ARN", appSecretArn);
  const original = taskDefinitionRegistrationPayload(taskDefinition, tags);
  findDatabaseUrlSecret(original, containerName);
  assertRlsRouteFlagsFalse(extractRlsRouteFlags(original, containerName));
  const proposed = clone(original);
  const container = extractBackendContainer(proposed, containerName);
  const databaseSecret = (container.secrets || []).filter((entry) => entry?.name === "DATABASE_URL");
  if (databaseSecret.length !== 1) throw new StagingDatabaseRoleSafetyError("Expected exactly one backend DATABASE_URL secret to mutate.");
  databaseSecret[0].valueFrom = appSecretArn;
  assertTaskDefinitionOnlyDatabaseSecretChanged({ before: original, after: proposed, containerName, appSecretArn });
  return proposed;
}

export function sanitizedTaskDefinitionDiff({ before, after, containerName = STAGING_DATABASE_ROLE_CONTEXT.backendContainer }) {
  const beforeSecret = findDatabaseUrlSecret(before, containerName);
  const afterSecret = findDatabaseUrlSecret(after, containerName);
  return {
    allowedChanges: [{
      path: `containerDefinitions[name=${containerName}].secrets[name=DATABASE_URL].valueFrom`,
      before: beforeSecret,
      after: afterSecret,
    }],
    unrelatedChanges: [],
    rlsRouteFlags: extractRlsRouteFlags(after, containerName),
  };
}

export function assertRollbackTarget(previousTaskDefinitionArn) {
  const arn = toText(previousTaskDefinitionArn);
  if (!safeArnPattern.test(arn) || containsForbiddenEnvironmentMarker(arn)) {
    throw new StagingDatabaseRoleSafetyError("Previous task definition ARN is missing, unsafe, or not staging-only.");
  }
  return arn;
}

export function assertServiceStable(service, expectedTaskDefinitionArn = "") {
  if (!service || Number(service.runningCount) < Number(service.desiredCount) || Number(service.desiredCount) < 1) {
    throw new StagingDatabaseRoleSafetyError("ECS service is not stable with its desired running task count.", "ECS_NOT_STABLE");
  }
  if (expectedTaskDefinitionArn && service.taskDefinition !== expectedTaskDefinitionArn) {
    throw new StagingDatabaseRoleSafetyError("ECS service task definition does not match the expected revision.", "ECS_TASK_DEFINITION_MISMATCH");
  }
  return true;
}

export function assertRuntimeIdentity(identity) {
  if (identity?.databaseName !== STAGING_DATABASE_ROLE_CONTEXT.databaseName) {
    throw new StagingDatabaseRoleSafetyError("Runtime database identity did not report the staging database.", "RUNTIME_DATABASE_IDENTITY");
  }
  if (identity?.databaseUser !== STAGING_DATABASE_ROLE_CONTEXT.roles.app) {
    throw new StagingDatabaseRoleSafetyError("Runtime database identity is not the staging app role.", "RUNTIME_DATABASE_IDENTITY");
  }
  return true;
}

export function assertRoleInventory(inventory) {
  const byName = new Map((inventory?.roles || []).map((role) => [role.name, role]));
  const expected = [
    [STAGING_DATABASE_ROLE_CONTEXT.ownerRole, false],
    [STAGING_DATABASE_ROLE_CONTEXT.roles.app, true],
    [STAGING_DATABASE_ROLE_CONTEXT.roles.migrator, true],
    [STAGING_DATABASE_ROLE_CONTEXT.roles.rlsRead, true],
  ];
  for (const [name, canLogin] of expected) {
    const role = byName.get(name);
    if (!role) throw new StagingDatabaseRoleSafetyError(`Required role ${name} is missing.`);
    if (Boolean(role.rolcanlogin) !== canLogin) throw new StagingDatabaseRoleSafetyError(`${name} LOGIN attribute is unsafe.`);
    for (const attribute of privilegedRoleAttributes) {
      if (role[attribute]) throw new StagingDatabaseRoleSafetyError(`${name} has forbidden ${attribute}.`);
    }
  }
  const memberships = inventory?.memberships || [];
  const migratorMemberships = memberships.filter((item) => item.member === STAGING_DATABASE_ROLE_CONTEXT.roles.migrator);
  if (migratorMemberships.length !== 1 || migratorMemberships[0].granted !== STAGING_DATABASE_ROLE_CONTEXT.ownerRole ||
      migratorMemberships[0].adminOption || migratorMemberships[0].inheritOption || !migratorMemberships[0].setOption) {
    throw new StagingDatabaseRoleSafetyError("Migrator must have exactly one SET-only owner membership.");
  }
  for (const role of [STAGING_DATABASE_ROLE_CONTEXT.roles.app, STAGING_DATABASE_ROLE_CONTEXT.roles.rlsRead]) {
    if (memberships.some((item) => item.member === role)) {
      throw new StagingDatabaseRoleSafetyError(`${role} must have no role memberships.`);
    }
  }
  return true;
}

export function assertDatabaseInvariants(invariants) {
  assertSafeDatabaseName(invariants?.databaseName);
  assertRoleInventory(invariants);
  if (Number(invariants.ownerOwnedRelations) !== STAGING_DATABASE_ROLE_CONTEXT.expectedPublicApplicationRelations) {
    throw new StagingDatabaseRoleSafetyError("NOLOGIN owner must own all 78 reviewed public application relations.");
  }
  for (const [key, label] of [["rlsEnabledCount", "RLS enabled"], ["forceRlsCount", "FORCE RLS"], ["policyCount", "policy"]]) {
    if (Number(invariants?.[key]) !== 0) throw new StagingDatabaseRoleSafetyError(`${label} count must remain zero.`);
  }
  return true;
}

export function createPrivateEvidenceDirectory(root, timestamp = new Date()) {
  const stamp = timestamp.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
  const directory = path.resolve(root, `staging-database-role-credentials-${stamp}`);
  fs.mkdirSync(directory, { recursive: false, mode: 0o700 });
  fs.chmodSync(directory, 0o700);
  return directory;
}

export function writeSanitizedEvidence(directory, filename, value, sensitiveValues = []) {
  if (!/^[A-Za-z0-9_.-]+$/.test(filename) || filename === "SHA256SUMS.txt") {
    throw new StagingDatabaseRoleSafetyError("Evidence filename is unsafe or reserved.");
  }
  const serialized = typeof value === "string" ? value : `${JSON.stringify(value, null, 2)}\n`;
  const sanitized = redactSensitiveText(serialized, sensitiveValues);
  if (sanitized !== serialized && sensitiveValues.some((secret) => secret && serialized.includes(secret))) {
    // Redaction is intentional; only the sanitized value reaches disk.
  }
  const target = path.join(directory, filename);
  fs.writeFileSync(target, sanitized, { mode: 0o600, flag: "wx" });
  fs.chmodSync(target, 0o600);
  return target;
}

export function writeEvidenceChecksums(directory) {
  const files = fs.readdirSync(directory).filter((name) => name !== "SHA256SUMS.txt").sort();
  const lines = files.map((name) => {
    const target = path.join(directory, name);
    if (!fs.statSync(target).isFile()) throw new StagingDatabaseRoleSafetyError("Evidence directories may contain files only.");
    return `${crypto.createHash("sha256").update(fs.readFileSync(target)).digest("hex")}  ${name}`;
  });
  const checksumPath = path.join(directory, "SHA256SUMS.txt");
  fs.writeFileSync(checksumPath, `${lines.join("\n")}\n`, { mode: 0o600, flag: "wx" });
  fs.chmodSync(checksumPath, 0o600);
  return checksumPath;
}

export function createRestrictiveTempDirectory(prefix = "mscqr-staging-db-roles-") {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  fs.chmodSync(directory, 0o700);
  return directory;
}

export function securelyRemoveDirectory(directory) {
  if (!directory) return;
  const resolved = path.resolve(directory);
  if (!resolved.startsWith(path.resolve(os.tmpdir()) + path.sep)) {
    throw new StagingDatabaseRoleSafetyError("Refusing cleanup outside the operating-system temporary directory.");
  }
  for (const name of fs.existsSync(resolved) ? fs.readdirSync(resolved) : []) {
    const target = path.join(resolved, name);
    if (fs.statSync(target).isFile()) {
      try { fs.writeFileSync(target, Buffer.alloc(fs.statSync(target).size), { flag: "r+" }); } catch { /* best effort */ }
      fs.unlinkSync(target);
    }
  }
  fs.rmdirSync(resolved);
}
