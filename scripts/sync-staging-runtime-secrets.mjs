#!/usr/bin/env node
import process from "node:process";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

import { evaluateStagingAwsIdentity } from "./check-staging-aws-identity.mjs";

const terraformRoot = "infra/terraform/staging-api";
const expectedRegion = "eu-west-2";
const databaseSecretId = "mscqr/staging/database-url";
const redisSecretId = "mscqr/staging/redis-url";
const requiredSecretSyncConfirm = "MSCQR_UPDATE_STAGING_RUNTIME_SECRETS";
const requiredRedeployConfirm = "MSCQR_FORCE_STAGING_ECS_REDEPLOY";
const defaultDbIdentifier = "mscqr-staging-db";
const defaultRedisReplicationGroupId = "mscqr-staging-redis-euw2";
const allowedSecretIds = new Set([databaseSecretId, redisSecretId]);
const knownProductionFragments = [
  "prod",
  "production",
  "mscqr-prod",
  "mscqr-prod-db",
  "mscqr-prod-db-proxy",
  "mscqr-redis-euw2-primary",
];
const productionDomainHostnames = new Set(["mscqr.com", "www.mscqr.com"]);
const urlSchemePattern = /^[A-Za-z][A-Za-z0-9+.-]*:\/\//;
const rawHostUnsafePattern = /[/?#@\\\s]/;

export function usage() {
  return `Usage:
  node scripts/sync-staging-runtime-secrets.mjs [--dry-run]
  node scripts/sync-staging-runtime-secrets.mjs --sync-secrets
  node scripts/sync-staging-runtime-secrets.mjs --force-ecs-redeploy

Dry-run is the default. This script reads staging Terraform outputs and AWS
describe calls, validates staging-only guardrails, and prints redacted evidence.

Secret mutation requires both:
  MSCQR_STAGING_SECRET_SYNC_ENABLED=true
  MSCQR_STAGING_SECRET_SYNC_CONFIRM=MSCQR_UPDATE_STAGING_RUNTIME_SECRETS

ECS redeploy requires both:
  MSCQR_STAGING_ECS_REDEPLOY_ENABLED=true
  MSCQR_STAGING_ECS_REDEPLOY_CONFIRM=MSCQR_FORCE_STAGING_ECS_REDEPLOY

Required operator context:
  AWS_PROFILE=<staging provisioning profile>
  AWS_REGION=eu-west-2

DATABASE_URL password source, in precedence order:
  MSCQR_STAGING_DATABASE_PASSWORD
  MSCQR_STAGING_DATABASE_PASSWORD_SECRET_ID
  RDS managed master user secret returned by describe-db-instances

The script never prints full DATABASE_URL, REDIS_URL, passwords, tokens, or
secret strings.`;
}

function outputValue(outputs, key) {
  return outputs?.[key]?.value ?? null;
}

function normalizePort(value, fallback) {
  const port = Number(value ?? fallback);
  return Number.isInteger(port) && port > 0 && port <= 65535 ? port : null;
}

function normalizeHostname(hostname) {
  return String(hostname || "")
    .trim()
    .toLowerCase()
    .replace(/\.$/, "");
}

export function isProductionDomainHostname(hostname) {
  const normalized = normalizeHostname(hostname);
  const labels = normalized.split(".").filter(Boolean);
  const parentDomainLabels = labels.slice(-2);
  return productionDomainHostnames.has(normalized) ||
    (parentDomainLabels[0] === "mscqr" && parentDomainLabels[1] === "com");
}

function hasWrappedProductionDomainLabels(hostname) {
  const labels = normalizeHostname(hostname).split(".").filter(Boolean);
  return labels.some((label, index) => label === "mscqr" && labels[index + 1] === "com");
}

function parseUrlHostname(value) {
  const parsed = new URL(value);
  if (!parsed.hostname) throw new Error("URL must include a hostname.");
  return normalizeHostname(parsed.hostname);
}

export function parseRawHostname(value) {
  const text = String(value || "").trim();
  if (!text) throw new Error("hostname is required.");
  if (urlSchemePattern.test(text)) throw new Error("hostname must not include a URL scheme.");
  if (rawHostUnsafePattern.test(text)) {
    throw new Error("hostname must not include URL path, query, fragment, userinfo, or whitespace.");
  }

  const parsed = new URL(`http://${text}`);
  if (!parsed.hostname) throw new Error("hostname is required.");
  return normalizeHostname(parsed.hostname);
}

function parseRawHostnameOrNull(value) {
  try {
    return parseRawHostname(value);
  } catch {
    return null;
  }
}

function hostnameHasProductionFragment(hostname) {
  const normalized = normalizeHostname(hostname);
  return knownProductionFragments.some((fragment) => normalized.includes(fragment));
}

export function isProductionLooking(value) {
  const text = String(value || "").trim();
  const normalized = text.toLowerCase();
  if (!normalized) return false;

  if (urlSchemePattern.test(text)) {
    try {
      const hostname = parseUrlHostname(text);
      return isProductionDomainHostname(hostname) ||
        hasWrappedProductionDomainLabels(hostname) ||
        hostnameHasProductionFragment(hostname);
    } catch {
      return true;
    }
  }

  const hostname = parseRawHostnameOrNull(text);
  if (hostname && (isProductionDomainHostname(hostname) || hasWrappedProductionDomainLabels(hostname))) {
    return true;
  }

  return knownProductionFragments.some((fragment) => normalized.includes(fragment));
}

function hasStagingMarker(value) {
  return /staging|stg/i.test(String(value || ""));
}

function requireSafeStagingValue(label, value, { requireMarker = true } = {}) {
  const text = String(value || "").trim();
  if (!text) throw new Error(`${label} is required.`);
  if (isProductionLooking(text)) throw new Error(`${label} is production-looking and is refused.`);
  if (requireMarker && !hasStagingMarker(text)) throw new Error(`${label} must include a staging/stg marker.`);
  return text;
}

function requireSafeStagingHostname(label, value) {
  let hostname;
  try {
    hostname = parseRawHostname(value);
  } catch (error) {
    throw new Error(`${label} ${error.message}`);
  }
  if (
    isProductionDomainHostname(hostname) ||
    hasWrappedProductionDomainLabels(hostname) ||
    hostnameHasProductionFragment(hostname)
  ) {
    throw new Error(`${label} is production-looking and is refused.`);
  }
  if (!hasStagingMarker(hostname)) throw new Error(`${label} must include a staging/stg marker.`);
  return hostname;
}

function requireAllowedSecretId(secretId) {
  const value = String(secretId || "").trim();
  if (!allowedSecretIds.has(value)) {
    throw new Error(`Secret ID is not in the staging runtime allowlist: ${value || "<empty>"}.`);
  }
  if (isProductionLooking(value)) throw new Error("Secret ID is production-looking and is refused.");
  return value;
}

function encodeUrlPart(value) {
  return encodeURIComponent(String(value));
}

export function buildDatabaseUrl({
  username,
  password,
  host,
  port,
  databaseName,
  sslmode = "require",
}) {
  const safeUsername = requireSafeStagingValue("database username", username, { requireMarker: false });
  const safeHost = requireSafeStagingHostname("database host", host);
  const safeDatabaseName = requireSafeStagingValue("database name", databaseName);
  const safePort = normalizePort(port, 5432);
  if (!safePort) throw new Error("database port must be a valid TCP port.");
  if (!String(password || "")) throw new Error("database password is required and was not printed.");
  const query = sslmode ? `?sslmode=${encodeURIComponent(String(sslmode))}` : "";
  return `postgresql://${encodeUrlPart(safeUsername)}:${encodeUrlPart(password)}@${safeHost}:${safePort}/${encodeUrlPart(safeDatabaseName)}${query}`;
}

export function buildRedisUrl({ host, port, database = 0, password = "" }) {
  const safeHost = requireSafeStagingHostname("redis host", host);
  const safePort = normalizePort(port, 6379);
  if (!safePort) throw new Error("redis port must be a valid TCP port.");
  const auth = password ? `:${encodeUrlPart(password)}@` : "";
  return `redis://${auth}${safeHost}:${safePort}/${Number(database) || 0}`;
}

export function safeUrlPreview(raw) {
  if (!raw) return null;
  try {
    const parsed = new URL(raw);
    const auth = parsed.username || parsed.password ? "<redacted>@" : "";
    return `${parsed.protocol}//${auth}${parsed.host}${parsed.pathname}${parsed.search}${parsed.hash}`;
  } catch {
    return "<unparseable-url-redacted>";
  }
}

function parseSecretString(secretString) {
  const text = String(secretString || "");
  if (!text) return {};
  try {
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === "object" ? parsed : { password: text };
  } catch {
    return { password: text };
  }
}

function runJsonCommand(command, args, { env, input } = {}) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    env,
    input,
    maxBuffer: 8 * 1024 * 1024,
    stdio: [input === undefined ? "ignore" : "pipe", "pipe", "pipe"],
  });
  if (result.error?.code === "ENOENT") throw new Error(`${command} is not installed or is not on PATH.`);
  if (result.error) throw new Error(`${command} failed.`);
  if (result.status !== 0) throw new Error(`${command} ${args.join(" ")} failed.`);
  try {
    return JSON.parse(result.stdout);
  } catch {
    throw new Error(`${command} ${args.join(" ")} did not return valid JSON.`);
  }
}

export function createRealDeps() {
  return {
    getCallerIdentity: ({ env }) =>
      runJsonCommand("aws", ["sts", "get-caller-identity", "--output", "json"], { env }),
    getTerraformOutputs: ({ env }) =>
      runJsonCommand("terraform", [`-chdir=${terraformRoot}`, "output", "-json"], { env }),
    describeDbInstance: ({ env, region, dbIdentifier }) => {
      const result = runJsonCommand("aws", [
        "rds",
        "describe-db-instances",
        "--region",
        region,
        "--db-instance-identifier",
        dbIdentifier,
        "--output",
        "json",
      ], { env });
      return result.DBInstances?.[0] || null;
    },
    describeRedisReplicationGroup: ({ env, region, replicationGroupId }) => {
      const result = runJsonCommand("aws", [
        "elasticache",
        "describe-replication-groups",
        "--region",
        region,
        "--replication-group-id",
        replicationGroupId,
        "--output",
        "json",
      ], { env });
      return result.ReplicationGroups?.[0] || null;
    },
    getSecretValue: ({ env, region, secretId }) =>
      runJsonCommand("aws", [
        "secretsmanager",
        "get-secret-value",
        "--region",
        region,
        "--secret-id",
        secretId,
        "--output",
        "json",
      ], { env }).SecretString || "",
    putSecretValue: ({ env, region, secretId, secretString }) =>
      runJsonCommand("aws", [
        "secretsmanager",
        "put-secret-value",
        "--region",
        region,
        "--secret-id",
        secretId,
        "--secret-string",
        "file:///dev/stdin",
        "--output",
        "json",
      ], { env, input: secretString }),
    forceEcsRedeploy: ({ env, region, cluster, service }) =>
      runJsonCommand("aws", [
        "ecs",
        "update-service",
        "--region",
        region,
        "--cluster",
        cluster,
        "--service",
        service,
        "--force-new-deployment",
        "--output",
        "json",
      ], { env }),
  };
}

export function parseArgs(argv) {
  const allowed = new Set(["--help", "-h", "--dry-run", "--validate-only", "--sync-secrets", "--force-ecs-redeploy"]);
  const unsupported = argv.filter((arg) => !allowed.has(arg));
  return {
    help: argv.includes("--help") || argv.includes("-h"),
    syncSecrets: argv.includes("--sync-secrets"),
    forceEcsRedeploy: argv.includes("--force-ecs-redeploy"),
    unsupported,
  };
}

export function checkSecretSyncGates(env) {
  const failures = [];
  if (env.MSCQR_STAGING_SECRET_SYNC_ENABLED !== "true") {
    failures.push("MSCQR_STAGING_SECRET_SYNC_ENABLED must be true.");
  }
  if (env.MSCQR_STAGING_SECRET_SYNC_CONFIRM !== requiredSecretSyncConfirm) {
    failures.push(`MSCQR_STAGING_SECRET_SYNC_CONFIRM must be ${requiredSecretSyncConfirm}.`);
  }
  return failures;
}

export function checkRedeployGates(env) {
  const failures = [];
  if (env.MSCQR_STAGING_ECS_REDEPLOY_ENABLED !== "true") {
    failures.push("MSCQR_STAGING_ECS_REDEPLOY_ENABLED must be true.");
  }
  if (env.MSCQR_STAGING_ECS_REDEPLOY_CONFIRM !== requiredRedeployConfirm) {
    failures.push(`MSCQR_STAGING_ECS_REDEPLOY_CONFIRM must be ${requiredRedeployConfirm}.`);
  }
  return failures;
}

function validateBaseEnv(env) {
  const failures = [];
  const region = env.AWS_REGION || env.AWS_DEFAULT_REGION || "";
  if (!env.AWS_PROFILE) failures.push("AWS_PROFILE is required for the manual staging secret sync.");
  if (region !== expectedRegion) failures.push("AWS_REGION or AWS_DEFAULT_REGION must be eu-west-2.");
  return { region, failures };
}

function normalizeTerraformOutputs(outputs) {
  return {
    dbIdentifier: outputValue(outputs, "rds_identifier") || defaultDbIdentifier,
    dbHost: outputValue(outputs, "staging_rds_address"),
    dbPort: normalizePort(outputValue(outputs, "staging_rds_port"), 5432),
    dbName: outputValue(outputs, "staging_rds_database_name"),
    dbUsername: outputValue(outputs, "staging_rds_username"),
    redisReplicationGroupId: outputValue(outputs, "redis_replication_group_id") || defaultRedisReplicationGroupId,
    redisHost: outputValue(outputs, "staging_redis_primary_endpoint_address"),
    redisPort: normalizePort(outputValue(outputs, "staging_redis_port"), 6379),
    ecsCluster: outputValue(outputs, "ecs_cluster_name") || outputValue(outputs, "staging_cluster_name"),
    ecsService: outputValue(outputs, "ecs_service_name") || outputValue(outputs, "staging_backend_service_name"),
  };
}

function normalizeDbDescribe(dbInstance) {
  return {
    dbHost: dbInstance?.Endpoint?.Address || null,
    dbPort: normalizePort(dbInstance?.Endpoint?.Port, 5432),
    dbName: dbInstance?.DBName || null,
    dbUsername: dbInstance?.MasterUsername || null,
    masterUserSecretArn: dbInstance?.MasterUserSecret?.SecretArn || null,
  };
}

function normalizeRedisDescribe(group) {
  const nodeGroup = group?.NodeGroups?.[0] || {};
  const endpoint = nodeGroup.PrimaryEndpoint || group?.ConfigurationEndpoint || {};
  return {
    redisHost: endpoint.Address || null,
    redisPort: normalizePort(endpoint.Port || group?.ConfigurationEndpoint?.Port, 6379),
  };
}

function resolvePassword({ env, deps, region, masterUserSecretArn }) {
  if (env.MSCQR_STAGING_DATABASE_PASSWORD) {
    return { source: "operator-env", parsed: { password: env.MSCQR_STAGING_DATABASE_PASSWORD } };
  }
  const explicitSecretId = String(env.MSCQR_STAGING_DATABASE_PASSWORD_SECRET_ID || "").trim();
  const secretId = explicitSecretId || masterUserSecretArn;
  if (!secretId) throw new Error("Database password source is missing.");
  if (isProductionLooking(secretId)) throw new Error("Database password secret identifier is production-looking and is refused.");
  const secretString = deps.getSecretValue({ env, region, secretId });
  return {
    source: explicitSecretId ? "operator-secret" : "rds-managed-master-user-secret",
    parsed: parseSecretString(secretString),
  };
}

function buildPlan({ env, deps, region }) {
  const outputs = normalizeTerraformOutputs(deps.getTerraformOutputs({ env }));
  requireSafeStagingValue("RDS identifier", outputs.dbIdentifier);
  requireSafeStagingValue("Redis replication group ID", outputs.redisReplicationGroupId);

  const dbDescribe = normalizeDbDescribe(deps.describeDbInstance({
    env,
    region,
    dbIdentifier: outputs.dbIdentifier,
  }));
  const redisDescribe = normalizeRedisDescribe(deps.describeRedisReplicationGroup({
    env,
    region,
    replicationGroupId: outputs.redisReplicationGroupId,
  }));
  const password = resolvePassword({
    env,
    deps,
    region,
    masterUserSecretArn: dbDescribe.masterUserSecretArn,
  });

  const db = {
    username: env.MSCQR_STAGING_DATABASE_USERNAME || outputs.dbUsername || password.parsed.username || dbDescribe.dbUsername,
    password: password.parsed.password,
    host: outputs.dbHost || dbDescribe.dbHost,
    port: outputs.dbPort || dbDescribe.dbPort,
    databaseName: env.MSCQR_STAGING_DATABASE_NAME || outputs.dbName || password.parsed.dbname || password.parsed.dbName || dbDescribe.dbName,
    sslmode: env.MSCQR_STAGING_DATABASE_SSLMODE || "require",
  };
  const redis = {
    host: outputs.redisHost || redisDescribe.redisHost,
    port: outputs.redisPort || redisDescribe.redisPort,
    password: env.MSCQR_STAGING_REDIS_PASSWORD || "",
  };

  const databaseUrl = buildDatabaseUrl(db);
  const redisUrl = buildRedisUrl(redis);
  const ecsCluster = env.MSCQR_STAGING_ECS_CLUSTER || outputs.ecsCluster;
  const ecsService = env.MSCQR_STAGING_ECS_SERVICE || outputs.ecsService;

  requireAllowedSecretId(databaseSecretId);
  requireAllowedSecretId(redisSecretId);
  requireSafeStagingValue("ECS cluster", ecsCluster);
  requireSafeStagingValue("ECS service", ecsService);

  return {
    databaseUrl,
    redisUrl,
    ecsCluster,
    ecsService,
    evidence: {
      databaseSecretId,
      redisSecretId,
      dbIdentifier: outputs.dbIdentifier,
      dbHost: db.host,
      dbPort: Number(db.port),
      dbName: db.databaseName,
      dbUsername: db.username,
      dbPasswordSource: password.source,
      databaseUrlPreview: safeUrlPreview(databaseUrl),
      redisReplicationGroupId: outputs.redisReplicationGroupId,
      redisHost: redis.host,
      redisPort: Number(redis.port),
      redisAuthConfigured: Boolean(redis.password),
      redisUrlPreview: safeUrlPreview(redisUrl),
      ecsCluster,
      ecsService,
    },
  };
}

export function runSyncWorkflow({ argv = [], env = process.env, deps = createRealDeps() } = {}) {
  const args = parseArgs(argv);
  if (args.help) return { exitCode: 0, payload: { usage: usage() } };
  if (args.unsupported.length > 0) {
    return {
      exitCode: 1,
      payload: {
        status: "blocked",
        reason: "Unsupported arguments.",
        unsupportedArgs: args.unsupported,
        mutatesAws: false,
        rawSecretValuesPrinted: false,
      },
    };
  }

  const base = validateBaseEnv(env);
  const requestedMutation = args.syncSecrets || args.forceEcsRedeploy;
  const secretGateFailures = args.syncSecrets ? checkSecretSyncGates(env) : [];
  const redeployGateFailures = args.forceEcsRedeploy ? checkRedeployGates(env) : [];

  let identityCheck;
  try {
    identityCheck = evaluateStagingAwsIdentity({ identity: deps.getCallerIdentity({ env }), env });
  } catch (error) {
    identityCheck = {
      account: null,
      arnType: "unknown",
      classification: "blocked",
      region: base.region || null,
      allowed: false,
      refusalReason: error.message,
    };
  }

  const earlyFailures = [
    ...base.failures,
    ...(identityCheck.allowed ? [] : [identityCheck.refusalReason || "AWS identity is not allowed."]),
    ...secretGateFailures,
    ...redeployGateFailures,
  ];
  if (earlyFailures.length > 0) {
    return {
      exitCode: requestedMutation || base.failures.length > 0 || !identityCheck.allowed ? 1 : 0,
      payload: {
        status: "blocked",
        reason: "Staging runtime secret sync guardrails failed.",
        failures: earlyFailures,
        identityCheck,
        syncRequested: args.syncSecrets,
        redeployRequested: args.forceEcsRedeploy,
        mutatesAws: false,
        rawSecretValuesPrinted: false,
      },
    };
  }

  try {
    const plan = buildPlan({ env, deps, region: base.region });
    const operations = [];
    if (args.syncSecrets) {
      deps.putSecretValue({
        env,
        region: base.region,
        secretId: databaseSecretId,
        secretString: plan.databaseUrl,
      });
      deps.putSecretValue({
        env,
        region: base.region,
        secretId: redisSecretId,
        secretString: plan.redisUrl,
      });
      operations.push("updated-staging-runtime-secrets");
    }
    if (args.forceEcsRedeploy) {
      deps.forceEcsRedeploy({
        env,
        region: base.region,
        cluster: plan.ecsCluster,
        service: plan.ecsService,
      });
      operations.push("forced-staging-ecs-redeployment");
    }

    return {
      exitCode: 0,
      payload: {
        status: args.syncSecrets || args.forceEcsRedeploy ? "completed" : "dry_run_ready",
        region: base.region,
        identityCheck,
        syncRequested: args.syncSecrets,
        redeployRequested: args.forceEcsRedeploy,
        mutatesAws: Boolean(args.syncSecrets || args.forceEcsRedeploy),
        operations,
        evidence: plan.evidence,
        rawSecretValuesPrinted: false,
      },
    };
  } catch (error) {
    return {
      exitCode: 1,
      payload: {
        status: "blocked",
        reason: error.message,
        region: base.region,
        identityCheck,
        syncRequested: args.syncSecrets,
        redeployRequested: args.forceEcsRedeploy,
        mutatesAws: false,
        rawSecretValuesPrinted: false,
      },
    };
  }
}

export function main(argv = process.argv.slice(2), env = process.env) {
  const result = runSyncWorkflow({ argv, env });
  if (result.payload.usage) {
    console.log(result.payload.usage);
  } else {
    console.log(JSON.stringify(result.payload, null, 2));
  }
  return result.exitCode;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main());
}
