#!/usr/bin/env node
import process from "node:process";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

import { evaluateStagingAwsIdentity } from "./check-staging-aws-identity.mjs";

const expectedRegion = "eu-west-2";
const defaults = {
  redisReplicationGroupId: "mscqr-staging-redis-euw2",
  dbIdentifier: "mscqr-staging-db",
  ecsCluster: "mscqr-staging-euw2-main",
  ecsService: "mscqr-staging-backend-service-euw2",
  albName: "mscqr-stg-alb-euw2",
  targetGroupName: "mscqr-stg-backend-tg-euw2",
  redisSecretId: "mscqr/staging/redis-url",
};

const mutatingAwsActions = new Set([
  "authorize-security-group-egress",
  "authorize-security-group-ingress",
  "create-listener",
  "create-replication-group",
  "create-security-group",
  "delete-security-group",
  "modify-cache-cluster",
  "modify-db-instance",
  "modify-replication-group",
  "put-secret-value",
  "reboot-cache-cluster",
  "reboot-db-instance",
  "restore-db-instance-from-db-snapshot",
  "revoke-security-group-egress",
  "revoke-security-group-ingress",
  "update-service",
]);

export function usage() {
  return `Usage:
  node scripts/check-staging-hardening-posture.mjs [--alb-health-url <url>]

Read-only posture check for staging Redis, RDS, ECS egress, ALB listeners, and
target health. It requires AWS_PROFILE plus AWS_REGION=eu-west-2 and a staging
Terraform/provisioning role in account 368992683803 by default.

The checker never prints raw secret values and never mutates AWS.`;
}

function parseFlagValue(argv, flag) {
  const index = argv.indexOf(flag);
  if (index === -1) return null;
  return argv[index + 1] || "";
}

export function parseArgs(argv = []) {
  const albHealthUrl = parseFlagValue(argv, "--alb-health-url");
  const unsupported = [];
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--help" || arg === "-h") continue;
    if (arg === "--alb-health-url") {
      index += 1;
      continue;
    }
    unsupported.push(arg);
  }
  return {
    help: argv.includes("--help") || argv.includes("-h"),
    albHealthUrl,
    unsupported,
  };
}

function runJsonCommand(command, args, { env } = {}) {
  const action = command === "aws" ? args[0] : command;
  if (command === "aws" && mutatingAwsActions.has(action)) {
    throw new Error(`Refusing mutating AWS action: ${action}.`);
  }
  const result = spawnSync(command, args, {
    encoding: "utf8",
    env,
    maxBuffer: 8 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error?.code === "ENOENT") throw new Error(`${command} is not installed or is not on PATH.`);
  if (result.error || result.status !== 0) throw new Error(`${command} ${args.join(" ")} failed.`);
  try {
    return JSON.parse(result.stdout);
  } catch {
    throw new Error(`${command} ${args.join(" ")} did not return valid JSON.`);
  }
}

function first(value) {
  return Array.isArray(value) ? value[0] : null;
}

function parseRedisSecretPosture(secretString) {
  const text = String(secretString || "");
  if (!text) return { authConfigured: false, tlsConfigured: false };
  try {
    const parsed = new URL(text);
    return {
      authConfigured: Boolean(parsed.username || parsed.password),
      tlsConfigured: parsed.protocol === "rediss:",
    };
  } catch {
    return { authConfigured: false, tlsConfigured: false };
  }
}

function profileAllowed(env) {
  const profile = String(env.AWS_PROFILE || "");
  if (!profile) return { allowed: false, reason: "AWS_PROFILE is required." };
  if (!/(^|[^a-z0-9])(staging|stg)([^a-z0-9]|$)/i.test(profile)) {
    return { allowed: false, reason: "AWS_PROFILE must include a staging/stg marker." };
  }
  if (/(^|[^a-z0-9])(prod|production)([^a-z0-9]|$)/i.test(profile)) {
    return { allowed: false, reason: "Production-looking AWS_PROFILE is refused." };
  }
  return { allowed: true, reason: null };
}

function baseOutput(extra = {}) {
  return {
    status: "blocked",
    redisTransitEncryptionEnabled: null,
    redisAtRestEncryptionEnabled: null,
    redisAuthConfigured: null,
    rdsStorageEncrypted: null,
    ecsTemporaryOutboundOpen: null,
    albHttpOnly: null,
    backendHealthStatus: null,
    targetHealthHealthyCount: null,
    targetHealthDrainingCount: null,
    riskLevel: "needs-hardening-before-shared-use",
    hardeningGaps: [],
    accessIssues: [],
    mutatesAws: false,
    rawSecretValuesPrinted: false,
    ...extra,
  };
}

function targetHealthCounts(targetHealthDescriptions = []) {
  return targetHealthDescriptions.reduce((counts, item) => {
    const state = item?.TargetHealth?.State;
    if (state === "healthy") counts.healthy += 1;
    if (state === "draining") counts.draining += 1;
    return counts;
  }, { healthy: 0, draining: 0 });
}

function hasWorldOpenEgress(securityGroupRules = []) {
  return securityGroupRules.some((rule) => (
    rule?.IsEgress === true && (rule.CidrIpv4 === "0.0.0.0/0" || rule.CidrIpv6 === "::/0")
  ));
}

function flattenSecurityGroupEgress(groups = []) {
  return groups.flatMap((group) => (group.IpPermissionsEgress || []).flatMap((permission) => [
    ...(permission.IpRanges || []).map((range) => ({
      IsEgress: true,
      IpProtocol: permission.IpProtocol,
      CidrIpv4: range.CidrIp,
    })),
    ...(permission.Ipv6Ranges || []).map((range) => ({
      IsEgress: true,
      IpProtocol: permission.IpProtocol,
      CidrIpv6: range.CidrIpv6,
    })),
  ]));
}

function listenerPosture(listeners = []) {
  const protocols = new Set(listeners.map((listener) => String(listener?.Protocol || "").toUpperCase()));
  return protocols.has("HTTP") && !protocols.has("HTTPS") && !protocols.has("TLS");
}

function addGap(gaps, code, message) {
  gaps.push({ code, severity: "staging-only-hardening-gap", message });
}

export async function evaluatePosture({ env = process.env, deps, albHealthUrl = null } = {}) {
  const region = env.AWS_REGION || env.AWS_DEFAULT_REGION || "";
  const profile = profileAllowed(env);

  let identityCheck;
  try {
    identityCheck = evaluateStagingAwsIdentity({ identity: deps.getCallerIdentity({ env }), env });
  } catch (error) {
    identityCheck = {
      account: null,
      arnType: "unknown",
      classification: "blocked",
      region: region || null,
      allowed: false,
      refusalReason: error.message,
    };
  }

  const guardFailures = [
    ...(region === expectedRegion ? [] : ["AWS_REGION or AWS_DEFAULT_REGION must be eu-west-2."]),
    ...(profile.allowed ? [] : [profile.reason]),
    ...(identityCheck.allowed ? [] : [identityCheck.refusalReason || "AWS identity is not allowed."]),
  ];
  if (guardFailures.length > 0) {
    return {
      exitCode: 1,
      payload: baseOutput({
        reason: "Staging hardening posture guardrails failed.",
        failures: guardFailures,
        region: region || null,
        identityCheck,
      }),
    };
  }

  try {
    const redis = deps.describeRedisReplicationGroup({
      env,
      region,
      replicationGroupId: env.MSCQR_STAGING_REDIS_REPLICATION_GROUP_ID || defaults.redisReplicationGroupId,
    });
    const db = deps.describeDbInstance({
      env,
      region,
      dbIdentifier: env.MSCQR_STAGING_RDS_IDENTIFIER || defaults.dbIdentifier,
    });
    const service = deps.describeEcsService({
      env,
      region,
      cluster: env.MSCQR_STAGING_ECS_CLUSTER || defaults.ecsCluster,
      service: env.MSCQR_STAGING_ECS_SERVICE || defaults.ecsService,
    });
    const ecsSecurityGroupIds = service?.networkConfiguration?.awsvpcConfiguration?.securityGroups || [];
    const securityGroupRules = ecsSecurityGroupIds.length > 0
      ? deps.describeSecurityGroupRules({ env, region, securityGroupIds: ecsSecurityGroupIds })
      : [];
    const loadBalancer = deps.describeLoadBalancer({
      env,
      region,
      name: env.MSCQR_STAGING_ALB_NAME || defaults.albName,
    });
    const listeners = deps.describeListeners({ env, region, loadBalancerArn: loadBalancer.LoadBalancerArn });
    const targetGroup = deps.describeTargetGroup({
      env,
      region,
      name: env.MSCQR_STAGING_TARGET_GROUP_NAME || defaults.targetGroupName,
    });
    const targetHealth = deps.describeTargetHealth({ env, region, targetGroupArn: targetGroup.TargetGroupArn });
    const accessIssues = [];
    let redisSecret = "";
    if (deps.getSecretValue) {
      try {
        redisSecret = deps.getSecretValue({
          env,
          region,
          secretId: env.MSCQR_STAGING_REDIS_SECRET_ID || defaults.redisSecretId,
        });
      } catch {
        accessIssues.push("redis_secret_value_unreadable");
      }
    }
    const redisSecretPosture = parseRedisSecretPosture(redisSecret);
    const health = albHealthUrl ? await deps.fetchHealth({ url: albHealthUrl }) : null;
    const counts = targetHealthCounts(targetHealth.TargetHealthDescriptions || []);
    const gaps = [];
    const redisTransitEncryptionEnabled = redis.TransitEncryptionEnabled === true || redisSecretPosture.tlsConfigured;
    const redisAtRestEncryptionEnabled = redis.AtRestEncryptionEnabled === true;
    const redisAuthConfigured = Boolean(redis.AuthTokenEnabled || redisSecretPosture.authConfigured || redis.UserGroupIds?.length);
    const rdsStorageEncrypted = db.StorageEncrypted === true;
    const ecsTemporaryOutboundOpen = hasWorldOpenEgress(securityGroupRules);
    const albHttpOnly = listenerPosture(listeners);

    if (!redisTransitEncryptionEnabled) {
      addGap(gaps, "redis_transit_encryption_disabled", "Staging Valkey/Redis does not have in-transit TLS enabled.");
    }
    if (!redisAuthConfigured) {
      addGap(gaps, "redis_auth_not_configured", "Staging Valkey/Redis does not have AUTH or ACL user-group auth detected.");
    }
    if (!redisAtRestEncryptionEnabled) {
      addGap(gaps, "redis_at_rest_encryption_disabled", "Staging Valkey/Redis at-rest encryption is disabled.");
    }
    if (!rdsStorageEncrypted) {
      addGap(gaps, "rds_storage_unencrypted", "Staging RDS storage encryption is disabled.");
    }
    if (ecsTemporaryOutboundOpen) {
      addGap(gaps, "ecs_temporary_world_open_egress", "Staging ECS security group still has temporary 0.0.0.0/0 or ::/0 outbound.");
    }
    if (albHttpOnly) {
      addGap(gaps, "alb_http_only", "Staging ALB has HTTP listener coverage without HTTPS/TLS listener coverage.");
    }

    return {
      exitCode: 0,
      payload: {
        status: "ok",
        region,
        identityCheck,
        redisTransitEncryptionEnabled,
        redisAtRestEncryptionEnabled,
        redisAuthConfigured,
        rdsStorageEncrypted,
        ecsTemporaryOutboundOpen,
        albHttpOnly,
        backendHealthStatus: health?.status || null,
        targetHealthHealthyCount: counts.healthy,
        targetHealthDrainingCount: counts.draining,
        riskLevel: gaps.length > 0 ? "needs-hardening-before-shared-use" : "staging-only",
        hardeningGaps: gaps,
        accessIssues,
        mutatesAws: false,
        rawSecretValuesPrinted: false,
      },
    };
  } catch (error) {
    return {
      exitCode: 1,
      payload: baseOutput({ reason: error.message, region, identityCheck }),
    };
  }
}

export function createRealDeps() {
  return {
    getCallerIdentity: ({ env }) =>
      runJsonCommand("aws", ["sts", "get-caller-identity", "--output", "json"], { env }),
    describeRedisReplicationGroup: ({ env, region, replicationGroupId }) =>
      first(runJsonCommand("aws", [
        "elasticache", "describe-replication-groups", "--region", region,
        "--replication-group-id", replicationGroupId, "--output", "json",
      ], { env }).ReplicationGroups) || {},
    describeDbInstance: ({ env, region, dbIdentifier }) =>
      first(runJsonCommand("aws", [
        "rds", "describe-db-instances", "--region", region,
        "--db-instance-identifier", dbIdentifier, "--output", "json",
      ], { env }).DBInstances) || {},
    describeEcsService: ({ env, region, cluster, service }) =>
      first(runJsonCommand("aws", [
        "ecs", "describe-services", "--region", region, "--cluster", cluster,
        "--services", service, "--output", "json",
      ], { env }).services) || {},
    describeSecurityGroupRules: ({ env, region, securityGroupIds }) => {
      try {
        return runJsonCommand("aws", [
          "ec2", "describe-security-group-rules", "--region", region, "--filters",
          `Name=group-id,Values=${securityGroupIds.join(",")}`,
          "Name=is-egress,Values=true", "--output", "json",
        ], { env }).SecurityGroupRules || [];
      } catch {
        const groups = runJsonCommand("aws", [
          "ec2", "describe-security-groups", "--region", region,
          "--group-ids", ...securityGroupIds, "--output", "json",
        ], { env }).SecurityGroups || [];
        return flattenSecurityGroupEgress(groups);
      }
    },
    describeLoadBalancer: ({ env, region, name }) =>
      first(runJsonCommand("aws", [
        "elbv2", "describe-load-balancers", "--region", region, "--names", name, "--output", "json",
      ], { env }).LoadBalancers) || {},
    describeListeners: ({ env, region, loadBalancerArn }) =>
      runJsonCommand("aws", [
        "elbv2", "describe-listeners", "--region", region,
        "--load-balancer-arn", loadBalancerArn, "--output", "json",
      ], { env }).Listeners || [],
    describeTargetGroup: ({ env, region, name }) =>
      first(runJsonCommand("aws", [
        "elbv2", "describe-target-groups", "--region", region, "--names", name, "--output", "json",
      ], { env }).TargetGroups) || {},
    describeTargetHealth: ({ env, region, targetGroupArn }) =>
      runJsonCommand("aws", [
        "elbv2", "describe-target-health", "--region", region,
        "--target-group-arn", targetGroupArn, "--output", "json",
      ], { env }),
    getSecretValue: ({ env, region, secretId }) =>
      runJsonCommand("aws", [
        "secretsmanager", "get-secret-value", "--region", region,
        "--secret-id", secretId, "--output", "json",
      ], { env }).SecretString || "",
    fetchHealth: async ({ url }) => {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      try {
        const response = await fetch(url, { signal: controller.signal });
        return { status: response.status, ok: response.ok };
      } finally {
        clearTimeout(timeout);
      }
    },
  };
}

export async function main(argv = process.argv.slice(2), env = process.env) {
  const args = parseArgs(argv);
  if (args.help) {
    console.log(usage());
    return 0;
  }
  if (args.unsupported.length > 0) {
    console.log(JSON.stringify(baseOutput({ reason: "Unsupported arguments.", unsupportedArgs: args.unsupported }), null, 2));
    return 1;
  }
  const result = await evaluatePosture({ env, deps: createRealDeps(), albHealthUrl: args.albHealthUrl });
  console.log(JSON.stringify(result.payload, null, 2));
  return result.exitCode;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(await main());
}
