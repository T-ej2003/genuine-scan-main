import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

import {
  buildDatabaseUrl,
  buildRedisUrl,
  checkSecretSyncGates,
  runSyncWorkflow,
  safeUrlPreview,
} from "../sync-staging-runtime-secrets.mjs";

const allowedIdentity = {
  Account: "368992683803",
  Arn: "arn:aws:sts::368992683803:assumed-role/mscqr-staging-terraform-provisioner/test",
};

function baseEnv(extra = {}) {
  return {
    AWS_PROFILE: "mscqr-staging-provisioner",
    AWS_REGION: "eu-west-2",
    PATH: process.env.PATH,
    ...extra,
  };
}

function terraformOutputs(overrides = {}) {
  const value = (inner) => ({ value: inner });
  return {
    rds_identifier: value("mscqr-staging-db"),
    staging_rds_address: value("mscqr-staging-db.abc123.eu-west-2.rds.amazonaws.com"),
    staging_rds_port: value(5432),
    staging_rds_database_name: value("mscqr_staging"),
    staging_rds_username: value("mscqr_staging_admin"),
    redis_replication_group_id: value("mscqr-staging-redis-euw2"),
    staging_redis_primary_endpoint_address: value("mscqr-staging-redis.abc123.euw2.cache.amazonaws.com"),
    staging_redis_port: value(6379),
    ecs_cluster_name: value("mscqr-staging-euw2-main"),
    ecs_service_name: value("mscqr-staging-backend-service-euw2"),
    ...overrides,
  };
}

function fakeDeps(overrides = {}) {
  const calls = [];
  const deps = {
    calls,
    getCallerIdentity: () => allowedIdentity,
    getTerraformOutputs: () => terraformOutputs(),
    describeDbInstance: () => ({
      Endpoint: {
        Address: "mscqr-staging-db.abc123.eu-west-2.rds.amazonaws.com",
        Port: 5432,
      },
      DBName: "mscqr_staging",
      MasterUsername: "mscqr_staging_admin",
      MasterUserSecret: {
        SecretArn: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/staging/rds-master",
      },
    }),
    describeRedisReplicationGroup: () => ({
      NodeGroups: [
        {
          PrimaryEndpoint: {
            Address: "mscqr-staging-redis.abc123.euw2.cache.amazonaws.com",
            Port: 6379,
          },
        },
      ],
    }),
    getSecretValue: () => JSON.stringify({ password: "super-secret-password" }),
    putSecretValue: ({ secretId }) => calls.push(["putSecretValue", secretId]),
    forceEcsRedeploy: ({ cluster, service }) => calls.push(["forceEcsRedeploy", cluster, service]),
    ...overrides,
  };
  return deps;
}

test("default dry-run validates without mutating AWS", () => {
  const deps = fakeDeps();
  const result = runSyncWorkflow({ argv: [], env: baseEnv(), deps });

  assert.equal(result.exitCode, 0);
  assert.equal(result.payload.status, "dry_run_ready");
  assert.equal(result.payload.mutatesAws, false);
  assert.deepEqual(deps.calls, []);
});

test("missing gates block requested secret mutation", () => {
  const deps = fakeDeps();
  const result = runSyncWorkflow({ argv: ["--sync-secrets"], env: baseEnv(), deps });

  assert.equal(result.exitCode, 1);
  assert.equal(result.payload.status, "blocked");
  assert.deepEqual(deps.calls, []);
  assert(result.payload.failures.includes("MSCQR_STAGING_SECRET_SYNC_ENABLED must be true."));
});

test("secret mutation updates only the allowed staging secret names", () => {
  const deps = fakeDeps();
  const result = runSyncWorkflow({
    argv: ["--sync-secrets"],
    env: baseEnv({
      MSCQR_STAGING_SECRET_SYNC_ENABLED: "true",
      MSCQR_STAGING_SECRET_SYNC_CONFIRM: "MSCQR_UPDATE_STAGING_RUNTIME_SECRETS",
    }),
    deps,
  });

  assert.equal(result.exitCode, 0);
  assert.deepEqual(deps.calls, [
    ["putSecretValue", "mscqr/staging/database-url"],
    ["putSecretValue", "mscqr/staging/redis-url"],
  ]);
});

test("root identity blocks all mutation", () => {
  const deps = fakeDeps({
    getCallerIdentity: () => ({
      Account: "368992683803",
      Arn: "arn:aws:iam::368992683803:root",
    }),
  });
  const result = runSyncWorkflow({
    argv: ["--sync-secrets"],
    env: baseEnv({
      MSCQR_STAGING_SECRET_SYNC_ENABLED: "true",
      MSCQR_STAGING_SECRET_SYNC_CONFIRM: "MSCQR_UPDATE_STAGING_RUNTIME_SECRETS",
    }),
    deps,
  });

  assert.equal(result.exitCode, 1);
  assert.equal(result.payload.identityCheck.classification, "root");
  assert.deepEqual(deps.calls, []);
});

test("production-looking names and hosts block sync", () => {
  const deps = fakeDeps({
    getTerraformOutputs: () => terraformOutputs({
      staging_rds_address: { value: "mscqr-prod-db.abc123.eu-west-2.rds.amazonaws.com" },
    }),
  });
  const result = runSyncWorkflow({ argv: [], env: baseEnv(), deps });

  assert.equal(result.exitCode, 1);
  assert.match(result.payload.reason, /production-looking/);
  assert.deepEqual(deps.calls, []);
});

test("secret output is redacted", () => {
  const deps = fakeDeps();
  const result = runSyncWorkflow({ argv: [], env: baseEnv(), deps });
  const output = JSON.stringify(result.payload);

  assert.equal(output.includes("super-secret-password"), false);
  assert.equal(output.includes("postgresql://mscqr_staging_admin:"), false);
  assert.match(result.payload.evidence.databaseUrlPreview, /^postgresql:\/\/<redacted>@/);
  assert.equal(result.payload.rawSecretValuesPrinted, false);
});

test("redis URL construction supports unauthenticated staging Valkey explicitly", () => {
  const url = buildRedisUrl({
    host: "mscqr-staging-redis.abc123.euw2.cache.amazonaws.com",
    port: 6379,
  });

  assert.equal(url, "redis://mscqr-staging-redis.abc123.euw2.cache.amazonaws.com:6379/0");
  assert.equal(safeUrlPreview(url), url);
});

test("database URL construction never permits production hostnames", () => {
  assert.throws(() => buildDatabaseUrl({
    username: "mscqr_staging_admin",
    password: "secret",
    host: "mscqr-prod-db.abc123.eu-west-2.rds.amazonaws.com",
    port: 5432,
    databaseName: "mscqr_staging",
  }), /production-looking/);
});

test("gate helper accepts only the exact secret sync confirmation", () => {
  assert.deepEqual(checkSecretSyncGates({
    MSCQR_STAGING_SECRET_SYNC_ENABLED: "true",
    MSCQR_STAGING_SECRET_SYNC_CONFIRM: "MSCQR_UPDATE_STAGING_RUNTIME_SECRETS",
  }), []);
  assert.equal(checkSecretSyncGates({}).length, 2);
});

test("check wrapper help is non-mutating and does not require AWS", () => {
  const result = spawnSync(process.execPath, ["scripts/check-staging-runtime-secret-sync.mjs", "--help"], {
    encoding: "utf8",
  });

  assert.equal(result.status, 0);
  assert.match(result.stdout, /Non-mutating validation wrapper/);
});
