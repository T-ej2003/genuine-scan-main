import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

import { evaluatePosture } from "../check-staging-hardening-posture.mjs";

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

function fakeDeps(overrides = {}) {
  const calls = [];
  return {
    calls,
    getCallerIdentity: () => {
      calls.push("sts:get-caller-identity");
      return allowedIdentity;
    },
    describeRedisReplicationGroup: () => {
      calls.push("elasticache:describe-replication-groups");
      return {
        TransitEncryptionEnabled: false,
        AtRestEncryptionEnabled: true,
        AuthTokenEnabled: false,
        UserGroupIds: [],
      };
    },
    describeDbInstance: () => {
      calls.push("rds:describe-db-instances");
      return { StorageEncrypted: false };
    },
    describeEcsService: () => {
      calls.push("ecs:describe-services");
      return {
        networkConfiguration: {
          awsvpcConfiguration: {
            securityGroups: ["sg-staging-ecs"],
          },
        },
      };
    },
    describeSecurityGroupRules: () => {
      calls.push("ec2:describe-security-group-rules");
      return [{ IsEgress: true, IpProtocol: "-1", CidrIpv4: "0.0.0.0/0" }];
    },
    describeLoadBalancer: () => {
      calls.push("elbv2:describe-load-balancers");
      return {
        LoadBalancerArn: "arn:aws:elasticloadbalancing:eu-west-2:368992683803:loadbalancer/app/mscqr-stg-alb-euw2/test",
      };
    },
    describeListeners: () => {
      calls.push("elbv2:describe-listeners");
      return [{ Protocol: "HTTP", Port: 80 }];
    },
    describeTargetGroup: () => {
      calls.push("elbv2:describe-target-groups");
      return {
        TargetGroupArn: "arn:aws:elasticloadbalancing:eu-west-2:368992683803:targetgroup/mscqr-stg-backend-tg-euw2/test",
      };
    },
    describeTargetHealth: () => {
      calls.push("elbv2:describe-target-health");
      return {
        TargetHealthDescriptions: [
          { TargetHealth: { State: "healthy" } },
          { TargetHealth: { State: "draining" } },
        ],
      };
    },
    getSecretValue: () => {
      calls.push("secretsmanager:get-secret-value");
      return "redis://:fixture-redis-auth-token@mscqr-staging-redis.internal:6379/0";
    },
    fetchHealth: () => {
      calls.push("http:get-health");
      return { status: 200, ok: true };
    },
    ...overrides,
  };
}

function gapCodes(payload) {
  return new Set(payload.hardeningGaps.map((gap) => gap.code));
}

test("posture checker refuses non-staging AWS profile", async () => {
  const result = await evaluatePosture({
    env: baseEnv({ AWS_PROFILE: "prod-admin" }),
    deps: fakeDeps(),
  });

  assert.equal(result.exitCode, 1);
  assert.equal(result.payload.status, "blocked");
  assert(result.payload.failures.includes("AWS_PROFILE must include a staging/stg marker."));
});

test("posture checker refuses non-staging identity", async () => {
  const result = await evaluatePosture({
    env: baseEnv(),
    deps: fakeDeps({
      getCallerIdentity: () => ({
        Account: "368992683803",
        Arn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-terraform-provisioner/test",
      }),
    }),
  });

  assert.equal(result.exitCode, 1);
  assert.equal(result.payload.identityCheck.allowed, false);
  assert.equal(result.payload.identityCheck.classification, "production-looking-role");
});

test("posture checker never prints secret values", async () => {
  const result = await evaluatePosture({ env: baseEnv(), deps: fakeDeps() });
  const output = JSON.stringify(result.payload);

  assert.equal(output.includes("fixture-redis-auth-token"), false);
  assert.equal(output.includes("redis://:"), false);
  assert.equal(result.payload.rawSecretValuesPrinted, false);
});

test("posture checker labels Redis no TLS/auth as staging-only hardening gaps", async () => {
  const result = await evaluatePosture({
    env: baseEnv(),
    deps: fakeDeps({ getSecretValue: () => "redis://mscqr-staging-redis.internal:6379/0" }),
  });
  const codes = gapCodes(result.payload);

  assert.equal(result.exitCode, 0);
  assert.equal(result.payload.redisTransitEncryptionEnabled, false);
  assert.equal(result.payload.redisAuthConfigured, false);
  assert(codes.has("redis_transit_encryption_disabled"));
  assert(codes.has("redis_auth_not_configured"));
  assert(result.payload.hardeningGaps.every((gap) => gap.severity === "staging-only-hardening-gap"));
});

test("posture checker labels RDS unencrypted as staging-only hardening gap", async () => {
  const result = await evaluatePosture({ env: baseEnv(), deps: fakeDeps() });

  assert.equal(result.payload.rdsStorageEncrypted, false);
  assert(gapCodes(result.payload).has("rds_storage_unencrypted"));
});

test("posture checker detects temporary ECS outbound to 0.0.0.0/0", async () => {
  const result = await evaluatePosture({ env: baseEnv(), deps: fakeDeps() });

  assert.equal(result.payload.ecsTemporaryOutboundOpen, true);
  assert(gapCodes(result.payload).has("ecs_temporary_world_open_egress"));
});

test("posture checker emits valid JSON-shaped payload", async () => {
  const result = await evaluatePosture({
    env: baseEnv(),
    deps: fakeDeps(),
    albHealthUrl: "http://mscqr-stg-alb-euw2.example.test/health",
  });
  const parsed = JSON.parse(JSON.stringify(result.payload));

  assert.equal(parsed.status, "ok");
  assert.equal(parsed.backendHealthStatus, 200);
  assert.equal(parsed.targetHealthHealthyCount, 1);
  assert.equal(parsed.targetHealthDrainingCount, 1);
  assert.equal(parsed.riskLevel, "needs-hardening-before-shared-use");
  assert.equal(parsed.mutatesAws, false);
});

test("posture checker test doubles make no AWS mutation calls", async () => {
  const deps = fakeDeps();
  await evaluatePosture({ env: baseEnv(), deps });

  const mutatingVerbs = /:(put|update|modify|delete|create|reboot|restore|authorize|revoke)-/;
  assert.equal(deps.calls.some((call) => mutatingVerbs.test(call)), false);
});

test("CLI unsupported argument path still prints valid JSON without AWS", () => {
  const result = spawnSync(process.execPath, ["scripts/check-staging-hardening-posture.mjs", "--bogus"], {
    encoding: "utf8",
  });

  assert.equal(result.status, 1);
  assert.doesNotThrow(() => JSON.parse(result.stdout));
  assert.match(result.stdout, /rawSecretValuesPrinted/);
});
