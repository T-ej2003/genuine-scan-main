import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  backendConfig,
  checkBootstrapEnvGates,
  evaluateBackendBootstrapIdentity,
  runBootstrapWorkflow,
} from "../bootstrap-staging-terraform-backend.mjs";
import {
  checkMigrationEnvGates,
  inspectStateSource,
  runMigrationWorkflow,
} from "../migrate-staging-terraform-state-to-s3.mjs";
import { evaluateDriftSummary } from "../check-staging-terraform-drift-summary.mjs";
import { evaluateStateBucketAuditSelectors } from "../check-staging-terraform-state-audit.mjs";

const repoRoot = path.resolve(new URL("../..", import.meta.url).pathname);
const backendTfPath = path.join(repoRoot, "infra/terraform/staging-api/backend.tf");
const backendAccessPolicyPath = path.join(
  repoRoot,
  "documents/ops/iam/MSCQR_STAGING_TERRAFORM_BACKEND_ACCESS_POLICY_2026-07-08.json",
);

const allowedIdentity = {
  Account: "368992683803",
  Arn: "arn:aws:sts::368992683803:assumed-role/mscqr-staging-terraform-provisioner/session",
};

function writeStateFixture({ count = 39, omitRequired = null, productionValue = null } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-state-fixture-"));
  const statePath = path.join(root, "terraform.tfstate");
  const required = [
    { mode: "managed", type: "aws_ecs_service", name: "backend", instances: [{}] },
    { mode: "managed", type: "aws_db_instance", name: "staging", instances: [{}] },
    { mode: "managed", type: "aws_elasticache_replication_group", name: "staging", instances: [{}] },
    { mode: "managed", type: "aws_lb", name: "staging", instances: [{}] },
    {
      mode: "managed",
      type: "aws_vpc_security_group_ingress_rule",
      name: "alb_operator_http",
      instances: [{ index_key: "46.208.2.24/32" }],
    },
  ].filter((resource) => `${resource.type}.${resource.name}` !== omitRequired);
  const extras = Array.from({ length: Math.max(0, count - required.length) }, (_, index) => ({
    mode: "managed",
    type: "aws_cloudwatch_log_group",
    name: `fixture_${index}`,
    instances: [{}],
  }));
  const state = {
    version: 4,
    terraform_version: "1.15.0",
    serial: 1,
    lineage: "fixture",
    outputs: {},
    resources: [...required, ...extras],
  };
  if (productionValue) state.resources[0].instances[0].attributes = { name: productionValue };
  fs.writeFileSync(statePath, JSON.stringify(state, null, 2), "utf8");
  return { root, statePath };
}

function runIamPolicyCheckWithBackendAccessMutator(mutator) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-backend-policy-test-"));
  const policy = JSON.parse(fs.readFileSync(backendAccessPolicyPath, "utf8"));
  mutator(policy);
  const fixturePath = path.join(root, "backend-access-policy.json");
  fs.writeFileSync(fixturePath, JSON.stringify(policy, null, 2), "utf8");
  const result = spawnSync("node", ["scripts/check-staging-iam-policies.mjs"], {
    cwd: repoRoot,
    env: {
      ...process.env,
      MSCQR_STAGING_IAM_BACKEND_ACCESS_POLICY_PATH: fixturePath,
    },
    encoding: "utf8",
  });
  fs.rmSync(root, { recursive: true, force: true });
  return result;
}

function combinedOutput(result) {
  return `${result.stdout}\n${result.stderr}`;
}

test("backend config uses S3 backend with S3 lockfile and staging account guard", () => {
  const source = fs.readFileSync(backendTfPath, "utf8");

  assert.match(source, /backend\s+"s3"/);
  assert.match(source, /bucket\s*=\s*"mscqr-staging-terraform-state-368992683803"/);
  assert.match(source, /key\s*=\s*"staging-api\/terraform\.tfstate"/);
  assert.match(source, /region\s*=\s*"eu-west-2"/);
  assert.match(source, /encrypt\s*=\s*true/);
  assert.match(source, /use_lockfile\s*=\s*true/);
  assert.match(source, /allowed_account_ids\s*=\s*\["368992683803"\]/);
  assert.doesNotMatch(source, /dynamodb/i);
  assert.doesNotMatch(source, /prod|production|mscqr-prod/i);
});

test("backend constants match requested bucket key and lock mechanism", () => {
  assert.equal(backendConfig.bucket, "mscqr-staging-terraform-state-368992683803");
  assert.equal(backendConfig.key, "staging-api/terraform.tfstate");
  assert.equal(backendConfig.region, "eu-west-2");
  assert.equal(backendConfig.lockKey, "staging-api/terraform.tfstate.tflock");
});

test("bootstrap gates are required", () => {
  assert.deepEqual(checkBootstrapEnvGates({}), [
    "MSCQR_STAGING_TERRAFORM_BACKEND_BOOTSTRAP_ENABLED must be true.",
    "MSCQR_STAGING_TERRAFORM_BACKEND_BOOTSTRAP_CONFIRM must be MSCQR_BOOTSTRAP_STAGING_TERRAFORM_BACKEND_ONCE.",
  ]);

  const result = runBootstrapWorkflow({
    env: {
      AWS_PROFILE: "mscqr-staging-terraform-provisioner",
      AWS_REGION: "eu-west-2",
    },
    deps: {
      getIdentity: () => allowedIdentity,
      configureBucket: () => {
        throw new Error("must not configure bucket without gates");
      },
    },
  });

  assert.equal(result.exitCode, 1);
  assert.equal(result.payload.mutatesBackendStorage, false);
  assert.match(result.payload.reason, /Missing explicit/);
});

test("backend bootstrap identity refuses production-looking and root identities", () => {
  const prod = evaluateBackendBootstrapIdentity({
    env: { AWS_REGION: "eu-west-2" },
    identity: {
      Account: "368992683803",
      Arn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-terraform-provisioner/session",
    },
  });
  const root = evaluateBackendBootstrapIdentity({
    env: { AWS_REGION: "eu-west-2" },
    identity: { Account: "368992683803", Arn: "arn:aws:iam::368992683803:root" },
  });

  assert.equal(prod.allowed, false);
  assert.equal(prod.classification, "production-looking-role");
  assert.equal(root.allowed, false);
  assert.equal(root.classification, "root");
});

test("migration gates are required", () => {
  assert.deepEqual(checkMigrationEnvGates({}), [
    "MSCQR_STAGING_TERRAFORM_STATE_MIGRATION_ENABLED must be true.",
    "MSCQR_STAGING_TERRAFORM_STATE_MIGRATION_CONFIRM must be MSCQR_MIGRATE_STAGING_TERRAFORM_STATE_ONCE.",
  ]);
});

test("migration refuses missing source state", () => {
  const result = runMigrationWorkflow({
    argv: ["--source-state", path.join(os.tmpdir(), "does-not-exist.tfstate")],
    env: {
      AWS_PROFILE: "mscqr-staging-terraform-provisioner",
      AWS_REGION: "eu-west-2",
    },
  });

  assert.equal(result.exitCode, 1);
  assert.match(result.payload.reason, /does not exist/);
  assert.equal(result.payload.migrationAttempted, false);
});

test("migration refuses wrong managed resource count", () => {
  const fixture = writeStateFixture({ count: 38 });
  try {
    const inspection = inspectStateSource({ sourceStatePath: fixture.statePath, expectedCount: 39 });
    assert.equal(inspection.managedResourceCount, 38);
    assert(inspection.blockers.includes("managed_resource_count_mismatch"));
  } finally {
    fs.rmSync(fixture.root, { recursive: true, force: true });
  }
});

test("migration refuses production-looking state values without printing them", () => {
  const fixture = writeStateFixture({ productionValue: "mscqr-prod-db" });
  try {
    const result = runMigrationWorkflow({
      argv: ["--source-state", fixture.statePath],
      env: {
        AWS_PROFILE: "mscqr-staging-terraform-provisioner",
        AWS_REGION: "eu-west-2",
      },
    });

    assert.equal(result.exitCode, 1);
    assert(result.payload.blockerCodes.includes("production_looking_state_value"));
    assert.equal(JSON.stringify(result.payload).includes("mscqr-prod-db"), false);
  } finally {
    fs.rmSync(fixture.root, { recursive: true, force: true });
  }
});

test("migration verifies required resource addresses", () => {
  const fixture = writeStateFixture({ omitRequired: "aws_lb.staging" });
  try {
    const inspection = inspectStateSource({ sourceStatePath: fixture.statePath, expectedCount: 39 });
    assert(inspection.blockers.includes("missing_required_resource_addresses"));
    assert(inspection.missingRequiredAddresses.includes("aws_lb.staging"));
  } finally {
    fs.rmSync(fixture.root, { recursive: true, force: true });
  }
});

test("migration with valid state still does not run without explicit gates", () => {
  const fixture = writeStateFixture();
  let migrateCalled = false;
  try {
    const result = runMigrationWorkflow({
      argv: ["--source-state", fixture.statePath],
      env: {
        AWS_PROFILE: "mscqr-staging-terraform-provisioner",
        AWS_REGION: "eu-west-2",
      },
      deps: {
        getIdentity: () => allowedIdentity,
        migrate: () => {
          migrateCalled = true;
        },
        writeEvidence: () => ".terraform-plans/staging/fixture.evidence.json",
      },
    });

    assert.equal(result.exitCode, 1);
    assert.equal(migrateCalled, false);
    assert.equal(result.payload.migrationAttempted, false);
  } finally {
    fs.rmSync(fixture.root, { recursive: true, force: true });
  }
});

test("backend IAM policy rejects broad S3 actions", () => {
  const result = runIamPolicyCheckWithBackendAccessMutator((policy) => {
    policy.Statement[1].Action = "s3:*";
  });

  assert.notEqual(result.status, 0);
  assert.match(combinedOutput(result), /broad S3 action is forbidden/);
});

test("backend IAM policy rejects Resource star", () => {
  const result = runIamPolicyCheckWithBackendAccessMutator((policy) => {
    policy.Statement[1].Resource = "*";
  });

  assert.notEqual(result.status, 0);
  assert.match(combinedOutput(result), /Resource "\*" is forbidden/);
});

test("backend IAM policy does not require DynamoDB locking by default", () => {
  const source = fs.readFileSync(backendAccessPolicyPath, "utf8");
  assert.doesNotMatch(source, /dynamodb/i);

  const result = spawnSync("node", ["scripts/check-staging-iam-policies.mjs"], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  assert.equal(result.status, 0, combinedOutput(result));
  assert.match(combinedOutput(result), /S3 lockfile/);
});

test("zero-diff drift summary checker accepts only add change destroy zero", () => {
  const ok = evaluateDriftSummary({
    status: "plan_generated",
    applyAllowed: false,
    counts: { add: 0, change: 0, destroy: 0 },
  });
  const drift = evaluateDriftSummary({
    status: "plan_generated",
    applyAllowed: false,
    counts: { add: 0, change: 1, destroy: 0 },
  });

  assert.equal(ok.status, "ok");
  assert.equal(ok.rawPlanPrinted, false);
  assert.equal(drift.status, "blocked_drift_detected");
  assert(drift.blockerCodes.includes("change_count_not_zero"));
});

test("state bucket audit checker accepts classic S3 data event selector", () => {
  const result = evaluateStateBucketAuditSelectors({
    EventSelectors: [
      {
        ReadWriteType: "All",
        DataResources: [
          {
            Type: "AWS::S3::Object",
            Values: ["arn:aws:s3:::mscqr-staging-terraform-state-368992683803/"],
          },
        ],
      },
    ],
  });

  assert.equal(result.status, "ok");
  assert.equal(result.classicReadWriteCoverage, true);
});

test("state bucket audit checker rejects missing state bucket data events", () => {
  const result = evaluateStateBucketAuditSelectors({
    EventSelectors: [
      {
        ReadWriteType: "All",
        DataResources: [
          {
            Type: "AWS::S3::Object",
            Values: ["arn:aws:s3:::some-other-bucket/"],
          },
        ],
      },
    ],
  });

  assert.equal(result.status, "blocked_state_bucket_audit_missing");
  assert(result.blockerCodes.includes("missing_state_bucket_s3_data_event_selector"));
});

test("state bucket audit checker accepts advanced S3 data event selector", () => {
  const result = evaluateStateBucketAuditSelectors({
    AdvancedEventSelectors: [
      {
        FieldSelectors: [
          { Field: "eventCategory", Equals: ["Data"] },
          { Field: "resources.type", Equals: ["AWS::S3::Object"] },
          { Field: "resources.ARN", StartsWith: ["arn:aws:s3:::mscqr-staging-terraform-state-368992683803/"] },
        ],
      },
    ],
  });

  assert.equal(result.status, "ok");
  assert.equal(result.advancedCoverage, true);
});
