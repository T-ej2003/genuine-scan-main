import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  checkApplyEnvGates,
  evaluateSavedPlan,
  findForbiddenApplyArgs,
  runApplyWorkflow,
  validateApplyProfile,
} from "../apply-staging-terraform.mjs";
import { evaluateStagingAwsApplyIdentity } from "../check-staging-aws-apply-identity.mjs";

const allowedIdentity = {
  account: "368992683803",
  arnType: "assumed-role",
  classification: "staging-apply-role",
  region: "eu-west-2",
  allowed: true,
  refusalReason: null,
};

function baseEnv(extra = {}) {
  return {
    AWS_PROFILE: "mscqr-staging-apply",
    AWS_REGION: "eu-west-2",
    MSCQR_STAGING_TERRAFORM_APPLY_ENABLED: "true",
    MSCQR_STAGING_TERRAFORM_APPLY_CONFIRM: "MSCQR_APPLY_STAGING_TERRAFORM_ONCE",
    MSCQR_STAGING_TERRAFORM_APPLY_EXPECTED_ADD_COUNT: "38",
    MSCQR_STAGING_TERRAFORM_APPLY_EXPECTED_CHANGE_COUNT: "0",
    PATH: process.env.PATH,
    ...extra,
  };
}

function writePlanFixture({
  counts = { add: 38, change: 0, destroy: 0 },
  planText = "Plan: 38 to add, 0 to change, 0 to destroy.\n",
  summary = {},
} = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-apply-test-"));
  const planDir = path.join(root, ".terraform-plans/staging");
  fs.mkdirSync(planDir, { recursive: true });
  const planPath = path.join(planDir, "staging-plan.tfplan");
  const summaryPath = path.join(planDir, "staging-plan.summary.json");
  const textPath = path.join(planDir, "staging-plan.txt");
  fs.writeFileSync(planPath, "terraform plan fixture", "utf8");
  fs.writeFileSync(
    summaryPath,
    JSON.stringify({ status: "plan_generated", counts, applyAllowed: false, ...summary }, null, 2),
    "utf8",
  );
  fs.writeFileSync(textPath, planText, "utf8");
  return { root, planPath: path.relative(root, planPath) };
}

function fakeDeps(overrides = {}) {
  const calls = [];
  return {
    calls,
    getIdentity: () => allowedIdentity,
    apply: () => calls.push("apply"),
    writeFile: () => calls.push("writeFile"),
    ...overrides,
  };
}

test("apply identity guard allows only assumed staging apply role", () => {
  const result = evaluateStagingAwsApplyIdentity({
    env: { AWS_REGION: "eu-west-2" },
    identity: {
      Account: "368992683803",
      Arn: "arn:aws:sts::368992683803:assumed-role/mscqr-staging-terraform-apply-role/session",
    },
  });

  assert.equal(result.allowed, true);
  assert.equal(result.classification, "staging-apply-role");
});

test("root identity blocks", () => {
  const result = evaluateStagingAwsApplyIdentity({
    env: { AWS_REGION: "eu-west-2" },
    identity: {
      Account: "368992683803",
      Arn: "arn:aws:iam::368992683803:root",
    },
  });

  assert.equal(result.allowed, false);
  assert.equal(result.classification, "root");
});

test("plan role blocks", () => {
  const result = evaluateStagingAwsApplyIdentity({
    env: { AWS_REGION: "eu-west-2" },
    identity: {
      Account: "368992683803",
      Arn: "arn:aws:sts::368992683803:assumed-role/mscqr-staging-terraform-plan-role/session",
    },
  });

  assert.equal(result.allowed, false);
  assert.equal(result.classification, "plan-role");
});

test("wrong region blocks", () => {
  const result = evaluateStagingAwsApplyIdentity({
    env: { AWS_REGION: "us-east-1" },
    identity: {
      Account: "368992683803",
      Arn: "arn:aws:sts::368992683803:assumed-role/mscqr-staging-terraform-apply-role/session",
    },
  });

  assert.equal(result.allowed, false);
  assert.equal(result.classification, "wrong-region");
});

test("missing gates block apply", () => {
  assert.deepEqual(checkApplyEnvGates({}), [
    "MSCQR_STAGING_TERRAFORM_APPLY_ENABLED must be true.",
    "MSCQR_STAGING_TERRAFORM_APPLY_CONFIRM must be MSCQR_APPLY_STAGING_TERRAFORM_ONCE.",
  ]);
});

test("apply profile must be staging apply profile", () => {
  assert.deepEqual(validateApplyProfile({ AWS_PROFILE: "mscqr-staging-apply" }), []);
  assert(validateApplyProfile({ AWS_PROFILE: "mscqr-staging-plan" }).includes("AWS_PROFILE must contain apply."));
  assert(validateApplyProfile({ AWS_PROFILE: "mscqr-production-apply" }).includes("AWS_PROFILE must not be production-looking."));
});

test("raw apply without saved plan blocks and does not mutate", () => {
  const deps = fakeDeps();
  const result = runApplyWorkflow({ argv: [], env: baseEnv(), deps });

  assert.equal(result.exitCode, 1);
  assert.equal(result.payload.mutatesAws, false);
  assert.equal(deps.calls.length, 0);
});

test("forbidden apply options are refused", () => {
  assert.deepEqual(findForbiddenApplyArgs(["-target=aws_db_instance.staging", "-replace=aws_lb.staging"]), [
    "-replace=aws_lb.staging",
    "-target=aws_db_instance.staging",
  ]);
  assert.deepEqual(findForbiddenApplyArgs(["destroy"]), ["destroy"]);
});

test("destroy count blocks", () => {
  const fixture = writePlanFixture({ counts: { add: 38, change: 0, destroy: 1 } });
  try {
    const evaluated = evaluateSavedPlan({ planArg: fixture.planPath, env: baseEnv(), root: fixture.root });
    assert(evaluated.blockers.includes("destroy_count_not_zero"));
  } finally {
    fs.rmSync(fixture.root, { recursive: true, force: true });
  }
});

test("world-open ingress blocks", () => {
  const fixture = writePlanFixture({
    planText: [
      "# aws_vpc_security_group_ingress_rule.bad will be created",
      "+ resource \"aws_vpc_security_group_ingress_rule\" \"bad\" {",
      "  + cidr_ipv4 = \"0.0.0.0/0\"",
      "}",
    ].join("\n"),
  });
  try {
    const evaluated = evaluateSavedPlan({ planArg: fixture.planPath, env: baseEnv(), root: fixture.root });
    assert(evaluated.blockers.includes("world_open_ingress"));
  } finally {
    fs.rmSync(fixture.root, { recursive: true, force: true });
  }
});

test("secret URL patterns block", () => {
  const fixture = writePlanFixture({ planText: "postgresql://user:pass@staging-db.internal/mscqr\n" });
  try {
    const evaluated = evaluateSavedPlan({ planArg: fixture.planPath, env: baseEnv(), root: fixture.root });
    assert(evaluated.blockers.includes("secret_url_pattern_in_plan_text"));
  } finally {
    fs.rmSync(fixture.root, { recursive: true, force: true });
  }
});

test("production-looking plan text blocks", () => {
  const fixture = writePlanFixture({ planText: "name = \"mscqr-production-db\"\n" });
  try {
    const evaluated = evaluateSavedPlan({ planArg: fixture.planPath, env: baseEnv(), root: fixture.root });
    assert(evaluated.blockers.includes("production_looking_pattern_in_plan_text"));
  } finally {
    fs.rmSync(fixture.root, { recursive: true, force: true });
  }
});

test("summary must come from blocked plan-only evidence", () => {
  const fixture = writePlanFixture({ summary: { applyAllowed: true } });
  try {
    const evaluated = evaluateSavedPlan({ planArg: fixture.planPath, env: baseEnv(), root: fixture.root });
    assert(evaluated.blockers.includes("summary_apply_allowed_not_false"));
  } finally {
    fs.rmSync(fixture.root, { recursive: true, force: true });
  }
});

test("dry-run/default mode does not mutate before gates", () => {
  const fixture = writePlanFixture();
  const deps = fakeDeps();
  try {
    const result = runApplyWorkflow({
      argv: [fixture.planPath],
      env: { AWS_PROFILE: "mscqr-staging-apply", AWS_REGION: "eu-west-2" },
      deps,
    });

    assert.equal(result.exitCode, 1);
    assert.equal(result.payload.applyAttempted, false);
    assert.deepEqual(deps.calls, []);
  } finally {
    fs.rmSync(fixture.root, { recursive: true, force: true });
  }
});
