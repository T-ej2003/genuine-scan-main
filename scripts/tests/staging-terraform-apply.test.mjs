import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
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

function runIamPolicyCheckWithBoundaryResource(resource) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-boundary-test-"));
  const boundarySourcePath = path.join(
    process.cwd(),
    "documents/ops/iam/MSCQR_STAGING_TERRAFORM_APPLY_PERMISSIONS_BOUNDARY_2026-07-08.json",
  );
  const boundary = JSON.parse(fs.readFileSync(boundarySourcePath, "utf8"));
  boundary.Statement.push({
    Sid: "DenyInvalidFixtureResource",
    Effect: "Deny",
    Action: "*",
    Resource: resource,
  });

  const fixturePath = path.join(root, "boundary.json");
  fs.writeFileSync(fixturePath, JSON.stringify(boundary, null, 2), "utf8");

  const result = spawnSync("node", ["scripts/check-staging-iam-policies.mjs"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      MSCQR_STAGING_IAM_APPLY_BOUNDARY_PATH: fixturePath,
    },
    encoding: "utf8",
  });

  fs.rmSync(root, { recursive: true, force: true });
  return result;
}

function runIamPolicyCheckWithFixtures({ applyRolePolicyMutator, boundaryMutator } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-iam-policy-test-"));
  const applyRolePolicyPath = path.join(
    process.cwd(),
    "documents/ops/iam/MSCQR_STAGING_TERRAFORM_APPLY_ROLE_POLICY_2026-07-08.json",
  );
  const boundaryPath = path.join(
    process.cwd(),
    "documents/ops/iam/MSCQR_STAGING_TERRAFORM_APPLY_PERMISSIONS_BOUNDARY_2026-07-08.json",
  );
  const applyRolePolicy = JSON.parse(fs.readFileSync(applyRolePolicyPath, "utf8"));
  const boundary = JSON.parse(fs.readFileSync(boundaryPath, "utf8"));
  if (applyRolePolicyMutator) applyRolePolicyMutator(applyRolePolicy);
  if (boundaryMutator) boundaryMutator(boundary);

  const fixtureApplyRolePolicyPath = path.join(root, "apply-role-policy.json");
  const fixtureBoundaryPath = path.join(root, "boundary.json");
  fs.writeFileSync(fixtureApplyRolePolicyPath, JSON.stringify(applyRolePolicy, null, 2), "utf8");
  fs.writeFileSync(fixtureBoundaryPath, JSON.stringify(boundary, null, 2), "utf8");

  const result = spawnSync("node", ["scripts/check-staging-iam-policies.mjs"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      MSCQR_STAGING_IAM_APPLY_ROLE_POLICY_PATH: fixtureApplyRolePolicyPath,
      MSCQR_STAGING_IAM_APPLY_BOUNDARY_PATH: fixtureBoundaryPath,
    },
    encoding: "utf8",
  });

  fs.rmSync(root, { recursive: true, force: true });
  return result;
}

function combinedOutput(result) {
  return `${result.stdout}\n${result.stderr}`;
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

test("apply identity guard allows stg abbreviation role marker", () => {
  const result = evaluateStagingAwsApplyIdentity({
    env: { AWS_REGION: "eu-west-2" },
    identity: {
      Account: "368992683803",
      Arn: "arn:aws:sts::368992683803:assumed-role/mscqr-stg-terraform-apply-role/session",
    },
  });

  assert.equal(result.allowed, true);
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

test("iam user identity blocks", () => {
  const result = evaluateStagingAwsApplyIdentity({
    env: { AWS_REGION: "eu-west-2" },
    identity: {
      Account: "368992683803",
      Arn: "arn:aws:iam::368992683803:user/mscqr-staging-apply-operator",
    },
  });

  assert.equal(result.allowed, false);
  assert.equal(result.classification, "user");
});

test("wrong account blocks", () => {
  const result = evaluateStagingAwsApplyIdentity({
    env: { AWS_REGION: "eu-west-2" },
    identity: {
      Account: "111111111111",
      Arn: "arn:aws:sts::111111111111:assumed-role/mscqr-staging-terraform-apply-role/session",
    },
  });

  assert.equal(result.allowed, false);
  assert.equal(result.classification, "wrong-account");
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

test("production-looking role blocks", () => {
  const result = evaluateStagingAwsApplyIdentity({
    env: { AWS_REGION: "eu-west-2" },
    identity: {
      Account: "368992683803",
      Arn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-terraform-apply-role/session",
    },
  });

  assert.equal(result.allowed, false);
  assert.equal(result.classification, "production-looking-role");
});

test("staging IAM policy lint rejects boundary Resource ARN service wildcard patterns", async (t) => {
  const invalidResources = [
    "arn:aws:*:*:368992683803:*prod*",
    "arn:aws:*:*:368992683803:*production*",
  ];

  for (const resource of invalidResources) {
    await t.test(resource, () => {
      const result = runIamPolicyCheckWithBoundaryResource(resource);
      const combinedOutput = `${result.stdout}\n${result.stderr}`;

      assert.notEqual(result.status, 0);
      assert.match(combinedOutput, /Resource ARN service segment must be fully qualified/);
      assert.match(combinedOutput, new RegExp(resource.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    });
  }
});

test("staging Terraform apply role policy is scoped to reviewed staging ECS roles", () => {
  const result = runIamPolicyCheckWithFixtures();

  assert.equal(result.status, 0, combinedOutput(result));
  assert.match(combinedOutput(result), /Apply role policy is scoped to Terraform-managed staging ECS IAM roles only/);
});

test("staging Terraform apply role policy rejects production-looking IAM role ARNs", () => {
  const result = runIamPolicyCheckWithFixtures({
    applyRolePolicyMutator: (policy) => {
      policy.Statement[0].Resource = [
        "arn:aws:iam::368992683803:role/mscqr-production-ecs-task-role",
      ];
    },
  });

  assert.notEqual(result.status, 0);
  assert.match(combinedOutput(result), /production|prod/i);
});

test("staging Terraform apply role policy rejects AdministratorAccess", () => {
  const result = runIamPolicyCheckWithFixtures({
    applyRolePolicyMutator: (policy) => {
      policy.Statement[2].Condition.StringEquals["iam:PolicyARN"] =
        "arn:aws:iam::aws:policy/AdministratorAccess";
    },
  });

  assert.notEqual(result.status, 0);
  assert.match(combinedOutput(result), /AdministratorAccess is forbidden/);
});

test("staging Terraform apply role policy rejects managed policy attachment to task role", () => {
  const result = runIamPolicyCheckWithFixtures({
    applyRolePolicyMutator: (policy) => {
      policy.Statement[2].Resource = "arn:aws:iam::368992683803:role/mscqr-staging-ecs-task-role";
    },
  });

  assert.notEqual(result.status, 0);
  assert.match(combinedOutput(result), /managed policy attach\/detach must target only/);
});

test("staging Terraform apply role policy rejects global IAM write resources", () => {
  const result = runIamPolicyCheckWithFixtures({
    applyRolePolicyMutator: (policy) => {
      policy.Statement[1].Resource = "*";
    },
  });

  assert.notEqual(result.status, 0);
  assert.match(combinedOutput(result), /Resource "\*" is forbidden/);
});

test("staging Terraform apply boundary does not deny required staging IAM role policy actions", () => {
  const result = runIamPolicyCheckWithFixtures();

  assert.equal(result.status, 0, combinedOutput(result));
});

test("staging Terraform apply boundary rejects denies on required staging IAM role actions", () => {
  const result = runIamPolicyCheckWithFixtures({
    boundaryMutator: (boundary) => {
      boundary.Statement.push({
        Sid: "DenyRequiredStagingInlinePolicyFixture",
        Effect: "Deny",
        Action: "iam:PutRolePolicy",
        Resource: "arn:aws:iam::368992683803:role/mscqr-staging-ecs-task-role",
      });
    },
  });

  assert.notEqual(result.status, 0);
  assert.match(combinedOutput(result), /must not deny required staging Terraform IAM action/);
});

test("staging Terraform apply boundary requires task role managed policy attachment deny", () => {
  const result = runIamPolicyCheckWithFixtures({
    boundaryMutator: (boundary) => {
      boundary.Statement = boundary.Statement.filter(
        (statement) => statement.Sid !== "DenyManagedPolicyAttachmentsOnStagingTaskRole",
      );
    },
  });

  assert.notEqual(result.status, 0);
  assert.match(combinedOutput(result), /must deny managed policy attachment to the staging ECS task role/);
});

test("role markers must be segment-aware", () => {
  const result = evaluateStagingAwsApplyIdentity({
    env: { AWS_REGION: "eu-west-2" },
    identity: {
      Account: "368992683803",
      Arn: "arn:aws:sts::368992683803:assumed-role/mscqr-notstg-terraform-apply-role/session",
    },
  });

  assert.equal(result.allowed, false);
  assert.equal(result.classification, "unmarked-apply-role");
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
  assert.deepEqual(validateApplyProfile({ AWS_PROFILE: "mscqr-stg-apply" }), []);
  assert(validateApplyProfile({ AWS_PROFILE: "mscqr-notstg-apply" }).includes("AWS_PROFILE must contain staging/stg."));
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

test("inline aws_security_group world-open ingress blocks", () => {
  const fixture = writePlanFixture({
    planText: [
      "# aws_security_group.bad will be created",
      "+ resource \"aws_security_group\" \"bad\" {",
      "  + ingress = [",
      "      + {",
      "          + cidr_blocks = [",
      "              + \"0.0.0.0/0\",",
      "            ]",
      "          + from_port   = 443",
      "          + to_port     = 443",
      "        },",
      "    ]",
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

test("inline aws_security_group world-open egress does not count as ingress", () => {
  const fixture = writePlanFixture({
    planText: [
      "# aws_security_group.ok will be created",
      "+ resource \"aws_security_group\" \"ok\" {",
      "  + egress = [",
      "      + {",
      "          + cidr_blocks = [",
      "              + \"0.0.0.0/0\",",
      "            ]",
      "        },",
      "    ]",
      "}",
    ].join("\n"),
  });
  try {
    const evaluated = evaluateSavedPlan({ planArg: fixture.planPath, env: baseEnv(), root: fixture.root });
    assert.equal(evaluated.textInspection.worldOpenIngressCount, 0);
    assert(!evaluated.blockers.includes("world_open_ingress"));
  } finally {
    fs.rmSync(fixture.root, { recursive: true, force: true });
  }
});

test("secret URL patterns block", () => {
  // Keep this marker URL-shaped but non-credentialed so repository fixture scans stay secret-safe.
  const fixture = writePlanFixture({ planText: "postgresql://<redacted-service-url>\n" });
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

test("apply requires exact saved plan under staging plan directory", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-apply-test-"));
  const planPath = path.join(root, "outside.tfplan");
  fs.writeFileSync(planPath, "terraform plan fixture", "utf8");
  try {
    const result = runApplyWorkflow({
      argv: [path.relative(root, planPath)],
      env: baseEnv(),
      deps: fakeDeps(),
    });

    assert.equal(result.exitCode, 1);
    assert.equal(result.payload.applyAttempted, false);
    assert.match(result.payload.reason, /Saved plan must live under \.terraform-plans\/staging/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("terraform apply failure writes redacted local evidence path", () => {
  const fixture = writePlanFixture();
  const writes = new Map();
  const rawArn = "arn:aws:iam::368992683803:role/mscqr-staging-ecs-task-role";
  const rawRedisUrl = "redis://staging-cache.internal:6379/0";
  const rawPassword = "stagingPasswordValue";
  const deps = fakeDeps({
    apply: () => {
      const error = new Error(`terraform apply failed for ${rawArn}; password = ${rawPassword}`);
      error.applyAttempted = true;
      error.terraformExitStatus = 1;
      error.stdout = `creating ${rawArn} for 368992683803\n`;
      error.stderr = `redis endpoint ${rawRedisUrl}\npassword = ${rawPassword}\n`;
      throw error;
    },
    writeFile: (filePath, content) => writes.set(filePath, content),
  });

  try {
    const result = runApplyWorkflow({
      argv: [fixture.planPath],
      env: baseEnv(),
      root: fixture.root,
      deps,
    });

    assert.equal(result.exitCode, 1);
    assert.equal(result.payload.status, "apply_failed");
    assert.equal(result.payload.applyAttempted, true);
    assert.equal(result.payload.mutatesAws, true);
    assert.equal(result.payload.rawSecretValuesPrinted, false);
    assert.match(result.payload.errorEvidencePath, /\.terraform-plans\/staging\/staging-plan\.apply-error-evidence\.json/);
    assert.equal(writes.size, 1);
    assert.match(result.payload.reason, /<redacted-arn>/);
    assert.match(result.payload.reason, /<redacted-secret-value>/);

    const evidence = [...writes.values()][0];
    assert.doesNotMatch(JSON.stringify(result.payload), /368992683803|arn:aws:|redis:\/\/staging-cache|stagingPasswordValue/);
    assert.doesNotMatch(evidence, /368992683803|arn:aws:|redis:\/\/staging-cache|stagingPasswordValue/);
    assert.match(evidence, /<redacted-account-id>/);
    assert.match(evidence, /<redacted-arn>/);
    assert.match(evidence, /<redacted-service-url>/);
    assert.match(evidence, /<redacted-secret-value>/);
  } finally {
    fs.rmSync(fixture.root, { recursive: true, force: true });
  }
});
