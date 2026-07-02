import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

import {
  evaluateStagingAwsIdentity,
  parseAwsArn,
} from "../check-staging-aws-identity.mjs";
import {
  checkPlanEnvGates,
  collectPrivateInputState,
  findTerraformCliArgEnvKeys,
  findForbiddenPlanArgs,
} from "../plan-staging-terraform.mjs";

const repoRoot = path.resolve(new URL("../..", import.meta.url).pathname);

test("identity guard classifies assumed staging terraform role as allowed", () => {
  const result = evaluateStagingAwsIdentity({
    env: { AWS_REGION: "eu-west-2" },
    identity: {
      Account: "368992683803",
      Arn: "arn:aws:sts::368992683803:assumed-role/mscqr-staging-terraform-provisioner/session",
    },
  });

  assert.equal(result.allowed, true);
  assert.equal(result.arnType, "assumed-role");
  assert.equal(result.classification, "staging-provisioning-role");
});

test("identity guard refuses root identity", () => {
  const result = evaluateStagingAwsIdentity({
    env: { AWS_REGION: "eu-west-2" },
    identity: {
      Account: "368992683803",
      Arn: "arn:aws:iam::368992683803:root",
    },
  });

  assert.equal(result.allowed, false);
  assert.equal(result.classification, "root");
});

test("identity guard refuses production-looking role", () => {
  const result = evaluateStagingAwsIdentity({
    env: { AWS_REGION: "eu-west-2" },
    identity: {
      Account: "368992683803",
      Arn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-terraform-provisioner/session",
    },
  });

  assert.equal(result.allowed, false);
  assert.equal(result.classification, "production-looking-role");
});

test("parseAwsArn does not expose caller ARN in classification output", () => {
  assert.deepEqual(
    parseAwsArn("arn:aws:sts::368992683803:assumed-role/mscqr-stg-provision/session"),
    {
      arnType: "assumed-role",
      identityName: "mscqr-stg-provision",
      accountFromArn: "368992683803",
    },
  );
});

test("plan wrapper refuses missing confirmation gates before identity or terraform", () => {
  const result = spawnSync(process.execPath, ["scripts/plan-staging-terraform.mjs"], {
    cwd: repoRoot,
    env: { PATH: process.env.PATH },
    encoding: "utf8",
  });

  assert.notEqual(result.status, 0);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.status, "blocked_before_plan");
  assert.equal(parsed.reason, "Missing explicit staging Terraform plan confirmation.");
});

test("plan env gate helper reports both required confirmations", () => {
  assert.deepEqual(checkPlanEnvGates({}), [
    "MSCQR_STAGING_TERRAFORM_PLAN_ENABLED must be true.",
    "MSCQR_STAGING_TERRAFORM_PLAN_CONFIRM must be MSCQR_GENERATE_STAGING_PLAN_ONLY.",
  ]);
});

test("terraform CLI argument environment variables are refused by key without values", () => {
  assert.deepEqual(findTerraformCliArgEnvKeys({
    TF_CLI_ARGS: "-destroy",
    TF_CLI_ARGS_plan: "-var-file=/private/unapproved.tfvars",
    TF_VAR_account_id: "368992683803",
  }), ["TF_CLI_ARGS", "TF_CLI_ARGS_plan"]);
});

test("plan wrapper refuses TF_CLI_ARGS before private input or terraform", () => {
  const result = spawnSync(process.execPath, ["scripts/plan-staging-terraform.mjs"], {
    cwd: repoRoot,
    env: {
      PATH: process.env.PATH,
      MSCQR_STAGING_TERRAFORM_PLAN_ENABLED: "true",
      MSCQR_STAGING_TERRAFORM_PLAN_CONFIRM: "MSCQR_GENERATE_STAGING_PLAN_ONLY",
      TF_CLI_ARGS_plan: "-destroy -var-file=/private/unapproved.tfvars",
    },
    encoding: "utf8",
  });

  assert.notEqual(result.status, 0);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.status, "blocked_before_plan");
  assert.equal(parsed.reason, "TF_CLI_ARGS* environment variables are forbidden for this wrapper.");
  assert.deepEqual(parsed.terraformCliArgEnvKeys, ["TF_CLI_ARGS_plan"]);
  assert(!result.stdout.includes("-destroy"));
  assert(!result.stdout.includes("/private/unapproved.tfvars"));
});

test("forbidden terraform arguments are refused", () => {
  assert.deepEqual(findForbiddenPlanArgs(["state", "rm"]), ["state rm"]);
  assert.deepEqual(findForbiddenPlanArgs(["-target=aws_iam_role.apply_role"]), ["-target=aws_iam_role.apply_role"]);
  assert.deepEqual(findForbiddenPlanArgs(["destroy"]), ["destroy"]);
});

test(".terraform-plans is gitignored", () => {
  const ignore = fs.readFileSync(path.join(repoRoot, ".gitignore"), "utf8");
  assert.match(ignore, /^\.terraform-plans\/$/m);
  assert.match(ignore, /^infra\/terraform\/staging-api\/staging\.auto\.tfvars$/m);
  assert.match(ignore, /^infra\/terraform\/staging-api\/\*\.local\.tfvars$/m);
});

test("private input state reports missing variables without live AWS", () => {
  const tempRoot = fs.mkdtempSync(path.join(process.env.TMPDIR || "/tmp", "mscqr-plan-test-"));
  try {
    const tfRoot = path.join(tempRoot, "infra/terraform/staging-api");
    fs.mkdirSync(tfRoot, { recursive: true });
    fs.writeFileSync(path.join(tfRoot, "staging.auto.tfvars"), "account_id = \"368992683803\"\n", "utf8");

    const result = collectPrivateInputState({ root: tempRoot, env: {} });
    assert.deepEqual(result.allowedTfvars, ["infra/terraform/staging-api/staging.auto.tfvars"]);
    assert(result.missingRequiredVariables.includes("vpc_id"));
    assert.equal(result.refusedTfvars.length, 0);
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});
