import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  assertStageBTerraformBackendConfig,
  assertStageBTerraformBackendManifest,
  assertStageBTerraformBackendPolicy,
  STAGE_B_TERRAFORM_BACKEND,
  STAGE_B_TERRAFORM_BACKEND_CONFIG,
  STAGE_B_TERRAFORM_BACKEND_MANIFEST,
  STAGE_B_TERRAFORM_BACKEND_POLICY,
} from "../aws/stage-b-terraform-backend-contract.mjs";
import { generateStageBTerraformBackendConfig } from "../aws/generate-production-green-stage-b-backend-config.mjs";
import { validateManifest } from "../aws/validate-production-green-stage-b-permissions.mjs";

const policy = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionGreenStageBWorkspaceState-v2.json", "utf8"));
const manifest = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionGreenStageBPermissionManifest-v1.json", "utf8"));
const stageA = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionGreenStageAReleaseS3Contract-v1.json", "utf8"));

function matches(statement, action, resource, context) {
  const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
  const resources = Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource];
  if (!actions.includes(action) || !resources.includes(resource)) return false;
  const expected = statement.Condition?.StringEquals?.["s3:prefix"];
  return expected === undefined || context.prefix === expected;
}

function decision(policies, action, resource, context = {}) {
  const statements = policies.flatMap((document) => document.Statement);
  if (statements.some((statement) => statement.Effect === "Deny" && matches(statement, action, resource, context))) return "explicitDeny";
  return statements.some((statement) => statement.Effect === "Allow" && matches(statement, action, resource, context)) ? "allowed" : "implicitDeny";
}

const { bucketArn, stateArn, lockArn, legacyWorkspaceArn, legacyWorkspaceLockArn } = STAGE_B_TERRAFORM_BACKEND;

test("the canonical backend policy and manifest are exact and complete", () => {
  assert.equal(assertStageBTerraformBackendPolicy(policy), true);
  assert.equal(assertStageBTerraformBackendManifest(manifest), true);
  assert.equal(validateManifest(manifest), true);
  assert.deepEqual(manifest.backendContract, STAGE_B_TERRAFORM_BACKEND_MANIFEST);
  assert.deepEqual(policy, STAGE_B_TERRAFORM_BACKEND_POLICY);
});

test("the direct production-state config uses the default CLI workspace", () => {
  assert.equal(assertStageBTerraformBackendConfig(STAGE_B_TERRAFORM_BACKEND_CONFIG), true);
  assert.equal(STAGE_B_TERRAFORM_BACKEND.workspaceName, "default");
  assert.equal(STAGE_B_TERRAFORM_BACKEND_CONFIG.key, STAGE_B_TERRAFORM_BACKEND.stateKey);
  assert.match(STAGE_B_TERRAFORM_BACKEND_CONFIG.key, /^env:\/production\//);
  assert.throws(() => assertStageBTerraformBackendConfig({ ...STAGE_B_TERRAFORM_BACKEND_CONFIG, key: "other.tfstate" }), /backend key/);
});

test("the canonical backend-config generator writes only the direct production key", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-backend-"));
  const outputPath = path.join(directory, "production.tfbackend");
  const result = generateStageBTerraformBackendConfig({ outputPath });
  assert.equal(fs.statSync(outputPath).mode & 0o777, 0o600);
  assert.match(fs.readFileSync(outputPath, "utf8"), /env:\/production\/mscqr\/production\/rls-green\/stage-b\/terraform\.tfstate/);
  assert.equal(result.outputPath, outputPath);
  assert.throws(() => generateStageBTerraformBackendConfig({ outputPath }), /new absolute private output path/);
  fs.rmSync(directory, { recursive: true, force: true });
});

test("Terraform's exact direct backend operation set is allowed", () => {
  for (const [action, resource, context] of [
    ["s3:GetBucketLocation", bucketArn, {}],
    ["s3:GetObject", stateArn, {}],
    ["s3:PutObject", stateArn, {}],
    ["s3:GetObject", lockArn, {}],
    ["s3:PutObject", lockArn, {}],
    ["s3:DeleteObject", lockArn, {}],
  ]) assert.equal(decision([policy], action, resource, context), "allowed", `${action} ${resource}`);
});

test("workspace listing and HeadBucket-style access are not required", () => {
  assert.equal(decision([policy], "s3:ListBucket", bucketArn), "implicitDeny");
  assert.equal(decision([policy], "s3:ListBucket", bucketArn, { prefix: "env:/production/" }), "implicitDeny");
  assert.equal(decision([policy], "s3:ListBucket", bucketArn, { prefix: "unrelated/" }), "implicitDeny");
  assert.equal(STAGE_B_TERRAFORM_BACKEND.headBucketRequired, false);
});

test("state deletion and legacy workspace access fail closed even with overlapping stale allows", () => {
  const staleStageB = {
    Version: "2012-10-17",
    Statement: [
      { Effect: "Allow", Action: ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"], Resource: [stateArn, lockArn, legacyWorkspaceArn, legacyWorkspaceLockArn] },
    ],
  };
  assert.equal(decision([policy, staleStageB], "s3:DeleteObject", stateArn), "explicitDeny");
  for (const action of ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]) {
    assert.equal(decision([policy, staleStageB], action, legacyWorkspaceArn), "explicitDeny");
    assert.equal(decision([policy, staleStageB], action, legacyWorkspaceLockArn), "explicitDeny");
  }
});

test("unrelated keys, buckets, and backend administration actions are denied", () => {
  for (const [action, resource] of [
    ["s3:GetObject", `${bucketArn}/env:/production/other/terraform.tfstate`],
    ["s3:GetObject", `${bucketArn}/env:/production/mscqr/production/rls-green/stage-b/other.tfstate`],
    ["s3:GetObject", "arn:aws:s3:::unrelated-bucket/state.tfstate"],
    ["s3:PutObject", `${bucketArn}/env:/production/other/terraform.tfstate`],
    ["s3:DeleteObject", `${bucketArn}/env:/production/other/terraform.tfstate.tflock`],
    ["s3:PutBucketPolicy", bucketArn],
    ["s3:DeleteBucket", bucketArn],
    ["s3:PutBucketVersioning", bucketArn],
    ["s3:PutEncryptionConfiguration", bucketArn],
    ["s3:GetObject", "*"],
  ]) assert.notEqual(decision([policy], action, resource), "allowed", `${action} ${resource}`);
  assert.equal(policy.Statement.some((statement) => statement.Effect === "Allow" && statement.Action === "s3:ListBucket" && !statement.Condition), false);
});

test("the stale Stage A inline contract contains no Stage B access", () => {
  const serialized = JSON.stringify(stageA);
  assert.equal(serialized.includes("rls-green/stage-b"), false);
  assert.equal(stageA.Statement.some((statement) => statement.Sid.startsWith("StageB")), false);
});
