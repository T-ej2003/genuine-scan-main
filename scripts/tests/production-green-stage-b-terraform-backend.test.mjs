import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  assertStageBTerraformBackendConfig,
  assertStageBTerraformBackendMetadataPrivate,
  assertStageBTerraformInitializedBackendMetadata,
  assertStageBTerraformBackendManifest,
  assertStageBTerraformBackendPolicy,
  STAGE_B_TERRAFORM_BACKEND,
  STAGE_B_TERRAFORM_BACKEND_CONFIG,
  STAGE_B_TERRAFORM_BACKEND_MANIFEST,
  STAGE_B_TERRAFORM_BACKEND_POLICY,
  ensureStageBTerraformBackendMetadataPrivate,
} from "../aws/stage-b-terraform-backend-contract.mjs";
import { generateStageBTerraformBackendConfig } from "../aws/generate-production-green-stage-b-backend-config.mjs";
import { validateManifest } from "../aws/validate-production-green-stage-b-permissions.mjs";

const policy = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionGreenStageBWorkspaceState-v2.json", "utf8"));
const manifest = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionGreenStageBPermissionManifest-v1.json", "utf8"));
const stageA = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionGreenStageAReleaseS3Contract-v1.json", "utf8"));
const initializedMetadata = JSON.parse(fs.readFileSync("scripts/tests/fixtures/production-green-stage-b-s3-backend-metadata.json", "utf8"));
const asArray = (value) => Array.isArray(value) ? value : [value];

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
  assert.throws(() => assertStageBTerraformBackendConfig({ ...STAGE_B_TERRAFORM_BACKEND_CONFIG, profile: "other" }), /unreviewed key/);
});

test("Terraform v1.15.7 initialized metadata accepts only the canonical normalized S3 shape", () => {
  assert.equal(assertStageBTerraformInitializedBackendMetadata(initializedMetadata.backend), true);
});

test("initialized backend metadata rejects noncanonical type, keys, endpoints, credentials, and transport options", () => {
  const reject = (label, mutate, pattern) => {
    const metadata = structuredClone(initializedMetadata);
    mutate(metadata);
    assert.throws(() => assertStageBTerraformInitializedBackendMetadata(metadata.backend), pattern, label);
  };
  reject("backend type", ({ backend }) => { backend.type = "local"; }, /type/);
  reject("unknown metadata key", ({ backend }) => { backend.unreviewed = true; }, /unreviewed/);
  reject("unknown config key", ({ backend }) => { backend.config.unreviewed = true; }, /unreviewed/);
  for (const [key, value] of [
    ["endpoints", { s3: "https://other.example" }], ["endpoints", { sts: "https://other.example" }],
    ["profile", "other"], ["shared_credentials_file", "/tmp/creds"], ["shared_credentials_files", ["/tmp/creds"]], ["shared_config_files", ["/tmp/config"]], ["assume_role", { role_arn: "arn:aws:iam::1:role/other" }],
    ["assume_role_with_web_identity", { role_arn: "arn:aws:iam::1:role/other" }], ["access_key", "access"], ["secret_key", "secret"], ["token", "token"],
    ["custom_ca_bundle", "/tmp/ca"], ["insecure", true], ["http_proxy", "http://proxy"], ["https_proxy", "https://proxy"], ["no_proxy", "internal"], ["sts_region", "us-east-1"],
    ["use_path_style", true], ["workspace_key_prefix", "env:"], ["dynamodb_table", "locks"], ["kms_key_id", "alias/other"],
    ["skip_credentials_validation", true], ["skip_region_validation", true], ["skip_requesting_account_id", true], ["skip_metadata_api_check", true], ["skip_s3_checksum", true], ["max_retries", 10], ["retry_mode", "adaptive"],
  ]) reject(key, ({ backend }) => { backend.config[key] = value; }, new RegExp(key));
  reject("nested endpoint key", ({ backend }) => { backend.config.endpoints = { other: "https://other.example" }; }, /endpoints/);
  reject("legacy path-style alias", ({ backend }) => { backend.config.force_path_style = true; backend.config.use_path_style = true; }, /force_path_style/);
});

test("initialized backend metadata rejects canonical value overrides", () => {
  for (const [key, value] of [["bucket", "other"], ["key", "other.tfstate"], ["region", "us-east-1"], ["encrypt", false], ["use_lockfile", false]]) {
    const metadata = structuredClone(initializedMetadata);
    metadata.backend.config[key] = value;
    assert.throws(() => assertStageBTerraformInitializedBackendMetadata(metadata.backend), new RegExp(key));
  }
});

test("plan, closure, verify-only, and pre-apply consume initialized metadata rather than generated HCL", () => {
  const planSource = fs.readFileSync("scripts/plan-production-green-stage-b.mjs", "utf8");
  const closureSource = fs.readFileSync("scripts/aws/validate-stage-b-deployment-closure.mjs", "utf8");
  const applySource = fs.readFileSync("scripts/apply-production-green-stage-b.mjs", "utf8");
  assert.match(planSource, /assertStageBTerraformInitializedBackendMetadata/);
  assert.match(closureSource, /STAGE_B_TERRAFORM_BACKEND_METADATA_PATH/);
  assert.match(applySource, /assertStageBTerraformInitializedBackendMetadata/);
  assert.match(applySource, /getBackendMetadata/);
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

test("the backend producer normalizes Terraform metadata to 0600 and returns its binding", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-backend-data-"));
  const metadataPath = path.join(directory, "terraform.tfstate");
  fs.writeFileSync(metadataPath, JSON.stringify(initializedMetadata), { mode: 0o644 });
  fs.chmodSync(directory, 0o700); fs.chmodSync(metadataPath, 0o644);
  const result = ensureStageBTerraformBackendMetadataPrivate({ terraformDataDir: directory, backendMetadataPath: metadataPath, repositoryRoot: process.cwd(), normalize: true });
  assert.equal(result.backendMetadataMode, "0600");
  assert.equal(result.privateModeValidated, true);
  assert.equal(fs.statSync(metadataPath).mode & 0o777, 0o600);
  assert.equal(result.backendMetadataSha256.length, 64);
  fs.rmSync(directory, { recursive: true, force: true });
});

test("downstream validation rejects metadata made public after initialization", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-backend-data-"));
  const metadataPath = path.join(directory, "terraform.tfstate");
  fs.writeFileSync(metadataPath, JSON.stringify(initializedMetadata), { mode: 0o600 });
  fs.chmodSync(directory, 0o700); fs.chmodSync(metadataPath, 0o644);
  assert.throws(() => assertStageBTerraformBackendMetadataPrivate({ terraformDataDir: directory, backendMetadataPath: metadataPath, repositoryRoot: process.cwd() }), /mode 0600/);
  fs.rmSync(directory, { recursive: true, force: true });
});

test("metadata normalization fails closed when chmod fails", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-backend-data-"));
  const metadataPath = path.join(directory, "terraform.tfstate");
  fs.writeFileSync(metadataPath, JSON.stringify(initializedMetadata), { mode: 0o644 });
  fs.chmodSync(directory, 0o700); fs.chmodSync(metadataPath, 0o644);
  const fsOps = { ...fs, chmodSync: () => { throw new Error("chmod denied"); } };
  assert.throws(() => ensureStageBTerraformBackendMetadataPrivate({ terraformDataDir: directory, backendMetadataPath: metadataPath, repositoryRoot: process.cwd(), normalize: true, fsOps }), /chmod denied/);
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

test("the canonical Stage A managed contract is exact and recovery-scoped", () => {
  const serialized = JSON.stringify(stageA);
  assert.equal(serialized.includes("rls-green/stage-b"), false);
  assert.equal(stageA.Statement.some((statement) => statement.Sid.startsWith("StageB")), false);
  assert.deepEqual(stageA.Statement[0], {
    Sid: "ReadExactStageAStateForHandoff",
    Effect: "Allow",
    Action: "s3:GetObject",
    Resource: "arn:aws:s3:::mscqr-production-terraform-state-368992683803-eu-west-2/mscqr/production/rls-green/stage-a/terraform.tfstate",
  });
  assert.deepEqual(stageA.Statement.map(({ Sid }) => Sid), [
    "ReadExactStageAStateForHandoff",
    "ReadExactStageABackendBucketLocation",
    "WriteExactStageAState",
    "ReadExactStageALock",
    "WriteExactStageALock",
    "ReleaseExactStageALock",
    "ReadExactStageAProviderEndpointMetadata",
    "ReadExactStageAStorageKeys",
    "ReadExactStageAGreenRdsGroups",
    "ReadExactStageAGreenRdsParameters",
    "ReadExactStageAGreenRdsInstance",
    "ReadExactStageAKmsAliases",
    "ReadExactStageASecretMetadata",
    "ReadExactStageACheckerRole",
    "ReadExactStageACheckerRolePolicy",
    "ReadExactStageAProviderLogGroups",
    "ReadExactStageALogTags",
    "ApplyExactStageAEndpointSecurityGroupIngress",
  ]);
  const stageAStatement = (sid) => stageA.Statement.find((statement) => statement.Sid === sid);
  assert.equal(stageAStatement("ReadExactStageABackendBucketLocation").Action, "s3:GetBucketLocation");
  assert.equal(stageAStatement("ReadExactStageABackendBucketLocation").Resource, "arn:aws:s3:::mscqr-production-terraform-state-368992683803-eu-west-2");
  assert.deepEqual(stageAStatement("WriteExactStageAState").Action, "s3:PutObject");
  assert.match(stageAStatement("WriteExactStageAState").Resource, /stage-a\/terraform\.tfstate$/);
  assert.deepEqual(stageAStatement("ReadExactStageALock").Action, "s3:GetObject");
  assert.match(stageAStatement("ReadExactStageALock").Resource, /stage-a\/terraform\.tfstate\.tflock$/);
  assert.deepEqual(stageAStatement("WriteExactStageALock").Action, "s3:PutObject");
  assert.match(stageAStatement("WriteExactStageALock").Resource, /stage-a\/terraform\.tfstate\.tflock$/);
  assert.deepEqual(stageAStatement("ReleaseExactStageALock").Action, "s3:DeleteObject");
  assert.match(stageAStatement("ReleaseExactStageALock").Resource, /stage-a\/terraform\.tfstate\.tflock$/);
  assert.equal(stageA.Statement.some(({ Action }) => asArray(Action).includes("s3:ListBucket")), false);
  assert.equal(stageA.Statement.some(({ Action, Resource }) => asArray(Action).includes("s3:DeleteObject") && asArray(Resource).some((value) => value.endsWith("terraform.tfstate"))), false);
  const apply = stageA.Statement.at(-1);
  assert.equal(apply.Action, "ec2:AuthorizeSecurityGroupIngress");
  assert.equal(apply.Resource, "arn:aws:ec2:eu-west-2:368992683803:security-group/sg-04d5bf116755ba412");
  assert.deepEqual(apply.Condition, { StringEquals: { "aws:RequestedRegion": "eu-west-2" } });
});
