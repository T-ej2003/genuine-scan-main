import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";

const directory = fileURLToPath(new URL("../../infra/aws/terraform/production-component-deployment-state/", import.meta.url));
export const canonical = (value) => JSON.stringify(order(value));
function order(value) {
  if (Array.isArray(value)) return value.map(order);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((key) => [key, order(value[key])]));
  return value;
}
export const digest = (value) => crypto.createHash("sha256").update(canonical(value)).digest("hex");
const document = (name) => JSON.parse(fs.readFileSync(`${directory}${name}.json`, "utf8"));
const account = "368992683803";
const roleArn = (name) => `arn:aws:iam::${account}:role/${name}`;
export const installationIdentity = Object.freeze({
  account, region: "eu-west-2", repository: "T-ej2003/genuine-scan-main",
  provisionerRole: "mscqr-production-component-iam-provisioner",
  terraformRole: "mscqr-production-component-table-installer",
  functionName: "mscqr-production-component-iam-installer",
  authorizationEnvironment: "production-component-infrastructure-install-permission",
  reviewer: Object.freeze({ login: "T-ej2003", id: 183396573 }),
});

// This inventory is source-owned. No caller chooses a target, document or path.
export function installationDocuments() {
  assert.equal(arguments.length, 0, "Document overrides are forbidden");
  return [
    { role: "mscqr-production-normal-deployer", policyName: "MSCQRProductionNormalDeployment", trust: document("normal-deployer-trust-policy"), policy: document("normal-deployer-policy") },
    { role: "mscqr-production-component-state-bootstrap", policyName: "MSCQRProductionComponentStateBootstrap", trust: document("bootstrap-trust-policy"), policy: document("bootstrap-policy") },
    { role: "mscqr-production-release-deployer", policyName: "MSCQRProductionComponentStateTerminalWriter", policy: document("release-terminal-state-policy") },
  ].map((target) => ({ ...target, arn: roleArn(target.role), policySha256: digest(target.policy), ...(target.trust ? { trustSha256: digest(target.trust) } : {}) }));
}

export function terraformTargetPolicy() {
  const bucket = "arn:aws:s3:::mscqr-production-terraform-state-368992683803-eu-west-2";
  const key = "mscqr/production/component-deployment-state/terraform.tfstate";
  const state = `${bucket}/${key}`;
  return { Version: "2012-10-17", Statement: [
    // The fixed broker authenticates this role's MFA/expiry proof read-only.
    // Its IAM-write entry rejects a Terraform-role proof. No Lambda deployment,
    // configuration or authority modification is granted to this executor.
    { Effect: "Allow", Action: "lambda:InvokeFunction", Resource: `arn:aws:lambda:eu-west-2:${account}:function:${installationIdentity.functionName}:1`, Condition: { StringEquals: { "aws:RequestedRegion": "eu-west-2" } } },
    { Effect: "Allow", Action: "s3:GetBucketVersioning", Resource: bucket },
    { Effect: "Allow", Action: ["s3:ListBucket", "s3:ListBucketVersions"], Resource: bucket, Condition: { StringEquals: { "s3:prefix": key } } },
    { Effect: "Allow", Action: "s3:GetObject", Resource: [state, `${state}.tflock`, `${bucket}/mscqr/production/component-deployment-state/iam-installation.json`] },
    { Effect: "Allow", Action: "s3:PutObject", Resource: [state, `${state}.tflock`, `${state}.initial-activation-attempt`], Condition: { StringEquals: { "s3:x-amz-server-side-encryption": "AES256" } } },
    { Effect: "Allow", Action: "s3:DeleteObject", Resource: `${state}.tflock` },
    { Effect: "Allow", Action: ["dynamodb:DescribeTable", "dynamodb:DescribeContinuousBackups", "dynamodb:DescribeTimeToLive", "dynamodb:ListTagsOfResource", "dynamodb:CreateTable", "dynamodb:TagResource", "dynamodb:UpdateContinuousBackups"], Resource: `arn:aws:dynamodb:eu-west-2:${account}:table/mscqr-production-component-deployment-state`, Condition: { StringEquals: { "aws:RequestedRegion": "eu-west-2" } } },
    { Effect: "Allow", Action: ["iam:GetRole", "iam:GetRolePolicy"], Resource: installationDocuments().map(({ arn }) => arn) },
    { Effect: "Allow", Action: ["iam:ListRolePolicies", "iam:ListAttachedRolePolicies"], Resource: installationDocuments().filter(({ trust }) => trust).map(({ arn }) => arn) },
  ] };
}

export function terraformExecutorPolicyGeneration(version, recovery = false) {
  assert(["4", "7", "10"].includes(version) && recovery === (version === "7" || version === "10"), "Unsupported Terraform executor policy generation");
  const policy = terraformTargetPolicy();
  policy.Statement.find(({ Action }) => Action === "lambda:InvokeFunction").Resource = `arn:aws:lambda:eu-west-2:${account}:function:${installationIdentity.functionName}:${version}`;
  if (recovery) {
    const state = "arn:aws:s3:::mscqr-production-terraform-state-368992683803-eu-west-2/mscqr/production/component-deployment-state/terraform.tfstate";
    policy.Statement.splice(4, 0, { Effect: "Allow", Action: "s3:GetObjectVersion", Resource: [`${state}.tflock`, `${state}.initial-activation-attempt`] });
  }
  return policy;
}

export function installationCapabilitySet() {
  const provisioner = provisionerTargetPolicy();
  const receipt = "arn:aws:s3:::mscqr-production-terraform-state-368992683803-eu-west-2/mscqr/production/component-deployment-state/iam-installation.json";
  provisioner.Statement.push(
    { Effect: "Allow", Action: "s3:ListBucket", Resource: "arn:aws:s3:::mscqr-production-terraform-state-368992683803-eu-west-2", Condition: { StringEquals: { "s3:prefix": "mscqr/production/component-deployment-state/iam-installation.json" } } },
    { Effect: "Allow", Action: "s3:GetObject", Resource: receipt },
    { Effect: "Allow", Action: "s3:PutObject", Resource: receipt, Condition: { StringEquals: { "s3:x-amz-server-side-encryption": "AES256" } } },
  );
  return { identity: installationIdentity, provisioner, terraform: terraformTargetPolicy(),
    provisionerTrust: { Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { Service: "lambda.amazonaws.com" }, Action: "sts:AssumeRole" }] },
    terraformTrust: { Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: { AWS: `arn:aws:iam::${account}:user/mscqr-production-bootstrap-operator` }, Action: "sts:AssumeRole", Condition: { Bool: { "aws:MultiFactorAuthPresent": "true" } } }] },
  };
}

export function documentBindings() {
  return installationDocuments().map(({ arn, policyName, policySha256, trustSha256 }) => ({ arn, policyName, policySha256, ...(trustSha256 ? { trustSha256 } : {}) }));
}

export function classifyIamDocument(observed, expected) {
  if (observed === null) return "ABSENT";
  try { return canonical(normalizeIamPolicyDocument(observed)) === canonical(expected) ? "EXPECTED" : "DIFFERENT"; }
  catch { return "DIFFERENT"; }
}

// Capability is only for the isolated writer, never operator/Terraform credentials.
// Delivery, expiry, authorization and isolation must be authenticated separately.
export function provisionerTargetPolicy() {
  const targets = installationDocuments();
  assert(!targets.some(({ arn }) => arn === roleArn(installationIdentity.provisionerRole)));
  return {
    Version: "2012-10-17",
    Statement: [
      { Sid: "ReadExactInstallationTargets", Effect: "Allow", Action: ["iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies"], Resource: targets.map(({ arn }) => arn) },
      { Sid: "CreateOnlyTwoComponentRoles", Effect: "Allow", Action: ["iam:CreateRole", "iam:TagRole"], Resource: targets.filter(({ trust }) => trust).map(({ arn }) => arn) },
      { Sid: "WriteOnlyComponentTargetPolicies", Effect: "Allow", Action: "iam:PutRolePolicy", Resource: targets.map(({ arn }) => arn) },
    ],
  };
}
