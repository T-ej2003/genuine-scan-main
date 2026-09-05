#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { execFileSync } from "node:child_process";
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";
import { canonicalJson } from "./production-green-stage-b-contract.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
export const INITIAL_ACTIVATION_RECONCILER = Object.freeze({
  roleName: "mscqr-production-initial-activation-policy-reconciler",
  roleArn: "arn:aws:iam::368992683803:role/mscqr-production-initial-activation-policy-reconciler",
  policyName: "MSCQRProductionInitialActivationPolicyReconciler",
  policyArn: "arn:aws:iam::368992683803:policy/MSCQRProductionInitialActivationPolicyReconciler",
  targetPolicyArn: "arn:aws:iam::368992683803:policy/MSCQRProductionInitialActivationLifecycle",
  releaseRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer",
  oidcProviderArn: "arn:aws:iam::368992683803:oidc-provider/token.actions.githubusercontent.com",
  trustPath: "infra/aws/terraform/production-initial-activation-policy-reconciler/trust-policy.json",
  permissionsPath: "infra/aws/terraform/production-initial-activation-policy-reconciler/permissions-policy.json",
  path: "/",
  roleDescription: "GitHub OIDC-only writer for the exact InitialActivationLifecycle policy reconciliation.",
  policyDescription: "Exact readback and CreatePolicyVersion capability for InitialActivationLifecycle reconciliation.",
  tags: Object.freeze({ ManagedBy: "Terraform", Environment: "production", Component: "initial-activation-policy-reconciliation", Stack: "production-initial-activation-policy-reconciler" }),
});

const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const readJson = (relativePath) => JSON.parse(fs.readFileSync(path.join(root, relativePath), "utf8"));
const readBytes = (relativePath) => fs.readFileSync(path.join(root, relativePath));
const decodeAwsDocument = (value, label) => normalizeIamPolicyDocument(value, label);
const exactJson = (actual, expected, label) => {
  if (canonicalJson(actual) !== canonicalJson(expected)) throw new Error(`${label} differs from the protected source contract.`);
};
const json = (run, args) => JSON.parse(run([...args, "--output", "json", "--no-cli-pager"]));

function assertTags(tags, label) {
  if (!Array.isArray(tags)) throw new Error(`${label} tags are malformed.`);
  const entries = tags.map((tag) => {
    if (!tag || typeof tag.Key !== "string" || typeof tag.Value !== "string" || Object.keys(tag).sort().join(",") !== "Key,Value") throw new Error(`${label} tags are malformed.`);
    return [tag.Key, tag.Value];
  });
  if (new Set(entries.map(([key]) => key)).size !== entries.length) throw new Error(`${label} tags are malformed.`);
  exactJson(Object.fromEntries(entries), INITIAL_ACTIVATION_RECONCILER.tags, `${label} tags`);
}

export function assertInitialActivationReconcilerRoleMetadata(role) {
  if (role?.Arn !== INITIAL_ACTIVATION_RECONCILER.roleArn || role?.RoleName !== INITIAL_ACTIVATION_RECONCILER.roleName || role?.Path !== INITIAL_ACTIVATION_RECONCILER.path || role?.Description !== INITIAL_ACTIVATION_RECONCILER.roleDescription || role?.MaxSessionDuration !== 3600) throw new Error("Initial-activation reconciler role source metadata is not exact.");
  if (Object.hasOwn(role, "PermissionsBoundary")) throw new Error("Initial-activation reconciler role must not have a permissions boundary.");
  exactJson(decodeAwsDocument(role.AssumeRolePolicyDocument, "reconciler trust policy"), readJson(INITIAL_ACTIVATION_RECONCILER.trustPath), "reconciler trust policy");
  assertTags(role.Tags, "Initial-activation reconciler role");
  return role;
}

export function assertInitialActivationReconcilerPolicyMetadata(policy, document) {
  if (policy?.Arn !== INITIAL_ACTIVATION_RECONCILER.policyArn || policy?.PolicyName !== INITIAL_ACTIVATION_RECONCILER.policyName || policy?.Path !== INITIAL_ACTIVATION_RECONCILER.path || policy?.Description !== INITIAL_ACTIVATION_RECONCILER.policyDescription || !/^v[1-9][0-9]*$/.test(policy?.DefaultVersionId || "")) throw new Error("Initial-activation reconciler managed-policy source metadata is not exact.");
  if (policy?.PermissionsBoundaryUsageCount !== 0) throw new Error("Initial-activation reconciler managed-policy permissions-boundary usage is not zero.");
  exactJson(decodeAwsDocument(document, "reconciler permissions policy"), readJson(INITIAL_ACTIVATION_RECONCILER.permissionsPath), "reconciler permissions policy");
  assertTags(policy.Tags, "Initial-activation reconciler managed policy");
  return policy;
}

export function readPolicyEntities(run) {
  const roles = [];
  const users = [];
  const groups = [];
  let marker;
  const seenMarkers = new Set();
  for (;;) {
    const response = json(run, ["iam", "list-entities-for-policy", "--policy-arn", INITIAL_ACTIVATION_RECONCILER.policyArn, "--no-paginate", ...(marker ? ["--marker", marker] : [])]);
    if (!Array.isArray(response.PolicyRoles) || !Array.isArray(response.PolicyUsers) || !Array.isArray(response.PolicyGroups) || typeof response.IsTruncated !== "boolean") throw new Error("Initial-activation reconciler policy entity response is malformed.");
    roles.push(...response.PolicyRoles);
    users.push(...response.PolicyUsers);
    groups.push(...response.PolicyGroups);
    if (!response.IsTruncated) break;
    if (typeof response.Marker !== "string" || !response.Marker || seenMarkers.has(response.Marker)) throw new Error("Initial-activation reconciler policy entity pagination is invalid.");
    seenMarkers.add(response.Marker);
    marker = response.Marker;
  }
  return { roles, users, groups };
}

export function verifyInitialActivationPolicyReconciler({ run, expectedCallerArn = "arn:aws:iam::368992683803:root" } = {}) {
  if (typeof run !== "function") throw new Error("An explicit AWS runner is required.");
  const identity = json(run, ["sts", "get-caller-identity"]);
  if (identity?.Arn !== expectedCallerArn) throw new Error("Initial-activation reconciler verification requires the authorized administrator identity.");
  const provider = json(run, ["iam", "get-open-id-connect-provider", "--open-id-connect-provider-arn", INITIAL_ACTIVATION_RECONCILER.oidcProviderArn]);
  if (provider?.Url !== "token.actions.githubusercontent.com" || !Array.isArray(provider.ClientIDList) || !provider.ClientIDList.some((clientId) => clientId === "sts.amazonaws.com")) throw new Error("GitHub Actions OIDC provider URL or audience is not exact.");
  const role = json(run, ["iam", "get-role", "--role-name", INITIAL_ACTIVATION_RECONCILER.roleName]).Role;
  assertInitialActivationReconcilerRoleMetadata(role);
  const policy = json(run, ["iam", "get-policy", "--policy-arn", INITIAL_ACTIVATION_RECONCILER.policyArn]).Policy;
  const version = json(run, ["iam", "get-policy-version", "--policy-arn", INITIAL_ACTIVATION_RECONCILER.policyArn, "--version-id", policy.DefaultVersionId]).PolicyVersion;
  assertInitialActivationReconcilerPolicyMetadata(policy, version?.Document);
  const attached = json(run, ["iam", "list-attached-role-policies", "--role-name", INITIAL_ACTIVATION_RECONCILER.roleName]).AttachedPolicies;
  if (!Array.isArray(attached) || attached.length !== 1 || attached[0].PolicyArn !== INITIAL_ACTIVATION_RECONCILER.policyArn) throw new Error("Initial-activation reconciler policy attachment topology is not exact.");
  const inline = json(run, ["iam", "list-role-policies", "--role-name", INITIAL_ACTIVATION_RECONCILER.roleName]).PolicyNames;
  if (!Array.isArray(inline) || inline.length !== 0) throw new Error("Initial-activation reconciler must not have inline policies.");
  const entities = readPolicyEntities(run);
  if (entities.roles.length !== 1 || entities.roles[0]?.RoleName !== INITIAL_ACTIVATION_RECONCILER.roleName || entities.users.length !== 0 || entities.groups.length !== 0) throw new Error("Initial-activation reconciler policy entity topology is not exact.");
  return Object.freeze({ roleArn: role.Arn, policyArn: policy.Arn, defaultVersionId: policy.DefaultVersionId, trustPolicySha256: sha256(readBytes(INITIAL_ACTIVATION_RECONCILER.trustPath)), permissionsPolicySha256: sha256(readBytes(INITIAL_ACTIVATION_RECONCILER.permissionsPath)), targetPolicyArn: INITIAL_ACTIVATION_RECONCILER.targetPolicyArn, releaseRoleArn: INITIAL_ACTIVATION_RECONCILER.releaseRoleArn, policyRoleCount: entities.roles.length, policyUserCount: entities.users.length, policyGroupCount: entities.groups.length, permissionsBoundaryUsageCount: policy.PermissionsBoundaryUsageCount, roleDefinedInSource: true, pr448RuntimeMigrated: false });
}

const required = (argv, name) => { const index = argv.indexOf(name); const value = index < 0 ? undefined : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };

export function runInitialActivationPolicyReconcilerVerification(argv = process.argv.slice(2), deps = {}) {
  const profile = required(argv, "--admin-profile");
  const run = deps.run || createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile });
  return verifyInitialActivationPolicyReconciler({ run });
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) process.stdout.write(`${JSON.stringify(runInitialActivationPolicyReconcilerVerification(), null, 2)}\n`);
