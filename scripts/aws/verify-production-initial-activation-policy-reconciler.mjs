#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { execFileSync } from "node:child_process";
import { createProductionAwsCommandRunner, PRODUCTION_AWS_CREDENTIAL_SOURCE } from "./production-credential-source-contract.mjs";
import { normalizeIamPolicyDocument } from "./iam-policy-document.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
export const INITIAL_ACTIVATION_RECONCILER = Object.freeze({
  roleName: "mscqr-production-initial-activation-policy-reconciler",
  roleArn: "arn:aws:iam::368992683803:role/mscqr-production-initial-activation-policy-reconciler",
  policyName: "MSCQRProductionInitialActivationPolicyReconciler",
  policyArn: "arn:aws:iam::368992683803:policy/MSCQRProductionInitialActivationPolicyReconciler",
  targetPolicyArn: "arn:aws:iam::368992683803:policy/MSCQRProductionInitialActivationLifecycle",
  releaseRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer",
  trustPath: "infra/aws/terraform/production-initial-activation-policy-reconciler/trust-policy.json",
  permissionsPath: "infra/aws/terraform/production-initial-activation-policy-reconciler/permissions-policy.json",
});

const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const readJson = (relativePath) => JSON.parse(fs.readFileSync(path.join(root, relativePath), "utf8"));
const decodeAwsDocument = (value, label) => normalizeIamPolicyDocument(value, label);
const exactJson = (actual, expected, label) => {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error(`${label} differs from the protected source contract.`);
};
const json = (run, args) => JSON.parse(run(args));

function readPolicyEntities(run) {
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
  const trust = readJson(INITIAL_ACTIVATION_RECONCILER.trustPath);
  const permissions = readJson(INITIAL_ACTIVATION_RECONCILER.permissionsPath);
  const identity = json(run, ["sts", "get-caller-identity"]);
  if (identity?.Arn !== expectedCallerArn) throw new Error("Initial-activation reconciler verification requires the authorized administrator identity.");
  const role = json(run, ["iam", "get-role", "--role-name", INITIAL_ACTIVATION_RECONCILER.roleName]).Role;
  if (role?.Arn !== INITIAL_ACTIVATION_RECONCILER.roleArn) throw new Error("Initial-activation reconciler role ARN is not exact.");
  if (Object.hasOwn(role, "PermissionsBoundary")) throw new Error("Initial-activation reconciler role must not have a permissions boundary.");
  exactJson(decodeAwsDocument(role.AssumeRolePolicyDocument, "reconciler trust policy"), trust, "reconciler trust policy");
  const policy = json(run, ["iam", "get-policy", "--policy-arn", INITIAL_ACTIVATION_RECONCILER.policyArn]).Policy;
  if (policy?.Arn !== INITIAL_ACTIVATION_RECONCILER.policyArn || policy?.PolicyName !== INITIAL_ACTIVATION_RECONCILER.policyName || !/^v[1-9][0-9]*$/.test(policy.DefaultVersionId || "") || policy.PermissionsBoundaryUsageCount !== 0) throw new Error("Initial-activation reconciler managed-policy identity or permissions-boundary usage is not exact.");
  const version = json(run, ["iam", "get-policy-version", "--policy-arn", INITIAL_ACTIVATION_RECONCILER.policyArn, "--version-id", policy.DefaultVersionId]).PolicyVersion;
  exactJson(decodeAwsDocument(version?.Document, "reconciler permissions policy"), permissions, "reconciler permissions policy");
  const attached = json(run, ["iam", "list-attached-role-policies", "--role-name", INITIAL_ACTIVATION_RECONCILER.roleName]).AttachedPolicies;
  if (!Array.isArray(attached) || attached.length !== 1 || attached[0].PolicyArn !== INITIAL_ACTIVATION_RECONCILER.policyArn) throw new Error("Initial-activation reconciler policy attachment topology is not exact.");
  const inline = json(run, ["iam", "list-role-policies", "--role-name", INITIAL_ACTIVATION_RECONCILER.roleName]).PolicyNames;
  if (!Array.isArray(inline) || inline.length !== 0) throw new Error("Initial-activation reconciler must not have inline policies.");
  const entities = readPolicyEntities(run);
  if (entities.roles.length !== 1 || entities.roles[0]?.RoleName !== INITIAL_ACTIVATION_RECONCILER.roleName || entities.users.length !== 0 || entities.groups.length !== 0) throw new Error("Initial-activation reconciler policy entity topology is not exact.");
  return Object.freeze({ roleArn: role.Arn, policyArn: policy.Arn, defaultVersionId: policy.DefaultVersionId, trustPolicySha256: sha256(Buffer.from(JSON.stringify(trust))), permissionsPolicySha256: sha256(Buffer.from(JSON.stringify(permissions))), targetPolicyArn: INITIAL_ACTIVATION_RECONCILER.targetPolicyArn, releaseRoleArn: INITIAL_ACTIVATION_RECONCILER.releaseRoleArn, policyRoleCount: entities.roles.length, policyUserCount: entities.users.length, policyGroupCount: entities.groups.length, permissionsBoundaryUsageCount: policy.PermissionsBoundaryUsageCount, roleDefinedInSource: true, pr448RuntimeMigrated: false });
}

const required = (argv, name) => { const index = argv.indexOf(name); const value = index < 0 ? undefined : argv[index + 1]; if (!value || value.startsWith("--")) throw new Error(`${name} is required.`); return value; };

export function runInitialActivationPolicyReconcilerVerification(argv = process.argv.slice(2), deps = {}) {
  const profile = required(argv, "--admin-profile");
  const run = deps.run || createProductionAwsCommandRunner({ credentialSource: PRODUCTION_AWS_CREDENTIAL_SOURCE.NAMED_PROFILE, profile });
  return verifyInitialActivationPolicyReconciler({ run });
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) process.stdout.write(`${JSON.stringify(runInitialActivationPolicyReconcilerVerification(), null, 2)}\n`);
