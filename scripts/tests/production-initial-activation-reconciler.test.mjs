import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { INITIAL_ACTIVATION_RECONCILER, verifyInitialActivationPolicyReconciler } from "../aws/verify-production-initial-activation-policy-reconciler.mjs";

const root = "infra/aws/terraform/production-initial-activation-policy-reconciler";
const trust = JSON.parse(fs.readFileSync(`${root}/trust-policy.json`, "utf8"));
const policy = JSON.parse(fs.readFileSync(`${root}/permissions-policy.json`, "utf8"));
const terraform = fs.readFileSync(`${root}/main.tf`, "utf8");
const backend = JSON.parse(fs.readFileSync(`${root}/state-backend-contract.json`, "utf8"));
const installation = JSON.parse(fs.readFileSync(`${root}/installation-contract.json`, "utf8"));
const capability = JSON.parse(fs.readFileSync("documents/ops/iam/MSCQRProductionInitialActivationPolicyReconciler-capability-v1.json", "utf8"));
const encoded = (value) => encodeURIComponent(JSON.stringify(value));

const commands = ({ role = {}, policyMetadata = {}, version = policy, encodeRole = true, encodeVersion = true, attached = [{ PolicyArn: INITIAL_ACTIVATION_RECONCILER.policyArn }], inline = [], entities = [{ PolicyRoles: [{ RoleName: INITIAL_ACTIVATION_RECONCILER.roleName }], PolicyUsers: [], PolicyGroups: [], IsTruncated: false }] } = {}) => {
  const calls = [];
  const run = (args) => {
    calls.push(args);
    if (args[0] === "sts") return JSON.stringify({ Arn: "arn:aws:iam::368992683803:root" });
    if (args[0] === "iam" && args[1] === "get-role") return JSON.stringify({ Role: { Arn: INITIAL_ACTIVATION_RECONCILER.roleArn, MaxSessionDuration: 3600, AssumeRolePolicyDocument: encodeRole ? encoded(trust) : trust, ...role } });
    if (args[0] === "iam" && args[1] === "get-policy") return JSON.stringify({ Policy: { Arn: INITIAL_ACTIVATION_RECONCILER.policyArn, PolicyName: INITIAL_ACTIVATION_RECONCILER.policyName, DefaultVersionId: "v1", PermissionsBoundaryUsageCount: 0, ...policyMetadata } });
    if (args[0] === "iam" && args[1] === "get-policy-version") return JSON.stringify({ PolicyVersion: { Document: encodeVersion ? encoded(version) : version } });
    if (args[0] === "iam" && args[1] === "list-attached-role-policies") return JSON.stringify({ AttachedPolicies: attached });
    if (args[0] === "iam" && args[1] === "list-role-policies") return JSON.stringify({ PolicyNames: inline });
    if (args[0] === "iam" && args[1] === "list-entities-for-policy") {
      const page = entities[args.includes("--marker") ? 1 : 0];
      if (!page) throw new Error("unexpected entity page");
      return JSON.stringify(page);
    }
    throw new Error(`unexpected command: ${args.join(" ")}`);
  };
  return { run, calls };
};

test("trust is exactly production GitHub OIDC and excludes local principals", () => {
  assert.deepEqual(trust, {
    Version: "2012-10-17",
    Statement: [{
      Sid: "GitHubOidcProductionEnvironmentOnly",
      Effect: "Allow",
      Principal: { Federated: "arn:aws:iam::368992683803:oidc-provider/token.actions.githubusercontent.com" },
      Action: "sts:AssumeRoleWithWebIdentity",
      Condition: { StringEquals: { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com", "token.actions.githubusercontent.com:sub": "repo:T-ej2003/genuine-scan-main:environment:production" } },
    }],
  });
  assert.doesNotMatch(JSON.stringify(trust), /bootstrap|release-deployer|mfa|pull_request|refs\/heads/i);
});

test("runtime policy has exact target mutation and readback-only companion actions", () => {
  const actions = policy.Statement.flatMap(({ Action }) => Array.isArray(Action) ? Action : [Action]);
  const create = policy.Statement.find(({ Sid }) => Sid === "CreateExactInitialActivationLifecyclePolicyVersion");
  assert.deepEqual(create, { Sid: "CreateExactInitialActivationLifecyclePolicyVersion", Effect: "Allow", Action: "iam:CreatePolicyVersion", Resource: INITIAL_ACTIVATION_RECONCILER.targetPolicyArn });
  for (const action of ["iam:CreatePolicy", "iam:DeletePolicy", "iam:DeletePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:AttachRolePolicy", "iam:DetachRolePolicy", "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:UpdateAssumeRolePolicy", "iam:CreateRole", "iam:DeleteRole"]) assert.equal(actions.includes(action), false, action);
  assert.deepEqual(actions.sort(), ["iam:CreatePolicyVersion", "iam:GetPolicy", "iam:GetPolicyVersion", "iam:GetRole", "iam:ListAttachedRolePolicies", "iam:ListEntitiesForPolicy", "iam:ListPolicyVersions", "sts:GetCallerIdentity"].sort());
  assert.equal(policy.Statement.find(({ Sid }) => Sid === "ReadExactInitialActivationReleaseRole").Resource, INITIAL_ACTIVATION_RECONCILER.releaseRoleArn);
});

test("Terraform root owns only the purpose-bound role, policy, and attachment", () => {
  assert.match(terraform, /aws_iam_role" "reconciler/);
  assert.match(terraform, /aws_iam_policy" "reconciler/);
  assert.match(terraform, /aws_iam_role_policy_attachment" "reconciler/);
  for (const forbidden of ["release-deployer", "production-green-stage-a", "production-green-stage-b", "image-publisher", "aws_s3_", "aws_ecs_", "aws_rds_", "aws_secretsmanager_"]) assert.doesNotMatch(terraform, new RegExp(forbidden, "i"), forbidden);
  assert.equal(backend.roleArn, INITIAL_ACTIVATION_RECONCILER.roleArn);
  assert.equal(backend.productionExecutionEnabled, false);
  assert.equal(backend.rootApplyRequired, true);
  assert.equal(installation.administratorBoundary, "existing independently authorized mscqr-production-root administrator session");
  assert.deepEqual(installation.maxAwsMutations, { "iam:CreateRole": 1, "iam:CreatePolicy": 1, "iam:AttachRolePolicy": 1, "iam:UpdateAssumeRolePolicy": 0, "iam:PutRolePolicy": 0, "iam:CreatePolicyVersion": 0 });
  assert.equal(installation.executionPerformedInThisSource, false);
});

test("exact installed topology verifies read-only and fails closed on drift", () => {
  const exact = commands();
  const result = verifyInitialActivationPolicyReconciler(exact);
  assert.equal(result.roleDefinedInSource, true);
  assert.equal(result.pr448RuntimeMigrated, false);
  assert.equal(exact.calls.some((args) => args[0] === "iam" && ["create-role", "create-policy", "attach-role-policy", "update-assume-role-policy"].includes(args[1])), false);
  assert.throws(() => verifyInitialActivationPolicyReconciler(commands({ attached: [{ PolicyArn: "arn:aws:iam::368992683803:policy/unrelated" }] })), /attachment topology/);
  assert.throws(() => verifyInitialActivationPolicyReconciler(commands({ inline: ["unexpected"] })), /inline policies/);
});

test("normalizes parsed and encoded AWS documents and authenticates paginated policy topology", () => {
  const parsed = commands({ entities: [
    { PolicyRoles: [], PolicyUsers: [], PolicyGroups: [], IsTruncated: true, Marker: "page-2" },
    { PolicyRoles: [{ RoleName: INITIAL_ACTIVATION_RECONCILER.roleName }], PolicyUsers: [], PolicyGroups: [], IsTruncated: false },
  ] });
  const encodedResult = verifyInitialActivationPolicyReconciler(parsed);
  assert.equal(encodedResult.policyRoleCount, 1);
  assert.equal(encodedResult.permissionsBoundaryUsageCount, 0);
  const parsedResult = verifyInitialActivationPolicyReconciler(commands({ encodeRole: false, encodeVersion: false }));
  assert.equal(parsedResult.roleArn, INITIAL_ACTIVATION_RECONCILER.roleArn);
});

test("rejects malformed, primitive, extra-entity, truncated, and boundary-used policy shapes", () => {
  assert.throws(() => verifyInitialActivationPolicyReconciler(commands({ role: { AssumeRolePolicyDocument: "%7B" } })), /trust policy/);
  assert.throws(() => verifyInitialActivationPolicyReconciler(commands({ version: 7 })), /permissions policy/);
  for (const PermissionsBoundary of [
    { PermissionsBoundaryType: "PermissionsBoundaryPolicy", PermissionsBoundaryArn: "arn:aws:iam::368992683803:policy/unrelated" },
    { PermissionsBoundaryType: "PermissionsBoundaryPolicy", PermissionsBoundaryArn: INITIAL_ACTIVATION_RECONCILER.policyArn },
    {},
    null,
  ]) assert.throws(() => verifyInitialActivationPolicyReconciler(commands({ role: { PermissionsBoundary } })), /permissions boundary/);
  assert.throws(() => verifyInitialActivationPolicyReconciler(commands({ entities: [{ PolicyRoles: [{ RoleName: INITIAL_ACTIVATION_RECONCILER.roleName }, { RoleName: "other" }], PolicyUsers: [], PolicyGroups: [], IsTruncated: false }] })), /entity topology/);
  assert.throws(() => verifyInitialActivationPolicyReconciler(commands({ entities: [{ PolicyRoles: [], PolicyUsers: [], PolicyGroups: [], IsTruncated: true }] })), /pagination/);
  assert.throws(() => verifyInitialActivationPolicyReconciler(commands({ policyMetadata: { PermissionsBoundaryUsageCount: 1 } })), /permissions-boundary/);
  assert.throws(() => verifyInitialActivationPolicyReconciler(commands({ role: { MaxSessionDuration: 7200 } })), /session duration/);
});

test("capability contract defines the role without claiming PR #448 migration", () => {
  assert.equal(capability.roleDefinedInSource, true);
  assert.equal(capability.pr448RuntimeMigrated, false);
  assert.equal(capability.roleArn, INITIAL_ACTIVATION_RECONCILER.roleArn);
  assert.equal(capability.oidcSubject, "repo:T-ej2003/genuine-scan-main:environment:production");
  assert.deepEqual(capability.capabilities.filter(({ mutation }) => mutation), [{ action: "iam:CreatePolicyVersion", resource: INITIAL_ACTIVATION_RECONCILER.targetPolicyArn, mutation: true }]);
  assert.equal(capability.installation.runtimeSelfInstallation, false);
  assert.equal(capability.installation.executionPerformedInThisSource, false);
});
