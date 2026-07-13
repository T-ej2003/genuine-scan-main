import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import {
  STAGING_DATABASE_ROLE_CONTEXT as C,
  assertConsistentStagingHttpUrls,
  assertDatabaseRoleCutoverIdentity,
  assertDatabaseRoleVerificationReceipt,
} from "../lib/staging-database-role-credentials-core.mjs";

const files = {
  trust: "documents/ops/iam/MSCQR_STAGING_DATABASE_ROLE_CUTOVER_TRUST_POLICY_2026-07-13.json",
  assume: "documents/ops/iam/MSCQR_STAGING_DATABASE_ROLE_CUTOVER_ASSUME_ROLE_POLICY_2026-07-13.json",
  role: "documents/ops/iam/MSCQR_STAGING_DATABASE_ROLE_CUTOVER_POLICY_2026-07-13.json",
};
const read = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const output = (result) => `${result.stdout}\n${result.stderr}`;
const runCheck = (mutate = {}) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-db-role-cutover-iam-"));
  const env = { ...process.env };
  try {
    for (const [key, file] of Object.entries(files)) {
      const policy = read(file);
      mutate[key]?.(policy);
      const fixture = path.join(directory, `${key}.json`);
      fs.writeFileSync(fixture, JSON.stringify(policy), { mode: 0o600 });
      env[`MSCQR_STAGING_DATABASE_ROLE_CUTOVER_${key === "role" ? "POLICY" : key === "assume" ? "ASSUME_POLICY" : "TRUST_POLICY"}_PATH`] = fixture;
    }
    return spawnSync("node", ["scripts/check-staging-database-role-cutover-iam.mjs"], { encoding: "utf8", env });
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
};

test("dedicated staging cutover IAM templates pass", () => {
  const result = runCheck();
  assert.equal(result.status, 0, output(result));
});

test("cutover role exposes only reviewed calls and no broker, secret-value, RDS, or SSM channel access", () => {
  const policy = read(files.role);
  const actions = policy.Statement.flatMap((statement) => Array.isArray(statement.Action) ? statement.Action : [statement.Action]);
  for (const forbidden of ["lambda:InvokeFunction", "secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue", "secretsmanager:UpdateSecretVersionStage", "rds:ModifyDBInstance", "ecs:RunTask", "ecs:UntagResource", "ssmmessages:CreateControlChannel", "ssmmessages:OpenDataChannel"]) assert(!actions.includes(forbidden));
  assert(actions.includes("secretsmanager:DescribeSecret"));
  assert(actions.includes("ecs:RegisterTaskDefinition"));
  assert(actions.includes("ecs:TagResource"));
  assert(actions.includes("ecs:UpdateService"));
  assert(actions.includes("ecs:ExecuteCommand"));
  assert(actions.every((action) => !action.includes("*")));
});

test("task-definition tagging is limited to reviewed-family RegisterTaskDefinition tag-on-create", async (t) => {
  const policy = read(files.role);
  const tag = policy.Statement.find((statement) => statement.Sid === "TagOnlyReviewedStagingBackendTaskDefinitionOnRegistration");
  assert.equal(tag.Action, "ecs:TagResource");
  assert.equal(tag.Resource, `arn:aws:ecs:${C.region}:${C.accountId}:task-definition/mscqr-staging-backend:*`);
  assert.deepEqual(tag.Condition.StringEquals, {
    "aws:RequestedRegion": C.region,
    "ecs:CreateAction": "RegisterTaskDefinition",
  });

  await t.test("rejects unrelated ECS resources and task-definition families", () => {
    for (const resource of [
      `arn:aws:ecs:${C.region}:${C.accountId}:service/${C.cluster}/${C.service}`,
      `arn:aws:ecs:${C.region}:${C.accountId}:task-definition/unrelated:*`,
      "*",
    ]) {
      const result = runCheck({ role: (fixture) => { fixture.Statement.find((statement) => statement.Sid === tag.Sid).Resource = resource; } });
      assert.notEqual(result.status, 0);
      assert.match(output(result), /TagOnlyReviewedStagingBackendTaskDefinitionOnRegistration must use only|Resource wildcard is not approved/);
    }
  });

  await t.test("rejects ordinary tagging and wildcard actions", () => {
    const wrongCreateAction = runCheck({ role: (fixture) => { fixture.Statement.find((statement) => statement.Sid === tag.Sid).Condition.StringEquals["ecs:CreateAction"] = "CreateService"; } });
    assert.notEqual(wrongCreateAction.status, 0);
    assert.match(output(wrongCreateAction), /TagResource must be limited to RegisterTaskDefinition tag-on-create/);

    const wildcardAction = runCheck({ role: (fixture) => { fixture.Statement.find((statement) => statement.Sid === tag.Sid).Action = "ecs:*"; } });
    assert.notEqual(wildcardAction.status, 0);
    assert.match(output(wildcardAction), /Unapproved or wildcard action ecs:\*/);
  });
});

test("cutover role wildcards exist only for APIs that require them", () => {
  const policy = read(files.role);
  const wildcardSids = policy.Statement.filter((statement) => (Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource]).includes("*")).map((statement) => statement.Sid).sort();
  assert.deepEqual(wildcardSids, [
    "DescribeTaskDefinitionsRequiredByEcsApi",
    "IdentifyExactStagingAccount",
    "ListExactStagingBackendTasks",
    "ListExactStagingClusterServices",
    "ListStagingEventBridgeRulesRequiredForConsumerInventory",
    "ListTaskDefinitionsRequiredByEcsApi",
  ].sort());
});

test("cutover trust rejects the database operator, Terraform roles, root, wildcard, and missing MFA", async (t) => {
  const principals = [
    `arn:aws:iam::${C.accountId}:role/${C.operatorRole}`,
    `arn:aws:iam::${C.accountId}:role/mscqr-staging-terraform-plan-role`,
    `arn:aws:iam::${C.accountId}:role/mscqr-staging-terraform-apply-role`,
    `arn:aws:iam::${C.accountId}:root`,
    "*",
  ];
  for (const principal of principals) await t.test(principal, () => {
    const result = runCheck({ trust: (policy) => { policy.Statement[0].Principal.AWS = principal; } });
    assert.notEqual(result.status, 0);
    assert.match(output(result), /forbidden|allow only/);
  });
  const noMfa = runCheck({ trust: (policy) => { delete policy.Statement[0].Condition; } });
  assert.notEqual(noMfa.status, 0);
  assert.match(output(noMfa), /require MFA/);
});

test("only the exact cutover assumed role can cut over or roll back", () => {
  const identity = (role) => ({ Account: C.accountId, Arn: `arn:aws:sts::${C.accountId}:assumed-role/${role}/reviewed-session` });
  assert.doesNotThrow(() => assertDatabaseRoleCutoverIdentity(identity(C.cutoverRole), { AWS_REGION: C.region }));
  for (const role of [C.operatorRole, "mscqr-staging-terraform-plan-role", "mscqr-staging-terraform-apply-role"]) assert.throws(() => assertDatabaseRoleCutoverIdentity(identity(role), { AWS_REGION: C.region }), /require assumed role/);
});

test("cutover URL set rejects placeholders and cross-origin smoke checks", () => {
  const valid = assertConsistentStagingHttpUrls("http://mscqr-stg-alb.example.invalid/health/live", ["http://mscqr-stg-alb.example.invalid/health/ready"]);
  assert.equal(valid.hostname, "mscqr-stg-alb.example.invalid");
  for (const placeholder of ["https://REVIEWED-STAGING-HOST/health/live", "https://staging.example.com/health/live", "https://placeholder-staging.invalid/health/live"]) assert.throws(() => assertConsistentStagingHttpUrls(placeholder, [placeholder]), /placeholder/);
  assert.throws(() => assertConsistentStagingHttpUrls("https://api-staging.invalid/health/live", ["https://other-staging.invalid/health/ready"]), /same reviewed staging origin/);
});

test("verification receipt is fresh, complete, staging-only, and bound to the current task definition", () => {
  const now = Date.parse("2026-07-13T10:00:00Z");
  const receipt = {
    status: "staging_database_role_permission_matrix_passed",
    permissionMatrixPassed: true,
    accountId: C.accountId,
    region: C.region,
    cluster: C.cluster,
    service: C.service,
    backendTaskDefinitionArn: `arn:aws:ecs:${C.region}:${C.accountId}:task-definition/mscqr-staging-backend:2`,
    executorTaskDefinitionArn: `arn:aws:ecs:${C.region}:${C.accountId}:task-definition/mscqr-staging-database-role-admin:2`,
    executorTaskArn: `arn:aws:ecs:${C.region}:${C.accountId}:task/${C.cluster}/fixture`,
    verifiedRoles: Object.values(C.roles),
    rlsRouteFlags: Object.fromEntries(C.routeFlags.map((name) => [name, "false"])),
    verifiedAt: "2026-07-13T09:30:00Z",
  };
  assert.equal(assertDatabaseRoleVerificationReceipt(receipt, { currentTaskDefinitionArn: receipt.backendTaskDefinitionArn, now }), receipt);
  assert.throws(() => assertDatabaseRoleVerificationReceipt({ ...receipt, verifiedAt: "2026-07-11T09:30:00Z" }, { currentTaskDefinitionArn: receipt.backendTaskDefinitionArn, now }), /expired/);
  assert.throws(() => assertDatabaseRoleVerificationReceipt({ ...receipt, permissionMatrixPassed: false }, { currentTaskDefinitionArn: receipt.backendTaskDefinitionArn, now }), /successful/);
  assert.throws(() => assertDatabaseRoleVerificationReceipt(receipt, { currentTaskDefinitionArn: receipt.backendTaskDefinitionArn.replace(":2", ":3"), now }), /current backend/);
});

test("cutover controller consumes verification receipt without invoking the database-role broker", () => {
  const source = fs.readFileSync("scripts/aws/staging-database-role-credentials.mjs", "utf8");
  const cutover = source.match(/async function cutover\(\) \{[\s\S]*?(?=\nasync function rollback)/)?.[0] || "";
  assert.match(cutover, /verifiedReceipt\(base\)/);
  assert.doesNotMatch(cutover, /runExecutor|lambda/);
  assert.match(cutover, /cutoverIdentityPermissionsSufficient: true/);
  assert.match(cutover, /applyOnlyPermissionsDynamicallyProven: false/);
  assert.match(cutover, /mutatesAws: false/);
});

test("Terraform apply role may manage but cannot assume or use the cutover role", () => {
  const policy = read("documents/ops/iam/MSCQR_STAGING_TERRAFORM_APPLY_ROLE_POLICY_2026-07-08.json");
  const actions = new Set(policy.Statement.flatMap((statement) => Array.isArray(statement.Action) ? statement.Action : [statement.Action]));
  assert(actions.has("iam:CreateRole"));
  assert(actions.has("iam:PutRolePolicy"));
  assert(!actions.has("sts:AssumeRole"));
  assert(!actions.has("ecs:RegisterTaskDefinition"));
  assert(!actions.has("ecs:UpdateService"));
  assert(!actions.has("ecs:ExecuteCommand"));
  assert(policy.Statement.some((statement) => (Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource]).includes(`arn:aws:iam::${C.accountId}:role/${C.cutoverRole}`)));
});

test("endpoint discovery wrapper is syntax-valid and its implementation is read-only and fail-closed", () => {
  assert.equal(spawnSync("bash", ["-n", "scripts/aws/discover-staging-endpoints.sh"]).status, 0);
  const source = fs.readFileSync("scripts/aws/discover-staging-endpoints.mjs", "utf8");
  for (const call of ["describe-services", "describe-target-groups", "describe-load-balancers", "describe-listeners", "get-rest-apis", "get-apis", "list-distributions", "list-hosted-zones", "list-resource-record-sets"]) assert(source.includes(`\"${call}\"`));
  assert.doesNotMatch(source, /create-|update-|delete-|put-|get-secret-value|SecretString/i);
  assert.match(source, /Expected exactly one reviewed staging origin/);
  assert.match(source, /mutatesAws: false/);
});
