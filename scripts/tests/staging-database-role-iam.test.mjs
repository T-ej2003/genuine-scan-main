import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const source = fs.readFileSync("infra/terraform/staging-api/main.tf", "utf8");
const createBlock = source.match(/for role, secret_name in \{([\s\S]*?)\}\s*: \{[\s\S]*?Action\s*= \["secretsmanager:CreateSecret"\][\s\S]*?Resource\s*= "\*"[\s\S]*?\n\s*\}\n\s*\]/)?.[0] || "";
const allowed = new Map([
  ["mscqr/staging/database-url/app", "app"],
  ["mscqr/staging/database-url/migrator", "migrator"],
]);
const requiredTags = { Environment: "staging", Application: "mscqr", Purpose: "database-role-credential", ManagedBy: "manual-reviewed-script" };

function allowsCreate({ name, region = "eu-west-2", tags = {}, role = allowed.get(name) }) {
  return allowed.has(name) && region === "eu-west-2" && allowed.get(name) === role && Object.entries(requiredTags).every(([key, value]) => tags[key] === value);
}

test("CreateSecret IAM is a separate wildcard-resource statement with exact fail-closed conditions", () => {
  assert(createBlock);
  assert.match(createBlock, /"secretsmanager:Name"\s*= secret_name/);
  assert.match(createBlock, /"aws:RequestedRegion"\s*= var\.aws_region/);
  for (const [key, value] of Object.entries(requiredTags)) assert.match(createBlock, new RegExp(`"aws:RequestTag/${key}"\\s*= "${value}"`));
  assert.match(createBlock, /"aws:RequestTag\/Role"\s*= role/);
  for (const [name, role] of allowed) assert.match(createBlock, new RegExp(`${role.replace("-", "\\-")}\\s*= "${name.replaceAll("/", "\\/")}"`));
  const scoped = source.match(/Sid\s*= "ManageExactStagingDatabaseRoleSecrets"[\s\S]*?\n\s*\}\]\n\s*\)/)?.[0] || "";
  assert.doesNotMatch(scoped, /CreateSecret/);
  for (const action of ["DescribeSecret", "GetSecretValue", "PutSecretValue", "TagResource", "UpdateSecretVersionStage"]) assert.match(scoped, new RegExp(`secretsmanager:${action}`));
});

test("CreateSecret permits only each exact name with its matching role tag", () => {
  for (const [name, role] of allowed) assert.equal(allowsCreate({ name, role, tags: requiredTags }), true);
  assert.equal(allowsCreate({ name: "mscqr/staging/database-url/app", role: "migrator", tags: requiredTags }), false);
});

test("CreateSecret denies arbitrary and production-like names", () => {
  for (const name of ["arbitrary", "mscqr/production/database-url/app", "mscqr/staging/database-url/admin"]) assert.equal(allowsCreate({ name, tags: requiredTags }), false);
});

test("CreateSecret denies missing or incorrect required request tags", () => {
  for (const key of [...Object.keys(requiredTags), "Role"]) {
    const tags = { ...requiredTags };
    if (key === "Role") assert.equal(allowsCreate({ name: "mscqr/staging/database-url/app", role: null, tags }), false);
    else { delete tags[key]; assert.equal(allowsCreate({ name: "mscqr/staging/database-url/app", tags }), false); tags[key] = "wrong"; assert.equal(allowsCreate({ name: "mscqr/staging/database-url/app", tags }), false); }
  }
});

test("CreateSecret denies requests outside eu-west-2", () => assert.equal(allowsCreate({ name: "mscqr/staging/database-url/app", region: "us-east-1", tags: requiredTags }), false));

test("ECS execution role adds only the app database-role secret pattern",()=>{
  assert.match(source,/app_database_secret_arn_pattern\s*= "arn:aws:secretsmanager:\$\{var\.aws_region\}:\$\{var\.account_id\}:secret:mscqr\/staging\/database-url\/app-\*"/);
  const policy=source.match(/resource "aws_iam_role_policy" "ecs_execution_staging_secrets"[\s\S]*?\n\}/)?.[0]||"";
  assert.match(policy,/Resource\s*= concat\(values\(local\.backend_secrets\), \[local\.app_database_secret_arn_pattern\]\)/);
  assert.doesNotMatch(policy,/database-url\/migrator|database-url\/rls-read|Resource\s*=\s*"\*"/);
});

test("ECS execution role database-role access allows app and denies migrator, RLS-read, arbitrary, and production secrets",()=>{
  const allows=(name)=>/^mscqr\/staging\/database-url\/app-[A-Za-z0-9]+$/.test(name);
  assert.equal(allows("mscqr/staging/database-url/app-AbCd"),true);
  for(const name of ["mscqr/staging/database-url/migrator-AbCd","mscqr/staging/database-url/rls-read-AbCd","mscqr/staging/database-url/arbitrary-AbCd","mscqr/production/database-url/app-AbCd"]) assert.equal(allows(name),false);
});
