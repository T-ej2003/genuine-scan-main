import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { STAGING_DATABASE_ROLE_CONTEXT as C, assertDatabaseRoleOperatorIdentity } from "../lib/staging-database-role-credentials-core.mjs";

const files = {
  trust: "documents/ops/iam/MSCQR_STAGING_DATABASE_ROLE_OPERATOR_TRUST_POLICY_2026-07-12.json",
  assume: "documents/ops/iam/MSCQR_STAGING_DATABASE_ROLE_OPERATOR_ASSUME_ROLE_POLICY_2026-07-12.json",
  role: "documents/ops/iam/MSCQR_STAGING_DATABASE_ROLE_OPERATOR_POLICY_2026-07-12.json",
};
const read = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const runCheck = (mutate = {}) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mscqr-db-role-operator-iam-"));
  const env = { ...process.env };
  try {
    for (const [key, file] of Object.entries(files)) {
      const policy = read(file);
      mutate[key]?.(policy);
      const fixture = path.join(directory, `${key}.json`);
      fs.writeFileSync(fixture, JSON.stringify(policy), { mode: 0o600 });
      env[`MSCQR_STAGING_DATABASE_ROLE_OPERATOR_${key === "role" ? "POLICY" : key === "assume" ? "ASSUME_POLICY" : "TRUST_POLICY"}_PATH`] = fixture;
    }
    return spawnSync("node", ["scripts/check-staging-database-role-operator-iam.mjs"], { encoding: "utf8", env });
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
};
const output = (result) => `${result.stdout}\n${result.stderr}`;
const operatorIdentity = { Account: C.accountId, Arn: `arn:aws:sts::${C.accountId}:assumed-role/${C.operatorRole}/reviewed-session` };

test("reviewed database-role operator IAM templates pass", () => { const result = runCheck(); assert.equal(result.status, 0, output(result)); });
test("wildcard RunTask resource is rejected", () => { const result = runCheck({ role: (policy) => { policy.Statement.find((value) => value.Sid === "RunReviewedDisposableDatabaseRoleTask").Resource = "*"; } }); assert.notEqual(result.status, 0); assert.match(output(result), /RunTask|Wildcard/); });
test("wildcard PassRole resource is rejected", () => { const result = runCheck({ role: (policy) => { policy.Statement.find((value) => value.Sid === "PassOnlyReviewedDatabaseRoleTaskRoles").Resource = "*"; } }); assert.notEqual(result.status, 0); assert.match(output(result), /PassRole|Wildcard/); });
test("PassRole requires ecs-tasks PassedToService", () => { const result = runCheck({ role: (policy) => { delete policy.Statement.find((value) => value.Sid === "PassOnlyReviewedDatabaseRoleTaskRoles").Condition; } }); assert.notEqual(result.status, 0); assert.match(output(result), /PassedToService/); });
test("PassRole permits only the two reviewed ECS roles", () => { const result = runCheck({ role: (policy) => { policy.Statement.find((value) => value.Sid === "PassOnlyReviewedDatabaseRoleTaskRoles").Resource.push(`arn:aws:iam::${C.accountId}:role/mscqr-staging-unreviewed-role`); } }); assert.notEqual(result.status, 0); assert.match(output(result), /only the reviewed admin task and ECS execution roles/); });
test("production-looking resources are rejected", () => { const result = runCheck({ role: (policy) => { policy.Statement.find((value) => value.Sid === "RunReviewedDisposableDatabaseRoleTask").Resource = `arn:aws:ecs:${C.region}:${C.accountId}:task-definition/mscqr-production-database-role-admin:*`; } }); assert.notEqual(result.status, 0); assert.match(output(result), /production-looking/); });
test("trust rejects root wildcard and Terraform plan or apply principals", async (t) => { for (const principal of [`arn:aws:iam::${C.accountId}:root`, "*", `arn:aws:iam::${C.accountId}:role/mscqr-staging-terraform-plan-role`, `arn:aws:iam::${C.accountId}:role/mscqr-staging-terraform-apply-role`]) await t.test(principal, () => { const result = runCheck({ trust: (policy) => { policy.Statement[0].Principal.AWS = principal; } }); assert.notEqual(result.status, 0); assert.match(output(result), /Trust policy|forbidden/); }); });
test("trust requires MFA", () => { const result = runCheck({ trust: (policy) => { delete policy.Statement[0].Condition; } }); assert.notEqual(result.status, 0); assert.match(output(result), /require MFA/); });
test("only the dedicated assumed role can execute probe provision or verify", () => { assert.doesNotThrow(() => assertDatabaseRoleOperatorIdentity(operatorIdentity, { AWS_REGION: C.region })); for (const role of ["mscqr-staging-terraform-plan-role", "mscqr-staging-terraform-apply-role", "mscqr-staging-broad-operator"]) assert.throws(() => assertDatabaseRoleOperatorIdentity({ Account: C.accountId, Arn: `arn:aws:sts::${C.accountId}:assumed-role/${role}/session` }, { AWS_REGION: C.region }), /require assumed role/); });
