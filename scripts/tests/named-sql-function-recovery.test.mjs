import assert from "node:assert/strict";
import test from "node:test";
import { buildNamedSqlFunctionRecovery } from "../rls/named-sql-function-recovery.mjs";

test("recovery distinguishes deployable SQL from fixture-only evidence", () => {
  const report = buildNamedSqlFunctionRecovery();
  const refresh = report.functions.find((item) => item.functionName === "app_auth.claim_refresh_token_rotation");
  const policy = report.functions.find((item) => item.functionName === "app_rls.c03_create_policy_rule");
  const compliance = report.functions.find((item) => item.functionName === "app_rls.c03_start_compliance_pack_job");
  assert.equal(refresh.classification, "fixture-only definition");
  assert.equal(policy.classification, "production definition recovered");
  assert.equal(compliance.classification, "no definition found");
  assert(refresh.historyCommits.length);
  assert(policy.definitionLocation.endsWith("c03Policy.sql"));
});
