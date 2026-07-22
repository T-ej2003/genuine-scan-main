import assert from "node:assert/strict";
import test from "node:test";
import { assertNamedSqlFunctionContracts, buildNamedSqlFunctionInventory } from "../rls/named-sql-function-inventory.mjs";

test("named SQL inventory is deterministic, accepts reviewed B01 and C03 contracts, and rejects missing contracts", () => {
  const first = buildNamedSqlFunctionInventory();
  const second = buildNamedSqlFunctionInventory();
  assert.deepEqual(first, second);
  const refresh = first.functions.find((item) => item.functionName === "app_auth.claim_refresh_token_rotation");
  assert.equal(refresh.definitionKind, "checked-in-production-package");
  assert.equal(refresh.contractStatus, "reviewed");
  assert.equal(refresh.canonicalWorkflowIds[0], "workflow-internal-backend-src-services-auth-auth-service-ts-refresh-session");
  const compliance = first.functions.find((item) => item.functionName === "app_rls.c03_start_compliance_pack_job");
  assert.equal(compliance.contractStatus, "reviewed");
  assert.equal(compliance.signature, "text,text,text,text,text,timestamp with time zone,timestamp with time zone");
  assert.equal(compliance.canonicalWorkflowIds[0], "workflow-scheduled-backend-src-services-compliance-pack-service-ts-start-compliance-pack-scheduler");
  const remaining = first.functions.find((item) => item.functionName === "app_rls.c03_generate_compliance_report");
  assert.equal(remaining.contractStatus, "missing");
  assert.throws(() => assertNamedSqlFunctionContracts(first), /named SQL function contracts missing/);
});
