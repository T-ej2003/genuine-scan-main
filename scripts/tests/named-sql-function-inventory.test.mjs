import assert from "node:assert/strict";
import test from "node:test";
import { assertNamedSqlFunctionContracts, buildNamedSqlFunctionInventory } from "../rls/named-sql-function-inventory.mjs";

test("named SQL inventory is deterministic and rejects fixture-only or missing production contracts", () => {
  const first = buildNamedSqlFunctionInventory();
  const second = buildNamedSqlFunctionInventory();
  assert.deepEqual(first, second);
  const refresh = first.functions.find((item) => item.functionName === "app_auth.claim_refresh_token_rotation");
  assert.equal(refresh.definitionKind, "fixture-only-non-production");
  assert.equal(refresh.contractStatus, "missing");
  const compliance = first.functions.find((item) => item.functionName === "app_rls.c03_start_compliance_pack_job");
  assert.equal(compliance.contractStatus, "missing");
  assert.throws(() => assertNamedSqlFunctionContracts(first), /named SQL function contracts missing/);
});
