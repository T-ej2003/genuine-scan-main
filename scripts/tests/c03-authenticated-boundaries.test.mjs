import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import { validateNamedSqlFunctionContracts } from "../rls/lib/named-sql-function-contracts.mjs";

const root = path.resolve(import.meta.dirname, "../..");
const read = (file) => fs.readFileSync(path.join(root, file), "utf8");

const expected = new Map([
  ["c03_revalidate_compliance_pack_job_actor_scope", "text,text,text,text"],
  ["c03_start_compliance_pack_job", "text,text,text,text,text,timestamp with time zone,timestamp with time zone"],
  ["c03_complete_compliance_pack_job", "text,text,text,text,jsonb"],
  ["c03_fail_compliance_pack_job", "text,text,text,text,text"],
  ["c03_get_compliance_pack_job", "text,text,text,text"],
  ["c03_complete_compliance_pack_rebuild", "text,text,text,text,jsonb"],
  ["c03_get_incident_evidence_file_by_storage_key", "text,text,text,text"],
]);

test("C03 public boundaries have exact capability contracts and internal helpers stay private", () => {
  const contracts = validateNamedSqlFunctionContracts().filter(({ security }) => security.deploymentPhase === "session-c-c03");
  assert.equal(contracts.length, expected.size);
  assert.deepEqual(new Map(contracts.map(({ name, signature }) => [name, signature])), expected);
  for (const contract of contracts) {
    assert.equal(contract.security.publicExecute, "revoked");
    assert.deepEqual(contract.security.runtimeExecuteGrantees, ["app"]);
    assert.equal(contract.security.ownerIdentity, "identity-auth-function-owner");
    assert(contract.repositoryCallers.length > 0);
    assert(contract.canonicalWorkflowIds.length > 0);
    assert(contract.tableCommands.some(([table]) => table === "RefreshToken"));
    assert(contract.disposableProbes.includes("c03-authenticated-boundaries-postgres18"));
  }

  const source = read("backend/src/rls-waves/session-c/c03/c03AuthenticatedBoundaries.sql");
  assert.match(source, /app_auth\.require_authenticated_session\(p_capability,p_purpose,p_request_id\)/);
  assert.doesNotMatch(source, /install_actor_context/);
  for (const helper of [
    "c03_require_authenticated_actor", "c03_assert_live_licensee_scope", "c03_bind_operation",
    "c03_compliance_job_projection", "c03_validate_compliance_result", "c03_queue_audit", "c03_build_compliance_report",
  ]) {
    assert.match(source, new RegExp(`REVOKE ALL ON FUNCTION app_rls\\.${helper}`));
  }
});

test("production C03 callers do not use the generic context installer", () => {
  const c03Files = [
    "backend/src/rls-waves/session-c/c03/c03ActorBoundary.ts",
    "backend/src/rls-waves/session-c/c03/c03CompliancePackRepository.ts",
    "backend/src/rls-waves/session-c/c03/c03IncidentRepository.ts",
    "backend/src/services/compliancePackService.ts",
    "backend/src/controllers/governanceController.ts",
    "backend/src/controllers/incidentController.ts",
  ];
  const production = c03Files.map(read).join("\n");
  assert.doesNotMatch(production, /withCanonicalDbContext|install_actor_context/);
  assert.match(production, /databaseSessionCapability/);
  assert.match(production, /c03_start_compliance_pack_job/);
  assert.match(production, /c03_get_incident_evidence_file_by_storage_key/);
});

test("generated C03 package has exact grants and no blanket execute grant", () => {
  const generated = [
    "scripts/rls/sql/generated/20-context-helpers.sql",
    "scripts/rls/sql/generated/21-runtime-grants.sql",
    "scripts/rls/sql/generated/30-policies.sql",
  ].map(read).join("\n");
  assert.doesNotMatch(generated, /GRANT\s+EXECUTE\s+ON\s+ALL\s+FUNCTIONS/i);
  for (const [name, signature] of expected) {
    assert.match(generated, new RegExp(`GRANT EXECUTE ON FUNCTION app_rls\\.${name}\\(${signature.replaceAll(" ", "\\s+")}\\) TO "mscqr_rls_cert_app"`));
  }
  assert.doesNotMatch(generated, /GRANT EXECUTE ON FUNCTION app_rls\.c03_(?:require_authenticated_actor|bind_operation)/);
});
