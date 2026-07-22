import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { NAMED_SQL_FUNCTION_CONTRACTS } from "../rls/lib/named-sql-function-contracts.mjs";

const root = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const read = (file) => fs.readFileSync(path.join(root, file), "utf8");
const scheduledNames = [
  "provision_scheduled_job_credential",
  "revoke_scheduled_job_credential",
  "claim_compliance_pack_slice",
  "scheduled_get_compliance_pack_job",
  "scheduled_complete_compliance_pack_job",
  "scheduled_fail_compliance_pack_job",
];

test("scheduled identity is hash-only, exact, and production reviewed", () => {
  const schema = read("backend/prisma/schema.prisma");
  const migration = read("backend/prisma/migrations/20260722150000_add_scheduled_job_credential/migration.sql");
  assert.match(schema, /model ScheduledJobCredential/);
  assert.match(schema, /capabilityHash String @unique/);
  assert.doesNotMatch(schema, /rawCapability|capabilitySecret/);
  assert.match(migration, /ScheduledJobCredential_one_active_schedule/);
  assert.match(migration, /capabilityHashVersion.*sha256-v1/s);

  const contracts = NAMED_SQL_FUNCTION_CONTRACTS.filter((contract) => scheduledNames.includes(contract.name));
  assert.deepEqual(contracts.map(({ name }) => name).sort(), [...scheduledNames].sort());
  for (const contract of contracts) {
    assert.equal(contract.definitionStatus, "production-reviewed");
    assert.equal(contract.security.mode, "SECURITY DEFINER");
    assert.equal(contract.security.ownerRole, "authOwner");
    assert.equal(contract.security.publicExecute, "revoked");
    assert.equal(contract.security.searchPath, "pg_catalog,public");
    assert(contract.repositoryCallers.length > 0);
    assert(contract.tableCommands.length > 0);
    assert.deepEqual(contract.disposableProbes, ["scheduled-job-identity-postgres18"]);
  }
  assert(contracts.filter(({ security }) => security.runtimeExecuteGrantees.includes("operator")).length === 2);
  assert(contracts.filter(({ security }) => security.runtimeExecuteGrantees.includes("scheduled")).length === 4);
});

test("generated package grants only exact scheduled boundaries", () => {
  const helpers = read("scripts/rls/sql/generated/20-context-helpers.sql");
  const grants = `${helpers}\n${read("scripts/rls/sql/generated/21-runtime-grants.sql")}`;
  const policies = read("scripts/rls/sql/generated/30-policies.sql");
  const productionSources = [
    ...fs.readdirSync(path.join(root, "scripts/rls/sql/generated")).map((name) => read(`scripts/rls/sql/generated/${name}`)),
    read("backend/src/rls-waves/session-b/b03/scheduledJobIdentityFunctions.sql"),
  ].join("\n");

  assert.doesNotMatch(productionSources, /GRANT\s+(?:ALL|EXECUTE)\s+ON\s+ALL\s+FUNCTIONS/i);
  assert.doesNotMatch(grants, /GRANT EXECUTE ON FUNCTION app_rls\.scheduled_job_prepare/i);
  assert.doesNotMatch(grants, /GRANT EXECUTE ON FUNCTION app_rls\.scheduled_job_queue_audit/i);
  for (const name of scheduledNames) assert.match(grants, new RegExp(`GRANT EXECUTE ON FUNCTION app_rls\\.${name}\\(`));
  assert.match(helpers, /SECURITY DEFINER SET search_path=pg_catalog,public/);
  assert.match(policies, /ScheduledJobCredential/);
  assert.match(policies, /session_user='mscqr_rls_cert_scheduled'/);
  assert.match(policies, /current_setting\('app\.scheduled_credential_id',true\)/);
});

test("scheduled application path carries capability and never installs human context", () => {
  const service = read("backend/src/services/compliancePackService.ts");
  const context = read("backend/src/rls-waves/session-b/b03/systemContext.ts");
  const repository = read("backend/src/rls-waves/session-b/b03/repositoryFunctions.ts");
  assert.match(service, /MSCQR_SCHEDULED_JOB_CAPABILITY/);
  assert.match(service, /withB03ScheduledContext/);
  assert.doesNotMatch(service, /PLATFORM_SUPER_ADMIN|findFirst\(.*Licensee/s);
  assert.match(context, /database-verifiable capability/);
  assert.doesNotMatch(context.slice(context.indexOf("export const withB03ScheduledContext")), /set_config\(/);
  assert.match(repository, /app_rls\.claim_compliance_pack_slice/);
  assert.match(repository, /app_rls\.scheduled_complete_compliance_pack_job/);
  assert.match(repository, /app_rls\.scheduled_fail_compliance_pack_job/);
});
