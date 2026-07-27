import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { NAMED_SQL_FUNCTION_CONTRACTS } from "../rls/lib/named-sql-function-contracts.mjs";

const root = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const read = (file) => fs.readFileSync(path.join(root, file), "utf8");
const names = [
  "enqueue_audit_log_outbox", "claim_audit_log_outbox_slice", "consume_audit_log_outbox", "fail_audit_log_outbox",
  "enqueue_security_event_outbox", "claim_security_event_outbox_slice", "complete_security_event_outbox", "fail_security_event_outbox",
];

test("B03 durable outbox contracts are exact and reviewed", () => {
  const contracts = NAMED_SQL_FUNCTION_CONTRACTS.filter(({ name }) => names.includes(name));
  assert.deepEqual(contracts.map(({ name }) => name).sort(), [...names].sort());
  for (const contract of contracts) {
    assert.equal(contract.definitionStatus, "production-reviewed");
    assert.equal(contract.security.mode, "SECURITY DEFINER");
    assert.equal(contract.security.ownerRole, "authOwner");
    assert.equal(contract.security.publicExecute, "revoked");
    assert.equal(contract.security.searchPath, "pg_catalog,public");
    assert(contract.repositoryCallers.length > 0);
    assert(contract.tableCommands.length > 0);
    assert.deepEqual(contract.disposableProbes, ["b03-outbox-postgres18"]);
  }
  assert.equal(contracts.filter(({ security }) => security.runtimeExecuteGrantees.includes("app")).length, 2);
  assert.equal(contracts.filter(({ security }) => security.runtimeExecuteGrantees.includes("worker")).length, 6);
});

test("B03 outbox SQL is lease-bound, digest-bound and atomically projects recovered audits", () => {
  const source = read("backend/src/rls-waves/session-b/b03/b03OutboxFunctions.sql");
  const rollback = read("backend/src/rls-waves/session-b/b03/b03OutboxRollback.sql");
  assert.match(source, /FOR UPDATE SKIP LOCKED/g);
  assert.match(source, /claimLeaseExpiresAt/);
  assert.match(source, /B03_OUTBOX_REPLAY_MISMATCH/);
  assert.match(source, /INSERT INTO public\."AuditLog"/);
  assert.match(source, /INSERT INTO public\."SecurityEventOutbox"/);
  assert.match(source, /set_config\('app\.b03_audit_user_id'/);
  assert.doesNotMatch(source, /GRANT\s+(?:ALL|EXECUTE)\s+ON\s+ALL\s+FUNCTIONS/i);
  for (const name of names) {
    assert.match(source, new RegExp(`REVOKE ALL ON FUNCTION app_rls\\.${name}\\(`));
    assert.match(rollback, new RegExp(`DROP FUNCTION IF EXISTS app_rls\\.${name}\\(`));
  }
});

test("generated B03 grants expose public boundaries only to their exact identities", () => {
  const grants = `${read("scripts/rls/sql/generated/20-context-helpers.sql")}\n${read("scripts/rls/sql/generated/21-runtime-grants.sql")}`;
  assert.doesNotMatch(grants, /GRANT\s+(?:ALL|EXECUTE)\s+ON\s+ALL\s+FUNCTIONS/i);
  assert.doesNotMatch(grants, /GRANT EXECUTE ON FUNCTION app_rls\.b03_bind_outbox_operation/i);
  for (const name of names) assert.match(grants, new RegExp(`GRANT EXECUTE ON FUNCTION app_rls\\.${name}\\(`));
  const policies = read("scripts/rls/sql/generated/30-policies.sql");
  assert.match(policies, /app\.b03_outbox_idempotency_key/);
  assert.match(policies, /app\.b03_audit_user_id/);
  assert.doesNotMatch(policies, /USING\s*\(\s*true\s*\)|WITH CHECK\s*\(\s*true\s*\)/i);
});

test("B03 schema migration preserves legacy rows and constrains durable authority", () => {
  const schema = read("backend/prisma/schema.prisma");
  const migration = read("backend/prisma/migrations/20260722143000_add_b03_outbox_authority/migration.sql");
  assert.match(schema, /model AuditLogOutbox[\s\S]*payloadDigest String\?[\s\S]*idempotencyKey String\? @unique/);
  assert.match(schema, /model SecurityEventOutbox[\s\S]*payloadDigest String\?[\s\S]*idempotencyKey String\? @unique/);
  assert.match(migration, /payloadDigest_check/);
  assert.match(migration, /claimLease_check/);
  assert.doesNotMatch(schema, /rawCapability|rawToken/);
});
