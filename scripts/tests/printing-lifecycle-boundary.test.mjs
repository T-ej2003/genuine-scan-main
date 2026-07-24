import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const read = (file) => readFileSync(file, "utf8");
const sql = read("backend/src/rls-waves/session-c/c02/printingLifecycle.sql");
const rollback = read("backend/src/rls-waves/session-c/c02/printingLifecycleRollback.sql");
const contracts = read("scripts/rls/lib/named-sql-function-contracts.mjs");
const repository = read("backend/src/rls-waves/session-c/c02/printingLifecycleRepository.ts");
const connector = read("backend/src/controllers/printerAgentJobController.ts");
const create = read("backend/src/services/printJobCreationTransactionService.ts");
const controls = read("backend/src/services/printOperationControlService.ts");
const query = read("backend/src/controllers/print-job/queryHandlers.ts");
const roles = read("backend/src/controllers/print-job/shared.ts");
const printer = read("backend/src/controllers/printerController.ts");
const createHandler = read("backend/src/controllers/print-job/createPrintJobHandler.ts");

for (const name of [
  "printing_readiness",
  "printing_create_job",
  "printing_control_job",
  "printing_printer_administration",
  "printing_idempotency",
  "printing_connector_registration",
  "printing_test_label_job",
  "printing_connector_event",
  "printing_connector_identity",
  "printing_gateway_job",
  "printing_record_sample",
  "printing_release_batch",
  "printing_reissue_request",
  "printing_worker_reconcile",
  "printing_worker_network_job",
]) {
  assert.match(sql, new RegExp(`CREATE OR REPLACE FUNCTION app_rls\\.${name}\\(`));
  assert.match(rollback, new RegExp(`DROP FUNCTION IF EXISTS app_rls\\.${name}\\(`));
  assert.match(contracts, new RegExp(`"${name}"`));
}

assert.match(sql, /app_auth\.require_authenticated_session/);
assert.match(sql, /'SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','MANUFACTURER_ADMIN'/);
assert.doesNotMatch(sql, /ORG_ADMIN|MANUFACTURER_USER|'MANUFACTURER'/);
assert.doesNotMatch(sql, /UPDATE\s+public\."QRCode"\s+SET\s+code\b/i);
assert.doesNotMatch(sql, /USING\s*\(\s*true\s*\)|WITH CHECK\s*\(\s*true\s*\)|BYPASSRLS/i);
assert.doesNotMatch(rollback, /\bCASCADE\b/i);
assert.equal([...rollback.matchAll(/^DROP POLICY IF EXISTS printing_lifecycle_/gm)].length, 40);
assert.doesNotMatch(contracts, /GRANT\s+(?:ALL|EXECUTE)\s+ON\s+ALL\s+FUNCTIONS/i);
assert.match(sql, /pg_advisory_xact_lock\(hashtextextended\('printing_batch_'/);
assert.match(sql, /p\."licenseeId"=batch_row\."licenseeId"[\s\S]*p\."assignedUserId"=actor\."userId"/);
assert.match(sql, /PRINTER_PAYLOAD_MISMATCH/);
assert.match(sql, /MAKER_CANNOT_APPROVE/);
assert.match(sql, /PRINT_ACK_REQUIRED/);
assert.match(sql, /SAMPLE_SCAN_REQUIRED/);
assert.match(sql, /EXCEPTION WHEN NO_DATA_FOUND THEN\s+RAISE EXCEPTION 'QR_NOT_IN_PRINT_JOB'/);
assert.doesNotMatch(sql, /EXCEPTION WHEN OTHERS THEN\s+RAISE EXCEPTION 'QR_NOT_IN_PRINT_JOB'/);
assert.doesNotMatch(sql, /SELECT\s+a\.\*\s+INTO\s+approval_row\s+FROM\s+public\."SensitiveActionApproval"/i);
assert.doesNotMatch(sql, /RETURNING\s+\*\s+INTO\s+approval_row/i);
assert.match(sql, /coalesce\(policy->>'type',policy->>'mode','ONE_PER_PRINT_JOB'\)/);
assert.match(sql, /coalesce\(\(policy->>'min'\)::integer,1\)/);

for (const source of [connector, create, controls, query]) {
  assert.match(source, /printingLifecycleRepository|printing_(?:readiness|create_job|control_job|connector_event)/);
  assert.doesNotMatch(source, /install_actor_context|withCanonicalDbContext/);
}
assert.doesNotMatch(connector, /prisma\.(?:printJob|printSession|printItem|qRCode|batch)\./);
assert.doesNotMatch(query, /getPrintJobOperationalView|listPrintJobsForManufacturer/);
assert.match(repository, /app_rls\.printing_connector_event/);
assert.match(repository, /app_rls\.printing_connector_registration/);
assert.match(repository, /app_rls\.printing_idempotency/);
assert.match(createHandler, /abortPrintActionIdempotency/);
assert.doesNotMatch(printer, /beginIdempotentAction|completeIdempotentAction|createAuditLog|resolveAccessibleLicenseeIdsForUser/);
assert.doesNotMatch(createHandler, /beginIdempotentAction|completeIdempotentAction/);
assert.match(sql, /'PRINTER_TEST_LABEL_'\|\|p_operation/);
assert.match(roles, /const MANUFACTURER_ROLES: UserRole\[\] = \[UserRole\.MANUFACTURER_ADMIN\]/);
assert.doesNotMatch(roles, /UserRole\.(?:ORG_ADMIN|MANUFACTURER_USER|MANUFACTURER),/);

console.log("Printing lifecycle boundary static contract: PASS");
