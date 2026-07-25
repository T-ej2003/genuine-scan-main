import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const sql = readFileSync("backend/src/rls-waves/session-c/c01/qrSystem.sql", "utf8");
const rollback = readFileSync("backend/src/rls-waves/session-c/c01/qrSystemRollback.sql", "utf8");
const contracts = readFileSync("scripts/rls/lib/named-sql-function-contracts.mjs", "utf8");
const generator = readFileSync("scripts/rls/generate-clean-room-rls-sql.mjs", "utf8");
const repository = readFileSync("backend/src/rls-waves/session-c/c01/qrSystemRepository.ts", "utf8");
const controller = readFileSync("backend/src/controllers/qrController.ts", "utf8");
const routes = readFileSync("backend/src/routes/index.ts", "utf8");

for (const name of [
  "qr_allocate_range",
  "qr_read_codes",
  "qr_stats",
  "qr_delete_codes",
  "qr_get_code_scope",
  "qr_bind_break_glass_tokens",
  "qr_batch_command",
  "qr_approve_allocation_request",
  "qr_inventory_projection",
  "qr_export_codes",
  "refresh_inventory_status_rollups",
  "refresh_scan_metrics_hourly_rollups",
]) {
  assert.match(sql, new RegExp(`CREATE OR REPLACE FUNCTION app_rls\\.${name}\\(`));
  assert.match(rollback, new RegExp(`DROP FUNCTION IF EXISTS app_rls\\.${name}\\(`));
  assert.match(contracts, new RegExp(`\"${name}\"`));
}

assert.match(sql, /app_auth\.require_authenticated_session/);
assert.match(sql, /'SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','MANUFACTURER_ADMIN'/);
assert.doesNotMatch(sql, /ORG_ADMIN|MANUFACTURER_USER|'MANUFACTURER'/);
assert.doesNotMatch(sql, /displayCode\s*\|\||\|\|\s*code/);
assert.doesNotMatch(sql, /UPDATE\s+public\."QRCode"\s+SET\s+code\b/i);
assert.doesNotMatch(sql, /gen_random_bytes|USING\s*\(\s*true\s*\)|WITH CHECK\s*\(\s*true\s*\)/i);
assert.doesNotMatch(rollback, /\bCASCADE\b/i);
assert.doesNotMatch(contracts, /GRANT\s+(?:ALL|EXECUTE)\s+ON\s+ALL\s+FUNCTIONS/i);
assert.match(generator, /!\["QRCode", "QRRange"\]\.includes\(table\)/);
assert.match(routes, /delete\("\/qr\/codes"[\s\S]*?requireAdministrationMutator[\s\S]*?bulkDeleteQRCodes/);
assert.doesNotMatch(routes, /delete\("\/qr\/codes"[\s\S]*?requireTenantDirectoryReader[\s\S]*?bulkDeleteQRCodes/);
assert.match(sql, /qr_delete_codes[\s\S]*?actor\.role NOT IN \('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN'\)/);
assert.match(sql, /p_operation NOT IN \('CREATE_BATCH','DELETE_BATCH','BULK_DELETE_BATCHES','ASSIGN_MANUFACTURER','RENAME_BATCH','AUDIT_CODE_EXPORT'\)/);
assert.match(controller, /renameBatch[\s\S]*?operation:\s*"RENAME_BATCH"/);
assert.match(contracts, /\["Batch","UPDATE",\["name","startCode","endCode","totalCodes","updatedAt"\]\]/);
assert.doesNotMatch(controller.match(/export const renameBatch[\s\S]*?\/\* ===================== PRINT/s)?.[0] || "", /findScopedBatch|prisma\.batch|createAuditLog/);
assert.match(controller, /exportQRCodesCsv[\s\S]*?operation:\s*"AUDIT_CODE_EXPORT"/);
assert.doesNotMatch(controller.match(/export const exportQRCodesCsv[\s\S]*$/s)?.[0] || "", /createAuditLog|prisma\.(qRCode|auditLog)/);
assert.match(contracts, /const qrDeleteVisible = `\(\$\{qrRole\} IN \('SUPER_ADMIN','PLATFORM_SUPER_ADMIN'\)/);
assert.match(sql, /\^\(\?:\[a-f0-9\]\{64\}\|\[A-Za-z0-9_-\]\{22\}\)\$/);
assert.match(controller, /withQrBoundaryTransaction\([\s\S]*?timeout:\s*ALLOCATION_TX_TIMEOUT_MS[\s\S]*?maxWait:\s*ALLOCATION_TX_MAX_WAIT_MS/);
assert.match(repository, /client\(\)\.\$transaction\(fn, options\)/);
assert.match(controller, /visitQrCodePages/);
assert.match(controller, /mkdtemp\(join\(tmpdir\(\),"mscqr-qr-export-"\)\)/);
assert.doesNotMatch(controller, /limit:\s*500000,\s*offset:\s*0/);
assert.match(sql, /ORDER BY "displayCode" NULLS LAST,"createdAt",id LIMIT p_limit OFFSET p_offset/);
assert.match(sql, /qr_inventory_projection\([\s\S]*?p_limit integer,p_offset integer[\s\S]*?LEFT JOIN public\."QRCode"/);
assert.match(sql, /SELECT jsonb_build_object\('_scope',scope\.aggregate\),tally\.total[\s\S]*?WHERE NOT EXISTS \(SELECT 1 FROM page\)/);
assert.match(sql, /scope_grouped AS MATERIALIZED[\s\S]*?'totals'[\s\S]*?'trend'/);
assert.match(repository, /aggregate:\s*A \| null/);
assert.match(sql, /'traceEvents'[\s\S]*?FROM public\."TraceEvent" t WHERE t\."batchId"=p_batch_id/);
assert.match(sql, /'policyAlerts'[\s\S]*?FROM public\."PolicyAlert" a WHERE a\."batchId"=p_batch_id/);
assert.match(contracts, /\["TraceEvent","SELECT"/);
assert.match(contracts, /\["PolicyAlert","SELECT"/);
assert.doesNotMatch(readFileSync("backend/src/controllers/qrLogController.ts","utf8"), /\.slice\(offset,offset\+limit\)/);
for (const file of [
  "backend/src/controllers/qrLogController.ts",
  "backend/src/services/qrTrackingAnalyticsService.ts",
  "backend/src/services/immutableAuditExportService.ts",
]) {
  assert.doesNotMatch(readFileSync(file,"utf8"), /(?:prisma|tx|db)\.(?:qRCode|qRRange)\./);
}
const immutableAudit = readFileSync("backend/src/services/immutableAuditExportService.ts","utf8");
assert.doesNotMatch(immutableAudit, /prisma\.(?:traceEvent|policyAlert)\./);
assert.match(immutableAudit, /projection\.traceEvents/);
assert.match(immutableAudit, /projection\.policyAlerts/);
const httpEntry = readFileSync("backend/src/index.ts","utf8");
const workerEntry = readFileSync("backend/src/worker.ts","utf8");
const rollupService = readFileSync("backend/src/services/analyticsRollupService.ts","utf8");
assert.doesNotMatch(httpEntry, /startAnalyticsRollupWorker|legacyQrRotationService/);
assert.match(workerEntry, /stopAnalyticsRollupWorker = startAnalyticsRollupWorker\(\)/);
assert.match(workerEntry, /stopAnalyticsRollupWorker\?\.\(\)/);
assert.match(rollupService, /if \(activeAnalyticsRollupStop\) return activeAnalyticsRollupStop/);
assert.match(rollupService, /app_rls\.refresh_inventory_status_rollups/);
assert.match(rollupService, /app_rls\.refresh_scan_metrics_hourly_rollups/);
assert.doesNotMatch(rollupService, /\.(?:batch|qRCode|qrScanLog|inventoryStatusRollup|scanMetricsHourlyRollup|systemCheckpoint)\./);
assert.match(generator, /qrSystemWorkerSignatures/);
assert.match(sql, /session_user<>\{\{WORKER_ROLE\}\}/);
assert.doesNotMatch(workerEntry, /legacyQrRotationService/);

console.log("QR system boundary static contract: PASS");
