// Fixed, review-only query set for the 2026-11-12 incident. Execution requires a separately approved database role and task.
export const INCIDENT_SOURCE_SHA = "7407b80b7919ca88f53e4a6d05596701fe00d0e0";
export const INCIDENT_DATABASE = "mscqr_production_rls_green_phase2";
export const INCIDENT_ROLE = "mscqr_prod_rls_canary_read";
export const INCIDENT_SCOPE = Object.freeze({
  manufacturerId: "cd8ddbcd-ce8f-4cc1-8178-9e65140c1c68",
  licenseeId: "07083e4d-3891-4afe-ad23-6c16bbdeb8c3",
  batchId: "3f0eb49e-7536-46d4-8ff9-b680a5c7b58a",
  productionPrinterId: "ac73d03e-69de-4c71-a793-07afa6b36937",
  testPrinterId: "3983f773-9383-4a42-a176-e733ff049163",
});

export const INCIDENT_QUERIES = Object.freeze({
  identity: `SELECT current_user AS role, session_user AS session_role,
    current_database() AS database_name, current_setting('transaction_read_only') AS read_only,
    current_setting('row_security') AS row_security, current_setting('application_name') AS application_name`,
  rls: `SELECT c.relname AS table_name, c.relrowsecurity AS rls_enabled, c.relforcerowsecurity AS force_rls
    FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relname IN
      ('PrintJob','PrintSession','PrintItem','PrintItemEvent','PrintAuditEvent','Printer','Batch','QRCode','InventoryStatusRollup','RefreshToken','SupportIssueReport','AuditLog')
    ORDER BY c.relname LIMIT 12`,
  activity: `SELECT pid, application_name, usename, state, wait_event_type, wait_event,
      xact_start, query_start, pg_catalog.pg_blocking_pids(pid) AS blocking_pids
    FROM pg_catalog.pg_stat_activity WHERE datname = 'mscqr_production_rls_green_phase2'
      AND application_name LIKE 'mscqr%'
    ORDER BY query_start NULLS LAST, pid LIMIT 30`,
  printJobs: `SELECT j.id, j.status, j."pipelineState", j."printerId", j."createdAt", j."updatedAt", j."sentAt", j."completedAt",
      s.id AS session_id, s.status AS session_status, s."createdAt" AS session_created_at,
      s."updatedAt" AS session_updated_at, s."completedAt" AS session_completed_at,
      s."issuedItems", s."confirmedItems", s."frozenItems"
    FROM public."PrintJob" j LEFT JOIN public."PrintSession" s ON s."printJobId" = j.id
    WHERE j."batchId" = '3f0eb49e-7536-46d4-8ff9-b680a5c7b58a'
      AND j."manufacturerId" = 'cd8ddbcd-ce8f-4cc1-8178-9e65140c1c68'
    ORDER BY j."createdAt" DESC, j.id LIMIT 20`,
  printEvents: `SELECT e."printItemId", e."eventType", e."previousState", e."nextState", e."createdAt"
    FROM public."PrintItemEvent" e JOIN public."PrintItem" i ON i.id = e."printItemId"
    JOIN public."PrintSession" s ON s.id = i."printSessionId"
    WHERE s."batchId" = '3f0eb49e-7536-46d4-8ff9-b680a5c7b58a'
      AND s."manufacturerId" = 'cd8ddbcd-ce8f-4cc1-8178-9e65140c1c68'
    ORDER BY e."createdAt" DESC, e.id LIMIT 30`,
  testLabel: `SELECT p.id,
      p.metadata->'pendingLocalAgentTestLabel'->>'testJobId' AS test_job_id,
      p.metadata->'pendingLocalAgentTestLabel'->>'status' AS status,
      p.metadata->'pendingLocalAgentTestLabel'->>'createdAt' AS created_at,
      p.metadata->'pendingLocalAgentTestLabel'->>'expiresAt' AS expires_at,
      p.metadata->'pendingLocalAgentTestLabel'->>'claimedAt' AS claimed_at,
      p.metadata->'pendingLocalAgentTestLabel'->>'ackedAt' AS acked_at,
      p.metadata->'pendingLocalAgentTestLabel'->>'confirmedAt' AS confirmed_at,
      p.metadata->'pendingLocalAgentTestLabel'->>'failedAt' AS failed_at,
      p.metadata->'pendingLocalAgentTestLabel'->>'deviceJobRef' AS device_job_ref,
      p.metadata->'pendingLocalAgentTestLabel'->>'confirmationMode' AS confirmation_mode
    FROM public."Printer" p WHERE p.id = '3983f773-9383-4a42-a176-e733ff049163' LIMIT 1`,
  testLabelAudit: `SELECT a.action, a."createdAt", a.details->>'testJobId' AS test_job_id,
      a.details->>'deviceJobRef' AS device_job_ref
    FROM public."AuditLog" a
    WHERE a."entityType"='Printer' AND a."entityId"='3983f773-9383-4a42-a176-e733ff049163'
      AND a.action LIKE 'PRINTER_TEST_LABEL_%'
      AND a."createdAt">=timestamp '2026-11-12 11:00:00'
      AND a."createdAt"<timestamp '2026-11-12 12:00:00'
    ORDER BY a."createdAt" DESC, a.id LIMIT 30`,
  sessions: `SELECT r.id, r."createdAt", r."expiresAt", r."lastUsedAt", r."revokedAt",
      r."rotationClaimedAt", r."rotationCompletedAt", r."sessionCapabilityExpiresAt", r."sessionCapabilityRevokedAt"
    FROM public."RefreshToken" r WHERE r."userId" = 'cd8ddbcd-ce8f-4cc1-8178-9e65140c1c68'
    ORDER BY r."createdAt" DESC, r.id LIMIT 20`,
  support: `SELECT r.id, r.status, r.priority, r."issueType", r."emailDeliveryStatus", r."createdAt", r."updatedAt"
    FROM public."SupportIssueReport" r
    WHERE r."reporterUserId" = 'cd8ddbcd-ce8f-4cc1-8178-9e65140c1c68'
      AND r."createdAt" >= timestamptz '2026-11-12 11:00:00+00'
      AND r."createdAt" < timestamptz '2026-11-12 12:00:00+00'
    ORDER BY r."createdAt" DESC, r.id LIMIT 20`,
  batch: `SELECT b.id, b."licenseeId", b."manufacturerId", b."parentBatchId", b."rootBatchId",
      b."totalCodes", b."lifecycleState", b."printedAt", b."updatedAt",
      i."totalCodes" AS rollup_total, i.dormant, i.active, i.activated, i.allocated, i.printed, i.redeemed, i.blocked, i.scanned, i."refreshedAt"
    FROM public."Batch" b LEFT JOIN public."InventoryStatusRollup" i ON i."batchId" = b.id
    WHERE b.id = '3f0eb49e-7536-46d4-8ff9-b680a5c7b58a'
      AND b."licenseeId" = '07083e4d-3891-4afe-ad23-6c16bbdeb8c3' LIMIT 1`,
  qrCounts: `SELECT q.status, count(*)::integer AS count FROM public."QRCode" q
    WHERE q."batchId" = '3f0eb49e-7536-46d4-8ff9-b680a5c7b58a'
      AND q."licenseeId" = '07083e4d-3891-4afe-ad23-6c16bbdeb8c3'
    GROUP BY q.status ORDER BY q.status LIMIT 20`,
});
