export type B03WorkflowProof = {
  workflowId: string;
  entryPoint: string;
  productionRoot: string;
  boundary: "authenticated-function" | "scheduled-function" | "worker-transaction";
  localStatus: "implemented-pending-global-integration" | "seam-only-pending-session-a-integration";
};

const pending = "implemented-pending-global-integration" as const;
const seam = "seam-only-pending-session-a-integration" as const;

export const b03WorkflowProofs: readonly B03WorkflowProof[] = [
  { workflowId: "workflow-internal-backend-src-services-analytics-rollup-service-ts-get-checkpoint-date", entryPoint: "internal:getCheckpointDate", productionRoot: "backend/src/services/analyticsRollupService.ts", boundary: "worker-transaction", localStatus: pending },
  { workflowId: "workflow-internal-backend-src-services-analytics-rollup-service-ts-load-changed-batch-ids", entryPoint: "internal:loadChangedBatchIds", productionRoot: "backend/src/services/analyticsRollupService.ts", boundary: "worker-transaction", localStatus: pending },
  { workflowId: "workflow-internal-backend-src-services-analytics-rollup-service-ts-refresh-inventory-status-rollups", entryPoint: "internal:refreshInventoryStatusRollups", productionRoot: "backend/src/services/analyticsRollupService.ts", boundary: "worker-transaction", localStatus: pending },
  { workflowId: "workflow-internal-backend-src-services-analytics-rollup-service-ts-refresh-scan-metrics-hourly-rollups", entryPoint: "internal:refreshScanMetricsHourlyRollups", productionRoot: "backend/src/services/analyticsRollupService.ts", boundary: "worker-transaction", localStatus: pending },
  { workflowId: "workflow-internal-backend-src-services-analytics-rollup-service-ts-set-checkpoint-date", entryPoint: "internal:setCheckpointDate", productionRoot: "backend/src/services/analyticsRollupService.ts", boundary: "worker-transaction", localStatus: pending },
  { workflowId: "workflow-internal-backend-src-services-audit-log-outbox-service-ts-queue-audit-log-outbox", entryPoint: "internal:queueAuditLogOutbox", productionRoot: "backend/src/services/auditLogOutboxService.ts", boundary: "worker-transaction", localStatus: pending },
  { workflowId: "workflow-worker-backend-src-services-audit-log-outbox-service-ts-flush-audit-log-outbox", entryPoint: "worker:flushAuditLogOutbox", productionRoot: "backend/src/services/auditLogOutboxService.ts", boundary: "worker-transaction", localStatus: pending },
  { workflowId: "workflow-internal-backend-src-services-incident-email-service-ts-get-primary-superadmin-email", entryPoint: "internal:getPrimarySuperadminEmail", productionRoot: "backend/src/services/incidentEmailService.ts", boundary: "authenticated-function", localStatus: pending },
  { workflowId: "workflow-internal-backend-src-services-incident-email-service-ts-get-superadmin-alert-emails", entryPoint: "internal:getSuperadminAlertEmails", productionRoot: "backend/src/services/incidentEmailService.ts", boundary: "authenticated-function", localStatus: pending },
  { workflowId: "workflow-internal-backend-src-services-incident-email-service-ts-resolve-actor-user", entryPoint: "internal:resolveActorUser", productionRoot: "backend/src/services/incidentEmailService.ts", boundary: "authenticated-function", localStatus: pending },
  { workflowId: "workflow-internal-backend-src-services-incident-email-service-ts-send-incident-email", entryPoint: "internal:sendIncidentEmail", productionRoot: "backend/src/services/incidentEmailService.ts", boundary: "authenticated-function", localStatus: pending },
  { workflowId: "workflow-internal-backend-src-services-notification-service-ts-create-role-notifications", entryPoint: "internal:createRoleNotifications", productionRoot: "backend/src/services/notificationService.ts", boundary: "authenticated-function", localStatus: pending },
  { workflowId: "workflow-internal-backend-src-services-notification-service-ts-create-user-notification", entryPoint: "internal:createUserNotification", productionRoot: "backend/src/services/notificationService.ts", boundary: "authenticated-function", localStatus: pending },
  { workflowId: "workflow-internal-backend-src-services-notification-service-ts-list-notifications-for-user-uncached", entryPoint: "internal:listNotificationsForUserUncached", productionRoot: "backend/src/services/notificationService.ts", boundary: "authenticated-function", localStatus: pending },
  { workflowId: "workflow-internal-backend-src-services-notification-service-ts-mark-all-notifications-read", entryPoint: "internal:markAllNotificationsRead", productionRoot: "backend/src/services/notificationService.ts", boundary: "authenticated-function", localStatus: pending },
  { workflowId: "workflow-internal-backend-src-services-notification-service-ts-mark-notification-read", entryPoint: "internal:markNotificationRead", productionRoot: "backend/src/services/notificationService.ts", boundary: "authenticated-function", localStatus: pending },
  { workflowId: "workflow-internal-backend-src-services-notification-service-ts-notify-incident-lifecycle", entryPoint: "internal:notifyIncidentLifecycle", productionRoot: "backend/src/services/notificationService.ts", boundary: "authenticated-function", localStatus: pending },
  { workflowId: "workflow-internal-backend-src-services-siem-outbox-service-ts-queue-security-event", entryPoint: "internal:queueSecurityEvent", productionRoot: "backend/src/services/siemOutboxService.ts", boundary: "worker-transaction", localStatus: pending },
  { workflowId: "workflow-worker-backend-src-services-siem-outbox-service-ts-flush-security-event-outbox", entryPoint: "worker:flushSecurityEventOutbox", productionRoot: "backend/src/services/siemOutboxService.ts", boundary: "worker-transaction", localStatus: pending },
  { workflowId: "workflow-scheduled-backend-src-services-compliance-pack-service-ts-start-compliance-pack-scheduler", entryPoint: "scheduled:startCompliancePackScheduler", productionRoot: "backend/src/services/compliancePackService.ts", boundary: "scheduled-function", localStatus: seam },
] as const;

export const b03SessionAIntegrationRequests = [
  {
    targetSymbol: "AuditLogOutbox and SecurityEventOutbox durable authority columns and indexes",
    callShape: "Add non-null job type, request UUID, SHA-256 digest, idempotency key, tenant/initiator scope, expiry, claim lease/token and terminal dead-letter state; unique(job type, tenant scope, idempotency key).",
    ordering: "Migrate and backfill before granting worker execution or enabling MSCQR_RLS_B03_WORKER_BOUNDARIES_ENABLED.",
    invariant: "JSON payload is never authority; immutable row columns and CAS state are authoritative.",
    responsePreservation: "Existing enqueue IDs and worker void return shapes remain unchanged.",
    focusedTest: "B03 PostgreSQL concurrent claim, conflicting digest, replay, expiry and max-attempt denial tests.",
  },
  {
    targetSymbol: "app_rls B03 worker repository functions",
    callShape: "Create exact functions enqueue/claim/consume/fail audit outbox, enqueue/claim/complete/fail security outbox, including required consume_audit_log_outbox(job_id text,payload_digest text,attempted_at timestamp).",
    ordering: "Functions lock/CAS durable rows, validate scope/digest/type/age, then atomically write terminal state; grants only to exact runtime identities.",
    invariant: "SENT is terminal, one logical side effect per idempotency key, max 10 attempts, no human role/platform flag.",
    responsePreservation: "Audit worker retains the existing flushed audit ID semantics; SIEM event ID remains the outbox row ID.",
    focusedTest: "B03 worker repository projection and two-concurrent-worker single-winner test.",
  },
  {
    targetSymbol: "app_rls B03 authenticated notification and incident-email functions",
    callShape: "Create the exact b03_* functions referenced by repositoryFunctions.ts with the fixed scalar signatures, bounded result projections, notification replay marker, and durable incident-email claim/completion record declared there.",
    ordering: "Install canonical actor context, revalidate actor/tenant in SQL, commit the idempotent notification or incident-email claim, perform network delivery without an open DB transaction, then complete in a fresh canonical transaction.",
    invariant: "No claimed role/scope authorizes access; protected user/email fields and incident scope are function-only.",
    responsePreservation: "Return notification JSON/write-result projections and incident delivery result matching current service return values.",
    focusedTest: "Foreign/stale/blank actor denial, notification replay without duplicate delivery, incident-email in-flight refusal, and same-tenant response-equivalence tests.",
  },
  {
    targetSymbol: "backend/src/services/compliancePackService.ts::startCompliancePackScheduler",
    callShape: "Inside withB03ScheduledContext call app_rls.claim_compliance_pack_slice(schedule_id,due_at,batch_size<=100), then process each returned tenant job by durable job ID; remove platform User lookup/impersonation.",
    ordering: "Claim schedule partition first, revalidate active licensee-to-organization binding, CAS RUNNING, generate, then CAS COMPLETED/FAILED and audit.",
    invariant: "Exact scheduled DB identity only; unique tenant/schedule claim; no platform-admin or human actor context.",
    responsePreservation: "Scheduler remains background/void and existing completed pack artifacts are not regenerated.",
    focusedTest: "Run compliance scheduler focused test with concurrent single winner, replay, wrong identity, unknown schedule and expiry denial.",
  },
  {
    targetSymbol: "B03 authenticated service callers",
    callShape: "Pass {requestId, run(callback)} as databaseBoundary; run opens a fresh canonical actor transaction, revalidates the actor/scope and invokes callback with its transaction client.",
    ordering: "Each protected function call completes and commits inside run before network delivery starts; completion markers use a new run transaction so no database transaction spans network I/O.",
    invariant: "MSCQR_RLS_B03_AUTHENTICATED_FUNCTIONS_ENABLED is enabled only after every caller supplies the boundary; missing boundary fails closed.",
    responsePreservation: "Controllers keep existing status codes, response bodies, email behavior, notification cache shape and realtime events.",
    focusedTest: "Registered call-path test proves function invocation precedes protected access and missing boundary causes no DB/network side effect.",
  },
  {
    targetSymbol: "B03 runtime roles and grants",
    callShape: "Provide MSCQR_WORKER_DATABASE_ROLE and MSCQR_SCHEDULED_DATABASE_ROLE from trusted runtime config; grant only exact B03 functions/tables to distinct LOGIN identities.",
    ordering: "Provision roles/credentials and grants before either activation flag; validate current_user before setting system context.",
    invariant: "No owner, superuser, BYPASSRLS, SET ROLE, human role or cross-identity credential reuse.",
    responsePreservation: "Background loop registration and polling cadence remain unchanged.",
    focusedTest: "PostgreSQL 18 wrong-role, owner-role, empty-context and transaction-local context-clearing tests.",
  },
  {
    targetSymbol: "backend/src/app.ts request correlation middleware",
    callShape: "Accept a client x-request-id only when it is a valid UUID; otherwise generate a server UUID and retain any safe client correlation value separately for logs only.",
    ordering: "Normalize the request ID before canonical actor context or any B03 service boundary is constructed.",
    invariant: "Untrusted arbitrary text never enters app.request_id, durable authority columns or idempotency keys.",
    responsePreservation: "Every request still has a correlation ID and response headers/log correlation remain available without turning previously accepted headers into a 500.",
    focusedTest: "Valid UUID preservation plus malformed, blank and oversized x-request-id replacement tests.",
  },
] as const;
