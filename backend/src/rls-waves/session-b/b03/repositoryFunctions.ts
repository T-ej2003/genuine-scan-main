import { createHash } from "crypto";
import { Prisma } from "@prisma/client";
import type { AuthenticatedSessionClaims } from "../../../types";
import { withDatabaseAuthenticatedSession } from "../b01/canonicalAuthContext";

export type B03FunctionClient = Pick<Prisma.TransactionClient, "$queryRaw">;
export type B03AuthenticatedFunctionBoundary = {
  requestId: string;
  run: <T>(callback: (db: B03FunctionClient) => Promise<T>) => Promise<T>;
};

export const createB03AuthenticatedFunctionBoundary = (input: {
  claims: AuthenticatedSessionClaims;
  capability: string;
  requestId: string;
  purpose: string;
}): B03AuthenticatedFunctionBoundary => {
  const requestId = String(input.requestId || "").trim();
  if (!requestId || !/^[\x21-\x7e]{1,128}$/.test(requestId)) {
    throw new Error("B03 authenticated repository requires a printable requestId");
  }
  return {
    requestId,
    run: (callback) => withDatabaseAuthenticatedSession(
      input.claims,
      {
        capability: input.capability,
        requestId,
        purpose: input.purpose,
      },
      (tx) => callback(tx)
    ),
  };
};

export const b03AuthenticatedFunctionsEnabled = () =>
  ["1", "true", "yes", "on"].includes(
    String(process.env.MSCQR_RLS_B03_AUTHENTICATED_FUNCTIONS_ENABLED || "").trim().toLowerCase()
  );

export type B03DurableClaim = {
  id: string;
  jobType: string;
  requestId: string;
  payloadDigest: string;
  idempotencyKey: string;
  organizationId: string | null;
  licenseeId: string | null;
  manufacturerId: string | null;
  initiatingUserId: string | null;
  expiresAt: Date;
  attempt: number;
};

export type B03AuditClaim = B03DurableClaim & { jobType: "AUDIT_LOG_RECOVERY" };
export type B03SiemClaim = B03DurableClaim & {
  jobType: "AUDIT_LOG" | "CSP_VIOLATION";
  eventType: "AUDIT_LOG" | "CSP_VIOLATION";
  eventPayload: unknown;
  createdAt: Date;
};

type NotificationAudience = "SUPER_ADMIN" | "LICENSEE_ADMIN" | "MANUFACTURER" | "ALL";
type NotificationChannel = "WEB" | "EMAIL";

export type B03RoleNotificationInput = {
  audience: NotificationAudience;
  title: string;
  body: string;
  notificationType: string;
  licenseeId?: string | null;
  organizationId?: string | null;
  incidentId?: string | null;
  data?: unknown;
  channels: NotificationChannel[];
  requestId: string;
};

export type B03UserNotificationInput = {
  userId: string;
  title: string;
  body: string;
  notificationType: string;
  licenseeId?: string | null;
  organizationId?: string | null;
  incidentId?: string | null;
  data?: unknown;
  channel: NotificationChannel;
  requestId: string;
};

export type B03NotificationDeliveryRow = {
  notificationId: string;
  userId: string | null;
  userEmail: string | null;
  userRole: string | null;
  userLicenseeId: string | null;
  userOrganizationId: string | null;
  channel: NotificationChannel;
  writeResult: Prisma.JsonValue;
  sideEffectRequired: boolean;
};

export type B03AttentionQueueProjection = {
  incidents: { count: number; latest: {
    id: string; qrCodeValue: string; severity: string; status: string; createdAt: string;
  } | null };
  policyAlerts: { count: number; latest: {
    id: string; alertType: string; severity: string; message: string; createdAt: string;
  } | null };
  supportTickets: { count: number; latest: {
    id: string; referenceCode: string; status: string; priority: string; updatedAt: string;
  } | null };
  auditEvents: { count: number; latest: {
    id: string; action: string; entityType: string; entityId: string | null; createdAt: string;
  } | null };
};

export type B03IncidentEmailDeliveryInput = {
  incidentId: string;
  licenseeId?: string | null;
  actorUserId?: string | null;
  senderMode: "actor" | "system";
  toAddress: string;
  subject: string;
  bodyPreview: string;
  attemptedFrom?: string | null;
  usedFrom?: string | null;
  replyTo?: string | null;
  providerMessageId?: string | null;
  emailErrorCode?: string | null;
  status: "QUEUED" | "SENT" | "FAILED";
  template?: string | null;
  smtpConfigSource?: string | null;
  requestId: string;
};

export type B03IncidentEmailClaim = {
  deliveryId: string;
  disposition: "CLAIMED" | "REPLAY_SENT" | "REPLAY_FAILED" | "IN_FLIGHT";
  delivered: boolean;
  providerMessageId: string | null;
  emailErrorCode: string | null;
  attemptedFrom: string | null;
  usedFrom: string | null;
  replyTo: string | null;
};

export type B03AuditEnqueueInput = {
  payload: unknown;
  requestId: string;
  payloadDigest: string;
  idempotencyKey: string;
  organizationId?: string | null;
  licenseeId?: string | null;
  manufacturerId?: string | null;
  initiatingUserId?: string | null;
  initiatingActorRoleSnapshot?: string | null;
  expiresAt: Date;
  initialErrorCode?: string | null;
};

export type B03SiemEnqueueInput = Omit<B03AuditEnqueueInput, "initiatingActorRoleSnapshot" | "initialErrorCode"> & {
  eventType: "AUDIT_LOG" | "CSP_VIOLATION";
};

const id = (value: unknown, label: string) => text(value, label, 191);
const text = (value: unknown, label: string, max: number) => {
  const normalized = String(value || "").trim();
  if (!normalized || normalized.length > max) throw new Error(`B03 repository requires valid ${label}`);
  return normalized;
};
const optional = (value: unknown, label: string, max = 191) => {
  const normalized = String(value || "").trim();
  if (normalized.length > max) throw new Error(`B03 repository requires valid ${label}`);
  return normalized || null;
};
const bounded = (value: unknown, label: string, max: number) => {
  const normalized = String(value ?? "");
  if (normalized.length > max) throw new Error(`B03 repository requires valid ${label}`);
  return normalized;
};
const uuid = (value: unknown) => {
  const normalized = text(value, "requestId", 36).toLowerCase();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(normalized)) {
    throw new Error("B03 repository requires UUID requestId");
  }
  return normalized;
};
const authenticatedRequestId = (value: unknown) => {
  const normalized = text(value, "requestId", 128);
  if (!/^[\x21-\x7e]+$/.test(normalized)) {
    throw new Error("B03 repository requires a printable requestId");
  }
  return normalized;
};
export const requireB03AuthenticatedFunctionBoundary = (
  boundary: B03AuthenticatedFunctionBoundary | undefined
) => {
  if (!boundary || typeof boundary.run !== "function") {
    throw new Error("B03 authenticated repository requires a transaction runner");
  }
  return { ...boundary, requestId: authenticatedRequestId(boundary.requestId) };
};
const digest = (value: unknown) => {
  const normalized = text(value, "payloadDigest", 64).toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(normalized)) throw new Error("B03 repository requires SHA-256 payloadDigest");
  return normalized;
};
const timestamp = (value: unknown, label: string) => {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) throw new Error(`B03 repository requires valid ${label}`);
  return value;
};
const integer = (value: unknown, label: string, min: number, max: number) => {
  if (!Number.isInteger(value) || Number(value) < min || Number(value) > max) {
    throw new Error(`B03 repository requires ${label} between ${min} and ${max}`);
  }
  return Number(value);
};
const json = (value: unknown) => {
  const encoded = JSON.stringify(value ?? null);
  if (encoded === undefined || Buffer.byteLength(encoded, "utf8") > 65_536) {
    throw new Error("B03 repository requires bounded JSON data");
  }
  return encoded;
};
const stableJson = (value: unknown): string => {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  return `{${Object.keys(value as Record<string, unknown>)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableJson((value as Record<string, unknown>)[key])}`)
    .join(",")}}`;
};
export const b03PayloadDigest = (payload: unknown) =>
  createHash("sha256").update(stableJson(payload)).digest("hex");
const exactEnum = <T extends string>(value: unknown, label: string, allowed: readonly T[]) => {
  const normalized = String(value || "") as T;
  if (!allowed.includes(normalized)) throw new Error(`B03 repository rejects ${label}`);
  return normalized;
};
const boundedRows = <T>(rows: T[], max: number, functionName: string) => {
  if (!Array.isArray(rows) || rows.length > max) throw new Error(`${functionName} returned an unbounded result`);
  return rows;
};
const emailProjection = (value: unknown, label: string) => {
  if (value === null) return null;
  const normalized = String(value || "").trim().toLowerCase();
  if (!normalized || normalized.length > 320 || !normalized.includes("@")) {
    throw new Error(`B03 repository received invalid ${label}`);
  }
  return normalized;
};
const booleanProjection = (value: unknown, label: string) => {
  if (typeof value !== "boolean") throw new Error(`B03 repository received invalid ${label}`);
  return value;
};
const exactlyOne = <T>(rows: T[], functionName: string) => {
  if (rows.length !== 1) throw new Error(`${functionName} must return exactly one row`);
  return rows[0];
};
const dateCursor = (value: unknown) => {
  const encoded = optional(value, "cursor", 512);
  if (!encoded) return { createdAt: null, id: null };
  try {
    const parsed = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
    const createdAt = new Date(String(parsed?.createdAt || ""));
    const cursorId = id(parsed?.id, "cursor id");
    if (!Number.isFinite(createdAt.getTime())) throw new Error();
    return { createdAt, id: cursorId };
  } catch {
    throw new Error("B03 repository requires a valid notification cursor");
  }
};

const validateClaim = <T extends B03DurableClaim>(claim: T, allowedTypes: readonly string[]) => {
  id(claim.id, "durable job id");
  exactEnum(claim.jobType, "jobType", allowedTypes);
  uuid(claim.requestId);
  digest(claim.payloadDigest);
  text(claim.idempotencyKey, "idempotencyKey", 255);
  optional(claim.organizationId, "organizationId");
  optional(claim.licenseeId, "licenseeId");
  optional(claim.manufacturerId, "manufacturerId");
  optional(claim.initiatingUserId, "initiatingUserId");
  timestamp(claim.expiresAt, "expiresAt");
  integer(claim.attempt, "attempt", 1, 10);
  return claim;
};

export const enqueueAuditLogOutbox = async (db: B03FunctionClient, input: B03AuditEnqueueInput) =>
  exactlyOne(await db.$queryRaw<Array<{ id: string }>>(Prisma.sql`
    SELECT result."id"
    FROM app_rls.enqueue_audit_log_outbox(
      CAST(${json(input.payload)} AS jsonb), ${digest(input.payloadDigest)}::text,
      ${text(input.idempotencyKey, "idempotencyKey", 255)}::text, ${uuid(input.requestId)}::text,
      ${optional(input.organizationId, "organizationId")}::text, ${optional(input.licenseeId, "licenseeId")}::text,
      ${optional(input.manufacturerId, "manufacturerId")}::text, ${optional(input.initiatingUserId, "initiatingUserId")}::text,
      ${optional(input.initiatingActorRoleSnapshot, "initiatingActorRoleSnapshot", 64)}::text,
      ${timestamp(input.expiresAt, "expiresAt")}::timestamp without time zone,
      ${optional(input.initialErrorCode, "initialErrorCode", 128)}::text
    ) AS result
  `), "app_rls.enqueue_audit_log_outbox");

export const enqueueSecurityEventOutbox = async (db: B03FunctionClient, input: B03SiemEnqueueInput) =>
  exactlyOne(await db.$queryRaw<Array<{ id: string }>>(Prisma.sql`
    SELECT result."id"
    FROM app_rls.enqueue_security_event_outbox(
      ${exactEnum(input.eventType, "eventType", ["AUDIT_LOG", "CSP_VIOLATION"])}::text,
      CAST(${json(input.payload)} AS jsonb), ${digest(input.payloadDigest)}::text,
      ${text(input.idempotencyKey, "idempotencyKey", 255)}::text, ${uuid(input.requestId)}::text,
      ${optional(input.organizationId, "organizationId")}::text, ${optional(input.licenseeId, "licenseeId")}::text,
      ${optional(input.manufacturerId, "manufacturerId")}::text, ${optional(input.initiatingUserId, "initiatingUserId")}::text,
      CAST(${timestamp(input.expiresAt, "expiresAt")} AS timestamp without time zone)
    ) AS result
  `), "app_rls.enqueue_security_event_outbox");

export const claimAuditLogOutboxSlice = async (
  db: B03FunctionClient,
  input: { attemptedAt: Date; batchSize: number }
) => {
  const attemptedAt = timestamp(input.attemptedAt, "attemptedAt");
  const batchSize = integer(input.batchSize, "batchSize", 1, 250);
  const rows = await db.$queryRaw<B03AuditClaim[]>(Prisma.sql`
    SELECT claim."id", claim."jobType", claim."requestId", claim."payloadDigest",
      claim."idempotencyKey", claim."organizationId", claim."licenseeId",
      claim."manufacturerId", claim."initiatingUserId", claim."expiresAt", claim."attempt"
    FROM app_rls.claim_audit_log_outbox_slice(
      CAST(${attemptedAt} AS timestamp without time zone), CAST(${batchSize} AS integer)
    ) AS claim
  `);
  return boundedRows(rows, batchSize, "app_rls.claim_audit_log_outbox_slice")
    .map((row) => validateClaim(row, ["AUDIT_LOG_RECOVERY"]));
};

export const consumeAuditLogOutbox = async (
  db: B03FunctionClient,
  input: { jobId: string; payloadDigest: string; attemptedAt: Date }
) => exactlyOne(await db.$queryRaw<Array<{ auditLogId: string; replayed: boolean }>>(Prisma.sql`
  SELECT result."auditLogId", result."replayed"
  FROM app_rls.consume_audit_log_outbox(
    ${id(input.jobId, "jobId")}::text, ${digest(input.payloadDigest)}::text,
    CAST(${timestamp(input.attemptedAt, "attemptedAt")} AS timestamp without time zone)
  ) AS result
`), "app_rls.consume_audit_log_outbox");

export const failAuditLogOutbox = async (
  db: B03FunctionClient,
  input: { jobId: string; payloadDigest: string; attemptedAt: Date; attempt: number; errorCode: string }
) => exactlyOne(await db.$queryRaw<Array<{ terminal: boolean; nextAttemptAt: Date | null }>>(Prisma.sql`
  SELECT result."terminal", result."nextAttemptAt"
  FROM app_rls.fail_audit_log_outbox(
    ${id(input.jobId, "jobId")}::text, ${digest(input.payloadDigest)}::text,
    CAST(${timestamp(input.attemptedAt, "attemptedAt")} AS timestamp without time zone),
    CAST(${integer(input.attempt, "attempt", 1, 10)} AS integer),
    ${text(input.errorCode, "errorCode", 128)}::text
  ) AS result
`), "app_rls.fail_audit_log_outbox");

export const claimSecurityEventOutboxSlice = async (
  db: B03FunctionClient,
  input: { attemptedAt: Date; batchSize: number; jobType: "AUDIT_LOG" | "CSP_VIOLATION" }
) => {
  const attemptedAt = timestamp(input.attemptedAt, "attemptedAt");
  const batchSize = integer(input.batchSize, "batchSize", 1, 200);
  const rows = await db.$queryRaw<B03SiemClaim[]>(Prisma.sql`
    SELECT claim."id", claim."jobType", claim."requestId", claim."payloadDigest",
      claim."idempotencyKey", claim."organizationId", claim."licenseeId",
      claim."manufacturerId", claim."initiatingUserId", claim."expiresAt", claim."attempt",
      claim."eventType", claim."eventPayload", claim."createdAt"
    FROM app_rls.claim_security_event_outbox_slice(
      CAST(${attemptedAt} AS timestamp without time zone), CAST(${batchSize} AS integer),
      ${exactEnum(input.jobType, "jobType", ["AUDIT_LOG", "CSP_VIOLATION"])}::text
    ) AS claim
  `);
  return boundedRows(rows, batchSize, "app_rls.claim_security_event_outbox_slice").map((row) => {
    validateClaim(row, ["AUDIT_LOG", "CSP_VIOLATION"]);
    exactEnum(row.eventType, "eventType", ["AUDIT_LOG", "CSP_VIOLATION"]);
    timestamp(row.createdAt, "createdAt");
    return row;
  });
};

export const completeSecurityEventOutbox = async (
  db: B03FunctionClient,
  input: { jobId: string; payloadDigest: string; attemptedAt: Date; sinkEventId: string }
) => exactlyOne(await db.$queryRaw<Array<{ completed: boolean; replayed: boolean }>>(Prisma.sql`
  SELECT result."completed", result."replayed"
  FROM app_rls.complete_security_event_outbox(
    ${id(input.jobId, "jobId")}::text, ${digest(input.payloadDigest)}::text,
    CAST(${timestamp(input.attemptedAt, "attemptedAt")} AS timestamp without time zone),
    ${id(input.sinkEventId, "sinkEventId")}::text
  ) AS result
`), "app_rls.complete_security_event_outbox");

export const failSecurityEventOutbox = async (
  db: B03FunctionClient,
  input: { jobId: string; payloadDigest: string; attemptedAt: Date; attempt: number; errorCode: string }
) => exactlyOne(await db.$queryRaw<Array<{ terminal: boolean; nextAttemptAt: Date | null }>>(Prisma.sql`
  SELECT result."terminal", result."nextAttemptAt"
  FROM app_rls.fail_security_event_outbox(
    ${id(input.jobId, "jobId")}::text, ${digest(input.payloadDigest)}::text,
    CAST(${timestamp(input.attemptedAt, "attemptedAt")} AS timestamp without time zone),
    CAST(${integer(input.attempt, "attempt", 1, 10)} AS integer),
    ${text(input.errorCode, "errorCode", 128)}::text
  ) AS result
`), "app_rls.fail_security_event_outbox");

export const claimCompliancePackSlice = async (
  db: B03FunctionClient,
  input: { capability: string; scheduleId: string; dueAt: Date; batchSize: number }
) => {
  const batchSize = integer(input.batchSize, "batchSize", 1, 100);
  const rows = await db.$queryRaw<Array<{
  jobId: string; requestId: string; organizationId: string; licenseeId: string;
  scheduleScopeVersion: string; expiresAt: Date; attempt: number; report: Record<string, unknown>;
}>>(Prisma.sql`
  SELECT claim."jobId", claim."requestId", claim."organizationId", claim."licenseeId",
    claim."scheduleScopeVersion", claim."expiresAt", claim."attempt", claim."report"
  FROM app_rls.claim_compliance_pack_slice(
    ${text(input.capability, "scheduled capability", 43)}, ${text(input.scheduleId, "scheduleId", 128)}, ${timestamp(input.dueAt, "dueAt")},
    ${batchSize}
  ) AS claim
  `);
  return boundedRows(rows, batchSize, "app_rls.claim_compliance_pack_slice").map((row) => {
    id(row.jobId, "jobId");
    uuid(row.requestId);
    id(row.organizationId, "organizationId");
    id(row.licenseeId, "licenseeId");
    text(row.scheduleScopeVersion, "scheduleScopeVersion", 128);
    timestamp(row.expiresAt, "expiresAt");
    integer(row.attempt, "attempt", 1, 3);
    json(row.report);
    return row;
  });
};

export const completeScheduledCompliancePackJob = async (
  db: B03FunctionClient,
  input: { capability: string; scheduleId: string; requestId: string; jobId: string; result: unknown }
) => exactlyOne(await db.$queryRaw<Array<{ result: Prisma.JsonValue }>>(Prisma.sql`
  SELECT app_rls.scheduled_complete_compliance_pack_job(
    ${text(input.capability, "scheduled capability", 43)}, ${text(input.scheduleId, "scheduleId", 128)},
    ${uuid(input.requestId)}, ${id(input.jobId, "jobId")}, CAST(${json(input.result)} AS jsonb)
  ) AS result
`), "app_rls.scheduled_complete_compliance_pack_job").result;

export const failScheduledCompliancePackJob = async (
  db: B03FunctionClient,
  input: { capability: string; scheduleId: string; requestId: string; jobId: string; errorCode: string }
) => exactlyOne(await db.$queryRaw<Array<{ result: Prisma.JsonValue }>>(Prisma.sql`
  SELECT app_rls.scheduled_fail_compliance_pack_job(
    ${text(input.capability, "scheduled capability", 43)}, ${text(input.scheduleId, "scheduleId", 128)},
    ${uuid(input.requestId)}, ${id(input.jobId, "jobId")}, ${text(input.errorCode, "errorCode", 128)}
  ) AS result
`), "app_rls.scheduled_fail_compliance_pack_job").result;

export const getPrimarySuperadminEmail = async (db: B03FunctionClient) => {
  const row = exactlyOne(await db.$queryRaw<Array<{ email: string | null }>>(Prisma.sql`
    SELECT result."email" FROM app_rls.b03_primary_superadmin_email() AS result
  `), "app_rls.b03_primary_superadmin_email");
  emailProjection(row.email, "primary superadmin email");
  return row;
};

export const getSuperadminAlertEmails = async (db: B03FunctionClient) => {
  const rows = await db.$queryRaw<Array<{ email: string }>>(Prisma.sql`
    SELECT result."email" FROM app_rls.b03_superadmin_alert_emails() AS result
  `);
  return boundedRows(rows, 100, "app_rls.b03_superadmin_alert_emails").map((row) => ({
    email: emailProjection(row.email, "superadmin alert email")!,
  }));
};

export const resolveIncidentEmailActor = async (db: B03FunctionClient, actorUserId: string) => {
  const row = exactlyOne(await db.$queryRaw<Array<{
    id: string | null; email: string | null; name: string | null; role: string | null; active: boolean;
  }>>(Prisma.sql`
    SELECT result."id", result."email", result."name", result."role", result."active"
    FROM app_rls.b03_resolve_incident_email_actor(${id(actorUserId, "actorUserId")}) AS result
  `), "app_rls.b03_resolve_incident_email_actor");
  booleanProjection(row.active, "actor active state");
  if (row.active) {
    id(row.id, "actor id");
    emailProjection(row.email, "actor email");
    text(row.role, "actor role", 64);
  }
  optional(row.name, "actor name", 255);
  return row;
};

export const createRoleNotifications = (db: B03FunctionClient, input: B03RoleNotificationInput) => {
  const channels = input.channels.map((channel) => exactEnum(channel, "channel", ["WEB", "EMAIL"]));
  if (!channels.length || channels.length > 2 || new Set(channels).size !== channels.length) {
    throw new Error("B03 repository requires unique notification channels");
  }
  return db.$queryRaw<B03NotificationDeliveryRow[]>(Prisma.sql`
    SELECT result."notificationId", result."userId", result."userEmail", result."userRole",
      result."userLicenseeId", result."userOrganizationId", result."channel", result."writeResult",
      result."sideEffectRequired"
    FROM app_rls.b03_create_role_notifications(
      ${exactEnum(input.audience, "audience", ["SUPER_ADMIN", "LICENSEE_ADMIN", "MANUFACTURER", "ALL"])},
      ${text(input.title, "title", 255)}, ${text(input.body, "body", 10_000)},
      ${text(input.notificationType, "notificationType", 128)},
      ${optional(input.licenseeId, "licenseeId")}, ${optional(input.organizationId, "organizationId")},
      ${optional(input.incidentId, "incidentId")}, CAST(${json(input.data)} AS jsonb),
      ${channels}, ${authenticatedRequestId(input.requestId)}
    ) AS result
  `).then((rows) => boundedRows(rows, 1_000, "app_rls.b03_create_role_notifications").map((row) => {
    id(row.notificationId, "notificationId");
    optional(row.userId, "userId");
    emailProjection(row.userEmail, "notification user email");
    optional(row.userRole, "notification user role", 64);
    optional(row.userLicenseeId, "notification user licenseeId");
    optional(row.userOrganizationId, "notification user organizationId");
    exactEnum(row.channel, "notification result channel", ["WEB", "EMAIL"]);
    json(row.writeResult);
    booleanProjection(row.sideEffectRequired, "notification side-effect state");
    return row;
  }));
};

export const createUserNotification = async (db: B03FunctionClient, input: B03UserNotificationInput) => {
  const row = exactlyOne(await db.$queryRaw<Array<B03NotificationDeliveryRow & { notification: Prisma.JsonObject }>>(Prisma.sql`
    SELECT result."notificationId", result."userId", result."userEmail", result."userRole",
      result."userLicenseeId", result."userOrganizationId", result."channel", result."writeResult",
      result."sideEffectRequired", result."notification"
    FROM app_rls.b03_create_user_notification(
      ${id(input.userId, "userId")}, ${text(input.title, "title", 255)},
      ${text(input.body, "body", 10_000)}, ${text(input.notificationType, "notificationType", 128)},
      ${optional(input.licenseeId, "licenseeId")}, ${optional(input.organizationId, "organizationId")},
      ${optional(input.incidentId, "incidentId")}, CAST(${json(input.data)} AS jsonb),
      ${exactEnum(input.channel, "channel", ["WEB", "EMAIL"])}, ${authenticatedRequestId(input.requestId)}
    ) AS result
  `), "app_rls.b03_create_user_notification");
  id(row.notificationId, "notificationId");
  if (row.userId !== id(input.userId, "userId")) throw new Error("B03 user notification result changed owner");
  emailProjection(row.userEmail, "notification user email");
  optional(row.userRole, "notification user role", 64);
  optional(row.userLicenseeId, "notification user licenseeId");
  optional(row.userOrganizationId, "notification user organizationId");
  exactEnum(row.channel, "notification result channel", ["WEB", "EMAIL"]);
  booleanProjection(row.sideEffectRequired, "notification side-effect state");
  json(row.notification);
  return row;
};

export const markNotificationEmailed = async (
  db: B03FunctionClient,
  input: { notificationId: string; requestId: string; emailedAt: Date }
) => exactlyOne(await db.$queryRaw<Array<{ updated: boolean }>>(Prisma.sql`
  SELECT result."updated"
  FROM app_rls.b03_mark_notification_emailed(
    ${id(input.notificationId, "notificationId")}, ${timestamp(input.emailedAt, "emailedAt")},
    ${authenticatedRequestId(input.requestId)}
  ) AS result
`), "app_rls.b03_mark_notification_emailed");

export const listNotificationsForUser = async (
  db: B03FunctionClient,
  input: { userId: string; limit: number; offset: number; unreadOnly: boolean; cursor?: string | null; requestId: string }
) => {
  const limit = integer(input.limit, "limit", 1, 100);
  const cursor = dateCursor(input.cursor);
  const row = exactlyOne(await db.$queryRaw<Array<{
  notifications: Prisma.JsonArray; total: number | null; unread: number;
}>>(Prisma.sql`
  SELECT result."notifications", result."total", result."unread"
  FROM app_rls.b03_list_notifications_for_user(
    ${id(input.userId, "userId")}::text, ${limit}::integer,
    ${integer(input.offset, "offset", 0, 1_000_000)}::integer, ${Boolean(input.unreadOnly)}::boolean,
    ${cursor.createdAt}::timestamp without time zone, ${cursor.id}::text,
    ${authenticatedRequestId(input.requestId)}::text
  ) AS result
  `), "app_rls.b03_list_notifications_for_user");
  if (!Array.isArray(row.notifications) || row.notifications.length > limit) {
    throw new Error("app_rls.b03_list_notifications_for_user returned an unbounded result");
  }
  if (row.total !== null) integer(row.total, "total", 0, 1_000_000_000);
  integer(row.unread, "unread", 0, 1_000_000_000);
  json(row.notifications);
  return row;
};

export const readAttentionQueueProjection = async (
  db: B03FunctionClient,
  input: { licenseeId?: string | null; since: Date; requestId: string }
) => {
  const row = exactlyOne(await db.$queryRaw<Array<{ result: Prisma.JsonValue }>>(Prisma.sql`
    SELECT app_rls.b03_attention_queue_projection(
      ${optional(input.licenseeId, "licenseeId")}::text,
      ${timestamp(input.since, "since")}::timestamp without time zone,
      ${authenticatedRequestId(input.requestId)}::text
    ) AS result
  `), "app_rls.b03_attention_queue_projection");
  if (!row.result || typeof row.result !== "object" || Array.isArray(row.result)) {
    throw new Error("app_rls.b03_attention_queue_projection returned an invalid projection");
  }
  for (const key of ["incidents", "policyAlerts", "supportTickets", "auditEvents"] as const) {
    const section = row.result[key];
    if (!section || typeof section !== "object" || Array.isArray(section)) {
      throw new Error("app_rls.b03_attention_queue_projection returned an invalid section");
    }
    integer(section.count, `${key} count`, 0, 1_000_000_000);
  }
  return row.result as unknown as B03AttentionQueueProjection;
};

export const markNotificationRead = async (
  db: B03FunctionClient,
  input: { notificationId: string; userId: string; requestId: string; readAt: Date }
) => {
  const row = exactlyOne(await db.$queryRaw<Array<{ notification: Prisma.JsonObject | null }>>(Prisma.sql`
  SELECT result."notification"
  FROM app_rls.b03_mark_notification_read(
    ${id(input.notificationId, "notificationId")}, ${id(input.userId, "userId")},
    ${timestamp(input.readAt, "readAt")}, ${authenticatedRequestId(input.requestId)}
  ) AS result
  `), "app_rls.b03_mark_notification_read");
  json(row.notification);
  return row;
};

export const markAllNotificationsRead = async (
  db: B03FunctionClient,
  input: { userId: string; requestId: string; readAt: Date }
) => {
  const row = exactlyOne(await db.$queryRaw<Array<{ count: number }>>(Prisma.sql`
  SELECT result."count"
  FROM app_rls.b03_mark_all_notifications_read(
    ${id(input.userId, "userId")}, ${timestamp(input.readAt, "readAt")}, ${authenticatedRequestId(input.requestId)}
  ) AS result
  `), "app_rls.b03_mark_all_notifications_read");
  integer(row.count, "count", 0, 1_000_000_000);
  return row;
};

export const resolveIncidentNotificationScope = async (db: B03FunctionClient, incidentId: string) =>
  exactlyOne(await db.$queryRaw<Array<{
    incidentId: string; licenseeId: string | null; manufacturerOrganizationId: string | null;
  }>>(Prisma.sql`
    SELECT result."incidentId", result."licenseeId", result."manufacturerOrganizationId"
    FROM app_rls.b03_resolve_incident_notification_scope(${id(incidentId, "incidentId")}) AS result
  `), "app_rls.b03_resolve_incident_notification_scope");

export const claimIncidentEmailDelivery = async (
  db: B03FunctionClient,
  input: Omit<B03IncidentEmailDeliveryInput, "providerMessageId" | "emailErrorCode" | "status" | "smtpConfigSource"> & {
    idempotencyKey: string;
    payloadDigest: string;
  }
) => {
  const row = exactlyOne(await db.$queryRaw<B03IncidentEmailClaim[]>(Prisma.sql`
    SELECT result."deliveryId", result."disposition", result."delivered",
      result."providerMessageId", result."emailErrorCode", result."attemptedFrom",
      result."usedFrom", result."replyTo"
    FROM app_rls.b03_claim_incident_email_delivery(
      ${id(input.incidentId, "incidentId")}, ${optional(input.licenseeId, "licenseeId")},
      ${optional(input.actorUserId, "actorUserId")}, ${exactEnum(input.senderMode, "senderMode", ["actor", "system"])},
      ${text(input.toAddress, "toAddress", 320)}, ${text(input.subject, "subject", 998)},
      ${bounded(input.bodyPreview, "bodyPreview", 500)}, ${optional(input.attemptedFrom, "attemptedFrom", 320)},
      ${optional(input.usedFrom, "usedFrom", 320)}, ${optional(input.replyTo, "replyTo", 320)},
      ${optional(input.template, "template", 128)}, ${authenticatedRequestId(input.requestId)},
      ${digest(input.idempotencyKey)}, ${digest(input.payloadDigest)}
    ) AS result
  `), "app_rls.b03_claim_incident_email_delivery");
  id(row.deliveryId, "deliveryId");
  exactEnum(row.disposition, "incident email claim disposition", ["CLAIMED", "REPLAY_SENT", "REPLAY_FAILED", "IN_FLIGHT"]);
  booleanProjection(row.delivered, "incident email delivered state");
  optional(row.providerMessageId, "providerMessageId", 512);
  if (row.emailErrorCode !== null) {
    exactEnum(row.emailErrorCode, "emailErrorCode", [
      "SMTP_CONFIG_MISSING", "SMTP_AUTH_FAILED", "SMTP_CONNECTION_FAILED", "SMTP_TLS_FAILED",
      "SMTP_TIMEOUT", "SMTP_RECIPIENT_REJECTED", "SMTP_NO_ACCEPTED_RECIPIENTS",
      "SMTP_SEND_FAILED", "EMAIL_DISABLED", "EMAIL_DRY_RUN", "UNKNOWN_EMAIL_ERROR",
    ]);
  }
  optional(row.attemptedFrom, "attemptedFrom", 320);
  optional(row.usedFrom, "usedFrom", 320);
  optional(row.replyTo, "replyTo", 320);
  return row;
};

export const completeIncidentEmailDelivery = async (
  db: B03FunctionClient,
  input: Pick<B03IncidentEmailDeliveryInput, "providerMessageId" | "emailErrorCode" | "status" | "smtpConfigSource"> & {
    deliveryId: string;
    idempotencyKey: string;
    usedFrom?: string | null;
    completedAt: Date;
  }
) => exactlyOne(await db.$queryRaw<Array<{
    communicationId: string; eventId: string; auditLogId: string;
  }>>(Prisma.sql`
    SELECT result."communicationId", result."eventId", result."auditLogId"
    FROM app_rls.b03_complete_incident_email_delivery(
      ${id(input.deliveryId, "deliveryId")}, ${digest(input.idempotencyKey)},
      ${optional(input.providerMessageId, "providerMessageId", 512)},
      ${optional(input.emailErrorCode, "emailErrorCode", 128)},
      ${exactEnum(input.status, "status", ["QUEUED", "SENT", "FAILED"])},
      ${optional(input.smtpConfigSource, "smtpConfigSource", 128)},
      ${optional(input.usedFrom, "usedFrom", 320)},
      ${timestamp(input.completedAt, "completedAt")}
    ) AS result
  `), "app_rls.b03_complete_incident_email_delivery");

const supportProjection = (value: Prisma.JsonValue, operation: string) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${operation} returned an invalid projection`);
  }
  return value as Record<string, unknown>;
};

export const listSupportTickets = async (
  db: B03FunctionClient,
  input: {
    licenseeId?: string | null;
    status?: string | null;
    priority?: string | null;
    search?: string | null;
    limit: number;
    offset: number;
    requestId: string;
  }
) => {
  const limit = integer(input.limit, "support ticket limit", 1, 200);
  const row = exactlyOne(await db.$queryRaw<Array<{ result: Prisma.JsonValue }>>(Prisma.sql`
    SELECT app_rls.b03_list_support_tickets(
      ${optional(input.licenseeId, "licenseeId")}::text,
      ${input.status ? exactEnum(input.status, "support ticket status", ["OPEN","IN_PROGRESS","WAITING_CUSTOMER","RESOLVED","CLOSED"]) : null}::text,
      ${input.priority ? exactEnum(input.priority, "support ticket priority", ["P1","P2","P3","P4"]) : null}::text,
      ${optional(input.search, "search", 120)}::text,
      ${limit}::integer, ${integer(input.offset, "support ticket offset", 0, 2_000)}::integer,
      ${authenticatedRequestId(input.requestId)}::text
    ) AS result
  `), "app_rls.b03_list_support_tickets");
  const result = supportProjection(row.result, "app_rls.b03_list_support_tickets");
  if (!Array.isArray(result.tickets) || result.tickets.length > limit) {
    throw new Error("app_rls.b03_list_support_tickets returned an unbounded result");
  }
  integer(result.total, "support ticket total", 0, 1_000_000_000);
  return result;
};

export const getSupportTicket = async (
  db: B03FunctionClient,
  input: { ticketId: string; requestId: string }
) => {
  const row = exactlyOne(await db.$queryRaw<Array<{ result: Prisma.JsonValue | null }>>(Prisma.sql`
    SELECT app_rls.b03_get_support_ticket(
      ${id(input.ticketId, "ticketId")}::text, ${authenticatedRequestId(input.requestId)}::text
    ) AS result
  `), "app_rls.b03_get_support_ticket");
  return row.result === null ? null : supportProjection(row.result, "app_rls.b03_get_support_ticket");
};

export const updateSupportTicket = async (
  db: B03FunctionClient,
  input: {
    ticketId: string;
    status?: string;
    assignedToUserId?: string | null;
    changedAt: Date;
    requestId: string;
  }
) => {
  const row = exactlyOne(await db.$queryRaw<Array<{ result: Prisma.JsonValue | null }>>(Prisma.sql`
    SELECT app_rls.b03_update_support_ticket(
      ${id(input.ticketId, "ticketId")}::text,
      ${input.status ? exactEnum(input.status, "support ticket status", ["OPEN","IN_PROGRESS","WAITING_CUSTOMER","RESOLVED","CLOSED"]) : null}::text,
      ${input.assignedToUserId ? id(input.assignedToUserId, "assignedToUserId") : null}::text,
      ${input.assignedToUserId !== undefined}::boolean,
      ${timestamp(input.changedAt, "changedAt")}::timestamp without time zone,
      ${authenticatedRequestId(input.requestId)}::text
    ) AS result
  `), "app_rls.b03_update_support_ticket");
  return row.result === null ? null : supportProjection(row.result, "app_rls.b03_update_support_ticket");
};

export const addSupportTicketMessage = async (
  db: B03FunctionClient,
  input: { ticketId: string; message: string; isInternal: boolean; createdAt: Date; requestId: string }
) => {
  const row = exactlyOne(await db.$queryRaw<Array<{ result: Prisma.JsonValue | null }>>(Prisma.sql`
    SELECT app_rls.b03_add_support_ticket_message(
      ${id(input.ticketId, "ticketId")}::text, ${text(input.message, "support ticket message", 4_000)}::text,
      ${Boolean(input.isInternal)}::boolean, ${timestamp(input.createdAt, "createdAt")}::timestamp without time zone,
      ${authenticatedRequestId(input.requestId)}::text
    ) AS result
  `), "app_rls.b03_add_support_ticket_message");
  return row.result === null ? null : supportProjection(row.result, "app_rls.b03_add_support_ticket_message");
};
