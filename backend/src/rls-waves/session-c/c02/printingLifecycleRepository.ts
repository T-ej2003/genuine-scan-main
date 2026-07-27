import { Prisma } from "@prisma/client";
import { createHash } from "crypto";

import prisma from "../../../config/database";

type SqlClient = Pick<typeof prisma, "$queryRaw">;
type PrintingIdempotencyAction = "PRINT_JOB_CREATE" | "PRINTER_TEST_LABEL";

const stableStringify = (value: unknown): string => {
  if (value == null) return "null";
  if (typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(object[key])}`).join(",")}}`;
};
const digest = (value: string) => createHash("sha256").update(value).digest("hex");
const idempotencyHashes = (action: PrintingIdempotencyAction, actorScope: string, key: string, payload: unknown) => ({
  keyHash: digest(`idem:${action}:${actorScope}:${key}`),
  requestHash: digest(`${action}|${actorScope}|${stableStringify(payload)}`),
});

const oneJson = async (client: SqlClient, query: Prisma.Sql) => {
  const rows = await client.$queryRaw<Array<{ result: unknown }>>(query);
  if (rows.length !== 1) throw new Error("PRINTING_BOUNDARY_INVALID_RESULT");
  return rows[0].result as any;
};

export const readPrintingProjection = (input: {
  capability: string;
  requestId: string;
  operation: "BATCH" | "JOB" | "JOB_LIST" | "ATTENTION_QUEUE" | "RELEASE" | "REISSUE" | "REISSUE_REQUEST" | "REISSUE_LIST" | "PRINTABLE_ITEMS" | "PRINTER" | "PRINTER_LIST" | "PRINTER_STATUS" | "VALIDATION_EVIDENCE";
  subjectId: string;
  options?: Record<string, unknown>;
  client?: SqlClient;
}) =>
  oneJson(input.client || prisma, Prisma.sql`
    SELECT app_rls.printing_readiness(
      ${input.capability}::text,'printing-readiness'::text,${input.requestId}::text,
      ${input.operation}::text,${input.subjectId}::text,${input.options || {}}::jsonb
    ) AS result
  `);

export const administerPrintingPrinter = (input: {
  capability: string;
  requestId: string;
  operation: "CREATE" | "UPDATE" | "DELETE" | "RELINK" | "AUDIT_TEST" | "AUDIT_TEST_LABEL_ATTENTION" | "AUDIT_TEST_LABEL_CONFIRMED" | "AUDIT_TEST_LABEL_QUEUED" | "AUDIT_DISCOVERY";
  printerId?: string | null;
  payload?: Record<string, unknown>;
  client?: SqlClient;
}) =>
  oneJson(input.client || prisma, Prisma.sql`
    SELECT app_rls.printing_printer_administration(
      ${input.capability}::text,'printing-printer-admin'::text,${input.requestId}::text,
      ${input.operation}::text,${input.printerId || null}::text,
      ${input.payload || {}}::jsonb
    ) AS result
  `);

export const beginPrintingIdempotency = (input: {
  capability: string;
  requestId: string;
  action: PrintingIdempotencyAction;
  actorScope: string;
  key: string;
  payload: unknown;
  client?: SqlClient;
}) => {
  const hashes = idempotencyHashes(input.action, input.actorScope, input.key, input.payload);
  return oneJson(input.client || prisma, Prisma.sql`
    SELECT app_rls.printing_idempotency(
      ${input.capability}::text,'printing-idempotency'::text,${input.requestId}::text,
      'BEGIN'::text,${input.action}::text,${hashes.keyHash}::text,${hashes.requestHash}::text,
      NULL::integer,'{}'::jsonb
    ) AS result
  `);
};

export const completePrintingIdempotency = (input: {
  capability: string;
  requestId: string;
  action: PrintingIdempotencyAction;
  actorScope: string;
  key: string;
  payload: unknown;
  statusCode: number;
  responsePayload: Record<string, unknown>;
  client?: SqlClient;
}) => {
  const hashes = idempotencyHashes(input.action, input.actorScope, input.key, input.payload);
  return oneJson(input.client || prisma, Prisma.sql`
    SELECT app_rls.printing_idempotency(
      ${input.capability}::text,'printing-idempotency'::text,${input.requestId}::text,
      'COMPLETE'::text,${input.action}::text,${hashes.keyHash}::text,${hashes.requestHash}::text,
      ${input.statusCode}::integer,${input.responsePayload}::jsonb
    ) AS result
  `);
};

export const abortPrintingIdempotency = (input: {
  capability: string;
  requestId: string;
  action: PrintingIdempotencyAction;
  actorScope: string;
  key: string;
  payload: unknown;
  client?: SqlClient;
}) => {
  const hashes = idempotencyHashes(input.action, input.actorScope, input.key, input.payload);
  return oneJson(input.client || prisma, Prisma.sql`
    SELECT app_rls.printing_idempotency(
      ${input.capability}::text,'printing-idempotency'::text,${input.requestId}::text,
      'ABORT'::text,${input.action}::text,${hashes.keyHash}::text,${hashes.requestHash}::text,
      NULL::integer,'{}'::jsonb
    ) AS result
  `);
};

export const registerPrintingConnector = (input: {
  capability: string;
  requestId: string;
  operation: "LOOKUP" | "HEARTBEAT";
  payload?: Record<string, unknown>;
  client?: SqlClient;
}) =>
  oneJson(input.client || prisma, Prisma.sql`
    SELECT app_rls.printing_connector_registration(
      ${input.capability}::text,'printing-connector-registration'::text,
      ${input.requestId}::text,${input.operation}::text,${input.payload || {}}::jsonb
    ) AS result
  `);

export const mutatePrintingTestLabelJob = (input: {
  capability?: string | null;
  requestId: string;
  operation: "QUEUE" | "CLAIM" | "ACK" | "CONFIRM" | "FAIL";
  printerId: string;
  connector?: Record<string, unknown>;
  job?: Record<string, unknown>;
  client?: SqlClient;
}) =>
  oneJson(input.client || prisma, Prisma.sql`
    SELECT app_rls.printing_test_label_job(
      ${input.capability || null}::text,${input.requestId}::text,${input.operation}::text,
      ${input.printerId}::text,${input.connector || {}}::jsonb,${input.job || {}}::jsonb
    ) AS result
  `);

export const createPrintingJob = (input: {
  capability: string;
  requestId: string;
  batchId: string;
  printerId: string;
  quantity: number;
  rangeStart?: string | null;
  rangeEnd?: string | null;
  printMode: string;
  payloadType: string;
  printLockTokenHash?: string | null;
  items: Array<{ qrCodeId: string; tokenNonce: string; tokenHash: string; tokenExpiresAt: string }>;
  client?: SqlClient;
}) => {
  const items = JSON.stringify(input.items);
  return oneJson(input.client || prisma, Prisma.sql`
    SELECT app_rls.printing_create_job(
      ${input.capability}::text,'printing-create-job'::text,${input.requestId}::text,
      ${input.batchId}::text,${input.printerId}::text,${input.quantity}::integer,
      ${input.rangeStart || null}::text,${input.rangeEnd || null}::text,
      ${input.printMode}::text,${input.payloadType}::text,${input.printLockTokenHash || null}::text,
      ${items}::jsonb
    ) AS result
  `);
};

export const controlPrintingJob = (input: {
  capability: string;
  requestId: string;
  jobId: string;
  operation: "PAUSE" | "RESUME" | "STOP" | "ABANDON";
  reason?: string | null;
  client?: SqlClient;
}) =>
  oneJson(input.client || prisma, Prisma.sql`
    SELECT app_rls.printing_control_job(
      ${input.capability}::text,'printing-job-control'::text,${input.requestId}::text,
      ${input.jobId}::text,${input.operation}::text,${input.reason || null}::text
    ) AS result
  `);

export const recordConnectorEvent = (input: {
  registrationId: string;
  agentId: string;
  deviceFingerprint: string;
  nonce: string;
  issuedAt: Date | string;
  requestId: string;
  operation: "CLAIM" | "ACK" | "CONFIRM" | "FAIL";
  jobId: string;
  itemId?: string | null;
  printerId: string;
  payloadHash?: string | null;
  deviceJobRef?: string | null;
  details?: Record<string, unknown>;
  client?: SqlClient;
}) =>
  oneJson(input.client || prisma, Prisma.sql`
    SELECT app_rls.printing_connector_event(
      ${input.registrationId}::text,${input.agentId}::text,${input.deviceFingerprint}::text,
      ${input.nonce}::text,${new Date(input.issuedAt)}::timestamp,${input.requestId}::text,
      ${input.operation}::text,${input.jobId}::text,${input.itemId || null}::text,
      ${input.printerId}::text,${input.payloadHash || null}::text,
      ${input.deviceJobRef || null}::text,${input.details || {}}::jsonb
    ) AS result
  `);

export const resolvePrintingConnectorIdentity = (input: {
  kind: "LOCAL_AGENT" | "SITE_GATEWAY";
  agentId?: string | null;
  deviceFingerprint?: string | null;
  printerSelector?: string | null;
  gatewayId?: string | null;
  gatewaySecretHash?: string | null;
  operation?: "VERIFY" | "HEARTBEAT";
  client?: SqlClient;
}) =>
  oneJson(input.client || prisma, Prisma.sql`
    SELECT app_rls.printing_connector_identity(
      ${input.kind}::text,${input.agentId || null}::text,${input.deviceFingerprint || null}::text,
      ${input.printerSelector || null}::text,${input.gatewayId || null}::text,
      ${input.gatewaySecretHash || null}::text,${input.operation || "VERIFY"}::text
    ) AS result
  `);

export const recordGatewayPrintingEvent = (input: {
  gatewayId: string;
  gatewaySecretHash: string;
  requestId: string;
  operation: "CLAIM" | "ACK" | "CONFIRM" | "FAIL";
  mode: "NETWORK_DIRECT" | "NETWORK_IPP";
  jobId?: string | null;
  itemId?: string | null;
  details?: Record<string, unknown>;
  client?: SqlClient;
}) =>
  oneJson(input.client || prisma, Prisma.sql`
    SELECT app_rls.printing_gateway_job(
      ${input.gatewayId}::text,${input.gatewaySecretHash}::text,${input.requestId}::text,
      ${input.operation}::text,${input.mode}::text,${input.jobId || null}::text,
      ${input.itemId || null}::text,${input.details || {}}::jsonb
    ) AS result
  `);

export const recordPrintingSample = (input: {
  capability: string;
  requestId: string;
  jobId: string;
  code: string;
  evidence?: Record<string, unknown>;
  client?: SqlClient;
}) =>
  oneJson(input.client || prisma, Prisma.sql`
    SELECT app_rls.printing_record_sample(
      ${input.capability}::text,'printing-sample-scan'::text,${input.requestId}::text,
      ${input.jobId}::text,${input.code}::text,${input.evidence || {}}::jsonb
    ) AS result
  `);

export const releasePrintingBatch = (input: {
  capability: string;
  requestId: string;
  batchId: string;
  decision: "REQUEST" | "APPROVE" | "REJECT";
  reason?: string | null;
  client?: SqlClient;
}) =>
  oneJson(input.client || prisma, Prisma.sql`
    SELECT app_rls.printing_release_batch(
      ${input.capability}::text,'printing-release'::text,${input.requestId}::text,
      ${input.batchId}::text,${input.decision}::text,${input.reason || null}::text
    ) AS result
  `);

export const mutatePrintingReissueRequest = (input: {
  capability: string;
  requestId: string;
  operation: "CREATE" | "FORWARD" | "APPROVE" | "REJECT" | "CANCEL" | "EXECUTE";
  reissueId?: string | null;
  originalJobId?: string | null;
  quantity?: number | null;
  rangeStart?: string | null;
  rangeEnd?: string | null;
  reason?: string | null;
  decisionNote?: string | null;
  client?: SqlClient;
}) =>
  oneJson(input.client || prisma, Prisma.sql`
    SELECT app_rls.printing_reissue_request(
      ${input.capability}::text,'printing-reissue'::text,${input.requestId}::text,
      ${input.operation}::text,${input.reissueId || null}::text,${input.originalJobId || null}::text,
      ${input.quantity || null}::integer,${input.rangeStart || null}::text,${input.rangeEnd || null}::text,
      ${input.reason || null}::text,${input.decisionNote || null}::text
    ) AS result
  `);

export const reconcilePrintingLifecycle = async (input: {
  operation: "EXPIRE_CONFIRMATIONS" | "RECONCILE_BATCHES";
  requestId: string;
  limit: number;
  client?: SqlClient;
}) => {
  const rows = await (input.client || prisma).$queryRaw<Array<{ result: number }>>(Prisma.sql`
    SELECT app_rls.printing_worker_reconcile(
      ${input.operation}::text,${input.requestId}::text,${input.limit}::integer
    ) AS result
  `);
  if (rows.length !== 1) throw new Error("PRINTING_BOUNDARY_INVALID_RESULT");
  return Number(rows[0].result);
};

export const runNetworkPrintingWorker = (input: {
  operation: "CLAIM_DIRECT" | "CLAIM_IPP" | "CONFIRM" | "FAIL";
  requestId: string;
  jobId?: string | null;
  details?: Record<string, unknown>;
  client?: SqlClient;
}) =>
  oneJson(input.client || prisma, Prisma.sql`
    SELECT app_rls.printing_worker_network_job(
      ${input.operation}::text,${input.requestId}::text,${input.jobId || null}::text,
      ${input.details || {}}::jsonb
    ) AS result
  `);
