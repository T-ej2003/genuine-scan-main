import { randomUUID } from "crypto";

import { Prisma, PrismaClient } from "@prisma/client";

import prisma from "../../config/database";

export type ProcedureDatabase = Pick<PrismaClient, "$transaction">;

type ProcedureContext = {
  purpose: string;
  requestId?: string;
  actorId?: string;
  assurance: "operator-approved" | "dual-approved-break-glass" | "system-verified";
  environment: "development" | "staging" | "production";
  licenseeId?: string | null;
};

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const exactUuid = (value: string, field: string) => {
  const normalized = String(value || "").trim().toLowerCase();
  if (!UUID.test(normalized)) throw new Error(`${field} must be a UUID.`);
  return normalized;
};

const boundedText = (value: string, field: string, maximum: number) => {
  const normalized = String(value || "").trim();
  if (!normalized) throw new Error(`${field} is required.`);
  if (normalized.length > maximum) throw new Error(`${field} must not exceed ${maximum} characters.`);
  return normalized;
};

const oneRow = <T>(rows: T[], procedure: string) => {
  if (rows.length !== 1) throw new Error(`${procedure} returned an invalid result cardinality.`);
  return rows[0];
};

const inProcedureTransaction = async <T>(
  db: ProcedureDatabase,
  context: ProcedureContext,
  run: (tx: Prisma.TransactionClient) => Promise<T[]>,
  procedure: string
) => {
  const purpose = boundedText(context.purpose, "purpose", 160);
  const requestId = exactUuid(context.requestId || randomUUID(), "requestId");
  const actorId = context.actorId ? exactUuid(context.actorId, "actorId") : "";
  const licenseeId = context.licenseeId ? exactUuid(context.licenseeId, "licenseeId") : "";
  return db.$transaction(async (tx) => {
    await tx.$executeRaw(
      Prisma.sql`SELECT set_config('app.user_id', ${actorId}, true),
                        set_config('app.licensee_id', ${licenseeId}, true),
                        set_config('app.auth_assurance', ${context.assurance}, true),
                        set_config('app.operator_environment', ${context.environment}, true),
                        set_config('app.request_id', ${requestId}, true),
                        set_config('app.purpose', ${purpose}, true),
                        set_config('app.context_installed', '1', true)`
    );
    return oneRow(await run(tx), procedure);
  }, { isolationLevel: Prisma.TransactionIsolationLevel.Serializable });
};

export type PrintDiagnosticResult = {
  batchId: string;
  printJobId: string | null;
  printState: string | null;
  itemCounts: Prisma.JsonValue;
  redactedFailureCodes: Prisma.JsonValue;
};

export const runPrintDiagnostic = async (
  input: ProcedureContext & { batchId: string; operatorId: string },
  db: ProcedureDatabase = prisma
) => {
  const batchId = exactUuid(input.batchId, "batchId");
  const operatorId = exactUuid(input.operatorId, "operatorId");
  return inProcedureTransaction<PrintDiagnosticResult>(
    db,
    { ...input, actorId: operatorId },
    (tx) =>
      tx.$queryRaw(Prisma.sql`
        SELECT batch_id AS "batchId",
               print_job_id AS "printJobId",
               print_state AS "printState",
               item_counts AS "itemCounts",
               redacted_failure_codes AS "redactedFailureCodes"
          FROM app_ops.print_diagnostic(${batchId}::uuid)
      `),
    "app_ops.print_diagnostic"
  );
};

export type OperatorMutationResult = {
  operationId: string;
  status?: string;
  affectedCount?: number;
  deliveryQueued?: boolean;
  auditEventId: string;
};

export const reissueAccountSetupLink = async (
  input: ProcedureContext & {
    targetUserId: string;
    operatorId: string;
    reason: string;
    approvalId: string;
  },
  db: ProcedureDatabase = prisma
) => {
  const targetUserId = exactUuid(input.targetUserId, "targetUserId");
  const operatorId = exactUuid(input.operatorId, "operatorId");
  const reason = boundedText(input.reason, "reason", 500);
  const approvalId = exactUuid(input.approvalId, "approvalId");
  return inProcedureTransaction<OperatorMutationResult>(
    db,
    { ...input, actorId: operatorId },
    (tx) =>
      tx.$queryRaw(Prisma.sql`
        SELECT operation_id AS "operationId",
               delivery_queued AS "deliveryQueued",
               audit_event_id AS "auditEventId"
          FROM app_ops.reissue_account_setup_link(
            ${targetUserId}::uuid,
            ${operatorId}::uuid,
            ${reason}::text,
            ${approvalId}::uuid
          )
      `),
    "app_ops.reissue_account_setup_link"
  );
};

export const resetAccountMfaBreakGlass = async (
  input: ProcedureContext & {
    targetUserId: string;
    executorId: string;
    reason: string;
    approvalId: string;
  },
  db: ProcedureDatabase = prisma
) => {
  const targetUserId = exactUuid(input.targetUserId, "targetUserId");
  const executorId = exactUuid(input.executorId, "executorId");
  const reason = boundedText(input.reason, "reason", 500);
  const approvalId = exactUuid(input.approvalId, "approvalId");
  return inProcedureTransaction<OperatorMutationResult>(
    db,
    { ...input, actorId: executorId },
    (tx) =>
      tx.$queryRaw(Prisma.sql`
        SELECT operation_id AS "operationId",
               status,
               affected_count::integer AS "affectedCount",
               audit_event_id AS "auditEventId"
          FROM app_ops.reset_account_mfa(
            ${targetUserId}::uuid,
            ${executorId}::uuid,
            ${reason}::text,
            ${approvalId}::uuid
          )
      `),
    "app_ops.reset_account_mfa"
  );
};

export const prepareRlsValidationFixture = async (
  input: ProcedureContext & {
    fixtureId: string;
    tenantKey: string;
    approvalId: string;
    operatorId: string;
  },
  db: ProcedureDatabase = prisma
) => {
  const fixtureId = exactUuid(input.fixtureId, "fixtureId");
  const tenantKey = boundedText(input.tenantKey, "tenantKey", 64);
  if (!/^[a-z0-9][a-z0-9_-]{2,63}$/i.test(tenantKey)) throw new Error("tenantKey has an invalid shape.");
  const approvalId = exactUuid(input.approvalId, "approvalId");
  const operatorId = exactUuid(input.operatorId, "operatorId");
  return inProcedureTransaction<OperatorMutationResult>(
    db,
    { ...input, actorId: operatorId },
    (tx) =>
      tx.$queryRaw(Prisma.sql`
        SELECT operation_id AS "operationId",
               status,
               affected_count::integer AS "affectedCount",
               audit_event_id AS "auditEventId"
          FROM app_ops.prepare_rls_validation_fixture(
            ${fixtureId}::uuid,
            ${tenantKey}::text,
            ${approvalId}::uuid
          )
      `),
    "app_ops.prepare_rls_validation_fixture"
  );
};

export type BootstrapSuperAdminResult = {
  status: "created" | "skipped_existing" | "blocked";
  userId: string | null;
  email: string | null;
  role: string | null;
  autoVerified: boolean | null;
  reason: string | null;
  auditEventId: string;
};

export const bootstrapConfiguredSuperAdminProcedure = async (
  input: ProcedureContext & {
    email: string;
    passwordHash: string;
    name: string;
    autoVerify: boolean;
  },
  db: ProcedureDatabase = prisma
) => {
  const email = boundedText(input.email, "email", 320);
  const passwordHash = boundedText(input.passwordHash, "passwordHash", 1024);
  const name = boundedText(input.name, "name", 160);
  return inProcedureTransaction<BootstrapSuperAdminResult>(
    db,
    input,
    (tx) =>
      tx.$queryRaw(Prisma.sql`
        SELECT status,
               user_id AS "userId",
               email,
               role,
               auto_verified AS "autoVerified",
               reason,
               audit_event_id AS "auditEventId"
          FROM app_ops.bootstrap_configured_super_admin(
            ${email}::text,
            ${passwordHash}::text,
            ${name}::text,
            ${input.autoVerify}::boolean
          )
      `),
    "app_ops.bootstrap_configured_super_admin"
  );
};
