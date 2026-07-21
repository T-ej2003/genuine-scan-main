import { Prisma, PrismaClient } from "@prisma/client";

import prisma from "../../../config/database";

export type B03SystemIdentity = "identity-worker" | "identity-scheduled-job";
export type B03JobType =
  | "ANALYTICS_INVENTORY_ROLLUP"
  | "ANALYTICS_SCAN_HOURLY_ROLLUP"
  | "AUDIT_LOG"
  | "AUDIT_LOG_RECOVERY"
  | "CSP_VIOLATION"
  | "SCHEDULED_COMPLIANCE_PACK";

export type B03SystemContext = {
  systemIdentity: B03SystemIdentity;
  jobId: string;
  jobType: B03JobType;
  requestId: string;
  organizationId?: string | null;
  licenseeId?: string | null;
  manufacturerId?: string | null;
  initiatingUserId?: string | null;
};

type TransactionRunner = Pick<PrismaClient, "$transaction">;

const required = (value: unknown, label: string) => {
  const normalized = String(value || "").trim();
  if (!normalized) throw new Error(`B03 system boundary requires ${label}`);
  return normalized;
};

const requestIdPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const transactionTimeoutMs = () => {
  const configured = Number(process.env.MSCQR_RLS_B03_TRANSACTION_TIMEOUT_MS || 120_000);
  return Number.isFinite(configured) ? Math.max(5_000, Math.min(300_000, Math.floor(configured))) : 120_000;
};

const validated = (
  context: B03SystemContext,
  acceptedJobTypes: ReadonlySet<B03JobType>
): Required<B03SystemContext> & { expectedDatabaseRole: string } => {
  const systemIdentity = required(context.systemIdentity, "a system identity") as B03SystemIdentity;
  const jobType = required(context.jobType, "an allowlisted job type") as B03JobType;
  if (!acceptedJobTypes.has(jobType)) {
    throw new Error(`B03 system boundary rejects job type ${jobType} for ${systemIdentity}`);
  }

  const requestId = required(context.requestId, "a request ID");
  if (!requestIdPattern.test(requestId)) {
    throw new Error("B03 system boundary requires a UUID request ID");
  }

  return {
    systemIdentity,
    expectedDatabaseRole: configuredB03DatabaseRole(systemIdentity),
    jobId: required(context.jobId, "a durable job ID"),
    jobType,
    requestId: requestId.toLowerCase(),
    organizationId: String(context.organizationId || "").trim() || null,
    licenseeId: String(context.licenseeId || "").trim() || null,
    manufacturerId: String(context.manufacturerId || "").trim() || null,
    initiatingUserId: String(context.initiatingUserId || "").trim() || null,
  };
};

export const configuredB03DatabaseRole = (identity: B03SystemIdentity) => {
  const key = identity === "identity-worker" ? "MSCQR_WORKER_DATABASE_ROLE" : "MSCQR_SCHEDULED_DATABASE_ROLE";
  return required(process.env[key], `${key} trusted runtime configuration`);
};

export const b03WorkerBoundariesEnabled = () =>
  ["1", "true", "yes", "on"].includes(
    String(process.env.MSCQR_RLS_B03_WORKER_BOUNDARIES_ENABLED || "").trim().toLowerCase()
  );

const withB03SystemContext = async <T>(
  contextInput: B03SystemContext,
  acceptedJobTypes: ReadonlySet<B03JobType>,
  callback: (tx: Prisma.TransactionClient) => Promise<T>,
  runner: TransactionRunner = prisma
) => {
  const context = validated(contextInput, acceptedJobTypes);
  return runner.$transaction(async (tx) => {
    const [identity] = await tx.$queryRaw<Array<{ databaseRole: string }>>(Prisma.sql`
      SELECT current_user::text AS "databaseRole"
    `);
    if (identity?.databaseRole !== context.expectedDatabaseRole) {
      throw new Error("B03 system boundary database role mismatch");
    }

    await tx.$queryRaw(Prisma.sql`
      SELECT
        set_config('app.system_identity', ${context.systemIdentity}, true),
        set_config('app.job_id', ${context.jobId}, true),
        set_config('app.job_type', ${context.jobType}, true),
        set_config('app.organization_id', ${context.organizationId || ""}, true),
        set_config('app.licensee_id', ${context.licenseeId || ""}, true),
        set_config('app.manufacturer_id', ${context.manufacturerId || ""}, true),
        set_config('app.initiating_user_id', ${context.initiatingUserId || ""}, true),
        set_config('app.request_id', ${context.requestId}, true),
        set_config('app.auth_assurance', 'system-verified', true),
        set_config('app.user_id', '', true),
        set_config('app.role', '', true),
        set_config('app.is_platform_admin', 'false', true)
    `);

    return callback(tx);
  }, { maxWait: 5_000, timeout: transactionTimeoutMs() });
};

type BoundaryInput = Omit<B03SystemContext, "systemIdentity" | "jobType">;

export const withB03AuditWorkerContext = <T>(
  input: BoundaryInput,
  callback: (tx: Prisma.TransactionClient) => Promise<T>,
  runner: TransactionRunner = prisma
) => withB03SystemContext(
  { ...input, systemIdentity: "identity-worker", jobType: "AUDIT_LOG_RECOVERY" },
  new Set(["AUDIT_LOG_RECOVERY"]),
  callback,
  runner
);

export const withB03SiemWorkerContext = <T>(
  input: BoundaryInput & { jobType: "AUDIT_LOG" | "CSP_VIOLATION" },
  callback: (tx: Prisma.TransactionClient) => Promise<T>,
  runner: TransactionRunner = prisma
) => withB03SystemContext(
  { ...input, systemIdentity: "identity-worker" },
  new Set(["AUDIT_LOG", "CSP_VIOLATION"]),
  callback,
  runner
);

export const withB03AnalyticsWorkerContext = <T>(
  input: BoundaryInput & { jobType: "ANALYTICS_INVENTORY_ROLLUP" | "ANALYTICS_SCAN_HOURLY_ROLLUP" },
  callback: (tx: Prisma.TransactionClient) => Promise<T>,
  runner: TransactionRunner = prisma
) => withB03SystemContext(
  { ...input, systemIdentity: "identity-worker" },
  new Set(["ANALYTICS_INVENTORY_ROLLUP", "ANALYTICS_SCAN_HOURLY_ROLLUP"]),
  callback,
  runner
);

export const withB03ScheduledContext = <T>(
  input: BoundaryInput,
  callback: (tx: Prisma.TransactionClient) => Promise<T>,
  runner: TransactionRunner = prisma
) => withB03SystemContext(
  { ...input, systemIdentity: "identity-scheduled-job", jobType: "SCHEDULED_COMPLIANCE_PACK" },
  new Set(["SCHEDULED_COMPLIANCE_PACK"]),
  callback,
  runner
);
