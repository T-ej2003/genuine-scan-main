import { Prisma } from "@prisma/client";

type ComplianceDb = Pick<Prisma.TransactionClient, "$queryRaw" | "compliancePackJob">;
type JsonRow = { result: Prisma.JsonValue };

const json = (value: unknown) => JSON.stringify(value ?? {});

const requiredObject = <T>(rows: JsonRow[], operation: string): T => {
  const result = rows[0]?.result;
  if (!result || typeof result !== "object" || Array.isArray(result)) {
    throw new Error(`${operation} returned an invalid database result`);
  }
  return result as T;
};

export type CompliancePackStart = {
  job: Record<string, any> & { id: string; licenseeId: string };
  report: Record<string, any>;
};

export const startCompliancePackJobInTransaction = async (
  tx: ComplianceDb,
  input: { triggerType: "MANUAL" | "SCHEDULED"; from?: Date | null; to?: Date | null }
) =>
  requiredObject<CompliancePackStart>(
    await tx.$queryRaw<JsonRow[]>`
      SELECT app_rls.c03_start_compliance_pack_job(
        ${input.triggerType},
        ${input.from || null}::timestamptz,
        ${input.to || null}::timestamptz
      ) AS result
    `,
    "start compliance pack job"
  );

export const completeCompliancePackJobInTransaction = async <T>(
  tx: ComplianceDb,
  jobId: string,
  result: Record<string, unknown>
) =>
  requiredObject<T>(
    await tx.$queryRaw<JsonRow[]>`
      SELECT app_rls.c03_complete_compliance_pack_job(${jobId}, ${json(result)}::jsonb) AS result
    `,
    "complete compliance pack job"
  );

export const failCompliancePackJobInTransaction = async <T>(
  tx: ComplianceDb,
  jobId: string,
  errorCode: string
) =>
  requiredObject<T>(
    await tx.$queryRaw<JsonRow[]>`
      SELECT app_rls.c03_fail_compliance_pack_job(${jobId}, ${errorCode}) AS result
    `,
    "fail compliance pack job"
  );

export const listCompliancePackJobsInTransaction = async (
  tx: ComplianceDb,
  input: { licenseeId: string; limit: number; offset: number }
) => {
  const where = { licenseeId: input.licenseeId };
  const [jobs, total] = await Promise.all([
    tx.compliancePackJob.findMany({
      where,
      orderBy: [{ startedAt: "desc" }, { id: "desc" }],
      take: input.limit,
      skip: input.offset,
      select: {
        id: true,
        licenseeId: true,
        status: true,
        triggerType: true,
        periodFrom: true,
        periodTo: true,
        fileName: true,
        signatureAlgorithm: true,
        startedByUserId: true,
        startedAt: true,
        finishedAt: true,
        createdAt: true,
        updatedAt: true,
      },
    }),
    tx.compliancePackJob.count({ where }),
  ]);
  return { jobs, total };
};

export const loadCompliancePackJobInTransaction = async <T>(tx: ComplianceDb, jobId: string) =>
  requiredObject<T>(
    await tx.$queryRaw<JsonRow[]>`
      SELECT app_rls.c03_get_compliance_pack_job(${jobId}) AS result
    `,
    "load compliance pack job"
  );

export const completeCompliancePackRebuildInTransaction = async <T>(
  tx: ComplianceDb,
  jobId: string,
  result: Record<string, unknown>
) =>
  requiredObject<T>(
    await tx.$queryRaw<JsonRow[]>`
      SELECT app_rls.c03_complete_compliance_pack_rebuild(${jobId}, ${json(result)}::jsonb) AS result
    `,
    "complete compliance pack rebuild"
  );
