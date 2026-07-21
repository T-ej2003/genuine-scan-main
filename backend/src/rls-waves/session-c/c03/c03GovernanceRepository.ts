import { Prisma } from "@prisma/client";

type GovernanceDb = Pick<Prisma.TransactionClient, "$queryRaw" | "tenantFeatureFlag">;
type JsonRow = { result: Prisma.JsonValue };

const json = (value: unknown) => JSON.stringify(value ?? {});

const requiredObject = <T>(rows: JsonRow[], operation: string): T => {
  const result = rows[0]?.result;
  if (!result || typeof result !== "object" || Array.isArray(result)) {
    throw new Error(`${operation} returned an invalid database result`);
  }
  return result as T;
};

export const listTenantFeatureFlagsInTransaction = (
  tx: GovernanceDb,
  licenseeId: string
) =>
  tx.tenantFeatureFlag.findMany({
    where: { licenseeId },
    orderBy: [{ key: "asc" }, { id: "asc" }],
    select: {
      id: true,
      licenseeId: true,
      key: true,
      enabled: true,
      updatedAt: true,
    },
  });

export const upsertTenantFeatureFlagInTransaction = async <T>(
  tx: GovernanceDb,
  input: { key: string; enabled: boolean; config?: unknown }
) =>
  requiredObject<T>(
    await tx.$queryRaw<JsonRow[]>`
      SELECT app_rls.c03_upsert_tenant_feature_flag(
        ${input.key},
        ${input.enabled},
        ${json(input.config ?? null)}::jsonb
      ) AS result
    `,
    "upsert tenant feature flag"
  );

export const getOrCreateRetentionPolicyInTransaction = async <T>(tx: GovernanceDb) =>
  requiredObject<T>(
    await tx.$queryRaw<JsonRow[]>`
      SELECT app_rls.c03_get_or_create_retention_policy() AS result
    `,
    "get or create retention policy"
  );

export const updateRetentionPolicyInTransaction = async <T>(
  tx: GovernanceDb,
  patch: Record<string, unknown>
) =>
  requiredObject<T>(
    await tx.$queryRaw<JsonRow[]>`
      SELECT app_rls.c03_update_retention_policy(${json(patch)}::jsonb) AS result
    `,
    "update retention policy"
  );

export type RetentionLifecycleResult = {
  job: Record<string, unknown> & { id: string };
  policy: Record<string, unknown>;
  cutoffAt: string | Date;
  evaluated: number;
  eligible: number;
  purged: number;
  exported: number;
  storageKeysToDelete?: string[];
};

export const runRetentionLifecycleInTransaction = async (
  tx: GovernanceDb,
  input: { mode: "PREVIEW" | "APPLY"; approvalId?: string | null }
) =>
  requiredObject<RetentionLifecycleResult>(
    await tx.$queryRaw<JsonRow[]>`
      SELECT app_rls.c03_run_retention_lifecycle(
        ${input.mode},
        ${input.approvalId || null}
      ) AS result
    `,
    "run retention lifecycle"
  );

export const loadIncidentEvidenceAuditSnapshotInTransaction = async <T>(
  tx: GovernanceDb,
  incidentId: string
) =>
  requiredObject<T>(
    await tx.$queryRaw<JsonRow[]>`
      SELECT app_rls.c03_build_incident_evidence_audit_snapshot(${incidentId}) AS result
    `,
    "build incident evidence audit snapshot"
  );

export const generateComplianceReportInTransaction = async <T>(
  tx: GovernanceDb,
  input: { from?: Date | null; to?: Date | null }
) =>
  requiredObject<T>(
    await tx.$queryRaw<JsonRow[]>`
      SELECT app_rls.c03_generate_compliance_report(
        ${input.from || null}::timestamptz,
        ${input.to || null}::timestamptz
      ) AS result
    `,
    "generate compliance report"
  );
