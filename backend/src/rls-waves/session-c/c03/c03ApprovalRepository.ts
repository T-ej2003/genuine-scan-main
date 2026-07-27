import { Prisma } from "@prisma/client";

type ApprovalDb = Pick<Prisma.TransactionClient, "$queryRaw">;
type JsonRow = { result: Prisma.JsonValue };

const json = (value: unknown) => JSON.stringify(value ?? {});

const requiredObject = <T>(rows: JsonRow[], operation: string): T => {
  if (rows.length !== 1) {
    throw new Error(`${operation} returned an invalid database result`);
  }
  const result = rows[0]?.result;
  if (!result || typeof result !== "object" || Array.isArray(result)) {
    throw new Error(`${operation} returned an invalid database result`);
  }
  return result as T;
};

export const createSensitiveApprovalInTransaction = async <T>(
  tx: ApprovalDb,
  input: Record<string, unknown>
) =>
  requiredObject<T>(
    await tx.$queryRaw<JsonRow[]>`
      SELECT app_rls.c03_create_sensitive_action_approval(${json(input)}::jsonb) AS result
    `,
    "create sensitive action approval"
  );

export const listSensitiveApprovalsInTransaction = async <T>(
  tx: ApprovalDb,
  input: { status?: string | null; limit: number; offset: number }
) => {
  const rows = await tx.$queryRaw<JsonRow[]>`
    SELECT result
      FROM app_rls.c03_list_sensitive_action_approvals(
        ${input.status || null},
        ${input.limit},
        ${input.offset}
      ) AS listed(result)
  `;
  return rows.map((row) => {
    if (!row.result || typeof row.result !== "object" || Array.isArray(row.result)) {
      throw new Error("list sensitive action approvals returned an invalid database result");
    }
    return row.result as T;
  });
};

export const approveSensitiveApprovalInTransaction = async <T>(
  tx: ApprovalDb,
  approvalId: string,
  reviewNote?: string | null
) =>
  requiredObject<T>(
    await tx.$queryRaw<JsonRow[]>`
      SELECT app_rls.c03_approve_sensitive_action_approval(
        ${approvalId},
        ${reviewNote || null}
      ) AS result
    `,
    "approve sensitive action approval"
  );

export const rejectSensitiveApprovalInTransaction = async <T>(
  tx: ApprovalDb,
  approvalId: string,
  reviewNote?: string | null
) =>
  requiredObject<T>(
    await tx.$queryRaw<JsonRow[]>`
      SELECT app_rls.c03_reject_sensitive_action_approval(
        ${approvalId},
        ${reviewNote || null}
      ) AS result
    `,
    "reject sensitive action approval"
  );
