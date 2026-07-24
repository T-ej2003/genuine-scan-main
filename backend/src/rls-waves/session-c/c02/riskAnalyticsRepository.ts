import { Prisma } from "@prisma/client";

import { getB01AuthenticatedPrisma } from "../../session-b/b01/runtimeClients";

type RiskAnalyticsDb = Pick<Prisma.TransactionClient, "$queryRaw">;

export class RiskAnalyticsBoundaryDenied extends Error {
  constructor() {
    super("RISK_ANALYTICS_DENIED");
    this.name = "RiskAnalyticsBoundaryDenied";
  }
}

export const isRiskAnalyticsBoundaryDenied = (error: unknown) =>
  error instanceof RiskAnalyticsBoundaryDenied ||
  /RISK_ANALYTICS_DENIED|AUTH_SESSION_CAPABILITY_DENIED|42501/.test(
    String((error as { meta?: { message?: unknown }; message?: unknown })?.meta?.message ||
      (error as { message?: unknown })?.message || "")
  );

export const readRiskAnalyticsSnapshot = async <T>(input: {
  capability: string;
  requestId: string;
  licenseeId: string;
  expectedUserId: string;
  lookbackHours: number;
  limit: number;
  checkedAt: Date;
}, db: RiskAnalyticsDb = getB01AuthenticatedPrisma()) => {
  if (!input.capability || !input.requestId) throw new RiskAnalyticsBoundaryDenied();
  try {
    const rows = await db.$queryRaw<Array<{ result: Prisma.JsonValue }>>`
      SELECT app_rls.risk_analytics_snapshot(
        ${input.capability},${"tenant-risk-analytics"},${input.requestId},${input.licenseeId},
        ${input.expectedUserId},${input.lookbackHours}::integer,${input.limit}::integer,
        ${input.checkedAt}::timestamp without time zone
      ) AS result
    `;
    if (rows.length !== 1 || !rows[0].result || typeof rows[0].result !== "object" || Array.isArray(rows[0].result)) {
      throw new Error("Risk analytics returned an invalid database snapshot");
    }
    return rows[0].result as T;
  } catch (error) {
    if (isRiskAnalyticsBoundaryDenied(error)) throw new RiskAnalyticsBoundaryDenied();
    throw error;
  }
};
