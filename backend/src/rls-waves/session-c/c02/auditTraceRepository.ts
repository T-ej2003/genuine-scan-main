import { Prisma, UserRole } from "@prisma/client";

import { CanonicalDbContext } from "../../../lib/canonicalDbContext";
import { getAdminStepUpWindowMinutes } from "../../../services/auth/authService";
import { AuthenticatedSessionClaims } from "../../../types";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const platformRoles = new Set<UserRole>([UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN]);

export class AuditTraceAccessError extends Error {
  constructor(message: string, readonly statusCode = 403) {
    super(message);
  }
}

export const buildFraudResponseBoundary = (
  user: AuthenticatedSessionClaims,
  requestId: string
): CanonicalDbContext => {
  const userId = String(user?.userId || "").trim();
  const normalizedRequestId = String(requestId || "").trim();
  if (!UUID_RE.test(userId) || !UUID_RE.test(normalizedRequestId) || user?.sessionStage !== "ACTIVE") {
    throw new AuditTraceAccessError("Authenticated fraud-response context is invalid", 401);
  }
  if (!platformRoles.has(user.role)) throw new AuditTraceAccessError("Platform fraud-response authority is required");
  const verifiedAt = Date.parse(String(user.mfaVerifiedAt || ""));
  if (
    user.authAssurance !== "ADMIN_MFA" ||
    !Number.isFinite(verifiedAt) ||
    Date.now() - verifiedAt > getAdminStepUpWindowMinutes() * 60_000
  ) {
    throw new AuditTraceAccessError("Fresh administrator MFA is required", 428);
  }
  if (user.licenseeId || user.orgId) throw new AuditTraceAccessError("Platform actor scope is stale");

  return {
    userId,
    role: String(user.role),
    organizationId: null,
    licenseeId: null,
    manufacturerId: null,
    authAssurance: "mfa-verified",
    requestId: normalizedRequestId,
    purpose: "platform-fraud-report-response",
  };
};

type JsonRow = { result: Prisma.JsonValue };

export const respondToFraudReportInTransaction = async <T>(
  tx: Pick<Prisma.TransactionClient, "$queryRaw">,
  input: {
    reportId: string;
    status: "REVIEWED" | "RESOLVED" | "DISMISSED";
    message?: string | null;
    notifyCustomer: boolean;
  }
) => {
  const rows = await tx.$queryRaw<JsonRow[]>`
    SELECT app_rls.c02_respond_fraud_report(
      ${input.reportId},
      ${input.status},
      ${input.message || null},
      ${input.notifyCustomer}
    ) AS result
  `;
  const result = rows[0]?.result;
  if (!result || typeof result !== "object" || Array.isArray(result)) {
    throw new Error("respond to fraud report returned an invalid database result");
  }
  return result as T;
};
