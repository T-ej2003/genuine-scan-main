import { Prisma, UserRole } from "@prisma/client";

import { CanonicalDbContext } from "../lib/canonicalDbContext";
import { AuthenticatedSessionClaims } from "../types";
import { getAdminStepUpWindowMinutes } from "./auth/authService";
import { coerceAuditDetails, redactAuditDetails } from "./auditExportRedactionService";

export type FraudReportStatus = "ALL" | "OPEN" | "REVIEWED" | "RESOLVED" | "DISMISSED";

export type FraudReportQuery = {
  licenseeId: string;
  purpose: string;
  status: FraudReportStatus;
  limit: number;
  offset: number;
};

export class FraudReportAccessError extends Error {
  constructor(message: string, readonly statusCode = 403) {
    super(message);
  }
}

export const buildFraudReportBoundary = (
  user: AuthenticatedSessionClaims,
  query: FraudReportQuery,
  requestId: string
): CanonicalDbContext => {
  const userId = String(user?.userId || "").trim();
  const normalizedRequestId = String(requestId || "").trim();
  const licenseeId = String(query.licenseeId || "").trim();
  const purpose = String(query.purpose || "").trim();
  if (!userId || !normalizedRequestId || user?.sessionStage !== "ACTIVE") {
    throw new FraudReportAccessError("Authenticated actor context is required", 401);
  }
  if (user.role !== UserRole.SUPER_ADMIN && user.role !== UserRole.PLATFORM_SUPER_ADMIN) {
    throw new FraudReportAccessError("Access denied");
  }
  if (user.authAssurance !== "ADMIN_MFA") throw new FraudReportAccessError("Fresh administrator MFA is required");
  const mfaVerifiedAt = Date.parse(String(user.mfaVerifiedAt || ""));
  if (!Number.isFinite(mfaVerifiedAt) || Date.now() - mfaVerifiedAt > getAdminStepUpWindowMinutes() * 60_000) {
    throw new FraudReportAccessError("Fresh administrator MFA is required");
  }
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(licenseeId)) {
    throw new FraudReportAccessError("A valid bounded licensee scope is required", 400);
  }
  if (!purpose) throw new FraudReportAccessError("An explicit fraud-report purpose is required");
  if (purpose.length > 240) throw new FraudReportAccessError("Fraud-report purpose is too long", 400);
  if (!Number.isInteger(query.limit) || query.limit < 1 || query.limit > 500 || !Number.isInteger(query.offset) || query.offset < 0 || query.offset > 20_000) {
    throw new FraudReportAccessError("Fraud-report pagination is out of bounds", 400);
  }

  return {
    userId,
    role: String(user.role),
    organizationId: user.orgId || null,
    licenseeId,
    manufacturerId: null,
    authAssurance: "mfa-verified",
    requestId: normalizedRequestId,
    purpose,
  };
};

export const queryFraudReports = async (
  tx: Prisma.TransactionClient,
  query: FraudReportQuery,
  context: CanonicalDbContext
) => {
  if (query.licenseeId !== context.licenseeId) throw new FraudReportAccessError("Fraud-report scope does not match canonical context");
  const where: Prisma.AuditLogWhereInput = {
    action: "CUSTOMER_FRAUD_REPORT",
    licenseeId: context.licenseeId,
  };
  const [total, reportLogs] = await Promise.all([
    tx.auditLog.count({ where }),
    tx.auditLog.findMany({
      where,
      select: { id: true, createdAt: true, licenseeId: true, details: true, ipAddress: true },
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: query.limit,
      skip: query.offset,
    }),
  ]);
  const reportIds = reportLogs.map((log) => log.id);
  const responseLogs = reportIds.length
    ? await tx.auditLog.findMany({
        where: {
          action: "CUSTOMER_FRAUD_REPORT_RESPONSE",
          licenseeId: context.licenseeId,
          OR: reportIds.map((id) => ({ details: { path: ["reportId"], equals: id } })),
        },
        select: { id: true, createdAt: true, userId: true, details: true },
        orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      })
    : [];

  const latestResponseByReportId = new Map<string, (typeof responseLogs)[number]>();
  for (const log of responseLogs) {
    const reportId = String(coerceAuditDetails(log.details).reportId || "");
    if (reportId && !latestResponseByReportId.has(reportId)) latestResponseByReportId.set(reportId, log);
  }
  const reports = reportLogs
    .map((reportLog) => {
      const reportDetails = coerceAuditDetails(reportLog.details);
      const responseLog = latestResponseByReportId.get(reportLog.id);
      const responseDetails = coerceAuditDetails(responseLog?.details);
      const status = String(responseDetails.status || "OPEN").toUpperCase();
      return {
        id: reportLog.id,
        createdAt: reportLog.createdAt,
        licenseeId: reportLog.licenseeId || null,
        report: {
          code: reportDetails.code || null,
          reason: reportDetails.reason || null,
          notes: reportDetails.notes || null,
          contactEmail: reportDetails.contactEmail || null,
          observedStatus: reportDetails.observedStatus || null,
          observedOutcome: reportDetails.observedOutcome || null,
          pageUrl: reportDetails.pageUrl || null,
          userAgent: reportDetails.userAgent || null,
          ipAddress: reportLog.ipAddress || null,
        },
        status,
        response: responseLog
          ? {
              id: responseLog.id,
              createdAt: responseLog.createdAt,
              message: responseDetails.message || null,
              notifyCustomer: Boolean(responseDetails.notifyCustomer),
              recipientEmail: responseDetails.recipientEmail || null,
              delivery: redactAuditDetails(responseDetails.delivery || null),
              actorUserId: responseLog.userId || null,
            }
          : null,
      };
    })
    .filter((report) => query.status === "ALL" || report.status === query.status);

  await tx.auditLog.create({
    data: {
      userId: context.userId,
      orgId: context.organizationId,
      licenseeId: context.licenseeId,
      action: "AUDIT_FRAUD_REPORTS_READ",
      entityType: "AuditLog",
      entityId: context.licenseeId,
      details: {
        purpose: context.purpose,
        requestId: context.requestId,
        status: query.status,
        limit: query.limit,
        offset: query.offset,
        matchingRows: total,
        returnedRows: reports.length,
      },
    },
    select: { id: true },
  });

  return { reports, total: reports.length, limit: query.limit, offset: query.offset };
};
