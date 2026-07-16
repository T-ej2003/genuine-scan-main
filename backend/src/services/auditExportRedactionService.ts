import { UserRole } from "@prisma/client";

export const hiddenActionsForNonSuper = ["CUSTOMER_FRAUD_REPORT", "CUSTOMER_FRAUD_REPORT_RESPONSE"];

export const isAuditSuperUser = (role?: UserRole | null) =>
  role === UserRole.SUPER_ADMIN || role === UserRole.PLATFORM_SUPER_ADMIN;

export const isAuditManufacturerUser = (role?: UserRole | null) =>
  role === UserRole.MANUFACTURER ||
  role === UserRole.MANUFACTURER_ADMIN ||
  role === UserRole.MANUFACTURER_USER;

export const coerceAuditDetails = (details: unknown): Record<string, any> => {
  if (!details || typeof details !== "object" || Array.isArray(details)) return {};
  return details as Record<string, any>;
};

const auditCsvHeaders = (isSuper: boolean) =>
  isSuper
    ? ["createdAt", "action", "entityType", "entityId", "userId", "userName", "userEmail", "licenseeId", "ipAddress", "details"]
    : ["createdAt", "action", "entityType", "userName", "userEmail"];

const escapeCsv = (val: unknown) => {
  const s = val == null ? "" : String(val);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};

const sensitiveDetailKey = /(?:password|token|secret|credential|authorization|cookie|private.?key|mfa|otp|hash)/i;

const redactDetails = (value: unknown, depth = 0): unknown => {
  if (depth > 8) return "[REDACTED]";
  if (Array.isArray(value)) return value.map((item) => redactDetails(item, depth + 1));
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).map(([key, item]) => [
      key,
      sensitiveDetailKey.test(key) ? "[REDACTED]" : redactDetails(item, depth + 1),
    ])
  );
};

export const emptyAuditCsv = (isSuper: boolean) => `${auditCsvHeaders(isSuper).join(",")}\n`;

export const buildAuditLogsCsv = (
  logs: Array<{
    createdAt?: Date | string | null;
    action?: string | null;
    entityType?: string | null;
    entityId?: string | null;
    userId?: string | null;
    licenseeId?: string | null;
    ipAddress?: string | null;
    details?: unknown;
  }>,
  userMap: Map<string, { id: string; name: string; email: string }>,
  isSuper: boolean
) => {
  const lines = [auditCsvHeaders(isSuper).join(",")];
  for (const log of logs) {
    const user = log.userId ? userMap.get(log.userId) : null;
    const createdAt =
      log.createdAt && typeof log.createdAt === "object" && "toISOString" in log.createdAt
        ? log.createdAt.toISOString()
        : log.createdAt;
    const baseRow = [
      escapeCsv(createdAt),
      escapeCsv(log.action),
      escapeCsv(log.entityType),
      escapeCsv(user?.name || ""),
      escapeCsv(user?.email || ""),
    ];
    lines.push(
      (isSuper
        ? [
            baseRow[0],
            baseRow[1],
            baseRow[2],
            escapeCsv(log.entityId),
            escapeCsv(log.userId),
            baseRow[3],
            baseRow[4],
            escapeCsv(log.licenseeId),
            escapeCsv(log.ipAddress),
            escapeCsv(log.details ? JSON.stringify(redactDetails(log.details)) : ""),
          ]
        : baseRow
      ).join(",")
    );
  }
  return lines.join("\n");
};
