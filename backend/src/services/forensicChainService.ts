import { createHash } from "crypto";
import { ForensicEventType } from "@prisma/client";

import prisma from "../config/database";

const stableStringify = (value: any): string => {
  if (value === null || value === undefined) return "null";
  if (typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => stableStringify(item)).join(",")}]`;

  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
};

const sha256Hex = (value: string) => createHash("sha256").update(value).digest("hex");

const mapAuditToForensicType = (input: {
  action: string;
  entityType: string;
}): ForensicEventType | null => {
  const action = String(input.action || "").trim().toUpperCase();
  const entityType = String(input.entityType || "").trim().toUpperCase();

  if (
    action === "DIRECT_PRINT_TOKEN_ISSUED" ||
    action === "DIRECT_PRINT_ITEM_ISSUED" ||
    action === "PRINT_SESSION_TOKENS_ISSUED"
  ) {
    return ForensicEventType.PRINT_ISSUANCE;
  }

  if (
    action === "PRINT_CONFIRMED" ||
    action === "DIRECT_PRINT_ITEM_CONFIRMED" ||
    (action === "PRINTED" && (entityType === "PRINTJOB" || entityType === "QRCODE" || entityType === "PRINTITEM"))
  ) {
    return ForensicEventType.PRINT_CONFIRM;
  }

  if (action === "VERIFY_SUCCESS" || action === "REDEEMED") {
    return ForensicEventType.SCAN_VERIFY;
  }

  if (action === "BLOCKED" || action === "DIRECT_PRINT_FAIL_STOP") {
    return ForensicEventType.SECURITY_BLOCK;
  }

  return null;
};

const chainScopeFor = (licenseeId?: string | null) => {
  const normalized = String(licenseeId || "").trim();
  return normalized ? `LICENSEE:${normalized}` : "GLOBAL";
};

export const appendForensicChainFromAuditLog = async (auditLog: {
  id: string;
  action: string;
  entityType: string;
  entityId?: string | null;
  userId?: string | null;
  orgId?: string | null;
  licenseeId?: string | null;
  details?: any;
  createdAt: Date;
}) => {
  const eventType = mapAuditToForensicType({
    action: auditLog.action,
    entityType: auditLog.entityType,
  });

  if (!eventType) return null;

  const chainScope = chainScopeFor(auditLog.licenseeId || null);

  const payload = {
    auditLogId: auditLog.id,
    action: auditLog.action,
    entityType: auditLog.entityType,
    entityId: auditLog.entityId || null,
    userId: auditLog.userId || null,
    orgId: auditLog.orgId || null,
    licenseeId: auditLog.licenseeId || null,
    details: auditLog.details ?? null,
    createdAt: auditLog.createdAt.toISOString(),
  };

  const payloadHash = sha256Hex(stableStringify(payload));

  const previous = await prisma.forensicEventChain.findFirst({
    where: { chainScope },
    orderBy: [{ createdAt: "desc" }, { id: "desc" }],
    select: { eventHash: true },
  });

  const previousHash = previous?.eventHash || sha256Hex(`GENESIS:${chainScope}`);
  const eventHash = sha256Hex(`${previousHash}|${eventType}|${payloadHash}`);

  const existing = await prisma.forensicEventChain.findFirst({
    where: {
      auditLogId: auditLog.id,
      eventType,
      chainScope,
    },
    select: { id: true },
  });
  if (existing) return null;

  return prisma.forensicEventChain.create({
    data: {
      eventType,
      chainScope,
      previousHash,
      payloadHash,
      eventHash,
      payload,
      auditLogId: auditLog.id,
      licenseeId: auditLog.licenseeId || null,
      createdAt: auditLog.createdAt,
    },
  });
};
