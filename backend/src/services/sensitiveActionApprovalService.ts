import { Prisma, UserRole, QRStatus, PrinterCommandLanguage, PrinterConnectionType, PrinterDeliveryMode } from "@prisma/client";
import { z } from "zod";

import prisma from "../config/database";
import { createAuditLog } from "./auditService";
import { hashIp, hashToken, normalizeUserAgent } from "../utils/security";
import { runRetentionLifecycle, updateRetentionPolicy, upsertTenantFeatureFlag } from "./governanceService";
import { upsertManagedNetworkPrinter } from "./printerRegistryService";

export const SENSITIVE_ACTION_KEYS = {
  FEATURE_FLAG_UPSERT: "FEATURE_FLAG_UPSERT",
  RETENTION_POLICY_PATCH: "RETENTION_POLICY_PATCH",
  RETENTION_APPLY: "RETENTION_APPLY",
  QR_BLOCK: "QR_BLOCK",
  BATCH_BLOCK: "BATCH_BLOCK",
  PRINTER_GATEWAY_SECRET_ROTATION: "PRINTER_GATEWAY_SECRET_ROTATION",
} as const;

export type SensitiveActionKey = (typeof SENSITIVE_ACTION_KEYS)[keyof typeof SENSITIVE_ACTION_KEYS];

const ACTION_STATUS = {
  PENDING: "PENDING",
  APPROVED: "APPROVED",
  REJECTED: "REJECTED",
  EXECUTED: "EXECUTED",
  FAILED: "FAILED",
  EXPIRED: "EXPIRED",
} as const;

const approvalTtlMinutes = () => {
  const raw = Number(String(process.env.SENSITIVE_APPROVAL_TTL_MINUTES || "").trim());
  if (Number.isFinite(raw) && raw > 0) return Math.floor(raw);
  return 24 * 60;
};

const featureFlagPayloadSchema = z.object({
  licenseeId: z.string().uuid(),
  key: z.string().trim().min(3).max(120),
  enabled: z.boolean(),
  config: z.unknown().optional(),
}).strict();

const retentionPolicyPayloadSchema = z.object({
  licenseeId: z.string().uuid(),
  retentionDays: z.number().int().min(30).max(3650).optional(),
  purgeEnabled: z.boolean().optional(),
  exportBeforePurge: z.boolean().optional(),
  legalHoldTags: z.array(z.string().trim().min(1).max(40)).max(20).optional(),
}).strict();

const retentionApplyPayloadSchema = z.object({
  licenseeId: z.string().uuid(),
}).strict();

const qrBlockPayloadSchema = z.object({
  qrId: z.string().uuid(),
  reason: z.string().trim().max(500).optional().nullable(),
}).strict();

const batchBlockPayloadSchema = z.object({
  batchId: z.string().uuid(),
  reason: z.string().trim().max(500).optional().nullable(),
}).strict();

const printerRotationPayloadSchema = z.object({
  printerId: z.string().uuid(),
  userId: z.string().uuid(),
  orgId: z.string().uuid().optional().nullable(),
  licenseeId: z.string().uuid().optional().nullable(),
  name: z.string().trim().min(2).max(180),
  vendor: z.string().trim().max(180).optional().nullable(),
  model: z.string().trim().max(180).optional().nullable(),
  connectionType: z.nativeEnum(PrinterConnectionType),
  commandLanguage: z.nativeEnum(PrinterCommandLanguage).optional().nullable(),
  ipAddress: z.string().trim().max(120).optional().nullable(),
  host: z.string().trim().max(180).optional().nullable(),
  port: z.number().int().min(1).max(65535).nullable(),
  resourcePath: z.string().trim().max(240).optional().nullable(),
  tlsEnabled: z.boolean().optional().nullable(),
  printerUri: z.string().trim().max(512).optional().nullable(),
  deliveryMode: z.nativeEnum(PrinterDeliveryMode).optional().nullable(),
  capabilitySummary: z.record(z.any()).optional().nullable(),
  calibrationProfile: z.record(z.any()).optional().nullable(),
  isActive: z.boolean().optional(),
  isDefault: z.boolean().optional(),
}).strict();

type ApprovalActor = {
  userId: string;
  role: UserRole;
  orgId?: string | null;
  licenseeId?: string | null;
};

type CreateApprovalInput = {
  actionKey: SensitiveActionKey;
  actor: ApprovalActor;
  payload: Record<string, unknown>;
  summary?: Record<string, unknown> | null;
  entityType?: string | null;
  entityId?: string | null;
  orgId?: string | null;
  licenseeId?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
};

const isPlatformApproverRole = (role?: UserRole | null) =>
  role === UserRole.SUPER_ADMIN || role === UserRole.PLATFORM_SUPER_ADMIN;

const isPrinterApproverRole = (role?: UserRole | null) =>
  role === UserRole.SUPER_ADMIN ||
  role === UserRole.PLATFORM_SUPER_ADMIN ||
  role === UserRole.MANUFACTURER ||
  role === UserRole.MANUFACTURER_ADMIN;

const canReviewApproval = (actor: ApprovalActor, approval: any) => {
  if (actor.userId === approval.requestedByUserId) return false;
  if (approval.status !== ACTION_STATUS.PENDING) return false;
  if (approval.expiresAt && new Date(approval.expiresAt).getTime() <= Date.now()) return false;

  switch (approval.actionKey as SensitiveActionKey) {
    case SENSITIVE_ACTION_KEYS.PRINTER_GATEWAY_SECRET_ROTATION:
      if (!isPrinterApproverRole(actor.role)) return false;
      if (isPlatformApproverRole(actor.role)) return true;
      return Boolean(actor.licenseeId && approval.licenseeId && actor.licenseeId === approval.licenseeId);
    default:
      return isPlatformApproverRole(actor.role);
  }
};

const serializeUserAgentHash = (userAgent?: string | null) => {
  const normalized = normalizeUserAgent(userAgent || undefined);
  return normalized ? hashToken(normalized) : null;
};

const expireIfNeeded = async (approval: any) => {
  if (approval.status !== ACTION_STATUS.PENDING) return approval;
  if (!approval.expiresAt || new Date(approval.expiresAt).getTime() > Date.now()) return approval;
  return prisma.sensitiveActionApproval.update({
    where: { id: approval.id },
    data: { status: ACTION_STATUS.EXPIRED },
  });
};

export const createSensitiveActionApproval = async (input: CreateApprovalInput) => {
  const expiresAt = new Date(Date.now() + approvalTtlMinutes() * 60_000);
  const row = await prisma.sensitiveActionApproval.create({
    data: {
      actionKey: input.actionKey,
      status: ACTION_STATUS.PENDING,
      requestedByUserId: input.actor.userId,
      orgId: input.orgId || input.actor.orgId || null,
      licenseeId: input.licenseeId || input.actor.licenseeId || null,
      entityType: input.entityType || null,
      entityId: input.entityId || null,
      payload: input.payload as Prisma.InputJsonValue,
      summary: input.summary ? (input.summary as Prisma.InputJsonValue) : Prisma.JsonNull,
      requestIpHash: hashIp(input.ipAddress || undefined) || null,
      requestUserAgentHash: serializeUserAgentHash(input.userAgent),
      expiresAt,
    },
  });

  await createAuditLog({
    userId: input.actor.userId,
    orgId: row.orgId || undefined,
    licenseeId: row.licenseeId || undefined,
    action: "SENSITIVE_ACTION_APPROVAL_REQUESTED",
    entityType: "SensitiveActionApproval",
    entityId: row.id,
    details: {
      actionKey: row.actionKey,
      approvalStatus: row.status,
      entityType: row.entityType,
      entityId: row.entityId,
      summary: row.summary ?? null,
    },
    ipAddress: input.ipAddress || undefined,
    userAgent: input.userAgent || undefined,
  });

  return row;
};

export const listSensitiveActionApprovals = async (input: {
  actor: ApprovalActor;
  status?: string | null;
  limit?: number;
  offset?: number;
}) => {
  const limit = Math.min(Math.max(Number(input.limit || 50), 1), 200);
  const offset = Math.max(Number(input.offset || 0), 0);
  const where: any = {};
  if (input.status) where.status = String(input.status).trim().toUpperCase();

  const rows = await prisma.sensitiveActionApproval.findMany({
    where,
    include: {
      requestedByUser: { select: { id: true, name: true, email: true, role: true } },
      reviewedByUser: { select: { id: true, name: true, email: true, role: true } },
      executedByUser: { select: { id: true, name: true, email: true, role: true } },
    },
    orderBy: [{ createdAt: "desc" }],
    take: limit,
    skip: offset,
  });

  const normalized = await Promise.all(rows.map((row) => expireIfNeeded(row)));
  return normalized.filter((row) => row.requestedByUserId === input.actor.userId || canReviewApproval(input.actor, row));
};

const executeFeatureFlagUpsert = async (approval: any, reviewer: ApprovalActor) => {
  const payload = featureFlagPayloadSchema.parse(approval.payload);
  const row = await upsertTenantFeatureFlag({
    licenseeId: payload.licenseeId,
    key: payload.key,
    enabled: payload.enabled,
    config: payload.config,
    updatedByUserId: reviewer.userId,
  });

  await createAuditLog({
    userId: reviewer.userId,
    licenseeId: payload.licenseeId,
    action: "TENANT_FEATURE_FLAG_UPSERT",
    entityType: "TenantFeatureFlag",
    entityId: row.id,
    details: {
      key: row.key,
      enabled: row.enabled,
      dualControlApprovalId: approval.id,
      requestedByUserId: approval.requestedByUserId,
    },
  });

  return row;
};

const executeRetentionPolicyPatch = async (approval: any, reviewer: ApprovalActor) => {
  const payload = retentionPolicyPayloadSchema.parse(approval.payload);
  const policy = await updateRetentionPolicy({
    licenseeId: payload.licenseeId,
    retentionDays: payload.retentionDays,
    purgeEnabled: payload.purgeEnabled,
    exportBeforePurge: payload.exportBeforePurge,
    legalHoldTags: payload.legalHoldTags,
    updatedByUserId: reviewer.userId,
  });

  await createAuditLog({
    userId: reviewer.userId,
    licenseeId: payload.licenseeId,
    action: "EVIDENCE_RETENTION_POLICY_UPDATED",
    entityType: "EvidenceRetentionPolicy",
    entityId: policy.id,
    details: {
      retentionDays: policy.retentionDays,
      purgeEnabled: policy.purgeEnabled,
      dualControlApprovalId: approval.id,
      requestedByUserId: approval.requestedByUserId,
    },
  });

  return policy;
};

const executeRetentionApply = async (approval: any, reviewer: ApprovalActor) => {
  const payload = retentionApplyPayloadSchema.parse(approval.payload);
  const result = await runRetentionLifecycle({
    licenseeId: payload.licenseeId,
    startedByUserId: reviewer.userId,
    mode: "APPLY",
  });

  await createAuditLog({
    userId: reviewer.userId,
    licenseeId: payload.licenseeId,
    action: "EVIDENCE_RETENTION_JOB_RUN",
    entityType: "EvidenceRetentionJob",
    entityId: result.job.id,
    details: {
      mode: "APPLY",
      evaluated: result.evaluated,
      purged: result.purged,
      dualControlApprovalId: approval.id,
      requestedByUserId: approval.requestedByUserId,
    },
  });

  return result;
};

const executeQrBlock = async (approval: any, reviewer: ApprovalActor) => {
  const payload = qrBlockPayloadSchema.parse(approval.payload);
  const updated = await prisma.qRCode.update({
    where: { id: payload.qrId },
    data: {
      status: QRStatus.BLOCKED,
      blockedAt: new Date(),
    },
  });

  await createAuditLog({
    userId: reviewer.userId,
    licenseeId: updated.licenseeId,
    action: "BLOCKED",
    entityType: "QRCode",
    entityId: updated.id,
    details: {
      reason: payload.reason || null,
      batchId: updated.batchId || null,
      dualControlApprovalId: approval.id,
      requestedByUserId: approval.requestedByUserId,
    },
  });

  return { id: updated.id };
};

const executeBatchBlock = async (approval: any, reviewer: ApprovalActor) => {
  const payload = batchBlockPayloadSchema.parse(approval.payload);
  const batch = await prisma.batch.findUnique({
    where: { id: payload.batchId },
    select: { id: true, licenseeId: true },
  });
  if (!batch) {
    throw new Error("Batch not found");
  }

  const updated = await prisma.qRCode.updateMany({
    where: { batchId: batch.id },
    data: {
      status: QRStatus.BLOCKED,
      blockedAt: new Date(),
    },
  });

  await createAuditLog({
    userId: reviewer.userId,
    licenseeId: batch.licenseeId,
    action: "BLOCKED",
    entityType: "Batch",
    entityId: batch.id,
    details: {
      blockedCodes: updated.count,
      reason: payload.reason || null,
      dualControlApprovalId: approval.id,
      requestedByUserId: approval.requestedByUserId,
    },
  });

  return { batchId: batch.id, blocked: updated.count };
};

const executePrinterGatewayRotation = async (approval: any, reviewer: ApprovalActor) => {
  const payload = printerRotationPayloadSchema.parse(approval.payload);
  const result = await upsertManagedNetworkPrinter({
    printerId: payload.printerId,
    userId: reviewer.userId,
    orgId: payload.orgId || null,
    licenseeId: payload.licenseeId || null,
    name: payload.name,
    vendor: payload.vendor || null,
    model: payload.model || null,
    connectionType: payload.connectionType,
    commandLanguage: payload.commandLanguage || undefined,
    ipAddress: payload.ipAddress || null,
    host: payload.host || null,
    port: payload.port,
    resourcePath: payload.resourcePath || null,
    tlsEnabled: payload.tlsEnabled ?? undefined,
    printerUri: payload.printerUri || null,
    deliveryMode: payload.deliveryMode || undefined,
    rotateGatewaySecret: true,
    capabilitySummary: (payload.capabilitySummary as Record<string, unknown> | null | undefined) || null,
    calibrationProfile: (payload.calibrationProfile as Record<string, unknown> | null | undefined) || null,
    isActive: payload.isActive,
    isDefault: payload.isDefault,
  });

  await createAuditLog({
    userId: reviewer.userId,
    licenseeId: payload.licenseeId || undefined,
    action: "PRINTER_GATEWAY_SECRET_ROTATED",
    entityType: "Printer",
    entityId: result.printer.id,
    details: {
      connectionType: result.printer.connectionType,
      deliveryMode: result.printer.deliveryMode,
      dualControlApprovalId: approval.id,
      requestedByUserId: approval.requestedByUserId,
    },
  });

  return {
    printer: result.printer,
    gatewayProvisioningSecret: result.gatewayProvisioningSecret || null,
  };
};

const executeApprovalAction = async (approval: any, reviewer: ApprovalActor) => {
  switch (approval.actionKey as SensitiveActionKey) {
    case SENSITIVE_ACTION_KEYS.FEATURE_FLAG_UPSERT:
      return executeFeatureFlagUpsert(approval, reviewer);
    case SENSITIVE_ACTION_KEYS.RETENTION_POLICY_PATCH:
      return executeRetentionPolicyPatch(approval, reviewer);
    case SENSITIVE_ACTION_KEYS.RETENTION_APPLY:
      return executeRetentionApply(approval, reviewer);
    case SENSITIVE_ACTION_KEYS.QR_BLOCK:
      return executeQrBlock(approval, reviewer);
    case SENSITIVE_ACTION_KEYS.BATCH_BLOCK:
      return executeBatchBlock(approval, reviewer);
    case SENSITIVE_ACTION_KEYS.PRINTER_GATEWAY_SECRET_ROTATION:
      return executePrinterGatewayRotation(approval, reviewer);
    default:
      throw new Error(`Unsupported sensitive approval action: ${approval.actionKey}`);
  }
};

export const approveSensitiveActionApproval = async (input: {
  approvalId: string;
  actor: ApprovalActor;
  reviewNote?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
}) => {
  const current = await prisma.sensitiveActionApproval.findUnique({
    where: { id: input.approvalId },
  });
  if (!current) {
    throw new Error("Approval request not found");
  }

  const approval = await expireIfNeeded(current);
  if (approval.status !== ACTION_STATUS.PENDING) {
    throw new Error("Approval request is no longer pending");
  }
  if (!canReviewApproval(input.actor, approval)) {
    throw new Error("You cannot approve this request");
  }

  await prisma.sensitiveActionApproval.update({
    where: { id: approval.id },
    data: {
      status: ACTION_STATUS.APPROVED,
      reviewedByUserId: input.actor.userId,
      reviewedAt: new Date(),
      reviewNote: input.reviewNote || null,
    },
  });

  await createAuditLog({
    userId: input.actor.userId,
    orgId: approval.orgId || undefined,
    licenseeId: approval.licenseeId || undefined,
    action: "SENSITIVE_ACTION_APPROVAL_APPROVED",
    entityType: "SensitiveActionApproval",
    entityId: approval.id,
    details: {
      actionKey: approval.actionKey,
      requestedByUserId: approval.requestedByUserId,
      reviewNote: input.reviewNote || null,
    },
    ipAddress: input.ipAddress || undefined,
    userAgent: input.userAgent || undefined,
  });

  try {
    const result = await executeApprovalAction(approval, input.actor);
    const executed = await prisma.sensitiveActionApproval.update({
      where: { id: approval.id },
      data: {
        status: ACTION_STATUS.EXECUTED,
        executedByUserId: input.actor.userId,
        executedAt: new Date(),
        executionError: null,
      },
    });
    return { approval: executed, result };
  } catch (error) {
    const failed = await prisma.sensitiveActionApproval.update({
      where: { id: approval.id },
      data: {
        status: ACTION_STATUS.FAILED,
        executedByUserId: input.actor.userId,
        executedAt: new Date(),
        executionError: error instanceof Error ? error.message : String(error || "Unknown error"),
      },
    });
    throw Object.assign(error instanceof Error ? error : new Error(String(error || "Unknown error")), {
      approval: failed,
    });
  }
};

export const rejectSensitiveActionApproval = async (input: {
  approvalId: string;
  actor: ApprovalActor;
  reviewNote?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
}) => {
  const current = await prisma.sensitiveActionApproval.findUnique({
    where: { id: input.approvalId },
  });
  if (!current) {
    throw new Error("Approval request not found");
  }

  const approval = await expireIfNeeded(current);
  if (approval.status !== ACTION_STATUS.PENDING) {
    throw new Error("Approval request is no longer pending");
  }
  if (!canReviewApproval(input.actor, approval)) {
    throw new Error("You cannot reject this request");
  }

  const rejected = await prisma.sensitiveActionApproval.update({
    where: { id: approval.id },
    data: {
      status: ACTION_STATUS.REJECTED,
      reviewedByUserId: input.actor.userId,
      reviewedAt: new Date(),
      reviewNote: input.reviewNote || null,
    },
  });

  await createAuditLog({
    userId: input.actor.userId,
    orgId: approval.orgId || undefined,
    licenseeId: approval.licenseeId || undefined,
    action: "SENSITIVE_ACTION_APPROVAL_REJECTED",
    entityType: "SensitiveActionApproval",
    entityId: approval.id,
    details: {
      actionKey: approval.actionKey,
      requestedByUserId: approval.requestedByUserId,
      reviewNote: input.reviewNote || null,
    },
    ipAddress: input.ipAddress || undefined,
    userAgent: input.userAgent || undefined,
  });

  return rejected;
};
