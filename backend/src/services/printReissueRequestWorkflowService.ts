import {
  NotificationAudience,
  NotificationChannel,
  ReissueRequestStatus,
  UserRole,
} from "@prisma/client";

import prisma from "../config/database";
import { createAuditLog } from "./auditService";
import { createAuthorizedPrintReissue } from "./printReissueService";
import { buildScopedPrintJobWhere, type PrintJobScope } from "./printJobScopeService";
import { createRoleNotifications, createUserNotification } from "./notificationService";

const NOTE_MIN_LENGTH = 8;

const isPlatformRole = (role: UserRole) =>
  role === UserRole.SUPER_ADMIN || role === UserRole.PLATFORM_SUPER_ADMIN;
const isLicenseeAdminRole = (role: UserRole) =>
  role === UserRole.LICENSEE_ADMIN || role === UserRole.ORG_ADMIN;
const isManufacturerRole = (role: UserRole) =>
  role === UserRole.MANUFACTURER ||
  role === UserRole.MANUFACTURER_ADMIN ||
  role === UserRole.MANUFACTURER_USER;

const normalizeNote = (value: string, label: string) => {
  const note = String(value || "").replace(/\s+/g, " ").trim();
  if (note.length < NOTE_MIN_LENGTH) {
    throw Object.assign(new Error(`${label} is required.`), { statusCode: 400 });
  }
  return note.slice(0, 500);
};

const targetApproverRoleFor = (role: UserRole) => {
  if (isManufacturerRole(role)) return "LICENSEE_ADMIN";
  if (isLicenseeAdminRole(role)) return "SUPER_ADMIN";
  if (isPlatformRole(role)) return "SUPER_ADMIN";
  throw Object.assign(new Error("Access denied"), { statusCode: 403 });
};

const serializeRequest = (row: any) => ({
  id: row.id,
  originalPrintJobId: row.originalPrintJobId,
  replacementPrintJobId: row.replacementPrintJobId,
  status: row.status,
  reason: row.reason,
  decisionNote: row.decisionNote || row.rejectionReason || null,
  requestedByRole: row.requestedByRole,
  targetApproverRole: row.targetApproverRole,
  quantity: row.quantity,
  affectedRangeStart: row.affectedRangeStart,
  affectedRangeEnd: row.affectedRangeEnd,
  requestedAt: row.createdAt,
  updatedAt: row.updatedAt,
  approvedAt: row.approvedAt,
  rejectedAt: row.rejectedAt,
  executedAt: row.executedAt,
  batch: row.originalPrintJob?.batch
    ? {
        id: row.originalPrintJob.batch.id,
        name: row.originalPrintJob.batch.name,
        licenseeId: row.originalPrintJob.batch.licenseeId,
      }
    : null,
  printer: row.originalPrintJob?.printer
    ? {
        id: row.originalPrintJob.printer.id,
        displayName: row.originalPrintJob.printer.name || "Printer",
      }
    : null,
  requestedBy: row.requestedByUser
    ? {
        id: row.requestedByUser.id,
        name: row.requestedByUser.name || row.requestedByUser.email || "User",
        email: row.requestedByUser.email || null,
        role: row.requestedByUser.role,
      }
    : null,
  decidedBy: row.approvedByUser
    ? {
        id: row.approvedByUser.id,
        name: row.approvedByUser.name || row.approvedByUser.email || "User",
        email: row.approvedByUser.email || null,
        role: row.approvedByUser.role,
      }
    : null,
});

const serializeReplacementPrintStart = (row: any, idempotent = false) => ({
  reissueRequestId: row.id,
  replacementPrintJobId: row.replacementPrintJobId,
  printSessionId: row.replacementPrintJob?.printSession?.id || null,
  quantity: Number(row.replacementPrintJob?.itemCount || row.replacementPrintJob?.quantity || row.quantity || 0),
  mode: row.replacementPrintJob?.printMode || null,
  pipelineState: row.replacementPrintJob?.pipelineState || null,
  idempotent,
});

const requestInclude = {
  originalPrintJob: {
    include: {
      batch: { select: { id: true, name: true, licenseeId: true } },
      printer: { select: { id: true, name: true } },
    },
  },
  replacementPrintJob: {
    select: {
      id: true,
      quantity: true,
      itemCount: true,
      printMode: true,
      pipelineState: true,
      printSession: { select: { id: true } },
    },
  },
  requestedByUser: { select: { id: true, name: true, email: true, role: true } },
  approvedByUser: { select: { id: true, name: true, email: true, role: true } },
};

export const createScopedPrintReissueRequest = async (params: {
  scope: PrintJobScope;
  originalPrintJobId: string;
  reason: string;
  quantity?: number | null;
  affectedRangeStart?: string | null;
  affectedRangeEnd?: string | null;
}) => {
  const reason = normalizeNote(params.reason, "A clear reason");
  const originalJob = await prisma.printJob.findFirst({
    where: buildScopedPrintJobWhere(params.scope, { id: params.originalPrintJobId }),
    include: {
      batch: { select: { id: true, name: true, licenseeId: true } },
      printer: { select: { id: true, name: true } },
    },
  });
  if (!originalJob) throw Object.assign(new Error("Print job not found"), { statusCode: 404 });
  const original = originalJob as any;

  const targetApproverRole = targetApproverRoleFor(params.scope.role);
  const existing = await prisma.printReissueRequest.findFirst({
    where: {
      originalPrintJobId: originalJob.id,
      requestedByUserId: params.scope.userId,
      status: ReissueRequestStatus.PENDING,
      targetApproverRole,
    },
    include: requestInclude,
    orderBy: { createdAt: "desc" },
  });
  if (existing) return { request: serializeRequest(existing), idempotent: true };

  const created = await prisma.printReissueRequest.create({
    data: {
      originalPrintJobId: originalJob.id,
      requestedByUserId: params.scope.userId,
      status: ReissueRequestStatus.PENDING,
      reason,
      licenseeId: original.batch.licenseeId,
      manufacturerId: original.manufacturerId,
      batchId: original.batch.id,
      requestedByRole: params.scope.role,
      targetApproverRole,
      quantity: params.quantity || null,
      affectedRangeStart: params.affectedRangeStart || null,
      affectedRangeEnd: params.affectedRangeEnd || null,
    },
    include: requestInclude,
  });

  await createAuditLog({
    userId: params.scope.userId,
    licenseeId: original.batch.licenseeId || undefined,
    action: "PRINT_REISSUE_REQUESTED",
    entityType: "PrintReissueRequest",
    entityId: created.id,
    details: {
      originalPrintJobId: originalJob.id,
      batchId: original.batch.id,
      manufacturerId: original.manufacturerId,
      targetApproverRole,
      quantity: params.quantity || null,
    },
  });

  await createRoleNotifications({
    audience:
      targetApproverRole === "SUPER_ADMIN"
        ? NotificationAudience.SUPER_ADMIN
        : NotificationAudience.LICENSEE_ADMIN,
    licenseeId: targetApproverRole === "SUPER_ADMIN" ? null : original.batch.licenseeId,
    title: "Print reissue request needs review",
    body: `${original.batch.name} has a replacement label request awaiting approval.`,
    type: "print_reissue_requested",
    data: {
      reissueRequestId: created.id,
      originalPrintJobId: originalJob.id,
      batchId: original.batch.id,
      targetRoute: "/batches",
    },
    channels: [NotificationChannel.WEB],
  });

  return { request: serializeRequest(created), idempotent: false };
};

export const listScopedPrintReissueRequests = async (params: {
  scope: PrintJobScope;
  status?: ReissueRequestStatus | null;
  limit?: number | null;
}) => {
  const statusWhere = params.status ? { status: params.status } : {};
  const scopeWhere = isPlatformRole(params.scope.role)
    ? {}
    : isLicenseeAdminRole(params.scope.role)
    ? { licenseeId: params.scope.licenseeId || "__denied__" }
    : { requestedByUserId: params.scope.userId };

  const rows = await prisma.printReissueRequest.findMany({
    where: {
      ...scopeWhere,
      ...statusWhere,
    },
    include: requestInclude,
    orderBy: [{ createdAt: "desc" }],
    take: Math.min(Math.max(Number(params.limit || 25), 1), 100),
  });

  return rows.map(serializeRequest);
};

const assertCanDecide = (scope: PrintJobScope, request: any) => {
  if (request.requestedByUserId === scope.userId) {
    throw Object.assign(new Error("You cannot approve your own reissue request."), { statusCode: 403 });
  }
  if (request.status !== ReissueRequestStatus.PENDING) {
    throw Object.assign(new Error("This reissue request has already been reviewed."), { statusCode: 409 });
  }
  if (request.targetApproverRole === "LICENSEE_ADMIN") {
    if (!isLicenseeAdminRole(scope.role) || request.licenseeId !== scope.licenseeId) {
      throw Object.assign(new Error("Reissue request not found"), { statusCode: 404 });
    }
    return;
  }
  if (request.targetApproverRole === "SUPER_ADMIN") {
    if (!isPlatformRole(scope.role)) {
      throw Object.assign(new Error("Only super admins can review this reissue request."), { statusCode: 403 });
    }
    return;
  }
  throw Object.assign(new Error("Reissue request not found"), { statusCode: 404 });
};

export const decideScopedPrintReissueRequest = async (params: {
  scope: PrintJobScope;
  requestId: string;
  decision: "approve" | "reject";
  decisionNote: string;
  ipAddress?: string | null;
  userAgent?: string | null;
}) => {
  const decisionNote = normalizeNote(params.decisionNote, "A clear decision note");
  const request = await prisma.printReissueRequest.findUnique({
    where: { id: params.requestId },
    include: requestInclude,
  });
  if (!request) throw Object.assign(new Error("Reissue request not found"), { statusCode: 404 });

  assertCanDecide(params.scope, request);

  if (params.decision === "reject") {
    const rejected = await prisma.printReissueRequest.update({
      where: { id: request.id },
      data: {
        status: ReissueRequestStatus.REJECTED,
        approvedByUserId: params.scope.userId,
        decisionNote,
        rejectionReason: decisionNote,
        rejectedAt: new Date(),
      },
      include: requestInclude,
    });
    await createAuditLog({
      userId: params.scope.userId,
      licenseeId: request.licenseeId || undefined,
      action: "PRINT_REISSUE_REJECTED",
      entityType: "PrintReissueRequest",
      entityId: request.id,
      details: { originalPrintJobId: request.originalPrintJobId, decisionNote },
      ipAddress: params.ipAddress || undefined,
      userAgent: params.userAgent || undefined,
    });
    await createUserNotification({
      userId: request.requestedByUserId,
      licenseeId: request.licenseeId,
      type: "print_reissue_rejected",
      title: "Print reissue request rejected",
      body: "A replacement label request was reviewed and rejected.",
      data: { reissueRequestId: request.id, targetRoute: "/batches" },
    });
    return { request: serializeRequest(rejected), result: null };
  }

  const approved = await prisma.printReissueRequest.update({
    where: { id: request.id },
    data: {
      status: ReissueRequestStatus.APPROVED,
      approvedByUserId: params.scope.userId,
      decisionNote,
      approvedAt: new Date(),
      approvalReferenceId: request.id,
    },
    include: requestInclude,
  });

  await createAuditLog({
    userId: params.scope.userId,
    licenseeId: request.licenseeId || undefined,
    action: "PRINT_REISSUE_APPROVED",
    entityType: "PrintReissueRequest",
    entityId: request.id,
    details: {
      originalPrintJobId: request.originalPrintJobId,
      decisionNote,
      targetApproverRole: request.targetApproverRole,
      readyToPrint: true,
    },
    ipAddress: params.ipAddress || undefined,
    userAgent: params.userAgent || undefined,
  });

  if (request.targetApproverRole === "LICENSEE_ADMIN") {
    await createRoleNotifications({
      audience: NotificationAudience.SUPER_ADMIN,
      title: "Print reissue approved by brand admin",
      body: "A brand admin approved a manufacturer replacement label request.",
      type: "print_reissue_approved_audit",
      data: {
        reissueRequestId: request.id,
        originalPrintJobId: request.originalPrintJobId,
        targetRoute: "/batches",
      },
      channels: [NotificationChannel.WEB],
    });
  }

  await createUserNotification({
    userId: request.requestedByUserId,
    licenseeId: request.licenseeId,
    type: "print_reissue_approved",
    title: "Print reissue request approved",
    body: "A replacement label request was approved and is ready to print.",
    data: {
      reissueRequestId: request.id,
      targetRoute: "/batches",
    },
  });

  return { request: serializeRequest(approved), result: null };
};

export const startApprovedPrintReissueRequest = async (params: {
  scope: PrintJobScope;
  requestId: string;
  ipAddress?: string | null;
  userAgent?: string | null;
}) => {
  const request = await prisma.printReissueRequest.findUnique({
    where: { id: params.requestId },
    include: requestInclude,
  });
  if (!request) throw Object.assign(new Error("Reissue request not found"), { statusCode: 404 });

  if (!isManufacturerRole(params.scope.role) || request.requestedByUserId !== params.scope.userId) {
    throw Object.assign(new Error("Reissue request not found"), { statusCode: 404 });
  }

  if (request.status === ReissueRequestStatus.EXECUTED && request.replacementPrintJobId) {
    return { request: serializeRequest(request), result: serializeReplacementPrintStart(request, true), idempotent: true };
  }

  if (request.status !== ReissueRequestStatus.APPROVED) {
    throw Object.assign(new Error("Reissue request is not ready to print."), { statusCode: 409 });
  }

  await createAuditLog({
    userId: params.scope.userId,
    licenseeId: request.licenseeId || undefined,
    action: "PRINT_REISSUE_PRINT_START_REQUESTED",
    entityType: "PrintReissueRequest",
    entityId: request.id,
    details: {
      originalPrintJobId: request.originalPrintJobId,
      targetApproverRole: request.targetApproverRole,
    },
    ipAddress: params.ipAddress || undefined,
    userAgent: params.userAgent || undefined,
  });

  let result;
  try {
    result = await createAuthorizedPrintReissue({
      scope: params.scope,
      originalPrintJobId: request.originalPrintJobId,
      approvedReissueRequestId: request.id,
      reason: request.reason,
      quantity: request.quantity,
      ipAddress: params.ipAddress,
      userAgent: params.userAgent,
    });
  } catch (error: any) {
    if (String(error?.message || "").includes("PRINTER_NOT_TRUSTED")) {
      await createAuditLog({
        userId: params.scope.userId,
        licenseeId: request.licenseeId || undefined,
        action: "PRINT_REISSUE_PRINT_BLOCKED",
        entityType: "PrintReissueRequest",
        entityId: request.id,
        details: {
          originalPrintJobId: request.originalPrintJobId,
          code: "PRINTER_ATTESTATION_STALE",
          recoveryAction: "refresh_printer_status",
        },
        ipAddress: params.ipAddress || undefined,
        userAgent: params.userAgent || undefined,
      });
    }
    throw error;
  }

  const executed = await prisma.printReissueRequest.findUnique({
    where: { id: request.id },
    include: requestInclude,
  });

  if (!executed) throw Object.assign(new Error("Reissue request not found"), { statusCode: 404 });

  await createAuditLog({
    userId: params.scope.userId,
    licenseeId: request.licenseeId || undefined,
    action: "PRINT_REISSUE_PRINT_STARTED",
    entityType: "PrintReissueRequest",
    entityId: request.id,
    details: {
      originalPrintJobId: request.originalPrintJobId,
      replacementPrintJobId: result.replacementPrintJobId,
      printSessionId: result.printSessionId,
      mode: result.mode,
    },
    ipAddress: params.ipAddress || undefined,
    userAgent: params.userAgent || undefined,
  });

  return { request: serializeRequest(executed), result, idempotent: false };
};
