import {
  NotificationAudience,
  NotificationChannel,
  ReissueRequestStatus,
  UserRole,
} from "@prisma/client";

import prisma from "../config/database";
import { createAuditLog } from "./auditService";
import {
  createAuthorizedPrintReissue,
  describeOriginalPrintJobForReissue,
  projectPrintJobReissueSummaries,
  type PrintJobReissueProjection,
} from "./printReissueService";
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

const approvalStateFor = (row: any) => {
  if (row.status === ReissueRequestStatus.APPROVED) return "APPROVED_READY_TO_PRINT";
  if (row.status === ReissueRequestStatus.EXECUTED) return "PRINT_JOB_CREATED";
  if (row.status === ReissueRequestStatus.REJECTED) return "REJECTED";
  if (row.targetApproverRole === "SUPER_ADMIN") return "SUPER_ADMIN_REVIEW";
  return "BRAND_ADMIN_REVIEW";
};

const nextActionFor = (row: any) => {
  if (row.status === ReissueRequestStatus.APPROVED) return "Print replacement labels";
  if (row.status === ReissueRequestStatus.EXECUTED) return "Watch replacement print job";
  if (row.status === ReissueRequestStatus.REJECTED) return "No action";
  if (row.targetApproverRole === "SUPER_ADMIN") return "Waiting for super admin review";
  return "Waiting for brand admin review";
};

const serializeRequest = (row: any, projection?: PrintJobReissueProjection | null) => {
  const original = row.originalPrintJob ? describeOriginalPrintJobForReissue(row.originalPrintJob, projection) : null;
  const requestedCount = Number(row.quantity || original?.requestedCount || 0);
  const requestedRangeStart = row.affectedRangeStart || original?.requestedRangeStart || null;
  const requestedRangeEnd = row.affectedRangeEnd || original?.requestedRangeEnd || null;

  return {
    id: row.id,
    originalPrintJobId: row.originalPrintJobId,
    replacementPrintJobId: row.replacementPrintJobId,
    status: row.status,
    approvalState: approvalStateFor(row),
    reason: row.reason,
    decisionNote: row.decisionNote || row.rejectionReason || null,
    requestedByRole: row.requestedByRole,
    targetApproverRole: row.targetApproverRole,
    quantity: row.quantity,
    requestedCount,
    affectedRangeStart: row.affectedRangeStart,
    affectedRangeEnd: row.affectedRangeEnd,
    requestedRangeStart,
    requestedRangeEnd,
    requestedAt: row.createdAt,
    updatedAt: row.updatedAt,
    approvedAt: row.approvedAt,
    rejectedAt: row.rejectedAt,
    executedAt: row.executedAt,
    originalPrintJobNumber: original?.originalPrintJobNumber || null,
    originalRequestedRange: original?.originalRequestedRange || null,
    originalConfirmedCount: original?.originalConfirmedCount || 0,
    originalPendingCount: original?.originalPendingCount || 0,
    originalFailedCount: original?.originalFailedCount || 0,
    recoveryStartLabel: original?.recoveryStartLabel || requestedRangeStart,
    recoveryEndLabel: original?.recoveryEndLabel || requestedRangeEnd,
    nextAction: nextActionFor(row),
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
  };
};

const serializeReplacementPrintStart = (row: any, idempotent = false) => ({
  reissueRequestId: row.id,
  replacementPrintJobId: row.replacementPrintJobId,
  printSessionId: row.replacementPrintJob?.printSession?.id || null,
  quantity: Number(row.replacementPrintJob?.itemCount || row.replacementPrintJob?.quantity || row.quantity || 0),
  requestedRangeStart: row.replacementPrintJob?.rangeStart || row.affectedRangeStart || null,
  requestedRangeEnd: row.replacementPrintJob?.rangeEnd || row.affectedRangeEnd || null,
  recoveryStartLabel: row.affectedRangeStart || null,
  recoveryEndLabel: row.affectedRangeEnd || null,
  mode: row.replacementPrintJob?.printMode || null,
  pipelineState: row.replacementPrintJob?.pipelineState || null,
  idempotent,
});

const requestInclude = {
  originalPrintJob: {
    include: {
      batch: { select: { id: true, name: true, licenseeId: true } },
      printer: { select: { id: true, name: true } },
      printSession: {
        select: {
          id: true,
          status: true,
        },
      },
    },
  },
  replacementPrintJob: {
    select: {
      id: true,
      quantity: true,
      itemCount: true,
      rangeStart: true,
      rangeEnd: true,
      printMode: true,
      pipelineState: true,
      printSession: { select: { id: true } },
    },
  },
  requestedByUser: { select: { id: true, name: true, email: true, role: true } },
  approvedByUser: { select: { id: true, name: true, email: true, role: true } },
};

const loadProjectionForRequest = async (request: { originalPrintJobId?: string | null }) =>
  (await projectPrintJobReissueSummaries(prisma, [String(request.originalPrintJobId || "").trim()])).get(
    String(request.originalPrintJobId || "").trim()
  ) || null;

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
      printSession: {
        select: {
          id: true,
          status: true,
        },
      },
    },
  });
  if (!originalJob) throw Object.assign(new Error("Print job not found"), { statusCode: 404 });
  const original = originalJob as any;
  const originalProjection =
    (await projectPrintJobReissueSummaries(prisma, [originalJob.id])).get(originalJob.id) || null;
  const originalReissue = describeOriginalPrintJobForReissue(originalJob, originalProjection);
  const requestedCount = params.quantity || originalReissue.requestedCount || null;
  const requestedRangeStart = params.affectedRangeStart || originalReissue.requestedRangeStart || null;
  const requestedRangeEnd = params.affectedRangeEnd || originalReissue.requestedRangeEnd || null;

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
  if (existing) return { request: serializeRequest(existing, originalProjection), idempotent: true };

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
      quantity: requestedCount,
      affectedRangeStart: requestedRangeStart,
      affectedRangeEnd: requestedRangeEnd,
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
      quantity: requestedCount,
      affectedRangeStart: requestedRangeStart,
      affectedRangeEnd: requestedRangeEnd,
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
      entityType: "reissue_request",
      entityId: created.id,
      reissueRequestId: created.id,
      originalPrintJobId: originalJob.id,
      batchId: original.batch.id,
      licenseeId: original.batch.licenseeId,
      manufacturerId: original.manufacturerId,
      preferredTab: "reissue",
      preferredSection: "review",
      targetRoute: `/batches?batchId=${encodeURIComponent(original.batch.id)}&tab=reissue&reissueRequestId=${encodeURIComponent(created.id)}`,
    },
    channels: [NotificationChannel.WEB],
  });

  return { request: serializeRequest(created, originalProjection), idempotent: false };
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

  const summaries = await projectPrintJobReissueSummaries(
    prisma,
    rows.map((row) => row.originalPrintJobId)
  );
  return rows.map((row) => serializeRequest(row, summaries.get(row.originalPrintJobId) || null));
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
      data: {
        entityType: "reissue_request",
        entityId: request.id,
        reissueRequestId: request.id,
        originalPrintJobId: request.originalPrintJobId,
        batchId: request.batchId,
        licenseeId: request.licenseeId,
        manufacturerId: request.manufacturerId,
        preferredTab: "reissue",
        preferredSection: "status",
        targetRoute: `/batches?batchId=${encodeURIComponent(String(request.batchId || ""))}&tab=reissue&reissueRequestId=${encodeURIComponent(request.id)}`,
      },
    });
    return { request: serializeRequest(rejected, await loadProjectionForRequest(rejected)), result: null };
  }

  if (request.targetApproverRole === "LICENSEE_ADMIN") {
    const forwarded = await prisma.printReissueRequest.update({
      where: { id: request.id },
      data: {
        status: ReissueRequestStatus.PENDING,
        targetApproverRole: "SUPER_ADMIN",
        decisionNote,
        approvalReferenceId: request.id,
      },
      include: requestInclude,
    });

    await createAuditLog({
      userId: params.scope.userId,
      licenseeId: request.licenseeId || undefined,
      action: "PRINT_REISSUE_FORWARDED_TO_SUPER_ADMIN",
      entityType: "PrintReissueRequest",
      entityId: request.id,
      details: {
        originalPrintJobId: request.originalPrintJobId,
        decisionNote,
        targetApproverRole: "SUPER_ADMIN",
        readyToPrint: false,
      },
      ipAddress: params.ipAddress || undefined,
      userAgent: params.userAgent || undefined,
    });

    await createRoleNotifications({
      audience: NotificationAudience.SUPER_ADMIN,
      title: "Print reissue forwarded for super admin review",
      body: "A brand admin forwarded a manufacturer replacement label request for final approval.",
      type: "print_reissue_forwarded_to_super_admin",
      data: {
        entityType: "reissue_request",
        entityId: request.id,
        reissueRequestId: request.id,
        originalPrintJobId: request.originalPrintJobId,
        batchId: request.batchId,
        licenseeId: request.licenseeId,
        manufacturerId: request.manufacturerId,
        preferredTab: "reissue",
        preferredSection: "review",
        targetRoute: `/batches?batchId=${encodeURIComponent(String(request.batchId || ""))}&tab=reissue&reissueRequestId=${encodeURIComponent(request.id)}`,
      },
      channels: [NotificationChannel.WEB],
    });

    await createUserNotification({
      userId: request.requestedByUserId,
      licenseeId: request.licenseeId,
      type: "print_reissue_forwarded",
      title: "Print reissue forwarded",
      body: "Your replacement label request was forwarded for super admin review.",
      data: {
        entityType: "reissue_request",
        entityId: request.id,
        reissueRequestId: request.id,
        originalPrintJobId: request.originalPrintJobId,
        batchId: request.batchId,
        licenseeId: request.licenseeId,
        manufacturerId: request.manufacturerId,
        preferredTab: "reissue",
        preferredSection: "status",
        targetRoute: `/batches?batchId=${encodeURIComponent(String(request.batchId || ""))}&tab=reissue&reissueRequestId=${encodeURIComponent(request.id)}`,
      },
    });

    return { request: serializeRequest(forwarded, await loadProjectionForRequest(forwarded)), result: null };
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

  await createUserNotification({
    userId: request.requestedByUserId,
    licenseeId: request.licenseeId,
    type: "print_reissue_approved",
    title: "Print reissue request approved",
    body: "A replacement label request was approved and is ready to print.",
    data: {
      entityType: "reissue_request",
      entityId: request.id,
      reissueRequestId: request.id,
      originalPrintJobId: request.originalPrintJobId,
      batchId: request.batchId,
      licenseeId: request.licenseeId,
      manufacturerId: request.manufacturerId,
      preferredTab: "reissue",
      preferredSection: "replacement-ready",
      targetRoute: `/batches?batchId=${encodeURIComponent(String(request.batchId || ""))}&tab=reissue&reissueRequestId=${encodeURIComponent(request.id)}`,
    },
  });

  return { request: serializeRequest(approved, await loadProjectionForRequest(approved)), result: null };
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
    return {
      request: serializeRequest(request, await loadProjectionForRequest(request)),
      result: serializeReplacementPrintStart(request, true),
      idempotent: true,
    };
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

  return { request: serializeRequest(executed, await loadProjectionForRequest(executed)), result, idempotent: false };
};
