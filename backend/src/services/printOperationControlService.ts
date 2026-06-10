import {
  PrintItemEventType,
  PrintItemState,
  PrintJobStatus,
  PrintPipelineState,
  PrintSessionStatus,
  Prisma,
  QRStatus,
} from "@prisma/client";

import prisma from "../config/database";
import { createAuditLog } from "./auditService";
import { buildScopedPrintJobWhere, type PrintJobScope } from "./printJobScopeService";
import { getPrintJobOperationalView } from "./networkDirectPrintService";

type PrintControlAction = "pause" | "resume" | "stop";

const MIN_REASON_LENGTH = 8;

export const validatePrintOperationReason = (reason: string) => {
  const trimmed = String(reason || "").replace(/\s+/g, " ").trim();
  if (trimmed.length < MIN_REASON_LENGTH) {
    throw Object.assign(new Error("A clear reason is required."), { statusCode: 400 });
  }
  return trimmed.slice(0, 500);
};

const getScopedJobForControl = async (params: { printJobId: string; scope: PrintJobScope }) =>
  prisma.printJob.findFirst({
    where: buildScopedPrintJobWhere(params.scope, { id: params.printJobId }),
    include: {
      batch: { select: { id: true, licenseeId: true, name: true } },
      printSession: {
        include: {
          items: {
            select: {
              id: true,
              qrCodeId: true,
              state: true,
              code: true,
            },
            orderBy: [{ issueSequence: "asc" }, { code: "asc" }],
          },
        },
      },
    },
  });

const activeJobStatuses: PrintJobStatus[] = [PrintJobStatus.PENDING, PrintJobStatus.SENT, PrintJobStatus.PAUSED, PrintJobStatus.PARTIALLY_COMPLETED];
const activeSessionStatuses: PrintSessionStatus[] = [
  PrintSessionStatus.ACTIVE,
  PrintSessionStatus.PAUSED,
  PrintSessionStatus.RESUME_PENDING,
  PrintSessionStatus.RETRY_WAITING,
];

const createPrintAudit = async (tx: Prisma.TransactionClient, params: {
  batchId: string;
  printJobId: string;
  actorUserId: string;
  eventType: string;
  metadata: Record<string, unknown>;
}) =>
  tx.printAuditEvent.create({
    data: {
      batchId: params.batchId,
      printJobId: params.printJobId,
      actorId: params.actorUserId,
      eventType: params.eventType,
      metadata: params.metadata as Prisma.InputJsonValue,
    },
  });

const auditControlAction = async (params: {
  action: PrintControlAction;
  actorUserId: string;
  licenseeId?: string | null;
  printJobId: string;
  printSessionId: string;
  reason: string;
  previousStatus?: string | null;
  nextStatus?: string | null;
  counts?: Record<string, number>;
}) =>
  createAuditLog({
    userId: params.actorUserId,
    licenseeId: params.licenseeId || undefined,
    action:
      params.action === "pause"
        ? "PRINT_JOB_PAUSED"
        : params.action === "resume"
        ? "PRINT_JOB_RESUMED"
        : "PRINT_JOB_STOPPED",
    entityType: "PrintJob",
    entityId: params.printJobId,
    details: {
      printSessionId: params.printSessionId,
      reason: params.reason,
      previousStatus: params.previousStatus || null,
      nextStatus: params.nextStatus || null,
      counts: params.counts || null,
    },
  });

export const pausePrintJob = async (params: {
  printJobId: string;
  scope: PrintJobScope;
  reason: string;
}) => {
  const reason = validatePrintOperationReason(params.reason);
  const job = await getScopedJobForControl(params);
  if (!job || !job.printSession) throw Object.assign(new Error("Print job not found"), { statusCode: 404 });

  if (job.printSession.status === PrintSessionStatus.PAUSED || job.status === PrintJobStatus.PAUSED) {
    return { view: await getPrintJobOperationalView({ jobId: job.id, scope: params.scope }), idempotent: true };
  }

  if (!activeJobStatuses.includes(job.status) || !activeSessionStatuses.includes(job.printSession.status)) {
    throw Object.assign(new Error("This print run cannot be paused in its current state."), { statusCode: 409 });
  }

  await prisma.$transaction(async (tx) => {
    await tx.printSession.update({
      where: { id: job.printSession!.id },
      data: {
        status: PrintSessionStatus.PAUSED,
        failedReason: reason,
      },
    });
    await tx.printJob.update({
      where: { id: job.id },
      data: {
        status: PrintJobStatus.PAUSED,
        pipelineState: PrintPipelineState.PAUSED,
        failureReason: reason,
      },
    });
    await createPrintAudit(tx, {
      batchId: job.batchId,
      printJobId: job.id,
      actorUserId: params.scope.userId,
      eventType: "print_job_paused",
      metadata: {
        reason,
        previousJobStatus: job.status,
        previousSessionStatus: job.printSession!.status,
      },
    });
  });

  await auditControlAction({
    action: "pause",
    actorUserId: params.scope.userId,
    licenseeId: job.batch.licenseeId,
    printJobId: job.id,
    printSessionId: job.printSession.id,
    reason,
    previousStatus: job.printSession.status,
    nextStatus: PrintSessionStatus.PAUSED,
  });

  return { view: await getPrintJobOperationalView({ jobId: job.id, scope: params.scope }), idempotent: false };
};

export const resumePrintJob = async (params: {
  printJobId: string;
  scope: PrintJobScope;
}) => {
  const job = await getScopedJobForControl(params);
  if (!job || !job.printSession) throw Object.assign(new Error("Print job not found"), { statusCode: 404 });

  if (job.printSession.status === PrintSessionStatus.ACTIVE && ([PrintJobStatus.PENDING, PrintJobStatus.SENT] as PrintJobStatus[]).includes(job.status)) {
    return { view: await getPrintJobOperationalView({ jobId: job.id, scope: params.scope }), idempotent: true };
  }

  if (!([PrintSessionStatus.PAUSED, PrintSessionStatus.RESUME_PENDING, PrintSessionStatus.RETRY_WAITING] as PrintSessionStatus[]).includes(job.printSession.status)) {
    throw Object.assign(new Error("This print run cannot be resumed in its current state."), { statusCode: 409 });
  }

  const hasRemaining = job.printSession.items.some((item) =>
    ([PrintItemState.RESERVED, PrintItemState.ISSUED, PrintItemState.AGENT_ACKED] as PrintItemState[]).includes(item.state)
  );
  if (!hasRemaining) {
    throw Object.assign(new Error("No remaining labels are available to resume."), { statusCode: 409 });
  }

  await prisma.$transaction(async (tx) => {
    await tx.printSession.update({
      where: { id: job.printSession!.id },
      data: {
        status: PrintSessionStatus.ACTIVE,
        failedReason: null,
      },
    });
    await tx.printJob.update({
      where: { id: job.id },
      data: {
        status: job.sentAt ? PrintJobStatus.SENT : PrintJobStatus.PENDING,
        pipelineState: job.sentAt ? PrintPipelineState.SENT_TO_PRINTER : PrintPipelineState.QUEUED,
        failureReason: null,
      },
    });
    await createPrintAudit(tx, {
      batchId: job.batchId,
      printJobId: job.id,
      actorUserId: params.scope.userId,
      eventType: "print_job_resumed",
      metadata: {
        previousJobStatus: job.status,
        previousSessionStatus: job.printSession!.status,
      },
    });
  });

  await auditControlAction({
    action: "resume",
    actorUserId: params.scope.userId,
    licenseeId: job.batch.licenseeId,
    printJobId: job.id,
    printSessionId: job.printSession.id,
    reason: "Operator resumed paused print run.",
    previousStatus: job.printSession.status,
    nextStatus: PrintSessionStatus.ACTIVE,
  });

  return { view: await getPrintJobOperationalView({ jobId: job.id, scope: params.scope }), idempotent: false };
};

export const stopPrintJob = async (params: {
  printJobId: string;
  scope: PrintJobScope;
  reason: string;
}) => {
  const reason = validatePrintOperationReason(params.reason);
  const job = await getScopedJobForControl(params);
  if (!job || !job.printSession) throw Object.assign(new Error("Print job not found"), { statusCode: 404 });

  if (job.printSession.status === PrintSessionStatus.STOPPED || job.status === PrintJobStatus.STOPPED) {
    return { view: await getPrintJobOperationalView({ jobId: job.id, scope: params.scope }), idempotent: true };
  }

  if (([PrintSessionStatus.COMPLETED, PrintSessionStatus.CANCELLED] as PrintSessionStatus[]).includes(job.printSession.status)) {
    throw Object.assign(new Error("This print run is already closed."), { statusCode: 409 });
  }

  const cancellable = job.printSession.items.filter((item) =>
    ([PrintItemState.RESERVED, PrintItemState.ISSUED, PrintItemState.AGENT_ACKED, PrintItemState.FAILED] as PrintItemState[]).includes(item.state)
  );
  const confirmedCount = job.printSession.items.filter((item) =>
    ([PrintItemState.PRINT_CONFIRMED, PrintItemState.CLOSED] as PrintItemState[]).includes(item.state)
  ).length;
  const cancellableIds = cancellable.map((item) => item.id);
  const cancellableQrIds = cancellable.map((item) => item.qrCodeId);

  await prisma.$transaction(async (tx) => {
    await tx.printSession.update({
      where: { id: job.printSession!.id },
      data: {
        status: PrintSessionStatus.STOPPED,
        failedReason: reason,
        completedAt: new Date(),
      },
    });
    await tx.printJob.update({
      where: { id: job.id },
      data: {
        status: confirmedCount > 0 ? PrintJobStatus.PARTIALLY_COMPLETED : PrintJobStatus.STOPPED,
        pipelineState: PrintPipelineState.STOPPED,
        failureReason: reason,
        completedAt: new Date(),
      },
    });
    if (cancellableIds.length > 0) {
      await tx.printItem.updateMany({
        where: { id: { in: cancellableIds } },
        data: {
          state: PrintItemState.CANCELLED,
          pipelineState: PrintPipelineState.STOPPED,
          failedAt: new Date(),
          failureReason: reason,
          deadLetterReason: "operator_stopped_print_run",
          closedAt: new Date(),
        },
      });
      await tx.printItemEvent.createMany({
        data: cancellable.map((item) => ({
          printItemId: item.id,
          eventType: PrintItemEventType.CANCELLED,
          previousState: item.state,
          nextState: PrintItemState.CANCELLED,
          actorUserId: params.scope.userId,
          details: {
            reason,
            action: "operator_stopped_print_run",
          },
        })),
      });
      // scope-guardrail-ignore: job was loaded through buildScopedPrintJobWhere; this release is further bounded to QR ids from that scoped print session, printJobId, batchId, and unconfirmed statuses.
      await tx.qRCode.updateMany({
        where: {
          id: { in: cancellableQrIds },
          printJobId: job.id,
          batchId: job.batchId,
          status: { in: [QRStatus.ACTIVATED, QRStatus.ALLOCATED] },
        },
        data: {
          status: QRStatus.ALLOCATED,
          printJobId: null,
          tokenNonce: null,
          tokenIssuedAt: null,
          tokenExpiresAt: null,
          tokenHash: null,
          issuanceMode: "LEGACY_UNSPECIFIED",
        },
      });
    }
    await createPrintAudit(tx, {
      batchId: job.batchId,
      printJobId: job.id,
      actorUserId: params.scope.userId,
      eventType: "print_job_stopped",
      metadata: {
        reason,
        previousJobStatus: job.status,
        previousSessionStatus: job.printSession!.status,
        cancelledItems: cancellableIds.length,
        confirmedItems: confirmedCount,
      },
    });
  });

  await auditControlAction({
    action: "stop",
    actorUserId: params.scope.userId,
    licenseeId: job.batch.licenseeId,
    printJobId: job.id,
    printSessionId: job.printSession.id,
    reason,
    previousStatus: job.printSession.status,
    nextStatus: PrintSessionStatus.STOPPED,
    counts: {
      cancelledItems: cancellableIds.length,
      confirmedItems: confirmedCount,
    },
  });

  return { view: await getPrintJobOperationalView({ jobId: job.id, scope: params.scope }), idempotent: false };
};
