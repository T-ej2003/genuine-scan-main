import {
  IncidentActorType,
  IncidentEventType,
  IncidentPriority,
  IncidentSeverity,
  IncidentType,
  PrintJobStatus,
  PrintItemEventType,
  PrintItemState,
  PrintSessionStatus,
  Prisma,
  QRStatus,
} from "@prisma/client";

import prisma from "../config/database";
import { createAuditLog } from "./auditService";

export const OPEN_PRINT_STATES: PrintItemState[] = [
  PrintItemState.RESERVED,
  PrintItemState.ISSUED,
  PrintItemState.AGENT_ACKED,
];

const CLOSABLE_PRINT_STATES: PrintItemState[] = [PrintItemState.PRINT_CONFIRMED];

const mapLegacyPrintItemState = (status: QRStatus): PrintItemState => {
  if (status === QRStatus.PRINTED || status === QRStatus.REDEEMED || status === QRStatus.SCANNED) {
    return PrintItemState.CLOSED;
  }
  if (status === QRStatus.BLOCKED) {
    return PrintItemState.FROZEN;
  }
  return PrintItemState.RESERVED;
};

export const getOrCreatePrintSession = async (job: {
  id: string;
  batchId: string;
  manufacturerId: string;
  quantity: number;
  status: string;
  printerRegistrationId?: string | null;
  printerId?: string | null;
}) => {
  const existing = await prisma.printSession.findUnique({ where: { printJobId: job.id } });
  if (existing) return existing;

  return prisma.$transaction(async (tx) => {
    const stillExisting = await tx.printSession.findUnique({ where: { printJobId: job.id } });
    if (stillExisting) return stillExisting;

    const qrRows = await tx.qRCode.findMany({
      where: { printJobId: job.id },
      orderBy: { code: "asc" },
      select: { id: true, code: true, status: true },
    });

    const totalItems = qrRows.length || job.quantity;

    const created = await tx.printSession.create({
      data: {
        printJobId: job.id,
        batchId: job.batchId,
        manufacturerId: job.manufacturerId,
        printerRegistrationId: job.printerRegistrationId || null,
        printerId: job.printerId || null,
        status: job.status === "CONFIRMED" ? PrintSessionStatus.COMPLETED : PrintSessionStatus.ACTIVE,
        totalItems,
        issuedItems: qrRows.filter((row) => row.status !== QRStatus.ALLOCATED && row.status !== QRStatus.ACTIVATED).length,
        confirmedItems: qrRows.filter((row) => row.status === QRStatus.PRINTED || row.status === QRStatus.REDEEMED || row.status === QRStatus.SCANNED).length,
        completedAt: job.status === "CONFIRMED" ? new Date() : null,
      },
    });

    if (qrRows.length > 0) {
      await tx.printItem.createMany({
        data: qrRows.map((row) => ({
          printSessionId: created.id,
          qrCodeId: row.id,
          code: row.code,
          state: mapLegacyPrintItemState(row.status),
          issuedAt: row.status === QRStatus.ACTIVATED ? null : new Date(),
          printConfirmedAt:
            row.status === QRStatus.PRINTED || row.status === QRStatus.REDEEMED || row.status === QRStatus.SCANNED
              ? new Date()
              : null,
          closedAt:
            row.status === QRStatus.PRINTED || row.status === QRStatus.REDEEMED || row.status === QRStatus.SCANNED
              ? new Date()
              : null,
        })),
        skipDuplicates: true,
      });
    }

    return created;
  });
};

export const countRemainingToPrint = async (tx: Prisma.TransactionClient, printSessionId: string) => {
  return tx.printItem.count({
    where: {
      printSessionId,
      state: { in: OPEN_PRINT_STATES },
    },
  });
};

export const finalizePrintSessionIfReady = async (params: {
  tx: Prisma.TransactionClient;
  printSessionId: string;
  printJobId: string;
  batchId: string;
  now: Date;
  actorUserId: string;
}) => {
  const remainingToPrint = await countRemainingToPrint(params.tx, params.printSessionId);
  let confirmedAt: Date | null = null;

  if (remainingToPrint > 0) {
    return {
      remainingToPrint,
      jobConfirmed: false,
      confirmedAt,
    };
  }

  const closableItems = await params.tx.printItem.findMany({
    where: {
      printSessionId: params.printSessionId,
      state: { in: CLOSABLE_PRINT_STATES },
    },
    select: { id: true },
  });

  if (closableItems.length > 0) {
    await params.tx.printItem.updateMany({
      where: {
        id: { in: closableItems.map((item) => item.id) },
        state: { in: CLOSABLE_PRINT_STATES },
      },
      data: {
        state: PrintItemState.CLOSED,
        closedAt: params.now,
      },
    });

    await params.tx.printItemEvent.createMany({
      data: closableItems.map((item) => ({
        printItemId: item.id,
        eventType: PrintItemEventType.CLOSED,
        previousState: PrintItemState.PRINT_CONFIRMED,
        nextState: PrintItemState.CLOSED,
        actorUserId: params.actorUserId,
        details: {
          reason: "session_completed",
        },
      })),
    });
  }

  await params.tx.printSession.update({
    where: { id: params.printSessionId },
    data: {
      status: PrintSessionStatus.COMPLETED,
      completedAt: params.now,
    },
  });

  const jobUpdate = await params.tx.printJob.updateMany({
    where: { id: params.printJobId, status: { in: [PrintJobStatus.PENDING, PrintJobStatus.SENT] } },
    data: { status: PrintJobStatus.CONFIRMED, confirmedAt: params.now, completedAt: params.now },
  });

  if (jobUpdate.count > 0) {
    await params.tx.batch.update({
      where: { id: params.batchId },
      data: { printedAt: params.now },
    });
    confirmedAt = params.now;
  } else {
    const currentJob = await params.tx.printJob.findUnique({ where: { id: params.printJobId }, select: { confirmedAt: true } });
    confirmedAt = currentJob?.confirmedAt || null;
  }

  return {
    remainingToPrint: 0,
    jobConfirmed: true,
    confirmedAt,
  };
};

const createFailStopIncident = async (params: {
  tx: Prisma.TransactionClient;
  printJobId: string;
  printSessionId: string;
  licenseeId: string | null;
  reason: string;
  actorUserId?: string | null;
  diagnostics: Record<string, any>;
}) => {
  const incident = await params.tx.incident.create({
    data: {
      qrCodeValue: `PRINT_JOB:${params.printJobId}`,
      licenseeId: params.licenseeId,
      reportedBy: "ADMIN",
      incidentType: IncidentType.OTHER,
      severity: IncidentSeverity.CRITICAL,
      priority: IncidentPriority.P1,
      description: `Direct-print fail-stop triggered for session ${params.printSessionId}: ${params.reason}`,
      tags: ["print_fail_stop", "direct_print", `print_job_${params.printJobId}`],
    },
  });

  await params.tx.incidentEvent.create({
    data: {
      incidentId: incident.id,
      actorType: IncidentActorType.SYSTEM,
      actorUserId: params.actorUserId || null,
      eventType: IncidentEventType.CREATED,
      eventPayload: {
        reason: params.reason,
        diagnostics: params.diagnostics,
        context: "DIRECT_PRINT_FAIL_STOP",
      },
    },
  });

  return incident;
};

export const failStopPrintSession = async (params: {
  printSessionId: string;
  printJobId: string;
  batchId: string;
  licenseeId: string | null;
  actorUserId: string;
  reason: string;
  printItemId?: string;
  retries?: number;
  metadata?: any;
}) => {
  const now = new Date();

  const result = await prisma.$transaction(async (tx) => {
    const session = await tx.printSession.findUnique({
      where: { id: params.printSessionId },
      select: { id: true, status: true },
    });
    if (!session) throw new Error("PRINT_SESSION_NOT_FOUND");

    const toFreeze = await tx.printItem.findMany({
      where: {
        printSessionId: params.printSessionId,
        state: { in: [PrintItemState.RESERVED, PrintItemState.ISSUED, PrintItemState.AGENT_ACKED, PrintItemState.PRINT_CONFIRMED] },
      },
      select: { id: true, code: true, qrCodeId: true, state: true },
    });

    let failedItem: { id: string; code: string } | null = null;
    if (params.printItemId) {
      const updated = await tx.printItem.updateMany({
        where: {
          id: params.printItemId,
          printSessionId: params.printSessionId,
          state: { in: [PrintItemState.ISSUED, PrintItemState.AGENT_ACKED, PrintItemState.PRINT_CONFIRMED] },
        },
        data: {
          state: PrintItemState.FAILED,
          failedAt: now,
          failureReason: params.reason,
          deadLetterReason: params.reason,
        },
      });
      if (updated.count > 0) {
        const row = await tx.printItem.findUnique({ where: { id: params.printItemId }, select: { id: true, code: true } });
        failedItem = row || null;
      }
    }

    const freezeTargets = toFreeze.filter((item) => item.id !== params.printItemId);
    if (freezeTargets.length > 0) {
      await tx.printItem.updateMany({
        where: { id: { in: freezeTargets.map((item) => item.id) } },
        data: {
          state: PrintItemState.FROZEN,
          frozenAt: now,
          failureReason: params.reason,
        },
      });

      await tx.qRCode.updateMany({
        where: {
          id: { in: freezeTargets.map((item) => item.qrCodeId) },
          status: { in: [QRStatus.ACTIVATED, QRStatus.PRINTED] },
        },
        data: {
          status: QRStatus.BLOCKED,
          blockedAt: now,
          underInvestigationAt: now,
          underInvestigationReason: `Print fail-stop: ${params.reason}`,
        },
      });
    }

    if (failedItem) {
      await tx.printItemEvent.create({
        data: {
          printItemId: failedItem.id,
          eventType: PrintItemEventType.FAILED,
          nextState: PrintItemState.FAILED,
          actorUserId: params.actorUserId,
          details: {
            reason: params.reason,
            retries: params.retries ?? 0,
            metadata: params.metadata ?? null,
          },
        },
      });
    }

    if (freezeTargets.length > 0) {
      await tx.printItemEvent.createMany({
        data: freezeTargets.map((item) => ({
          printItemId: item.id,
          eventType: PrintItemEventType.FROZEN,
          previousState: item.state,
          nextState: PrintItemState.FROZEN,
          actorUserId: params.actorUserId,
          details: {
            reason: params.reason,
            metadata: params.metadata ?? null,
          },
        })),
      });
    }

    await tx.printSession.update({
      where: { id: params.printSessionId },
      data: {
        status: PrintSessionStatus.FAILED,
        failedReason: params.reason,
        frozenItems: freezeTargets.length,
      },
    });

    await tx.printJob.updateMany({
      where: { id: params.printJobId, status: { in: [PrintJobStatus.PENDING, PrintJobStatus.SENT] } },
      data: { status: PrintJobStatus.FAILED, failureReason: params.reason, completedAt: now },
    });

    const incident = await createFailStopIncident({
      tx,
      printJobId: params.printJobId,
      printSessionId: params.printSessionId,
      licenseeId: params.licenseeId,
      actorUserId: params.actorUserId,
      reason: params.reason,
      diagnostics: {
        printItemId: params.printItemId || null,
        retries: params.retries ?? 0,
        failedItemCode: failedItem?.code || null,
        frozenCount: freezeTargets.length,
        metadata: params.metadata ?? null,
      },
    });

    return {
      incident,
      failedItem,
      frozenCount: freezeTargets.length,
    };
  });

  await createAuditLog({
    userId: params.actorUserId,
    licenseeId: params.licenseeId || undefined,
    action: "DIRECT_PRINT_FAIL_STOP",
    entityType: "PrintSession",
    entityId: params.printSessionId,
    details: {
      printJobId: params.printJobId,
      reason: params.reason,
      printItemId: params.printItemId || null,
      retries: params.retries ?? 0,
      frozenCount: result.frozenCount,
      incidentId: result.incident.id,
      metadata: params.metadata ?? null,
    },
  });

  return result;
};
