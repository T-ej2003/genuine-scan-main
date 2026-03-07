import {
  NotificationAudience,
  NotificationChannel,
  PrintDispatchMode,
  PrintJobStatus,
  PrintItemEventType,
  PrintItemState,
  PrintSessionStatus,
  PrintPayloadType,
  PrinterConnectionType,
  QRStatus,
} from "@prisma/client";

import prisma from "../config/database";
import { logger } from "../utils/logger";
import { sendRawPayloadToNetworkPrinter } from "./networkPrinterSocketService";
import { buildApprovedPrintPayload, supportsNetworkDirectPayload } from "./printPayloadService";
import { failStopPrintSession, finalizePrintSessionIfReady, getOrCreatePrintSession, OPEN_PRINT_STATES } from "./printLifecycleService";
import { createAuditLog } from "./auditService";
import { createRoleNotifications, createUserNotification } from "./notificationService";

const activeDispatches = new Set<string>();
const NETWORK_DIRECT_CHUNK_SIZE = Math.max(1, Math.min(250, Number(process.env.NETWORK_DIRECT_CHUNK_SIZE || 25) || 25));

const notifySystemPrintEvent = async (params: {
  licenseeId?: string | null;
  orgId?: string | null;
  type: string;
  title: string;
  body: string;
  data?: any;
  channels?: NotificationChannel[];
}) => {
  const channels = params.channels && params.channels.length > 0 ? params.channels : [NotificationChannel.WEB];

  await Promise.allSettled([
    createRoleNotifications({
      audience: NotificationAudience.SUPER_ADMIN,
      type: params.type,
      title: params.title,
      body: params.body,
      licenseeId: params.licenseeId || null,
      orgId: params.orgId || null,
      data: params.data || null,
      channels,
    }),
    params.licenseeId
      ? createRoleNotifications({
          audience: NotificationAudience.LICENSEE_ADMIN,
          licenseeId: params.licenseeId,
          type: params.type,
          title: params.title,
          body: params.body,
          data: params.data || null,
          channels: [NotificationChannel.WEB],
        })
      : Promise.resolve([] as any[]),
    params.orgId
      ? createRoleNotifications({
          audience: NotificationAudience.MANUFACTURER,
          licenseeId: params.licenseeId || null,
          orgId: params.orgId,
          type: params.type,
          title: params.title,
          body: params.body,
          data: params.data || null,
          channels: [NotificationChannel.WEB],
        })
      : Promise.resolve([] as any[]),
  ]);
};

const loadNetworkDispatchJob = async (jobId: string) => {
  return prisma.printJob.findUnique({
    where: { id: jobId },
    include: {
      batch: { select: { id: true, name: true, licenseeId: true } },
      printer: true,
      printSession: true,
    },
  });
};

const markJobSent = async (jobId: string) => {
  const now = new Date();
  await prisma.printJob.updateMany({
    where: { id: jobId, status: PrintJobStatus.PENDING },
    data: { status: PrintJobStatus.SENT, sentAt: now },
  });
};

const ensureSafeResumeState = async (sessionId: string) => {
  const ambiguous = await prisma.printItem.count({
    where: {
      printSessionId: sessionId,
      state: { in: [PrintItemState.ISSUED, PrintItemState.AGENT_ACKED, PrintItemState.PRINT_CONFIRMED] },
    },
  });
  return ambiguous;
};

const reserveNextChunk = async (params: { sessionId: string; actorUserId: string; chunkSize: number }) => {
  const now = new Date();
  return prisma.$transaction(async (tx) => {
    const rows = await tx.printItem.findMany({
      where: {
        printSessionId: params.sessionId,
        state: PrintItemState.RESERVED,
      },
      orderBy: { code: "asc" },
      take: params.chunkSize,
      include: {
        qrCode: {
          select: {
            id: true,
            code: true,
            batchId: true,
            licenseeId: true,
            tokenNonce: true,
            tokenIssuedAt: true,
            tokenExpiresAt: true,
            tokenHash: true,
            status: true,
          },
        },
      },
    });

    if (!rows.length) return [] as typeof rows;

    const session = await tx.printSession.findUnique({ where: { id: params.sessionId }, select: { issuedItems: true } });
    const startingSequence = Number(session?.issuedItems || 0);

    for (const [index, row] of rows.entries()) {
      const updated = await tx.printItem.updateMany({
        where: {
          id: row.id,
          state: PrintItemState.RESERVED,
        },
        data: {
          state: PrintItemState.ISSUED,
          issuedAt: now,
          issueSequence: startingSequence + index + 1,
        },
      });
      if (updated.count === 0) {
        throw new Error("PRINT_ITEM_RESERVE_CONFLICT");
      }
    }

    await tx.printItemEvent.createMany({
      data: rows.map((row) => ({
        printItemId: row.id,
        eventType: PrintItemEventType.ISSUED,
        previousState: PrintItemState.RESERVED,
        nextState: PrintItemState.ISSUED,
        actorUserId: params.actorUserId,
        details: {
          dispatchMode: PrintDispatchMode.NETWORK_DIRECT,
        },
      })),
    });

    await tx.printSession.update({
      where: { id: params.sessionId },
      data: {
        issuedItems: { increment: rows.length },
      },
    });

    return rows;
  });
};

const confirmNetworkPrintedItem = async (params: {
  sessionId: string;
  jobId: string;
  batchId: string;
  actorUserId: string;
  item: {
    id: string;
    qrCodeId: string;
    code: string;
    qrCode: { status: QRStatus };
  };
  payloadType: PrintPayloadType;
  payloadHash: string;
  bytesWritten: number;
}) => {
  const now = new Date();
  return prisma.$transaction(async (tx) => {
    const acked = await tx.printItem.updateMany({
      where: { id: params.item.id, state: PrintItemState.ISSUED },
      data: {
        state: PrintItemState.AGENT_ACKED,
        agentAckedAt: now,
        attemptCount: { increment: 1 },
      },
    });
    if (acked.count === 0) throw new Error("NETWORK_DIRECT_ACK_CONFLICT");

    await tx.printItemEvent.create({
      data: {
        printItemId: params.item.id,
        eventType: PrintItemEventType.AGENT_ACKED,
        previousState: PrintItemState.ISSUED,
        nextState: PrintItemState.AGENT_ACKED,
        actorUserId: params.actorUserId,
        details: {
          dispatchMode: PrintDispatchMode.NETWORK_DIRECT,
          payloadType: params.payloadType,
          payloadHash: params.payloadHash,
          bytesWritten: params.bytesWritten,
        },
      },
    });

    const confirmed = await tx.printItem.updateMany({
      where: { id: params.item.id, state: PrintItemState.AGENT_ACKED },
      data: {
        state: PrintItemState.PRINT_CONFIRMED,
        printConfirmedAt: now,
      },
    });
    if (confirmed.count === 0) throw new Error("NETWORK_DIRECT_CONFIRM_CONFLICT");

    await tx.printItemEvent.create({
      data: {
        printItemId: params.item.id,
        eventType: PrintItemEventType.PRINT_CONFIRMED,
        previousState: PrintItemState.AGENT_ACKED,
        nextState: PrintItemState.PRINT_CONFIRMED,
        actorUserId: params.actorUserId,
        details: {
          dispatchMode: PrintDispatchMode.NETWORK_DIRECT,
          payloadType: params.payloadType,
          payloadHash: params.payloadHash,
          bytesWritten: params.bytesWritten,
        },
      },
    });

    const qrUpdated = await tx.qRCode.updateMany({
      where: {
        id: params.item.qrCodeId,
        printJobId: params.jobId,
        status: QRStatus.ACTIVATED,
      },
      data: {
        status: QRStatus.PRINTED,
        printedAt: now,
        printedByUserId: params.actorUserId,
      },
    });

    if (qrUpdated.count === 0 && params.item.qrCode.status !== QRStatus.PRINTED) {
      throw new Error("NETWORK_DIRECT_QR_NOT_PRINTABLE");
    }

    await tx.printSession.update({
      where: { id: params.sessionId },
      data: {
        confirmedItems: { increment: 1 },
      },
    });

    return finalizePrintSessionIfReady({
      tx,
      printSessionId: params.sessionId,
      printJobId: params.jobId,
      batchId: params.batchId,
      now,
      actorUserId: params.actorUserId,
    });
  });
};

export const getPrintJobOperationalView = async (params: { jobId: string; userId: string }) => {
  const job = await prisma.printJob.findFirst({
    where: {
      id: params.jobId,
      manufacturerId: params.userId,
    },
    include: {
      batch: { select: { id: true, name: true, licenseeId: true } },
      printer: {
        select: {
          id: true,
          name: true,
          connectionType: true,
          commandLanguage: true,
          ipAddress: true,
          port: true,
          nativePrinterId: true,
        },
      },
      printSession: {
        select: {
          id: true,
          status: true,
          totalItems: true,
          issuedItems: true,
          confirmedItems: true,
          frozenItems: true,
          failedReason: true,
          startedAt: true,
          completedAt: true,
        },
      },
    },
  });
  if (!job) return null;

  const stateCounts = await prisma.printItem.groupBy({
    by: ["state"],
    where: { printSessionId: job.printSession?.id || "__missing__" },
    _count: { _all: true },
  });
  const counts = stateCounts.reduce<Record<string, number>>((acc, row) => {
    acc[row.state] = row._count._all;
    return acc;
  }, {});
  const remainingToPrint = job.printSession?.id ? await prisma.printItem.count({ where: { printSessionId: job.printSession.id, state: { in: OPEN_PRINT_STATES } } }) : 0;

  return {
    id: job.id,
    jobNumber: job.jobNumber,
    status: job.status,
    printMode: job.printMode,
    quantity: job.quantity,
    itemCount: job.itemCount || job.quantity,
    failureReason: job.failureReason,
    createdAt: job.createdAt,
    updatedAt: job.updatedAt,
    sentAt: job.sentAt,
    confirmedAt: job.confirmedAt,
    completedAt: job.completedAt,
    batch: job.batch,
    printer: job.printer,
    session: {
      ...(job.printSession || null),
      remainingToPrint,
      counts,
    },
  };
};

export const listPrintJobsForManufacturer = async (params: {
  userId: string;
  batchId?: string;
  limit?: number;
}) => {
  const jobs = await prisma.printJob.findMany({
    where: {
      manufacturerId: params.userId,
      ...(params.batchId ? { batchId: params.batchId } : {}),
    },
    include: {
      batch: { select: { id: true, name: true } },
      printer: { select: { id: true, name: true, connectionType: true, commandLanguage: true } },
      printSession: { select: { id: true, status: true, totalItems: true, confirmedItems: true, frozenItems: true, failedReason: true } },
    },
    orderBy: [{ createdAt: "desc" }],
    take: Math.max(1, Math.min(100, params.limit || 20)),
  });

  return jobs;
};

const runNetworkDirectDispatch = async (jobId: string, actorUserId: string) => {
  const job = await loadNetworkDispatchJob(jobId);
  if (!job) throw new Error("PRINT_JOB_NOT_FOUND");
  if (!job.printer || job.printer.connectionType !== PrinterConnectionType.NETWORK_DIRECT) {
    throw new Error("PRINT_JOB_NOT_NETWORK_DIRECT");
  }
  if (!job.printer.ipAddress || !job.printer.port) {
    throw new Error("NETWORK_PRINTER_CONFIGURATION_INVALID");
  }
  if (!supportsNetworkDirectPayload(job.printer as any)) {
    throw new Error("NETWORK_DIRECT_LANGUAGE_NOT_SUPPORTED");
  }

  const session = await getOrCreatePrintSession({
    id: job.id,
    batchId: job.batchId,
    manufacturerId: job.manufacturerId,
    quantity: job.quantity,
    status: job.status,
    printerRegistrationId: job.printSession?.printerRegistrationId || null,
    printerId: job.printerId || null,
  });

  if (session.status !== PrintSessionStatus.ACTIVE) {
    logger.info("Skipping network direct dispatch for inactive session", { jobId, sessionId: session.id, status: session.status });
    return;
  }

  const ambiguous = await ensureSafeResumeState(session.id);
  if (ambiguous > 0) {
    await failStopPrintSession({
      printSessionId: session.id,
      printJobId: job.id,
      batchId: job.batchId,
      licenseeId: job.batch.licenseeId || null,
      actorUserId,
      reason: `Network-direct dispatcher resumed with ${ambiguous} ambiguous in-flight items.`,
      metadata: { dispatchMode: PrintDispatchMode.NETWORK_DIRECT },
    });
    return;
  }

  await markJobSent(job.id);

  let done = false;
  while (!done) {
    const reservedItems = await reserveNextChunk({
      sessionId: session.id,
      actorUserId,
      chunkSize: NETWORK_DIRECT_CHUNK_SIZE,
    });

    if (!reservedItems.length) {
      const remaining = await prisma.printItem.count({
        where: {
          printSessionId: session.id,
          state: { in: OPEN_PRINT_STATES },
        },
      });
      if (remaining === 0) break;
      await failStopPrintSession({
        printSessionId: session.id,
        printJobId: job.id,
        batchId: job.batchId,
        licenseeId: job.batch.licenseeId || null,
        actorUserId,
        reason: `Network-direct dispatch stalled with ${remaining} remaining items but no reservable labels.`,
        metadata: { dispatchMode: PrintDispatchMode.NETWORK_DIRECT },
      });
      return;
    }

    for (const item of reservedItems) {
      if (item.qrCode.status !== QRStatus.ACTIVATED) {
        await failStopPrintSession({
          printSessionId: session.id,
          printJobId: job.id,
          batchId: job.batchId,
          licenseeId: job.batch.licenseeId || null,
          actorUserId,
          reason: `QR ${item.code} is not in ACTIVATED state for network direct printing.`,
          printItemId: item.id,
          metadata: { dispatchMode: PrintDispatchMode.NETWORK_DIRECT },
        });
        return;
      }

      let payload;
      try {
        payload = buildApprovedPrintPayload({
          printer: job.printer as any,
          qr: item.qrCode,
          manufacturerId: job.manufacturerId,
          printJobId: job.id,
          printItemId: item.id,
          jobNumber: job.jobNumber,
          reprintOfJobId: job.reprintOfJobId,
        });
      } catch (error: any) {
        await failStopPrintSession({
          printSessionId: session.id,
          printJobId: job.id,
          batchId: job.batchId,
          licenseeId: job.batch.licenseeId || null,
          actorUserId,
          reason: error?.message || `Payload generation failed for ${item.code}`,
          printItemId: item.id,
          metadata: { dispatchMode: PrintDispatchMode.NETWORK_DIRECT },
        });
        return;
      }

      try {
        const socketResult = await sendRawPayloadToNetworkPrinter({
          ipAddress: job.printer.ipAddress,
          port: job.printer.port,
          payload: payload.payloadContent,
        });

        await prisma.printJob.updateMany({
          where: { id: job.id, payloadHash: null },
          data: {
            payloadType: payload.payloadType,
            payloadHash: payload.payloadHash,
          },
        });

        const finalize = await confirmNetworkPrintedItem({
          sessionId: session.id,
          jobId: job.id,
          batchId: job.batchId,
          actorUserId,
          item: {
            id: item.id,
            qrCodeId: item.qrCodeId,
            code: item.code,
            qrCode: { status: item.qrCode.status },
          },
          payloadType: payload.payloadType,
          payloadHash: payload.payloadHash,
          bytesWritten: socketResult.bytesWritten,
        });

        await createAuditLog({
          userId: actorUserId,
          licenseeId: job.batch.licenseeId,
          action: "DIRECT_PRINT_ITEM_CONFIRMED",
          entityType: "PrintItem",
          entityId: item.id,
          details: {
            printJobId: job.id,
            printSessionId: session.id,
            dispatchMode: PrintDispatchMode.NETWORK_DIRECT,
            qrId: item.qrCodeId,
            code: item.code,
            payloadType: payload.payloadType,
            payloadHash: payload.payloadHash,
            remainingToPrint: finalize.remainingToPrint,
          },
        });
      } catch (error: any) {
        await failStopPrintSession({
          printSessionId: session.id,
          printJobId: job.id,
          batchId: job.batchId,
          licenseeId: job.batch.licenseeId || null,
          actorUserId,
          reason: error?.message || `Network printer dispatch failed for ${item.code}`,
          printItemId: item.id,
          metadata: {
            dispatchMode: PrintDispatchMode.NETWORK_DIRECT,
            printerId: job.printer.id,
            printerName: job.printer.name,
          },
        });

        const alertBody = `Network-direct fail-stop activated for ${job.batch.name}. Reason: ${error?.message || "Dispatch error"}`;
        await notifySystemPrintEvent({
          licenseeId: job.batch.licenseeId,
          orgId: job.printer.orgId || null,
          type: "system_print_job_failed",
          title: "Network-direct fail-stop triggered",
          body: alertBody,
          data: {
            printJobId: job.id,
            printSessionId: session.id,
            reason: error?.message || "Dispatch error",
            targetRoute: "/batches",
          },
          channels: [NotificationChannel.WEB, NotificationChannel.EMAIL],
        });
        return;
      }
    }

    const remaining = await prisma.printItem.count({
      where: {
        printSessionId: session.id,
        state: { in: OPEN_PRINT_STATES },
      },
    });
    done = remaining === 0;
  }

  const fresh = await prisma.printJob.findUnique({ where: { id: job.id }, select: { status: true } });
  if (fresh?.status === PrintJobStatus.CONFIRMED) {
    await Promise.allSettled([
      createUserNotification({
        userId: actorUserId,
        licenseeId: job.batch.licenseeId,
        type: "manufacturer_print_job_confirmed",
        title: "Network-direct job completed",
        body: `All labels were sent and confirmed for ${job.batch.name}.`,
        data: {
          printJobId: job.id,
          batchId: job.batch.id,
          batchName: job.batch.name,
          printedCodes: job.quantity,
          mode: PrintDispatchMode.NETWORK_DIRECT,
          targetRoute: "/batches",
        },
      }),
      notifySystemPrintEvent({
        licenseeId: job.batch.licenseeId,
        orgId: job.printer.orgId || null,
        type: "system_print_job_completed",
        title: "Network-direct print job completed",
        body: `Network-direct job completed for ${job.batch.name}.`,
        data: {
          printJobId: job.id,
          batchId: job.batch.id,
          batchName: job.batch.name,
          printedCodes: job.quantity,
          mode: PrintDispatchMode.NETWORK_DIRECT,
          targetRoute: "/batches",
        },
      }),
    ]);
  }
};

export const startNetworkDirectDispatch = async (params: { jobId: string; actorUserId: string }) => {
  if (activeDispatches.has(params.jobId)) {
    return { started: false, reason: "already_running" as const };
  }

  activeDispatches.add(params.jobId);
  setImmediate(async () => {
    try {
      await runNetworkDirectDispatch(params.jobId, params.actorUserId);
    } catch (error: any) {
      logger.error("Unhandled network-direct dispatcher error", {
        jobId: params.jobId,
        error: error?.message || error,
      });
    } finally {
      activeDispatches.delete(params.jobId);
    }
  });

  return { started: true };
};

export const resumePendingNetworkDirectJobs = async () => {
  const jobs = await prisma.printJob.findMany({
    where: {
      printMode: PrintDispatchMode.NETWORK_DIRECT,
      status: { in: [PrintJobStatus.PENDING, PrintJobStatus.SENT] },
      printSession: {
        is: {
          status: PrintSessionStatus.ACTIVE,
        },
      },
    },
    select: {
      id: true,
      manufacturerId: true,
    },
    take: 25,
    orderBy: [{ createdAt: "asc" }],
  });

  for (const job of jobs) {
    if (activeDispatches.has(job.id)) continue;
    await startNetworkDirectDispatch({ jobId: job.id, actorUserId: job.manufacturerId });
  }
};
