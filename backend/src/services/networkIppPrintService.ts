import {
  NotificationAudience,
  NotificationChannel,
  PrintDispatchMode,
  PrintJobStatus,
  PrintItemEventType,
  PrintItemState,
  PrintPayloadType,
  PrintSessionStatus,
  PrinterConnectionType,
  QRStatus,
} from "@prisma/client";
import { createHash } from "crypto";

import prisma from "../config/database";
import { renderPdfLabelBuffer } from "../printing/pdfLabel";
import { submitPdfToIppPrinter } from "../printing/ippClient";
import { logger } from "../utils/logger";
import { createAuditLog } from "./auditService";
import { createRoleNotifications, createUserNotification } from "./notificationService";
import { buildApprovedPrintContext } from "./printPayloadService";
import { failStopPrintSession, finalizePrintSessionIfReady, getOrCreatePrintSession, OPEN_PRINT_STATES } from "./printLifecycleService";

const activeDispatches = new Set<string>();
const NETWORK_IPP_CHUNK_SIZE = Math.max(1, Math.min(100, Number(process.env.NETWORK_IPP_CHUNK_SIZE || 10) || 10));
const GATEWAY_HEARTBEAT_TTL_MS = Math.max(10_000, Math.min(10 * 60_000, Number(process.env.PRINT_GATEWAY_HEARTBEAT_TTL_MS || 45_000) || 45_000));

const sha256Hex = (value: Buffer | string) => createHash("sha256").update(value).digest("hex");

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

const loadIppDispatchJob = async (jobId: string) => {
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
  return prisma.printItem.count({
    where: {
      printSessionId: sessionId,
      state: { in: [PrintItemState.ISSUED, PrintItemState.AGENT_ACKED, PrintItemState.PRINT_CONFIRMED] },
    },
  });
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
        where: { id: row.id, state: PrintItemState.RESERVED },
        data: {
          state: PrintItemState.ISSUED,
          issuedAt: now,
          issueSequence: startingSequence + index + 1,
        },
      });
      if (updated.count === 0) throw new Error("PRINT_ITEM_RESERVE_CONFLICT");
    }

    await tx.printItemEvent.createMany({
      data: rows.map((row) => ({
        printItemId: row.id,
        eventType: PrintItemEventType.ISSUED,
        previousState: PrintItemState.RESERVED,
        nextState: PrintItemState.ISSUED,
        actorUserId: params.actorUserId,
        details: {
          dispatchMode: PrintDispatchMode.NETWORK_IPP,
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

const confirmIppPrintedItem = async (params: {
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
  payloadHash: string;
  bytesWritten: number;
  ippJobId?: number | null;
  metadata?: Record<string, unknown>;
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
    if (acked.count === 0) throw new Error("NETWORK_IPP_ACK_CONFLICT");

    await tx.printItemEvent.create({
      data: {
        printItemId: params.item.id,
        eventType: PrintItemEventType.AGENT_ACKED,
        previousState: PrintItemState.ISSUED,
        nextState: PrintItemState.AGENT_ACKED,
        actorUserId: params.actorUserId,
        details: {
          dispatchMode: PrintDispatchMode.NETWORK_IPP,
          payloadType: PrintPayloadType.PDF,
          payloadHash: params.payloadHash,
          bytesWritten: params.bytesWritten,
          ippJobId: params.ippJobId || null,
          ...(params.metadata || {}),
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
    if (confirmed.count === 0) throw new Error("NETWORK_IPP_CONFIRM_CONFLICT");

    await tx.printItemEvent.create({
      data: {
        printItemId: params.item.id,
        eventType: PrintItemEventType.PRINT_CONFIRMED,
        previousState: PrintItemState.AGENT_ACKED,
        nextState: PrintItemState.PRINT_CONFIRMED,
        actorUserId: params.actorUserId,
        details: {
          dispatchMode: PrintDispatchMode.NETWORK_IPP,
          payloadType: PrintPayloadType.PDF,
          payloadHash: params.payloadHash,
          bytesWritten: params.bytesWritten,
          ippJobId: params.ippJobId || null,
          ...(params.metadata || {}),
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
      throw new Error("NETWORK_IPP_QR_NOT_PRINTABLE");
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

export const isGatewayFresh = (lastSeenAt?: Date | string | null) => {
  if (!lastSeenAt) return false;
  const parsed = new Date(lastSeenAt);
  if (Number.isNaN(parsed.getTime())) return false;
  return Date.now() - parsed.getTime() <= GATEWAY_HEARTBEAT_TTL_MS;
};

const runNetworkIppDispatch = async (jobId: string, actorUserId: string) => {
  const job = await loadIppDispatchJob(jobId);
  if (!job) throw new Error("PRINT_JOB_NOT_FOUND");
  if (!job.printer || job.printer.connectionType !== PrinterConnectionType.NETWORK_IPP) {
    throw new Error("PRINT_JOB_NOT_NETWORK_IPP");
  }
  if (job.printer.deliveryMode === "SITE_GATEWAY") {
    logger.info("Skipping direct NETWORK_IPP dispatch for gateway-backed printer", {
      jobId,
      printerId: job.printer.id,
      gatewayId: job.printer.gatewayId || null,
    });
    return;
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
    logger.info("Skipping network IPP dispatch for inactive session", { jobId, sessionId: session.id, status: session.status });
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
      reason: `Network IPP dispatcher resumed with ${ambiguous} ambiguous in-flight items.`,
      metadata: { dispatchMode: PrintDispatchMode.NETWORK_IPP },
    });
    return;
  }

  await markJobSent(job.id);

  let done = false;
  while (!done) {
    const reservedItems = await reserveNextChunk({
      sessionId: session.id,
      actorUserId,
      chunkSize: NETWORK_IPP_CHUNK_SIZE,
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
        reason: `Network IPP dispatch stalled with ${remaining} remaining items but no reservable labels.`,
        metadata: { dispatchMode: PrintDispatchMode.NETWORK_IPP },
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
          reason: `QR ${item.code} is not in ACTIVATED state for network IPP printing.`,
          printItemId: item.id,
          metadata: { dispatchMode: PrintDispatchMode.NETWORK_IPP },
        });
        return;
      }

      try {
        const context = buildApprovedPrintContext({
          qr: item.qrCode,
          manufacturerId: job.manufacturerId,
          reprintOfJobId: job.reprintOfJobId,
        });
        const pdf = await renderPdfLabelBuffer({
          code: item.code,
          scanUrl: context.scanUrl,
          previewLabel: context.previewLabel,
          calibrationProfile: (job.printer.calibrationProfile as Record<string, unknown> | null) || null,
        });
        const payloadHash = sha256Hex(pdf);
        const ippResult = await submitPdfToIppPrinter({
          profile: {
            host: job.printer.host,
            port: job.printer.port,
            resourcePath: job.printer.resourcePath,
            tlsEnabled: job.printer.tlsEnabled,
            printerUri: job.printer.printerUri,
          },
          pdf,
          jobName: `${job.jobNumber || "MSCQR"}-${item.code}`,
          requestingUserName: job.manufacturerId,
        });

        await prisma.printJob.updateMany({
          where: { id: job.id, payloadHash: null },
          data: {
            payloadType: PrintPayloadType.PDF,
            payloadHash,
          },
        });

        const finalize = await confirmIppPrintedItem({
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
          payloadHash,
          bytesWritten: pdf.length,
          ippJobId: ippResult.jobId,
          metadata: {
            printerUri: ippResult.printerUri,
            endpointUrl: ippResult.endpointUrl,
          },
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
            dispatchMode: PrintDispatchMode.NETWORK_IPP,
            qrId: item.qrCodeId,
            code: item.code,
            payloadType: PrintPayloadType.PDF,
            payloadHash,
            ippJobId: ippResult.jobId,
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
          reason: error?.message || `Network IPP dispatch failed for ${item.code}`,
          printItemId: item.id,
          metadata: {
            dispatchMode: PrintDispatchMode.NETWORK_IPP,
            printerId: job.printer.id,
            printerName: job.printer.name,
          },
        });

        await notifySystemPrintEvent({
          licenseeId: job.batch.licenseeId,
          orgId: job.printer.orgId || null,
          type: "system_print_job_failed",
          title: "Network IPP fail-stop triggered",
          body: `Network IPP fail-stop activated for ${job.batch.name}. Reason: ${error?.message || "Dispatch error"}`,
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
        title: "Network IPP job completed",
        body: `All labels were sent and confirmed for ${job.batch.name}.`,
        data: {
          printJobId: job.id,
          batchId: job.batch.id,
          batchName: job.batch.name,
          printedCodes: job.quantity,
          mode: PrintDispatchMode.NETWORK_IPP,
          targetRoute: "/batches",
        },
      }),
      notifySystemPrintEvent({
        licenseeId: job.batch.licenseeId,
        orgId: job.printer.orgId || null,
        type: "system_print_job_completed",
        title: "Network IPP print job completed",
        body: `Network IPP job completed for ${job.batch.name}.`,
        data: {
          printJobId: job.id,
          batchId: job.batch.id,
          batchName: job.batch.name,
          printedCodes: job.quantity,
          mode: PrintDispatchMode.NETWORK_IPP,
          targetRoute: "/batches",
        },
      }),
    ]);
  }
};

export const startNetworkIppDispatch = async (params: { jobId: string; actorUserId: string }) => {
  if (activeDispatches.has(params.jobId)) {
    return { started: false, reason: "already_running" as const };
  }

  activeDispatches.add(params.jobId);
  setImmediate(async () => {
    try {
      await runNetworkIppDispatch(params.jobId, params.actorUserId);
    } catch (error: any) {
      logger.error("Unhandled network IPP dispatcher error", {
        jobId: params.jobId,
        error: error?.message || error,
      });
    } finally {
      activeDispatches.delete(params.jobId);
    }
  });

  return { started: true };
};

export const resumePendingNetworkIppJobs = async () => {
  const jobs = await prisma.printJob.findMany({
    where: {
      printMode: PrintDispatchMode.NETWORK_IPP,
      status: { in: [PrintJobStatus.PENDING, PrintJobStatus.SENT] },
      printSession: {
        is: {
          status: PrintSessionStatus.ACTIVE,
        },
      },
      printer: {
        is: {
          connectionType: PrinterConnectionType.NETWORK_IPP,
          deliveryMode: "DIRECT",
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
    await startNetworkIppDispatch({ jobId: job.id, actorUserId: job.manufacturerId });
  }
};
