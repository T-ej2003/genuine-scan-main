import {
  NotificationAudience,
  NotificationChannel,
  PrintDispatchMode,
  PrintItemEventType,
  PrintItemState,
  PrintJobStatus,
  PrintPayloadType,
  PrintPipelineState,
  PrintSessionStatus,
  PrinterConnectionType,
  QRStatus,
} from "@prisma/client";
import type { PrintJobDTO } from "../../../shared/contracts/printing.d.ts";

import prisma from "../config/database";
import { logger } from "../utils/logger";
import { sendRawPayloadToNetworkPrinter } from "./networkPrinterSocketService";
import { buildApprovedPrintPayload, supportsNetworkDirectPayload } from "./printPayloadService";
import { failStopPrintSession, getOrCreatePrintSession, OPEN_PRINT_STATES } from "./printLifecycleService";
import { createAuditLog } from "./auditService";
import { createRoleNotifications, createUserNotification } from "./notificationService";
import { buildScopedPrintJobWhere, type PrintJobScope } from "./printJobScopeService";
import {
  acknowledgePrintItemDispatch,
  confirmPrintItemDispatch,
  isPrintItemConfirmationExpired,
  resolvePrinterConfirmationMode,
} from "./printConfirmationService";
import { getZebraTotalLabelCount, waitForZebraLabelConfirmation } from "./zebraPrinterStatusService";

const activeDispatches = new Set<string>();
const NETWORK_DIRECT_CHUNK_SIZE = Math.max(
  1,
  Math.min(250, Number(process.env.NETWORK_DIRECT_CHUNK_SIZE || 25) || 25)
);

const toIsoOrNull = (value: Date | null | undefined) => (value ? value.toISOString() : null);

const toRecord = (value: unknown) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {} as Record<string, unknown>;
  return value as Record<string, unknown>;
};

const toPositiveInt = (value: unknown) => {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return null;
  return Math.floor(parsed);
};

const toPayloadType = (value: unknown) => {
  const normalized = String(value || "").trim().toUpperCase();
  return (Object.values(PrintPayloadType) as string[]).includes(normalized) ? (normalized as PrintPayloadType) : null;
};

const buildSessionStateCounts = async (sessionIds: string[]) => {
  if (sessionIds.length === 0) return {} as Record<string, Record<string, number>>;

  const rows = await prisma.printItem.groupBy({
    by: ["printSessionId", "state"],
    where: { printSessionId: { in: sessionIds } },
    _count: { _all: true },
  });

  return rows.reduce<Record<string, Record<string, number>>>((acc, row) => {
    const sessionCounts = acc[row.printSessionId] || {};
    sessionCounts[row.state] = row._count._all;
    acc[row.printSessionId] = sessionCounts;
    return acc;
  }, {});
};

const buildDispatchReferenceSummary = async (sessionId: string, awaitingCount: number) => {
  if (!sessionId || awaitingCount <= 0) return null;

  const rows = await prisma.printItem.findMany({
    where: {
      printSessionId: sessionId,
      state: PrintItemState.AGENT_ACKED,
      deviceJobRef: { not: null },
    },
    orderBy: [{ issueSequence: "asc" }, { code: "asc" }],
    select: { deviceJobRef: true },
    take: 10,
  });

  return {
    awaitingCount,
    outstandingJobRefs: rows
      .map((row) => String(row.deviceJobRef || "").trim())
      .filter(Boolean),
  };
};

const buildSessionSnapshot = <
  T extends {
    id: string;
    status: PrintSessionStatus;
    totalItems: number;
    issuedItems?: number;
    confirmedItems?: number;
    frozenItems?: number;
    failedReason?: string | null;
    startedAt?: Date;
    completedAt?: Date | null;
  },
>(
  session: T | null | undefined,
  countsByState: Record<string, number> = {}
) => {
  if (!session) return null;

  const remainingToPrint = OPEN_PRINT_STATES.reduce((sum, state) => sum + (countsByState[state] || 0), 0);
  const confirmedItems = (countsByState[PrintItemState.PRINT_CONFIRMED] || 0) + (countsByState[PrintItemState.CLOSED] || 0);
  const frozenItems = countsByState[PrintItemState.FROZEN] || 0;
  const awaitingConfirmationCount = countsByState[PrintItemState.AGENT_ACKED] || 0;

  return {
    ...session,
    confirmedItems: Math.max(Number(session.confirmedItems || 0), confirmedItems),
    frozenItems: Math.max(Number(session.frozenItems || 0), frozenItems),
    remainingToPrint,
    awaitingConfirmationCount,
    counts: countsByState,
  };
};

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
    Promise.resolve([] as any[]),
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

const loadNetworkDispatchJob = async (jobId: string) =>
  prisma.printJob.findUnique({
    where: { id: jobId },
    include: {
      batch: { select: { id: true, name: true, licenseeId: true } },
      printer: {
        include: {
          profile: {
            select: {
              statusConfig: true,
            },
          },
        },
      },
      printSession: true,
    },
  });

const markJobSent = async (jobId: string) => {
  const now = new Date();
  await prisma.printJob.updateMany({
    where: { id: jobId, status: PrintJobStatus.PENDING },
    data: {
      status: PrintJobStatus.SENT,
      pipelineState: PrintPipelineState.SENT_TO_PRINTER,
      sentAt: now,
    },
  });
};

const ensureSafeResumeState = async (sessionId: string) =>
  prisma.printItem.count({
    where: {
      printSessionId: sessionId,
      state: PrintItemState.ISSUED,
    },
  });

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
          pipelineState: PrintPipelineState.SENT_TO_PRINTER,
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
          pipelineState: PrintPipelineState.SENT_TO_PRINTER,
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

const loadAcknowledgedItems = async (sessionId: string) =>
  prisma.printItem.findMany({
    where: {
      printSessionId: sessionId,
      state: PrintItemState.AGENT_ACKED,
    },
    orderBy: [{ issueSequence: "asc" }, { code: "asc" }],
    select: {
      id: true,
      qrCodeId: true,
      code: true,
      state: true,
      deviceJobRef: true,
      dispatchMetadata: true,
      confirmationDeadlineAt: true,
      qrCode: {
        select: {
          status: true,
        },
      },
    },
  });

const getRemainingTimeoutMs = (deadlineAt?: Date | string | null) => {
  if (!deadlineAt) return undefined;
  const parsed = new Date(deadlineAt);
  if (Number.isNaN(parsed.getTime())) return undefined;
  return Math.max(1000, parsed.getTime() - Date.now());
};

const confirmAcknowledgedZebraItem = async (params: {
  job: NonNullable<Awaited<ReturnType<typeof loadNetworkDispatchJob>>>;
  sessionId: string;
  actorUserId: string;
  item: Awaited<ReturnType<typeof loadAcknowledgedItems>>[number];
}) => {
  if (!params.job.printer?.ipAddress || !params.job.printer?.port) {
    throw new Error("NETWORK_PRINTER_CONFIGURATION_INVALID");
  }

  const confirmationMode = resolvePrinterConfirmationMode(params.job.printer);
  if (confirmationMode !== "ZEBRA_ODOMETER") {
    throw new Error("NETWORK_DIRECT_CONFIRMATION_UNSUPPORTED");
  }

  const metadata = toRecord(params.item.dispatchMetadata);
  const startingLabelCount = toPositiveInt(metadata.startingLabelCount);
  if (startingLabelCount === null) {
    throw new Error(`Network-direct item ${params.item.id} is missing a Zebra baseline label count.`);
  }
  const expectedIncrement = toPositiveInt(metadata.expectedIncrement) || 1;

  const zebraStatus = await waitForZebraLabelConfirmation({
    ipAddress: params.job.printer.ipAddress,
    port: params.job.printer.port,
    startingLabelCount,
    expectedIncrement,
    timeoutMs: getRemainingTimeoutMs(params.item.confirmationDeadlineAt),
  });

  const finalize = await confirmPrintItemDispatch({
    printSessionId: params.sessionId,
    printJobId: params.job.id,
    batchId: params.job.batchId,
    printItemId: params.item.id,
    actorUserId: params.actorUserId,
    dispatchMode: PrintDispatchMode.NETWORK_DIRECT,
    payloadType: toPayloadType(metadata.payloadType),
    payloadHash: typeof metadata.payloadHash === "string" ? metadata.payloadHash : null,
    bytesWritten: toPositiveInt(metadata.bytesWritten),
    deviceJobRef: params.item.deviceJobRef || `zebra-odometer:${startingLabelCount}`,
    dispatchMetadata: metadata,
    confirmationMode,
    confirmationEvidence: {
      startingLabelCount,
      confirmedLabelCount: zebraStatus.lastCount,
      expectedIncrement,
      printerIpAddress: params.job.printer.ipAddress,
      printerPort: params.job.printer.port,
    },
  });

  await createAuditLog({
    userId: params.actorUserId,
    licenseeId: params.job.batch.licenseeId || undefined,
    action: "NETWORK_DIRECT_PRINT_ITEM_CONFIRMED",
    entityType: "PrintItem",
    entityId: params.item.id,
    details: {
      printJobId: params.job.id,
      printSessionId: params.sessionId,
      dispatchMode: PrintDispatchMode.NETWORK_DIRECT,
      qrId: params.item.qrCodeId,
      code: params.item.code,
      remainingToPrint: finalize.remainingToPrint,
      startingLabelCount,
      confirmedLabelCount: zebraStatus.lastCount,
    },
  });
};

const buildPrintJobView = async (job: {
  id: string;
  jobNumber: string | null;
  status: PrintJobStatus;
  pipelineState: PrintPipelineState | null;
  printMode: PrintDispatchMode;
  quantity: number;
  itemCount: number | null;
  reprintOfJobId: string | null;
  reprintReason: string | null;
  failureReason: string | null;
  createdAt: Date;
  updatedAt: Date;
  sentAt: Date | null;
  confirmedAt: Date | null;
  completedAt: Date | null;
  batch: { id: string; name: string | null; licenseeId?: string | null } | null;
  printer: any;
  printSession:
    | {
        id: string;
        status: PrintSessionStatus;
        totalItems: number;
        issuedItems: number;
        confirmedItems: number;
        frozenItems: number;
        failedReason: string | null;
        startedAt: Date;
        completedAt: Date | null;
      }
    | null;
}): Promise<PrintJobDTO> => {
  const sessionIds = job.printSession?.id ? [job.printSession.id] : [];
  const sessionStateCounts = await buildSessionStateCounts(sessionIds);
  const counts = job.printSession?.id ? sessionStateCounts[job.printSession.id] || {} : {};
  const awaitingConfirmationCount = counts[PrintItemState.AGENT_ACKED] || 0;

  return {
    id: job.id,
    jobNumber: job.jobNumber,
    status: job.status,
    pipelineState: job.pipelineState || undefined,
    printMode: job.printMode,
    quantity: job.quantity,
    itemCount: job.itemCount || job.quantity,
    reprintOfJobId: job.reprintOfJobId,
    reprintReason: job.reprintReason,
    failureReason: job.failureReason,
    confirmationFailureReason: job.status === PrintJobStatus.FAILED ? job.failureReason || job.printSession?.failedReason || null : null,
    awaitingConfirmation: awaitingConfirmationCount > 0,
    confirmationMode: job.printer ? resolvePrinterConfirmationMode(job.printer) : null,
    dispatchReferenceSummary:
      job.printSession?.id && awaitingConfirmationCount > 0
        ? await buildDispatchReferenceSummary(job.printSession.id, awaitingConfirmationCount)
        : null,
    createdAt: job.createdAt.toISOString(),
    updatedAt: job.updatedAt.toISOString(),
    sentAt: toIsoOrNull(job.sentAt),
    confirmedAt: toIsoOrNull(job.confirmedAt),
    completedAt: toIsoOrNull(job.completedAt),
    batch: job.batch,
    printer: job.printer,
    session: buildSessionSnapshot(job.printSession, counts),
  };
};

export const getPrintJobOperationalView = async (params: {
  jobId: string;
  scope: PrintJobScope;
}): Promise<PrintJobDTO | null> => {
  const job = await prisma.printJob.findFirst({
    where: buildScopedPrintJobWhere(params.scope, { id: params.jobId }),
    include: {
      batch: { select: { id: true, name: true, licenseeId: true } },
      printer: {
        select: {
          id: true,
          name: true,
          vendor: true,
          model: true,
          connectionType: true,
          commandLanguage: true,
          ipAddress: true,
          host: true,
          port: true,
          resourcePath: true,
          tlsEnabled: true,
          printerUri: true,
          deliveryMode: true,
          nativePrinterId: true,
          profile: {
            select: {
              statusConfig: true,
            },
          },
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

  return buildPrintJobView(job);
};

export const listPrintJobsForManufacturer = async (params: {
  scope: PrintJobScope;
  batchId?: string;
  limit?: number;
}): Promise<PrintJobDTO[]> => {
  const jobs = await prisma.printJob.findMany({
    where: buildScopedPrintJobWhere(params.scope, {
      ...(params.batchId ? { batchId: params.batchId } : {}),
    }),
    include: {
      batch: { select: { id: true, name: true, licenseeId: true } },
      printer: {
        select: {
          id: true,
          name: true,
          vendor: true,
          model: true,
          connectionType: true,
          commandLanguage: true,
          ipAddress: true,
          host: true,
          port: true,
          resourcePath: true,
          tlsEnabled: true,
          printerUri: true,
          deliveryMode: true,
          nativePrinterId: true,
          profile: {
            select: {
              statusConfig: true,
            },
          },
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
    orderBy: [{ createdAt: "desc" }],
    take: Math.max(1, Math.min(100, params.limit || 20)),
  });

  return Promise.all(jobs.map((job) => buildPrintJobView(job)));
};

const failDispatch = async (params: {
  job: NonNullable<Awaited<ReturnType<typeof loadNetworkDispatchJob>>>;
  sessionId: string;
  actorUserId: string;
  reason: string;
  printItemId?: string;
  metadata?: Record<string, unknown>;
}) => {
  await failStopPrintSession({
    printSessionId: params.sessionId,
    printJobId: params.job.id,
    batchId: params.job.batchId,
    licenseeId: params.job.batch.licenseeId || null,
    actorUserId: params.actorUserId,
    reason: params.reason,
    printItemId: params.printItemId,
    metadata: {
      dispatchMode: PrintDispatchMode.NETWORK_DIRECT,
      ...(params.metadata || {}),
    },
  });

  const alertBody = `Network-direct fail-stop activated for ${params.job.batch.name}. Reason: ${params.reason}`;
  await notifySystemPrintEvent({
    licenseeId: params.job.batch.licenseeId,
    orgId: params.job.printer?.orgId || null,
    type: "system_print_job_failed",
    title: "Network-direct fail-stop triggered",
    body: alertBody,
    data: {
      printJobId: params.job.id,
      printSessionId: params.sessionId,
      reason: params.reason,
      targetRoute: "/batches",
    },
    channels: [NotificationChannel.WEB, NotificationChannel.EMAIL],
  });
};

const processAcknowledgedItems = async (params: {
  job: NonNullable<Awaited<ReturnType<typeof loadNetworkDispatchJob>>>;
  sessionId: string;
  actorUserId: string;
}) => {
  const acknowledgedItems = await loadAcknowledgedItems(params.sessionId);
  for (const item of acknowledgedItems) {
    if (isPrintItemConfirmationExpired(item.confirmationDeadlineAt)) {
      await failDispatch({
        job: params.job,
        sessionId: params.sessionId,
        actorUserId: params.actorUserId,
        reason: `Printer confirmation deadline expired for ${item.code}.`,
        printItemId: item.id,
      });
      return false;
    }

    try {
      await confirmAcknowledgedZebraItem({
        job: params.job,
        sessionId: params.sessionId,
        actorUserId: params.actorUserId,
        item,
      });
    } catch (error: any) {
      await failDispatch({
        job: params.job,
        sessionId: params.sessionId,
        actorUserId: params.actorUserId,
        reason: error?.message || `Network printer confirmation failed for ${item.code}`,
        printItemId: item.id,
        metadata: {
          printerId: params.job.printer?.id || null,
          printerName: params.job.printer?.name || null,
        },
      });
      return false;
    }
  }

  return true;
};

const dispatchAndConfirmReservedItem = async (params: {
  job: NonNullable<Awaited<ReturnType<typeof loadNetworkDispatchJob>>>;
  sessionId: string;
  actorUserId: string;
  item: Awaited<ReturnType<typeof reserveNextChunk>>[number];
}) => {
  if (!params.job.printer?.ipAddress || !params.job.printer?.port) {
    throw new Error("NETWORK_PRINTER_CONFIGURATION_INVALID");
  }

  const confirmationMode = resolvePrinterConfirmationMode(params.job.printer);
  if (confirmationMode !== "ZEBRA_ODOMETER") {
    throw new Error("NETWORK_DIRECT_CONFIRMATION_UNSUPPORTED");
  }

  const payload = buildApprovedPrintPayload({
    printer: params.job.printer as any,
    qr: params.item.qrCode,
    manufacturerId: params.job.manufacturerId,
    printJobId: params.job.id,
    printItemId: params.item.id,
    jobNumber: params.job.jobNumber,
    reprintOfJobId: params.job.reprintOfJobId,
  });

  const startingLabelCount = await getZebraTotalLabelCount({
    ipAddress: params.job.printer.ipAddress,
    port: params.job.printer.port,
  });
  const socketResult = await sendRawPayloadToNetworkPrinter({
    ipAddress: params.job.printer.ipAddress,
    port: params.job.printer.port,
    payload: payload.payloadContent,
  });

  await prisma.printJob.updateMany({
    where: { id: params.job.id, payloadHash: null },
    data: {
      payloadType: payload.payloadType,
      payloadHash: payload.payloadHash,
    },
  });

  const dispatchMetadata = {
    payloadType: payload.payloadType,
    payloadHash: payload.payloadHash,
    bytesWritten: socketResult.bytesWritten,
    startingLabelCount,
    expectedIncrement: 1,
    printerIpAddress: params.job.printer.ipAddress,
    printerPort: params.job.printer.port,
  };

  await acknowledgePrintItemDispatch({
    printItemId: params.item.id,
    actorUserId: params.actorUserId,
    dispatchMode: PrintDispatchMode.NETWORK_DIRECT,
    payloadType: payload.payloadType,
    payloadHash: payload.payloadHash,
    bytesWritten: socketResult.bytesWritten,
    deviceJobRef: `zebra-odometer:${startingLabelCount}`,
    dispatchMetadata,
    confirmationMode,
  });

  await confirmAcknowledgedZebraItem({
    job: params.job,
    sessionId: params.sessionId,
    actorUserId: params.actorUserId,
    item: {
      id: params.item.id,
      qrCodeId: params.item.qrCodeId,
      code: params.item.code,
      state: PrintItemState.AGENT_ACKED,
      deviceJobRef: `zebra-odometer:${startingLabelCount}`,
      dispatchMetadata,
      confirmationDeadlineAt: null,
      qrCode: {
        status: params.item.qrCode.status,
      },
    },
  });
};

const runNetworkDirectDispatch = async (jobId: string, actorUserId: string) => {
  const job = await loadNetworkDispatchJob(jobId);
  if (!job) throw new Error("PRINT_JOB_NOT_FOUND");
  if (!job.printer || job.printer.connectionType !== PrinterConnectionType.NETWORK_DIRECT) {
    throw new Error("PRINT_JOB_NOT_NETWORK_DIRECT");
  }
  if (job.printer.deliveryMode === "SITE_GATEWAY") {
    logger.info("Skipping direct NETWORK_DIRECT dispatch for gateway-backed printer", {
      jobId,
      printerId: job.printer.id,
      gatewayId: job.printer.gatewayId || null,
    });
    return;
  }
  if (!job.printer.ipAddress || !job.printer.port) {
    throw new Error("NETWORK_PRINTER_CONFIGURATION_INVALID");
  }
  if (!supportsNetworkDirectPayload(job.printer as any)) {
    throw new Error("NETWORK_DIRECT_LANGUAGE_NOT_SUPPORTED");
  }
  if (resolvePrinterConfirmationMode(job.printer) !== "ZEBRA_ODOMETER") {
    throw new Error("NETWORK_DIRECT_CONFIRMATION_UNSUPPORTED");
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
    await failDispatch({
      job,
      sessionId: session.id,
      actorUserId,
      reason: `Network-direct dispatcher resumed with ${ambiguous} ambiguous in-flight items.`,
    });
    return;
  }

  await markJobSent(job.id);

  while (true) {
    const ackedOk = await processAcknowledgedItems({
      job,
      sessionId: session.id,
      actorUserId,
    });
    if (!ackedOk) return;

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
      await failDispatch({
        job,
        sessionId: session.id,
        actorUserId,
        reason: `Network-direct dispatch stalled with ${remaining} remaining items but no reservable labels.`,
      });
      return;
    }

    for (const item of reservedItems) {
      if (item.qrCode.status !== QRStatus.ACTIVATED) {
        await failDispatch({
          job,
          sessionId: session.id,
          actorUserId,
          reason: `QR ${item.code} is not in ACTIVATED state for network direct printing.`,
          printItemId: item.id,
        });
        return;
      }

      try {
        await dispatchAndConfirmReservedItem({
          job,
          sessionId: session.id,
          actorUserId,
          item,
        });
      } catch (error: any) {
        await failDispatch({
          job,
          sessionId: session.id,
          actorUserId,
          reason: error?.message || `Network printer dispatch failed for ${item.code}`,
          printItemId: item.id,
          metadata: {
            dispatchMode: PrintDispatchMode.NETWORK_DIRECT,
            printerId: job.printer.id,
            printerName: job.printer.name,
          },
        });
        return;
      }
    }
  }

  const fresh = await prisma.printJob.findUnique({ where: { id: job.id }, select: { status: true } });
  if (fresh?.status === PrintJobStatus.CONFIRMED) {
    await Promise.allSettled([
      createUserNotification({
        userId: actorUserId,
        licenseeId: job.batch.licenseeId,
        type: "manufacturer_print_job_confirmed",
        title: "Network-direct job completed",
        body: `All labels were terminally confirmed for ${job.batch.name}.`,
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
      printer: {
        is: {
          connectionType: PrinterConnectionType.NETWORK_DIRECT,
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
    await startNetworkDirectDispatch({ jobId: job.id, actorUserId: job.manufacturerId });
  }
};
