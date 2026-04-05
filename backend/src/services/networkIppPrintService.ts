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
import { createHash } from "crypto";

import prisma from "../config/database";
import { renderPdfLabelBuffer } from "../printing/pdfLabel";
import { inspectIppJob, submitPdfToIppPrinter } from "../printing/ippClient";
import { logger } from "../utils/logger";
import { createAuditLog } from "./auditService";
import { createRoleNotifications, createUserNotification } from "./notificationService";
import {
  acknowledgePrintItemDispatch,
  confirmPrintItemDispatch,
  isPrintItemConfirmationExpired,
  resolvePrinterConfirmationMode,
} from "./printConfirmationService";
import { buildApprovedPrintContext } from "./printPayloadService";
import { failStopPrintSession, getOrCreatePrintSession, OPEN_PRINT_STATES } from "./printLifecycleService";

const activeDispatches = new Set<string>();
const NETWORK_IPP_CHUNK_SIZE = Math.max(1, Math.min(100, Number(process.env.NETWORK_IPP_CHUNK_SIZE || 10) || 10));
const GATEWAY_HEARTBEAT_TTL_MS = Math.max(
  10_000,
  Math.min(10 * 60_000, Number(process.env.PRINT_GATEWAY_HEARTBEAT_TTL_MS || 45_000) || 45_000)
);
const NETWORK_IPP_CONFIRM_POLL_MS = Math.max(
  500,
  Math.min(15_000, Number(process.env.NETWORK_IPP_CONFIRM_POLL_MS || 1500) || 1500)
);
const NETWORK_IPP_CONFIRM_TIMEOUT_MS = Math.max(
  5_000,
  Math.min(20 * 60_000, Number(process.env.NETWORK_IPP_CONFIRM_TIMEOUT_MS || 2 * 60_000) || 2 * 60_000)
);

const sha256Hex = (value: Buffer | string) => createHash("sha256").update(value).digest("hex");
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const toRecord = (value: unknown) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {} as Record<string, unknown>;
  return value as Record<string, unknown>;
};

const toPositiveInt = (value: unknown) => {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return null;
  return Math.floor(parsed);
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

const loadIppDispatchJob = async (jobId: string) =>
  prisma.printJob.findUnique({
    where: { id: jobId },
    include: {
      batch: { select: { id: true, name: true, licenseeId: true } },
      printer: true,
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
        where: { id: row.id, state: PrintItemState.RESERVED },
        data: {
          state: PrintItemState.ISSUED,
          pipelineState: PrintPipelineState.SENT_TO_PRINTER,
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
  if (!deadlineAt) return NETWORK_IPP_CONFIRM_TIMEOUT_MS;
  const parsed = new Date(deadlineAt);
  if (Number.isNaN(parsed.getTime())) return NETWORK_IPP_CONFIRM_TIMEOUT_MS;
  return Math.max(1000, parsed.getTime() - Date.now());
};

const hasIppCompletionError = (reasons: string[]) =>
  reasons.some((reason) =>
    [
      "completed-with-errors",
      "job-completed-with-errors",
      "document-format-error",
      "processing-to-stop-point",
      "job-canceled-at-device",
      "job-canceled-by-operator",
      "job-canceled-by-user",
      "job-aborted-at-device",
    ].some((marker) => reason.includes(marker))
  );

const waitForIppTerminalState = async (params: {
  printer: {
    host?: string | null;
    port?: number | null;
    resourcePath?: string | null;
    tlsEnabled?: boolean | null;
    printerUri?: string | null;
  };
  ippJobId: number;
  timeoutMs: number;
}) => {
  const deadline = Date.now() + params.timeoutMs;

  while (Date.now() < deadline) {
    const inspection = await inspectIppJob({
      profile: {
        host: params.printer.host,
        port: params.printer.port,
        resourcePath: params.printer.resourcePath,
        tlsEnabled: params.printer.tlsEnabled,
        printerUri: params.printer.printerUri,
      },
      jobId: params.ippJobId,
    });
    const reasons = inspection.jobStateReasons.map((value) => value.toLowerCase());

    if (inspection.jobState === 9) {
      if (hasIppCompletionError(reasons)) {
        throw new Error(
          `IPP job ${params.ippJobId} completed with printer-reported errors: ${inspection.jobStateReasons.join(", ")}`
        );
      }
      return inspection;
    }

    if (inspection.jobState === 7 || inspection.jobState === 8) {
      throw new Error(
        `IPP job ${params.ippJobId} reached terminal failure state ${inspection.jobState}: ${
          inspection.jobStateMessage || inspection.jobStateReasons.join(", ") || "printer rejected the job"
        }`
      );
    }

    await sleep(NETWORK_IPP_CONFIRM_POLL_MS);
  }

  throw new Error(`IPP job ${params.ippJobId} did not reach terminal completion before the confirmation deadline.`);
};

const confirmAcknowledgedIppItem = async (params: {
  job: NonNullable<Awaited<ReturnType<typeof loadIppDispatchJob>>>;
  sessionId: string;
  actorUserId: string;
  item: Awaited<ReturnType<typeof loadAcknowledgedItems>>[number];
}) => {
  const confirmationMode = resolvePrinterConfirmationMode(params.job.printer || {});
  if (confirmationMode !== "IPP_JOB_STATE") {
    throw new Error(`IPP printer ${params.job.printer?.id || "unknown"} is not configured for IPP job-state confirmation.`);
  }

  const ippJobId = toPositiveInt(params.item.deviceJobRef);
  if (!ippJobId) {
    throw new Error(`IPP print item ${params.item.id} is missing a valid device job reference.`);
  }

  const metadata = toRecord(params.item.dispatchMetadata);
  const inspection = await waitForIppTerminalState({
    printer: params.job.printer || {},
    ippJobId,
    timeoutMs: getRemainingTimeoutMs(params.item.confirmationDeadlineAt),
  });

  const finalize = await confirmPrintItemDispatch({
    printSessionId: params.sessionId,
    printJobId: params.job.id,
    batchId: params.job.batchId,
    printItemId: params.item.id,
    actorUserId: params.actorUserId,
    dispatchMode: PrintDispatchMode.NETWORK_IPP,
    payloadType: PrintPayloadType.PDF,
    payloadHash: typeof metadata.payloadHash === "string" ? metadata.payloadHash : null,
    bytesWritten: toPositiveInt(metadata.bytesWritten),
    deviceJobRef: String(inspection.jobId),
    dispatchMetadata: metadata,
    confirmationMode,
    confirmationEvidence: {
      printerUri: inspection.printerUri,
      endpointUrl: inspection.endpointUrl,
      jobUri: inspection.jobUri,
      jobState: inspection.jobState,
      jobStateReasons: inspection.jobStateReasons,
      jobStateMessage: inspection.jobStateMessage,
      impressionsCompleted: inspection.impressionsCompleted,
      mediaSheetsCompleted: inspection.mediaSheetsCompleted,
      pagesCompleted: inspection.pagesCompleted,
    },
  });

  await createAuditLog({
    userId: params.actorUserId,
    licenseeId: params.job.batch.licenseeId || undefined,
    action: "NETWORK_IPP_PRINT_ITEM_CONFIRMED",
    entityType: "PrintItem",
    entityId: params.item.id,
    details: {
      printJobId: params.job.id,
      printSessionId: params.sessionId,
      dispatchMode: PrintDispatchMode.NETWORK_IPP,
      qrId: params.item.qrCodeId,
      code: params.item.code,
      ippJobId: inspection.jobId,
      remainingToPrint: finalize.remainingToPrint,
      jobState: inspection.jobState,
      jobStateReasons: inspection.jobStateReasons,
    },
  });
};

const dispatchAndConfirmReservedItem = async (params: {
  job: NonNullable<Awaited<ReturnType<typeof loadIppDispatchJob>>>;
  sessionId: string;
  actorUserId: string;
  item: Awaited<ReturnType<typeof reserveNextChunk>>[number];
}) => {
  const confirmationMode = resolvePrinterConfirmationMode(params.job.printer || {});
  if (confirmationMode !== "IPP_JOB_STATE") {
    throw new Error(`IPP printer ${params.job.printer?.id || "unknown"} does not expose IPP terminal job-state confirmation.`);
  }

  const context = buildApprovedPrintContext({
    qr: params.item.qrCode,
    manufacturerId: params.job.manufacturerId,
    reprintOfJobId: params.job.reprintOfJobId,
  });
  const pdf = await renderPdfLabelBuffer({
    code: params.item.code,
    scanUrl: context.scanUrl,
    previewLabel: context.previewLabel,
    calibrationProfile: (params.job.printer?.calibrationProfile as Record<string, unknown> | null) || null,
  });
  const payloadHash = sha256Hex(pdf);
  const ippResult = await submitPdfToIppPrinter({
    profile: {
      host: params.job.printer?.host,
      port: params.job.printer?.port,
      resourcePath: params.job.printer?.resourcePath,
      tlsEnabled: params.job.printer?.tlsEnabled,
      printerUri: params.job.printer?.printerUri,
    },
    pdf,
    jobName: `${params.job.jobNumber || "MSCQR"}-${params.item.code}`,
    requestingUserName: params.job.manufacturerId,
  });

  if (!ippResult.jobId) {
    throw new Error("IPP printer accepted the payload but did not return a job identifier for terminal confirmation.");
  }

  await prisma.printJob.updateMany({
    where: { id: params.job.id, payloadHash: null },
    data: {
      payloadType: PrintPayloadType.PDF,
      payloadHash,
    },
  });

  await acknowledgePrintItemDispatch({
    printItemId: params.item.id,
    actorUserId: params.actorUserId,
    dispatchMode: PrintDispatchMode.NETWORK_IPP,
    payloadType: PrintPayloadType.PDF,
    payloadHash,
    bytesWritten: pdf.length,
    deviceJobRef: String(ippResult.jobId),
    dispatchMetadata: {
      payloadHash,
      bytesWritten: pdf.length,
      ippJobId: ippResult.jobId,
      printerUri: ippResult.printerUri,
      endpointUrl: ippResult.endpointUrl,
      jobUri: ippResult.jobUri,
    },
    confirmationMode,
  });

  await confirmAcknowledgedIppItem({
    job: params.job,
    sessionId: params.sessionId,
    actorUserId: params.actorUserId,
    item: {
      id: params.item.id,
      qrCodeId: params.item.qrCodeId,
      code: params.item.code,
      state: PrintItemState.AGENT_ACKED,
      deviceJobRef: String(ippResult.jobId),
      dispatchMetadata: {
        payloadHash,
        bytesWritten: pdf.length,
        ippJobId: ippResult.jobId,
        printerUri: ippResult.printerUri,
        endpointUrl: ippResult.endpointUrl,
        jobUri: ippResult.jobUri,
      },
      confirmationDeadlineAt: null,
      qrCode: {
        status: params.item.qrCode.status,
      },
    },
  });
};

export const isGatewayFresh = (lastSeenAt?: Date | string | null) => {
  if (!lastSeenAt) return false;
  const parsed = new Date(lastSeenAt);
  if (Number.isNaN(parsed.getTime())) return false;
  return Date.now() - parsed.getTime() <= GATEWAY_HEARTBEAT_TTL_MS;
};

const failDispatch = async (params: {
  job: NonNullable<Awaited<ReturnType<typeof loadIppDispatchJob>>>;
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
      dispatchMode: PrintDispatchMode.NETWORK_IPP,
      ...(params.metadata || {}),
    },
  });

  await notifySystemPrintEvent({
    licenseeId: params.job.batch.licenseeId,
    orgId: params.job.printer?.orgId || null,
    type: "system_print_job_failed",
    title: "Network IPP fail-stop triggered",
    body: `Network IPP fail-stop activated for ${params.job.batch.name}. Reason: ${params.reason}`,
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
  job: NonNullable<Awaited<ReturnType<typeof loadIppDispatchJob>>>;
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
        reason: `IPP confirmation deadline expired for ${item.code}.`,
        printItemId: item.id,
      });
      return false;
    }

    try {
      await confirmAcknowledgedIppItem({
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
        reason: error?.message || `Network IPP confirmation failed for ${item.code}`,
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

  const confirmationMode = resolvePrinterConfirmationMode(job.printer);
  if (confirmationMode !== "IPP_JOB_STATE") {
    throw new Error("NETWORK_IPP_CONFIRMATION_MODE_INVALID");
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
    await failDispatch({
      job,
      sessionId: session.id,
      actorUserId,
      reason: `Network IPP dispatcher resumed with ${ambiguous} ambiguous in-flight items.`,
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
      await failDispatch({
        job,
        sessionId: session.id,
        actorUserId,
        reason: `Network IPP dispatch stalled with ${remaining} remaining items but no reservable labels.`,
      });
      return;
    }

    for (const item of reservedItems) {
      if (item.qrCode.status !== QRStatus.ACTIVATED) {
        await failDispatch({
          job,
          sessionId: session.id,
          actorUserId,
          reason: `QR ${item.code} is not in ACTIVATED state for network IPP printing.`,
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
          reason: error?.message || `Network IPP dispatch failed for ${item.code}`,
          printItemId: item.id,
          metadata: {
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
        title: "Network IPP job completed",
        body: `All labels were terminally confirmed for ${job.batch.name}.`,
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
