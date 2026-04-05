import {
  PrintDispatchMode,
  PrintItemEventType,
  PrintItemState,
  PrintPipelineState,
  PrintPayloadType,
  Prisma,
  PrinterConnectionType,
  QRStatus,
} from "@prisma/client";

import prisma from "../config/database";
import { finalizePrintSessionIfReady } from "./printLifecycleService";

export type PrintConfirmationMode =
  | "IPP_JOB_STATE"
  | "LOCAL_QUEUE"
  | "ZEBRA_ODOMETER"
  | "DIRECT_NOT_ALLOWED";

const PRINT_CONFIRMATION_TIMEOUT_MS = Math.max(
  10_000,
  Math.min(30 * 60_000, Number(process.env.PRINT_CONFIRMATION_TIMEOUT_MS || 5 * 60_000) || 5 * 60_000)
);

const toRecord = (value: unknown) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {} as Record<string, unknown>;
  return value as Record<string, unknown>;
};

const mergeJsonRecord = (...values: Array<Record<string, unknown> | null | undefined>) =>
  values.reduce<Record<string, unknown>>((acc, value) => Object.assign(acc, toRecord(value)), {});

const isZebraPrinter = (printer: {
  vendor?: string | null;
  model?: string | null;
  name?: string | null;
}) => /\bzebra\b/i.test([printer.vendor, printer.model, printer.name].filter(Boolean).join(" "));

const getConfiguredConfirmationMode = (printer: {
  profile?: { statusConfig?: unknown } | null;
  printerProfile?: { statusConfig?: unknown } | null;
  statusConfig?: unknown;
}) => {
  const statusConfig = mergeJsonRecord(
    toRecord(printer.statusConfig),
    toRecord(printer.profile?.statusConfig),
    toRecord(printer.printerProfile?.statusConfig)
  );
  const raw = String(statusConfig.confirmationMode || "").trim().toUpperCase();
  if (raw === "IPP_JOB_STATE") return "IPP_JOB_STATE" as const;
  if (raw === "LOCAL_QUEUE") return "LOCAL_QUEUE" as const;
  if (raw === "ZEBRA_ODOMETER") return "ZEBRA_ODOMETER" as const;
  if (raw === "DIRECT_NOT_ALLOWED") return "DIRECT_NOT_ALLOWED" as const;
  return null;
};

export const resolvePrinterConfirmationMode = (printer: {
  connectionType?: PrinterConnectionType | string | null;
  vendor?: string | null;
  model?: string | null;
  name?: string | null;
  profile?: { statusConfig?: unknown } | null;
  printerProfile?: { statusConfig?: unknown } | null;
  statusConfig?: unknown;
}): PrintConfirmationMode => {
  const configured = getConfiguredConfirmationMode(printer);
  if (configured) return configured;

  const connectionType = String(printer.connectionType || "").trim().toUpperCase();
  if (connectionType === PrinterConnectionType.LOCAL_AGENT) return "LOCAL_QUEUE";
  if (connectionType === PrinterConnectionType.NETWORK_IPP) return "IPP_JOB_STATE";
  if (connectionType === PrinterConnectionType.NETWORK_DIRECT) {
    return isZebraPrinter(printer) ? "ZEBRA_ODOMETER" : "DIRECT_NOT_ALLOWED";
  }
  return "DIRECT_NOT_ALLOWED";
};

export const buildPrintConfirmationDeadline = (now = new Date()) =>
  new Date(now.getTime() + PRINT_CONFIRMATION_TIMEOUT_MS);

const loadPrintItemForTransition = async (
  tx: Prisma.TransactionClient,
  printItemId: string
) => {
  return tx.printItem.findUnique({
    where: { id: printItemId },
    select: {
      id: true,
      state: true,
      pipelineState: true,
      qrCodeId: true,
      dispatchedAt: true,
      deviceJobRef: true,
      dispatchMetadata: true,
      confirmationEvidence: true,
      confirmationDeadlineAt: true,
      printConfirmedAt: true,
      qrCode: {
        select: {
          status: true,
        },
      },
    },
  });
};

export const acknowledgePrintItemDispatch = async (params: {
  tx?: Prisma.TransactionClient;
  printItemId: string;
  actorUserId: string;
  dispatchMode: PrintDispatchMode;
  payloadType?: PrintPayloadType | null;
  payloadHash?: string | null;
  bytesWritten?: number | null;
  deviceJobRef?: string | null;
  dispatchMetadata?: Record<string, unknown> | null;
  confirmationMode?: PrintConfirmationMode | null;
  confirmationDeadlineAt?: Date | null;
  now?: Date;
}) => {
  const tx = params.tx || prisma;
  const now = params.now || new Date();
  const item = await loadPrintItemForTransition(tx as Prisma.TransactionClient, params.printItemId);
  if (!item) throw new Error("PRINT_ITEM_NOT_FOUND");

  if (item.state === PrintItemState.RESERVED) {
    throw new Error("PRINT_ITEM_NOT_ISSUED");
  }

  const mergedDispatchMetadata = mergeJsonRecord(item.dispatchMetadata as Record<string, unknown> | null, params.dispatchMetadata, {
    confirmationMode: params.confirmationMode || undefined,
    deviceJobRef: params.deviceJobRef || undefined,
    bytesWritten: params.bytesWritten ?? undefined,
  });

  if (item.state === PrintItemState.AGENT_ACKED || item.state === PrintItemState.PRINT_CONFIRMED || item.state === PrintItemState.CLOSED) {
    await tx.printItem.update({
      where: { id: item.id },
      data: {
        deviceJobRef: params.deviceJobRef || item.deviceJobRef || null,
        dispatchMetadata: mergedDispatchMetadata as Prisma.InputJsonValue,
        confirmationDeadlineAt: params.confirmationDeadlineAt || item.confirmationDeadlineAt || buildPrintConfirmationDeadline(now),
      },
    });
    return { item, alreadyAcknowledged: true as const };
  }

  await tx.printItem.update({
    where: { id: item.id },
    data: {
      state: PrintItemState.AGENT_ACKED,
      pipelineState: PrintPipelineState.PRINTER_ACKNOWLEDGED,
      agentAckedAt: now,
      dispatchedAt: item.dispatchedAt || now,
      attemptCount: { increment: 1 },
      deviceJobRef: params.deviceJobRef || null,
      dispatchMetadata: mergedDispatchMetadata as Prisma.InputJsonValue,
      confirmationDeadlineAt: params.confirmationDeadlineAt || buildPrintConfirmationDeadline(now),
    },
  });

  await tx.printItemEvent.create({
    data: {
      printItemId: item.id,
      eventType: PrintItemEventType.AGENT_ACKED,
      previousState: item.state,
      nextState: PrintItemState.AGENT_ACKED,
      actorUserId: params.actorUserId,
      details: {
        dispatchMode: params.dispatchMode,
        payloadType: params.payloadType || null,
        payloadHash: params.payloadHash || null,
        bytesWritten: params.bytesWritten ?? null,
        deviceJobRef: params.deviceJobRef || null,
        confirmationMode: params.confirmationMode || null,
        ...(params.dispatchMetadata || {}),
      },
    },
  });

  return { item, alreadyAcknowledged: false as const };
};

export const confirmPrintItemDispatch = async (params: {
  tx?: Prisma.TransactionClient;
  printSessionId: string;
  printJobId: string;
  batchId: string;
  printItemId: string;
  actorUserId: string;
  dispatchMode: PrintDispatchMode;
  payloadType?: PrintPayloadType | null;
  payloadHash?: string | null;
  bytesWritten?: number | null;
  deviceJobRef?: string | null;
  dispatchMetadata?: Record<string, unknown> | null;
  confirmationMode?: PrintConfirmationMode | null;
  confirmationEvidence?: Record<string, unknown> | null;
  now?: Date;
}) => {
  const tx = params.tx || prisma;
  const now = params.now || new Date();

  await acknowledgePrintItemDispatch({
    tx,
    printItemId: params.printItemId,
    actorUserId: params.actorUserId,
    dispatchMode: params.dispatchMode,
    payloadType: params.payloadType || null,
    payloadHash: params.payloadHash || null,
    bytesWritten: params.bytesWritten ?? null,
    deviceJobRef: params.deviceJobRef || null,
    dispatchMetadata: params.dispatchMetadata || null,
    confirmationMode: params.confirmationMode || null,
    now,
  });

  const item = await loadPrintItemForTransition(tx as Prisma.TransactionClient, params.printItemId);
  if (!item) throw new Error("PRINT_ITEM_NOT_FOUND");
  if (item.state === PrintItemState.PRINT_CONFIRMED || item.state === PrintItemState.CLOSED) {
    return {
      remainingToPrint: 0,
      jobConfirmed: false,
      confirmedAt: item.printConfirmedAt || null,
    };
  }
  if (item.state !== PrintItemState.AGENT_ACKED) {
    throw new Error("PRINT_ITEM_NOT_ACKNOWLEDGED");
  }

  const mergedEvidence = mergeJsonRecord(item.confirmationEvidence as Record<string, unknown> | null, params.confirmationEvidence, {
    confirmationMode: params.confirmationMode || undefined,
    deviceJobRef: params.deviceJobRef || item.deviceJobRef || undefined,
    confirmedAt: now.toISOString(),
    bytesWritten: params.bytesWritten ?? undefined,
  });

  await tx.printItem.update({
    where: { id: item.id },
    data: {
      state: PrintItemState.PRINT_CONFIRMED,
      pipelineState: PrintPipelineState.PRINT_CONFIRMED,
      printConfirmedAt: now,
      deviceJobRef: params.deviceJobRef || item.deviceJobRef || null,
      confirmationEvidence: mergedEvidence as Prisma.InputJsonValue,
    },
  });

  await tx.printItemEvent.create({
    data: {
      printItemId: item.id,
      eventType: PrintItemEventType.PRINT_CONFIRMED,
      previousState: PrintItemState.AGENT_ACKED,
      nextState: PrintItemState.PRINT_CONFIRMED,
      actorUserId: params.actorUserId,
      details: {
        dispatchMode: params.dispatchMode,
        payloadType: params.payloadType || null,
        payloadHash: params.payloadHash || null,
        bytesWritten: params.bytesWritten ?? null,
        deviceJobRef: params.deviceJobRef || item.deviceJobRef || null,
        confirmationMode: params.confirmationMode || null,
        ...(params.confirmationEvidence || {}),
      },
    },
  });

  const qrUpdated = await tx.qRCode.updateMany({
    where: {
      id: item.qrCodeId,
      printJobId: params.printJobId,
      status: QRStatus.ACTIVATED,
    },
    data: {
      status: QRStatus.PRINTED,
      printedAt: now,
      printedByUserId: params.actorUserId,
    },
  });

  if (qrUpdated.count === 0 && item.qrCode.status !== QRStatus.PRINTED) {
    throw new Error("PRINT_ITEM_QR_NOT_PRINTABLE");
  }

  await tx.printSession.update({
    where: { id: params.printSessionId },
    data: {
      confirmedItems: { increment: 1 },
    },
  });

  await tx.printJob.update({
    where: { id: params.printJobId },
    data: {
      pipelineState: PrintPipelineState.PRINT_CONFIRMED,
    },
  });

  const finalized = await finalizePrintSessionIfReady({
    tx: tx as Prisma.TransactionClient,
    printSessionId: params.printSessionId,
    printJobId: params.printJobId,
    batchId: params.batchId,
    now,
    actorUserId: params.actorUserId,
  });

  if (finalized.jobConfirmed) {
    await tx.printItem.updateMany({
      where: {
        printSessionId: params.printSessionId,
        state: PrintItemState.CLOSED,
      },
      data: {
        pipelineState: PrintPipelineState.LOCKED,
      },
    });
    await tx.printJob.update({
      where: { id: params.printJobId },
      data: {
        pipelineState: PrintPipelineState.LOCKED,
      },
    });
  }

  return finalized;
};

export const isPrintItemConfirmationExpired = (value?: Date | string | null) => {
  if (!value) return false;
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return false;
  return parsed.getTime() <= Date.now();
};
