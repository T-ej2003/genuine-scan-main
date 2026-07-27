import { PrintDispatchMode, PrintPayloadType, PrinterConnectionType } from "@prisma/client";

import {
  createPrintingJob,
  readPrintingProjection,
} from "../rls-waves/session-c/c02/printingLifecycleRepository";
import { getQrTokenExpiryDate, hashToken, randomNonce, signQrPayload } from "./qrTokenService";

type TransactionEventLogger = (event: string, data: Record<string, unknown>) => void;
type TransactionStageLogger = (stage: string, event: string, data?: Record<string, unknown>) => void;

const payloadTypeFor = (printer: any) => {
  if (printer.connectionType === PrinterConnectionType.NETWORK_IPP) return PrintPayloadType.PDF;
  const language = String(printer.commandLanguage || "ZPL").toUpperCase();
  return Object.values(PrintPayloadType).includes(language as PrintPayloadType)
    ? (language as PrintPayloadType)
    : PrintPayloadType.ZPL;
};
export const createPrintJobRecords = async (params: {
  capability: string;
  requestId: string;
  batchId: string;
  printerId: string;
  quantity: number;
  rangeStart?: string | null;
  rangeEnd?: string | null;
  printLockTokenHash?: string | null;
  onEvent: TransactionEventLogger;
  onStage: TransactionStageLogger;
}) => {
  params.onStage("reservation_started", "reservation_started", {
    batchId: params.batchId,
    quantity: params.quantity,
    rangeStart: params.rangeStart || null,
    rangeEnd: params.rangeEnd || null,
  });
  const [readiness, printer] = await Promise.all([
    readPrintingProjection({
      capability: params.capability,
      requestId: params.requestId,
      operation: "PRINTABLE_ITEMS",
      subjectId: params.batchId,
      options: {
        limit: params.quantity,
        rangeStart: params.rangeStart || null,
        rangeEnd: params.rangeEnd || null,
      },
    }),
    readPrintingProjection({
      capability: params.capability,
      requestId: params.requestId,
      operation: "PRINTER",
      subjectId: params.printerId,
      options: { batchId: params.batchId },
    }),
  ]);
  if (!readiness?.batch) throw Object.assign(new Error("BATCH_NOT_FOUND"), { statusCode: 404 });
  if (!printer) throw Object.assign(new Error("PRINTER_NOT_FOUND"), { statusCode: 404 });
  const qrRows = Array.isArray(readiness.printableItems) ? readiness.printableItems.slice(0, params.quantity) : [];
  if (qrRows.length !== params.quantity) throw new Error(`NOT_ENOUGH_CODES:${qrRows.length}`);

  const now = new Date();
  const expiresAt = getQrTokenExpiryDate(now);
  let cryptoMetadataLogged = false;
  const items = qrRows.map((qr: any) => {
    const nonce = randomNonce();
    const token = signQrPayload({
      qr_id: qr.id,
      batch_id: qr.batchId,
      licensee_id: qr.licenseeId,
      manufacturer_id: readiness.batch.manufacturerId || null,
      epoch: Number(qr.replayEpoch || 1),
      iat: Math.floor(now.getTime() / 1000),
      exp: Math.floor(expiresAt.getTime() / 1000),
      nonce,
    }, {
      onCryptoMetadata: (metadata) => {
        if (cryptoMetadataLogged) return;
        cryptoMetadataLogged = true;
        params.onEvent("crypto_metadata", { transactionStage: "print_job_prepare_tokens", ...metadata });
      },
    });
    return {
      qrCodeId: qr.id,
      tokenNonce: nonce,
      tokenHash: hashToken(token),
      tokenExpiresAt: expiresAt.toISOString(),
    };
  });
  const printMode = printer.connectionType as PrintDispatchMode;
  const payloadType = payloadTypeFor(printer);
  params.onStage("print_job_created", "print_job_created", {
    batchId: params.batchId,
    printerId: printer.id,
    itemCount: items.length,
  });
  const created = await createPrintingJob({
    capability: params.capability,
    requestId: params.requestId,
    batchId: params.batchId,
    printerId: printer.id,
    quantity: params.quantity,
    rangeStart: params.rangeStart || null,
    rangeEnd: params.rangeEnd || null,
    printMode,
    payloadType,
    printLockTokenHash: params.printLockTokenHash || null,
    items,
  });
  params.onEvent("print_items_created", {
    printJobId: created.job.id,
    printSessionId: created.session.id,
    itemCount: items.length,
  });
  return {
    ...created,
    batch: readiness.batch,
    printerSelection: { printer, printerStatus: null, printMode, payloadType },
  };
};
