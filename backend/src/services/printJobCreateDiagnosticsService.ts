import { QRStatus } from "@prisma/client";

import prisma from "../config/database";
import { AuthRequest } from "../middleware/auth";
import { getPrinterConnectionStatusForUser } from "./printerConnectionService";

export const buildPrintJobCreateDiagnostics = async (
  req: AuthRequest,
  requestId: string | null,
  params: {
    errorCode?: string | null;
    failureStage?: string | null;
    missingFields?: string[];
    validationIssuePaths?: string[];
    batchId?: string | null;
    printerId?: string | null;
    quantity?: number | null;
    parsedQuantity?: number | null;
    exceptionName?: string | null;
    exceptionCode?: string | null;
    cryptoMetadata?: Record<string, unknown> | null;
    transactionStage?: string | null;
  }
) => {
  const userId = req.user?.userId || null;
  const [batch, printableCount, printer, printerStatus] = await Promise.all([
    params.batchId && userId
      ? prisma.batch.findFirst({
          where: { id: params.batchId, manufacturerId: userId },
          select: {
            id: true,
            name: true,
            manufacturerId: true,
            licenseeId: true,
            totalCodes: true,
            printedAt: true,
            suspendedAt: true,
          },
        })
      : Promise.resolve(null),
    params.batchId
      ? prisma.qRCode
          .count({
            where: {
              batchId: params.batchId,
              status: QRStatus.ALLOCATED,
              printJobId: null,
            },
          })
          .catch(() => null)
      : Promise.resolve(null),
    params.printerId
      ? prisma.printer.findUnique({
          where: { id: params.printerId },
          select: {
            id: true,
            name: true,
            connectionType: true,
            deliveryMode: true,
            nativePrinterId: true,
            printerRegistrationId: true,
            assignedUserId: true,
            createdByUserId: true,
            isActive: true,
            agentId: true,
            deviceFingerprint: true,
          },
        })
      : Promise.resolve(null),
    userId ? getPrinterConnectionStatusForUser(userId).catch(() => null) : Promise.resolve(null),
  ]);

  return {
    requestId,
    errorCode: params.errorCode || null,
    failureStage: params.failureStage || null,
    validationIssuePaths: params.validationIssuePaths || [],
    missingFields: params.missingFields || [],
    transactionStage: params.transactionStage || null,
    exception: {
      name: params.exceptionName || null,
      code: params.exceptionCode || null,
    },
    crypto: params.cryptoMetadata || null,
    batch: {
      present: Boolean(params.batchId),
      validForManufacturer: Boolean(batch),
      batchId: batch?.id || params.batchId || null,
      name: batch?.name || null,
      licenseeId: batch?.licenseeId || null,
      manufacturerMatches: batch?.manufacturerId ? batch.manufacturerId === userId : null,
      totalCodes: batch?.totalCodes ?? null,
      printedAt: batch?.printedAt?.toISOString?.() || null,
      suspendedAt: batch?.suspendedAt?.toISOString?.() || null,
      printableCount: printableCount ?? null,
      remainingCodes: printableCount ?? null,
    },
    printerProfile: {
      present: Boolean(params.printerId),
      found: Boolean(printer),
      id: printer?.id || params.printerId || null,
      name: printer?.name || null,
      connectionType: printer?.connectionType || null,
      deliveryMode: printer?.deliveryMode || null,
      isActive: printer?.isActive ?? null,
      assignedUserMatches: printer?.assignedUserId ? printer.assignedUserId === userId : null,
      createdByUserMatches: printer?.createdByUserId ? printer.createdByUserId === userId : null,
      localPrinterId: printer?.nativePrinterId || null,
      printerRegistrationIdPresent: Boolean(printer?.printerRegistrationId),
      printerRegistrationId: printer?.printerRegistrationId || null,
      agentIdPresent: Boolean(printer?.agentId),
      agentId: printer?.agentId || null,
      deviceFingerprintPresent: Boolean(printer?.deviceFingerprint),
    },
    heartbeat: printerStatus
      ? {
          exists: true,
          connected: printerStatus.connected,
          eligibleForPrinting: printerStatus.eligibleForPrinting,
          trusted: printerStatus.trusted,
          compatibilityMode: printerStatus.compatibilityMode,
          stale: printerStatus.stale,
          registrationId: printerStatus.registrationId || null,
          agentId: printerStatus.agentId || null,
          deviceFingerprintPresent: Boolean(printerStatus.deviceFingerprint),
          printerId: printerStatus.printerId || null,
          printerName: printerStatus.printerName || null,
          selectedPrinterId: printerStatus.selectedPrinterId || null,
          selectedPrinterName: printerStatus.selectedPrinterName || null,
          inventory: Array.isArray(printerStatus.printers)
            ? printerStatus.printers
                .map((row) => ({
                  printerId: String((row as any)?.printerId || "").trim() || null,
                  printerName: String((row as any)?.printerName || "").trim() || null,
                  connection: String((row as any)?.connection || "").trim() || null,
                  online: typeof (row as any)?.online === "boolean" ? (row as any).online : null,
                  languages: Array.isArray((row as any)?.languages) ? (row as any).languages.slice(0, 8) : [],
                }))
                .filter((row) => row.printerId || row.printerName)
                .slice(0, 20)
            : [],
        }
      : { exists: false },
    quantity: {
      raw: params.quantity ?? null,
      parsed: params.parsedQuantity ?? params.quantity ?? null,
    },
  };
};
