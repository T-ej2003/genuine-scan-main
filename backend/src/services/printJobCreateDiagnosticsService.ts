import { AuthRequest } from "../middleware/auth";
import { readPrintingProjection } from "../rls-waves/session-c/c02/printingLifecycleRepository";

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
  const boundary = {
    capability: String(req.databaseSessionCapability || ""),
    requestId: String(requestId || ""),
  };
  const [batchProjection, printer, printerStatus] = await Promise.all([
    params.batchId && userId
      ? readPrintingProjection({
          ...boundary,
          operation: "PRINTABLE_ITEMS",
          subjectId: params.batchId,
          options: { limit: Math.max(1, Math.min(Number(params.quantity || 1), 200000)) },
        })
      : Promise.resolve(null),
    params.printerId
      ? readPrintingProjection({
          ...boundary,
          operation: "PRINTER",
          subjectId: params.printerId,
          options: params.batchId ? { batchId: params.batchId } : {},
        })
      : Promise.resolve(null),
    userId
      ? readPrintingProjection({
          ...boundary,
          operation: "PRINTER_STATUS",
          subjectId: userId,
        }).catch(() => null)
      : Promise.resolve(null),
  ]);
  const batch = batchProjection?.batch || null;
  const printableCount = Array.isArray(batchProjection?.printableItems)
    ? batchProjection.printableItems.length
    : null;

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
      blockedByPrintItemEvidenceCount: null,
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
                .map((row: unknown) => ({
                  printerId: String((row as any)?.printerId || "").trim() || null,
                  printerName: String((row as any)?.printerName || "").trim() || null,
                  connection: String((row as any)?.connection || "").trim() || null,
                  online: typeof (row as any)?.online === "boolean" ? (row as any).online : null,
                  languages: Array.isArray((row as any)?.languages) ? (row as any).languages.slice(0, 8) : [],
                }))
                .filter((row: { printerId: string | null; printerName: string | null }) => row.printerId || row.printerName)
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
