import prisma from "../config/database";
import { AuthRequest } from "../middleware/auth";
import { getPrinterConnectionStatusForUser } from "./printerConnectionService";

export const buildPrintJobCreateDiagnostics = async (
  req: AuthRequest,
  requestId: string | null,
  params: {
    batchId?: string | null;
    printerId?: string | null;
    quantity?: number | null;
    parsedQuantity?: number | null;
  }
) => {
  const userId = req.user?.userId || null;
  const [batch, printer, printerStatus] = await Promise.all([
    params.batchId && userId
      ? prisma.batch.findFirst({
          where: { id: params.batchId, manufacturerId: userId },
          select: { id: true, manufacturerId: true, licenseeId: true },
        })
      : Promise.resolve(null),
    params.printerId
      ? prisma.printer.findUnique({
          where: { id: params.printerId },
          select: {
            id: true,
            name: true,
            connectionType: true,
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
    batch: {
      present: Boolean(params.batchId),
      validForManufacturer: Boolean(batch),
      batchId: batch?.id || params.batchId || null,
      licenseeId: batch?.licenseeId || null,
    },
    printerProfile: {
      present: Boolean(params.printerId),
      found: Boolean(printer),
      id: printer?.id || params.printerId || null,
      name: printer?.name || null,
      connectionType: printer?.connectionType || null,
      isActive: printer?.isActive ?? null,
      assignedUserMatches: printer?.assignedUserId ? printer.assignedUserId === userId : null,
      createdByUserMatches: printer?.createdByUserId ? printer.createdByUserId === userId : null,
      localPrinterId: printer?.nativePrinterId || null,
      printerRegistrationId: printer?.printerRegistrationId || null,
      agentId: printer?.agentId || null,
      deviceFingerprintPresent: Boolean(printer?.deviceFingerprint),
    },
    heartbeat: printerStatus
      ? {
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
          inventoryPrinterIds: Array.isArray(printerStatus.printers)
            ? printerStatus.printers
                .map((row) => String((row as any)?.printerId || "").trim())
                .filter(Boolean)
                .slice(0, 20)
            : [],
        }
      : null,
    quantity: {
      raw: params.quantity ?? null,
      parsed: params.parsedQuantity ?? params.quantity ?? null,
    },
  };
};
