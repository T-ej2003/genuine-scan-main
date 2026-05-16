import { PrinterConnectionType } from "@prisma/client";

import prisma from "../config/database";

const normalizePrinterIdentity = (value: unknown) => String(value || "").trim();

const samePrinterText = (left: unknown, right: unknown) =>
  normalizePrinterIdentity(left).toLowerCase() === normalizePrinterIdentity(right).toLowerCase();

const throwPrinterMappingMissing = (params: {
  printer: any;
  printerStatus: any;
  reason: string;
  expectedNativePrinterId?: string | null;
  activeNativePrinterId?: string | null;
}) => {
  throw Object.assign(new Error("PRINTER_MAPPING_MISSING"), params);
};

export const resolveLocalAgentPrinterMapping = async (params: {
  printer: any;
  printerStatus: any;
}) => {
  const { printerStatus } = params;
  let { printer } = params;
  const activeNativePrinterId = normalizePrinterIdentity(printerStatus.selectedPrinterId || printerStatus.printerId);
  const activePrinterName = normalizePrinterIdentity(printerStatus.selectedPrinterName || printerStatus.printerName);
  const selectedInventoryRow = Array.isArray(printerStatus.printers)
    ? printerStatus.printers.find((row: any) => normalizePrinterIdentity(row?.printerId) === activeNativePrinterId)
    : null;
  const expectedNativePrinterId = normalizePrinterIdentity(printer.nativePrinterId);
  const expectedRegistrationId = normalizePrinterIdentity(printer.printerRegistrationId);
  const activeRegistrationId = normalizePrinterIdentity(printerStatus.registrationId);

  if (!activeNativePrinterId || !activeRegistrationId) {
    throw Object.assign(new Error("PRINTER_NOT_TRUSTED"), { printerStatus, printer });
  }

  if (expectedRegistrationId && expectedRegistrationId !== activeRegistrationId) {
    throwPrinterMappingMissing({
      printer,
      printerStatus,
      reason: "registration_mismatch",
      expectedNativePrinterId,
      activeNativePrinterId,
    });
  }

  if (expectedNativePrinterId && expectedNativePrinterId !== activeNativePrinterId) {
    throw Object.assign(new Error("PRINTER_SELECTION_MISMATCH"), { printerStatus, printer });
  }

  if (!expectedNativePrinterId || !expectedRegistrationId) {
    const nameMatches =
      samePrinterText(printer.name, activePrinterName) ||
      samePrinterText(printer.name, selectedInventoryRow?.printerName) ||
      samePrinterText(printer.name, activeNativePrinterId);

    if (!nameMatches) {
      throwPrinterMappingMissing({
        printer,
        printerStatus,
        reason: "missing_native_mapping",
        expectedNativePrinterId,
        activeNativePrinterId,
      });
    }

    const existingMappedPrinter = await prisma.printer.findFirst({
      where: {
        connectionType: PrinterConnectionType.LOCAL_AGENT,
        printerRegistrationId: activeRegistrationId,
        nativePrinterId: activeNativePrinterId,
        id: { not: printer.id },
      },
      select: { id: true, name: true },
    });

    if (existingMappedPrinter) {
      throwPrinterMappingMissing({
        printer,
        printerStatus,
        reason: "native_mapping_belongs_to_another_profile",
        expectedNativePrinterId,
        activeNativePrinterId,
      });
    }

    printer = await prisma.printer.update({
      where: { id: printer.id },
      data: {
        nativePrinterId: activeNativePrinterId,
        printerRegistrationId: activeRegistrationId,
        agentId: normalizePrinterIdentity(printerStatus.agentId) || printer.agentId || null,
        deviceFingerprint: normalizePrinterIdentity(printerStatus.deviceFingerprint) || printer.deviceFingerprint || null,
        isActive: true,
        isDefault: true,
        lastSeenAt: new Date(),
        lastValidatedAt: new Date(),
        lastValidationStatus: "READY",
        lastValidationMessage: null,
      },
      include: {
        printerRegistration: {
          select: {
            id: true,
            trustStatus: true,
            trustReason: true,
            userId: true,
          },
        },
      },
    });
  }

  if (
    Array.isArray(printerStatus.printers) &&
    printerStatus.printers.length > 0 &&
    !printerStatus.printers.some((row: any) => normalizePrinterIdentity(row?.printerId) === activeNativePrinterId)
  ) {
    throwPrinterMappingMissing({
      printer,
      printerStatus,
      reason: "selected_printer_not_in_heartbeat_inventory",
      expectedNativePrinterId,
      activeNativePrinterId,
    });
  }

  return printer;
};
