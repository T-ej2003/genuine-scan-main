import { PrinterConnectionType } from "@prisma/client";

import prisma from "../config/database";

const normalizePrinterIdentity = (value: unknown) => String(value || "").trim();

const samePrinterText = (left: unknown, right: unknown) =>
  normalizePrinterIdentity(left).toLowerCase() === normalizePrinterIdentity(right).toLowerCase();

const LABEL_PRINTER_TERMS = ["zdesigner", "zebra", "zt410", "zt411", "zpl"];
const VIRTUAL_PRINTER_TERMS = ["fax", "microsoft print to pdf", "print to pdf", "pdf", "onenote", "xps", "document writer", "airprint"];

const toSearchText = (...values: unknown[]) =>
  values
    .flatMap((value) => (Array.isArray(value) ? value : [value]))
    .map((value) => normalizePrinterIdentity(value).toLowerCase())
    .filter(Boolean)
    .join(" ");

const hasAny = (value: string, terms: string[]) => terms.some((term) => value.includes(term));

const hasLanguage = (row: any, language: string) =>
  Array.isArray(row?.languages) &&
  row.languages.some((value: unknown) => normalizePrinterIdentity(value).toUpperCase() === language);

const rowSearchText = (row: any) =>
  toSearchText(row?.printerId, row?.printerName, row?.model, row?.connection, row?.protocols, row?.languages);

const isSafeLabelPrinterRow = (row: any) =>
  Boolean(row && row.online !== false && (hasLanguage(row, "ZPL") || hasAny(rowSearchText(row), LABEL_PRINTER_TERMS)));

const isVirtualPrinterRow = (row: any) =>
  Boolean(row && !isSafeLabelPrinterRow(row) && hasAny(rowSearchText(row), VIRTUAL_PRINTER_TERMS));

const savedProfileLooksLikeLabelPrinter = (printer: any) =>
  hasAny(
    toSearchText(printer?.name, printer?.model, printer?.nativePrinterId, printer?.commandLanguage),
    LABEL_PRINTER_TERMS
  );

export const hasExactTrustedSelectedPrinterMatch = (printer: any, printerStatus: any) => {
  const expectedNativePrinterId = normalizePrinterIdentity(printer?.nativePrinterId);
  const selectedNativePrinterId = normalizePrinterIdentity(printerStatus?.selectedPrinterId || printerStatus?.printerId);
  const selectedPrinterName = normalizePrinterIdentity(printerStatus?.selectedPrinterName || printerStatus?.printerName);
  const expectedRegistrationId = normalizePrinterIdentity(printer?.printerRegistrationId);
  const activeRegistrationId = normalizePrinterIdentity(printerStatus?.registrationId);
  const expectedAgentId = normalizePrinterIdentity(printer?.agentId);
  const activeAgentId = normalizePrinterIdentity(printerStatus?.agentId);
  const expectedDeviceFingerprint = normalizePrinterIdentity(printer?.deviceFingerprint);
  const activeDeviceFingerprint = normalizePrinterIdentity(printerStatus?.deviceFingerprint);

  return Boolean(
    expectedNativePrinterId &&
      selectedNativePrinterId &&
      samePrinterText(expectedNativePrinterId, selectedNativePrinterId) &&
      samePrinterText(printer?.name, selectedPrinterName) &&
      expectedRegistrationId &&
      samePrinterText(expectedRegistrationId, activeRegistrationId) &&
      (!expectedAgentId || samePrinterText(expectedAgentId, activeAgentId)) &&
      (!expectedDeviceFingerprint || samePrinterText(expectedDeviceFingerprint, activeDeviceFingerprint)) &&
      printerStatus?.eligibleForPrinting === true &&
      printerStatus?.stale === false
  );
};

export const pickSafeHeartbeatPrinterForProfile = (printer: any, printerStatus: any) => {
  const rows = Array.isArray(printerStatus?.printers) ? printerStatus.printers : [];
  const safeRows = rows.filter(isSafeLabelPrinterRow);
  if (safeRows.length === 0 || !savedProfileLooksLikeLabelPrinter(printer)) return null;

  const expectedNativePrinterId = normalizePrinterIdentity(printer.nativePrinterId);
  const byNativeId = safeRows.find((row: any) => samePrinterText(row?.printerId, expectedNativePrinterId));
  if (byNativeId) return byNativeId;

  const byProfileName = safeRows.find((row: any) => samePrinterText(row?.printerName, printer.name));
  if (byProfileName) return byProfileName;

  const profileText = toSearchText(printer?.name, printer?.nativePrinterId);
  const byContainedName = safeRows.find((row: any) => {
    const rowText = rowSearchText(row);
    return profileText && (rowText.includes(profileText) || profileText.includes(rowText));
  });
  if (byContainedName) return byContainedName;

  return safeRows.length === 1 ? safeRows[0] : null;
};

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
  let activeNativePrinterId = normalizePrinterIdentity(printerStatus.selectedPrinterId || printerStatus.printerId);
  let activePrinterName = normalizePrinterIdentity(printerStatus.selectedPrinterName || printerStatus.printerName);
  let selectedInventoryRow = Array.isArray(printerStatus.printers)
    ? printerStatus.printers.find((row: any) => normalizePrinterIdentity(row?.printerId) === activeNativePrinterId)
    : null;
  const expectedNativePrinterId = normalizePrinterIdentity(printer.nativePrinterId);
  const expectedRegistrationId = normalizePrinterIdentity(printer.printerRegistrationId);
  const activeRegistrationId = normalizePrinterIdentity(printerStatus.registrationId);
  const repairCandidate = pickSafeHeartbeatPrinterForProfile(printer, printerStatus);

  if (
    repairCandidate &&
    (!activeNativePrinterId || isVirtualPrinterRow(selectedInventoryRow) || activeNativePrinterId !== expectedNativePrinterId)
  ) {
    activeNativePrinterId = normalizePrinterIdentity(repairCandidate.printerId);
    activePrinterName = normalizePrinterIdentity(repairCandidate.printerName);
    selectedInventoryRow = repairCandidate;
    printerStatus.selectedPrinterId = activeNativePrinterId;
    printerStatus.printerId = activeNativePrinterId;
    printerStatus.selectedPrinterName = activePrinterName;
    printerStatus.printerName = activePrinterName;
  }

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

  if (hasExactTrustedSelectedPrinterMatch(printer, printerStatus)) {
    return printer;
  }

  const activeStatusRow =
    selectedInventoryRow ||
    (activeNativePrinterId
      ? { printerId: activeNativePrinterId, printerName: activePrinterName, online: printerStatus.connected }
      : null);
  if (isVirtualPrinterRow(activeStatusRow)) {
    throw Object.assign(new Error("PRINTER_SELECTION_MISMATCH"), { printerStatus, printer });
  }

  if (
    expectedNativePrinterId &&
    expectedNativePrinterId !== activeNativePrinterId &&
    !(repairCandidate && savedProfileLooksLikeLabelPrinter(printer))
  ) {
    throw Object.assign(new Error("PRINTER_SELECTION_MISMATCH"), { printerStatus, printer });
  }

  if (!expectedNativePrinterId || !expectedRegistrationId || printer.nativePrinterId !== activeNativePrinterId) {
    const nameMatches =
      samePrinterText(printer.name, activePrinterName) ||
      samePrinterText(printer.name, selectedInventoryRow?.printerName) ||
      samePrinterText(printer.name, activeNativePrinterId) ||
      (repairCandidate && savedProfileLooksLikeLabelPrinter(printer));

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
