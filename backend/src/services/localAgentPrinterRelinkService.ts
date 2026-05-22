import { PrinterCommandLanguage, PrinterConnectionType } from "@prisma/client";

import prisma from "../config/database";
import { createAuditLog } from "./auditService";

const normalize = (value: unknown) => String(value || "").trim();
const sameText = (left: unknown, right: unknown) => normalize(left).toLowerCase() === normalize(right).toLowerCase();
const searchText = (...values: unknown[]) =>
  values
    .flatMap((value) => (Array.isArray(value) ? value : [value]))
    .map((value) => normalize(value).toLowerCase())
    .filter(Boolean)
    .join(" ");

const VIRTUAL_PRINTER_TERMS = ["fax", "microsoft print to pdf", "print to pdf", "pdf", "onenote", "xps", "document writer", "airprint"];

const rowLooksVirtual = (row: any) => {
  const text = searchText(row?.printerId, row?.printerName, row?.model, row?.connection, row?.languages, row?.protocols);
  return VIRTUAL_PRINTER_TERMS.some((term) => text.includes(term));
};

const rowSupportsCommandLanguage = (row: any, commandLanguage: unknown) => {
  const expected = normalize(commandLanguage).toUpperCase();
  if (!expected || expected === PrinterCommandLanguage.AUTO) return true;
  const languages = Array.isArray(row?.languages) ? row.languages.map((item: unknown) => normalize(item).toUpperCase()) : [];
  if (languages.includes(expected)) return true;
  return searchText(row?.printerId, row?.printerName, row?.model, row?.languages).includes(expected.toLowerCase());
};

const findMatchingInventoryRow = (printer: any, printerStatus: any) => {
  const rows = Array.isArray(printerStatus?.printers) ? printerStatus.printers : [];
  const expectedNativePrinterId = normalize(printer?.nativePrinterId);
  const expectedName = normalize(printer?.name);

  return (
    rows.find((row: any) => {
      if (!row || row.online === false || rowLooksVirtual(row)) return false;
      if (!rowSupportsCommandLanguage(row, printer?.commandLanguage)) return false;
      const nativeMatches = expectedNativePrinterId && sameText(row?.printerId, expectedNativePrinterId);
      const nameMatches = expectedName && sameText(row?.printerName, expectedName);
      return Boolean(nativeMatches || nameMatches);
    }) || null
  );
};

export const assessLocalAgentPrinterRelink = (printer: any, printerStatus: any) => {
  const activeRegistrationId = normalize(printerStatus?.registrationId);
  const savedRegistrationId = normalize(printer?.printerRegistrationId);
  const matchingInventoryPrinter = findMatchingInventoryRow(printer, printerStatus);

  if (printer?.connectionType !== PrinterConnectionType.LOCAL_AGENT) {
    return { relinkRequired: false, eligible: false, reason: "not_local_agent", matchingInventoryPrinter: null };
  }
  if (!printerStatus?.connected || printerStatus?.eligibleForPrinting !== true || printerStatus?.stale === true) {
    return { relinkRequired: false, eligible: false, reason: "connector_not_ready", matchingInventoryPrinter: null };
  }
  if (!activeRegistrationId) {
    return { relinkRequired: false, eligible: false, reason: "current_registration_missing", matchingInventoryPrinter: null };
  }
  if (!savedRegistrationId || sameText(savedRegistrationId, activeRegistrationId)) {
    return { relinkRequired: false, eligible: false, reason: "registration_current", matchingInventoryPrinter: null };
  }
  if (!matchingInventoryPrinter) {
    return { relinkRequired: true, eligible: false, reason: "safe_inventory_match_missing", matchingInventoryPrinter: null };
  }

  return {
    relinkRequired: true,
    eligible: true,
    reason: "registration_mismatch",
    matchingInventoryPrinter,
  };
};

export const relinkLocalAgentPrinterToCurrentConnector = async (params: {
  printer: any;
  printerStatus: any;
  actorUserId: string;
  licenseeId?: string | null;
  orgId?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
}) => {
  const assessment = assessLocalAgentPrinterRelink(params.printer, params.printerStatus);
  if (!assessment.relinkRequired) {
    return { repaired: false, reason: assessment.reason, printer: params.printer };
  }
  if (!assessment.eligible || !assessment.matchingInventoryPrinter) {
    throw Object.assign(new Error("LOCAL_PRINTER_RELINK_NOT_SAFE"), {
      reason: assessment.reason,
      printer: params.printer,
      printerStatus: params.printerStatus,
    });
  }

  const activeRegistrationId = normalize(params.printerStatus.registrationId);
  const nativePrinterId = normalize(assessment.matchingInventoryPrinter.printerId);
  const printerName = normalize(assessment.matchingInventoryPrinter.printerName) || params.printer.name;
  const now = new Date();

  const result = await prisma.$transaction(async (tx) => {
    const currentRegistration = await tx.printerRegistration.findFirst({
      where: {
        id: activeRegistrationId,
        userId: params.actorUserId,
        ...(params.orgId ? { orgId: params.orgId } : {}),
        ...(params.licenseeId ? { licenseeId: params.licenseeId } : {}),
      },
      select: { id: true, agentId: true, deviceFingerprint: true },
    });
    if (!currentRegistration) {
      throw Object.assign(new Error("LOCAL_PRINTER_RELINK_NOT_SAFE"), { reason: "current_registration_out_of_scope" });
    }

    const existingCurrentPrinter = await tx.printer.findFirst({
      where: {
        id: { not: params.printer.id },
        connectionType: PrinterConnectionType.LOCAL_AGENT,
        printerRegistrationId: activeRegistrationId,
        nativePrinterId,
        OR: [
          { assignedUserId: params.actorUserId },
          { printerRegistration: { is: { userId: params.actorUserId } } },
        ],
      },
    });

    await tx.printer.updateMany({
      where: {
        connectionType: PrinterConnectionType.LOCAL_AGENT,
        assignedUserId: params.actorUserId,
        isDefault: true,
      },
      data: { isDefault: false },
    });

    if (existingCurrentPrinter) {
      const updatedCurrent = await tx.printer.update({
        where: { id: existingCurrentPrinter.id },
        data: {
          name: printerName,
          agentId: normalize(params.printerStatus.agentId) || currentRegistration.agentId,
          deviceFingerprint: normalize(params.printerStatus.deviceFingerprint) || currentRegistration.deviceFingerprint,
          isActive: true,
          isDefault: true,
          lastSeenAt: now,
          lastValidatedAt: now,
          lastValidationStatus: "READY",
          lastValidationMessage: null,
          metadata: {
            ...((existingCurrentPrinter.metadata as Record<string, unknown> | null) || {}),
            relinkedFromPrinterId: params.printer.id,
            relinkedAt: now.toISOString(),
          },
        },
      });

      await tx.printer.update({
        where: { id: params.printer.id },
        data: {
          isActive: false,
          isDefault: false,
          lastValidatedAt: now,
          lastValidationStatus: "RELINKED",
          lastValidationMessage: `Superseded by current connector printer profile ${updatedCurrent.id}`,
          metadata: {
            ...((params.printer.metadata as Record<string, unknown> | null) || {}),
            supersededByPrinterId: updatedCurrent.id,
            supersededAt: now.toISOString(),
            stalePrinterRegistrationId: params.printer.printerRegistrationId || null,
          },
        },
      });

      return { printer: updatedCurrent, repairedVia: "current_profile" as const };
    }

    const updatedPrinter = await tx.printer.update({
      where: { id: params.printer.id },
      data: {
        name: printerName,
        nativePrinterId,
        printerRegistrationId: activeRegistrationId,
        agentId: normalize(params.printerStatus.agentId) || currentRegistration.agentId,
        deviceFingerprint: normalize(params.printerStatus.deviceFingerprint) || currentRegistration.deviceFingerprint,
        isActive: true,
        isDefault: true,
        lastSeenAt: now,
        lastValidatedAt: now,
        lastValidationStatus: "READY",
        lastValidationMessage: null,
        metadata: {
          ...((params.printer.metadata as Record<string, unknown> | null) || {}),
          relinkedAt: now.toISOString(),
          previousPrinterRegistrationId: params.printer.printerRegistrationId || null,
        },
      },
    });

    return { printer: updatedPrinter, repairedVia: "updated_profile" as const };
  });

  await createAuditLog({
    userId: params.actorUserId,
    licenseeId: params.licenseeId || undefined,
    orgId: params.orgId || undefined,
    action: "PRINTER_LOCAL_AGENT_RELINKED",
    entityType: "Printer",
    entityId: result.printer.id,
    details: {
      previousPrinterId: params.printer.id,
      previousPrinterRegistrationId: params.printer.printerRegistrationId || null,
      currentPrinterRegistrationId: activeRegistrationId,
      nativePrinterId,
      repairedVia: result.repairedVia,
    },
    ipAddress: params.ipAddress || undefined,
    userAgent: params.userAgent || undefined,
  });

  return { repaired: true, reason: "registration_mismatch", ...result };
};
