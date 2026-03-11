import {
  Prisma,
  Printer,
  PrinterCommandLanguage,
  PrinterConnectionType,
  PrinterTrustStatus,
} from "@prisma/client";

import prisma from "../config/database";
import { testNetworkPrinterConnectivity } from "./networkPrinterSocketService";
import { getPrinterConnectionStatusForUser, type PrinterConnectionStatus } from "./printerConnectionService";
import { supportsNetworkDirectCommandLanguage, supportsNetworkDirectPayload } from "./printPayloadService";

const toCleanString = (value: unknown, max = 180) => String(value || "").trim().slice(0, max);
const toNullableString = (value: unknown, max = 180) => {
  const normalized = toCleanString(value, max);
  return normalized || null;
};

const toNullableJsonValue = (value: Record<string, unknown> | null | undefined) => {
  if (value === undefined) return undefined;
  if (value === null) return Prisma.JsonNull;
  return value as Prisma.InputJsonValue;
};

const KNOWN_VENDOR_MARKERS = [
  "Zebra",
  "SATO",
  "Honeywell",
  "TSC",
  "Brother",
  "Godex",
  "Bixolon",
  "Citizen",
  "Toshiba",
  "Epson",
  "Xprinter",
];

const detectVendor = (name: string, model?: string | null) => {
  const combined = `${name} ${model || ""}`;
  return KNOWN_VENDOR_MARKERS.find((candidate) => new RegExp(`\\b${candidate}\\b`, "i").test(combined)) || null;
};

const coerceCommandLanguage = (value: unknown): PrinterCommandLanguage => {
  const normalized = String(value || "").trim().toUpperCase();
  if (normalized === "ZPL") return PrinterCommandLanguage.ZPL;
  if (normalized === "TSPL") return PrinterCommandLanguage.TSPL;
  if (normalized === "SBPL") return PrinterCommandLanguage.SBPL;
  if (normalized === "EPL") return PrinterCommandLanguage.EPL;
  if (normalized === "CPCL") return PrinterCommandLanguage.CPCL;
  if (normalized === "ESC_POS") return PrinterCommandLanguage.ESC_POS;
  return PrinterCommandLanguage.AUTO;
};

const deriveCommandLanguageFromInventory = (row: any) => {
  const languages = Array.isArray(row?.languages) ? row.languages.map((item: unknown) => String(item || "").trim().toUpperCase()) : [];
  if (languages.includes("ZPL")) return PrinterCommandLanguage.ZPL;
  if (languages.includes("TSPL")) return PrinterCommandLanguage.TSPL;
  if (languages.includes("SBPL")) return PrinterCommandLanguage.SBPL;
  if (languages.includes("EPL")) return PrinterCommandLanguage.EPL;
  if (languages.includes("CPCL")) return PrinterCommandLanguage.CPCL;
  if (languages.includes("ESC_POS")) return PrinterCommandLanguage.ESC_POS;
  return PrinterCommandLanguage.AUTO;
};

export type RegisteredPrinterRecord = Printer & {
  printerRegistration?: {
    id: string;
    trustStatus: PrinterTrustStatus;
    trustReason: string | null;
    userId: string;
  } | null;
};

export type PrinterRegistryStatus = {
  state: "READY" | "ATTENTION" | "OFFLINE" | "BLOCKED";
  summary: string;
  detail: string | null;
  connectionStatus?: PrinterConnectionStatus | null;
};

const buildLocalPrinterStatus = (printer: RegisteredPrinterRecord, connectionStatus: PrinterConnectionStatus): PrinterRegistryStatus => {
  if (!connectionStatus.connected || !connectionStatus.eligibleForPrinting) {
    return {
      state: connectionStatus.connectionClass === "BLOCKED" ? "BLOCKED" : "OFFLINE",
      summary: "Local agent not ready",
      detail: connectionStatus.error || connectionStatus.trustReason || "Local printer heartbeat is unavailable.",
      connectionStatus,
    };
  }

  const activeNativePrinterId = String(connectionStatus.selectedPrinterId || connectionStatus.printerId || "").trim();
  if (printer.nativePrinterId && activeNativePrinterId && printer.nativePrinterId !== activeNativePrinterId) {
    return {
      state: "ATTENTION",
      summary: "Different local printer selected",
      detail: `Active workstation printer is ${connectionStatus.selectedPrinterName || connectionStatus.printerName || activeNativePrinterId}. Switch the local agent before printing.`,
      connectionStatus,
    };
  }

  return {
    state: connectionStatus.trusted ? "READY" : "ATTENTION",
    summary: connectionStatus.trusted ? "Local printer ready" : "Local printer ready in compatibility mode",
    detail: connectionStatus.compatibilityMode ? connectionStatus.compatibilityReason || null : null,
    connectionStatus,
  };
};

const buildNetworkPrinterStatus = (printer: RegisteredPrinterRecord): PrinterRegistryStatus => {
  const validationState = String(printer.lastValidationStatus || "").trim().toUpperCase();

  if (validationState === "READY") {
    return {
      state: "READY",
      summary: "Network printer validated",
      detail: printer.lastValidationMessage || null,
    };
  }

  if (validationState === "OFFLINE" || validationState === "FAILED") {
    return {
      state: "OFFLINE",
      summary: "Network printer offline",
      detail: printer.lastValidationMessage || "The last connectivity check could not reach this printer.",
    };
  }

  if (validationState === "BLOCKED") {
    return {
      state: "BLOCKED",
      summary: "Language not available for network-direct dispatch",
      detail:
        printer.lastValidationMessage ||
        "Network-direct printing currently supports ZPL, TSPL, EPL, and CPCL. Use the local agent for other printer languages.",
    };
  }

  return {
    state: "ATTENTION",
    summary: "Network printer needs validation",
    detail: printer.lastValidationMessage || "Run printer validation before dispatching a server-side job.",
  };
};

export const buildPrinterRegistryStatus = async (
  printer: RegisteredPrinterRecord,
  userContext?: { userId: string }
): Promise<PrinterRegistryStatus> => {
  if (printer.connectionType === PrinterConnectionType.NETWORK_DIRECT) {
    if (!supportsNetworkDirectPayload(printer as any)) {
      return {
        state: "BLOCKED",
        summary: "Language not available for network-direct dispatch",
        detail: "Network-direct printing currently supports ZPL, TSPL, EPL, and CPCL. Use the local agent for other printer languages.",
      };
    }
    if (!printer.ipAddress || !printer.port) {
      return {
        state: "BLOCKED",
        summary: "Network printer config incomplete",
        detail: "IP address or TCP port is missing.",
      };
    }
    if (!printer.isActive) {
      return {
        state: "OFFLINE",
        summary: "Printer disabled",
        detail: printer.lastValidationMessage || "Network printer profile is inactive.",
      };
    }
    return buildNetworkPrinterStatus(printer);
  }

  if (!userContext?.userId) {
    return {
      state: "ATTENTION",
      summary: "Local printer status unavailable",
      detail: "No user context provided for local printer lookup.",
    };
  }

  const connectionStatus = await getPrinterConnectionStatusForUser(userContext.userId);
  return buildLocalPrinterStatus(printer, connectionStatus);
};

export const syncLocalAgentPrintersFromHeartbeat = async (params: {
  userId: string;
  orgId?: string | null;
  licenseeId?: string | null;
  printerRegistrationId?: string | null;
  agentId?: string | null;
  deviceFingerprint?: string | null;
  selectedPrinterId?: string | null;
  selectedPrinterName?: string | null;
  printers: Array<Record<string, unknown>>;
  capabilitySummary?: Record<string, unknown> | null;
  calibrationProfile?: Record<string, unknown> | null;
  connected: boolean;
}) => {
  if (!params.printerRegistrationId) return [] as Printer[];
  const now = new Date();
  const discovered = Array.isArray(params.printers) ? params.printers : [];
  const seenIds = new Set<string>();

  const outputs: Printer[] = [];
  for (const raw of discovered) {
    const nativePrinterId = toCleanString((raw as any).printerId || (raw as any).id, 180);
    const name = toCleanString((raw as any).printerName || (raw as any).name, 180);
    if (!nativePrinterId || !name) continue;
    seenIds.add(nativePrinterId);

    const model = toNullableString((raw as any).model, 180);
    const capabilitySummary = {
      ...(params.capabilitySummary || {}),
      protocols: Array.isArray((raw as any).protocols) ? (raw as any).protocols : [],
      languages: Array.isArray((raw as any).languages) ? (raw as any).languages : [],
      mediaSizes: Array.isArray((raw as any).mediaSizes) ? (raw as any).mediaSizes : [],
      dpi: Number.isFinite(Number((raw as any).dpi)) ? Number((raw as any).dpi) : null,
    } as Record<string, unknown>;
    const metadata = {
      connection: toNullableString((raw as any).connection, 80),
      isDefault: Boolean((raw as any).isDefault),
      online: Boolean((raw as any).online ?? true),
    } as Record<string, unknown>;
    const printer = await prisma.printer.upsert({
      where: {
        printerRegistrationId_nativePrinterId: {
          printerRegistrationId: params.printerRegistrationId,
          nativePrinterId,
        },
      },
      create: {
        name,
        vendor: detectVendor(name, model),
        model,
        connectionType: PrinterConnectionType.LOCAL_AGENT,
        commandLanguage: deriveCommandLanguageFromInventory(raw),
        nativePrinterId,
        agentId: toNullableString(params.agentId, 180),
        deviceFingerprint: toNullableString(params.deviceFingerprint, 256),
        printerRegistrationId: params.printerRegistrationId,
        orgId: params.orgId || null,
        licenseeId: params.licenseeId || null,
        assignedUserId: params.userId,
        createdByUserId: params.userId,
        isActive: true,
        isDefault: nativePrinterId === String(params.selectedPrinterId || "").trim(),
        lastSeenAt: now,
        lastValidatedAt: now,
        lastValidationStatus: params.connected ? "READY" : "OFFLINE",
        lastValidationMessage: params.connected ? null : "Local agent reported printer unavailable",
        capabilitySummary: toNullableJsonValue(capabilitySummary),
        calibrationProfile: toNullableJsonValue(params.calibrationProfile || null),
        metadata: toNullableJsonValue(metadata),
      },
      update: {
        name,
        vendor: detectVendor(name, model),
        model,
        commandLanguage: deriveCommandLanguageFromInventory(raw),
        agentId: toNullableString(params.agentId, 180),
        deviceFingerprint: toNullableString(params.deviceFingerprint, 256),
        orgId: params.orgId || undefined,
        licenseeId: params.licenseeId || undefined,
        assignedUserId: params.userId,
        isActive: true,
        isDefault: nativePrinterId === String(params.selectedPrinterId || "").trim(),
        lastSeenAt: now,
        lastValidatedAt: now,
        lastValidationStatus: params.connected ? "READY" : "OFFLINE",
        lastValidationMessage: params.connected ? null : "Local agent reported printer unavailable",
        capabilitySummary: toNullableJsonValue(capabilitySummary),
        calibrationProfile: toNullableJsonValue(params.calibrationProfile),
        metadata: toNullableJsonValue(metadata),
      },
    });
    outputs.push(printer);
  }

  await prisma.printer.updateMany({
    where: {
      printerRegistrationId: params.printerRegistrationId,
      connectionType: PrinterConnectionType.LOCAL_AGENT,
      ...(seenIds.size > 0 ? { nativePrinterId: { notIn: Array.from(seenIds) } } : {}),
    },
    data: seenIds.size > 0
      ? {
          isActive: false,
          lastValidationStatus: "OFFLINE",
          lastValidationMessage: "Printer not present in latest local-agent inventory",
          updatedAt: now,
        }
      : {
          lastValidationStatus: "OFFLINE",
          lastValidationMessage: "No printers reported by local agent",
          updatedAt: now,
        },
  });

  return outputs;
};

const printerListWhere = (params: {
  licenseeId?: string | null;
  licenseeIds?: string[] | null;
  orgId?: string | null;
  userId: string;
  includeInactive?: boolean;
}): Prisma.PrinterWhereInput => {
  const normalizedLicenseeIds = Array.from(new Set((params.licenseeIds || []).filter(Boolean)));
  const networkScope = params.licenseeId
    ? { licenseeId: params.licenseeId }
    : normalizedLicenseeIds.length > 0
      ? { licenseeId: normalizedLicenseeIds.length === 1 ? normalizedLicenseeIds[0] : { in: normalizedLicenseeIds } }
      : params.orgId
        ? { orgId: params.orgId }
        : {};
  return ({
  ...(params.includeInactive ? {} : { isActive: true }),
  OR: [
    {
      connectionType: PrinterConnectionType.LOCAL_AGENT,
      assignedUserId: params.userId,
    },
    {
      connectionType: PrinterConnectionType.LOCAL_AGENT,
      printerRegistration: {
        is: {
          userId: params.userId,
        },
      },
    },
    {
      connectionType: PrinterConnectionType.NETWORK_DIRECT,
      ...networkScope,
    },
  ],
});
};

export const listRegisteredPrintersForManufacturer = async (params: {
  userId: string;
  orgId?: string | null;
  licenseeId?: string | null;
  licenseeIds?: string[] | null;
  includeInactive?: boolean;
}) => {
  const printers = (await prisma.printer.findMany({
    where: printerListWhere(params),
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
    orderBy: [{ connectionType: "asc" }, { isDefault: "desc" }, { name: "asc" }],
  })) as RegisteredPrinterRecord[];

  const localStatus = printers.some((printer) => printer.connectionType === PrinterConnectionType.LOCAL_AGENT)
    ? await getPrinterConnectionStatusForUser(params.userId)
    : null;

  const rows = await Promise.all(
    printers.map(async (printer) => ({
      ...printer,
      registryStatus:
        printer.connectionType === PrinterConnectionType.LOCAL_AGENT && localStatus
          ? buildLocalPrinterStatus(printer, localStatus)
          : await buildPrinterRegistryStatus(printer, { userId: params.userId }),
    }))
  );

  return rows;
};

export const getRegisteredPrinterForManufacturer = async (params: {
  printerId: string;
  userId: string;
  orgId?: string | null;
  licenseeId?: string | null;
  licenseeIds?: string[] | null;
  includeInactive?: boolean;
}) => {
  return (await prisma.printer.findFirst({
    where: {
      id: params.printerId,
      ...printerListWhere(params),
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
  })) as RegisteredPrinterRecord | null;
};

export const upsertNetworkDirectPrinter = async (params: {
  printerId?: string;
  userId: string;
  orgId?: string | null;
  licenseeId?: string | null;
  name: string;
  vendor?: string | null;
  model?: string | null;
  ipAddress: string;
  port: number;
  commandLanguage: PrinterCommandLanguage;
  capabilitySummary?: Record<string, unknown> | null;
  calibrationProfile?: Record<string, unknown> | null;
  isActive?: boolean;
  isDefault?: boolean;
}) => {
  if (!supportsNetworkDirectCommandLanguage(params.commandLanguage)) {
    throw new Error(
      "Network-direct printing currently supports only ZPL, TSPL, EPL, and CPCL. Use the local agent for other printer languages."
    );
  }

  const data = {
    name: toCleanString(params.name, 180),
    vendor: toNullableString(params.vendor, 180) || detectVendor(params.name, params.model || null),
    model: toNullableString(params.model, 180),
    connectionType: PrinterConnectionType.NETWORK_DIRECT,
    commandLanguage: params.commandLanguage,
    ipAddress: toCleanString(params.ipAddress, 120),
    port: Number(params.port),
    orgId: params.orgId || null,
    licenseeId: params.licenseeId || null,
    createdByUserId: params.userId,
    isActive: params.isActive ?? true,
    isDefault: params.isDefault ?? false,
    capabilitySummary: toNullableJsonValue(params.capabilitySummary || null),
    calibrationProfile: toNullableJsonValue(params.calibrationProfile || null),
  };

  if (params.printerId) {
    return prisma.printer.update({
      where: { id: params.printerId },
      data,
    });
  }

  return prisma.printer.create({ data });
};

export const testRegisteredPrinterConnection = async (params: {
  printer: RegisteredPrinterRecord;
  userId: string;
}) => {
  if (params.printer.connectionType === PrinterConnectionType.LOCAL_AGENT) {
    const connectionStatus = await getPrinterConnectionStatusForUser(params.userId);
    const registryStatus = buildLocalPrinterStatus(params.printer, connectionStatus);
    await prisma.printer.update({
      where: { id: params.printer.id },
      data: {
        lastValidatedAt: new Date(),
        lastValidationStatus: registryStatus.state,
        lastValidationMessage: registryStatus.detail || registryStatus.summary,
      },
    });
    return {
      ok: registryStatus.state === "READY" || registryStatus.state === "ATTENTION",
      registryStatus,
    };
  }

  if (!supportsNetworkDirectCommandLanguage(params.printer.commandLanguage)) {
    const validationMessage =
      "Network-direct printing currently supports only ZPL, TSPL, EPL, and CPCL. Use the local agent for other printer languages.";
    await prisma.printer.update({
      where: { id: params.printer.id },
      data: {
        lastValidatedAt: new Date(),
        lastValidationStatus: "BLOCKED",
        lastValidationMessage: validationMessage,
      },
    });
    return {
      ok: false,
      registryStatus: buildNetworkPrinterStatus({
        ...params.printer,
        lastValidationStatus: "BLOCKED",
        lastValidationMessage: validationMessage,
      } as RegisteredPrinterRecord),
    };
  }

  if (!params.printer.ipAddress || !params.printer.port) {
    throw new Error("Network printer IP address or port is missing");
  }

  const result = await testNetworkPrinterConnectivity({
    ipAddress: params.printer.ipAddress,
    port: params.printer.port,
  }).catch(async (error: any) => {
    const detail = error?.message || `Could not reach ${params.printer.ipAddress}:${params.printer.port}`;
    await prisma.printer.update({
      where: { id: params.printer.id },
      data: {
        lastValidatedAt: new Date(),
        lastValidationStatus: "OFFLINE",
        lastValidationMessage: detail,
      },
    });
    throw error;
  });

  const networkDirectSupported = supportsNetworkDirectPayload(params.printer as any);
  const validationStatus = networkDirectSupported ? "READY" : "BLOCKED";
  const validationMessage = networkDirectSupported
    ? `TCP connectivity validated in ${result.latencyMs}ms`
    : `TCP connectivity validated in ${result.latencyMs}ms, but network-direct printing currently supports only ZPL, TSPL, EPL, and CPCL.`;

  await prisma.printer.update({
    where: { id: params.printer.id },
    data: {
      lastValidatedAt: new Date(),
      lastValidationStatus: validationStatus,
      lastValidationMessage: validationMessage,
    },
  });

  return {
    ok: networkDirectSupported,
    latencyMs: result.latencyMs,
    registryStatus: buildNetworkPrinterStatus({
      ...params.printer,
      lastValidationStatus: validationStatus,
      lastValidationMessage: validationMessage,
    } as RegisteredPrinterRecord),
  };
};
