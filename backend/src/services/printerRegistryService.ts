import {
  Prisma,
  Printer,
  PrinterCommandLanguage,
  PrinterConnectionType,
  PrinterDeliveryMode,
  PrinterTrustStatus,
} from "@prisma/client";
import { createHash, randomBytes } from "crypto";

import prisma from "../config/database";
import { inspectIppPrinter } from "../printing/ippClient";
import {
  ensurePrinterProfileForPrinter,
  getPrinterProfileForPrinter,
  serializePrinterCapabilityDiscoveryForClient,
  serializePrinterProfileForClient,
} from "../printing/registry/printerProfileService";
import { testNetworkPrinterConnectivity } from "./networkPrinterSocketService";
import { isGatewayFresh } from "./networkIppPrintService";
import { getPrinterConnectionStatusForUser, type PrinterConnectionStatus } from "./printerConnectionService";
import { supportsNetworkDirectCommandLanguage, supportsNetworkDirectPayload } from "./printPayloadService";
import { resolvePrinterConfirmationMode } from "./printConfirmationService";

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
  if (normalized === "DPL") return PrinterCommandLanguage.DPL;
  if (normalized === "HONEYWELL_DP") return PrinterCommandLanguage.HONEYWELL_DP;
  if (normalized === "HONEYWELL_FINGERPRINT") return PrinterCommandLanguage.HONEYWELL_FINGERPRINT;
  if (normalized === "IPL") return PrinterCommandLanguage.IPL;
  if (normalized === "ZSIM") return PrinterCommandLanguage.ZSIM;
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
  if (languages.includes("DPL")) return PrinterCommandLanguage.DPL;
  if (languages.includes("HONEYWELL_DP")) return PrinterCommandLanguage.HONEYWELL_DP;
  if (languages.includes("HONEYWELL_FINGERPRINT")) return PrinterCommandLanguage.HONEYWELL_FINGERPRINT;
  if (languages.includes("IPL")) return PrinterCommandLanguage.IPL;
  if (languages.includes("ZSIM")) return PrinterCommandLanguage.ZSIM;
  if (languages.includes("CPCL")) return PrinterCommandLanguage.CPCL;
  if (languages.includes("ESC_POS")) return PrinterCommandLanguage.ESC_POS;
  return PrinterCommandLanguage.AUTO;
};

const GATEWAY_OFFLINE_DETAIL =
  "Site gateway has not checked in recently. The on-prem print service must be installed once and kept online for private-LAN printers.";

export const hashGatewaySecret = (secret: string) => createHash("sha256").update(secret).digest("hex");

const normalizeIppPath = (value: string | null | undefined) => {
  const trimmed = String(value || "").trim();
  if (!trimmed) return "/ipp/print";
  return trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
};

const buildStoredPrinterUri = (params: {
  printerUri?: string | null;
  host?: string | null;
  port?: number | null;
  resourcePath?: string | null;
  tlsEnabled?: boolean | null;
}) => {
  const explicit = toNullableString(params.printerUri, 512);
  if (explicit) return explicit;
  const host = toNullableString(params.host, 180);
  if (!host) return null;
  const port = Number(params.port || 631) || 631;
  const tlsEnabled = Boolean(params.tlsEnabled ?? true);
  return `${tlsEnabled ? "ipps" : "ipp"}://${host}:${port}${normalizeIppPath(params.resourcePath)}`;
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
      summary: printer.connectionType === PrinterConnectionType.NETWORK_IPP ? "IPP printer validated" : "Network printer validated",
      detail: printer.lastValidationMessage || null,
    };
  }

  if (validationState === "OFFLINE" || validationState === "FAILED") {
    return {
      state: "OFFLINE",
      summary: printer.connectionType === PrinterConnectionType.NETWORK_IPP ? "IPP printer offline" : "Network printer offline",
      detail: printer.lastValidationMessage || "The last connectivity check could not reach this printer.",
    };
  }

  if (validationState === "BLOCKED") {
    return {
      state: "BLOCKED",
      summary:
        printer.connectionType === PrinterConnectionType.NETWORK_IPP
          ? "IPP printer configuration blocked"
          : "Language not available for network-direct dispatch",
      detail:
        printer.lastValidationMessage ||
        (printer.connectionType === PrinterConnectionType.NETWORK_IPP
          ? "Network IPP printing requires a valid printer URI and PDF-capable IPP endpoint."
          : "Network-direct printing currently supports certified industrial language profiles such as ZPL, TSPL, EPL, DPL, Honeywell DP/Fingerprint, IPL, SBPL, ZSim, and CPCL."),
    };
  }

  return {
    state: "ATTENTION",
    summary: printer.connectionType === PrinterConnectionType.NETWORK_IPP ? "IPP printer needs validation" : "Network printer needs validation",
    detail:
      printer.lastValidationMessage ||
      (printer.connectionType === PrinterConnectionType.NETWORK_IPP
        ? "Run printer validation before dispatching a server-side IPP job."
        : "Run printer validation before dispatching a server-side job."),
  };
};

const buildGatewayPrinterStatus = (printer: RegisteredPrinterRecord): PrinterRegistryStatus => {
  if (!printer.gatewayId || !printer.gatewaySecretHash) {
    return {
      state: "BLOCKED",
      summary: "Gateway enrollment incomplete",
      detail: "Gateway-backed printers require a generated gateway credential before jobs can be claimed on site.",
    };
  }

  if (!printer.isActive) {
    return {
      state: "OFFLINE",
      summary: "Printer disabled",
      detail: printer.gatewayLastError || "Gateway-backed printer profile is inactive.",
    };
  }

  if (!isGatewayFresh(printer.gatewayLastSeenAt)) {
    return {
      state: "OFFLINE",
      summary: "Site gateway offline",
      detail: printer.gatewayLastError || GATEWAY_OFFLINE_DETAIL,
    };
  }

  if (String(printer.gatewayStatus || "").trim().toUpperCase() === "ERROR") {
    return {
      state: "ATTENTION",
      summary: "Site gateway needs attention",
      detail: printer.gatewayLastError || "Gateway reported an error on its last poll cycle.",
    };
  }

  return {
    state: "READY",
    summary: "Site gateway online",
    detail:
      printer.gatewayLastError ||
      "Gateway heartbeat is current. Secure outbound pull dispatch is ready for private-LAN jobs.",
  };
};

export const buildPrinterRegistryStatus = async (
  printer: RegisteredPrinterRecord,
  userContext?: { userId: string }
): Promise<PrinterRegistryStatus> => {
  if (printer.connectionType === PrinterConnectionType.NETWORK_DIRECT) {
    if (printer.deliveryMode === PrinterDeliveryMode.SITE_GATEWAY) {
      if (resolvePrinterConfirmationMode(printer) === "DIRECT_NOT_ALLOWED") {
        return {
          state: "BLOCKED",
          summary: "Direct industrial route not certified",
          detail:
            "This raw label printer does not yet expose a production-safe completion proof for strict direct printing. Use the workstation connector path or a certified Zebra profile.",
        };
      }
      return buildGatewayPrinterStatus(printer);
    }
    if (!supportsNetworkDirectPayload(printer as any)) {
      return {
        state: "BLOCKED",
        summary: "Language not available for network-direct dispatch",
        detail:
          "Network-direct printing currently supports certified industrial language profiles such as ZPL, TSPL, EPL, DPL, Honeywell DP/Fingerprint, IPL, SBPL, ZSim, and CPCL.",
      };
    }
    if (resolvePrinterConfirmationMode(printer) === "DIRECT_NOT_ALLOWED") {
      return {
        state: "BLOCKED",
        summary: "Direct confirmation not available",
        detail:
          "This raw printer can receive data, but MSCQR cannot prove label completion safely in direct mode yet. Use the workstation connector path or a certified Zebra profile.",
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

  if (printer.connectionType === PrinterConnectionType.NETWORK_IPP) {
    if (printer.deliveryMode === PrinterDeliveryMode.SITE_GATEWAY) {
      return buildGatewayPrinterStatus(printer);
    }

    const host = toNullableString(printer.host, 180);
    const printerUri = buildStoredPrinterUri({
      printerUri: printer.printerUri,
      host: printer.host,
      port: printer.port,
      resourcePath: printer.resourcePath,
      tlsEnabled: printer.tlsEnabled,
    });
    if (!host || !printerUri) {
      return {
        state: "BLOCKED",
        summary: "IPP printer config incomplete",
        detail: "Host/FQDN or printer URI is missing.",
      };
    }
    if (!printer.isActive) {
      return {
        state: "OFFLINE",
        summary: "Printer disabled",
        detail: printer.lastValidationMessage || "IPP printer profile is inactive.",
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
    await ensurePrinterProfileForPrinter(
      printer,
      outputs.length === 0 ? "ONBOARDING" : "LIVE_DISCOVERY"
    );
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
    {
      connectionType: PrinterConnectionType.NETWORK_IPP,
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
    printers.map(async (printer) => {
      const profile = await getPrinterProfileForPrinter(printer.id);
      const latestDiscoverySnapshot =
        profile?.snapshots.find((snapshot) => snapshot.snapshotType === "LIVE_DISCOVERY") ||
        profile?.onboardingSnapshot ||
        profile?.snapshots[0] ||
        null;

      return {
        ...printer,
        registryStatus:
          printer.connectionType === PrinterConnectionType.LOCAL_AGENT && localStatus
            ? buildLocalPrinterStatus(printer, localStatus)
            : await buildPrinterRegistryStatus(printer, { userId: params.userId }),
        printerProfile: serializePrinterProfileForClient(profile),
        latestDiscoverySnapshot: latestDiscoverySnapshot
          ? {
              id: latestDiscoverySnapshot.id,
              printerProfileId: latestDiscoverySnapshot.printerProfileId,
              snapshotType: latestDiscoverySnapshot.snapshotType,
              summary: latestDiscoverySnapshot.summary || null,
              warnings: Array.isArray(latestDiscoverySnapshot.warnings) ? (latestDiscoverySnapshot.warnings as string[]) : [],
              capturedAt: latestDiscoverySnapshot.capturedAt.toISOString(),
              data: (latestDiscoverySnapshot.data as Record<string, unknown>) || {},
            }
          : null,
        capabilityDiscovery: serializePrinterCapabilityDiscoveryForClient(profile),
      };
    })
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

export const upsertManagedNetworkPrinter = async (params: {
  printerId?: string;
  userId: string;
  orgId?: string | null;
  licenseeId?: string | null;
  name: string;
  vendor?: string | null;
  model?: string | null;
  connectionType: PrinterConnectionType;
  commandLanguage?: PrinterCommandLanguage;
  ipAddress?: string | null;
  host?: string | null;
  port?: number | null;
  resourcePath?: string | null;
  tlsEnabled?: boolean | null;
  printerUri?: string | null;
  deliveryMode?: PrinterDeliveryMode;
  rotateGatewaySecret?: boolean;
  capabilitySummary?: Record<string, unknown> | null;
  calibrationProfile?: Record<string, unknown> | null;
  isActive?: boolean;
  isDefault?: boolean;
}) => {
  const current = params.printerId
    ? await prisma.printer.findUnique({
        where: { id: params.printerId },
      })
    : null;
  if (params.connectionType === PrinterConnectionType.NETWORK_DIRECT) {
    if (!supportsNetworkDirectCommandLanguage(params.commandLanguage || null)) {
      throw new Error(
        "Network-direct printing currently supports only certified industrial printer languages such as ZPL, TSPL, EPL, DPL, Honeywell DP/Fingerprint, IPL, SBPL, ZSim, and CPCL."
      );
    }
  }

  const deliveryMode =
    params.connectionType === PrinterConnectionType.NETWORK_IPP || params.connectionType === PrinterConnectionType.NETWORK_DIRECT
      ? params.deliveryMode || PrinterDeliveryMode.DIRECT
      : PrinterDeliveryMode.DIRECT;
  const nextGatewaySecret =
    (params.connectionType === PrinterConnectionType.NETWORK_IPP || params.connectionType === PrinterConnectionType.NETWORK_DIRECT) &&
    deliveryMode === PrinterDeliveryMode.SITE_GATEWAY &&
    (!params.printerId || params.rotateGatewaySecret)
      ? randomBytes(24).toString("base64url")
      : null;
  const gatewayId =
    (params.connectionType === PrinterConnectionType.NETWORK_IPP || params.connectionType === PrinterConnectionType.NETWORK_DIRECT) &&
    deliveryMode === PrinterDeliveryMode.SITE_GATEWAY
      ? toNullableString(current?.gatewayId, 64) || `gw-${randomBytes(9).toString("hex")}`
      : null;
  const data = {
    name: toCleanString(params.name, 180),
    vendor: toNullableString(params.vendor, 180) || detectVendor(params.name, params.model || null),
    model: toNullableString(params.model, 180),
    connectionType: params.connectionType,
    commandLanguage:
      params.connectionType === PrinterConnectionType.NETWORK_DIRECT
        ? params.commandLanguage || PrinterCommandLanguage.ZPL
        : PrinterCommandLanguage.AUTO,
    ipAddress:
      params.connectionType === PrinterConnectionType.NETWORK_DIRECT
        ? toNullableString(params.ipAddress, 120)
        : null,
    host:
      params.connectionType === PrinterConnectionType.NETWORK_IPP
        ? toNullableString(params.host, 180)
        : null,
    port: Number(params.port || (params.connectionType === PrinterConnectionType.NETWORK_IPP ? 631 : 9100)) || (params.connectionType === PrinterConnectionType.NETWORK_IPP ? 631 : 9100),
    resourcePath:
      params.connectionType === PrinterConnectionType.NETWORK_IPP
        ? normalizeIppPath(params.resourcePath)
        : null,
    tlsEnabled:
      params.connectionType === PrinterConnectionType.NETWORK_IPP
        ? Boolean(params.tlsEnabled ?? true)
        : false,
    printerUri:
      params.connectionType === PrinterConnectionType.NETWORK_IPP
        ? buildStoredPrinterUri({
            printerUri: params.printerUri || null,
            host: params.host || null,
            port: params.port || 631,
            resourcePath: params.resourcePath || null,
            tlsEnabled: params.tlsEnabled ?? true,
          })
        : null,
    deliveryMode,
    gatewayId,
    gatewaySecretHash:
      (params.connectionType === PrinterConnectionType.NETWORK_IPP || params.connectionType === PrinterConnectionType.NETWORK_DIRECT) &&
      deliveryMode === PrinterDeliveryMode.SITE_GATEWAY
        ? nextGatewaySecret
          ? hashGatewaySecret(nextGatewaySecret)
          : current?.gatewaySecretHash || undefined
        : null,
    gatewayStatus:
      (params.connectionType === PrinterConnectionType.NETWORK_IPP || params.connectionType === PrinterConnectionType.NETWORK_DIRECT) &&
      deliveryMode === PrinterDeliveryMode.SITE_GATEWAY
        ? "PENDING"
        : null,
    gatewayLastError:
      (params.connectionType === PrinterConnectionType.NETWORK_IPP || params.connectionType === PrinterConnectionType.NETWORK_DIRECT) &&
      deliveryMode === PrinterDeliveryMode.SITE_GATEWAY
        ? "Gateway has not checked in yet."
        : null,
    gatewayLastSeenAt:
      (params.connectionType === PrinterConnectionType.NETWORK_IPP || params.connectionType === PrinterConnectionType.NETWORK_DIRECT) &&
      deliveryMode === PrinterDeliveryMode.SITE_GATEWAY
        ? null
        : undefined,
    orgId: params.orgId || null,
    licenseeId: params.licenseeId || null,
    createdByUserId: params.userId,
    isActive: params.isActive ?? true,
    isDefault: params.isDefault ?? false,
    capabilitySummary: toNullableJsonValue(params.capabilitySummary || null),
    calibrationProfile: toNullableJsonValue(params.calibrationProfile || null),
  };

  if (params.printerId) {
    const updated = await prisma.printer.update({
      where: { id: params.printerId },
      data,
    });
    await ensurePrinterProfileForPrinter(
      updated,
      current ? "LIVE_DISCOVERY" : "ONBOARDING"
    );
    return {
      printer: updated,
      gatewayProvisioningSecret: nextGatewaySecret,
    };
  }

  const created = await prisma.printer.create({ data });
  await ensurePrinterProfileForPrinter(created, "ONBOARDING");
  return {
    printer: created,
    gatewayProvisioningSecret: nextGatewaySecret,
  };
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
  const result = await upsertManagedNetworkPrinter({
    ...params,
    connectionType: PrinterConnectionType.NETWORK_DIRECT,
  });
  return result.printer;
};

export const deleteNetworkDirectPrinter = async (params: {
  printerId: string;
  replacementDefaultPrinterId?: string | null;
}) => {
  const printer = await prisma.printer.findUnique({
    where: { id: params.printerId },
  });

  if (!printer) {
    throw new Error("Printer not found");
  }

  if (printer.connectionType === PrinterConnectionType.LOCAL_AGENT) {
    throw new Error("Local-agent printers are managed automatically from the workstation agent.");
  }

  const replacementId = toNullableString(params.replacementDefaultPrinterId, 64);

  return prisma.$transaction(async (tx) => {
    await tx.printer.delete({
      where: { id: printer.id },
    });

    const remainingNetworkPrinters = await tx.printer.findMany({
      where: {
        connectionType: printer.connectionType,
        isActive: true,
        licenseeId: printer.licenseeId || null,
        ...(printer.orgId ? { orgId: printer.orgId } : {}),
      },
      orderBy: [{ isDefault: "desc" }, { updatedAt: "desc" }],
    });

    if (remainingNetworkPrinters.length === 0) {
      return printer;
    }

    const nextDefault =
      (replacementId && remainingNetworkPrinters.find((entry) => entry.id === replacementId)) ||
      remainingNetworkPrinters.find((entry) => entry.isDefault) ||
      remainingNetworkPrinters[0];

    await tx.printer.updateMany({
      where: {
        connectionType: printer.connectionType,
        isActive: true,
        licenseeId: printer.licenseeId || null,
        ...(printer.orgId ? { orgId: printer.orgId } : {}),
      },
      data: {
        isDefault: false,
      },
    });

    await tx.printer.update({
      where: { id: nextDefault.id },
      data: { isDefault: true },
    });

    return printer;
  });
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

  if (params.printer.connectionType === PrinterConnectionType.NETWORK_DIRECT) {
    if (!supportsNetworkDirectCommandLanguage(params.printer.commandLanguage)) {
      const validationMessage =
        "Network-direct printing currently supports only certified industrial printer languages such as ZPL, TSPL, EPL, DPL, Honeywell DP/Fingerprint, IPL, SBPL, ZSim, and CPCL.";
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

    const confirmationMode = resolvePrinterConfirmationMode(params.printer);
    if (confirmationMode === "DIRECT_NOT_ALLOWED") {
      const validationMessage =
        "This raw industrial printer does not yet expose a strict completion signal for safe direct printing. Use the workstation connector path or a certified Zebra profile.";
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

    if (params.printer.deliveryMode === PrinterDeliveryMode.SITE_GATEWAY) {
      const registryStatus = buildGatewayPrinterStatus(params.printer);
      await prisma.printer.update({
        where: { id: params.printer.id },
        data: {
          lastValidatedAt: new Date(),
          lastValidationStatus: registryStatus.state,
          lastValidationMessage: registryStatus.detail || registryStatus.summary,
        },
      });
      return {
        ok: registryStatus.state === "READY",
        registryStatus,
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
      : `TCP connectivity validated in ${result.latencyMs}ms, but the current printer language/profile is not certified for direct dispatch.`;

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
  }

  if (params.printer.connectionType === PrinterConnectionType.NETWORK_IPP) {
    if (params.printer.deliveryMode === PrinterDeliveryMode.SITE_GATEWAY) {
      const registryStatus = buildGatewayPrinterStatus(params.printer);
      await prisma.printer.update({
        where: { id: params.printer.id },
        data: {
          lastValidatedAt: new Date(),
          lastValidationStatus: registryStatus.state,
          lastValidationMessage: registryStatus.detail || registryStatus.summary,
        },
      });
      return {
        ok: registryStatus.state === "READY",
        registryStatus,
      };
    }

    const inspection = await inspectIppPrinter({
      host: params.printer.host,
      port: params.printer.port,
      resourcePath: params.printer.resourcePath,
      tlsEnabled: params.printer.tlsEnabled,
      printerUri: params.printer.printerUri,
    }).catch(async (error: any) => {
      const detail =
        error?.message ||
        `Could not reach ${params.printer.printerUri || buildStoredPrinterUri(params.printer as any) || "IPP printer"}`;
      await prisma.printer.update({
        where: { id: params.printer.id },
        data: {
          lastValidatedAt: new Date(),
          lastValidationStatus: "OFFLINE",
          lastValidationMessage: detail,
          capabilitySummary: toNullableJsonValue({
            ...(params.printer.capabilitySummary as Record<string, unknown> | null),
            documentFormats: [],
          }),
        },
      });
      throw error;
    });

    const validationStatus = inspection.pdfSupported ? "READY" : "BLOCKED";
    const validationMessage = inspection.pdfSupported
      ? `IPP attributes validated at ${inspection.printerUri}. PDF document format supported.`
      : `IPP endpoint is reachable at ${inspection.printerUri}, but application/pdf is not advertised by the printer.`;

    const nextCapabilitySummary = {
      ...((params.printer.capabilitySummary as Record<string, unknown> | null) || {}),
      printerUri: inspection.printerUri,
      endpointUrl: inspection.endpointUrl,
      documentFormats: inspection.documentFormats,
      uriSecurity: inspection.uriSecurity,
      ippVersions: inspection.ippVersions,
      printerState: inspection.printerState,
      printerName: inspection.printerName,
    };

    await prisma.printer.update({
      where: { id: params.printer.id },
      data: {
        host: inspection.endpointUrl ? new URL(inspection.endpointUrl).hostname : params.printer.host,
        printerUri: inspection.printerUri,
        lastValidatedAt: new Date(),
        lastValidationStatus: validationStatus,
        lastValidationMessage: validationMessage,
        capabilitySummary: toNullableJsonValue(nextCapabilitySummary),
      },
    });

    return {
      ok: inspection.pdfSupported,
      registryStatus: buildNetworkPrinterStatus({
        ...params.printer,
        printerUri: inspection.printerUri,
        lastValidationStatus: validationStatus,
        lastValidationMessage: validationMessage,
        capabilitySummary: nextCapabilitySummary as any,
      } as RegisteredPrinterRecord),
    };
  }

  throw new Error("Unsupported printer connection type");
};
