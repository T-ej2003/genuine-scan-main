import {
  Prisma,
  Printer,
  PrinterCommandLanguage,
  PrinterConnectionType,
  PrinterDeliveryMode,
  PrinterLanguageKind,
  PrinterProfileSnapshotType,
  PrinterProfileStatus,
  PrinterTransportKind,
} from "@prisma/client";

import prisma from "../../config/database";
import { inspectIppPrinter } from "../ippClient";
import { testNetworkPrinterConnectivity } from "../../services/networkPrinterSocketService";
import { matchPrinterCatalogEntry } from "./printerProfileCatalog";

const toArray = (value: unknown): string[] => {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => String(item || "").trim())
    .filter(Boolean)
    .slice(0, 40);
};

const toBool = (value: unknown) => (value == null ? null : Boolean(value));

const toNumber = (value: unknown) => {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
};

const mapCommandLanguage = (value: PrinterCommandLanguage | string | null | undefined): PrinterLanguageKind => {
  const normalized = String(value || "").trim().toUpperCase();
  if (normalized === "ZPL") return PrinterLanguageKind.ZPL;
  if (normalized === "EPL") return PrinterLanguageKind.EPL;
  if (normalized === "TSPL") return PrinterLanguageKind.TSPL;
  if (normalized === "DPL") return PrinterLanguageKind.DPL;
  if (normalized === "SBPL") return PrinterLanguageKind.SBPL;
  if (normalized === "HONEYWELL_DP") return PrinterLanguageKind.HONEYWELL_DP;
  if (normalized === "HONEYWELL_FINGERPRINT") return PrinterLanguageKind.HONEYWELL_FINGERPRINT;
  if (normalized === "IPL") return PrinterLanguageKind.IPL;
  if (normalized === "ZSIM") return PrinterLanguageKind.ZSIM;
  if (normalized === "PDF") return PrinterLanguageKind.PDF;
  if (normalized === "CPCL") return PrinterLanguageKind.OTHER;
  if (normalized === "ESC_POS") return PrinterLanguageKind.OTHER;
  return PrinterLanguageKind.AUTO;
};

const transportKindFromPrinter = (printer: Pick<Printer, "connectionType" | "deliveryMode">): PrinterTransportKind => {
  if (printer.connectionType === "NETWORK_DIRECT") return PrinterTransportKind.RAW_TCP;
  if (printer.connectionType === "NETWORK_IPP") {
    return printer.deliveryMode === "SITE_GATEWAY" ? PrinterTransportKind.SITE_GATEWAY : PrinterTransportKind.WEB_API;
  }
  return PrinterTransportKind.DRIVER_QUEUE;
};

const jobModeFromPrinter = (printer: Pick<Printer, "connectionType" | "deliveryMode">): string => {
  if (printer.connectionType === "NETWORK_DIRECT") return "raw_tcp";
  if (printer.connectionType === "NETWORK_IPP") {
    return printer.deliveryMode === "SITE_GATEWAY" ? "web_api" : "driver_queue";
  }
  return "driver_queue";
};

const modelFromPrinter = (printer: Pick<Printer, "vendor" | "model" | "name" | "commandLanguage" | "capabilitySummary" | "metadata" | "connectionType" | "deliveryMode" | "host" | "ipAddress" | "port" | "tlsEnabled">) => {
  const catalog = matchPrinterCatalogEntry({
    brand: printer.vendor,
    vendor: printer.vendor,
    model: printer.model,
    name: printer.name,
  });

  const capabilitySummary = printer.capabilitySummary && typeof printer.capabilitySummary === "object"
    ? (printer.capabilitySummary as Record<string, unknown>)
    : {};
  const metadata = printer.metadata && typeof printer.metadata === "object"
    ? (printer.metadata as Record<string, unknown>)
    : {};
  const liveLanguages = toArray(capabilitySummary.languages);
  const activeLanguage =
    liveLanguages.length > 0
      ? mapCommandLanguage(liveLanguages[0])
      : catalog?.activeLanguage || mapCommandLanguage(printer.commandLanguage);
  const transportKind = transportKindFromPrinter(printer);

  return {
    status:
      printer.connectionType === "LOCAL_AGENT"
        ? PrinterProfileStatus.NEEDS_REVIEW
        : printer.connectionType === "NETWORK_DIRECT" || printer.connectionType === "NETWORK_IPP"
          ? PrinterProfileStatus.CERTIFIED
          : PrinterProfileStatus.NEEDS_REVIEW,
    transportKind,
    activeLanguage,
    nativeLanguage: catalog?.nativeLanguage || String(printer.commandLanguage || "AUTO"),
    supportedLanguages:
      liveLanguages.length > 0
        ? liveLanguages
        : catalog?.supportedLanguages || [String(printer.commandLanguage || "AUTO")],
    emulationMode: typeof metadata.emulationMode === "string" ? metadata.emulationMode : null,
    languageVersion: typeof metadata.languageVersion === "string" ? metadata.languageVersion : null,
    jobMode: jobModeFromPrinter(printer),
    spoolFormat:
      catalog?.spoolFormat ||
      (printer.connectionType === "NETWORK_IPP" ? "pdf" : String(printer.commandLanguage || "zpl").toLowerCase()),
    preferredTransport: catalog?.preferredTransport || (printer.connectionType === "NETWORK_DIRECT" ? "Ethernet" : "USB"),
    connectionTypes:
      catalog?.connectionTypes ||
      (printer.connectionType === "LOCAL_AGENT" ? ["USB", "Wi-Fi"] : ["Ethernet"]),
    brand: printer.vendor || catalog?.brand || null,
    modelName: printer.model || null,
    modelFamily: catalog?.modelFamily || null,
    firmwareVersion: typeof metadata.firmwareVersion === "string" ? metadata.firmwareVersion : null,
    serialNumber: typeof metadata.serialNumber === "string" ? metadata.serialNumber : null,
    dpi:
      toNumber((capabilitySummary as Record<string, unknown>).dpi) ||
      (Array.isArray(capabilitySummary.dpiOptions) ? toNumber(capabilitySummary.dpiOptions[0]) : null),
    statusConfig: {
      supportsStatusQuery: printer.connectionType !== "LOCAL_AGENT",
      statusMethod:
        printer.connectionType === "NETWORK_DIRECT"
          ? "socket_probe"
          : printer.connectionType === "NETWORK_IPP"
            ? "ipp_inspection"
            : "workstation_inventory",
      supportsConfigQuery: printer.connectionType !== "LOCAL_AGENT",
      configMethod:
        printer.connectionType === "NETWORK_IPP"
          ? "ipp_inspection"
          : printer.connectionType === "NETWORK_DIRECT"
            ? "socket_probe"
            : "agent_inventory",
      snmpVersion: catalog?.security.snmpv3Supported ? "v3" : null,
      supportsTraps: null,
      webAdmin: printer.connectionType !== "LOCAL_AGENT" ? true : null,
      sdkAvailable: null,
    },
    mediaConstraints: {
      printMethod: catalog?.printMethod || "both",
      supportsRibbon: catalog?.printMethod === "direct_thermal" ? false : null,
      mediaTypes: catalog?.mediaTypes || toArray(capabilitySummary.mediaSizes),
      mediaWidthMinMm: toNumber(metadata.mediaWidthMinMm),
      mediaWidthMaxMm: toNumber(metadata.mediaWidthMaxMm),
      mediaLengthMinMm: toNumber(metadata.mediaLengthMinMm),
      mediaLengthMaxMm: toNumber(metadata.mediaLengthMaxMm),
      mediaThicknessMm: toNumber(metadata.mediaThicknessMm),
      coreDiameterMm: toNumber(metadata.coreDiameterMm),
      sensorTypes: toArray(metadata.sensorTypes),
    },
    installedOptions: {
      cutter: toBool(metadata.cutter ?? catalog?.installedOptions.cutter),
      peeler: toBool(metadata.peeler ?? catalog?.installedOptions.peeler),
      presentSensor: toBool(metadata.presentSensor),
      rewinder: toBool(metadata.rewinder ?? catalog?.installedOptions.rewinder),
      applicatorSupport: toBool(metadata.applicatorSupport ?? catalog?.installedOptions.applicatorSupport),
      gpio: toBool(metadata.gpio ?? catalog?.installedOptions.gpio),
      printEngineMode: toBool(metadata.printEngineMode),
      rfid: toBool(metadata.rfid ?? catalog?.installedOptions.rfid),
      verificationModule: toBool(metadata.verificationModule),
    },
    renderingCapabilities: {
      supportsQr: catalog?.rendering.supportsQr ?? true,
      supportsDatamatrix: catalog?.rendering.supportsDatamatrix ?? true,
      supportsPdf417: catalog?.rendering.supportsPdf417 ?? true,
      maxGraphicMemoryMb: toNumber(metadata.maxGraphicMemoryMb ?? catalog?.rendering.maxGraphicMemoryMb),
      supportsDownloadedFonts: catalog?.rendering.supportsDownloadedFonts ?? true,
      rotationSupport: catalog?.rendering.rotationSupport ?? true,
      unicodeSupport: catalog?.rendering.unicodeSupport ?? true,
    },
    securityPosture: {
      authRequired: catalog?.security.authRequired ?? true,
      defaultCredentialsChanged: toBool(metadata.defaultCredentialsChanged),
      tlsSupport: printer.tlsEnabled ?? catalog?.security.tlsSupport ?? null,
      snmpv3Supported: catalog?.security.snmpv3Supported ?? null,
      networkExposed: printer.connectionType !== "LOCAL_AGENT",
      allowedHosts: Array.isArray(metadata.allowedHosts)
        ? toArray(metadata.allowedHosts)
        : Array.isArray(catalog?.security.allowedHosts)
          ? catalog.security.allowedHosts
          : [],
    },
    latestSeenCapabilities: {
      capabilitySummary,
      liveLanguages,
      host: printer.host || null,
      ipAddress: printer.ipAddress || null,
      port: printer.port || null,
      deliveryMode: printer.deliveryMode || null,
    },
    notes: catalog ? `Baseline matched from ${catalog.brand} ${catalog.modelFamily}.` : null,
  };
};

type JsonSerializable =
  | string
  | number
  | boolean
  | null
  | JsonSerializable[]
  | { [key: string]: JsonSerializable };

const sanitizeJson = (value: unknown): JsonSerializable => {
  if (value === null) return null;
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return value;
  if (Array.isArray(value)) return value.map((entry) => sanitizeJson(entry));
  if (value instanceof Date) return value.toISOString();
  if (typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([, entryValue]) => entryValue !== undefined)
        .map(([key, entryValue]) => [key, sanitizeJson(entryValue)])
    );
  }
  return String(value);
};

const toJsonValue = (value: unknown): Prisma.InputJsonValue => sanitizeJson(value) as Prisma.InputJsonValue;

const toNullableJson = (value: unknown): Prisma.InputJsonValue | typeof Prisma.JsonNull => {
  if (value === undefined || value === null) return Prisma.JsonNull;
  return toJsonValue(value);
};

export const ensurePrinterProfileForPrinter = async (
  printer: Pick<
    Printer,
    | "id"
    | "name"
    | "vendor"
    | "model"
    | "connectionType"
    | "commandLanguage"
    | "capabilitySummary"
    | "metadata"
    | "deliveryMode"
    | "host"
    | "ipAddress"
    | "port"
    | "tlsEnabled"
  >,
  snapshotType: PrinterProfileSnapshotType = PrinterProfileSnapshotType.LIVE_DISCOVERY
) => {
  const candidate = modelFromPrinter(printer);

  const profile = await prisma.printerProfile.upsert({
    where: { printerId: printer.id },
    create: {
      printerId: printer.id,
      status: candidate.status,
      transportKind: candidate.transportKind,
      activeLanguage: candidate.activeLanguage,
      nativeLanguage: candidate.nativeLanguage,
      supportedLanguages: toJsonValue(candidate.supportedLanguages),
      emulationMode: candidate.emulationMode,
      languageVersion: candidate.languageVersion,
      jobMode: candidate.jobMode,
      spoolFormat: candidate.spoolFormat,
      preferredTransport: candidate.preferredTransport,
      connectionTypes: toNullableJson(candidate.connectionTypes),
      brand: candidate.brand,
      modelName: candidate.modelName,
      modelFamily: candidate.modelFamily,
      firmwareVersion: candidate.firmwareVersion,
      serialNumber: candidate.serialNumber,
      dpi: candidate.dpi,
      statusConfig: toNullableJson(candidate.statusConfig),
      mediaConstraints: toNullableJson(candidate.mediaConstraints),
      installedOptions: toNullableJson(candidate.installedOptions),
      renderingCapabilities: toNullableJson(candidate.renderingCapabilities),
      securityPosture: toNullableJson(candidate.securityPosture),
      latestSeenCapabilities: toNullableJson(candidate.latestSeenCapabilities),
      notes: candidate.notes,
      lastVerifiedAt: new Date(),
      lastCertifiedAt: candidate.status === PrinterProfileStatus.CERTIFIED ? new Date() : null,
    },
    update: {
      status: candidate.status,
      transportKind: candidate.transportKind,
      activeLanguage: candidate.activeLanguage,
      nativeLanguage: candidate.nativeLanguage,
      supportedLanguages: toJsonValue(candidate.supportedLanguages),
      emulationMode: candidate.emulationMode,
      languageVersion: candidate.languageVersion,
      jobMode: candidate.jobMode,
      spoolFormat: candidate.spoolFormat,
      preferredTransport: candidate.preferredTransport,
      connectionTypes: toNullableJson(candidate.connectionTypes),
      brand: candidate.brand,
      modelName: candidate.modelName,
      modelFamily: candidate.modelFamily,
      firmwareVersion: candidate.firmwareVersion,
      serialNumber: candidate.serialNumber,
      dpi: candidate.dpi,
      statusConfig: toNullableJson(candidate.statusConfig),
      mediaConstraints: toNullableJson(candidate.mediaConstraints),
      installedOptions: toNullableJson(candidate.installedOptions),
      renderingCapabilities: toNullableJson(candidate.renderingCapabilities),
      securityPosture: toNullableJson(candidate.securityPosture),
      latestSeenCapabilities: toNullableJson(candidate.latestSeenCapabilities),
      notes: candidate.notes,
      lastVerifiedAt: new Date(),
      ...(candidate.status === PrinterProfileStatus.CERTIFIED ? { lastCertifiedAt: new Date() } : {}),
    },
  });

  const snapshot = await prisma.printerProfileSnapshot.create({
    data: {
      printerProfileId: profile.id,
      snapshotType,
      summary: candidate.notes,
      warnings:
        candidate.activeLanguage === PrinterLanguageKind.AUTO
          ? ["Active language could not be authoritatively resolved; printer remains in review."]
          : [],
      data: toJsonValue({
        identity: {
          brand: candidate.brand,
          model: candidate.modelName,
          modelFamily: candidate.modelFamily,
          firmwareVersion: candidate.firmwareVersion,
          serialNumber: candidate.serialNumber,
          dpi: candidate.dpi,
        },
        transport: {
          transportKind: candidate.transportKind,
          preferredTransport: candidate.preferredTransport,
          connectionTypes: candidate.connectionTypes,
          jobMode: candidate.jobMode,
          spoolFormat: candidate.spoolFormat,
        },
        language: {
          nativeLanguage: candidate.nativeLanguage,
          supportedLanguages: candidate.supportedLanguages,
          activeLanguage: candidate.activeLanguage,
          emulationMode: candidate.emulationMode,
          languageVersion: candidate.languageVersion,
        },
        latestSeenCapabilities: candidate.latestSeenCapabilities,
      }),
    },
  });

  if (snapshotType === PrinterProfileSnapshotType.ONBOARDING && profile.onboardingSnapshotId !== snapshot.id) {
    await prisma.printerProfile.update({
      where: { id: profile.id },
      data: { onboardingSnapshotId: snapshot.id },
    });
  }

  return prisma.printerProfile.findUnique({
    where: { id: profile.id },
    include: {
      onboardingSnapshot: true,
      snapshots: {
        orderBy: { capturedAt: "desc" },
        take: 6,
      },
    },
  });
};

export const getPrinterProfileForPrinter = async (printerId: string) =>
  prisma.printerProfile.findUnique({
    where: { printerId },
    include: {
      onboardingSnapshot: true,
      snapshots: {
        orderBy: { capturedAt: "desc" },
        take: 10,
      },
    },
  });

export const discoverPrinterCapabilities = async (printer: Printer) => {
  const warnings: string[] = [];
  const mismatches: string[] = [];
  const profile = await ensurePrinterProfileForPrinter(printer, PrinterProfileSnapshotType.LIVE_DISCOVERY);
  if (!profile) {
    throw new Error("Printer profile unavailable");
  }

  if (printer.connectionType === PrinterConnectionType.NETWORK_DIRECT && printer.ipAddress && printer.port) {
    try {
      await testNetworkPrinterConnectivity({ ipAddress: printer.ipAddress, port: printer.port });
    } catch (error: any) {
      warnings.push(error?.message || "Network printer did not respond to socket connectivity test.");
    }
  }

  if (printer.connectionType === PrinterConnectionType.NETWORK_IPP) {
    try {
      const inspection = await inspectIppPrinter({
        host: printer.host,
        port: printer.port,
        resourcePath: printer.resourcePath,
        tlsEnabled: printer.tlsEnabled,
        printerUri: printer.printerUri,
      });
      if (!inspection.pdfSupported) {
        mismatches.push("Printer does not advertise PDF support over IPP.");
      }
    } catch (error: any) {
      warnings.push(error?.message || "IPP inspection failed.");
    }
  }

  if (profile.activeLanguage === PrinterLanguageKind.AUTO) {
    mismatches.push("Authoritative active language is still AUTO. Certification should not be considered production-ready.");
  }

  const status = mismatches.length > 0 ? PrinterProfileStatus.NEEDS_REVIEW : warnings.length > 0 ? PrinterProfileStatus.NEEDS_REVIEW : PrinterProfileStatus.CERTIFIED;

  await prisma.printerProfile.update({
    where: { id: profile.id },
    data: {
      status,
      lastVerifiedAt: new Date(),
      ...(status === PrinterProfileStatus.CERTIFIED ? { lastCertifiedAt: new Date() } : {}),
    },
  });

  return {
    printerId: printer.id,
    printerProfileId: profile.id,
    status,
    summary:
      status === PrinterProfileStatus.CERTIFIED
        ? "Printer profile discovered and certified."
        : mismatches.length > 0
          ? "Printer profile needs review before production print."
          : "Printer profile discovered with warnings.",
    warnings,
    mismatches,
    lastVerifiedAt: new Date().toISOString(),
  };
};

export const serializePrinterProfileForClient = (profile: Awaited<ReturnType<typeof getPrinterProfileForPrinter>>) => {
  if (!profile) return null;
  return {
    id: profile.id,
    printerId: profile.printerId,
    status: profile.status,
    identity: {
      brand: profile.brand,
      model: profile.modelName,
      modelFamily: profile.modelFamily,
      firmwareVersion: profile.firmwareVersion,
      serialNumber: profile.serialNumber,
      dpi: profile.dpi,
    },
    transport: {
      transportKind: profile.transportKind,
      preferredTransport: profile.preferredTransport,
      connectionTypes: Array.isArray(profile.connectionTypes) ? (profile.connectionTypes as string[]) : [],
      jobMode: profile.jobMode,
      spoolFormat: profile.spoolFormat,
    },
    language: {
      nativeLanguage: profile.nativeLanguage,
      supportedLanguages: Array.isArray(profile.supportedLanguages) ? (profile.supportedLanguages as string[]) : [],
      activeLanguage: profile.activeLanguage,
      emulationMode: profile.emulationMode,
      languageVersion: profile.languageVersion,
    },
    statusConfig: (profile.statusConfig as Record<string, unknown> | null) || {},
    media: (profile.mediaConstraints as Record<string, unknown> | null) || {},
    installedOptions: (profile.installedOptions as Record<string, unknown> | null) || {},
    rendering: (profile.renderingCapabilities as Record<string, unknown> | null) || {},
    security: (profile.securityPosture as Record<string, unknown> | null) || {},
    latestSeenCapabilities: (profile.latestSeenCapabilities as Record<string, unknown> | null) || null,
    notes: profile.notes || null,
    lastVerifiedAt: profile.lastVerifiedAt?.toISOString() || null,
    lastCertifiedAt: profile.lastCertifiedAt?.toISOString() || null,
    snapshots: profile.snapshots.map((snapshot) => ({
      id: snapshot.id,
      snapshotType: snapshot.snapshotType,
      summary: snapshot.summary || null,
      warnings: Array.isArray(snapshot.warnings) ? (snapshot.warnings as string[]) : [],
      capturedAt: snapshot.capturedAt.toISOString(),
      data: (snapshot.data as Record<string, unknown>) || {},
    })),
  };
};

export const serializePrinterCapabilityDiscoveryForClient = (profile: Awaited<ReturnType<typeof getPrinterProfileForPrinter>>) => {
  if (!profile) return null;
  return {
    printerId: profile.printerId,
    identity: {
      brand: profile.brand,
      model: profile.modelName,
      modelFamily: profile.modelFamily,
      firmwareVersion: profile.firmwareVersion,
      serialNumber: profile.serialNumber,
      dpi: profile.dpi,
    },
    language: {
      nativeLanguage: profile.nativeLanguage,
      supportedLanguages: Array.isArray(profile.supportedLanguages) ? (profile.supportedLanguages as string[]) : [],
      activeLanguage: profile.activeLanguage,
      emulationMode: profile.emulationMode,
      languageVersion: profile.languageVersion,
    },
    statusConfig: (profile.statusConfig as Record<string, unknown> | null) || {},
    media: (profile.mediaConstraints as Record<string, unknown> | null) || {},
    installedOptions: (profile.installedOptions as Record<string, unknown> | null) || {},
    rendering: (profile.renderingCapabilities as Record<string, unknown> | null) || {},
    security: (profile.securityPosture as Record<string, unknown> | null) || {},
    warnings: profile.activeLanguage === PrinterLanguageKind.AUTO ? ["Active language is unresolved and still needs certification review."] : [],
    mismatches: profile.status === PrinterProfileStatus.NEEDS_REVIEW ? ["Live discovery or certification review is still required before production print."] : [],
    certified: profile.status === PrinterProfileStatus.CERTIFIED,
    status: profile.status,
  };
};

export const resolvePrinterPreflight = async (printer: Printer, params: { quantity: number; requiredOptions?: string[]; labelWidthMm?: number | null; labelHeightMm?: number | null }) => {
  const profile = await ensurePrinterProfileForPrinter(printer, PrinterProfileSnapshotType.LIVE_DISCOVERY);
  if (!profile) {
    throw new Error("Printer profile unavailable");
  }

  const issues: string[] = [];
  const warnings: string[] = [];
  const media = (profile.mediaConstraints as Record<string, unknown> | null) || {};
  const options = (profile.installedOptions as Record<string, unknown> | null) || {};
  const security = (profile.securityPosture as Record<string, unknown> | null) || {};

  if (profile.activeLanguage === PrinterLanguageKind.AUTO) {
    issues.push("Active language is unresolved. Run printer discovery before production print.");
  }
  if (profile.status === PrinterProfileStatus.BLOCKED) {
    issues.push("Printer profile is blocked by policy.");
  }
  if (security.networkExposed === true && (!Array.isArray(security.allowedHosts) || security.allowedHosts.length === 0)) {
    warnings.push("Network-exposed printer has no allow-list hosts configured.");
  }
  const widthMax = toNumber(media.mediaWidthMaxMm);
  const heightMax = toNumber(media.mediaLengthMaxMm);
  if (params.labelWidthMm && widthMax && params.labelWidthMm > widthMax) {
    issues.push(`Requested label width ${params.labelWidthMm}mm exceeds supported max ${widthMax}mm.`);
  }
  if (params.labelHeightMm && heightMax && params.labelHeightMm > heightMax) {
    issues.push(`Requested label height ${params.labelHeightMm}mm exceeds supported max ${heightMax}mm.`);
  }
  for (const requiredOption of params.requiredOptions || []) {
    if (options[requiredOption] !== true) {
      issues.push(`Required printer option missing: ${requiredOption}.`);
    }
  }

  return {
    ok: issues.length === 0,
    pipelineState: issues.length === 0 ? "PREFLIGHT_OK" : "NEEDS_OPERATOR_ACTION",
    summary: issues.length === 0 ? "Preflight checks passed." : "Preflight checks failed.",
    issues,
    warnings,
    resolvedLanguage: profile.activeLanguage,
    resolvedTransport: profile.transportKind,
    profile,
  };
};
