import { z } from "zod";

export const printerTransportKindSchema = z.enum([
  "RAW_TCP",
  "USB_RAW",
  "SERIAL_RAW",
  "DRIVER_QUEUE",
  "SITE_GATEWAY",
  "VENDOR_SDK",
  "WEB_API",
]);

export const printerLanguageKindSchema = z.enum([
  "AUTO",
  "ZPL",
  "EPL",
  "TSPL",
  "DPL",
  "SBPL",
  "HONEYWELL_DP",
  "HONEYWELL_FINGERPRINT",
  "IPL",
  "ZSIM",
  "PDF",
  "OTHER",
]);

export const printerProfileStatusSchema = z.enum(["DRAFT", "CERTIFIED", "NEEDS_REVIEW", "BLOCKED"]);
export const printerProfileSnapshotTypeSchema = z.enum(["ONBOARDING", "LIVE_DISCOVERY", "CERTIFICATION_TEST"]);
export const printPipelineStateSchema = z.enum([
  "QUEUED",
  "PREFLIGHT_OK",
  "SENT_TO_PRINTER",
  "PRINTER_ACKNOWLEDGED",
  "PRINT_CONFIRMED",
  "LOCKED",
  "FAILED",
  "NEEDS_OPERATOR_ACTION",
]);
export const reissueRequestStatusSchema = z.enum(["PENDING", "APPROVED", "REJECTED", "EXECUTED", "CANCELLED"]);

export const printerProfileIdentitySchema = z
  .object({
    brand: z.string().nullable().optional(),
    model: z.string().nullable().optional(),
    modelFamily: z.string().nullable().optional(),
    firmwareVersion: z.string().nullable().optional(),
    serialNumber: z.string().nullable().optional(),
    dpi: z.number().int().nullable().optional(),
  })
  .strict();

export const printerProfileTransportSchema = z
  .object({
    transportKind: printerTransportKindSchema,
    preferredTransport: z.string().nullable().optional(),
    connectionTypes: z.array(z.string()).default([]),
    ipAddress: z.string().nullable().optional(),
    host: z.string().nullable().optional(),
    port: z.number().int().nullable().optional(),
    baudRate: z.number().int().nullable().optional(),
    parity: z.enum(["none", "even", "odd"]).nullable().optional(),
    flowControl: z.enum(["none", "xon_xoff", "rts_cts"]).nullable().optional(),
    jobMode: z.string(),
    requiresDriver: z.boolean().optional(),
    spoolFormat: z.string().nullable().optional(),
    encoding: z.string().nullable().optional(),
    jobTerminator: z.string().nullable().optional(),
  })
  .strict();

export const printerProfileLanguageSchema = z
  .object({
    nativeLanguage: z.string(),
    supportedLanguages: z.array(z.string()).min(1),
    activeLanguage: printerLanguageKindSchema,
    emulationMode: z.string().nullable().optional(),
    languageVersion: z.string().nullable().optional(),
  })
  .strict();

export const printerProfileStatusConfigSchema = z
  .object({
    supportsStatusQuery: z.boolean().optional(),
    statusMethod: z.string().nullable().optional(),
    supportsConfigQuery: z.boolean().optional(),
    configMethod: z.string().nullable().optional(),
    snmpVersion: z.string().nullable().optional(),
    supportsTraps: z.boolean().nullable().optional(),
    webAdmin: z.boolean().nullable().optional(),
    sdkAvailable: z.boolean().nullable().optional(),
  })
  .strict();

export const printerProfileMediaSchema = z
  .object({
    printMethod: z.string().nullable().optional(),
    supportsRibbon: z.boolean().nullable().optional(),
    mediaTypes: z.array(z.string()).default([]),
    mediaWidthMinMm: z.number().nullable().optional(),
    mediaWidthMaxMm: z.number().nullable().optional(),
    mediaLengthMinMm: z.number().nullable().optional(),
    mediaLengthMaxMm: z.number().nullable().optional(),
    mediaThicknessMm: z.number().nullable().optional(),
    coreDiameterMm: z.number().nullable().optional(),
    sensorTypes: z.array(z.string()).default([]),
  })
  .strict();

export const printerProfileOptionsSchema = z
  .object({
    cutter: z.boolean().nullable().optional(),
    peeler: z.boolean().nullable().optional(),
    presentSensor: z.boolean().nullable().optional(),
    rewinder: z.boolean().nullable().optional(),
    applicatorSupport: z.boolean().nullable().optional(),
    gpio: z.boolean().nullable().optional(),
    printEngineMode: z.boolean().nullable().optional(),
    rfid: z.boolean().nullable().optional(),
    verificationModule: z.boolean().nullable().optional(),
  })
  .strict();

export const printerProfileRenderingSchema = z
  .object({
    supportsQr: z.boolean().nullable().optional(),
    supportsDatamatrix: z.boolean().nullable().optional(),
    supportsPdf417: z.boolean().nullable().optional(),
    maxGraphicMemoryMb: z.number().nullable().optional(),
    supportsDownloadedFonts: z.boolean().nullable().optional(),
    rotationSupport: z.boolean().nullable().optional(),
    unicodeSupport: z.boolean().nullable().optional(),
  })
  .strict();

export const printerProfileSecuritySchema = z
  .object({
    authRequired: z.boolean().nullable().optional(),
    defaultCredentialsChanged: z.boolean().nullable().optional(),
    tlsSupport: z.boolean().nullable().optional(),
    snmpv3Supported: z.boolean().nullable().optional(),
    networkExposed: z.boolean().nullable().optional(),
    allowedHosts: z.array(z.string()).default([]),
  })
  .strict();

export const printerProfileSchema = z
  .object({
    id: z.string(),
    printerId: z.string(),
    status: printerProfileStatusSchema,
    identity: printerProfileIdentitySchema,
    transport: printerProfileTransportSchema,
    language: printerProfileLanguageSchema,
    statusConfig: printerProfileStatusConfigSchema,
    media: printerProfileMediaSchema,
    installedOptions: printerProfileOptionsSchema,
    rendering: printerProfileRenderingSchema,
    security: printerProfileSecuritySchema,
    latestSeenCapabilities: z.record(z.string(), z.unknown()).nullable().optional(),
    notes: z.string().nullable().optional(),
    lastVerifiedAt: z.string().nullable().optional(),
    lastCertifiedAt: z.string().nullable().optional(),
  })
  .strict();

export const printerProfileSnapshotSchema = z
  .object({
    id: z.string(),
    printerProfileId: z.string(),
    snapshotType: printerProfileSnapshotTypeSchema,
    summary: z.string().nullable().optional(),
    warnings: z.array(z.string()).default([]),
    capturedAt: z.string(),
    data: z.record(z.string(), z.unknown()),
  })
  .strict();

export const printerCapabilityDiscoverySchema = z
  .object({
    printerId: z.string(),
    identity: printerProfileIdentitySchema,
    language: printerProfileLanguageSchema,
    statusConfig: printerProfileStatusConfigSchema,
    media: printerProfileMediaSchema,
    installedOptions: printerProfileOptionsSchema,
    rendering: printerProfileRenderingSchema,
    security: printerProfileSecuritySchema,
    warnings: z.array(z.string()).default([]),
    mismatches: z.array(z.string()).default([]),
    certified: z.boolean(),
    status: printerProfileStatusSchema,
  })
  .strict();

export const canonicalLabelBlockSchema = z
  .object({
    type: z.enum(["qr", "barcode", "text", "graphic"]),
    xMm: z.number(),
    yMm: z.number(),
    widthMm: z.number().nullable().optional(),
    heightMm: z.number().nullable().optional(),
    rotation: z.number().optional(),
    payload: z.record(z.string(), z.unknown()),
  })
  .strict();

export const canonicalLabelDocumentSchema = z
  .object({
    widthMm: z.number(),
    heightMm: z.number(),
    orientation: z.enum(["PORTRAIT", "LANDSCAPE"]),
    quietZoneMm: z.number().default(2),
    densityHintDpi: z.number().int().nullable().optional(),
    copies: z.number().int().min(1).default(1),
    qrReference: z.object({
      qrId: z.string(),
      code: z.string(),
      scanUrl: z.string(),
    }),
    batchContext: z
      .object({
        batchId: z.string(),
        batchName: z.string().nullable().optional(),
        printJobId: z.string(),
        printItemId: z.string().nullable().optional(),
        reissueOfJobId: z.string().nullable().optional(),
      })
      .strict(),
    blocks: z.array(canonicalLabelBlockSchema).min(1),
  })
  .strict();

export const printPreflightResultSchema = z
  .object({
    ok: z.boolean(),
    pipelineState: printPipelineStateSchema,
    summary: z.string(),
    issues: z.array(z.string()).default([]),
    warnings: z.array(z.string()).default([]),
    resolvedLanguage: printerLanguageKindSchema,
    resolvedTransport: printerTransportKindSchema,
  })
  .strict();

export const printerCertificationResultSchema = z
  .object({
    printerId: z.string(),
    printerProfileId: z.string(),
    status: printerProfileStatusSchema,
    summary: z.string(),
    warnings: z.array(z.string()).default([]),
    mismatches: z.array(z.string()).default([]),
    lastVerifiedAt: z.string().nullable().optional(),
  })
  .strict();

export const reissueRequestSchema = z
  .object({
    id: z.string(),
    originalPrintJobId: z.string(),
    replacementPrintJobId: z.string().nullable().optional(),
    status: reissueRequestStatusSchema,
    reason: z.string(),
    rejectionReason: z.string().nullable().optional(),
    createdAt: z.string(),
    approvedAt: z.string().nullable().optional(),
    executedAt: z.string().nullable().optional(),
  })
  .strict();

export type PrinterProfileDTO = z.infer<typeof printerProfileSchema>;
export type PrinterProfileSnapshotDTO = z.infer<typeof printerProfileSnapshotSchema>;
export type PrinterCapabilityDiscoveryDTO = z.infer<typeof printerCapabilityDiscoverySchema>;
export type CanonicalLabelDocumentDTO = z.infer<typeof canonicalLabelDocumentSchema>;
export type PrintPreflightResultDTO = z.infer<typeof printPreflightResultSchema>;
export type PrinterCertificationResultDTO = z.infer<typeof printerCertificationResultSchema>;
export type ReissueRequestDTO = z.infer<typeof reissueRequestSchema>;
