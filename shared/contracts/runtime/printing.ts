import { z } from "zod";
import {
  printerCapabilityDiscoverySchema,
  printerProfileSchema,
  printerProfileSnapshotSchema,
  printPipelineStateSchema,
} from "./printer-profiles";

export const printerCapabilitySummarySchema = z
  .object({
    transports: z.array(z.string()),
    protocols: z.array(z.string()),
    languages: z.array(z.string()),
    supportsRaster: z.boolean(),
    supportsPdf: z.boolean(),
    dpiOptions: z.array(z.number()),
    mediaSizes: z.array(z.string()),
  })
  .passthrough();

export const localPrinterSchema = z
  .object({
    printerId: z.string(),
    printerName: z.string(),
    model: z.string().nullable().optional(),
    connection: z.string().nullable().optional(),
    online: z.boolean().optional(),
    isDefault: z.boolean().optional(),
    protocols: z.array(z.string()).optional(),
    languages: z.array(z.string()).optional(),
    mediaSizes: z.array(z.string()).optional(),
    dpi: z.number().nullable().optional(),
  })
  .passthrough();

export const localPrinterArraySchema = z.array(localPrinterSchema);

export const printerConnectionStatusSchema = z
  .object({
    connected: z.boolean(),
    trusted: z.boolean(),
    compatibilityMode: z.boolean(),
    compatibilityReason: z.string().nullable().optional(),
    eligibleForPrinting: z.boolean(),
    connectionClass: z.enum(["TRUSTED", "COMPATIBILITY", "BLOCKED"]).optional(),
    stale: z.boolean(),
    requiredForPrinting: z.boolean(),
    trustStatus: z.string().optional(),
    trustReason: z.string().nullable().optional(),
    lastHeartbeatAt: z.string().nullable(),
    ageSeconds: z.number().nullable(),
    registrationId: z.string().nullable().optional(),
    agentId: z.string().nullable().optional(),
    deviceFingerprint: z.string().nullable().optional(),
    mtlsFingerprint: z.string().nullable().optional(),
    printerName: z.string().nullable().optional(),
    printerId: z.string().nullable().optional(),
    selectedPrinterId: z.string().nullable().optional(),
    selectedPrinterName: z.string().nullable().optional(),
    deviceName: z.string().nullable().optional(),
    agentVersion: z.string().nullable().optional(),
    capabilitySummary: printerCapabilitySummarySchema.nullable().optional(),
    printers: localPrinterArraySchema.optional(),
    calibrationProfile: z.record(z.string(), z.unknown()).nullable().optional(),
    error: z.string().nullable().optional(),
  })
  .passthrough();

export const registeredPrinterSchema = z
  .object({
    id: z.string(),
    name: z.string(),
    vendor: z.string().nullable().optional(),
    model: z.string().nullable().optional(),
    connectionType: z.enum(["LOCAL_AGENT", "NETWORK_DIRECT", "NETWORK_IPP"]),
    commandLanguage: z.string().nullable().optional(),
    ipAddress: z.string().nullable().optional(),
    host: z.string().nullable().optional(),
    port: z.number().nullable().optional(),
    resourcePath: z.string().nullable().optional(),
    tlsEnabled: z.boolean().nullable().optional(),
    printerUri: z.string().nullable().optional(),
    deliveryMode: z.enum(["DIRECT", "SITE_GATEWAY"]).optional(),
    nativePrinterId: z.string().nullable().optional(),
    isActive: z.boolean(),
    isDefault: z.boolean().optional(),
    registryStatus: z
      .object({
        state: z.enum(["READY", "ATTENTION", "OFFLINE", "BLOCKED"]),
        summary: z.string(),
        detail: z.string().nullable().optional(),
      })
      .nullable()
      .optional(),
    printerProfile: printerProfileSchema.nullable().optional(),
    latestDiscoverySnapshot: printerProfileSnapshotSchema.nullable().optional(),
    capabilityDiscovery: printerCapabilityDiscoverySchema.nullable().optional(),
  })
  .passthrough();

export const registeredPrinterArraySchema = z.array(registeredPrinterSchema);

export const printJobSessionSchema = z
  .object({
    id: z.string().optional(),
    remainingToPrint: z.number().optional(),
    confirmedItems: z.number().optional(),
    frozenItems: z.number().optional(),
    counts: z.record(z.string(), z.number()).optional(),
  })
  .passthrough();

export const printJobSchema = z
  .object({
    id: z.string(),
    jobNumber: z.string().nullable().optional(),
    status: z.enum(["PENDING", "SENT", "CONFIRMED", "FAILED", "CANCELLED"]),
    pipelineState: printPipelineStateSchema.optional(),
    printMode: z.enum(["LOCAL_AGENT", "NETWORK_DIRECT", "NETWORK_IPP"]),
    quantity: z.number(),
    itemCount: z.number().nullable().optional(),
    reprintOfJobId: z.string().nullable().optional(),
    reprintReason: z.string().nullable().optional(),
    failureReason: z.string().nullable().optional(),
    createdAt: z.string(),
    updatedAt: z.string().optional(),
    sentAt: z.string().nullable().optional(),
    confirmedAt: z.string().nullable().optional(),
    completedAt: z.string().nullable().optional(),
    batch: z
      .object({
        id: z.string().optional(),
        name: z.string().nullable().optional(),
        licenseeId: z.string().nullable().optional(),
      })
      .nullable()
      .optional(),
    printer: z
      .object({
        id: z.string().optional(),
        name: z.string().nullable().optional(),
        connectionType: z.string().nullable().optional(),
      })
      .nullable()
      .optional(),
    session: printJobSessionSchema.nullable().optional(),
  })
  .passthrough();

export const printJobArraySchema = z.array(printJobSchema);

export const dashboardNotificationSchema = z
  .object({
    id: z.string(),
    type: z.string().nullable().optional(),
    title: z.string().nullable().optional(),
    body: z.string().nullable().optional(),
    createdAt: z.string().nullable().optional(),
    readAt: z.string().nullable().optional(),
    data: z.unknown().optional(),
    incidentId: z.string().nullable().optional(),
  })
  .passthrough();

export const dashboardNotificationArraySchema = z.array(dashboardNotificationSchema);

export type PrinterCapabilitySummaryDTO = z.infer<typeof printerCapabilitySummarySchema>;
export type LocalPrinterDTO = z.infer<typeof localPrinterSchema>;
export type PrinterConnectionStatusDTO = z.infer<typeof printerConnectionStatusSchema>;
export type RegisteredPrinterDTO = z.infer<typeof registeredPrinterSchema>;
export type PrintJobSessionDTO = z.infer<typeof printJobSessionSchema>;
export type PrintJobDTO = z.infer<typeof printJobSchema>;
export type DashboardNotificationDTO = z.infer<typeof dashboardNotificationSchema>;
