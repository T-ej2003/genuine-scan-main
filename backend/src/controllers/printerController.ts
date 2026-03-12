import { PrinterCommandLanguage, PrinterConnectionType, PrinterDeliveryMode, UserRole } from "@prisma/client";
import { Response } from "express";
import { z } from "zod";

import { AuthRequest } from "../middleware/auth";
import { getEffectiveLicenseeId } from "../middleware/tenantIsolation";
import {
  deleteNetworkDirectPrinter as deleteNetworkDirectPrinterRecord,
  getRegisteredPrinterForManufacturer,
  listRegisteredPrintersForManufacturer,
  testRegisteredPrinterConnection,
  upsertManagedNetworkPrinter,
} from "../services/printerRegistryService";
import { createAuditLog } from "../services/auditService";
import { isManufacturerRole, resolveAccessibleLicenseeIdsForUser } from "../services/manufacturerScopeService";
import { sanitizePrinterActionError } from "../utils/printerUserFacingErrors";

const NETWORK_DIRECT_LANGUAGE_OPTIONS = [
  PrinterCommandLanguage.ZPL,
  PrinterCommandLanguage.TSPL,
  PrinterCommandLanguage.EPL,
  PrinterCommandLanguage.CPCL,
] as const;

const networkDirectPrinterSchema = z.object({
  name: z.string().trim().min(2).max(180),
  vendor: z.string().trim().max(180).optional(),
  model: z.string().trim().max(180).optional(),
  connectionType: z.literal(PrinterConnectionType.NETWORK_DIRECT).default(PrinterConnectionType.NETWORK_DIRECT),
  commandLanguage: z.enum(NETWORK_DIRECT_LANGUAGE_OPTIONS).default(PrinterCommandLanguage.ZPL),
  ipAddress: z.string().trim().min(3).max(120),
  port: z.number().int().min(1).max(65535).default(9100),
  capabilitySummary: z.record(z.any()).optional(),
  calibrationProfile: z.record(z.any()).optional(),
  isActive: z.boolean().optional(),
  isDefault: z.boolean().optional(),
});

const networkIppPrinterSchema = z.object({
  name: z.string().trim().min(2).max(180),
  vendor: z.string().trim().max(180).optional(),
  model: z.string().trim().max(180).optional(),
  connectionType: z.literal(PrinterConnectionType.NETWORK_IPP).default(PrinterConnectionType.NETWORK_IPP),
  host: z.string().trim().min(2).max(180).optional(),
  port: z.number().int().min(1).max(65535).default(631),
  resourcePath: z.string().trim().min(1).max(240).default("/ipp/print"),
  tlsEnabled: z.boolean().default(true),
  printerUri: z.string().trim().min(8).max(512).optional(),
  deliveryMode: z.enum([PrinterDeliveryMode.DIRECT, PrinterDeliveryMode.SITE_GATEWAY]).default(PrinterDeliveryMode.DIRECT),
  rotateGatewaySecret: z.boolean().optional(),
  capabilitySummary: z.record(z.any()).optional(),
  calibrationProfile: z.record(z.any()).optional(),
  isActive: z.boolean().optional(),
  isDefault: z.boolean().optional(),
});

const networkPrinterSchema = z.discriminatedUnion("connectionType", [networkDirectPrinterSchema, networkIppPrinterSchema]);
const networkPrinterUpdateSchema = z.union([
  networkDirectPrinterSchema.partial().extend({ connectionType: z.literal(PrinterConnectionType.NETWORK_DIRECT).optional() }),
  networkIppPrinterSchema.partial().extend({ connectionType: z.literal(PrinterConnectionType.NETWORK_IPP).optional() }),
]);

const isOpsRole = (role?: UserRole | null) =>
  Boolean(
    role &&
      [
        UserRole.SUPER_ADMIN,
        UserRole.PLATFORM_SUPER_ADMIN,
        UserRole.LICENSEE_ADMIN,
        UserRole.ORG_ADMIN,
        UserRole.MANUFACTURER,
        UserRole.MANUFACTURER_ADMIN,
        UserRole.MANUFACTURER_USER,
      ].includes(role)
  );

const resolveScope = async (req: AuthRequest) => ({
  userId: req.user!.userId,
  orgId: req.user?.orgId || null,
  licenseeId: getEffectiveLicenseeId(req),
  licenseeIds: isManufacturerRole(req.user?.role) ? await resolveAccessibleLicenseeIdsForUser(req.user!) : null,
});

export const listPrinters = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user || !isOpsRole(req.user.role)) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const scope = await resolveScope(req);
    const includeInactive = String(req.query.includeInactive || "").trim().toLowerCase() === "true";
    const rows = await listRegisteredPrintersForManufacturer({
      userId: scope.userId,
      orgId: scope.orgId,
      licenseeId: scope.licenseeId,
      licenseeIds: scope.licenseeIds,
      includeInactive,
    });

    return res.json({ success: true, data: rows });
  } catch (error: any) {
    console.error("listPrinters error:", error);
    return res.status(500).json({ success: false, error: "Printer information is temporarily unavailable." });
  }
};

export const createNetworkPrinter = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user || !isOpsRole(req.user.role)) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const parsed = networkPrinterSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid printer payload" });
    }

    const scope = await resolveScope(req);
    if (!scope.licenseeId) {
      return res.status(400).json({ success: false, error: "licenseeId is required to register a network printer" });
    }
    const result = await upsertManagedNetworkPrinter({
      userId: scope.userId,
      orgId: scope.orgId,
      licenseeId: scope.licenseeId,
      ...parsed.data,
    });
    const printer = result.printer;

    await createAuditLog({
      userId: scope.userId,
      licenseeId: scope.licenseeId || undefined,
      action: "PRINTER_REGISTERED",
      entityType: "Printer",
      entityId: printer.id,
      details: {
        connectionType: printer.connectionType,
        commandLanguage: printer.commandLanguage,
        ipAddress: printer.ipAddress,
        port: printer.port,
      },
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
    });

    return res.status(201).json({
      success: true,
      data: {
        ...printer,
        gatewayProvisioningSecret: result.gatewayProvisioningSecret || null,
      },
    });
  } catch (error: any) {
    console.error("createNetworkPrinter error:", error);
    return res.status(400).json({
      success: false,
      error: sanitizePrinterActionError(error?.message, "This printer setup could not be saved."),
    });
  }
};

export const updateNetworkPrinter = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user || !isOpsRole(req.user.role)) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const printerId = String(req.params.id || "").trim();
    if (!printerId) return res.status(400).json({ success: false, error: "Missing printer id" });

    const parsed = networkPrinterUpdateSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid printer payload" });
    }

    const scope = await resolveScope(req);
    const current = await getRegisteredPrinterForManufacturer({
      printerId,
      userId: scope.userId,
      orgId: scope.orgId,
      licenseeId: scope.licenseeId,
      licenseeIds: scope.licenseeIds,
      includeInactive: true,
    });
    if (!current) return res.status(404).json({ success: false, error: "Printer not found" });
    if (current.connectionType === PrinterConnectionType.LOCAL_AGENT) {
      return res.status(400).json({ success: false, error: "Local-agent printers are managed automatically from the workstation agent." });
    }

    const connectionType = parsed.data.connectionType || current.connectionType;
    const result = await upsertManagedNetworkPrinter({
      printerId,
      userId: scope.userId,
      orgId: scope.orgId,
      licenseeId: scope.licenseeId || current.licenseeId || null,
      name: parsed.data.name || current.name,
      vendor: parsed.data.vendor ?? current.vendor,
      model: parsed.data.model ?? current.model,
      connectionType,
      ipAddress:
        connectionType === PrinterConnectionType.NETWORK_DIRECT
          ? ("ipAddress" in parsed.data ? parsed.data.ipAddress : current.ipAddress) || ""
          : null,
      host:
        connectionType === PrinterConnectionType.NETWORK_IPP
          ? ("host" in parsed.data ? parsed.data.host : current.host) || ""
          : null,
      port: parsed.data.port ?? current.port ?? (connectionType === PrinterConnectionType.NETWORK_IPP ? 631 : 9100),
      resourcePath:
        connectionType === PrinterConnectionType.NETWORK_IPP
          ? ("resourcePath" in parsed.data ? parsed.data.resourcePath : current.resourcePath) || "/ipp/print"
          : null,
      tlsEnabled:
        connectionType === PrinterConnectionType.NETWORK_IPP
          ? ("tlsEnabled" in parsed.data ? parsed.data.tlsEnabled : current.tlsEnabled) ?? true
          : false,
      printerUri:
        connectionType === PrinterConnectionType.NETWORK_IPP
          ? ("printerUri" in parsed.data ? parsed.data.printerUri : current.printerUri) || undefined
          : undefined,
      deliveryMode:
        connectionType === PrinterConnectionType.NETWORK_IPP
          ? ("deliveryMode" in parsed.data ? parsed.data.deliveryMode : current.deliveryMode) ?? PrinterDeliveryMode.DIRECT
          : PrinterDeliveryMode.DIRECT,
      rotateGatewaySecret: "rotateGatewaySecret" in parsed.data ? parsed.data.rotateGatewaySecret : false,
      commandLanguage:
        connectionType === PrinterConnectionType.NETWORK_DIRECT
          ? (("commandLanguage" in parsed.data ? parsed.data.commandLanguage : current.commandLanguage) as PrinterCommandLanguage)
          : PrinterCommandLanguage.AUTO,
      capabilitySummary: parsed.data.capabilitySummary ?? ((current.capabilitySummary as any) || null),
      calibrationProfile: parsed.data.calibrationProfile ?? ((current.calibrationProfile as any) || null),
      isActive: parsed.data.isActive ?? current.isActive,
      isDefault: parsed.data.isDefault ?? current.isDefault,
    });
    const printer = result.printer;

    await createAuditLog({
      userId: scope.userId,
      licenseeId: scope.licenseeId || undefined,
      action: "PRINTER_UPDATED",
      entityType: "Printer",
      entityId: printer.id,
      details: {
        connectionType: printer.connectionType,
        commandLanguage: printer.commandLanguage,
        ipAddress: printer.ipAddress,
        port: printer.port,
        isActive: printer.isActive,
      },
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
    });

    return res.json({
      success: true,
      data: {
        ...printer,
        gatewayProvisioningSecret: result.gatewayProvisioningSecret || null,
      },
    });
  } catch (error: any) {
    console.error("updateNetworkPrinter error:", error);
    return res.status(400).json({
      success: false,
      error: sanitizePrinterActionError(error?.message, "This printer setup could not be updated."),
    });
  }
};

export const testPrinter = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user || !isOpsRole(req.user.role)) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const printerId = String(req.params.id || "").trim();
    if (!printerId) return res.status(400).json({ success: false, error: "Missing printer id" });

    const scope = await resolveScope(req);
    const printer = await getRegisteredPrinterForManufacturer({
      printerId,
      userId: scope.userId,
      orgId: scope.orgId,
      licenseeId: scope.licenseeId,
      licenseeIds: scope.licenseeIds,
      includeInactive: true,
    });
    if (!printer) return res.status(404).json({ success: false, error: "Printer not found" });

    const result = await testRegisteredPrinterConnection({ printer, userId: scope.userId });

    await createAuditLog({
      userId: scope.userId,
      licenseeId: scope.licenseeId || undefined,
      action: "PRINTER_TESTED",
      entityType: "Printer",
      entityId: printer.id,
      details: {
        connectionType: printer.connectionType,
        result,
      },
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
    });

    return res.json({ success: true, data: result });
  } catch (error: any) {
    console.error("testPrinter error:", error);
    return res.status(400).json({
      success: false,
      error: sanitizePrinterActionError(error?.message, "This printer could not be checked right now."),
    });
  }
};

export const deleteNetworkPrinter = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user || !isOpsRole(req.user.role)) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const printerId = String(req.params.id || "").trim();
    if (!printerId) return res.status(400).json({ success: false, error: "Missing printer id" });

    const scope = await resolveScope(req);
    const printer = await getRegisteredPrinterForManufacturer({
      printerId,
      userId: scope.userId,
      orgId: scope.orgId,
      licenseeId: scope.licenseeId,
      licenseeIds: scope.licenseeIds,
      includeInactive: true,
    });
    if (!printer) return res.status(404).json({ success: false, error: "Printer not found" });
    if (printer.connectionType === PrinterConnectionType.LOCAL_AGENT) {
      return res.status(400).json({ success: false, error: "Local-agent printers are managed automatically from the workstation agent." });
    }

    const deletedPrinter = await deleteNetworkDirectPrinterRecord({
      printerId: printer.id,
    });

    await createAuditLog({
      userId: scope.userId,
      licenseeId: scope.licenseeId || deletedPrinter.licenseeId || undefined,
      action: "PRINTER_REMOVED",
      entityType: "Printer",
      entityId: deletedPrinter.id,
      details: {
        connectionType: deletedPrinter.connectionType,
        commandLanguage: deletedPrinter.commandLanguage,
        ipAddress: deletedPrinter.ipAddress,
        port: deletedPrinter.port,
      },
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
    });

    return res.json({
      success: true,
      data: {
        id: deletedPrinter.id,
        removed: true,
      },
    });
  } catch (error: any) {
    console.error("deleteNetworkPrinter error:", error);
    return res.status(400).json({
      success: false,
      error: sanitizePrinterActionError(error?.message, "This printer setup could not be removed."),
    });
  }
};
