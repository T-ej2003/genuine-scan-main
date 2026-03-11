import { PrinterCommandLanguage, PrinterConnectionType, UserRole } from "@prisma/client";
import { Response } from "express";
import { z } from "zod";

import { AuthRequest } from "../middleware/auth";
import { getEffectiveLicenseeId } from "../middleware/tenantIsolation";
import {
  getRegisteredPrinterForManufacturer,
  listRegisteredPrintersForManufacturer,
  testRegisteredPrinterConnection,
  upsertNetworkDirectPrinter,
} from "../services/printerRegistryService";
import { createAuditLog } from "../services/auditService";
import { isManufacturerRole, resolveAccessibleLicenseeIdsForUser } from "../services/manufacturerScopeService";

const NETWORK_DIRECT_LANGUAGE_OPTIONS = [
  PrinterCommandLanguage.ZPL,
  PrinterCommandLanguage.TSPL,
  PrinterCommandLanguage.EPL,
  PrinterCommandLanguage.CPCL,
] as const;

const networkPrinterSchema = z.object({
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
    return res.status(500).json({ success: false, error: error?.message || "Internal server error" });
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
    const printer = await upsertNetworkDirectPrinter({
      userId: scope.userId,
      orgId: scope.orgId,
      licenseeId: scope.licenseeId,
      ...parsed.data,
    });

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

    return res.status(201).json({ success: true, data: printer });
  } catch (error: any) {
    console.error("createNetworkPrinter error:", error);
    return res.status(400).json({ success: false, error: error?.message || "Bad request" });
  }
};

export const updateNetworkPrinter = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user || !isOpsRole(req.user.role)) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const printerId = String(req.params.id || "").trim();
    if (!printerId) return res.status(400).json({ success: false, error: "Missing printer id" });

    const parsed = networkPrinterSchema.partial().safeParse(req.body || {});
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
    if (current.connectionType !== PrinterConnectionType.NETWORK_DIRECT) {
      return res.status(400).json({ success: false, error: "Local-agent printers are managed automatically from the workstation agent." });
    }

    const printer = await upsertNetworkDirectPrinter({
      printerId,
      userId: scope.userId,
      orgId: scope.orgId,
      licenseeId: scope.licenseeId || current.licenseeId || null,
      name: parsed.data.name || current.name,
      vendor: parsed.data.vendor ?? current.vendor,
      model: parsed.data.model ?? current.model,
      ipAddress: parsed.data.ipAddress || current.ipAddress || "",
      port: parsed.data.port ?? current.port ?? 9100,
      commandLanguage: parsed.data.commandLanguage || current.commandLanguage,
      capabilitySummary: parsed.data.capabilitySummary ?? ((current.capabilitySummary as any) || null),
      calibrationProfile: parsed.data.calibrationProfile ?? ((current.calibrationProfile as any) || null),
      isActive: parsed.data.isActive ?? current.isActive,
      isDefault: parsed.data.isDefault ?? current.isDefault,
    });

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

    return res.json({ success: true, data: printer });
  } catch (error: any) {
    console.error("updateNetworkPrinter error:", error);
    return res.status(400).json({ success: false, error: error?.message || "Bad request" });
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
    return res.status(400).json({ success: false, error: error?.message || "Bad request" });
  }
};
