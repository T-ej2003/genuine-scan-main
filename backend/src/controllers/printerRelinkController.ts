import { PrinterConnectionType, UserRole } from "@prisma/client";
import { Response } from "express";
import { z } from "zod";

import { AuthRequest } from "../middleware/auth";
import { getEffectiveLicenseeId } from "../middleware/tenantIsolation";
import { isManufacturerRole, resolveAccessibleLicenseeIdsForUser } from "../services/manufacturerScopeService";
import { getPrinterConnectionStatusForUser } from "../services/printerConnectionService";
import { relinkLocalAgentPrinterToCurrentConnector } from "../services/localAgentPrinterRelinkService";
import { getRegisteredPrinterForManufacturer } from "../services/printerRegistryService";
import { sanitizePrinterActionError } from "../utils/printerUserFacingErrors";

const printerIdParamSchema = z.object({ id: z.string().uuid("Invalid printer id") }).strict();

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

export const relinkLocalAgentPrinter = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user || !isOpsRole(req.user.role)) return res.status(403).json({ success: false, error: "Access denied" });
    const parsedParams = printerIdParamSchema.safeParse(req.params || {});
    if (!parsedParams.success) {
      return res.status(400).json({ success: false, error: parsedParams.error.errors[0]?.message || "Invalid printer id" });
    }

    const scope = {
      userId: req.user.userId,
      orgId: req.user.orgId || null,
      licenseeId: getEffectiveLicenseeId(req),
      licenseeIds: isManufacturerRole(req.user.role) ? await resolveAccessibleLicenseeIdsForUser(req.user) : null,
    };
    const printer = await getRegisteredPrinterForManufacturer({ printerId: parsedParams.data.id, ...scope, includeInactive: true });
    if (!printer) return res.status(404).json({ success: false, error: "Printer not found" });
    if (printer.connectionType !== PrinterConnectionType.LOCAL_AGENT) {
      return res.status(400).json({ success: false, error: "Only workstation connector printers can be relinked." });
    }

    const result = await relinkLocalAgentPrinterToCurrentConnector({
      printer,
      printerStatus: await getPrinterConnectionStatusForUser(scope.userId),
      actorUserId: scope.userId,
      orgId: scope.orgId,
      licenseeId: scope.licenseeId || printer.licenseeId || null,
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || null,
    });

    return res.json({ success: true, data: { repaired: result.repaired, reason: result.reason, printer: result.printer } });
  } catch (error: any) {
    console.error("relinkLocalAgentPrinter error:", error);
    if (error?.message === "LOCAL_PRINTER_RELINK_NOT_SAFE") {
      return res.status(409).json({
        success: false,
        error: "The saved printer could not be safely linked to this computer. Choose the ZDesigner printer again in Printer Setup.",
        code: "printer_relink_not_safe",
        errorCode: "printer_relink_not_safe",
        data: { reason: String(error?.reason || "not_safe") },
      });
    }
    return res.status(400).json({
      success: false,
      error: sanitizePrinterActionError(error?.message, "This saved printer could not be relinked right now."),
    });
  }
};
