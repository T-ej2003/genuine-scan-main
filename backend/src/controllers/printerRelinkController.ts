import { PrinterConnectionType, UserRole } from "@prisma/client";
import { Response } from "express";
import { z } from "zod";

import { AuthRequest } from "../middleware/auth";
import { sanitizePrinterActionError } from "../utils/printerUserFacingErrors";
import {
  administerPrintingPrinter,
  readPrintingProjection,
} from "../rls-waves/session-c/c02/printingLifecycleRepository";

const printerIdParamSchema = z.object({ id: z.string().uuid("Invalid printer id") }).strict();

const isOpsRole = (role?: UserRole | null) =>
  Boolean(
    role &&
      ([
        UserRole.SUPER_ADMIN,
        UserRole.PLATFORM_SUPER_ADMIN,
        UserRole.LICENSEE_ADMIN,
        UserRole.MANUFACTURER_ADMIN,
      ] as UserRole[]).includes(role)
  );

export const relinkLocalAgentPrinter = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user || !isOpsRole(req.user.role)) return res.status(403).json({ success: false, error: "Access denied" });
    const parsedParams = printerIdParamSchema.safeParse(req.params || {});
    if (!parsedParams.success) {
      return res.status(400).json({ success: false, error: parsedParams.error.errors[0]?.message || "Invalid printer id" });
    }

    const capability = String(req.databaseSessionCapability || "");
    const requestId = String((req as AuthRequest & { requestId?: string }).requestId || "");
    const printer = await readPrintingProjection({
      capability, requestId, operation: "PRINTER", subjectId: parsedParams.data.id,
    });
    if (!printer) return res.status(404).json({ success: false, error: "Printer not found" });
    if (printer.connectionType !== PrinterConnectionType.LOCAL_AGENT) {
      return res.status(400).json({ success: false, error: "Only workstation connector printers can be relinked." });
    }

    const status = await readPrintingProjection({
      capability, requestId, operation: "PRINTER_STATUS", subjectId: req.user.userId,
    });
    const matching = Array.isArray(status?.printers)
      ? status.printers.find((item: any) =>
          String(item?.printerId || item?.id || "") === String(printer.nativePrinterId || "")
          || String(item?.printerName || item?.name || "").toLowerCase() === String(printer.name || "").toLowerCase()
        )
      : null;
    if (!status?.connected || !status?.trusted || !status?.registrationId || !matching) {
      return res.status(409).json({
        success: false,
        error: "The saved printer could not be safely linked to this computer. Choose the printer again in Printer Setup.",
        code: "printer_relink_not_safe",
        errorCode: "printer_relink_not_safe",
      });
    }
    const result = await administerPrintingPrinter({
      capability,
      requestId,
      operation: "RELINK",
      printerId: printer.id,
      payload: {
        printerRegistrationId: status.registrationId,
        nativePrinterId: String(matching.printerId || matching.id),
        agentId: status.agentId,
        deviceFingerprint: status.deviceFingerprint,
      },
    });

    return res.json({ success: true, data: { repaired: true, reason: "registration_mismatch", printer: result } });
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
