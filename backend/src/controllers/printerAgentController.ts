import { NotificationAudience, NotificationChannel, UserRole } from "@prisma/client";
import { Response } from "express";
import { z } from "zod";

import { AuthRequest } from "../middleware/auth";
import { createAuditLog } from "../services/auditService";
import { createRoleNotifications } from "../services/notificationService";
import {
  getPrinterConnectionStatusForUser,
  upsertPrinterConnectionHeartbeat,
} from "../services/printerConnectionService";

const MANUFACTURER_ROLES: UserRole[] = [
  UserRole.MANUFACTURER,
  UserRole.MANUFACTURER_ADMIN,
  UserRole.MANUFACTURER_USER,
];

const isManufacturerRole = (role?: UserRole | null) =>
  Boolean(role && MANUFACTURER_ROLES.includes(role));

const heartbeatSchema = z.object({
  connected: z.boolean(),
  printerName: z.string().trim().max(180).optional(),
  printerId: z.string().trim().max(180).optional(),
  deviceName: z.string().trim().max(180).optional(),
  agentVersion: z.string().trim().max(80).optional(),
  error: z.string().trim().max(500).optional(),
});

export const reportPrinterHeartbeat = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user || !isManufacturerRole(req.user.role)) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const parsed = heartbeatSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid heartbeat payload" });
    }

    const update = upsertPrinterConnectionHeartbeat({
      userId: req.user.userId,
      role: req.user.role,
      licenseeId: req.user.licenseeId,
      orgId: req.user.orgId,
      connected: parsed.data.connected,
      printerName: parsed.data.printerName || null,
      printerId: parsed.data.printerId || null,
      deviceName: parsed.data.deviceName || null,
      agentVersion: parsed.data.agentVersion || null,
      error: parsed.data.error || null,
      sourceIp: req.ip,
    });

    if (update.changed) {
      const action = update.status.connected
        ? "PRINTER_CONNECTION_ONLINE"
        : "PRINTER_CONNECTION_OFFLINE";
      const title = update.status.connected ? "Printer connected" : "Printer disconnected";
      const body = update.status.connected
        ? `${update.status.printerName || "Connected printer"} is ready for secure direct-print.`
        : `Printer connection lost${update.status.error ? `: ${update.status.error}` : "."} Direct-print jobs are blocked until restored.`;

      await createAuditLog({
        userId: req.user.userId,
        licenseeId: req.user.licenseeId || undefined,
        action,
        entityType: "PrinterAgent",
        entityId: req.user.userId,
        details: {
          connected: update.status.connected,
          printerName: update.status.printerName || null,
          printerId: update.status.printerId || null,
          deviceName: update.status.deviceName || null,
          agentVersion: update.status.agentVersion || null,
          error: update.status.error || null,
        },
        ipAddress: req.ip,
      });

      await Promise.allSettled([
        createRoleNotifications({
          audience: NotificationAudience.SUPER_ADMIN,
          type: "system_printer_status_changed",
          title,
          body,
          licenseeId: req.user.licenseeId || null,
          orgId: req.user.orgId || null,
          data: {
            connected: update.status.connected,
            printerName: update.status.printerName || null,
            printerId: update.status.printerId || null,
            deviceName: update.status.deviceName || null,
            manufacturerUserId: req.user.userId,
            licenseeId: req.user.licenseeId || null,
            orgId: req.user.orgId || null,
            targetRoute: "/batches",
          },
          channels: [NotificationChannel.WEB],
        }),
        req.user.licenseeId
          ? createRoleNotifications({
              audience: NotificationAudience.LICENSEE_ADMIN,
              licenseeId: req.user.licenseeId,
              type: "system_printer_status_changed",
              title,
              body,
              data: {
                connected: update.status.connected,
                printerName: update.status.printerName || null,
                printerId: update.status.printerId || null,
                deviceName: update.status.deviceName || null,
                manufacturerUserId: req.user.userId,
                licenseeId: req.user.licenseeId || null,
                orgId: req.user.orgId || null,
                targetRoute: "/batches",
              },
              channels: [NotificationChannel.WEB],
            })
          : Promise.resolve([] as any[]),
        req.user.orgId
          ? createRoleNotifications({
              audience: NotificationAudience.MANUFACTURER,
              orgId: req.user.orgId,
              type: "system_printer_status_changed",
              title,
              body,
              data: {
                connected: update.status.connected,
                printerName: update.status.printerName || null,
                printerId: update.status.printerId || null,
                deviceName: update.status.deviceName || null,
                manufacturerUserId: req.user.userId,
                licenseeId: req.user.licenseeId || null,
                orgId: req.user.orgId || null,
                targetRoute: "/batches",
              },
              channels: [NotificationChannel.WEB],
            })
          : Promise.resolve([] as any[]),
      ]);
    }

    return res.json({
      success: true,
      data: update.status,
    });
  } catch (error: any) {
    console.error("reportPrinterHeartbeat error:", error);
    return res.status(500).json({ success: false, error: error?.message || "Internal server error" });
  }
};

export const getPrinterConnectionStatus = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user || !isManufacturerRole(req.user.role)) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    return res.json({
      success: true,
      data: getPrinterConnectionStatusForUser(req.user.userId),
    });
  } catch (error: any) {
    console.error("getPrinterConnectionStatus error:", error);
    return res.status(500).json({ success: false, error: error?.message || "Internal server error" });
  }
};

