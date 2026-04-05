import { NotificationAudience, NotificationChannel, Prisma, UserRole } from "@prisma/client";
import { Response } from "express";
import { z } from "zod";

import { AuthRequest } from "../middleware/auth";
import { resolveScopedLicenseeAccess } from "../services/manufacturerScopeService";
import { createAuditLog } from "../services/auditService";
import { createRoleNotifications } from "../services/notificationService";
import {
  getPrinterConnectionStatusForUser,
  onPrinterConnectionEvent,
  upsertPrinterConnectionHeartbeat,
} from "../services/printerConnectionService";
import { syncLocalAgentPrintersFromHeartbeat } from "../services/printerRegistryService";
import { hmacSha256Hex } from "../utils/security";
import { getPrinterSseSignSecret } from "../utils/secretConfig";
import { boundedJsonSchema } from "../utils/boundedJson";
import { isPrismaMissingTableError } from "../utils/prismaStorageGuard";
import { writeSseRealtimeEnvelope } from "../utils/realtime";
const MANUFACTURER_ROLES: UserRole[] = [
  UserRole.MANUFACTURER,
  UserRole.MANUFACTURER_ADMIN,
  UserRole.MANUFACTURER_USER,
];

const isManufacturerRole = (role?: UserRole | null) =>
  Boolean(role && MANUFACTURER_ROLES.includes(role));

const heartbeatSchema = z.object({
  licenseeId: z.string().trim().uuid().optional(),
  connected: z.boolean(),
  printerName: z.string().trim().max(180).optional(),
  printerId: z.string().trim().max(180).optional(),
  selectedPrinterId: z.string().trim().max(180).optional(),
  selectedPrinterName: z.string().trim().max(180).optional(),
  deviceName: z.string().trim().max(180).optional(),
  agentVersion: z.string().trim().max(80).optional(),
  error: z.string().trim().max(500).optional(),
  agentId: z.string().trim().max(180).optional(),
  deviceFingerprint: z.string().trim().max(256).optional(),
  publicKeyPem: z.string().trim().max(8000).optional(),
  clientCertFingerprint: z.string().trim().max(256).optional(),
  heartbeatNonce: z.string().trim().max(180).optional(),
  heartbeatIssuedAt: z.string().trim().max(80).optional(),
  heartbeatSignature: z.string().trim().max(2000).optional(),
  capabilitySummary: boundedJsonSchema({ maxDepth: 4, maxKeys: 40, maxArrayLength: 40 }).optional(),
  printers: z.array(boundedJsonSchema({ maxDepth: 3, maxKeys: 40, maxArrayLength: 40 })).max(50).optional(),
  calibrationProfile: boundedJsonSchema({ maxDepth: 4, maxKeys: 60, maxArrayLength: 40 }).optional(),
}).strict();

const sseKeepaliveSignature = (userId: string, nowIso: string) => {
  const secret = getPrinterSseSignSecret();
  const payload = `${userId}|${nowIso}`;
  return hmacSha256Hex(payload, secret);
};

const isRecoverableHeartbeatStorageError = (error: unknown) => {
  if (isPrismaMissingTableError(error, ["printerregistration", "printerattestation"])) {
    return true;
  }

  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    return ["P2002", "P2003", "P2010", "P2024"].includes(error.code);
  }

  return false;
};

const buildDegradedHeartbeatStatus = (input: z.infer<typeof heartbeatSchema>, currentStatus?: Record<string, any> | null) => {
  const connected = Boolean(input.connected);
  const nowIso = new Date().toISOString();
  const selectedPrinterId = input.selectedPrinterId || input.printerId || currentStatus?.selectedPrinterId || currentStatus?.printerId || null;
  const selectedPrinterName =
    input.selectedPrinterName || input.printerName || currentStatus?.selectedPrinterName || currentStatus?.printerName || null;

  return {
    connected,
    trusted: false,
    compatibilityMode: connected,
    compatibilityReason: connected
      ? "Heartbeat accepted in degraded mode while secure printer storage is recovering."
      : null,
    eligibleForPrinting: connected,
    connectionClass: connected ? "COMPATIBILITY" : "BLOCKED",
    stale: false,
    requiredForPrinting: true,
    trustStatus: currentStatus?.trustStatus || "DEGRADED",
    trustReason: connected
      ? "Printer heartbeat storage is temporarily unavailable"
      : input.error || currentStatus?.trustReason || "Local printer unavailable",
    lastHeartbeatAt: nowIso,
    ageSeconds: 0,
    registrationId: currentStatus?.registrationId || null,
    agentId: input.agentId || currentStatus?.agentId || null,
    deviceFingerprint: input.deviceFingerprint || currentStatus?.deviceFingerprint || null,
    mtlsFingerprint: currentStatus?.mtlsFingerprint || null,
    printerName: input.printerName || selectedPrinterName || currentStatus?.printerName || null,
    printerId: input.printerId || selectedPrinterId || currentStatus?.printerId || null,
    selectedPrinterId,
    selectedPrinterName,
    deviceName: input.deviceName || currentStatus?.deviceName || null,
    agentVersion: input.agentVersion || currentStatus?.agentVersion || null,
    capabilitySummary:
      (input.capabilitySummary && typeof input.capabilitySummary === "object" ? input.capabilitySummary : null) ||
      currentStatus?.capabilitySummary ||
      null,
    printers: Array.isArray(input.printers) ? input.printers : currentStatus?.printers || [],
    calibrationProfile:
      (input.calibrationProfile && typeof input.calibrationProfile === "object" ? input.calibrationProfile : null) ||
      currentStatus?.calibrationProfile ||
      null,
    error: connected ? null : input.error || currentStatus?.error || "Local printer unavailable",
    degraded: true,
  };
};

export const reportPrinterHeartbeat = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user || !isManufacturerRole(req.user.role)) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const parsed = heartbeatSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid heartbeat payload" });
    }
    const scope = await resolveScopedLicenseeAccess(req.user, parsed.data.licenseeId || null);
    const scopedLicenseeId = scope.scopeLicenseeId || req.user.licenseeId || null;

    let update;
    try {
      update = await upsertPrinterConnectionHeartbeat({
        userId: req.user.userId,
        role: req.user.role,
        licenseeId: scopedLicenseeId,
        orgId: req.user.orgId,
        connected: parsed.data.connected,
        printerName: parsed.data.printerName || null,
        printerId: parsed.data.printerId || null,
        selectedPrinterId: parsed.data.selectedPrinterId || null,
        selectedPrinterName: parsed.data.selectedPrinterName || null,
        deviceName: parsed.data.deviceName || null,
        agentVersion: parsed.data.agentVersion || null,
        error: parsed.data.error || null,
        sourceIp: req.ip,
        userAgent: req.get("user-agent") || null,
        agentId: parsed.data.agentId || null,
        deviceFingerprint: parsed.data.deviceFingerprint || null,
        publicKeyPem: parsed.data.publicKeyPem || null,
        clientCertFingerprint: parsed.data.clientCertFingerprint || null,
        mtlsFingerprintHeader: req.get("x-client-cert-fingerprint") || req.get("x-ssl-client-fingerprint") || null,
        heartbeatNonce: parsed.data.heartbeatNonce || null,
        heartbeatIssuedAt: parsed.data.heartbeatIssuedAt || null,
        heartbeatSignature: parsed.data.heartbeatSignature || null,
        capabilitySummary: parsed.data.capabilitySummary || null,
        printers: parsed.data.printers || [],
        calibrationProfile: parsed.data.calibrationProfile || null,
      });
    } catch (heartbeatError) {
      if (!isRecoverableHeartbeatStorageError(heartbeatError)) {
        throw heartbeatError;
      }

      console.error("reportPrinterHeartbeat degraded storage fallback:", heartbeatError);

      let currentStatus: Record<string, any> | null = null;
      try {
        currentStatus = await getPrinterConnectionStatusForUser(req.user.userId);
      } catch (statusError) {
        console.error("reportPrinterHeartbeat fallback status lookup failed:", statusError);
      }

      return res.json({
        success: true,
        degraded: true,
        data: buildDegradedHeartbeatStatus(parsed.data, currentStatus),
      });
    }

    try {
      await syncLocalAgentPrintersFromHeartbeat({
        userId: req.user.userId,
        orgId: req.user.orgId,
        licenseeId: scopedLicenseeId,
        printerRegistrationId: update.status.registrationId || null,
        agentId: update.status.agentId || parsed.data.agentId || null,
        deviceFingerprint: update.status.deviceFingerprint || parsed.data.deviceFingerprint || null,
        selectedPrinterId: update.status.selectedPrinterId || parsed.data.selectedPrinterId || null,
        selectedPrinterName: update.status.selectedPrinterName || parsed.data.selectedPrinterName || null,
        printers: Array.isArray(parsed.data.printers)
          ? parsed.data.printers.filter(
              (item): item is Record<string, unknown> => Boolean(item) && typeof item === "object" && !Array.isArray(item)
            )
          : [],
        capabilitySummary:
          update.status.capabilitySummary && typeof update.status.capabilitySummary === "object"
            ? (update.status.capabilitySummary as unknown as Record<string, unknown>)
            : null,
        calibrationProfile:
          update.status.calibrationProfile && typeof update.status.calibrationProfile === "object"
            ? (update.status.calibrationProfile as Record<string, unknown>)
            : null,
        connected: update.status.connected,
      });
    } catch (syncError) {
      console.error("reportPrinterHeartbeat local printer sync failed:", syncError);
    }

    if (update.changed) {
      const action = update.status.connected
        ? update.status.trusted
          ? "PRINTER_CONNECTION_TRUSTED_ONLINE"
          : "PRINTER_CONNECTION_COMPAT_MODE_ONLINE"
        : "PRINTER_CONNECTION_UNTRUSTED_OR_OFFLINE";
      const title = update.status.connected
        ? update.status.trusted
          ? "Trusted printer connected"
          : "Printer connected in compatibility mode"
        : "Printer trust or connection lost";
      const body = update.status.connected
        ? update.status.trusted
          ? `${update.status.printerName || "Connected printer"} is cryptographically trusted and ready for secure direct-print.`
          : `${update.status.printerName || "Connected printer"} is connected in compatibility mode. Direct-print is enabled while advanced trust enrollment is pending.`
        : `Printer unavailable for issuance${update.status.error ? `: ${update.status.error}` : "."} Direct-print jobs are blocked.`;

      await Promise.allSettled([
        createAuditLog({
          userId: req.user.userId,
          licenseeId: scopedLicenseeId || undefined,
          action,
          entityType: "PrinterAgent",
          entityId: req.user.userId,
          details: {
            connected: update.status.connected,
            trusted: update.status.trusted,
            compatibilityMode: update.status.compatibilityMode,
            compatibilityReason: update.status.compatibilityReason,
            connectionClass: update.status.connectionClass,
            trustStatus: update.status.trustStatus,
            trustReason: update.status.trustReason,
            printerName: update.status.printerName || null,
            printerId: update.status.printerId || null,
            selectedPrinterId: update.status.selectedPrinterId || null,
            selectedPrinterName: update.status.selectedPrinterName || null,
            capabilitySummary: update.status.capabilitySummary || null,
            printers: update.status.printers || [],
            calibrationProfile: update.status.calibrationProfile || null,
            deviceName: update.status.deviceName || null,
            agentVersion: update.status.agentVersion || null,
            agentId: update.status.agentId || null,
            deviceFingerprint: update.status.deviceFingerprint || null,
            mtlsFingerprint: update.status.mtlsFingerprint || null,
            error: update.status.error || null,
          },
          ipAddress: req.ip,
          userAgent: req.get("user-agent") || undefined,
        }),
        createRoleNotifications({
          audience: NotificationAudience.SUPER_ADMIN,
          type: "system_printer_status_changed",
          title,
          body,
          licenseeId: scopedLicenseeId || null,
          orgId: req.user.orgId || null,
          data: {
            connected: update.status.connected,
            trusted: update.status.trusted,
            compatibilityMode: update.status.compatibilityMode,
            compatibilityReason: update.status.compatibilityReason,
            connectionClass: update.status.connectionClass,
            trustStatus: update.status.trustStatus,
            trustReason: update.status.trustReason,
            printerName: update.status.printerName || null,
            printerId: update.status.printerId || null,
            selectedPrinterId: update.status.selectedPrinterId || null,
            selectedPrinterName: update.status.selectedPrinterName || null,
            capabilitySummary: update.status.capabilitySummary || null,
            printers: update.status.printers || [],
            deviceName: update.status.deviceName || null,
            manufacturerUserId: req.user.userId,
            licenseeId: scopedLicenseeId || null,
            orgId: req.user.orgId || null,
            targetRoute: "/batches",
          },
          channels: [NotificationChannel.WEB, NotificationChannel.EMAIL],
        }),
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
      data: await getPrinterConnectionStatusForUser(req.user.userId),
    });
  } catch (error: any) {
    console.error("getPrinterConnectionStatus error:", error);
    return res.status(500).json({ success: false, error: error?.message || "Internal server error" });
  }
};

export const printerConnectionEvents = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user || !isManufacturerRole(req.user.role)) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache, no-transform");
    res.setHeader("Connection", "keep-alive");
    res.flushHeaders?.();

    const sendSnapshot = async (reason: string) => {
      const status = await getPrinterConnectionStatusForUser(req.user!.userId);
      writeSseRealtimeEnvelope(res, {
        channel: "printer",
        type: "snapshot",
        payload: {
          reason,
          status,
          serverTime: new Date().toISOString(),
        },
      });
    };

    await sendSnapshot("initial");

    const off = onPrinterConnectionEvent(async (event) => {
      if (event.userId !== req.user!.userId) return;
      writeSseRealtimeEnvelope(res, {
        channel: "printer",
        type: "snapshot",
        payload: {
          reason: "changed",
          status: event.status,
          serverTime: event.changedAt,
        },
        occurredAt: event.changedAt,
      });
    });

    const keepAlive = setInterval(() => {
      const nowIso = new Date().toISOString();
      writeSseRealtimeEnvelope(res, {
        channel: "printer",
        type: "keepalive",
        payload: {
          serverTime: nowIso,
          signature: sseKeepaliveSignature(req.user!.userId, nowIso),
        },
        occurredAt: nowIso,
      });
    }, 20_000);

    req.on("close", () => {
      clearInterval(keepAlive);
      off();
      res.end();
    });
  } catch (error) {
    console.error("printerConnectionEvents error:", error);
    return res.status(500).end();
  }
};
