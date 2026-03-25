import { Response } from "express";
import { createHash, randomBytes } from "crypto";
import {
  NotificationAudience,
  NotificationChannel,
  PrintDispatchMode,
  PrintPayloadType,
  Prisma,
  PrinterConnectionType,
  PrinterDeliveryMode,
  UserRole,
} from "@prisma/client";
import { z } from "zod";

import prisma from "../../config/database";
import { AuthRequest } from "../../middleware/auth";
import { createRoleNotifications } from "../../services/notificationService";
import { getPrinterConnectionStatusForUser } from "../../services/printerConnectionService";
import {
  resolvePayloadType,
  supportsNetworkDirectPayload,
} from "../../services/printPayloadService";
import { getRegisteredPrinterForManufacturer } from "../../services/printerRegistryService";
import { testNetworkPrinterConnectivity } from "../../services/networkPrinterSocketService";
import { inspectIppPrinter } from "../../printing/ippClient";
import {
  beginIdempotentAction,
  extractIdempotencyKey,
  type IdempotencyBeginResult,
} from "../../services/idempotencyService";

const MANUFACTURER_ROLES: UserRole[] = [
  UserRole.MANUFACTURER,
  UserRole.MANUFACTURER_ADMIN,
  UserRole.MANUFACTURER_USER,
];

const isManufacturerRole = (role?: UserRole | null) =>
  Boolean(role && MANUFACTURER_ROLES.includes(role));

export const createPrintJobSchema = z.object({
  batchId: z.string().uuid(),
  printerId: z.string().uuid(),
  quantity: z.number().int().positive().max(200000),
  rangeStart: z.string().optional(),
  rangeEnd: z.string().optional(),
  reprintOfJobId: z.string().uuid().optional(),
  reprintReason: z.string().trim().min(3).max(300).optional(),
}).strict();

export const listPrintJobsQuerySchema = z.object({
  batchId: z.string().uuid().optional(),
  limit: z.coerce.number().int().min(1).max(100).optional(),
}).strict();

export const confirmSchema = z.object({
  printLockToken: z.string().min(10),
}).strict();

export const issueDirectPrintTokensSchema = z.object({
  printLockToken: z.string().min(10),
  count: z.number().int().min(1).max(500).optional(),
}).strict();

export const resolveDirectPrintTokenSchema = z.object({
  printLockToken: z.string().min(10),
  renderToken: z.string().min(16),
}).strict();

export const confirmDirectPrintItemSchema = z.object({
  printLockToken: z.string().min(10),
  printItemId: z.string().uuid(),
  agentMetadata: z.any().optional(),
}).strict();

export const reportDirectPrintFailureSchema = z.object({
  printLockToken: z.string().min(10),
  reason: z.string().trim().min(3).max(500),
  printItemId: z.string().uuid().optional(),
  retries: z.number().int().min(0).max(20).optional(),
  agentMetadata: z.any().optional(),
}).strict();

export const printJobIdParamSchema = z.object({
  id: z.string().uuid("Invalid print job id"),
}).strict();

export const hashLockToken = (raw: string) =>
  createHash("sha256").update(raw).digest("hex");

const parsePositiveIntEnv = (name: string, fallback: number, hardMax: number) => {
  const raw = Number(String(process.env[name] || "").trim());
  if (!Number.isFinite(raw) || raw <= 0) return fallback;
  return Math.max(1, Math.min(hardMax, Math.floor(raw)));
};

export const DIRECT_PRINT_LOCK_TTL_MINUTES = parsePositiveIntEnv("PRINT_JOB_LOCK_TTL_MINUTES", 45, 24 * 60);
export const DIRECT_PRINT_RENDER_TOKEN_TTL_SECONDS = parsePositiveIntEnv("DIRECT_PRINT_TOKEN_TTL_SECONDS", 90, 900);
export const DIRECT_PRINT_MAX_BATCH = parsePositiveIntEnv("DIRECT_PRINT_MAX_BATCH", 250, 500);

export const describePrintDispatchMode = (mode: PrintDispatchMode) => {
  if (mode === PrintDispatchMode.NETWORK_DIRECT) return "Network-direct";
  if (mode === PrintDispatchMode.NETWORK_IPP) return "Network IPP";
  return "Local-agent";
};

export const getLockExpiresAt = (createdAt: Date) =>
  new Date(createdAt.getTime() + DIRECT_PRINT_LOCK_TTL_MINUTES * 60 * 1000);

export const isLockExpired = (createdAt: Date, now: Date = new Date()) =>
  getLockExpiresAt(createdAt).getTime() <= now.getTime();

export const ensureManufacturerUser = (req: AuthRequest, res: Response) => {
  if (!req.user || !isManufacturerRole(req.user.role)) {
    res.status(403).json({ success: false, error: "Access denied" });
    return null;
  }
  return req.user;
};

export const getManufacturerPrintJob = async (jobId: string, userId: string) =>
  prisma.printJob.findFirst({
    where: { id: jobId, manufacturerId: userId },
    include: {
      batch: { select: { id: true, name: true, licenseeId: true } },
      printer: true,
      printSession: true,
    },
  });

export const generatePrintJobNumber = () =>
  `PJ-${new Date().toISOString().slice(0, 10).replace(/-/g, "")}-${randomBytes(4).toString("hex").toUpperCase()}`;

const ensureTrustedPrinterConnected = async (userId: string) => {
  const printerStatus = await getPrinterConnectionStatusForUser(userId);
  if (!printerStatus.connected || !printerStatus.eligibleForPrinting) {
    throw Object.assign(new Error("PRINTER_NOT_TRUSTED"), { printerStatus });
  }
  return printerStatus;
};

export const ensureSelectedPrinterReady = async (params: {
  printerId: string;
  userId: string;
  orgId?: string | null;
  licenseeId?: string | null;
}) => {
  const printer = await getRegisteredPrinterForManufacturer({
    printerId: params.printerId,
    userId: params.userId,
    orgId: params.orgId,
    licenseeId: params.licenseeId,
    includeInactive: true,
  });

  if (!printer) {
    throw new Error("PRINTER_NOT_FOUND");
  }
  if (!printer.isActive) {
    throw new Error("PRINTER_INACTIVE");
  }

  if (printer.connectionType === PrinterConnectionType.LOCAL_AGENT) {
    const printerStatus = await ensureTrustedPrinterConnected(params.userId);
    const activePrinterId = String(printerStatus.selectedPrinterId || printerStatus.printerId || "").trim();
    if (printer.nativePrinterId && activePrinterId && printer.nativePrinterId !== activePrinterId) {
      throw Object.assign(new Error("PRINTER_SELECTION_MISMATCH"), { printerStatus, printer });
    }
    return {
      printer,
      printerStatus,
      printMode: PrintDispatchMode.LOCAL_AGENT,
      payloadType: resolvePayloadType(printer as any),
    };
  }

  if (printer.connectionType === PrinterConnectionType.NETWORK_DIRECT) {
    if (!printer.ipAddress || !printer.port) {
      throw new Error("PRINTER_NETWORK_CONFIG_INVALID");
    }

    if (!supportsNetworkDirectPayload(printer as any)) {
      const detail =
        "Network-direct printing currently supports only ZPL, TSPL, EPL, and CPCL. Use the local agent for other printer languages.";
      await prisma.printer.update({
        where: { id: printer.id },
        data: {
          lastValidatedAt: new Date(),
          lastValidationStatus: "BLOCKED",
          lastValidationMessage: detail,
        },
      });
      throw Object.assign(new Error("PRINTER_NETWORK_LANGUAGE_UNSUPPORTED"), { reason: detail, printer });
    }

    try {
      const result = await testNetworkPrinterConnectivity({
        ipAddress: printer.ipAddress,
        port: printer.port,
      });
      await prisma.printer.update({
        where: { id: printer.id },
        data: {
          lastValidatedAt: new Date(),
          lastValidationStatus: "READY",
          lastValidationMessage: `TCP connectivity validated in ${result.latencyMs}ms`,
        },
      });
    } catch (error: any) {
      const detail = error?.message || `Could not reach ${printer.ipAddress}:${printer.port}`;
      await prisma.printer.update({
        where: { id: printer.id },
        data: {
          lastValidatedAt: new Date(),
          lastValidationStatus: "OFFLINE",
          lastValidationMessage: detail,
        },
      });
      throw Object.assign(new Error("PRINTER_NETWORK_UNREACHABLE"), {
        reason: detail,
        printer,
      });
    }

    return {
      printer,
      printerStatus: null,
      printMode: PrintDispatchMode.NETWORK_DIRECT,
      payloadType: resolvePayloadType(printer as any),
    };
  }

  if (printer.connectionType === PrinterConnectionType.NETWORK_IPP) {
    if (printer.deliveryMode === PrinterDeliveryMode.SITE_GATEWAY) {
      if (!printer.gatewayId || !printer.gatewaySecretHash) {
        throw Object.assign(new Error("PRINTER_GATEWAY_CONFIG_INVALID"), { printer });
      }
      const lastSeenAt = printer.gatewayLastSeenAt ? new Date(printer.gatewayLastSeenAt) : null;
      const stale =
        !lastSeenAt ||
        Number.isNaN(lastSeenAt.getTime()) ||
        Date.now() - lastSeenAt.getTime() >
          (Math.max(10_000, Number(process.env.PRINT_GATEWAY_HEARTBEAT_TTL_MS || 45_000) || 45_000));
      if (stale) {
        throw Object.assign(new Error("PRINTER_GATEWAY_OFFLINE"), {
          reason: printer.gatewayLastError || "Site gateway is offline.",
          printer,
        });
      }
      return {
        printer,
        printerStatus: null,
        printMode: PrintDispatchMode.NETWORK_IPP,
        payloadType: PrintPayloadType.PDF,
      };
    }

    try {
      const inspection = await inspectIppPrinter({
        host: printer.host,
        port: printer.port,
        resourcePath: printer.resourcePath,
        tlsEnabled: printer.tlsEnabled,
        printerUri: printer.printerUri,
      });
      if (!inspection.pdfSupported) {
        const detail = `IPP endpoint ${inspection.printerUri} is reachable, but application/pdf is not advertised by the printer.`;
        await prisma.printer.update({
          where: { id: printer.id },
          data: {
            lastValidatedAt: new Date(),
            lastValidationStatus: "BLOCKED",
            lastValidationMessage: detail,
            printerUri: inspection.printerUri,
            capabilitySummary: {
              ...(printer.capabilitySummary as Record<string, unknown> | null),
              documentFormats: inspection.documentFormats,
              uriSecurity: inspection.uriSecurity,
              ippVersions: inspection.ippVersions,
              printerState: inspection.printerState,
            } as any,
          },
        });
        throw Object.assign(new Error("PRINTER_IPP_FORMAT_UNSUPPORTED"), { reason: detail, printer });
      }
      await prisma.printer.update({
        where: { id: printer.id },
        data: {
          lastValidatedAt: new Date(),
          lastValidationStatus: "READY",
          lastValidationMessage: `IPP printer validated at ${inspection.printerUri}`,
          printerUri: inspection.printerUri,
          capabilitySummary: {
            ...(printer.capabilitySummary as Record<string, unknown> | null),
            documentFormats: inspection.documentFormats,
            uriSecurity: inspection.uriSecurity,
            ippVersions: inspection.ippVersions,
            printerState: inspection.printerState,
          } as any,
        },
      });
      return {
        printer: {
          ...printer,
          printerUri: inspection.printerUri,
        },
        printerStatus: null,
        printMode: PrintDispatchMode.NETWORK_IPP,
        payloadType: PrintPayloadType.PDF,
      };
    } catch (error: any) {
      if (String(error?.message || "").includes("PRINTER_IPP_FORMAT_UNSUPPORTED")) {
        throw error;
      }
      const detail = error?.message || "IPP printer validation failed.";
      await prisma.printer.update({
        where: { id: printer.id },
        data: {
          lastValidatedAt: new Date(),
          lastValidationStatus: "OFFLINE",
          lastValidationMessage: detail,
        },
      });
      throw Object.assign(new Error("PRINTER_IPP_UNREACHABLE"), { reason: detail, printer });
    }
  }

  throw new Error("PRINTER_MODE_UNSUPPORTED");
};

export const notifySystemPrintEvent = async (params: {
  licenseeId?: string | null;
  orgId?: string | null;
  type: string;
  title: string;
  body: string;
  data?: any;
  channels?: NotificationChannel[];
}) => {
  const channels = params.channels && params.channels.length > 0 ? params.channels : [NotificationChannel.WEB];

  await Promise.allSettled([
    createRoleNotifications({
      audience: NotificationAudience.SUPER_ADMIN,
      type: params.type,
      title: params.title,
      body: params.body,
      licenseeId: params.licenseeId || null,
      orgId: params.orgId || null,
      data: params.data || null,
      channels,
    }),
    Promise.resolve([] as any[]),
    params.orgId
      ? createRoleNotifications({
          audience: NotificationAudience.MANUFACTURER,
          licenseeId: params.licenseeId || null,
          orgId: params.orgId,
          type: params.type,
          title: params.title,
          body: params.body,
          data: params.data || null,
          channels: [NotificationChannel.WEB],
        })
      : Promise.resolve([] as any[]),
  ]);
};

export const handleIdempotencyError = (error: unknown, res: Response) => {
  const message = String((error as any)?.message || "");
  if (message.includes("IDEMPOTENCY_KEY_REQUIRED")) {
    res.status(400).json({ success: false, error: "Missing x-idempotency-key header" });
    return true;
  }
  if (message.includes("IDEMPOTENCY_KEY_IN_PROGRESS")) {
    res.status(409).json({ success: false, error: "Request with this idempotency key is already in progress" });
    return true;
  }
  if (message.includes("IDEMPOTENCY_KEY_PAYLOAD_MISMATCH")) {
    res.status(409).json({ success: false, error: "Idempotency key was already used for a different payload" });
    return true;
  }
  return false;
};

export const beginPrintActionIdempotency = async (params: {
  req: AuthRequest;
  action: string;
  scope: string;
  payload?: any;
}) => {
  return beginIdempotentAction({
    action: params.action,
    scope: params.scope,
    idempotencyKey: extractIdempotencyKey(params.req.headers as any, params.req.body as any),
    requestPayload: params.payload ?? null,
    required: true,
  });
};

export const replayIdempotentResponseIfAny = (idempotency: IdempotencyBeginResult<any>, res: Response) => {
  if (!idempotency.replayed) return false;
  return res.status(idempotency.statusCode || 200).json(idempotency.responsePayload || { success: true });
};
