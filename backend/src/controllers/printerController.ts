import { randomBytes } from "crypto";
import { PrinterCommandLanguage, PrinterConnectionType, PrinterDeliveryMode, UserRole } from "@prisma/client";
import { Response } from "express";
import { z } from "zod";

import { AuthRequest } from "../middleware/auth";
import { getEffectiveLicenseeId } from "../middleware/tenantIsolation";
import {
  hashGatewaySecret,
} from "../services/printerRegistryService";
import { resolvePrinterConfirmationMode } from "../services/printConfirmationService";
import { buildPrinterTestLabelFingerprint } from "../services/printerTestLabelGateService";
import { printTestLabelForRegisteredPrinter } from "../services/printerTestLabelService";
import { sanitizePrinterActionError } from "../utils/printerUserFacingErrors";
import { createSensitiveActionApproval, SENSITIVE_ACTION_KEYS } from "../services/sensitiveActionApprovalService";
import {
  extractIdempotencyKey,
} from "../services/idempotencyService";
import { mapPrinterIdempotencyError } from "./printerIdempotencyResponse";
import {
  administerPrintingPrinter,
  beginPrintingIdempotency,
  completePrintingIdempotency,
  readPrintingProjection,
} from "../rls-waves/session-c/c02/printingLifecycleRepository";
import { testNetworkPrinterConnectivity } from "../services/networkPrinterSocketService";
import { inspectIppPrinter } from "../printing/ippClient";
import { supportsNetworkDirectPayload } from "../services/printPayloadService";

const NETWORK_DIRECT_LANGUAGE_OPTIONS = [
  PrinterCommandLanguage.ZPL,
  PrinterCommandLanguage.TSPL,
  PrinterCommandLanguage.SBPL,
  PrinterCommandLanguage.EPL,
  PrinterCommandLanguage.DPL,
  PrinterCommandLanguage.HONEYWELL_DP,
  PrinterCommandLanguage.HONEYWELL_FINGERPRINT,
  PrinterCommandLanguage.IPL,
  PrinterCommandLanguage.ZSIM,
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
  deliveryMode: z.enum([PrinterDeliveryMode.DIRECT, PrinterDeliveryMode.SITE_GATEWAY]).default(PrinterDeliveryMode.DIRECT),
  rotateGatewaySecret: z.boolean().optional(),
  capabilitySummary: z.record(z.any()).optional(),
  calibrationProfile: z.record(z.any()).optional(),
  isActive: z.boolean().optional(),
  isDefault: z.boolean().optional(),
}).strict();

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
}).strict();

const networkPrinterSchema = z.discriminatedUnion("connectionType", [networkDirectPrinterSchema, networkIppPrinterSchema]);
const networkPrinterUpdateSchema = z.union([
  networkDirectPrinterSchema.partial().extend({ connectionType: z.literal(PrinterConnectionType.NETWORK_DIRECT).optional() }),
  networkIppPrinterSchema.partial().extend({ connectionType: z.literal(PrinterConnectionType.NETWORK_IPP).optional() }),
]);

const printerIdParamSchema = z.object({
  id: z.string().uuid("Invalid printer id"),
}).strict();

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

export const canConfigurePrinterNetworkEndpoint = (role?: UserRole | null) =>
  Boolean(
    role &&
      ([
        UserRole.SUPER_ADMIN,
        UserRole.PLATFORM_SUPER_ADMIN,
        UserRole.LICENSEE_ADMIN,
      ] as UserRole[]).includes(role)
  );

const canManagePrinterProfiles = canConfigurePrinterNetworkEndpoint;

const printingRequestId = (req: AuthRequest) =>
  String((req as AuthRequest & { requestId?: string }).requestId || "").trim();

const printingCapability = (req: AuthRequest) =>
  String(req.databaseSessionCapability || "").trim();

const recordPrinterEvidence = (
  req: AuthRequest,
  printerId: string,
  operation: "AUDIT_TEST" | "AUDIT_TEST_LABEL_ATTENTION" | "AUDIT_TEST_LABEL_CONFIRMED" | "AUDIT_TEST_LABEL_QUEUED" | "AUDIT_DISCOVERY",
  evidence: Record<string, unknown>
) => administerPrintingPrinter({
  capability: printingCapability(req),
  requestId: printingRequestId(req),
  operation,
  printerId,
  payload: { evidence },
});

const resolveScope = (req: AuthRequest) => ({
  userId: req.user!.userId,
  orgId: req.user?.orgId || null,
  licenseeId: getEffectiveLicenseeId(req),
});

const validatePrinterTransport = async (req: AuthRequest, printer: any) => {
  let ok = false;
  let detail = "Printer is not ready.";
  let latencyMs: number | null = null;
  if (printer.connectionType === PrinterConnectionType.LOCAL_AGENT) {
    const status = await readPrintingProjection({
      capability: printingCapability(req),
      requestId: printingRequestId(req),
      operation: "PRINTER_STATUS",
      subjectId: req.user!.userId,
    });
    ok = Boolean(status?.trusted && status?.connected && status?.eligibleForPrinting);
    detail = ok ? "Trusted connector and selected printer are ready." : String(status?.error || "Trusted connector is not ready.");
  } else if (printer.deliveryMode === PrinterDeliveryMode.SITE_GATEWAY) {
    const lastSeen = printer.gatewayLastSeenAt ? new Date(printer.gatewayLastSeenAt).getTime() : NaN;
    ok = printer.gatewayStatus === "ONLINE" && Number.isFinite(lastSeen) && Date.now() - lastSeen < 120_000;
    detail = ok ? "Site gateway is online." : String(printer.gatewayLastError || "Site gateway is offline.");
  } else if (printer.connectionType === PrinterConnectionType.NETWORK_DIRECT) {
    const result = await testNetworkPrinterConnectivity({
      ipAddress: String(printer.ipAddress || ""),
      port: Number(printer.port || 9100),
    });
    latencyMs = result.latencyMs;
    ok = supportsNetworkDirectPayload(printer);
    detail = ok
      ? `TCP connectivity validated in ${result.latencyMs}ms.`
      : "Printer language/profile is not certified for direct dispatch.";
  } else {
    const result = await inspectIppPrinter({
      host: printer.host,
      port: printer.port,
      resourcePath: printer.resourcePath,
      tlsEnabled: printer.tlsEnabled,
      printerUri: printer.printerUri,
    });
    ok = result.pdfSupported;
    detail = ok
      ? `IPP attributes validated at ${result.printerUri}.`
      : "IPP endpoint does not advertise application/pdf.";
  }
  await administerPrintingPrinter({
    capability: printingCapability(req),
    requestId: printingRequestId(req),
    operation: "UPDATE",
    printerId: printer.id,
    payload: { lastValidationStatus: ok ? "READY" : "BLOCKED", lastValidationMessage: detail },
  });
  return {
    ok,
    ...(latencyMs === null ? {} : { latencyMs }),
    registryStatus: { state: ok ? "READY" : "BLOCKED", summary: detail, detail },
  };
};

export const listPrinters = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user || !isOpsRole(req.user.role)) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const includeInactive = String(req.query.includeInactive || "").trim().toLowerCase() === "true";
    const rows = await readPrintingProjection({
      capability: printingCapability(req),
      requestId: printingRequestId(req),
      operation: "PRINTER_LIST",
      subjectId: req.user.userId,
      options: { includeInactive },
    });

    return res.json({ success: true, data: rows });
  } catch (error: any) {
    console.error("listPrinters error:", error);
    return res.status(500).json({ success: false, error: "Printer information is temporarily unavailable." });
  }
};

export const createNetworkPrinter = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user || !canManagePrinterProfiles(req.user.role)) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const parsed = networkPrinterSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid printer payload" });
    }

    const licenseeId = getEffectiveLicenseeId(req);
    if (!licenseeId) {
      return res.status(400).json({ success: false, error: "licenseeId is required to register a network printer" });
    }
    const gatewayProvisioningSecret =
      parsed.data.deliveryMode === PrinterDeliveryMode.SITE_GATEWAY
        ? randomBytes(24).toString("base64url")
        : null;
    const printer = await administerPrintingPrinter({
      capability: printingCapability(req),
      requestId: printingRequestId(req),
      operation: "CREATE",
      payload: {
        ...parsed.data,
        licenseeId,
        gatewayId: gatewayProvisioningSecret ? `gw-${randomBytes(9).toString("hex")}` : null,
        gatewaySecretHash: gatewayProvisioningSecret ? hashGatewaySecret(gatewayProvisioningSecret) : null,
      },
    });

    return res.status(201).json({
      success: true,
      data: {
        ...printer,
        gatewayProvisioningSecret,
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
    if (!req.user || !canManagePrinterProfiles(req.user.role)) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const paramsParsed = printerIdParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) {
      return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Invalid printer id" });
    }
    const printerId = paramsParsed.data.id;

    const parsed = networkPrinterUpdateSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid printer payload" });
    }

    const current = await readPrintingProjection({
      capability: printingCapability(req),
      requestId: printingRequestId(req),
      operation: "PRINTER",
      subjectId: printerId,
    });
    if (!current) return res.status(404).json({ success: false, error: "Printer not found" });
    if (current.connectionType === PrinterConnectionType.LOCAL_AGENT) {
      return res.status(400).json({ success: false, error: "Local-agent printers are managed automatically from the workstation agent." });
    }

    const connectionType = parsed.data.connectionType || current.connectionType;
    const upsertPayload = { ...parsed.data, connectionType };

    if ("rotateGatewaySecret" in parsed.data && parsed.data.rotateGatewaySecret) {
      const approval = await createSensitiveActionApproval({
        actionKey: SENSITIVE_ACTION_KEYS.PRINTER_GATEWAY_SECRET_ROTATION,
        actor: {
          userId: req.user.userId,
          role: req.user.role,
          orgId: req.user.orgId || null,
          licenseeId: req.user.licenseeId || null,
        },
        orgId: req.user.orgId || null,
        licenseeId: getEffectiveLicenseeId(req) || current.licenseeId || null,
        entityType: "Printer",
        entityId: printerId,
        summary: {
          name: upsertPayload.name,
          connectionType: upsertPayload.connectionType,
          deliveryMode: upsertPayload.deliveryMode,
          rotateGatewaySecret: true,
        },
        payload: upsertPayload,
        ipAddress: req.ip,
        userAgent: req.get("user-agent") || null,
        securityContext: {
          databaseSessionCapability: printingCapability(req),
          requestId: printingRequestId(req),
        },
      });

      return res.status(202).json({
        success: true,
        data: {
          approvalRequired: true,
          approvalId: approval.id,
          status: approval.status,
          expiresAt: approval.expiresAt,
        },
      });
    }

    const printer = await administerPrintingPrinter({
      capability: printingCapability(req),
      requestId: printingRequestId(req),
      operation: "UPDATE",
      printerId,
      payload: upsertPayload,
    });

    return res.json({
      success: true,
      data: {
        ...printer,
        gatewayProvisioningSecret: null,
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
    if (!req.user || !canManagePrinterProfiles(req.user.role)) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const paramsParsed = printerIdParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) {
      return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Invalid printer id" });
    }
    const printerId = paramsParsed.data.id;

    const printer = await readPrintingProjection({
      capability: printingCapability(req),
      requestId: printingRequestId(req),
      operation: "PRINTER",
      subjectId: printerId,
    });
    if (!printer) return res.status(404).json({ success: false, error: "Printer not found" });

    const result = await validatePrinterTransport(req, printer);

    await recordPrinterEvidence(req, printer.id, "AUDIT_TEST", {
        connectionType: printer.connectionType,
        result,
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

export const testPrinterLabel = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user || !isOpsRole(req.user.role)) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const paramsParsed = printerIdParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) {
      return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Invalid printer id" });
    }
    const printerId = paramsParsed.data.id;

    const scope = resolveScope(req);
    let idempotency;
    try {
      const key = String(extractIdempotencyKey(req.headers as any, req.body as any) || "").trim();
      if (!key) throw new Error("IDEMPOTENCY_KEY_REQUIRED");
      const context = {
        capability: printingCapability(req),
        requestId: printingRequestId(req),
        action: "PRINTER_TEST_LABEL" as const,
        actorScope: `tenant:${scope.licenseeId || scope.orgId || "none"}:user:${scope.userId}:printer:${printerId}`,
        key,
        payload: { printerId },
      };
      idempotency = { ...(await beginPrintingIdempotency(context)), context };
    } catch (error) {
      const mapped = mapPrinterIdempotencyError(error);
      if (mapped) return res.status(mapped.status).json(mapped.payload);
      throw error;
    }

    if (idempotency.replayed) {
      return res.status(idempotency.statusCode || 200).json(idempotency.responsePayload || { success: true });
    }

    const printer = await readPrintingProjection({
      capability: printingCapability(req),
      requestId: printingRequestId(req),
      operation: "PRINTER",
      subjectId: printerId,
    });
    if (!printer) return res.status(404).json({ success: false, error: "Printer not found" });

    const confirmationMode = resolvePrinterConfirmationMode(printer as any);
    const validation = await validatePrinterTransport(req, printer);

    if (!validation.ok) {
      const data = {
        outcome: "needs_attention" as const,
        message: sanitizePrinterActionError(
          validation.registryStatus?.detail || validation.registryStatus?.summary,
          "This printer route still needs attention before a live test label can run."
        ),
        confirmationMode,
        connectionType: printer.connectionType,
        deliveryMode: printer.deliveryMode || PrinterDeliveryMode.DIRECT,
        payloadType: null,
        deviceJobRef: null,
        dispatchedAt: null,
        confirmedAt: null,
      };

      await recordPrinterEvidence(req, printer.id, "AUDIT_TEST_LABEL_ATTENTION", {
          connectionType: printer.connectionType,
          deliveryMode: printer.deliveryMode,
          confirmationMode,
          validation,
          result: data,
      });

      const responsePayload = { success: true, data };
      await completePrintingIdempotency({ ...idempotency.context, statusCode: 200, responsePayload });
      return res.json(responsePayload);
    }

    try {
      const result = await printTestLabelForRegisteredPrinter({
        printer: printer as any,
        actorUserId: scope.userId,
        boundary: {
          capability: printingCapability(req),
          requestId: printingRequestId(req),
        },
      });
      if (result.outcome === "confirmed") {
        const metadata = printer.metadata && typeof printer.metadata === "object" && !Array.isArray(printer.metadata)
          ? printer.metadata
          : {};
        await administerPrintingPrinter({
          capability: printingCapability(req),
          requestId: printingRequestId(req),
          operation: "UPDATE",
          printerId: printer.id,
          payload: {
            metadata: {
              ...metadata,
              lastTestLabelConfirmedAt: result.confirmedAt,
              lastTestLabelConnectionType: result.connectionType,
              lastTestLabelDeviceJobRef: result.deviceJobRef || null,
              lastTestLabelFingerprint: buildPrinterTestLabelFingerprint(printer),
            },
          },
        });
      }

      if (!(printer.connectionType === PrinterConnectionType.LOCAL_AGENT && result.outcome === "queued")) {
        await recordPrinterEvidence(
          req,
          printer.id,
          result.outcome === "confirmed" ? "AUDIT_TEST_LABEL_CONFIRMED" : "AUDIT_TEST_LABEL_QUEUED",
          {
          connectionType: printer.connectionType,
          deliveryMode: printer.deliveryMode,
          validation,
          result,
          }
        );
      }

      const responsePayload = { success: true, data: result };
      await completePrintingIdempotency({ ...idempotency.context, statusCode: 200, responsePayload });
      return res.json(responsePayload);
    } catch (error: any) {
      const data = {
        outcome: "needs_attention" as const,
        message: sanitizePrinterActionError(error?.message, "The live printer test could not complete right now."),
        confirmationMode,
        connectionType: printer.connectionType,
        deliveryMode: printer.deliveryMode || PrinterDeliveryMode.DIRECT,
        payloadType: null,
        deviceJobRef: null,
        dispatchedAt: null,
        confirmedAt: null,
      };

      await recordPrinterEvidence(req, printer.id, "AUDIT_TEST_LABEL_ATTENTION", {
          connectionType: printer.connectionType,
          deliveryMode: printer.deliveryMode,
          confirmationMode,
          validation,
          error: error?.message || null,
          result: data,
      });

      const responsePayload = { success: true, data };
      await completePrintingIdempotency({ ...idempotency.context, statusCode: 200, responsePayload });
      return res.json(responsePayload);
    }
  } catch (error: any) {
    console.error("testPrinterLabel error:", error);
    return res.status(400).json({
      success: false,
      error: sanitizePrinterActionError(error?.message, "This live printer test could not start right now."),
    });
  }
};

export const discoverPrinter = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user || !canManagePrinterProfiles(req.user.role)) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const paramsParsed = printerIdParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) {
      return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Invalid printer id" });
    }
    const printerId = paramsParsed.data.id;

    const printer = await readPrintingProjection({
      capability: printingCapability(req),
      requestId: printingRequestId(req),
      operation: "PRINTER",
      subjectId: printerId,
    });
    if (!printer) return res.status(404).json({ success: false, error: "Printer not found" });

    if (printer.connectionType === PrinterConnectionType.LOCAL_AGENT) {
      return res.status(400).json({
        success: false,
        error: "Connector-managed workstation printers refresh their capabilities automatically. Open the standard Printer Setup flow instead of running manual certification here.",
      });
    }

    const validation = await validatePrinterTransport(req, printer);
    const certification = {
      printerId: printer.id,
      printerProfileId: null,
      status: validation.ok ? "CERTIFIED" : "NEEDS_REVIEW",
      summary: validation.ok
        ? "Printer transport discovered and certified."
        : "Printer transport needs review before production print.",
      warnings: validation.ok ? [] : [validation.registryStatus.detail],
      mismatches: validation.ok ? [] : [validation.registryStatus.detail],
      lastVerifiedAt: new Date().toISOString(),
    };

    await recordPrinterEvidence(req, printer.id, "AUDIT_DISCOVERY", {
        connectionType: printer.connectionType,
        commandLanguage: printer.commandLanguage,
        validation,
        certification,
    });

    return res.json({
      success: true,
      data: {
        validation,
        certification,
      },
    });
  } catch (error: any) {
    console.error("discoverPrinter error:", error);
    return res.status(400).json({
      success: false,
      error: sanitizePrinterActionError(error?.message, "This printer could not complete discovery and certification."),
    });
  }
};

export const deleteNetworkPrinter = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user || !canManagePrinterProfiles(req.user.role)) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const paramsParsed = printerIdParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) {
      return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Invalid printer id" });
    }
    const printerId = paramsParsed.data.id;

    const printer = await readPrintingProjection({
      capability: printingCapability(req),
      requestId: printingRequestId(req),
      operation: "PRINTER",
      subjectId: printerId,
    });
    if (!printer) return res.status(404).json({ success: false, error: "Printer not found" });
    if (printer.connectionType === PrinterConnectionType.LOCAL_AGENT) {
      return res.status(400).json({ success: false, error: "Local-agent printers are managed automatically from the workstation agent." });
    }

    const deletedPrinter = await administerPrintingPrinter({
      capability: printingCapability(req),
      requestId: printingRequestId(req),
      operation: "DELETE",
      printerId: printer.id,
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
