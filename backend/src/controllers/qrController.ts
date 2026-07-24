//File: backend/src/controllers/qrController.ts  
import { Response } from "express";
import { mkdtemp, open, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import { Prisma, QRStatus, UserRole } from "@prisma/client";
import prisma from "../config/database";
import { AuthRequest } from "../middleware/auth";
import { createAuditLog } from "../services/auditService";
import { getQrTokenExpiryDate, hashToken, randomNonce, signQrPayload } from "../services/qrTokenService";
import { createUserNotification } from "../services/notificationService";
import { buildLineageSuccessMessage } from "../services/batchAllocationService";
import { buildScopedWhere, findScopedBatch } from "../services/accessControlService";
import { listScopedBatchReadPayload } from "../services/stagingRlsBatchReadService";
import { getScopedBatchAllocationMapPayload } from "../services/stagingRlsBatchAllocationMapService";
import { resolveScopedLicenseeAccess } from "../services/manufacturerScopeService";
import { summarizeQrStatusCounts } from "../services/qrStatusMetrics";
import { createSensitiveActionApproval, SENSITIVE_ACTION_KEYS } from "../services/sensitiveActionApprovalService";
import { listLatestDecisionByQrCodeIds } from "../services/verificationDecisionReadService";
import { recordBreakGlassIssuanceMetric } from "../observability/verificationTrustMetrics";
import { getBatchReleaseApprovalContext, releaseBatchForSupplyChain, requestOrApproveBatchRelease } from "../services/batchReleaseService";
import {
  formatPrintValidationEvidenceMarkdown,
  generatePrintValidationEvidenceReport,
} from "../services/printValidationEvidenceService";
import {
  allocateRange as allocateQrRangeBoundary,
  bindBreakGlassTokens,
  deleteCodes as deleteQrCodesBoundary,
  getCodeScope,
  isQrBoundaryDenied,
  mutateBatch as mutateQrBatch,
  readCodes as readQrCodesBoundary,
  readStats as readQrStatsBoundary,
  visitQrCodePages,
  withQrBoundaryTransaction,
} from "../rls-waves/session-c/c01/qrSystemRepository";
import { b03BoundaryForRequest } from "../rls-waves/session-b/b03/requestBoundary";

/* ===================== SCHEMAS ===================== */

const allocateRangeSchema = z
  .object({
    licenseeId: z.string().uuid(),
    startNumber: z.number().int().positive(),
    endNumber: z.number().int().positive(),
    receivedBatchName: z.string().trim().min(2).max(120).optional(),
  })
  .strict()
  .refine((d) => d.endNumber >= d.startNumber, {
    message: "End number must be >= start number",
  });

const allocateLicenseeTopupSchema = z
  .object({
    startNumber: z.number().int().positive().optional(),
    endNumber: z.number().int().positive().optional(),
    quantity: z.number().int().positive().max(500000).optional(),
    receivedBatchName: z.string().trim().min(2).max(120).optional(),
  })
  .strict()
  .refine(
    (d) => {
      const hasRange = d.startNumber != null || d.endNumber != null;
      const hasQuantity = d.quantity != null;
      if (hasRange && hasQuantity) return false;
      if (!hasRange && !hasQuantity) return false;
      if (hasRange && (d.startNumber == null || d.endNumber == null)) return false;
      return true;
    },
    { message: "Provide either quantity or both startNumber and endNumber." }
  )
  .refine((d) => (d.startNumber != null && d.endNumber != null ? d.endNumber >= d.startNumber : true), {
    message: "End number must be >= start number",
  });

const isScopeError = (error: unknown) =>
  (
    (error as any)?.code === "P2010" &&
    (error as any)?.meta?.code === "42501" &&
    String((error as any)?.meta?.message || "").trim() === "ERROR: PRINTING_BOUNDARY_DENIED"
  ) ||
  (error instanceof Error &&
    /access denied|no licensee association|AUTH_SESSION_CAPABILITY_DENIED/i.test(error.message));

const createBatchSchema = z
  .object({
    name: z.string().trim().min(2).max(120),
    quantity: z.number().int().positive().max(500000),
    manufacturerId: z.string().uuid().optional(),
  })
  .strict();

const assignManufacturerSchema = z.object({
  manufacturerId: z.string().uuid(),
  quantity: z.number().int().positive().max(500000),
  name: z.string().trim().min(2).max(120).optional(),
}).strict();

const renameBatchSchema = z.object({
  name: z.string().trim().min(2).max(120),
}).strict();

const bulkDeleteQRCodesSchema = z
  .object({
    ids: z.array(z.string().uuid()).optional(),
    codes: z.array(z.string().min(1)).optional(),
  })
  .strict()
  .refine((d) => (d.ids && d.ids.length) || (d.codes && d.codes.length), {
    message: "Provide ids or codes to delete",
  });

const bulkDeleteBatchesSchema = z.object({
  ids: z.array(z.string().uuid()).min(1, "Provide batch ids"),
}).strict();

const generateQRCodesSchema = z.object({
  licenseeId: z.string().uuid(),
  quantity: z.number().int().positive().max(200000),
}).strict();

const generateSignedLinksSchema = z.object({
  codes: z.array(z.string().trim().min(2).max(128)).min(1).max(2000),
});

const blockQRSschema = z.object({
  reason: z.string().trim().max(500).optional(),
}).strict();

const batchIdParamSchema = z.object({
  id: z.string().uuid("Invalid batch id"),
}).strict();

const qrCodeIdParamSchema = z.object({
  id: z.string().uuid("Invalid QR id"),
}).strict();

const licenseeIdParamSchema = z.object({
  licenseeId: z.string().uuid("Invalid licensee id"),
}).strict();

/* ===================== HELPERS ===================== */

const ensureAuth = (req: AuthRequest) => {
  const role = req.user?.role;
  const userId = req.user?.userId;
  if (!role || !userId) return null;
  return { role, userId };
};

const qrRequestId = (req: AuthRequest) =>
  String((req as AuthRequest & { requestId?: string }).requestId || "").trim();

const isManufacturerRole = (role?: UserRole | null) =>
  role === UserRole.MANUFACTURER ||
  role === UserRole.MANUFACTURER_ADMIN ||
  role === UserRole.MANUFACTURER_USER;

const escapeCsv = (v: any) => {
  if (v === null || v === undefined) return "";
  const s = String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};

const isBatchBusyError = (msg: string) =>
  msg.includes("BATCH_BUSY") || msg.toLowerCase().includes("concurrency issue");

const parsePositiveIntEnv = (name: string, fallback: number) => {
  const raw = Number(String(process.env[name] || "").trim());
  return Number.isFinite(raw) && raw > 0 ? Math.floor(raw) : fallback;
};

const parseBooleanEnv = (name: string, fallback = false) => {
  const normalized = String(process.env[name] || "").trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
};

const ALLOCATION_TX_TIMEOUT_MS = parsePositiveIntEnv("ALLOCATION_TX_TIMEOUT_MS", 120000);
const ALLOCATION_TX_MAX_WAIT_MS = parsePositiveIntEnv("ALLOCATION_TX_MAX_WAIT_MS", 15000);
const BREAK_GLASS_QR_GENERATE_ENABLED = parseBooleanEnv("ALLOW_BREAK_GLASS_QR_GENERATE", false);

/* ===================== QR RANGE (SUPER ADMIN route) ===================== */

export const allocateQRRange = async (req: AuthRequest, res: Response) => {
  try {
    const auth = ensureAuth(req);
    if (!auth) return res.status(401).json({ success: false, error: "Not authenticated" });

    const parsed = allocateRangeSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const { licenseeId, startNumber, endNumber, receivedBatchName } = parsed.data;

    const result = await allocateQrRangeBoundary<any>({
      capability: String(req.databaseSessionCapability || ""), requestId: qrRequestId(req),
      licenseeId, startNumber, endNumber, receivedBatchName: receivedBatchName || null, source: "ADMIN_TOPUP",
    });

    return res.status(201).json({
      success: true,
      data: {
        range: result.range,
        startCode: result.startCode,
        endCode: result.endCode,
        totalCodes: result.totalCodes,
        receivedBatchId: result.receivedBatchId || null,
        receivedBatchName: result.receivedBatchName || null,
      },
    });
  } catch (e) {
    console.error("allocateQRRange error:", e);
    const msg = (e as any)?.message || "Internal server error";
    if (isBatchBusyError(msg)) {
      return res.status(409).json({ success: false, error: "Please retry — batch busy." });
    }
    return res.status(400).json({ success: false, error: msg });
  }
};

/* ===================== QR RANGE (SUPER ADMIN, by licensee) ===================== */

export const allocateQRRangeForLicensee = async (req: AuthRequest, res: Response) => {
  try {
    const auth = ensureAuth(req);
    if (!auth) return res.status(401).json({ success: false, error: "Not authenticated" });

    const paramsParsed = licenseeIdParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) {
      return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Invalid licenseeId" });
    }
    const { licenseeId } = paramsParsed.data;

    const parsed = allocateLicenseeTopupSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const startNumber = parsed.data.quantity != null ? 0 : parsed.data.startNumber as number;
    const endNumber = parsed.data.quantity != null ? parsed.data.quantity : parsed.data.endNumber as number;
    const allocation = await allocateQrRangeBoundary<any>({
      capability: String(req.databaseSessionCapability || ""), requestId: qrRequestId(req), licenseeId,
      startNumber, endNumber, receivedBatchName: parsed.data.receivedBatchName || null, source: "ADMIN_TOPUP",
    });

    return res.status(201).json({
      success: true,
      data: {
        range: allocation.range,
        startCode: allocation.startCode,
        endCode: allocation.endCode,
        startNumber: Number(String(allocation.startCode).slice(-10)),
        endNumber: Number(String(allocation.endCode).slice(-10)),
        totalCodes: allocation.totalCodes,
        receivedBatchId: allocation.receivedBatchId || null,
        receivedBatchName: allocation.receivedBatchName || null,
      },
    });
  } catch (e: any) {
    console.error("allocateQRRangeForLicensee error:", e);
    const msg = e?.message || "Bad request";
    if (isBatchBusyError(msg)) {
      return res.status(409).json({ success: false, error: "Please retry — batch busy." });
    }
    return res.status(400).json({ success: false, error: msg });
  }
};

/* ===================== QR CODES DELETE ===================== */

export const bulkDeleteQRCodes = async (req: AuthRequest, res: Response) => {
  try {
    const auth = ensureAuth(req);
    if (!auth) return res.status(401).json({ success: false, error: "Not authenticated" });
    if (!["SUPER_ADMIN","PLATFORM_SUPER_ADMIN","LICENSEE_ADMIN"].includes(auth.role)) {
      return res.status(403).json({ success:false,error:"Access denied" });
    }

    const parsed = bulkDeleteQRCodesSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const deleted = await deleteQrCodesBoundary({
      capability: String(req.databaseSessionCapability || ""), requestId: qrRequestId(req),
      ids: parsed.data.ids, codes: parsed.data.codes,
    });
    return res.json({ success: true, data: { deleted } });
  } catch (e: any) {
    console.error("bulkDeleteQRCodes error:", e);
    return res.status(500).json({ success: false, error: e.message || "Internal server error" });
  }
};

/* ===================== BATCH (LICENSEE ADMIN) ===================== */

export const createBatch = async (req: AuthRequest, res: Response) => {
  try {
    const auth = ensureAuth(req);
    if (!auth) return res.status(401).json({ success: false, error: "Not authenticated" });

    const parsed = createBatchSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const { name, quantity, manufacturerId } = parsed.data;
    const batch = await mutateQrBatch<Record<string, unknown>>({
      capability: String(req.databaseSessionCapability || ""),
      requestId: qrRequestId(req),
      operation: "CREATE_BATCH",
      payload: { name, quantity, manufacturerId: manufacturerId || null },
    });
    return res.status(201).json({ success: true, data: batch });
  } catch (e: any) {
    const msg = e?.message || "Internal server error";
    console.error("createBatch error:", e);
    if (isBatchBusyError(msg)) {
      return res.status(409).json({ success: false, error: "Please retry — batch busy." });
    }
    return res.status(400).json({ success: false, error: msg });
  }
};

/* ===================== BATCH (SUPER ADMIN) ===================== */

export const adminAllocateBatch = async (req: AuthRequest, res: Response) => {
  if (req.user?.role !== UserRole.SUPER_ADMIN && req.user?.role !== UserRole.PLATFORM_SUPER_ADMIN) {
    return res.status(403).json({ success: false, error: "Access denied" });
  }

  return res.status(403).json({
    success: false,
    error:
      "Direct super admin allocation to manufacturer is disabled. Allocate dormant pool to licensee only; licensee admin must assign batches to manufacturers.",
  });
};

/* ===================== DELETE ONE BATCH ===================== */

export const deleteBatch = async (req: AuthRequest, res: Response) => {
  try {
    if (!ensureAuth(req)) return res.status(401).json({ success: false, error: "Not authenticated" });

    const paramsParsed = batchIdParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) {
      return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Invalid batch id" });
    }
    const result = await mutateQrBatch<Record<string, unknown>>({
      capability: String(req.databaseSessionCapability || ""),
      requestId: qrRequestId(req),
      operation: "DELETE_BATCH",
      payload: { batchId: paramsParsed.data.id },
    });
    return res.json({ success: true, data: result });
  } catch (e) {
    console.error("deleteBatch error:", e);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

/* ===================== BULK DELETE BATCHES ===================== */

export const bulkDeleteBatches = async (req: AuthRequest, res: Response) => {
  try {
    if (!ensureAuth(req)) return res.status(401).json({ success: false, error: "Not authenticated" });

    const parsed = bulkDeleteBatchesSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const txResult = await mutateQrBatch<Record<string, unknown>>({
      capability: String(req.databaseSessionCapability || ""),
      requestId: qrRequestId(req),
      operation: "BULK_DELETE_BATCHES",
      payload: { batchIds: parsed.data.ids },
    });
    return res.json({ success: true, data: txResult });
  } catch (e) {
    console.error("bulkDeleteBatches error:", e);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

/* ===================== MANUFACTURER ASSIGN ===================== */

export const assignManufacturer = async (req: AuthRequest, res: Response) => {
  try {
    const auth = ensureAuth(req);
    if (!auth) return res.status(401).json({ success: false, error: "Not authenticated" });

    const parsed = assignManufacturerSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const paramsParsed = batchIdParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) {
      return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Invalid batch id" });
    }
    const batchId = paramsParsed.data.id;

    const result = await mutateQrBatch<{
      newBatchId: string;
      newBatchName: string;
      allocated: number;
      sourceBatchId: string;
      sourceBatchName: string;
      sourceRemainingCodes: number;
      manufacturerId: string;
      licenseeId: string;
    }>({
      capability: String(req.databaseSessionCapability || ""),
      requestId: qrRequestId(req),
      operation: "ASSIGN_MANUFACTURER",
      payload: { batchId, ...parsed.data },
    });

    try {
      await createUserNotification({
        databaseBoundary: b03BoundaryForRequest(req, "notification-write"),
        userId: result.manufacturerId,
        licenseeId: result.licenseeId,
        type: "manufacturer_batch_assigned",
        title: "New batch assigned",
        body: `${result.newBatchName} is ready for printing (${result.allocated} codes).`,
        data: {
          batchId: result.newBatchId,
          batchName: result.newBatchName,
          quantity: result.allocated,
          targetRoute: "/batches",
        },
      });
    } catch (notifyError) {
      console.error("assignManufacturer notification error:", notifyError);
    }

    return res.json({
      success: true,
      data: {
        ...result,
        message: buildLineageSuccessMessage({
          sourceBatchName: result.sourceBatchName,
          sourceBatchId: result.sourceBatchId,
          allocatedBatchName: result.newBatchName,
          allocatedBatchId: result.newBatchId,
          sourceRemainingCodes: result.sourceRemainingCodes,
        }),
      },
    });
  } catch (e) {
    console.error("assignManufacturer error:", e);
    const msg = (e as any)?.message || "Internal server error";
    if (isBatchBusyError(msg)) {
      return res.status(409).json({ success: false, error: "Please retry — batch busy." });
    }
    return res.status(400).json({ success: false, error: msg });
  }
};

export const renameBatch = async (req: AuthRequest, res: Response) => {
  try {
    const auth = ensureAuth(req);
    if (!auth) return res.status(401).json({ success: false, error: "Not authenticated" });

    if (
      auth.role === UserRole.MANUFACTURER ||
      auth.role === UserRole.MANUFACTURER_ADMIN ||
      auth.role === UserRole.MANUFACTURER_USER
    ) {
      return res.status(403).json({ success: false, error: "Manufacturers cannot rename batches" });
    }

    const parsed = renameBatchSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const paramsParsed = batchIdParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) {
      return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Invalid batch id" });
    }
    const batchId = paramsParsed.data.id;

    const existing = await findScopedBatch(req.user!, batchId, {
      select: { id: true, name: true, licenseeId: true },
    });
    if (!existing) return res.status(404).json({ success: false, error: "Batch not found" });

    const nextName = parsed.data.name.trim();
    if (nextName === existing.name) {
      return res.json({ success: true, data: existing });
    }

    const updated = await prisma.batch.update({
      where: { id: existing.id },
      data: { name: nextName },
    });

    await createAuditLog({
      userId: auth.userId,
      licenseeId: existing.licenseeId,
      action: "RENAME_BATCH",
      entityType: "Batch",
      entityId: existing.id,
      details: { from: existing.name, to: nextName },
      ipAddress: req.ip,
    });

    return res.json({ success: true, data: updated });
  } catch (e: any) {
    console.error("renameBatch error:", e);
    return res.status(500).json({ success: false, error: e?.message || "Internal server error" });
  }
};

/* ===================== PRINT ===================== */

export const markPrinted = async (req: AuthRequest, res: Response) => {
  return res.status(410).json({
    success: false,
    error:
      "Legacy manual print confirmation is retired. Start a controlled MSCQR print job and let the printer helper or registered printer confirm completion.",
  });
};

export const confirmBatchPrint = async (req: AuthRequest, res: Response) => {
  return res.status(410).json({
    success: false,
    error:
      "Legacy batch print confirmation is retired. Use the managed MSCQR print workflow so printed labels are confirmed through the print job lifecycle.",
  });
};

/* ===================== MANUFACTURER PRINT PACK (BATCH) ===================== */

export const createBatchPrintToken = async (req: AuthRequest, res: Response) => {
  return res.status(410).json({
    success: false,
    error:
      "Legacy batch print packs are retired. Start a controlled MSCQR print job to generate printable labels through the managed print pipeline.",
  });
};

export const downloadBatchPrintPack = async (req: AuthRequest, res: Response) => {
  return res.status(410).json({
    success: false,
    error:
      "Legacy downloadable print packs are retired. Use the managed MSCQR print pipeline so issued labels stay tied to authoritative print state.",
  });
};

/* ===================== ADMIN GENERATE SIGNED QRS ===================== */

export const generateQRCodes = async (req: AuthRequest, res: Response) => {
  try {
    if (req.user?.role !== UserRole.SUPER_ADMIN && req.user?.role !== UserRole.PLATFORM_SUPER_ADMIN) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    if (process.env.NODE_ENV === "production" && !BREAK_GLASS_QR_GENERATE_ENABLED) {
      return res.status(403).json({
        success: false,
        error:
          "Direct signed QR generation is disabled in production. Use the managed MSCQR print workflow so customer-verifiable labels remain tied to governed issuance and confirmed print state.",
      });
    }

    const parsed = generateQRCodesSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const { licenseeId, quantity } = parsed.data;

    const { allocation, tokens } = await withQrBoundaryTransaction(async (tx) => {
      const allocation = await allocateQrRangeBoundary<any>({
        capability: String(req.databaseSessionCapability || ""), requestId: qrRequestId(req),
        licenseeId, startNumber: 0, endNumber: quantity, source: "ADMIN_GENERATE",
      }, tx);
      const rows = Array.isArray(allocation.codes) ? allocation.codes : [];
      const now = new Date();
      const expAt = getQrTokenExpiryDate(now);
      const tokens: { qrId: string; token: string }[] = [];
      const bindings: Array<{ id: string; nonce: string; hash: string; issuedAt: Date; expiresAt: Date }> = [];
      for (const qr of rows) {
        const nonce = qr.tokenNonce || randomNonce();
        const payload = {
          qr_id: qr.id, batch_id: qr.batchId ?? null, licensee_id: qr.licenseeId,
          manufacturer_id: null, epoch: Number(qr.replayEpoch || 1),
          iat: Math.floor(now.getTime() / 1000), exp: Math.floor(expAt.getTime() / 1000), nonce,
        };
        const token = signQrPayload(payload);
        tokens.push({ qrId: qr.id, token });
        bindings.push({ id: qr.id, nonce, hash: hashToken(token), issuedAt: now, expiresAt: expAt });
      }
      await bindBreakGlassTokens({
        capability: String(req.databaseSessionCapability || ""), requestId: qrRequestId(req), licenseeId, tokens: bindings,
      }, tx);
      return { allocation, tokens };
    }, { timeout:ALLOCATION_TX_TIMEOUT_MS,maxWait:ALLOCATION_TX_MAX_WAIT_MS });
    recordBreakGlassIssuanceMetric({
      licenseeId,
      quantity,
      actorUserId: req.user.userId,
    });

    return res.status(201).json({
      success: true,
      data: {
        range: allocation.range,
        receivedBatch: allocation.receivedBatchId
          ? { id: allocation.receivedBatchId, name: allocation.receivedBatchName }
          : null,
        tokens,
      },
    });
  } catch (e: any) {
    console.error("generateQRCodes error:", e);
    const msg = e?.message || "Bad request";
    if (isBatchBusyError(msg)) {
      return res.status(409).json({ success: false, error: "Please retry — batch busy." });
    }
    return res.status(400).json({ success: false, error: msg });
  }
};

/* ===================== ADMIN BLOCK ===================== */

export const blockQRCode = async (req: AuthRequest, res: Response) => {
  try {
    if (req.user?.role !== UserRole.SUPER_ADMIN && req.user?.role !== UserRole.PLATFORM_SUPER_ADMIN) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const parsed = blockQRSschema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const paramsParsed = qrCodeIdParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) {
      return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Invalid QR id" });
    }
    const id = paramsParsed.data.id;
    const qr = await getCodeScope<{ id: string; licenseeId: string; batchId: string | null }>({
      capability: String(req.databaseSessionCapability || ""), requestId: qrRequestId(req), qrId: id,
    });
    if (!qr) {
      return res.status(404).json({ success: false, error: "QR code not found" });
    }

    const approval = await createSensitiveActionApproval({
      actionKey: SENSITIVE_ACTION_KEYS.QR_BLOCK,
      actor: {
        userId: req.user.userId,
        role: req.user.role,
        orgId: req.user.orgId || null,
        licenseeId: req.user.licenseeId || null,
      },
      licenseeId: qr.licenseeId,
      entityType: "QRCode",
      entityId: qr.id,
      summary: {
        reason: parsed.data.reason || null,
        batchId: qr.batchId || null,
      },
      payload: {
        qrId: qr.id,
        reason: parsed.data.reason || null,
      },
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || null,
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
  } catch (e: any) {
    console.error("blockQRCode error:", e);
    return res.status(400).json({ success: false, error: e?.message || "Bad request" });
  }
};

export const blockBatch = async (req: AuthRequest, res: Response) => {
  try {
    if (req.user?.role !== UserRole.SUPER_ADMIN && req.user?.role !== UserRole.PLATFORM_SUPER_ADMIN) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const parsed = blockQRSschema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const paramsParsed = batchIdParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) {
      return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Invalid batch id" });
    }
    const id = paramsParsed.data.id;

    const batch = await prisma.batch.findUnique({
      where: { id },
      select: { id: true, licenseeId: true },
    });
    if (!batch) return res.status(404).json({ success: false, error: "Batch not found" });

    const approval = await createSensitiveActionApproval({
      actionKey: SENSITIVE_ACTION_KEYS.BATCH_BLOCK,
      actor: {
        userId: req.user.userId,
        role: req.user.role,
        orgId: req.user.orgId || null,
        licenseeId: req.user.licenseeId || null,
      },
      licenseeId: batch.licenseeId,
      entityType: "Batch",
      entityId: batch.id,
      summary: {
        reason: parsed.data.reason || null,
      },
      payload: {
        batchId: batch.id,
        reason: parsed.data.reason || null,
      },
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || null,
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
  } catch (e: any) {
    console.error("blockBatch error:", e);
    return res.status(400).json({ success: false, error: e?.message || "Bad request" });
  }
};

/* ===================== READ ===================== */

export const getBatches = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({ success: false, error: "Not authenticated" });
    }

    const limit = Math.min(parseInt(String(req.query.limit ?? "100"), 10) || 100, 500);
    const offset = Math.max(0, parseInt(String(req.query.offset ?? "0"), 10) || 0);
    const requestedLicenseeId = (req.query.licenseeId as string | undefined) || null;

    const payload = await listScopedBatchReadPayload({
      user: req.user,
      requestedLicenseeId,
      requestId: (req as AuthRequest & { requestId?: string }).requestId,
      databaseSessionCapability: req.databaseSessionCapability,
      limit,
      offset,
    });

    return res.json({ success: true, data: payload.rows, meta: { total: payload.total, limit, offset } });
  } catch (e) {
    if (isScopeError(e)) {
      return res.status(404).json({ success: false, error: "Batches not found" });
    }
    console.error("getBatches error:", e);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

export const getBatchAllocationMap = async (req: AuthRequest, res: Response) => {
  try {
    const auth = ensureAuth(req);
    if (!auth || !req.user) {
      return res.status(401).json({ success: false, error: "Not authenticated" });
    }

    const batchId = String(req.params.id || "").trim();
    if (!batchId) {
      return res.status(400).json({ success: false, error: "Missing batch id" });
    }
    const parsed = batchIdParamSchema.safeParse({ id: batchId });
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: "Invalid batch id" });
    }

    const allocationPayload = await getScopedBatchAllocationMapPayload({
      user: req.user,
      batchId: parsed.data.id,
      requestedLicenseeId: (req.query.licenseeId as string | undefined) || null,
      requestId: (req as AuthRequest & { requestId?: string }).requestId,
      databaseSessionCapability: req.databaseSessionCapability,
    });
    if (allocationPayload.status === "batch_not_found") {
      return res.status(404).json({ success: false, error: "Batch not found" });
    }

    if (allocationPayload.status === "allocation_map_unavailable" || !allocationPayload.allocationMap) {
      return res.status(404).json({ success: false, error: "Allocation map unavailable" });
    }

    return res.json({ success: true, data: allocationPayload.allocationMap });
  } catch (error) {
    if (isScopeError(error)) {
      return res.status(404).json({ success: false, error: "Batch not found" });
    }
    console.error("getBatchAllocationMap error:", error);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

export const getQRCodes = async (req: AuthRequest, res: Response) => {
  try {
    const role = req.user?.role;
    const userId = req.user?.userId;
    if (!role || !userId || !req.user) {
      return res.status(401).json({ success: false, error: "Not authenticated" });
    }

    const q = (req.query.q as string | undefined)?.trim();
    const status = (req.query.status as QRStatus | undefined) || undefined;

    const limit = Math.min(parseInt(String(req.query.limit ?? "500"), 10) || 500, 2000);
    const offset = parseInt(String(req.query.offset ?? "0"), 10) || 0;

    const { total, qrCodes } = await readQrCodesBoundary<any[]>({
      capability: String(req.databaseSessionCapability || ""), requestId: qrRequestId(req),
      licenseeId: (req.query.licenseeId as string | undefined) || null, status, query: q, limit, offset,
    });

    const decisionMap = await listLatestDecisionByQrCodeIds(qrCodes.map((row) => row.id));
    const enrichedQRCodes = qrCodes.map((row) => ({
      ...row,
      latestDecision: decisionMap.get(row.id) || null,
    }));

    return res.json({ success: true, data: { qrCodes: enrichedQRCodes, total, limit, offset } });
  } catch (e: any) {
    if (isScopeError(e)) {
      return res.status(404).json({ success: false, error: "QR codes not found" });
    }
    console.error("getQRCodes error:", e);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

export const generateSignedScanLinks = async (req: AuthRequest, res: Response) => {
  return res.status(410).json({
    success: false,
    error:
      "Ad hoc signed label export is retired. Create labels through MSCQR print jobs so signed scans remain tied to controlled issuance and print confirmation.",
  });
};

export const getStats = async (req: AuthRequest, res: Response) => {
  try {
    const role = req.user?.role;
    const userId = req.user?.userId;
    if (!role || !userId || !req.user) {
      return res.status(401).json({ success: false, error: "Not authenticated" });
    }

    const stats = await readQrStatsBoundary<{ total: number; byStatus: Record<string, number> }>({
      capability: String(req.databaseSessionCapability || ""), requestId: qrRequestId(req),
      licenseeId: (req.query.licenseeId as string | undefined) || null,
    });
    return res.json({ success: true, data: { ...stats, ...summarizeQrStatusCounts(stats.byStatus || {}) } });
  } catch (e) {
    if (isScopeError(e)) {
      return res.status(404).json({ success: false, error: "QR stats not found" });
    }
    console.error("getStats error:", e);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

export const getLegacyPublicCodeReport = async (req: AuthRequest, res: Response) => {
  return res.status(410).json({
    success: false,
    error: "Legacy QR identity reports are retired; QRCode.code is immutable.",
  });
};

export const getPrintValidationEvidence = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user?.userId) {
      return res.status(401).json({ success: false, error: "Not authenticated" });
    }

    const paramsParsed = batchIdParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) {
      return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Invalid batch id" });
    }

    const report = await generatePrintValidationEvidenceReport({
      batchId: paramsParsed.data.id,
      capability: String(req.databaseSessionCapability || ""),
      requestId: qrRequestId(req),
      printJobId: String(req.query.printJobId || "").trim() || null,
      includePublicCode: String(req.query.includePublicCode || "").trim().toLowerCase() === "true",
    });

    if (String(req.query.format || "").trim().toLowerCase() === "markdown") {
      res.setHeader("Content-Type", "text/markdown; charset=utf-8");
      res.setHeader("Content-Disposition", `attachment; filename="mscqr-print-validation-${report.batch.id}.md"`);
      return res.send(`${formatPrintValidationEvidenceMarkdown(report)}\n`);
    }

    return res.json({ success: true, data: report });
  } catch (e) {
    const statusCode = typeof (e as { statusCode?: unknown })?.statusCode === "number" ? Number((e as { statusCode: number }).statusCode) : 500;
    if (statusCode === 404) return res.status(404).json({ success: false, error: "Validation evidence not found" });
    console.error("getPrintValidationEvidence error:", e);
    return res.status(500).json({ success: false, error: "Validation evidence is temporarily unavailable." });
  }
};

export const releaseBatch = async (req: AuthRequest, res: Response) => {
  try {
    const auth = ensureAuth(req);
    if (!auth || !req.user) return res.status(401).json({ success: false, error: "Not authenticated" });

    const paramsParsed = batchIdParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) {
      return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Invalid batch id" });
    }

    const boundary = {
      capability: String(req.databaseSessionCapability || ""),
      requestId: String((req as AuthRequest & { requestId?: string }).requestId || ""),
    };
    const releaseContext = await getBatchReleaseApprovalContext({
      batchId: paramsParsed.data.id,
      boundary,
    });

    if (releaseContext.approvalPolicy.required) {
      if (!releaseContext.readiness.releasable) {
        throw Object.assign(
          new Error(releaseContext.readiness.failures[0]?.message || "Batch is not ready for release."),
          {
            statusCode: 409,
            readiness: releaseContext.readiness,
          }
        );
      }
      const result = await requestOrApproveBatchRelease({
        batchId: paramsParsed.data.id,
        boundary,
        reason: releaseContext.approvalPolicy.reason,
      });
      const completed = result.batch?.lifecycleState === "RELEASED";
      return res.status(completed ? 200 : 202).json({
        success: true,
        data: {
          ...result.batch,
          readiness: result.readiness,
          approvalPolicy: result.approvalPolicy,
        },
      });
    }

    const result = await releaseBatchForSupplyChain({
      batchId: paramsParsed.data.id,
      boundary,
    });

    return res.json({ success: true, data: result });
  } catch (e) {
    const statusCode = typeof (e as { statusCode?: unknown })?.statusCode === "number" ? Number((e as { statusCode: number }).statusCode) : 500;
    const readiness = (e as { readiness?: unknown })?.readiness || null;
    if (isScopeError(e)) {
      return res.status(404).json({ success: false, error: "Batch not found" });
    }
    if (statusCode === 409) {
      const readinessObj =
        readiness && typeof readiness === "object" && !Array.isArray(readiness)
          ? (readiness as { failures?: Array<{ code?: string; message?: string }> })
          : null;
      const firstFailure = readinessObj?.failures?.[0] || null;
      const rawCode = typeof (e as { code?: unknown })?.code === "string" ? String((e as { code: string }).code) : firstFailure?.code || "";
      const codeByFailure: Record<string, string> = {
        already_released: "BATCH_ALREADY_RELEASED",
        print_job_missing: "PRINT_JOB_NOT_CONFIRMED",
        latest_print_job_failed: "PRINT_JOB_NOT_CONFIRMED",
        physical_print_not_confirmed: "PHYSICAL_CONFIRMATION_REQUIRED",
        sample_scan_policy_incomplete: "SAMPLE_SCAN_REQUIRED",
        qr_mutation_locked: "INVALID_STATE_TRANSITION",
        public_code_missing: "QR_VERIFY_TOKEN_REQUIRED",
        unsafe_public_code_shape: "QR_VERIFY_TOKEN_REQUIRED",
      };
      const code = codeByFailure[rawCode] || rawCode || "INVALID_STATE_TRANSITION";
      const message = (e as Error)?.message || firstFailure?.message || "Batch is not ready for release.";
      const requiredPreviousStepByCode: Record<string, string> = {
        BATCH_ALREADY_RELEASED: "Batch already released",
        PRINT_JOB_NOT_CONFIRMED: "Confirm physical printing",
        PHYSICAL_CONFIRMATION_REQUIRED: "Confirm physical printing",
        SAMPLE_SCAN_REQUIRED: "Scan one printed label",
        QR_VERIFY_TOKEN_REQUIRED: "Repair public QR token issuance",
        INVALID_STATE_TRANSITION: "Complete the previous batch step",
      };
      const recoveryActionByCode: Record<string, string> = {
        BATCH_ALREADY_RELEASED: "refresh_batch",
        PRINT_JOB_NOT_CONFIRMED: "confirm_physical_print",
        PHYSICAL_CONFIRMATION_REQUIRED: "confirm_physical_print",
        SAMPLE_SCAN_REQUIRED: "scan_sample_label",
        QR_VERIFY_TOKEN_REQUIRED: "open_support_or_admin_repair",
        INVALID_STATE_TRANSITION: "complete_previous_step",
      };
      return res.status(409).json({
        success: false,
        error: message,
        message,
        code,
        errorCode: code,
        userMessage: message,
        requiredPreviousStep: requiredPreviousStepByCode[code] || "Complete the previous batch step",
        recoveryAction: recoveryActionByCode[code] || "refresh_and_retry",
        canRetry: code !== "BATCH_ALREADY_RELEASED",
        data: readiness ? { readiness } : undefined,
      });
    }
    if (statusCode === 404) {
      return res.status(404).json({ success: false, error: "Batch not found" });
    }
    console.error("releaseBatch error:", e);
    return res.status(500).json({ success: false, error: "Batch release failed safely." });
  }
};

export const rotateLegacyPublicCodes = async (req: AuthRequest, res: Response) => {
  return res.status(410).json({
    success: false,
    error: "Legacy QR rotation is retired because QRCode.code is immutable.",
  });
};

export const exportQRCodesCsv = async (req: AuthRequest, res: Response) => {
  let exportDirectory: string | null = null;
  try {
    const role = req.user?.role;
    const userId = req.user?.userId;
    if (!role || !userId || !req.user) return res.status(401).json({ success: false, error: "Not authenticated" });

    const q = (req.query.q as string | undefined)?.trim();
    const status = (req.query.status as QRStatus | undefined) || undefined;

    const header = [
      "code","scanUrlPolicy","status","licenseeName","licenseePrefix","batchId","batchName",
      "productName","productCode","printedAt","scanCount","createdAt","scannedAt",
    ];
    exportDirectory = await mkdtemp(join(tmpdir(),"mscqr-qr-export-"));
    const exportPath=join(exportDirectory,"qr-codes.csv");
    const file=await open(exportPath,"wx",0o600);
    let exportedCount=0;
    try {
      await file.write(`${header.join(",")}\n`);
      exportedCount = await withQrBoundaryTransaction(
        (tx) => visitQrCodePages<any>(
          (limit, offset) => readQrCodesBoundary<any[]>({
            capability: String(req.databaseSessionCapability || ""), requestId: qrRequestId(req),
            licenseeId: (req.query.licenseeId as string | undefined) || null, status, query: q, limit, offset,
          }, tx),
          async (rows) => {
            const lines=rows.map((r) => [
              r.code,"SIGNED_SCAN_URL_REQUIRED",r.status,r.licensee?.name ?? "",r.licensee?.prefix ?? "",
              r.batchId ?? "",r.batch?.name ?? "","","",r.batch?.printedAt ?? "",r.scanCount ?? 0,
              r.createdAt,r.scannedAt ?? "",
            ].map(escapeCsv).join(","));
            if (lines.length) await file.write(`${lines.join("\n")}\n`);
          }
        ),
        {
          timeout: ALLOCATION_TX_TIMEOUT_MS,
          maxWait: ALLOCATION_TX_MAX_WAIT_MS,
          isolationLevel: Prisma.TransactionIsolationLevel.RepeatableRead,
        }
      );
    } finally {
      await file.close();
    }

    await createAuditLog({
      userId,
      licenseeId: (req.query.licenseeId as string | undefined) || undefined,
      action: "EXPORT_QR_CODES",
      entityType: "QRCode",
      details: { status: status || null, query: q || null, count: exportedCount },
      ipAddress: req.ip,
    });

    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="qr-codes.csv"`);
    await new Promise<void>((resolve,reject)=>res.sendFile(exportPath,(error)=>error?reject(error):resolve()));
    return res;
  } catch (e) {
    if (isScopeError(e)) {
      return res.status(404).json({ success: false, error: "QR codes not found" });
    }
    console.error("exportQRCodesCsv error:", e);
    return res.status(500).json({ success: false, error: "Internal server error" });
  } finally {
    if (exportDirectory) await rm(exportDirectory,{recursive:true,force:true});
  }
};
