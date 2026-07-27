import { Response } from "express";
import { UserRole } from "@prisma/client";

import { AuthRequest } from "../../middleware/auth";
import { getEffectiveLicenseeId } from "../../middleware/tenantIsolation";
import { pausePrintJob, resumePrintJob, stopPrintJob } from "../../services/printOperationControlService";
import { controlPrintingJob, readPrintingProjection } from "../../rls-waves/session-c/c02/printingLifecycleRepository";
import {
  createScopedPrintReissueRequest,
  decideScopedPrintReissueRequest,
  listScopedPrintReissueRequests,
  startApprovedPrintReissueRequest,
} from "../../services/printReissueRequestWorkflowService";
import {
  ensurePrintOperationsUser,
  listPrintJobsQuerySchema,
  printJobIdParamSchema,
  reissuePrintJobSchema,
} from "./shared";
import { describeMissingPrinterReadinessFields } from "./errorResponses";
import {
  createReissueRequestSchema,
  listReissueRequestsQuerySchema,
  printOperationReasonSchema,
  reissueRequestDecisionSchema,
  reissueRequestIdParamSchema,
} from "./operationSchemas";
import { getOrComputeVersionedCache } from "../../services/versionedCacheService";

const isPlatformAdmin = (role: UserRole) =>
  role === UserRole.SUPER_ADMIN || role === UserRole.PLATFORM_SUPER_ADMIN;

export const downloadPrintJobPack = async (_req: AuthRequest, res: Response) => {
  return res.status(410).json({
    success: false,
    error:
      "Print-pack download is disabled. Create the print job and let the MSCQR connector or certified printer route complete it directly.",
  });
};

export const listManufacturerPrintJobs = async (req: AuthRequest, res: Response) => {
  try {
    const user = ensurePrintOperationsUser(req, res);
    if (!user) return;

    const parsed = listPrintJobsQuerySchema.safeParse(req.query || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid query" });
    }

    const rows = await getOrComputeVersionedCache(
      "print-jobs",
      [user.role, user.userId, getEffectiveLicenseeId(req) || "none", parsed.data.batchId || "all", parsed.data.limit].join(":"),
      5,
      () => readPrintingProjection({
        ...printBoundary(req),
        operation: "JOB_LIST",
        subjectId: parsed.data.batchId || "00000000-0000-4000-8000-000000000000",
        options: { batchId: parsed.data.batchId || null, limit: parsed.data.limit || 50 },
      })
    );

    return res.json({ success: true, data: rows });
  } catch (error: any) {
    console.error("listManufacturerPrintJobs error:", error);
    return res.status(500).json({ success: false, error: error?.message || "Internal server error" });
  }
};

export const getManufacturerPrintJobStatus = async (req: AuthRequest, res: Response) => {
  try {
    const user = ensurePrintOperationsUser(req, res);
    if (!user) return;

    const parsedParams = printJobIdParamSchema.safeParse(req.params || {});
    if (!parsedParams.success) {
      return res.status(400).json({ success: false, error: parsedParams.error.errors[0]?.message || "Invalid print job id" });
    }

    const view = await getOrComputeVersionedCache(
      "print-jobs",
      [user.role, user.userId, getEffectiveLicenseeId(req) || "none", "status", parsedParams.data.id].join(":"),
      3,
      () => readPrintingProjection({ ...printBoundary(req), operation: "JOB", subjectId: parsedParams.data.id })
    );
    if (!view) {
      return res.status(404).json({ success: false, error: "Print job not found" });
    }

    return res.json({ success: true, data: view });
  } catch (error: any) {
    console.error("getManufacturerPrintJobStatus error:", error);
    return res.status(500).json({ success: false, error: error?.message || "Internal server error" });
  }
};

const printControlScope = (req: AuthRequest, user: NonNullable<AuthRequest["user"]>) => ({
  role: user.role,
  userId: user.userId,
  licenseeId: getEffectiveLicenseeId(req),
});
const printBoundary = (req: AuthRequest) => ({
  capability: String(req.databaseSessionCapability || ""),
  requestId: String((req as AuthRequest & { requestId?: string }).requestId || ""),
});

const handleUserSafeError = (res: Response, error: any, fallback: string) => {
  const statusCode = typeof error?.statusCode === "number" ? error.statusCode : 500;
  const message = String(error?.message || fallback);
  const code = typeof error?.code === "string" ? error.code : undefined;
  return res.status(statusCode).json({
    success: false,
    error: statusCode >= 500 ? fallback : message,
    message: statusCode >= 500 ? fallback : message,
    ...(code ? { code, errorCode: code } : {}),
  });
};

export const pauseManufacturerPrintJob = async (req: AuthRequest, res: Response) => {
  try {
    const user = ensurePrintOperationsUser(req, res);
    if (!user) return;

    const parsedParams = printJobIdParamSchema.safeParse(req.params || {});
    if (!parsedParams.success) {
      return res.status(400).json({ success: false, error: parsedParams.error.errors[0]?.message || "Invalid print job id" });
    }
    const parsedBody = printOperationReasonSchema.safeParse(req.body || {});
    if (!parsedBody.success) {
      return res.status(400).json({ success: false, error: parsedBody.error.errors[0]?.message || "A clear reason is required." });
    }

    const result = await pausePrintJob({
      printJobId: parsedParams.data.id,
      scope: printControlScope(req, user),
      boundary: printBoundary(req),
      reason: parsedBody.data.reason,
    });
    return res.json({ success: true, data: result.view, meta: { idempotent: result.idempotent } });
  } catch (error: any) {
    console.error("pauseManufacturerPrintJob error:", error);
    return handleUserSafeError(res, error, "Print run could not be paused.");
  }
};

export const resumeManufacturerPrintJob = async (req: AuthRequest, res: Response) => {
  try {
    const user = ensurePrintOperationsUser(req, res);
    if (!user) return;

    const parsedParams = printJobIdParamSchema.safeParse(req.params || {});
    if (!parsedParams.success) {
      return res.status(400).json({ success: false, error: parsedParams.error.errors[0]?.message || "Invalid print job id" });
    }

    const result = await resumePrintJob({
      printJobId: parsedParams.data.id,
      scope: printControlScope(req, user),
      boundary: printBoundary(req),
    });
    return res.json({ success: true, data: result.view, meta: { idempotent: result.idempotent } });
  } catch (error: any) {
    console.error("resumeManufacturerPrintJob error:", error);
    return handleUserSafeError(res, error, "Print run could not be resumed.");
  }
};

export const stopManufacturerPrintJob = async (req: AuthRequest, res: Response) => {
  try {
    const user = ensurePrintOperationsUser(req, res);
    if (!user) return;

    const parsedParams = printJobIdParamSchema.safeParse(req.params || {});
    if (!parsedParams.success) {
      return res.status(400).json({ success: false, error: parsedParams.error.errors[0]?.message || "Invalid print job id" });
    }
    const parsedBody = printOperationReasonSchema.safeParse(req.body || {});
    if (!parsedBody.success) {
      return res.status(400).json({ success: false, error: parsedBody.error.errors[0]?.message || "A clear reason is required." });
    }

    const result = await stopPrintJob({
      printJobId: parsedParams.data.id,
      scope: printControlScope(req, user),
      boundary: printBoundary(req),
      reason: parsedBody.data.reason,
    });
    return res.json({ success: true, data: result.view, meta: { idempotent: result.idempotent } });
  } catch (error: any) {
    console.error("stopManufacturerPrintJob error:", error);
    return handleUserSafeError(res, error, "Print run could not be stopped.");
  }
};

export const reissueManufacturerPrintJob = async (req: AuthRequest, res: Response) => {
  try {
    const user = ensurePrintOperationsUser(req, res);
    if (!user) return;
    return res.status(409).json({
      success: false,
      error: "Create a reissue request for maker-checker approval before replacement labels can be generated.",
    });
  } catch (error: any) {
    console.error("reissueManufacturerPrintJob error:", error);
    const message = String(error?.message || "");
    if (typeof error?.statusCode === "number") {
      return res.status(error.statusCode).json({ success: false, error: message || "Print reissue failed" });
    }
    if (message.startsWith("NOT_ENOUGH_CODES")) {
      return res.status(409).json({
        success: false,
        error: "Not enough unprinted codes remain in this source batch to authorize a controlled reissue.",
      });
    }
    if (message === "BATCH_BUSY") {
      return res.status(409).json({
        success: false,
        error: "This source batch is busy. Refresh the workspace and try the reissue again.",
      });
    }
    return res.status(500).json({ success: false, error: message || "Internal server error" });
  }
};

export const createManufacturerPrintReissueRequest = async (req: AuthRequest, res: Response) => {
  try {
    const user = ensurePrintOperationsUser(req, res);
    if (!user) return;

    const parsedParams = printJobIdParamSchema.safeParse(req.params || {});
    if (!parsedParams.success) {
      return res.status(400).json({ success: false, error: parsedParams.error.errors[0]?.message || "Invalid print job id" });
    }
    const parsedBody = createReissueRequestSchema.safeParse(req.body || {});
    if (!parsedBody.success) {
      return res.status(400).json({ success: false, error: parsedBody.error.errors[0]?.message || "Invalid reissue request" });
    }

    const result = await createScopedPrintReissueRequest({
      scope: printControlScope(req, user),
      boundary: printBoundary(req),
      originalPrintJobId: parsedParams.data.id,
      reason: parsedBody.data.reason,
      quantity: parsedBody.data.quantity ?? null,
      affectedRangeStart: parsedBody.data.affectedRangeStart || null,
      affectedRangeEnd: parsedBody.data.affectedRangeEnd || null,
    });
    return res.status(result.idempotent ? 200 : 201).json({ success: true, data: result.request, meta: { idempotent: result.idempotent } });
  } catch (error: any) {
    console.error("createManufacturerPrintReissueRequest error:", error);
    return handleUserSafeError(res, error, "Print reissue request could not be created.");
  }
};

export const listManufacturerPrintReissueRequests = async (req: AuthRequest, res: Response) => {
  try {
    const user = ensurePrintOperationsUser(req, res);
    if (!user) return;

    const parsedQuery = listReissueRequestsQuerySchema.safeParse(req.query || {});
    if (!parsedQuery.success) {
      return res.status(400).json({ success: false, error: parsedQuery.error.errors[0]?.message || "Invalid query" });
    }

    const rows = await listScopedPrintReissueRequests({
      scope: printControlScope(req, user),
      boundary: printBoundary(req),
      status: parsedQuery.data.status as any,
      limit: parsedQuery.data.limit,
    });
    return res.json({ success: true, data: rows });
  } catch (error: any) {
    console.error("listManufacturerPrintReissueRequests error:", error);
    return handleUserSafeError(res, error, "Print reissue requests could not be loaded.");
  }
};

export const approveManufacturerPrintReissueRequest = async (req: AuthRequest, res: Response) => {
  try {
    const user = ensurePrintOperationsUser(req, res);
    if (!user) return;

    const parsedParams = reissueRequestIdParamSchema.safeParse(req.params || {});
    if (!parsedParams.success) {
      return res.status(400).json({ success: false, error: parsedParams.error.errors[0]?.message || "Invalid reissue request id" });
    }
    const parsedBody = reissueRequestDecisionSchema.safeParse(req.body || {});
    if (!parsedBody.success) {
      return res.status(400).json({ success: false, error: parsedBody.error.errors[0]?.message || "A clear decision note is required." });
    }

    const result = await decideScopedPrintReissueRequest({
      scope: printControlScope(req, user),
      boundary: printBoundary(req),
      requestId: parsedParams.data.id,
      decision: "approve",
      decisionNote: parsedBody.data.decisionNote,
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || null,
    });
    return res.json({ success: true, data: result });
  } catch (error: any) {
    console.error("approveManufacturerPrintReissueRequest error:", error);
    return handleUserSafeError(res, error, "Print reissue request could not be approved.");
  }
};

export const printApprovedManufacturerPrintReissueRequest = async (req: AuthRequest, res: Response) => {
  try {
    const user = ensurePrintOperationsUser(req, res);
    if (!user) return;

    const parsedParams = reissueRequestIdParamSchema.safeParse(req.params || {});
    if (!parsedParams.success) {
      return res.status(400).json({ success: false, error: parsedParams.error.errors[0]?.message || "Invalid reissue request id" });
    }

    const result = await startApprovedPrintReissueRequest({
      scope: printControlScope(req, user),
      boundary: printBoundary(req),
      requestId: parsedParams.data.id,
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || null,
    });
    return res.status(result.idempotent ? 200 : 201).json({
      success: true,
      data: result,
      meta: { idempotent: result.idempotent },
    });
  } catch (error: any) {
    console.error("printApprovedManufacturerPrintReissueRequest error:", error);
    const message = String(error?.message || "");
    if (message.includes("PRINTER_NOT_TRUSTED")) {
      const printerStatus = error?.printerStatus || null;
      return res.status(409).json({
        success: false,
        error: "Printer verification expired. Refresh printer helper before printing.",
        message: "Printer verification expired. Refresh printer helper before printing.",
        code: "PRINTER_ATTESTATION_STALE",
        errorCode: "PRINTER_ATTESTATION_STALE",
        recoveryAction: "refresh_printer_status",
        canRetry: true,
        details: { missingFields: describeMissingPrinterReadinessFields(printerStatus) },
        data: { printerStatus },
      });
    }
    if (message.startsWith("NOT_ENOUGH_CODES")) {
      return res.status(409).json({
        success: false,
        error: "Not enough unprinted codes remain in this source batch to authorize a controlled reissue.",
      });
    }
    if (message === "BATCH_BUSY") {
      return res.status(409).json({
        success: false,
        error: "This source batch is busy. Refresh the workspace and try the reissue again.",
      });
    }
    if (typeof error?.statusCode === "number") {
      const safeMessage = message || "Replacement labels could not be printed.";
      return res.status(error.statusCode).json({
        success: false,
        error: safeMessage,
        message: safeMessage,
        ...(typeof error?.code === "string" ? { code: error.code, errorCode: error.code } : {}),
        ...(error?.details ? { details: error.details } : {}),
      });
    }
    return handleUserSafeError(res, error, "Replacement labels could not be printed.");
  }
};

export const rejectManufacturerPrintReissueRequest = async (req: AuthRequest, res: Response) => {
  try {
    const user = ensurePrintOperationsUser(req, res);
    if (!user) return;

    const parsedParams = reissueRequestIdParamSchema.safeParse(req.params || {});
    if (!parsedParams.success) {
      return res.status(400).json({ success: false, error: parsedParams.error.errors[0]?.message || "Invalid reissue request id" });
    }
    const parsedBody = reissueRequestDecisionSchema.safeParse(req.body || {});
    if (!parsedBody.success) {
      return res.status(400).json({ success: false, error: parsedBody.error.errors[0]?.message || "A clear decision note is required." });
    }

    const result = await decideScopedPrintReissueRequest({
      scope: printControlScope(req, user),
      boundary: printBoundary(req),
      requestId: parsedParams.data.id,
      decision: "reject",
      decisionNote: parsedBody.data.decisionNote,
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || null,
    });
    return res.json({ success: true, data: result });
  } catch (error: any) {
    console.error("rejectManufacturerPrintReissueRequest error:", error);
    return handleUserSafeError(res, error, "Print reissue request could not be rejected.");
  }
};

export const abandonManufacturerPrintJob = async (req: AuthRequest, res: Response) => {
  try {
    const user = ensurePrintOperationsUser(req, res);
    if (!user) return;

    const parsedParams = printJobIdParamSchema.safeParse(req.params || {});
    if (!parsedParams.success) {
      return res.status(400).json({ success: false, error: parsedParams.error.errors[0]?.message || "Invalid print job id" });
    }

    const scope = {
      role: user.role,
      userId: user.userId,
      licenseeId: getEffectiveLicenseeId(req),
    };
    const view = await readPrintingProjection({
      ...printBoundary(req), operation: "JOB", subjectId: parsedParams.data.id,
    });
    if (!view) {
      return res.status(404).json({ success: false, error: "Print job not found" });
    }

    const result = await controlPrintingJob({
      ...printBoundary(req),
      jobId: parsedParams.data.id,
      operation: "ABANDON",
      reason: "Operator closed unconfirmed failed print run so labels can be started again.",
    });
    const closed = await readPrintingProjection({
      ...printBoundary(req), operation: "JOB", subjectId: parsedParams.data.id,
    });

    return res.json({
      success: true,
      data: {
        jobId: result.jobId,
        status: closed.job.status,
        printSessionId: closed.session.id,
        sessionStatus: closed.session.status,
        releasedQrCodeCount: 0,
      },
    });
  } catch (error: any) {
    console.error("abandonManufacturerPrintJob error:", error);
    if (error?.message === "PRINT_SESSION_NOT_ABANDONABLE") {
      return res.status(409).json({
        success: false,
        error: "This print run already reached the printer or has confirmed labels. It cannot be abandoned automatically.",
        code: "print_session_not_abandonable",
        errorCode: "print_session_not_abandonable",
      });
    }
    if (error?.message === "PRINT_JOB_NOT_FOUND") {
      return res.status(404).json({ success: false, error: "Print job not found" });
    }
    return res.status(500).json({ success: false, error: error?.message || "Print run could not be closed." });
  }
};
