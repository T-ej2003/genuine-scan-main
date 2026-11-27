import { Response } from "express";
import { UserRole } from "@prisma/client";

import { AuthRequest } from "../../middleware/auth";
import { getEffectiveLicenseeId } from "../../middleware/tenantIsolation";
import { pausePrintJob, resumePrintJob, stopPrintJob, retireUncertainPrintJob } from "../../services/printOperationControlService";
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
  handleUserSafeError,
  reissuePrintJobSchema,
} from "./shared";
import { isPhysicalOutcomeUnconfirmed } from "./errorResponses";
import { sendPrintReissueExecutionError } from "./reissueOutcomeResponse";
import {
  createReissueRequestSchema,
  listReissueRequestsQuerySchema,
  printOperationReasonSchema,
  retireUncertainPrintJobSchema,
  reissueRequestDecisionSchema,
  reissueRequestIdParamSchema,
} from "./operationSchemas";
import { bumpCacheNamespaceVersion, getOrComputeVersionedCache } from "../../services/versionedCacheService";

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
      return res.status(400).json({ success: false, error: parsed.error.issues[0]?.message || "Invalid query" });
    }

    const rows = await getOrComputeVersionedCache(
      "print-jobs",
      [user.role, user.userId, getEffectiveLicenseeId(req) || "none", parsed.data.licenseeId || "all",
        parsed.data.batchId || "all", parsed.data.limit].join(":"),
      5,
      () => readPrintingProjection({
        ...printBoundary(req),
        operation: "JOB_LIST",
        subjectId: parsed.data.batchId || "00000000-0000-4000-8000-000000000000",
        options: { batchId: parsed.data.batchId || null, limit: parsed.data.limit || 50, licenseeId: parsed.data.licenseeId || null },
      })
    );

    return res.json({ success: true, data: rows });
  } catch (error: any) {
    console.error("listManufacturerPrintJobs error:", error);
    return handleUserSafeError(res, error, "Print jobs could not be loaded.");
  }
};

export const getManufacturerPrintJobStatus = async (req: AuthRequest, res: Response) => {
  try {
    const user = ensurePrintOperationsUser(req, res);
    if (!user) return;

    const parsedParams = printJobIdParamSchema.safeParse(req.params || {});
    if (!parsedParams.success) {
      return res.status(400).json({ success: false, error: parsedParams.error.issues[0]?.message || "Invalid print job id" });
    }

    const licenseeId = typeof req.query?.licenseeId === "string" ? req.query.licenseeId.trim() : null;
    const view = await getOrComputeVersionedCache(
      "print-jobs",
      [user.role, user.userId, getEffectiveLicenseeId(req) || "none", licenseeId || "all", "status", parsedParams.data.id].join(":"),
      3,
      () => readPrintingProjection({
        ...printBoundary(req), operation: "JOB", subjectId: parsedParams.data.id,
        options: { licenseeId },
      })
    );
    if (!view) {
      return res.status(404).json({ success: false, error: "Print job not found" });
    }

    return res.json({ success: true, data: view });
  } catch (error: any) {
    console.error("getManufacturerPrintJobStatus error:", error);
    return handleUserSafeError(res, error, "Print job status could not be loaded.");
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

export const pauseManufacturerPrintJob = async (req: AuthRequest, res: Response) => {
  try {
    const user = ensurePrintOperationsUser(req, res);
    if (!user) return;

    const parsedParams = printJobIdParamSchema.safeParse(req.params || {});
    if (!parsedParams.success) {
      return res.status(400).json({ success: false, error: parsedParams.error.issues[0]?.message || "Invalid print job id" });
    }
    const parsedBody = printOperationReasonSchema.safeParse(req.body || {});
    if (!parsedBody.success) {
      return res.status(400).json({ success: false, error: parsedBody.error.issues[0]?.message || "A clear reason is required." });
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
      return res.status(400).json({ success: false, error: parsedParams.error.issues[0]?.message || "Invalid print job id" });
    }

    const result = await resumePrintJob({
      printJobId: parsedParams.data.id,
      scope: printControlScope(req, user),
      boundary: printBoundary(req),
    });
    return res.json({ success: true, data: result.view, meta: { idempotent: result.idempotent } });
  } catch (error: any) {
    if (isPhysicalOutcomeUnconfirmed(error) && error?.code === "P2010") {
      await bumpCacheNamespaceVersion("print-jobs").catch(() => undefined);
      return handleUserSafeError(res, {
        statusCode: 409,
        code: "PHYSICAL_OUTCOME_UNCONFIRMED",
        message: "This run cannot resume until the outcome of the previous print attempt is resolved.",
      }, "Print run could not be resumed.");
    }
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
      return res.status(400).json({ success: false, error: parsedParams.error.issues[0]?.message || "Invalid print job id" });
    }
    const parsedBody = printOperationReasonSchema.safeParse(req.body || {});
    if (!parsedBody.success) {
      return res.status(400).json({ success: false, error: parsedBody.error.issues[0]?.message || "A clear reason is required." });
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

export const retireUncertainManufacturerPrintJob = async (req: AuthRequest, res: Response) => {
  try {
    const user = ensurePrintOperationsUser(req, res);
    if (!user) return;
    const params = printJobIdParamSchema.safeParse(req.params || {});
    const body = retireUncertainPrintJobSchema.safeParse(req.body || {});
    if (!params.success || !body.success) return res.status(400).json({ success: false, error: "Job ID, reason and boundary evidence SHA-256 are required." });
    if (params.data.id !== "197d65b3-cbea-4ff4-8a2f-258e4dcf5493" ||
        body.data.evidenceSha256 !== "d506fb1403ea5a1367e6d76eb1a580530cadaadb12e565ae5b55e1e06c93c421") {
      return res.status(403).json({ success: false, error: "This retirement is limited to the verified November 10 job and cancellation record." });
    }
    const result = await retireUncertainPrintJob({
      printJobId: params.data.id, scope: printControlScope(req, user), boundary: printBoundary(req),
      reason: body.data.reason, evidenceSha256: body.data.evidenceSha256,
    });
    return res.json({ success: true, data: result.view, meta: { idempotent: result.idempotent } });
  } catch (error: any) {
    console.error("retireUncertainManufacturerPrintJob error:", error);
    if (isPhysicalOutcomeUnconfirmed(error)) {
      return res.status(409).json({ success: false, code: "PHYSICAL_OUTCOME_UNCONFIRMED",
        error: "This print run has confirmation evidence or its state changed. Keep the printer fenced and review the job." });
    }
    return handleUserSafeError(res, error, "Uncertain print job could not be retired.");
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
      return res.status(400).json({ success: false, error: parsedParams.error.issues[0]?.message || "Invalid print job id" });
    }
    const parsedBody = createReissueRequestSchema.safeParse(req.body || {});
    if (!parsedBody.success) {
      return res.status(400).json({ success: false, error: parsedBody.error.issues[0]?.message || "Invalid reissue request" });
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
    if (isPhysicalOutcomeUnconfirmed(error)) {
      return res.status(409).json({
        success: false,
        code: "PHYSICAL_OUTCOME_UNCONFIRMED",
        error: "Physical output is uncertain. Review print history before requesting recovery.",
      });
    }
    return handleUserSafeError(res, error, "Print reissue request could not be created.");
  }
};

export const listManufacturerPrintReissueRequests = async (req: AuthRequest, res: Response) => {
  try {
    const user = ensurePrintOperationsUser(req, res);
    if (!user) return;

    const parsedQuery = listReissueRequestsQuerySchema.safeParse(req.query || {});
    if (!parsedQuery.success) {
      return res.status(400).json({ success: false, error: parsedQuery.error.issues[0]?.message || "Invalid query" });
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
    if (/PRINTING_BOUNDARY_DENIED|AUTH_SESSION_CAPABILITY_DENIED/.test(String(error?.meta?.message || error?.message || ""))) {
      return res.status(403).json({ success: false, error: "Access denied", code: "PRINTING_BOUNDARY_DENIED" });
    }
    return handleUserSafeError(res, error, "Print reissue requests could not be loaded.");
  }
};

export const approveManufacturerPrintReissueRequest = async (req: AuthRequest, res: Response) => {
  try {
    const user = ensurePrintOperationsUser(req, res);
    if (!user) return;

    const parsedParams = reissueRequestIdParamSchema.safeParse(req.params || {});
    if (!parsedParams.success) {
      return res.status(400).json({ success: false, error: parsedParams.error.issues[0]?.message || "Invalid reissue request id" });
    }
    const parsedBody = reissueRequestDecisionSchema.safeParse(req.body || {});
    if (!parsedBody.success) {
      return res.status(400).json({ success: false, error: parsedBody.error.issues[0]?.message || "A clear decision note is required." });
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
      return res.status(400).json({ success: false, error: parsedParams.error.issues[0]?.message || "Invalid reissue request id" });
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
    return sendPrintReissueExecutionError(res, error);
  }
};

export const rejectManufacturerPrintReissueRequest = async (req: AuthRequest, res: Response) => {
  try {
    const user = ensurePrintOperationsUser(req, res);
    if (!user) return;

    const parsedParams = reissueRequestIdParamSchema.safeParse(req.params || {});
    if (!parsedParams.success) {
      return res.status(400).json({ success: false, error: parsedParams.error.issues[0]?.message || "Invalid reissue request id" });
    }
    const parsedBody = reissueRequestDecisionSchema.safeParse(req.body || {});
    if (!parsedBody.success) {
      return res.status(400).json({ success: false, error: parsedBody.error.issues[0]?.message || "A clear decision note is required." });
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
      return res.status(400).json({ success: false, error: parsedParams.error.issues[0]?.message || "Invalid print job id" });
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
    if (isPhysicalOutcomeUnconfirmed(error)) {
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
    return handleUserSafeError(res, error, "Print run could not be closed.");
  }
};
