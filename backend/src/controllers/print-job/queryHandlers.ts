import { Response } from "express";
import { UserRole } from "@prisma/client";

import { AuthRequest } from "../../middleware/auth";
import { getEffectiveLicenseeId } from "../../middleware/tenantIsolation";
import { getPrintJobOperationalView, listPrintJobsForManufacturer } from "../../services/networkDirectPrintService";
import { createAuthorizedPrintReissue } from "../../services/printReissueService";
import { abandonUnconfirmedPrintJob } from "../../services/printLifecycleService";
import { pausePrintJob, resumePrintJob, stopPrintJob } from "../../services/printOperationControlService";
import {
  createScopedPrintReissueRequest,
  decideScopedPrintReissueRequest,
  listScopedPrintReissueRequests,
} from "../../services/printReissueRequestWorkflowService";
import {
  createReissueRequestSchema,
  ensurePrintOperationsUser,
  listReissueRequestsQuerySchema,
  listPrintJobsQuerySchema,
  printOperationReasonSchema,
  printJobIdParamSchema,
  reissueRequestDecisionSchema,
  reissueRequestIdParamSchema,
  reissuePrintJobSchema,
} from "./shared";

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

    const rows = await listPrintJobsForManufacturer({
      scope: {
        role: user.role,
        userId: user.userId,
        licenseeId: getEffectiveLicenseeId(req),
      },
      batchId: parsed.data.batchId,
      limit: parsed.data.limit,
    });

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

    const view = await getPrintJobOperationalView({
      jobId: parsedParams.data.id,
      scope: {
        role: user.role,
        userId: user.userId,
        licenseeId: getEffectiveLicenseeId(req),
      },
    });
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

const handleUserSafeError = (res: Response, error: any, fallback: string) => {
  const statusCode = typeof error?.statusCode === "number" ? error.statusCode : 500;
  const message = String(error?.message || fallback);
  return res.status(statusCode).json({ success: false, error: statusCode >= 500 ? fallback : message });
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
    if (!isPlatformAdmin(user.role)) {
      return res.status(403).json({
        success: false,
        error: "Create a reissue request for approval before replacement labels can be generated.",
      });
    }

    const parsedParams = printJobIdParamSchema.safeParse(req.params || {});
    if (!parsedParams.success) {
      return res.status(400).json({ success: false, error: parsedParams.error.errors[0]?.message || "Invalid print job id" });
    }

    const parsedBody = reissuePrintJobSchema.safeParse(req.body || {});
    if (!parsedBody.success) {
      return res.status(400).json({ success: false, error: parsedBody.error.errors[0]?.message || "Invalid reissue request" });
    }

    const data = await createAuthorizedPrintReissue({
      scope: {
        role: user.role,
        userId: user.userId,
        licenseeId: getEffectiveLicenseeId(req),
      },
      originalPrintJobId: parsedParams.data.id,
      reason: parsedBody.data.reason,
      quantity: parsedBody.data.quantity ?? null,
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || null,
    });

    return res.status(201).json({ success: true, data });
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
    const view = await getPrintJobOperationalView({ jobId: parsedParams.data.id, scope });
    if (!view) {
      return res.status(404).json({ success: false, error: "Print job not found" });
    }

    const result = await abandonUnconfirmedPrintJob({
      printJobId: parsedParams.data.id,
      actorUserId: user.userId,
      licenseeId: scope.licenseeId || view.batch?.licenseeId || null,
      reason: "Operator closed unconfirmed failed print run so labels can be started again.",
    });

    return res.json({
      success: true,
      data: {
        jobId: result.job.id,
        status: result.job.status,
        printSessionId: result.session.id,
        sessionStatus: result.session.status,
        releasedQrCodeCount: result.releasedQrCodeCount,
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
