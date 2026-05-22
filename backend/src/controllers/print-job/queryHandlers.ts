import { Response } from "express";

import { AuthRequest } from "../../middleware/auth";
import { getEffectiveLicenseeId } from "../../middleware/tenantIsolation";
import { getPrintJobOperationalView, listPrintJobsForManufacturer } from "../../services/networkDirectPrintService";
import { createAuthorizedPrintReissue } from "../../services/printReissueService";
import { abandonUnconfirmedPrintJob } from "../../services/printLifecycleService";
import {
  ensurePrintOperationsUser,
  ensurePrintReissueApprover,
  listPrintJobsQuerySchema,
  printJobIdParamSchema,
  reissuePrintJobSchema,
} from "./shared";

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

export const reissueManufacturerPrintJob = async (req: AuthRequest, res: Response) => {
  try {
    const user = ensurePrintReissueApprover(req, res);
    if (!user) return;

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
