import { Response } from "express";

import { AuthRequest } from "../../middleware/auth";
import {
  readPrintingProjection,
  recordPrintingSample,
} from "../../rls-waves/session-c/c02/printingLifecycleRepository";
import {
  confirmSchema,
  ensureManufacturerUser,
  printJobIdParamSchema,
  sampleScanSchema,
} from "./shared";

export const confirmDirectPrintItem = async (_req: AuthRequest, res: Response) =>
  res.status(410).json({
    success: false,
    error: "Browser-mediated direct printing has been disabled. The MSCQR connector now confirms printed labels directly with the server.",
  });

const boundary = (req: AuthRequest) => ({
  capability: String(req.databaseSessionCapability || ""),
  requestId: String((req as AuthRequest & { requestId?: string }).requestId || ""),
});

const failure = (error: any, fallback: string) => {
  const code = String(error?.code || error?.message || "");
  const status = Number(error?.statusCode || (/DENIED|42501/.test(code) ? 403 : /NOT_FOUND/.test(code) ? 404 : 409));
  return {
    status,
    payload: {
      success: false,
      error: status >= 500 ? fallback : String(error?.message || fallback),
      ...(code ? { code, errorCode: code } : {}),
    },
  };
};
export const confirmPrintJob = async (req: AuthRequest, res: Response) => {
  try {
    if (!ensureManufacturerUser(req, res)) return;
    const body = confirmSchema.safeParse(req.body || {});
    const params = printJobIdParamSchema.safeParse(req.params || {});
    if (!body.success || !params.success) {
      return res.status(400).json({ success: false, error: "Invalid print confirmation request." });
    }
    const view = await readPrintingProjection({
      ...boundary(req), operation: "JOB", subjectId: params.data.id,
    });
    const remainingToPrint = (view.items || []).filter((item: any) =>
      !["PRINT_CONFIRMED","CLOSED","CANCELLED","FAILED"].includes(String(item.state))
    ).length;
    if (remainingToPrint > 0 || view.job?.status !== "CONFIRMED") {
      return res.status(409).json({
        success: false,
        error: `Cannot confirm job while ${remainingToPrint} items are waiting for connector physical confirmation.`,
        code: "PHYSICAL_CONFIRMATION_REQUIRED",
        errorCode: "PHYSICAL_CONFIRMATION_REQUIRED",
        recoveryAction: "wait_for_connector_confirmation_or_stop_recover",
      });
    }
    return res.json({
      success: true,
      data: {
        printJobId: view.job.id,
        printSessionId: view.session.id,
        confirmedAt: view.job.confirmedAt,
        remainingToPrint: 0,
        jobConfirmed: true,
      },
    });
  } catch (error: any) {
    const mapped = failure(error, "Print confirmation failed.");
    return res.status(mapped.status).json(mapped.payload);
  }
};

export const capturePrintJobSampleScan = async (req: AuthRequest, res: Response) => {
  try {
    if (!ensureManufacturerUser(req, res)) return;
    const params = printJobIdParamSchema.safeParse(req.params || {});
    const body = sampleScanSchema.safeParse(req.body || {});
    if (!params.success || !body.success) {
      return res.status(400).json({ success: false, error: "Invalid sample scan payload." });
    }
    const result = await recordPrintingSample({
      ...boundary(req),
      jobId: params.data.id,
      code: body.data.publicCode,
      evidence: { source: "authenticated-print-sample" },
    });
    return res.json({ success: true, data: result });
  } catch (error: any) {
    const mapped = failure(error, "Sample scan could not be verified.");
    return res.status(mapped.status).json(mapped.payload);
  }
};
