import { Response } from "express";

import { AuthRequest } from "../../middleware/auth";
import { getPrintJobOperationalView, listPrintJobsForManufacturer } from "../../services/networkDirectPrintService";
import { ensureManufacturerUser, listPrintJobsQuerySchema } from "./shared";

export const downloadPrintJobPack = async (_req: AuthRequest, res: Response) => {
  return res.status(410).json({
    success: false,
    error:
      "Print-pack download is disabled. Use the direct-print pipeline (one-time short-lived render tokens) via authenticated print agent.",
  });
};

export const listManufacturerPrintJobs = async (req: AuthRequest, res: Response) => {
  try {
    const user = ensureManufacturerUser(req, res);
    if (!user) return;

    const parsed = listPrintJobsQuerySchema.safeParse(req.query || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid query" });
    }

    const rows = await listPrintJobsForManufacturer({
      userId: user.userId,
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
    const user = ensureManufacturerUser(req, res);
    if (!user) return;

    const jobId = String(req.params.id || "").trim();
    if (!jobId) {
      return res.status(400).json({ success: false, error: "Missing print job id" });
    }

    const view = await getPrintJobOperationalView({ jobId, userId: user.userId });
    if (!view) {
      return res.status(404).json({ success: false, error: "Print job not found" });
    }

    return res.json({ success: true, data: view });
  } catch (error: any) {
    console.error("getManufacturerPrintJobStatus error:", error);
    return res.status(500).json({ success: false, error: error?.message || "Internal server error" });
  }
};
