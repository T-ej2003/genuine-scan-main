import type { Response } from "express";

import type { AuthRequest } from "../middleware/auth";
import { getRateLimitAlertCandidates, getRateLimitAnalyticsSummary } from "../observability/rateLimitMetrics";

const parseWindowMs = (value: unknown, fallback: number) => {
  const numeric = Number(String(value || "").trim());
  if (!Number.isFinite(numeric) || numeric <= 0) return fallback;
  return Math.min(24 * 60 * 60 * 1000, Math.max(60_000, Math.floor(numeric)));
};

export const getRateLimitAnalyticsController = async (req: AuthRequest, res: Response) => {
  try {
    const windowMs = parseWindowMs(req.query.windowMs, 15 * 60 * 1000);
    return res.json({
      success: true,
      data: getRateLimitAnalyticsSummary(windowMs),
    });
  } catch (error) {
    console.error("getRateLimitAnalyticsController error:", error);
    return res.status(500).json({ success: false, error: "Failed to load rate-limit analytics" });
  }
};

export const getRateLimitAlertsController = async (req: AuthRequest, res: Response) => {
  try {
    const windowMs = parseWindowMs(req.query.windowMs, 15 * 60 * 1000);
    return res.json({
      success: true,
      data: getRateLimitAlertCandidates(windowMs),
    });
  } catch (error) {
    console.error("getRateLimitAlertsController error:", error);
    return res.status(500).json({ success: false, error: "Failed to load rate-limit alerts" });
  }
};
