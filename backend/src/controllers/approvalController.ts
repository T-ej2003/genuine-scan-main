import { Response } from "express";
import { z } from "zod";

import { AuthRequest } from "../middleware/auth";
import {
  approveSensitiveActionApproval,
  listSensitiveActionApprovals,
  rejectSensitiveActionApproval,
} from "../services/sensitiveActionApprovalService";

const approvalListQuerySchema = z.object({
  status: z.string().trim().max(40).optional(),
  limit: z.coerce.number().int().min(1).max(200).optional(),
  offset: z.coerce.number().int().min(0).max(20000).optional(),
}).strict();

const approvalIdParamSchema = z.object({
  id: z.string().uuid("Invalid approval id"),
}).strict();

const approvalDecisionSchema = z.object({
  note: z.string().trim().max(500).optional(),
}).strict();

const getActor = (req: AuthRequest) => {
  if (!req.user) return null;
  return {
    userId: req.user.userId,
    role: req.user.role,
    orgId: req.user.orgId || null,
    licenseeId: req.user.licenseeId || null,
  };
};

export const listApprovalsController = async (req: AuthRequest, res: Response) => {
  try {
    const actor = getActor(req);
    if (!actor) return res.status(401).json({ success: false, error: "Not authenticated" });

    const parsed = approvalListQuerySchema.safeParse(req.query || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid filters" });
    }

    const rows = await listSensitiveActionApprovals({
      actor,
      status: parsed.data.status || null,
      limit: parsed.data.limit,
      offset: parsed.data.offset,
    });

    return res.json({
      success: true,
      data: rows,
      meta: {
        limit: parsed.data.limit || 50,
        offset: parsed.data.offset || 0,
      },
    });
  } catch (error) {
    console.error("listApprovalsController error:", error);
    return res.status(500).json({ success: false, error: "Failed to load approvals" });
  }
};

export const approveApprovalController = async (req: AuthRequest, res: Response) => {
  try {
    const actor = getActor(req);
    if (!actor) return res.status(401).json({ success: false, error: "Not authenticated" });

    const paramsParsed = approvalIdParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) {
      return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Invalid approval id" });
    }

    const bodyParsed = approvalDecisionSchema.safeParse(req.body || {});
    if (!bodyParsed.success) {
      return res.status(400).json({ success: false, error: bodyParsed.error.errors[0]?.message || "Invalid approval note" });
    }

    const result = await approveSensitiveActionApproval({
      approvalId: paramsParsed.data.id,
      actor,
      reviewNote: bodyParsed.data.note || null,
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || null,
    });

    return res.json({ success: true, data: result });
  } catch (error: any) {
    console.error("approveApprovalController error:", error);
    return res.status(400).json({
      success: false,
      error: error?.message || "Failed to approve request",
      data: error?.approval ? { approval: error.approval } : undefined,
    });
  }
};

export const rejectApprovalController = async (req: AuthRequest, res: Response) => {
  try {
    const actor = getActor(req);
    if (!actor) return res.status(401).json({ success: false, error: "Not authenticated" });

    const paramsParsed = approvalIdParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) {
      return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Invalid approval id" });
    }

    const bodyParsed = approvalDecisionSchema.safeParse(req.body || {});
    if (!bodyParsed.success) {
      return res.status(400).json({ success: false, error: bodyParsed.error.errors[0]?.message || "Invalid approval note" });
    }

    const result = await rejectSensitiveActionApproval({
      approvalId: paramsParsed.data.id,
      actor,
      reviewNote: bodyParsed.data.note || null,
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || null,
    });

    return res.json({ success: true, data: result });
  } catch (error: any) {
    console.error("rejectApprovalController error:", error);
    return res.status(400).json({ success: false, error: error?.message || "Failed to reject request" });
  }
};
