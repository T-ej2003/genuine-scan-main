import { randomUUID } from "crypto";
import { Response } from "express";

import { CustomerVerifyRequest } from "../../middleware/customerVerifyAuth";
import { getB01PreAuthPrisma } from "../../rls-waves/session-b/b01/runtimeClients";
import { claimCustomerOwnership } from "../../rls-waves/session-b/b02/publicBoundaryRepository";
import { normalizeUserAgent } from "../../utils/security";
import {
  ensureDeviceClaimToken,
  getDeviceClaimTokenFromRequest,
  hashIp,
  hashToken,
} from "./shared";

const requestId = (req: CustomerVerifyRequest) =>
  String((req as CustomerVerifyRequest & { requestId?: string }).requestId || randomUUID());

const claim = async (req: CustomerVerifyRequest, res: Response, linkOnly: boolean) => {
  const sessionId = String(req.get("x-verification-session-id") || "").trim();
  const sessionProof = String(req.get("x-verification-session-proof") || "").trim();
  if (!sessionId || !sessionProof) {
    return res.status(400).json({ success: false, error: "A current verification session is required." });
  }
  const deviceToken = linkOnly ? getDeviceClaimTokenFromRequest(req) : ensureDeviceClaimToken(req, res);
  const normalizedUa = normalizeUserAgent(req.get("user-agent") || null);
  try {
    const result = await claimCustomerOwnership(getB01PreAuthPrisma(), {
      customerCapability: req.customerDatabaseCapability || null,
      sessionId,
      sessionProofHash: hashToken(sessionProof),
      deviceTokenHash: deviceToken ? hashToken(deviceToken) : null,
      ipHash: hashIp(req.ip),
      userAgentHash: normalizedUa ? hashToken(`ua:${normalizedUa}`) : null,
      linkOnly,
      checkedAt: new Date(),
      requestId: requestId(req),
    });
    return res.status(result.claimResult === "CLAIMED_DEVICE" || result.claimResult === "CLAIMED_USER" ? 201 : 200)
      .json({ success: true, data: result });
  } catch (error) {
    const message = String((error as Error)?.message || "");
    const status = /NOT_READY/.test(message) ? 409 : /DENIED|NOT_FOUND/.test(message) ? 403 : 500;
    return res.status(status).json({
      success: false,
      error: status === 409
        ? "Ownership is available only after product activation."
        : status === 403 ? "Ownership could not be proven for this product." : "Failed to update ownership.",
    });
  }
};

export const claimProductOwnership = (req: CustomerVerifyRequest, res: Response) =>
  claim(req, res, false);

export const linkDeviceClaimToCustomer = (req: CustomerVerifyRequest, res: Response) =>
  claim(req, res, true);
