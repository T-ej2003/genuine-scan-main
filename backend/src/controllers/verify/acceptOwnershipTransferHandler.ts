import { randomUUID } from "crypto";
import { Response } from "express";

import { CustomerVerifyRequest } from "../../middleware/customerVerifyAuth";
import { getB01PreAuthPrisma } from "../../rls-waves/session-b/b01/runtimeClients";
import { acceptCustomerOwnershipTransfer } from "../../rls-waves/session-b/b02/publicBoundaryRepository";
import { sendAuthEmail } from "../../services/auth/authEmailService";
import { normalizeUserAgent } from "../../utils/security";
import { acceptOwnershipTransferSchema, hashIp, hashToken } from "./shared";

export const acceptOwnershipTransfer = async (req: CustomerVerifyRequest, res: Response) => {
  const parsed = acceptOwnershipTransferSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return res.status(400).json({ success: false, error: "Invalid transfer acceptance payload" });
  }
  if (!req.customerDatabaseCapability) {
    return res.status(401).json({ success: false, error: "Customer authentication required" });
  }
  const normalizedUa = normalizeUserAgent(req.get("user-agent") || null);
  try {
    const result = await acceptCustomerOwnershipTransfer(getB01PreAuthPrisma(), {
      customerCapability: req.customerDatabaseCapability,
      tokenHash: hashToken(parsed.data.token),
      ipHash: hashIp(req.ip),
      userAgentHash: normalizedUa ? hashToken(`ua:${normalizedUa}`) : null,
      checkedAt: new Date(),
      requestId: String((req as CustomerVerifyRequest & { requestId?: string }).requestId || randomUUID()),
    });
    const recipients = Array.isArray(result.notificationEmails)
      ? [...new Set(result.notificationEmails.filter((value): value is string => typeof value === "string" && value.length > 0))]
      : [];
    await Promise.allSettled(recipients.map((address) =>
      sendAuthEmail({
        toAddress: address,
        subject: "MSCQR ownership transfer accepted",
        text: `The ownership transfer for QR ${String(result.code || "")} has been accepted successfully.`,
        template: "verify_transfer_accepted",
        userAgent: req.get("user-agent") || undefined,
      })
    ));
    return res.json({
      success: true,
      data: {
        message: "Ownership transfer accepted. This product is now linked to your signed-in account.",
        code: result.code,
        ownershipStatus: result.ownershipStatus,
        ownershipTransfer: { id: result.transferId, state: "accepted", status: "ACCEPTED", active: false },
      },
    });
  } catch {
    return res.status(403).json({ success: false, error: "Transfer link is invalid, expired, or bound to another customer." });
  }
};
