import { randomUUID } from "crypto";
import { Response } from "express";

import { CustomerVerifyRequest } from "../../middleware/customerVerifyAuth";
import { getB01PreAuthPrisma } from "../../rls-waves/session-b/b01/runtimeClients";
import { cancelCustomerOwnershipTransfer } from "../../rls-waves/session-b/b02/publicBoundaryRepository";
import { sendAuthEmail } from "../../services/auth/authEmailService";
import { cancelOwnershipTransferSchema, normalizeCode } from "./shared";

export const cancelOwnershipTransfer = async (req: CustomerVerifyRequest, res: Response) => {
  const parsed = cancelOwnershipTransferSchema.safeParse(req.body || {});
  const code = normalizeCode(req.params.code || "");
  if (!parsed.success || !code) {
    return res.status(400).json({ success: false, error: "Invalid cancellation payload" });
  }
  if (!req.customerDatabaseCapability) {
    return res.status(401).json({ success: false, error: "Customer authentication required" });
  }
  try {
    const result = await cancelCustomerOwnershipTransfer(getB01PreAuthPrisma(), {
      customerCapability: req.customerDatabaseCapability,
      requestedCode: code,
      transferId: parsed.data.transferId || null,
      checkedAt: new Date(),
      requestId: String((req as CustomerVerifyRequest & { requestId?: string }).requestId || randomUUID()),
    });
    const recipients = Array.isArray(result.notificationEmails)
      ? [...new Set(result.notificationEmails.filter((value): value is string => typeof value === "string" && value.length > 0))]
      : [];
    await Promise.allSettled(recipients.map((address) =>
      sendAuthEmail({
        toAddress: address,
        subject: "MSCQR ownership transfer cancelled",
        text: `The pending ownership transfer for QR ${code} has been cancelled.`,
        template: "verify_transfer_cancelled",
        userAgent: req.get("user-agent") || undefined,
      })
    ));
    return res.json({
      success: true,
      data: {
        message: "Ownership transfer cancelled.",
        ownershipTransfer: { id: result.transferId, state: "cancelled", status: "CANCELLED", active: false },
      },
    });
  } catch {
    return res.status(403).json({ success: false, error: "Only the transfer initiator can cancel it." });
  }
};
