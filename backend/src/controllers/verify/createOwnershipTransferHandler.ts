import { randomUUID } from "crypto";
import { Response } from "express";

import { CustomerVerifyRequest } from "../../middleware/customerVerifyAuth";
import { getB01PreAuthPrisma } from "../../rls-waves/session-b/b01/runtimeClients";
import { createCustomerOwnershipTransfer } from "../../rls-waves/session-b/b02/publicBoundaryRepository";
import { sendAuthEmail } from "../../services/auth/authEmailService";
import {
  OWNERSHIP_TRANSFER_TTL_HOURS,
  buildOwnershipTransferLink,
  createOwnershipTransferSchema,
  hashToken,
  normalizeCode,
  randomOpaqueToken,
} from "./shared";

export const createOwnershipTransfer = async (req: CustomerVerifyRequest, res: Response) => {
  const parsed = createOwnershipTransferSchema.safeParse(req.body || {});
  const code = normalizeCode(req.params.code || "");
  if (!parsed.success || !code) {
    return res.status(400).json({ success: false, error: "Invalid ownership transfer payload" });
  }
  if (!req.customer || !req.customerDatabaseCapability) {
    return res.status(401).json({ success: false, error: "Customer authentication required" });
  }
  const rawToken = randomOpaqueToken(32);
  const checkedAt = new Date();
  const expiresAt = new Date(checkedAt.getTime() + OWNERSHIP_TRANSFER_TTL_HOURS * 60 * 60 * 1000);
  const recipientEmail = parsed.data.recipientEmail?.trim().toLowerCase() || null;
  try {
    const result = await createCustomerOwnershipTransfer(getB01PreAuthPrisma(), {
      customerCapability: req.customerDatabaseCapability,
      requestedCode: code,
      recipientEmail,
      tokenHash: hashToken(rawToken),
      expiresAt,
      checkedAt,
      requestId: String((req as CustomerVerifyRequest & { requestId?: string }).requestId || randomUUID()),
    });
    const transferLink = buildOwnershipTransferLink(code, rawToken);
    await Promise.allSettled(
      [req.customer.email, recipientEmail].filter(Boolean).map((address) =>
        sendAuthEmail({
          toAddress: String(address),
          subject: "MSCQR ownership transfer",
          text: `Review this ownership transfer:\n${transferLink}\n\nIt expires at ${expiresAt.toISOString()}.`,
          template: address === recipientEmail ? "verify_transfer_recipient" : "verify_transfer_sender",
          userAgent: req.get("user-agent") || undefined,
        })
      )
    );
    return res.status(201).json({
      success: true,
      data: {
        message: "Ownership transfer created. Share the secure acceptance link with the next owner.",
        transferLink,
        transferToken: rawToken,
        ownershipTransfer: {
          id: result.transferId,
          state: "pending_buyer_action",
          status: result.status,
          active: true,
          expiresAt: result.expiresAt,
          canCancel: true,
          acceptUrl: transferLink,
        },
      },
    });
  } catch {
    return res.status(403).json({ success: false, error: "Only the current signed-in owner can start a transfer." });
  }
};
