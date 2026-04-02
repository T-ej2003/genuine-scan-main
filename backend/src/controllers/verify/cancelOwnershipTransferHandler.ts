import { Response } from "express";

import { CustomerVerifyRequest } from "../../middleware/customerVerifyAuth";
import { createAuditLog } from "../../services/auditService";
import { sendAuthEmail } from "../../services/auth/authEmailService";
import {
  OwnershipTransferStatus,
  QRStatus,
  cancelOwnershipTransferSchema,
  createOwnershipTransferView,
  expirePendingOwnershipTransfers,
  normalizeCode,
  prisma,
  resolvePublicVerificationReadiness,
} from "./shared";

export const cancelOwnershipTransfer = async (req: CustomerVerifyRequest, res: Response) => {
  try {
    const customer = req.customer;
    if (!customer) {
      return res.status(401).json({ success: false, error: "Customer authentication required" });
    }

    const parsed = cancelOwnershipTransferSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: parsed.error.errors[0]?.message || "Invalid cancellation payload",
      });
    }

    const normalizedCode = normalizeCode(req.params.code || "");
    if (!normalizedCode || normalizedCode.length < 2) {
      return res.status(400).json({ success: false, error: "Invalid QR code format" });
    }

    const qrCode = await prisma.qRCode.findUnique({
      where: { code: normalizedCode },
      select: {
        id: true,
        code: true,
        licenseeId: true,
        status: true,
        printJobId: true,
        printJob: {
          select: {
            status: true,
            pipelineState: true,
            confirmedAt: true,
            printSession: {
              select: {
                status: true,
                completedAt: true,
              },
            },
          },
        },
      },
    });
    if (!qrCode) {
      return res.status(404).json({ success: false, error: "QR code not found" });
    }

    await expirePendingOwnershipTransfers({ qrCodeId: qrCode.id });
    const transfer = await prisma.ownershipTransfer.findFirst({
      where: {
        qrCodeId: qrCode.id,
        status: OwnershipTransferStatus.PENDING,
        ...(parsed.data.transferId ? { id: parsed.data.transferId } : {}),
      },
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      select: {
        id: true,
        qrCodeId: true,
        ownershipId: true,
        initiatedByCustomerId: true,
        initiatedByEmail: true,
        recipientEmail: true,
        status: true,
        expiresAt: true,
        acceptedAt: true,
        cancelledAt: true,
        lastViewedAt: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    if (!transfer) {
      return res.status(404).json({ success: false, error: "No active transfer found for this product." });
    }
    if (transfer.initiatedByCustomerId !== customer.userId) {
      return res.status(403).json({ success: false, error: "Only the transfer initiator can cancel it." });
    }

    const cancelled = await prisma.ownershipTransfer.update({
      where: { id: transfer.id },
      data: {
        status: OwnershipTransferStatus.CANCELLED,
        cancelledAt: new Date(),
      },
      select: {
        id: true,
        qrCodeId: true,
        ownershipId: true,
        initiatedByCustomerId: true,
        initiatedByEmail: true,
        recipientEmail: true,
        status: true,
        expiresAt: true,
        acceptedAt: true,
        cancelledAt: true,
        lastViewedAt: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    await createAuditLog({
      action: "VERIFY_TRANSFER_CANCELLED",
      entityType: "OwnershipTransfer",
      entityId: cancelled.id,
      licenseeId: qrCode.licenseeId || undefined,
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
      details: {
        qrCodeId: qrCode.id,
      },
    });

    await Promise.allSettled(
      [cancelled.initiatedByEmail, cancelled.recipientEmail]
        .filter(Boolean)
        .map((email) =>
          sendAuthEmail({
            toAddress: String(email),
            subject: "MSCQR ownership transfer cancelled",
            text: `The pending ownership transfer for QR ${qrCode.code} has been cancelled.`,
            template: "verify_transfer_cancelled",
            licenseeId: qrCode.licenseeId || null,
            userAgent: req.get("user-agent") || undefined,
          })
        )
    );

    return res.json({
      success: true,
      data: {
        message: "Ownership transfer cancelled.",
        ownershipTransfer: createOwnershipTransferView({
          code: qrCode.code,
          transfer: cancelled,
          customerUserId: customer.userId,
          ownershipStatus: {
            isClaimed: true,
            claimedAt: null,
            isOwnedByRequester: true,
            isClaimedByAnother: false,
            canClaim: false,
            state: "owned_by_you",
            matchMethod: "user",
          },
          isReady: resolvePublicVerificationReadiness(qrCode).isReady,
          isBlocked: qrCode.status === QRStatus.BLOCKED,
        }),
      },
    });
  } catch (error) {
    console.error("cancelOwnershipTransfer error:", error);
    return res.status(500).json({ success: false, error: "Failed to cancel ownership transfer" });
  }
};
