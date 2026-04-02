import { Response } from "express";

import { CustomerVerifyRequest } from "../../middleware/customerVerifyAuth";
import { createAuditLogSafely } from "../../services/auditService";
import { sendAuthEmail } from "../../services/auth/authEmailService";
import { recordCustomerTrustCredential, resolveCustomerTrustLevel } from "../../services/customerTrustService";
import { normalizeUserAgent } from "../../utils/security";
import {
  OwnershipTransferStatus,
  QRStatus,
  acceptOwnershipTransferSchema,
  buildOwnershipStatus,
  createOwnershipTransferView,
  hashIp,
  hashToken,
  loadOwnershipTransferByRawToken,
  prisma,
  resolvePublicVerificationReadiness,
} from "./shared";

export const acceptOwnershipTransfer = async (req: CustomerVerifyRequest, res: Response) => {
  try {
    const customer = req.customer;
    if (!customer) {
      return res.status(401).json({ success: false, error: "Customer authentication required" });
    }

    const parsed = acceptOwnershipTransferSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: parsed.error.errors[0]?.message || "Invalid transfer acceptance payload",
      });
    }

    const transfer = await loadOwnershipTransferByRawToken(parsed.data.token);
    if (!transfer || transfer.status !== OwnershipTransferStatus.PENDING) {
      return res.status(404).json({ success: false, error: "Transfer link is invalid or has expired." });
    }
    if (transfer.initiatedByCustomerId === customer.userId) {
      return res.status(409).json({ success: false, error: "The current owner cannot accept their own transfer." });
    }

    const qrCode = await prisma.qRCode.findUnique({
      where: { id: transfer.qrCodeId },
      select: {
        id: true,
        code: true,
        status: true,
        licenseeId: true,
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

    const isBlocked = qrCode.status === QRStatus.BLOCKED;
    const isReady = resolvePublicVerificationReadiness(qrCode).isReady;
    if (isBlocked || !isReady) {
      return res.status(409).json({
        success: false,
        error: "This product is not in a transferable state.",
      });
    }

    const normalizedUa = normalizeUserAgent(req.get("user-agent") || null);
    const requesterIpHash = hashIp(req.ip);

    const result = await prisma.$transaction(async (tx) => {
      const currentTransfer = await tx.ownershipTransfer.findUnique({
        where: { id: transfer.id },
      });
      if (!currentTransfer || currentTransfer.status !== OwnershipTransferStatus.PENDING) {
        throw new Error("Transfer link is no longer active.");
      }

      const updatedOwnership = await tx.ownership.update({
        where: { id: transfer.ownershipId },
        data: {
          userId: customer.userId,
          linkedAt: new Date(),
          claimedAt: new Date(),
          ipHash: requesterIpHash,
          userAgentHash: normalizedUa ? hashToken(`ua:${normalizedUa}`) : null,
          claimSource: "USER_TRANSFERRED",
        },
        select: {
          id: true,
          userId: true,
          claimedAt: true,
          deviceTokenHash: true,
          ipHash: true,
          userAgentHash: true,
          claimSource: true,
          linkedAt: true,
        },
      });

      const acceptedTransfer = await tx.ownershipTransfer.update({
        where: { id: transfer.id },
        data: {
          status: OwnershipTransferStatus.ACCEPTED,
          acceptedAt: new Date(),
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

      await tx.ownershipTransfer.updateMany({
        where: {
          qrCodeId: transfer.qrCodeId,
          status: OwnershipTransferStatus.PENDING,
          id: { not: transfer.id },
        },
        data: {
          status: OwnershipTransferStatus.CANCELLED,
          cancelledAt: new Date(),
        },
      });

      return { updatedOwnership, acceptedTransfer };
    });

    await createAuditLogSafely({
      action: "VERIFY_TRANSFER_ACCEPTED",
      entityType: "OwnershipTransfer",
      entityId: transfer.id,
      licenseeId: qrCode.licenseeId || undefined,
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
      details: {
        qrCodeId: qrCode.id,
        recipientCustomerId: customer.userId,
      },
    });

    await recordCustomerTrustCredential({
      qrCodeId: qrCode.id,
      customerUserId: customer.userId,
      customerEmail: customer.email,
      deviceTokenHash: result.updatedOwnership.deviceTokenHash || null,
      trustLevel: resolveCustomerTrustLevel({
        customerUserId: customer.userId,
        deviceTokenHash: result.updatedOwnership.deviceTokenHash || null,
        ownershipStatus: {
          isOwnedByRequester: true,
          matchMethod: "user",
        },
        customerAuthStrength: req.customer?.authStrength || null,
      }),
      source: "OWNERSHIP_TRANSFER_ACCEPT",
      claimedAt: result.updatedOwnership.claimedAt,
      linkedAt: result.updatedOwnership.linkedAt,
      lastAssertionAt:
        req.customer?.authStrength === "PASSKEY" && req.customer?.webauthnVerifiedAt
          ? new Date(req.customer.webauthnVerifiedAt)
          : null,
    });

    await Promise.allSettled(
      [transfer.initiatedByEmail, customer.email, transfer.recipientEmail]
        .filter(Boolean)
        .map((email) =>
          sendAuthEmail({
            toAddress: String(email),
            subject: "MSCQR ownership transfer accepted",
            text: `The ownership transfer for QR ${qrCode.code} has been accepted successfully.`,
            template: "verify_transfer_accepted",
            licenseeId: qrCode.licenseeId || null,
            userAgent: req.get("user-agent") || undefined,
          })
        )
    );

    const ownershipStatus = buildOwnershipStatus({
      ownership: result.updatedOwnership,
      customerUserId: customer.userId,
      isReady,
      isBlocked,
      allowClaim: true,
    });

    return res.json({
      success: true,
      data: {
        message: "Ownership transfer accepted. This product is now linked to your signed-in account.",
        code: qrCode.code,
        ownershipStatus,
        ownershipTransfer: createOwnershipTransferView({
          code: qrCode.code,
          transfer: result.acceptedTransfer,
          customerUserId: customer.userId,
          ownershipStatus,
          isReady,
          isBlocked,
        }),
      },
    });
  } catch (error: any) {
    console.error("acceptOwnershipTransfer error:", error);
    return res.status(500).json({
      success: false,
      error: error?.message || "Failed to accept ownership transfer",
    });
  }
};
