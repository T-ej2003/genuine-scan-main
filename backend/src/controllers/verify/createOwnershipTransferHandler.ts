import { Response } from "express";

import { CustomerVerifyRequest } from "../../middleware/customerVerifyAuth";
import { createAuditLog } from "../../services/auditService";
import { sendAuthEmail } from "../../services/auth/authEmailService";
import { resolveVerifyUxPolicy } from "../../services/governanceService";
import { normalizeUserAgent } from "../../utils/security";
import {
  OwnershipTransferStatus,
  OWNERSHIP_TRANSFER_TTL_HOURS,
  QRStatus,
  buildOwnershipStatus,
  buildOwnershipTransferLink,
  createOwnershipTransferSchema,
  createOwnershipTransferView,
  expirePendingOwnershipTransfers,
  getDeviceClaimTokenFromRequest,
  hashIp,
  hashToken,
  loadOwnershipByQrCodeId,
  normalizeCode,
  prisma,
  randomOpaqueToken,
  resolvePublicVerificationReadiness,
} from "./shared";

export const createOwnershipTransfer = async (req: CustomerVerifyRequest, res: Response) => {
  try {
    const customer = req.customer;
    if (!customer) {
      return res.status(401).json({ success: false, error: "Customer authentication required" });
    }

    const parsed = createOwnershipTransferSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: parsed.error.errors[0]?.message || "Invalid ownership transfer payload",
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

    const verifyUxPolicy = await resolveVerifyUxPolicy(qrCode.licenseeId || null);
    const allowClaim = verifyUxPolicy.allowOwnershipClaim !== false;
    const isBlocked = qrCode.status === QRStatus.BLOCKED;
    const isReady = resolvePublicVerificationReadiness(qrCode).isReady;
    if (!allowClaim || isBlocked || !isReady) {
      return res.status(409).json({
        success: false,
        error: "Ownership transfer is not available for this product state.",
      });
    }

    const deviceClaimToken = getDeviceClaimTokenFromRequest(req);
    const deviceTokenHash = deviceClaimToken ? hashToken(deviceClaimToken) : null;
    const requesterIpHash = hashIp(req.ip);

    let ownership = await loadOwnershipByQrCodeId(qrCode.id);
    if (!ownership) {
      return res.status(409).json({
        success: false,
        error: "Claim ownership before starting a resale transfer.",
      });
    }

    let ownershipStatus = buildOwnershipStatus({
      ownership,
      customerUserId: customer.userId,
      deviceTokenHash,
      ipHash: requesterIpHash,
      isReady,
      isBlocked,
      allowClaim,
    });

    if (!ownershipStatus.isOwnedByRequester) {
      return res.status(403).json({
        success: false,
        error: "Only the current signed-in owner can start a transfer.",
      });
    }

    if (ownership.userId !== customer.userId) {
      ownership = await prisma.ownership.update({
        where: { qrCodeId: qrCode.id },
        data: {
          userId: customer.userId,
          linkedAt: new Date(),
          claimSource: "DEVICE_AND_USER",
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
      ownershipStatus = buildOwnershipStatus({
        ownership,
        customerUserId: customer.userId,
        deviceTokenHash,
        ipHash: requesterIpHash,
        isReady,
        isBlocked,
        allowClaim,
      });
    }

    await expirePendingOwnershipTransfers({ qrCodeId: qrCode.id });
    await prisma.ownershipTransfer.updateMany({
      where: {
        qrCodeId: qrCode.id,
        status: OwnershipTransferStatus.PENDING,
      },
      data: {
        status: OwnershipTransferStatus.CANCELLED,
        cancelledAt: new Date(),
      },
    });

    const rawToken = randomOpaqueToken(32);
    const expiresAt = new Date(Date.now() + OWNERSHIP_TRANSFER_TTL_HOURS * 60 * 60 * 1000);
    const recipientEmail = parsed.data.recipientEmail?.trim().toLowerCase() || null;
    const normalizedUa = normalizeUserAgent(req.get("user-agent") || null);

    const transfer = await prisma.ownershipTransfer.create({
      data: {
        qrCodeId: qrCode.id,
        ownershipId: ownership.id,
        initiatedByCustomerId: customer.userId,
        initiatedByEmail: customer.email,
        recipientEmail,
        tokenHash: hashToken(rawToken),
        status: OwnershipTransferStatus.PENDING,
        expiresAt,
        metadata: {
          requestedFromIpHash: requesterIpHash,
          requestedUserAgentHash: normalizedUa ? hashToken(`ua:${normalizedUa}`) : null,
        },
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

    const transferLink = buildOwnershipTransferLink(qrCode.code, rawToken);

    await createAuditLog({
      action: "VERIFY_TRANSFER_CREATED",
      entityType: "OwnershipTransfer",
      entityId: transfer.id,
      licenseeId: qrCode.licenseeId || undefined,
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
      details: {
        qrCodeId: qrCode.id,
        recipientEmail: recipientEmail || null,
        expiresAt: expiresAt.toISOString(),
      },
    });

    const emailJobs: Promise<unknown>[] = [];
    if (recipientEmail) {
      emailJobs.push(
        sendAuthEmail({
          toAddress: recipientEmail,
          subject: "MSCQR ownership transfer ready to accept",
          text:
            `A current owner started a product transfer for QR ${qrCode.code}.\n\n` +
            `Open this secure link to review and accept the transfer:\n${transferLink}\n\n` +
            `This link expires at ${expiresAt.toISOString()}.`,
          template: "verify_transfer_recipient",
          licenseeId: qrCode.licenseeId || null,
          userAgent: req.get("user-agent") || undefined,
        })
      );
    }
    if (customer.email) {
      emailJobs.push(
        sendAuthEmail({
          toAddress: customer.email,
          subject: "MSCQR ownership transfer created",
          text:
            `Your transfer for QR ${qrCode.code} is active.\n\n` +
            `Share this secure link with the next owner:\n${transferLink}\n\n` +
            `It expires at ${expiresAt.toISOString()}.`,
          template: "verify_transfer_sender",
          licenseeId: qrCode.licenseeId || null,
          userAgent: req.get("user-agent") || undefined,
        })
      );
    }
    await Promise.allSettled(emailJobs);

    return res.status(201).json({
      success: true,
      data: {
        message: "Ownership transfer created. Share the secure acceptance link with the next owner.",
        transferLink,
        transferToken: rawToken,
        ownershipStatus,
        ownershipTransfer: createOwnershipTransferView({
          code: qrCode.code,
          transfer,
          rawToken,
          customerUserId: customer.userId,
          ownershipStatus,
          isReady,
          isBlocked,
          transferRequested: true,
        }),
      },
    });
  } catch (error) {
    console.error("createOwnershipTransfer error:", error);
    return res.status(500).json({ success: false, error: "Failed to create ownership transfer" });
  }
};
