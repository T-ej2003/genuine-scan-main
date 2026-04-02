import { Response } from "express";

import { CustomerVerifyRequest } from "../../middleware/customerVerifyAuth";
import { createAuditLog } from "../../services/auditService";
import { resolveVerifyUxPolicy } from "../../services/governanceService";
import { normalizeUserAgent } from "../../utils/security";
import {
  Prisma,
  QRStatus,
  buildOwnershipStatus,
  ensureDeviceClaimToken,
  getDeviceClaimTokenFromRequest,
  hashIp,
  hashToken,
  isOwnershipStorageMissingError,
  loadOwnershipByQrCodeId,
  normalizeCode,
  prisma,
  resolvePublicVerificationReadiness,
  verifyStepUpChallenge,
  type OwnershipRecord,
} from "./shared";

export const claimProductOwnership = async (req: CustomerVerifyRequest, res: Response) => {
  try {
    const normalizedCode = normalizeCode(req.params.code || "");
    if (!normalizedCode || normalizedCode.length < 2) {
      return res.status(400).json({
        success: false,
        error: "Invalid QR code format",
      });
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
      return res.status(404).json({
        success: false,
        error: "QR code not found",
      });
    }

    const verifyUxPolicy = await resolveVerifyUxPolicy(qrCode.licenseeId || null);
    const isBlocked = qrCode.status === QRStatus.BLOCKED;
    const isReady = resolvePublicVerificationReadiness(qrCode).isReady;
    const allowClaim = verifyUxPolicy.allowOwnershipClaim !== false;
    const customerUserId = req.customer?.userId || null;
    const deviceClaimToken = ensureDeviceClaimToken(req, res);
    const deviceTokenHash = deviceClaimToken ? hashToken(deviceClaimToken) : null;
    const requesterIpHash = hashIp(req.ip);
    const normalizedUa = normalizeUserAgent(req.get("user-agent") || null);
    const requesterUserAgentHash = normalizedUa ? hashToken(`ua:${normalizedUa}`) : null;

    const buildClaimResponse = (ownership: OwnershipRecord | null) => {
      const ownershipStatus = buildOwnershipStatus({
        ownership,
        customerUserId,
        deviceTokenHash,
        ipHash: requesterIpHash,
        isReady,
        isBlocked,
        allowClaim,
      });
      return {
        ownershipStatus,
        claimTimestamp: ownership?.claimedAt?.toISOString?.() || null,
      };
    };

    if (isBlocked || !isReady || !allowClaim) {
      return res.status(409).json({
        success: false,
        error: isBlocked
          ? "Claim not allowed for blocked products"
          : !isReady
            ? "Claim is available only after product activation"
            : "Claiming is currently disabled by policy",
      });
    }

    const existingOwnership = await loadOwnershipByQrCodeId(qrCode.id);
    if (existingOwnership) {
      const currentStatus = buildClaimResponse(existingOwnership).ownershipStatus;
      if (currentStatus.isOwnedByRequester) {
        if (customerUserId && !existingOwnership.userId) {
          const linked = await prisma.ownership.update({
            where: { qrCodeId: qrCode.id },
            data: {
              userId: customerUserId,
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

          await createAuditLog({
            action: "VERIFY_CLAIM_LINKED_TO_USER",
            entityType: "Ownership",
            entityId: qrCode.id,
            licenseeId: qrCode.licenseeId || undefined,
            ipAddress: req.ip,
            userAgent: req.get("user-agent") || undefined,
            details: {
              qrCodeId: qrCode.id,
              customerUserId,
            },
          });

          return res.json({
            success: true,
            data: {
              claimResult: "LINKED_TO_SIGNED_IN_ACCOUNT",
              message: "Device claim linked to your signed-in account.",
              ...buildClaimResponse(linked),
            },
          });
        }

        return res.json({
          success: true,
          data: {
            claimResult: "ALREADY_OWNED_BY_YOU",
            message: "This product is already owned by you on this device/account.",
            ...buildClaimResponse(existingOwnership),
          },
        });
      }

      await createAuditLog({
        action: "VERIFY_CLAIM_CONFLICT",
        entityType: "Ownership",
        entityId: qrCode.id,
        licenseeId: qrCode.licenseeId || undefined,
        ipAddress: req.ip,
        userAgent: req.get("user-agent") || undefined,
        details: {
          qrCodeId: qrCode.id,
          requesterUserId: customerUserId,
          hasDeviceToken: Boolean(deviceTokenHash),
          existingOwnership: true,
        },
      });

      const stepUp = await verifyStepUpChallenge(req);
      if (!stepUp.ok) {
        return res.status(403).json({
          success: false,
          error: stepUp.reason || "Suspicious ownership conflict requires challenge verification.",
          challenge: {
            required: true,
            methods: ["CAPTCHA"],
          },
        });
      }

      return res.json({
        success: true,
        data: {
          claimResult: "OWNED_BY_ANOTHER_USER",
          conflict: true,
          classification: "SUSPICIOUS_DUPLICATE",
          reasons: [
            "Ownership is already claimed by another account or device.",
            "If this is unexpected, report suspected counterfeit immediately.",
          ],
          warningMessage: "Ownership conflict detected. Treat this product as potential duplicate until reviewed.",
          ...buildClaimResponse(existingOwnership),
        },
      });
    }

    let createdOwnership: OwnershipRecord | null = null;
    try {
      createdOwnership = await prisma.ownership.create({
        data: {
          qrCodeId: qrCode.id,
          userId: customerUserId || null,
          deviceTokenHash,
          ipHash: requesterIpHash,
          userAgentHash: requesterUserAgentHash,
          claimSource: customerUserId ? "USER" : "DEVICE",
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
    } catch (error: any) {
      if (isOwnershipStorageMissingError(error)) {
        return res.status(503).json({
          success: false,
          error: "Ownership feature is temporarily unavailable. Please retry after maintenance.",
        });
      }

      if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === "P2002") {
        const existing = await loadOwnershipByQrCodeId(qrCode.id);
        if (existing) {
          const stepUp = await verifyStepUpChallenge(req);
          if (!stepUp.ok) {
            return res.status(403).json({
              success: false,
              error: stepUp.reason || "Suspicious ownership conflict requires challenge verification.",
              challenge: {
                required: true,
                methods: ["CAPTCHA"],
              },
            });
          }
          return res.json({
            success: true,
            data: {
              claimResult: "OWNED_BY_ANOTHER_USER",
              conflict: true,
              classification: "SUSPICIOUS_DUPLICATE",
              reasons: [
                "Ownership is already claimed by another account or device.",
                "If this is unexpected, report suspected counterfeit immediately.",
              ],
              warningMessage: "Ownership conflict detected. Treat this product as potential duplicate until reviewed.",
              ...buildClaimResponse(existing),
            },
          });
        }
      }
      throw error;
    }

    await createAuditLog({
      action: "VERIFY_CLAIM_SUCCESS",
      entityType: "Ownership",
      entityId: qrCode.id,
      licenseeId: qrCode.licenseeId || undefined,
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
      details: {
        qrCodeId: qrCode.id,
        customerUserId,
        claimSource: customerUserId ? "USER" : "DEVICE",
      },
    });

    return res.status(201).json({
      success: true,
      data: {
        claimResult: customerUserId ? "CLAIMED_USER" : "CLAIMED_DEVICE",
        message: customerUserId
          ? "Product ownership claimed and linked to your account."
          : "Product ownership claimed on this device.",
        ...buildClaimResponse(createdOwnership),
      },
    });
  } catch (error) {
    console.error("claimProductOwnership error:", error);
    return res.status(500).json({
      success: false,
      error: "Failed to claim ownership",
    });
  }
};

export const linkDeviceClaimToCustomer = async (req: CustomerVerifyRequest, res: Response) => {
  try {
    const customer = req.customer;
    if (!customer) {
      return res.status(401).json({
        success: false,
        error: "Customer authentication required",
      });
    }

    const normalizedCode = normalizeCode(req.params.code || "");
    if (!normalizedCode || normalizedCode.length < 2) {
      return res.status(400).json({
        success: false,
        error: "Invalid QR code format",
      });
    }

    const qrCode = await prisma.qRCode.findUnique({
      where: { code: normalizedCode },
      select: {
        id: true,
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
      return res.status(404).json({
        success: false,
        error: "QR code not found",
      });
    }

    const verifyUxPolicy = await resolveVerifyUxPolicy(qrCode.licenseeId || null);
    const allowClaim = verifyUxPolicy.allowOwnershipClaim !== false;
    const isBlocked = qrCode.status === QRStatus.BLOCKED;
    const isReady = resolvePublicVerificationReadiness(qrCode).isReady;

    if (!allowClaim || isBlocked || !isReady) {
      return res.status(409).json({
        success: false,
        error: "Ownership linking is not available for this product state.",
      });
    }

    const deviceClaimToken = getDeviceClaimTokenFromRequest(req);
    const deviceTokenHash = deviceClaimToken ? hashToken(deviceClaimToken) : null;
    const requesterIpHash = hashIp(req.ip);

    const existingOwnership = await loadOwnershipByQrCodeId(qrCode.id);
    if (!existingOwnership) {
      return res.status(404).json({
        success: false,
        error: "No device claim exists for this product yet.",
      });
    }

    if (existingOwnership.userId && existingOwnership.userId === customer.userId) {
      return res.json({
        success: true,
        data: {
          linkResult: "ALREADY_LINKED",
          message: "Ownership is already linked to your account.",
          ownershipStatus: buildOwnershipStatus({
            ownership: existingOwnership,
            customerUserId: customer.userId,
            deviceTokenHash,
            ipHash: requesterIpHash,
            isReady,
            isBlocked,
            allowClaim,
          }),
        },
      });
    }

    if (existingOwnership.userId && existingOwnership.userId !== customer.userId) {
      const stepUp = await verifyStepUpChallenge(req);
      if (!stepUp.ok) {
        return res.status(403).json({
          success: false,
          error: stepUp.reason || "Suspicious ownership link requires challenge verification.",
          challenge: {
            required: true,
            methods: ["CAPTCHA"],
          },
        });
      }
      return res.status(409).json({
        success: false,
        error: "Ownership is already linked to another account.",
      });
    }

    const ownershipStatus = buildOwnershipStatus({
      ownership: existingOwnership,
      customerUserId: null,
      deviceTokenHash,
      ipHash: requesterIpHash,
      isReady,
      isBlocked,
      allowClaim,
    });

    if (!ownershipStatus.isOwnedByRequester) {
      const stepUp = await verifyStepUpChallenge(req);
      if (!stepUp.ok) {
        return res.status(403).json({
          success: false,
          error: stepUp.reason || "Ownership linking challenge required.",
          challenge: {
            required: true,
            methods: ["CAPTCHA"],
          },
        });
      }
      return res.status(409).json({
        success: false,
        error: "Current device could not prove ownership for linking.",
      });
    }

    const linked = await prisma.ownership.update({
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

    await createAuditLog({
      action: "VERIFY_CLAIM_LINKED_TO_USER",
      entityType: "Ownership",
      entityId: qrCode.id,
      licenseeId: qrCode.licenseeId || undefined,
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
      details: {
        qrCodeId: qrCode.id,
        customerUserId: customer.userId,
      },
    });

    return res.json({
      success: true,
      data: {
        linkResult: "LINKED",
        message: "Device claim linked to your account.",
        ownershipStatus: buildOwnershipStatus({
          ownership: linked,
          customerUserId: customer.userId,
          deviceTokenHash,
          ipHash: requesterIpHash,
          isReady,
          isBlocked,
          allowClaim,
        }),
      },
    });
  } catch (error) {
    console.error("linkDeviceClaimToCustomer error:", error);
    return res.status(500).json({
      success: false,
      error: "Failed to link claim",
    });
  }
};
