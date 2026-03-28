import { Response } from "express";
import { z } from "zod";

import { CustomerVerifyRequest } from "../../middleware/customerVerifyAuth";
import { createAuditLog } from "../../services/auditService";
import { resolveVerifyUxPolicy } from "../../services/governanceService";
import { recordScan } from "../../services/qrService";
import { evaluateScanAndEnforcePolicy } from "../../services/policyEngineService";
import { getScanInsight } from "../../services/scanInsightService";
import { assessDuplicateRisk, deriveAnomalyModelScore } from "../../services/duplicateRiskService";
import {
  buildPublicIntegrityErrorBody,
  isPublicIntegrityDependencyError,
} from "../../utils/publicIntegrityGuard";
import {
  QRStatus,
  VerifyClassification,
  buildContainment,
  buildOwnershipStatus,
  buildOwnershipTransferView,
  buildRepeatWarningMessage,
  buildRiskExplanation,
  buildScanSummary,
  buildSecurityContainmentReasons,
  buildVerificationTimeline,
  delay,
  deriveRequestDeviceFingerprint,
  getDeviceClaimTokenFromRequest,
  hashIp,
  hashToken,
  isQrReadyForCustomerUse,
  loadOwnershipByQrCodeId,
  loadOwnershipTransferByRawToken,
  loadPendingOwnershipTransferForQr,
  mapBatch,
  mapLicensee,
  normalizeCode,
  prisma,
  resolveDuplicateRiskProfile,
  statusNotReadyReason,
} from "./shared";
import {
  buildBlockedVerificationPayload,
  buildMissingQrVerificationPayload,
  buildNotReadyVerificationPayload,
} from "./verificationResponseBuilders";

const verifyParamsSchema = z.object({
  code: z.string().trim().min(2).max(128),
}).strict();

const verifyQuerySchema = z.object({
  transfer: z.string().trim().max(512).optional(),
  device: z.string().trim().max(256).optional(),
  lat: z.union([z.string().trim().max(40), z.number()]).optional(),
  lon: z.union([z.string().trim().max(40), z.number()]).optional(),
  acc: z.union([z.string().trim().max(40), z.number()]).optional(),
}).strict();

export const verifyQRCode = async (req: CustomerVerifyRequest, res: Response) => {
  try {
    const paramsParsed = verifyParamsSchema.safeParse(req.params || {});
    const queryParsed = verifyQuerySchema.safeParse(req.query || {});
    if (!paramsParsed.success || !queryParsed.success) {
      const error = paramsParsed.success ? queryParsed.error?.errors[0] : paramsParsed.error?.errors[0];
      return res.status(400).json({
        success: false,
        error: error?.message || "Invalid QR code format",
      });
    }

    const normalizedCode = normalizeCode(paramsParsed.data.code);
    const requestQuery = queryParsed.data;
    const defaultVerifyUxPolicy = await resolveVerifyUxPolicy(null);

    const qrCode = await prisma.qRCode.findUnique({
      where: { code: normalizedCode },
      include: {
        licensee: {
          select: {
            id: true,
            name: true,
            prefix: true,
            brandName: true,
            location: true,
            website: true,
            supportEmail: true,
            supportPhone: true,
            suspendedAt: true,
            suspendedReason: true,
          },
        },
        batch: {
          select: {
            id: true,
            name: true,
            printedAt: true,
            suspendedAt: true,
            suspendedReason: true,
            manufacturer: { select: { id: true, name: true, email: true, location: true, website: true } },
          },
        },
      },
    });

    if (!qrCode) {
      await delay(150 + Math.floor(Math.random() * 150));
      const reasons = ["Code not found in registry."];
      await createAuditLog({
        action: "VERIFY_FAILED",
        entityType: "QRCode",
        entityId: normalizedCode,
        details: { reason: "Code not found" },
        ipAddress: req.ip,
      });

      return res.json({
        success: true,
        data: buildMissingQrVerificationPayload({
          normalizedCode,
          reasons,
          verifyUxPolicy: defaultVerifyUxPolicy,
        }),
      });
    }

    const verifyUxPolicy = await resolveVerifyUxPolicy(qrCode.licenseeId || null);
    const riskProfile = await resolveDuplicateRiskProfile(qrCode.licenseeId || null);

    const customerUserId = req.customer?.userId || null;
    const requestedTransferToken = String(requestQuery.transfer || "").trim() || null;
    const requestDeviceFingerprint = deriveRequestDeviceFingerprint(req);
    const deviceClaimToken = getDeviceClaimTokenFromRequest(req);
    const deviceTokenHash = deviceClaimToken ? hashToken(deviceClaimToken) : null;
    const requesterIpHash = hashIp(req.ip);
    const containment = buildContainment(qrCode);
    const qrBlocked = qrCode.status === QRStatus.BLOCKED;
    const qrReady = isQrReadyForCustomerUse(qrCode.status);
    const baseOwnership = await loadOwnershipByQrCodeId(qrCode.id, { strictStorage: true });
    const baseOwnershipStatus = buildOwnershipStatus({
      ownership: baseOwnership,
      customerUserId,
      deviceTokenHash,
      ipHash: requesterIpHash,
      isReady: qrReady,
      isBlocked: qrBlocked,
      allowClaim: verifyUxPolicy.allowOwnershipClaim,
    });
    const scanInsight = await getScanInsight(qrCode.id, requestDeviceFingerprint, {
      currentIpAddress: req.ip || null,
      licenseeId: qrCode.licenseeId || null,
      currentCustomerUserId: customerUserId,
      currentOwnershipId: baseOwnership?.id || null,
      currentActorTrustedOwnerContext: baseOwnershipStatus.isOwnedByRequester,
      strictStorage: true,
    });
    const baseScanSummary = buildScanSummary({
      scanCount: Number(qrCode.scanCount || 0),
      scannedAt: qrCode.scannedAt,
      scanInsight,
    });
    const baseOwnershipTransfer = buildOwnershipTransferView({
      code: qrCode.code,
      transfer: requestedTransferToken
        ? await loadOwnershipTransferByRawToken(requestedTransferToken)
        : await loadPendingOwnershipTransferForQr(qrCode.id),
      rawToken: requestedTransferToken,
      customerUserId,
      ownershipStatus: baseOwnershipStatus,
      isReady: qrReady,
      isBlocked: qrBlocked,
      transferRequested: Boolean(requestedTransferToken),
    });

    const basePayload = {
      code: qrCode.code,
      status: qrCode.status,
      containment,
      licensee: mapLicensee(qrCode.licensee),
      batch: mapBatch(qrCode.batch),
      batchName: qrCode.batch?.name || null,
      printedAt: qrCode.batch?.printedAt || null,
      scanCount: baseScanSummary.totalScans,
      firstScanAt: scanInsight.firstScanAt,
      firstScanLocation: scanInsight.firstScanLocation,
      latestScanAt: scanInsight.latestScanAt,
      latestScanLocation: scanInsight.latestScanLocation,
      previousScanAt: scanInsight.previousScanAt,
      previousScanLocation: scanInsight.previousScanLocation,
      scanSignals: scanInsight.signals,
    };

    if (qrCode.status === QRStatus.BLOCKED) {
      return res.json({
        success: true,
        data: buildBlockedVerificationPayload({
          basePayload,
          containment,
          scanSummary: baseScanSummary,
          ownershipStatus: baseOwnershipStatus,
          ownershipTransfer: baseOwnershipTransfer,
          verifyUxPolicy,
        }),
      });
    }

    if (
      qrCode.status === QRStatus.DORMANT ||
      qrCode.status === QRStatus.ACTIVE ||
      qrCode.status === QRStatus.ALLOCATED ||
      qrCode.status === QRStatus.ACTIVATED
    ) {
      const reasons = [statusNotReadyReason(qrCode.status)];

      return res.json({
        success: true,
        data: buildNotReadyVerificationPayload({
          basePayload,
          status: qrCode.status,
          scanSummary: baseScanSummary,
          ownershipStatus: baseOwnershipStatus,
          ownershipTransfer: baseOwnershipTransfer,
          verifyUxPolicy,
          reasons,
        }),
      });
    }

    const toNum = (v: unknown) => {
      const n = parseFloat(String(v));
      return Number.isFinite(n) ? n : null;
    };

    const latitude = toNum(requestQuery.lat);
    const longitude = toNum(requestQuery.lon);
    const accuracy = toNum(requestQuery.acc);

    const { isFirstScan, qrCode: updated } = await recordScan(
      normalizedCode,
      {
        ipAddress: req.ip,
        userAgent: req.get("user-agent") || null,
        device: requestDeviceFingerprint,
        latitude,
        longitude,
        accuracy,
        customerUserId,
        ownershipId: baseOwnershipStatus.isOwnedByRequester ? baseOwnership?.id || null : null,
        ownershipMatchMethod: baseOwnershipStatus.isOwnedByRequester ? baseOwnershipStatus.matchMethod || null : null,
        isTrustedOwnerContext: baseOwnershipStatus.isOwnedByRequester,
      },
      { strictStorage: true }
    );

    await createAuditLog({
      action: "VERIFY_SUCCESS",
      entityType: "QRCode",
      entityId: qrCode.id,
      details: {
        isFirstScan,
        scanCount: updated.scanCount ?? 0,
      },
      ipAddress: req.ip,
    });

    const policy = await evaluateScanAndEnforcePolicy({
      qrCodeId: updated.id,
      code: updated.code,
      licenseeId: updated.licenseeId,
      batchId: updated.batchId ?? null,
      manufacturerId: updated.batch?.manufacturer?.id || null,
      scanCount: updated.scanCount ?? 0,
      scannedAt: new Date(),
      latitude,
      longitude,
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || null,
      strictStorage: true,
    });

    const blockedByPolicy = Boolean(policy.autoBlockedQr || policy.autoBlockedBatch);
    const finalStatus = blockedByPolicy ? QRStatus.BLOCKED : updated.status;
    const isBlocked = blockedByPolicy || finalStatus === QRStatus.BLOCKED;
    const isReady = isQrReadyForCustomerUse(finalStatus);

    const firstScanTime = updated.scannedAt ? new Date(updated.scannedAt) : null;
    const postScanInsight = await getScanInsight(updated.id, requestDeviceFingerprint, {
      currentIpAddress: req.ip || null,
      licenseeId: updated.licenseeId || null,
      currentCustomerUserId: customerUserId,
      currentOwnershipId: baseOwnership?.id || null,
      currentActorTrustedOwnerContext: baseOwnershipStatus.isOwnedByRequester,
      strictStorage: true,
    });
    const postScanSummary = buildScanSummary({
      scanCount: Number(updated.scanCount || 0),
      scannedAt: firstScanTime,
      scanInsight: postScanInsight,
    });

    const runtimeContainment = buildContainment(updated);
    const hasContainment =
      Boolean(runtimeContainment.qrUnderInvestigation) ||
      Boolean(runtimeContainment.batchSuspended) ||
      Boolean(runtimeContainment.orgSuspended);

    const ownership = await loadOwnershipByQrCodeId(updated.id, { strictStorage: true });
    const ownershipStatus = buildOwnershipStatus({
      ownership,
      customerUserId,
      deviceTokenHash,
      ipHash: requesterIpHash,
      isReady,
      isBlocked,
      allowClaim: verifyUxPolicy.allowOwnershipClaim,
    });
    const ownershipTransfer = buildOwnershipTransferView({
      code: updated.code,
      transfer: requestedTransferToken
        ? await loadOwnershipTransferByRawToken(requestedTransferToken)
        : await loadPendingOwnershipTransferForQr(updated.id),
      rawToken: requestedTransferToken,
      customerUserId,
      ownershipStatus,
      isReady,
      isBlocked,
      transferRequested: Boolean(requestedTransferToken),
    });

    const anomalyModelScore = deriveAnomalyModelScore({
      scanSignals: postScanInsight.signals,
      policy,
    });

    const duplicateRisk = assessDuplicateRisk({
      scanCount: postScanSummary.totalScans,
      scanSignals: postScanInsight.signals,
      policy,
      ownershipStatus,
      customerUserId,
      latestScanAt: postScanInsight.latestScanAt,
      previousScanAt: postScanInsight.previousScanAt,
      anomalyModelScore: Math.round(anomalyModelScore * riskProfile.anomalyWeight),
      tenantRiskLevel: riskProfile.tenantRiskLevel,
      productRiskLevel: riskProfile.productRiskLevel,
    });

    let classification: VerifyClassification;
    let reasons: string[];
    let riskScore = duplicateRisk.riskScore;
    let riskSignals: Record<string, unknown> | null = duplicateRisk.signals;
    const activitySummary = isFirstScan ? null : duplicateRisk.activitySummary;

    if (isBlocked) {
      classification = "BLOCKED_BY_SECURITY";
      reasons = [
        blockedByPolicy
          ? "Security policy auto-blocked this code after anomaly detection."
          : "This code is blocked by security controls.",
        ...buildSecurityContainmentReasons(runtimeContainment),
      ];
      riskScore = 100;
      riskSignals = null;
    } else if (isFirstScan) {
      classification = "FIRST_SCAN";
      reasons = ["First successful customer verification recorded."];
      riskScore = 4;
      riskSignals = null;
    } else {
      classification = duplicateRisk.classification;
      reasons = duplicateRisk.reasons;
    }

    if (ownershipStatus.isClaimedByAnother && !isBlocked) {
      classification = "SUSPICIOUS_DUPLICATE";
      if (!reasons.includes("Ownership is already claimed by another account.")) {
        reasons.unshift("Ownership is already claimed by another account.");
      }
      riskScore = Math.max(riskScore, 70);
    }

    const verificationTimeline = buildVerificationTimeline({
      scanSummary: postScanSummary,
      classification,
      reasons,
    });
    const warningMessage = buildRepeatWarningMessage({
      blockedByPolicy,
      hasContainment,
      isFirstScan,
      firstVerifiedAt: postScanSummary.firstVerifiedAt,
      activitySummary,
    });
    const riskExplanation = buildRiskExplanation({
      classification,
      reasons,
      scanSummary: postScanSummary,
      ownershipStatus,
      activitySummary,
    });
    const stepUpRequired = classification === "SUSPICIOUS_DUPLICATE" && !customerUserId;

    return res.json({
      success: true,
      data: {
        isAuthentic: !isBlocked,
        message: isBlocked
          ? "Blocked code."
          : isFirstScan
            ? "This is a genuine product."
            : "Already verified. Please review scan details below.",
        code: updated.code,
        status: finalStatus,
        containment: runtimeContainment,
        licensee: mapLicensee(updated.licensee),
        batch: mapBatch(updated.batch),
        batchName: updated.batch?.name || null,
        printedAt: updated.batch?.printedAt || null,
        firstScanned: firstScanTime ? firstScanTime.toISOString() : null,
        scanCount: updated.scanCount ?? 0,
        isFirstScan,
        firstScanAt: postScanInsight.firstScanAt,
        firstScanLocation: postScanInsight.firstScanLocation,
        latestScanAt: postScanInsight.latestScanAt,
        latestScanLocation: postScanInsight.latestScanLocation,
        previousScanAt: postScanInsight.previousScanAt,
        previousScanLocation: postScanInsight.previousScanLocation,
        scanSignals: postScanInsight.signals,
        classification,
        reasons,
        activitySummary,
        scanSummary: postScanSummary,
        ownershipStatus,
        ownershipTransfer,
        verificationTimeline,
        riskExplanation,
        verifyUxPolicy,
        isBlocked,
        isReady,
        totalScans: postScanSummary.totalScans,
        firstVerifiedAt: postScanSummary.firstVerifiedAt,
        latestVerifiedAt: postScanSummary.latestVerifiedAt,
        riskScore,
        riskThreshold: duplicateRisk.threshold,
        riskSignals,
        challenge: {
          required: stepUpRequired,
          methods: stepUpRequired ? ["EMAIL_OTP", "CAPTCHA"] : [],
        },
        warningMessage,
        policy,
      },
    });
  } catch (error) {
    if (isPublicIntegrityDependencyError(error)) {
      return res.status(error.statusCode).json(buildPublicIntegrityErrorBody(error.message, error.code));
    }
    console.error("Verify error:", error);
    return res.status(500).json({
      success: false,
      error: "Verification service unavailable",
    });
  }
};
