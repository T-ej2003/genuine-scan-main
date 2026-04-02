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
  hashToken as hashQrToken,
  isPrinterTestQrId,
  verifyQrToken,
} from "../../services/qrTokenService";
import {
  buildPublicIntegrityErrorBody,
  isPublicIntegrityDependencyError,
} from "../../utils/publicIntegrityGuard";
import {
  QRStatus,
  VerificationProofSource,
  VerifyClassification,
  buildContainment,
  describeVerificationProof,
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
  loadOwnershipByQrCodeId,
  loadOwnershipTransferByRawToken,
  loadPendingOwnershipTransferForQr,
  mapBatch,
  mapLicensee,
  normalizeCode,
  prisma,
  resolvePublicVerificationReadiness,
  resolveDuplicateRiskProfile,
} from "./shared";
import {
  buildBlockedVerificationPayload,
  buildMissingQrVerificationPayload,
  buildNotReadyVerificationPayload,
} from "./verificationResponseBuilders";

const verifyParamsSchema = z.object({
  code: z.string().trim().min(2).max(128).optional(),
}).strict();

const verifyQuerySchema = z.object({
  t: z.string().trim().min(16).max(4096).optional(),
  transfer: z.string().trim().max(512).optional(),
  device: z.string().trim().max(256).optional(),
  lat: z.union([z.string().trim().max(40), z.number()]).optional(),
  lon: z.union([z.string().trim().max(40), z.number()]).optional(),
  acc: z.union([z.string().trim().max(40), z.number()]).optional(),
}).strict();

const qrVerificationInclude = {
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
  printJob: {
    select: {
      id: true,
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
} as const;

const toNum = (v: unknown) => {
  const n = parseFloat(String(v));
  return Number.isFinite(n) ? n : null;
};

const buildSignedTokenErrorResponse = (message: string, scanOutcome: string) => ({
  success: true,
  data: {
    isAuthentic: false,
    message,
    scanOutcome,
    proofSource: "SIGNED_LABEL" as VerificationProofSource,
  },
});

const safeCreateAuditLog = async (payload: Parameters<typeof createAuditLog>[0]) => {
  try {
    await createAuditLog(payload);
  } catch (error) {
    console.warn("verify audit log skipped:", error);
  }
};

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

    const normalizedCode = normalizeCode(paramsParsed.data.code || "");
    const requestQuery = queryParsed.data;
    const signedToken = String(requestQuery.t || "").trim() || null;
    const defaultVerifyUxPolicy = await resolveVerifyUxPolicy(null);
    let proofSource: VerificationProofSource = signedToken ? "SIGNED_LABEL" : "MANUAL_CODE_LOOKUP";
    let qrCode;

    if (signedToken) {
      let payload;
      try {
        payload = verifyQrToken(signedToken).payload;
      } catch {
        return res.status(400).json(buildSignedTokenErrorResponse("Invalid or tampered QR token.", "INVALID_SIGNATURE"));
      }

      if (!payload.qr_id || !payload.licensee_id || !payload.nonce) {
        return res.status(400).json(buildSignedTokenErrorResponse("Invalid QR token payload.", "INVALID_PAYLOAD"));
      }

      if (payload.exp && payload.exp * 1000 < Date.now()) {
        return res.status(400).json(buildSignedTokenErrorResponse("QR token expired.", "EXPIRED"));
      }

      if (isPrinterTestQrId(payload.qr_id)) {
        return res.json({
          success: true,
          data: {
            isAuthentic: true,
            message:
              "MSCQR printer setup test label verified. This QR is for printer setup only and does not represent a product.",
            scanOutcome: "PRINTER_SETUP_TEST",
            classification: "LEGIT_REPEAT",
            code: "PRINTER_SETUP_TEST",
            status: "TEST_ONLY",
            proofSource,
            warningMessage: "Use this label only to confirm printer setup and print quality.",
            ownershipStatus: {
              isClaimed: false,
              claimedAt: null,
              isOwnedByRequester: false,
              isClaimedByAnother: false,
              canClaim: false,
            },
            verifyUxPolicy: {
              showTimelineCard: false,
              showRiskCards: false,
              allowOwnershipClaim: false,
              allowFraudReport: false,
              mobileCameraAssist: true,
            },
            scanSummary: {
              totalScans: 0,
              firstVerifiedAt: null,
              latestVerifiedAt: null,
            },
          },
        });
      }

      qrCode = await prisma.qRCode.findUnique({
        where: { id: payload.qr_id },
        include: qrVerificationInclude,
      });

      if (!qrCode) {
        return res.status(404).json({
          success: true,
          data: buildMissingQrVerificationPayload({
            normalizedCode: normalizedCode || null,
            reasons: ["Code not found in registry."],
            verifyUxPolicy: defaultVerifyUxPolicy,
            proofSource,
          }),
        });
      }

      if (normalizedCode && normalizedCode !== qrCode.code) {
        return res.status(400).json(buildSignedTokenErrorResponse("QR token does not match this verification URL.", "TOKEN_MISMATCH"));
      }

      const tokenHash = hashQrToken(signedToken);
      if (!qrCode.tokenHash) {
        return res.status(400).json(buildSignedTokenErrorResponse("QR token has not been issued.", "NOT_ISSUED"));
      }
      if (qrCode.tokenHash !== tokenHash) {
        return res.status(400).json(buildSignedTokenErrorResponse("QR token revoked or mismatched.", "TOKEN_MISMATCH"));
      }
      if (qrCode.tokenNonce && payload.nonce !== qrCode.tokenNonce) {
        return res.status(400).json(buildSignedTokenErrorResponse("QR token mismatch.", "TOKEN_MISMATCH"));
      }
      if (payload.licensee_id !== qrCode.licenseeId) {
        return res.status(400).json(buildSignedTokenErrorResponse("QR token invalid for this licensee.", "TOKEN_MISMATCH"));
      }
      if (payload.batch_id !== (qrCode.batchId ?? null)) {
        return res.status(400).json(buildSignedTokenErrorResponse("QR token invalid for this batch.", "TOKEN_MISMATCH"));
      }
      if (payload.manufacturer_id !== undefined && payload.manufacturer_id !== (qrCode.batch?.manufacturer?.id ?? null)) {
        return res.status(400).json(buildSignedTokenErrorResponse("QR token invalid for this manufacturer.", "TOKEN_MISMATCH"));
      }
    } else {
      if (!normalizedCode) {
        return res.status(400).json({
          success: false,
          error: "Invalid QR code format",
        });
      }

      qrCode = await prisma.qRCode.findUnique({
        where: { code: normalizedCode },
        include: qrVerificationInclude,
      });
    }

    if (!qrCode) {
      await delay(150 + Math.floor(Math.random() * 150));
      const reasons = ["Code not found in registry."];
      await safeCreateAuditLog({
        action: "VERIFY_FAILED",
        entityType: "QRCode",
        entityId: normalizedCode,
        details: { reason: "Code not found" },
        ipAddress: req.ip,
      });

      return res.json({
        success: true,
        data: buildMissingQrVerificationPayload({
          normalizedCode: normalizedCode || null,
          reasons,
          verifyUxPolicy: defaultVerifyUxPolicy,
          proofSource,
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
    const readiness = resolvePublicVerificationReadiness(qrCode);
    const qrReady = readiness.isReady;
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
      proofSource,
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

    if (!readiness.isReady) {
      const reasons = [readiness.reason || "Code is not ready for customer verification."];
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
          message: readiness.message,
        }),
      });
    }

    const latitude = toNum(requestQuery.lat);
    const longitude = toNum(requestQuery.lon);
    const accuracy = toNum(requestQuery.acc);

    const { isFirstScan, qrCode: updated } = await recordScan(
      qrCode.code,
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

    await safeCreateAuditLog({
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
    const isReady = resolvePublicVerificationReadiness({
      ...updated,
      printJobId: qrCode.printJobId,
      printJob: qrCode.printJob,
    }).isReady;

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
        proofSource,
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
        proof: describeVerificationProof(proofSource),
        challenge: {
          required: stepUpRequired,
          methods: stepUpRequired ? ["EMAIL_OTP", "CAPTCHA"] : [],
        },
        warningMessage,
        policy,
        scanOutcome: isBlocked ? "BLOCKED" : isFirstScan ? "FIRST_SCAN" : "REPEAT_SCAN",
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
