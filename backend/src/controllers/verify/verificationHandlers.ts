import { Response } from "express";
import {
  CustomerTrustLevel,
  VerificationDecisionOutcome,
  VerificationDegradationMode,
  VerificationReplacementStatus,
} from "@prisma/client";
import { z } from "zod";

import { CustomerVerifyRequest } from "../../middleware/customerVerifyAuth";
import { recordDegradationEvent } from "../../services/degradationEventService";
import {
  recordCustomerTrustCredential,
  resolveCustomerTrustLevel,
  resolveCustomerTrustSignal,
} from "../../services/customerTrustService";
import { resolveVerifyUxPolicy } from "../../services/governanceService";
import { recordScan } from "../../services/qrService";
import { evaluateScanAndEnforcePolicy } from "../../services/policyEngineService";
import { getScanInsight } from "../../services/scanInsightService";
import { assessDuplicateRisk, deriveAnomalyModelScore } from "../../services/duplicateRiskService";
import { resolveReplacementStatus } from "../../services/replacementChainService";
import {
  hashToken as hashQrToken,
  isPrinterTestQrId,
  verifyQrToken,
} from "../../services/qrTokenService";
import { assessManualVerificationFallback, assessSignedReplay } from "../../services/verificationReplayService";
import { persistVerificationDecision, type VerificationDecisionSummary } from "../../services/verificationDecisionService";
import {
  buildPublicIntegrityErrorBody,
  isPublicIntegrityDependencyError,
} from "../../utils/publicIntegrityGuard";
import {
  QRStatus,
  buildPublicVerificationSemantics,
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
  verifyStepUpChallenge,
} from "./shared";
import {
  buildBlockedVerificationPayload,
  buildMissingQrVerificationPayload,
  buildNotReadyVerificationPayload,
} from "./verificationResponseBuilders";
import {
  applyPublicSemantics,
  buildDecisionResponseBody,
  resolvePrintTrustState,
  safeCreateAuditLog,
  toNum,
} from "./verificationDecisionHelpers";
import { resolveSignedVerificationTarget } from "./verificationSignedTokenResolver";

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
    const customerUserId = req.customer?.userId || null;
    const requestDeviceFingerprint = deriveRequestDeviceFingerprint(req);
    const actorDeviceHash = requestDeviceFingerprint ? hashToken(`device:${requestDeviceFingerprint}`) : null;
    const deviceClaimToken = getDeviceClaimTokenFromRequest(req);
    const deviceTokenHash = deviceClaimToken ? hashToken(deviceClaimToken) : null;
    const requesterIpHash = hashIp(req.ip);
    let qrCode;
    let signedPayload: ReturnType<typeof verifyQrToken>["payload"] | null = null;
    let verifiedSigningMetadata: Record<string, unknown> | null = null;

    if (signedToken) {
      const signedResolution = await resolveSignedVerificationTarget({
        actorDeviceHash,
        customerAuthStrength: req.customer?.authStrength || null,
        customerUserId,
        defaultVerifyUxPolicy,
        deviceTokenHash,
        normalizedCode: normalizedCode || null,
        originalUrl: req.originalUrl || req.url,
        proofSource,
        qrVerificationInclude,
        queryToken: signedToken,
        requestUrl: req.url,
        requesterIpHash,
      });

      if (signedResolution.kind === "response") {
        return res.status(signedResolution.statusCode).json(signedResolution.body);
      }

      qrCode = signedResolution.value.qrCode;
      signedPayload = signedResolution.value.signedPayload;
      verifiedSigningMetadata = signedResolution.value.verifiedSigningMetadata;
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
      const semantics = buildPublicVerificationSemantics({
        classification: "NOT_FOUND",
        proofSource,
        notFound: true,
      });
      const degradationMode = await safeCreateAuditLog(
        {
          action: "VERIFY_FAILED",
          entityType: "QRCode",
          entityId: normalizedCode,
          details: { reason: "Code not found" },
          ipAddress: req.ip,
        },
        { code: normalizedCode || null, route: req.originalUrl || req.url }
      );
      const decision = await persistVerificationDecision({
        code: normalizedCode || null,
        proofSource,
        classification: "NOT_FOUND",
        notFound: true,
        isAuthentic: false,
        reasons,
        customerTrustLevel: resolveCustomerTrustLevel({
          customerUserId,
          deviceTokenHash,
          customerAuthStrength: req.customer?.authStrength || null,
        }),
        degradationMode,
        actorIpHash: requesterIpHash,
        actorDeviceHash,
        publicOutcome: semantics.publicOutcome,
        riskDisposition: semantics.riskDisposition,
        messageKey: semantics.messageKey,
        nextActionKey: semantics.nextActionKey,
        metadata: {
          route: req.originalUrl || req.url,
          signedToken: Boolean(signedToken),
        },
      });

      return res.json({
        success: true,
        data: await buildDecisionResponseBody(
          applyPublicSemantics(
            buildMissingQrVerificationPayload({
              normalizedCode: normalizedCode || null,
              reasons,
              verifyUxPolicy: defaultVerifyUxPolicy,
              proofSource,
            }),
            semantics
          ),
          decision
        ),
      });
    }

    const verifyUxPolicy = await resolveVerifyUxPolicy(qrCode.licenseeId || null);
    const riskProfile = await resolveDuplicateRiskProfile(qrCode.licenseeId || null);

    const requestedTransferToken = String(requestQuery.transfer || "").trim() || null;
    const containment = buildContainment(qrCode);
    const qrBlocked = qrCode.status === QRStatus.BLOCKED;
    const readiness = resolvePublicVerificationReadiness(qrCode);
    const qrReady = readiness.isReady;
    const replacement = await resolveReplacementStatus(qrCode.id);
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
    const baseTrustSignal = await resolveCustomerTrustSignal({
      qrCodeId: qrCode.id,
      customerUserId,
      deviceTokenHash,
      ownershipStatus: baseOwnershipStatus,
      customerAuthStrength: req.customer?.authStrength || null,
    });
    const baseCustomerTrustLevel = baseTrustSignal.trustLevel;
    const basePrintTrustState = resolvePrintTrustState(qrCode, readiness);

    const basePayload = {
      proofSource,
      code: qrCode.code,
      status: qrCode.status,
      labelState: qrCode.status,
      printTrustState: basePrintTrustState,
      issuanceMode: readiness.issuanceMode || null,
      customerVerifiableAt: readiness.customerVerifiableAt || null,
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
      replacementChainId: replacement.replacementChainId,
    };

    if (qrCode.status === QRStatus.BLOCKED) {
      const blockedReasons =
        replacement.replacementStatus === VerificationReplacementStatus.REPLACED_LABEL
          ? ["This label was superseded by a controlled replacement issuance."]
          : undefined;
      const blockedSemantics = buildPublicVerificationSemantics({
        classification: "BLOCKED_BY_SECURITY",
        proofSource,
        replacementStatus: replacement.replacementStatus,
      });
      const blockedPayload: any = buildBlockedVerificationPayload({
        basePayload,
        containment,
        scanSummary: baseScanSummary,
        ownershipStatus: baseOwnershipStatus,
        ownershipTransfer: baseOwnershipTransfer,
        verifyUxPolicy,
      });
      if (blockedReasons) {
        blockedPayload.message = "This label has been superseded by a controlled replacement.";
        blockedPayload.reasons = Array.from(new Set([...blockedReasons, ...(blockedPayload.reasons || [])]));
        blockedPayload.warningMessage =
          "Verify the active replacement label if it was reissued by the manufacturer or operator.";
      }
      blockedPayload.reasons = Array.from(new Set([...(blockedPayload.reasons || []), ...(baseTrustSignal.messages || [])]));
      const decision = await persistVerificationDecision({
        qrCodeId: qrCode.id,
        code: qrCode.code,
        licenseeId: qrCode.licenseeId || null,
        batchId: qrCode.batchId || null,
        proofSource,
        classification: "BLOCKED_BY_SECURITY",
        reasons: blockedPayload.reasons,
        extraReasonCodes: baseTrustSignal.reasonCodes,
        isAuthentic: false,
        scanCount: baseScanSummary.totalScans,
        riskScore: 100,
        replacementStatus: replacement.replacementStatus,
        customerTrustLevel: baseCustomerTrustLevel,
        actorIpHash: requesterIpHash,
        actorDeviceHash,
        replacementChainId: replacement.replacementChainId,
        publicOutcome: blockedSemantics.publicOutcome,
        riskDisposition: blockedSemantics.riskDisposition,
        messageKey: blockedSemantics.messageKey,
        nextActionKey: blockedSemantics.nextActionKey,
        scanSummary: baseScanSummary as unknown as Record<string, unknown>,
        ownershipSnapshot: baseOwnershipStatus as unknown as Record<string, unknown>,
        lifecycleSnapshot: {
          readiness,
          labelState: qrCode.status,
          printTrustState: basePrintTrustState,
          replacementStatus: replacement.replacementStatus,
          issuanceMode: readiness.issuanceMode || null,
          customerVerifiableAt: readiness.customerVerifiableAt || null,
          governedProofEligible: Boolean(readiness.governedProofEligible),
        },
      });
      return res.json({
        success: true,
        data: await buildDecisionResponseBody(
          applyPublicSemantics({
            ...blockedPayload,
            replacementStatus: replacement.replacementStatus,
            customerTrustLevel: baseCustomerTrustLevel,
            labelState: qrCode.status,
            printTrustState: basePrintTrustState,
            scanOutcome:
              replacement.replacementStatus === VerificationReplacementStatus.REPLACED_LABEL ? "REPLACED_LABEL" : "BLOCKED",
          }, blockedSemantics),
          decision
        ),
      });
    }

    if (!readiness.isReady) {
      const reasons = Array.from(
        new Set([readiness.reason || "Code is not ready for customer verification.", ...(baseTrustSignal.messages || [])])
      );
      const notReadySemantics = buildPublicVerificationSemantics({
        classification: "NOT_READY_FOR_CUSTOMER_USE",
        proofSource,
        replacementStatus: replacement.replacementStatus,
      });
      const decision = await persistVerificationDecision({
        qrCodeId: qrCode.id,
        code: qrCode.code,
        licenseeId: qrCode.licenseeId || null,
        batchId: qrCode.batchId || null,
        proofSource,
        classification: "NOT_READY_FOR_CUSTOMER_USE",
        reasons,
        extraReasonCodes: baseTrustSignal.reasonCodes,
        isAuthentic: false,
        scanCount: baseScanSummary.totalScans,
        riskScore: 70,
        replacementStatus: replacement.replacementStatus,
        customerTrustLevel: baseCustomerTrustLevel,
        actorIpHash: requesterIpHash,
        actorDeviceHash,
        replacementChainId: replacement.replacementChainId,
        publicOutcome: notReadySemantics.publicOutcome,
        riskDisposition: notReadySemantics.riskDisposition,
        messageKey: notReadySemantics.messageKey,
        nextActionKey: notReadySemantics.nextActionKey,
        scanSummary: baseScanSummary as unknown as Record<string, unknown>,
        ownershipSnapshot: baseOwnershipStatus as unknown as Record<string, unknown>,
        lifecycleSnapshot: {
          readiness,
          labelState: qrCode.status,
          printTrustState: basePrintTrustState,
          replacementStatus: replacement.replacementStatus,
          issuanceMode: readiness.issuanceMode || null,
          customerVerifiableAt: readiness.customerVerifiableAt || null,
          governedProofEligible: Boolean(readiness.governedProofEligible),
        },
      });
      return res.json({
        success: true,
        data: await buildDecisionResponseBody(
          applyPublicSemantics({
            ...buildNotReadyVerificationPayload({
              basePayload,
              status: qrCode.status,
              scanSummary: baseScanSummary,
              ownershipStatus: baseOwnershipStatus,
              ownershipTransfer: baseOwnershipTransfer,
              verifyUxPolicy,
              reasons,
              message: readiness.message,
            }),
            replacementStatus: replacement.replacementStatus,
            customerTrustLevel: baseCustomerTrustLevel,
            labelState: qrCode.status,
            printTrustState: basePrintTrustState,
            scanOutcome: "NOT_READY",
          }, notReadySemantics),
          decision
        ),
      });
    }

    const latitude = toNum(requestQuery.lat);
    const longitude = toNum(requestQuery.lon);
    const accuracy = toNum(requestQuery.acc);

    const scanRecord = await recordScan(
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
    const isFirstScan = scanRecord.isFirstScan;
    let updated = scanRecord.qrCode;

    const auditDegradationMode = await safeCreateAuditLog(
      {
        action: "VERIFY_SUCCESS",
        entityType: "QRCode",
        entityId: qrCode.id,
        details: {
          isFirstScan,
          scanCount: updated.scanCount ?? 0,
        },
        ipAddress: req.ip,
      },
      {
        qrCodeId: qrCode.id,
        code: qrCode.code,
        route: req.originalUrl || req.url,
      }
    );

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
    const postReadiness = resolvePublicVerificationReadiness({
      ...updated,
      printJobId: qrCode.printJobId,
      printJob: qrCode.printJob,
    });
    const isReady = postReadiness.isReady;

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

    const replayAssessment = assessSignedReplay({
      signedTokenPresent: Boolean(signedToken),
      replayEpoch: qrCode.replayEpoch,
      tokenReplayEpoch: signedPayload?.epoch ?? null,
      signedFirstSeenAt: qrCode.signedFirstSeenAt,
      lastSignedVerificationAt: qrCode.lastSignedVerificationAt,
      lastSignedVerificationIpHash: qrCode.lastSignedVerificationIpHash,
      lastSignedVerificationDeviceHash: qrCode.lastSignedVerificationDeviceHash,
      actorIpHash: requesterIpHash,
      actorDeviceHash,
      customerUserId,
      signals: postScanInsight.signals,
    });
    const manualFallbackAssessment = assessManualVerificationFallback({
      proofSource,
      signedFirstSeenAt: qrCode.signedFirstSeenAt,
      lastSignedVerificationAt: qrCode.lastSignedVerificationAt,
      signals: postScanInsight.signals,
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

    if (!isBlocked && replayAssessment.reviewRequired) {
      classification = "SUSPICIOUS_DUPLICATE";
      reasons = Array.from(new Set([...replayAssessment.reasons, ...reasons]));
      riskScore = Math.max(riskScore, replayAssessment.rapidReuse ? 92 : 78);
      riskSignals = {
        ...(riskSignals || {}),
        replayAssessment: replayAssessment.metadata,
        replayState: replayAssessment.replayState,
      };
    }

    if (!isBlocked && proofSource === "MANUAL_CODE_LOOKUP" && manualFallbackAssessment.hasSignedHistory) {
      reasons = Array.from(new Set([...manualFallbackAssessment.reasons, ...reasons]));
      riskSignals = {
        ...(riskSignals || {}),
        manualFallbackAssessment: manualFallbackAssessment.metadata,
      };

      if (manualFallbackAssessment.reviewRequired) {
        classification = "SUSPICIOUS_DUPLICATE";
        riskScore = Math.max(riskScore, 76);
      } else {
        riskScore = Math.max(riskScore, 18);
      }
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
      classification,
      activitySummary,
    });
    const replayAwareWarningMessage =
      warningMessage ||
      (proofSource === "MANUAL_CODE_LOOKUP" && manualFallbackAssessment.rescanRecommended
        ? "This code has prior signed-label history. If the original label is available, re-scan it instead of relying on manual entry."
        : null) ||
      (proofSource === "SIGNED_LABEL" && postReadiness.limitedProvenance
        ? "Governed print provenance is unavailable for this label, so MSCQR is showing a limited signed-label result."
        : null);
    const riskExplanation = buildRiskExplanation({
      classification,
      reasons,
      scanSummary: postScanSummary,
      ownershipStatus,
      activitySummary,
    });
    const stepUp: { ok: boolean; reason?: string } = replayAssessment.stepUpRecommended
      ? await verifyStepUpChallenge(req)
      : { ok: true };
    const stepUpEligible = Boolean(replayAssessment.reviewRequired);
    const stepUpRequired =
      classification === "SUSPICIOUS_DUPLICATE" &&
      !customerUserId &&
      Boolean(replayAssessment.stepUpRecommended) &&
      !stepUp.ok;
    const trustSignal = await resolveCustomerTrustSignal({
      qrCodeId: updated.id,
      customerUserId,
      deviceTokenHash,
      ownershipStatus,
      customerAuthStrength: req.customer?.authStrength || null,
    });
    const customerTrustLevel = trustSignal.trustLevel;
    const printTrustState = resolvePrintTrustState(
      {
        ...updated,
        printJobId: qrCode.printJobId,
        printJob: qrCode.printJob,
      },
      postReadiness
    );

    if (proofSource === "SIGNED_LABEL" && (prisma as any)?.qRCode?.update) {
      const shouldAdvanceSignedBaseline = !isBlocked && classification !== "SUSPICIOUS_DUPLICATE";
      const signedVerificationTimestamp = new Date();
      const signedVerificationUpdate = await prisma.qRCode.update({
        where: { id: updated.id },
        data: {
          signedFirstSeenAt: qrCode.signedFirstSeenAt || signedVerificationTimestamp,
          ...(shouldAdvanceSignedBaseline
            ? {
                lastSignedVerificationAt: signedVerificationTimestamp,
                lastSignedVerificationIpHash: requesterIpHash || null,
                lastSignedVerificationDeviceHash: actorDeviceHash || null,
              }
            : {}),
        },
        select: {
          signedFirstSeenAt: true,
          lastSignedVerificationAt: true,
          lastSignedVerificationIpHash: true,
          lastSignedVerificationDeviceHash: true,
        },
      });

      updated = {
        ...updated,
        ...signedVerificationUpdate,
      };
    } else if (proofSource === "SIGNED_LABEL") {
      const signedVerificationTimestamp = new Date();
      updated = {
        ...updated,
        signedFirstSeenAt: updated.signedFirstSeenAt || qrCode.signedFirstSeenAt || signedVerificationTimestamp,
      };
    }

    await recordCustomerTrustCredential({
      qrCodeId: updated.id,
      customerUserId,
      customerEmail: req.customer?.email || null,
      deviceTokenHash,
      trustLevel: customerTrustLevel,
      source: "VERIFY_SCAN",
      lastVerifiedAt: new Date(),
      lastAssertionAt:
        req.customer?.authStrength === "PASSKEY" && req.customer?.webauthnVerifiedAt
          ? new Date(req.customer.webauthnVerifiedAt)
          : null,
      metadata: {
        proofSource,
        classification,
        replacementStatus: replacement.replacementStatus,
        customerAuthStrength: req.customer?.authStrength || null,
      },
    });

    const decisionReasons = Array.from(
      new Set([
        ...reasons,
        ...(postReadiness.provenanceReason ? [postReadiness.provenanceReason] : []),
        ...(trustSignal.messages || []),
      ])
    );
    const verifiedSemantics = buildPublicVerificationSemantics({
      classification,
      proofSource,
      replacementStatus: replacement.replacementStatus,
      isFirstScan,
      limitedProvenance: proofSource === "SIGNED_LABEL" && Boolean(postReadiness.limitedProvenance),
      manualSignedHistory:
        proofSource === "MANUAL_CODE_LOOKUP" &&
        manualFallbackAssessment.hasSignedHistory &&
        !manualFallbackAssessment.reviewRequired,
    });
    const isPositiveVerification = !isBlocked && classification !== "SUSPICIOUS_DUPLICATE";

    const decision = await persistVerificationDecision({
      qrCodeId: updated.id,
      code: updated.code,
      licenseeId: updated.licenseeId || null,
      batchId: updated.batchId || null,
      proofSource,
      classification,
      reasons: decisionReasons,
      extraReasonCodes: trustSignal.reasonCodes,
      isAuthentic: isPositiveVerification,
      scanCount: postScanSummary.totalScans,
      riskScore,
      replacementStatus: replacement.replacementStatus,
      customerTrustLevel,
      degradationMode: auditDegradationMode,
      actorIpHash: requesterIpHash,
      actorDeviceHash,
      replacementChainId: replacement.replacementChainId,
      publicOutcome: verifiedSemantics.publicOutcome,
      riskDisposition: verifiedSemantics.riskDisposition,
      messageKey: verifiedSemantics.messageKey,
      nextActionKey: verifiedSemantics.nextActionKey,
      scanSummary: postScanSummary as unknown as Record<string, unknown>,
      ownershipSnapshot: ownershipStatus as unknown as Record<string, unknown>,
      riskSignals,
      policySnapshot: (policy || null) as unknown as Record<string, unknown> | null,
      lifecycleSnapshot: {
        isFirstScan,
        isReady,
        isBlocked,
        labelState: finalStatus,
        printTrustState,
        replacementStatus: replacement.replacementStatus,
        issuanceMode: postReadiness.issuanceMode || null,
        customerVerifiableAt: postReadiness.customerVerifiableAt || null,
        governedProofEligible: Boolean(postReadiness.governedProofEligible),
        replayEpoch: Number(qrCode.replayEpoch || 1),
        replayState: replayAssessment.replayState,
      },
      metadata: {
        scanOutcome:
          classification === "SUSPICIOUS_DUPLICATE"
            ? "SUSPICIOUS_DUPLICATE"
            : isBlocked
              ? "BLOCKED"
              : isFirstScan
                ? "FIRST_SCAN"
                : "REPEAT_SCAN",
        proofSource,
        signing: verifiedSigningMetadata,
        replayAssessment: replayAssessment.metadata,
        manualFallbackAssessment: manualFallbackAssessment.metadata,
        stepUpRequired,
        stepUpSatisfied: stepUpEligible ? (customerUserId ? true : stepUp.ok) : null,
        stepUpCompletedBy:
          stepUpEligible && !stepUpRequired
            ? (customerUserId ? "CUSTOMER_IDENTITY" : stepUp.ok ? "CAPTCHA" : null)
            : null,
      },
    });

    return res.json({
      success: true,
      data: await buildDecisionResponseBody(
        applyPublicSemantics({
          isAuthentic: isPositiveVerification,
          message: verifiedSemantics.headline,
          proofSource,
          code: updated.code,
          status: finalStatus,
          labelState: finalStatus,
          printTrustState,
          issuanceMode: postReadiness.issuanceMode || null,
          customerVerifiableAt: postReadiness.customerVerifiableAt || null,
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
          reasons: decisionReasons,
          activitySummary,
          scanSummary: postScanSummary,
          ownershipStatus,
          ownershipTransfer,
          customerTrustLevel,
          replacementStatus: replacement.replacementStatus,
          replacementChainId: replacement.replacementChainId,
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
            methods: stepUpRequired ? ["SIGN_IN"] : [],
            reason: stepUpRequired
              ? "Sign in with a verified identity so MSCQR can re-check this repeat scan before it should be trusted normally."
              : null,
            completed: stepUpEligible && !stepUpRequired && (Boolean(customerUserId) || stepUp.ok),
            completedBy:
              stepUpEligible && !stepUpRequired
                ? (customerUserId ? "CUSTOMER_IDENTITY" : stepUp.ok ? "CAPTCHA" : null)
                : null,
          },
          warningMessage: replayAwareWarningMessage,
          policy,
          scanOutcome:
            classification === "SUSPICIOUS_DUPLICATE"
              ? "SUSPICIOUS_DUPLICATE"
              : isBlocked
                ? "BLOCKED"
                : isFirstScan
                  ? "FIRST_SCAN"
                  : "REPEAT_SCAN",
        }, verifiedSemantics),
        decision
      ),
    });
  } catch (error) {
    if (isPublicIntegrityDependencyError(error)) {
      await recordDegradationEvent({
        dependencyKey: "public_verification",
        mode: VerificationDegradationMode.FAIL_CLOSED,
        code: error.code,
        message: error.message,
        context: {
          route: req.originalUrl || req.url,
        },
      });
      return res.status(error.statusCode).json({
        ...buildPublicIntegrityErrorBody(error.message, error.code),
        degradationMode: VerificationDegradationMode.FAIL_CLOSED,
      });
    }
    console.error("Verify error:", error);
    return res.status(500).json({
      success: false,
      error: "Verification service unavailable",
    });
  }
};
