import { QRStatus, VerificationReplacementStatus } from "@prisma/client";

import { CustomerVerifyRequest } from "../middleware/customerVerifyAuth";
import { recordCustomerTrustCredential, resolveCustomerTrustSignal } from "./customerTrustService";
import { assessDuplicateRisk, deriveAnomalyModelScore } from "./duplicateRiskService";
import { evaluateScanAndEnforcePolicy } from "./policyEngineService";
import { recordScan } from "./qrService";
import { getScanInsight } from "./scanInsightService";
import { persistVerificationDecision } from "./verificationDecisionService";
import { assessManualVerificationFallback, assessSignedReplay } from "./verificationReplayService";
import {
  applyPublicSemantics,
  buildDecisionResponseBody,
  resolvePrintTrustState,
  safeCreateAuditLog,
  toNum,
} from "../controllers/verify/verificationDecisionHelpers";
import {
  buildContainment,
  buildOwnershipStatus,
  buildOwnershipTransferView,
  buildPublicVerificationSemantics,
  buildRepeatWarningMessage,
  buildRiskExplanation,
  buildScanSummary,
  buildSecurityContainmentReasons,
  buildVerificationTimeline,
  describeVerificationProof,
  loadOwnershipByQrCodeId,
  loadOwnershipTransferByRawToken,
  loadPendingOwnershipTransferForQr,
  mapBatch,
  mapLicensee,
  prisma,
  resolvePublicVerificationReadiness,
  verifyStepUpChallenge,
} from "../controllers/verify/shared";

type PostScanVerificationContext = {
  actorDeviceHash: string | null;
  baseOwnership: any;
  baseOwnershipStatus: any;
  customerUserId: string | null;
  deviceTokenHash: string | null;
  proofSource: "SIGNED_LABEL" | "MANUAL_CODE_LOOKUP";
  qrCode: any;
  replacement: any;
  requestDeviceFingerprint: string | null;
  requesterIpHash: string | null;
  requestQuery: {
    lat?: string | number;
    lon?: string | number;
    acc?: string | number;
    transfer?: string;
  };
  requestedTransferToken: string | null;
  req: CustomerVerifyRequest;
  riskProfile: any;
  signedPayload: Record<string, unknown> | null;
  signedToken: string | null;
  verifiedSigningMetadata: Record<string, unknown> | null;
  verifyUxPolicy: Record<string, any>;
};

export const runPostScanVerificationFlow = async (context: PostScanVerificationContext) => {
  const latitude = toNum(context.requestQuery.lat);
  const longitude = toNum(context.requestQuery.lon);
  const accuracy = toNum(context.requestQuery.acc);
  const tokenReplayEpoch = typeof context.signedPayload?.epoch === "number" ? context.signedPayload.epoch : null;

  const scanRecord = await recordScan(
    context.qrCode.code,
    {
      ipAddress: context.req.ip,
      userAgent: context.req.get("user-agent") || null,
      device: context.requestDeviceFingerprint,
      latitude,
      longitude,
      accuracy,
      customerUserId: context.customerUserId,
      ownershipId: context.baseOwnershipStatus.isOwnedByRequester ? context.baseOwnership?.id || null : null,
      ownershipMatchMethod: context.baseOwnershipStatus.isOwnedByRequester
        ? context.baseOwnershipStatus.matchMethod || null
        : null,
      isTrustedOwnerContext: context.baseOwnershipStatus.isOwnedByRequester,
    },
    { strictStorage: true }
  );

  const isFirstScan = scanRecord.isFirstScan;
  let updated = scanRecord.qrCode;

  const auditDegradationMode = await safeCreateAuditLog(
    {
      action: "VERIFY_SUCCESS",
      entityType: "QRCode",
      entityId: context.qrCode.id,
      details: {
        isFirstScan,
        scanCount: updated.scanCount ?? 0,
      },
      ipAddress: context.req.ip,
    },
    {
      qrCodeId: context.qrCode.id,
      code: context.qrCode.code,
      route: context.req.originalUrl || context.req.url,
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
    ipAddress: context.req.ip,
    userAgent: context.req.get("user-agent") || null,
    strictStorage: true,
  });

  const blockedByPolicy = Boolean(policy.autoBlockedQr || policy.autoBlockedBatch);
  const finalStatus = blockedByPolicy ? QRStatus.BLOCKED : updated.status;
  const isBlocked = blockedByPolicy || finalStatus === QRStatus.BLOCKED;
  const postReadiness = resolvePublicVerificationReadiness({
    ...updated,
    printJobId: context.qrCode.printJobId,
    printJob: context.qrCode.printJob,
  });
  const isReady = postReadiness.isReady;

  const firstScanTime = updated.scannedAt ? new Date(updated.scannedAt) : null;
  const postScanInsight = await getScanInsight(updated.id, context.requestDeviceFingerprint, {
    currentIpAddress: context.req.ip || null,
    licenseeId: updated.licenseeId || null,
    currentCustomerUserId: context.customerUserId,
    currentOwnershipId: context.baseOwnership?.id || null,
    currentActorTrustedOwnerContext: context.baseOwnershipStatus.isOwnedByRequester,
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
    customerUserId: context.customerUserId,
    deviceTokenHash: context.deviceTokenHash,
    ipHash: context.requesterIpHash,
    isReady,
    isBlocked,
    allowClaim: context.verifyUxPolicy.allowOwnershipClaim,
  });
  const ownershipTransfer = buildOwnershipTransferView({
    code: updated.code,
    transfer: context.requestedTransferToken
      ? await loadOwnershipTransferByRawToken(context.requestedTransferToken)
      : await loadPendingOwnershipTransferForQr(updated.id),
    rawToken: context.requestedTransferToken,
    customerUserId: context.customerUserId,
    ownershipStatus,
    isReady,
    isBlocked,
    transferRequested: Boolean(context.requestedTransferToken),
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
    customerUserId: context.customerUserId,
    latestScanAt: postScanInsight.latestScanAt,
    previousScanAt: postScanInsight.previousScanAt,
    anomalyModelScore: Math.round(anomalyModelScore * context.riskProfile.anomalyWeight),
    tenantRiskLevel: context.riskProfile.tenantRiskLevel,
    productRiskLevel: context.riskProfile.productRiskLevel,
  });

  const replayAssessment = assessSignedReplay({
    signedTokenPresent: Boolean(context.signedToken),
    replayEpoch: context.qrCode.replayEpoch,
    tokenReplayEpoch,
    signedFirstSeenAt: context.qrCode.signedFirstSeenAt,
    lastSignedVerificationAt: context.qrCode.lastSignedVerificationAt,
    lastSignedVerificationIpHash: context.qrCode.lastSignedVerificationIpHash,
    lastSignedVerificationDeviceHash: context.qrCode.lastSignedVerificationDeviceHash,
    actorIpHash: context.requesterIpHash,
    actorDeviceHash: context.actorDeviceHash,
    customerUserId: context.customerUserId,
    signals: postScanInsight.signals,
  });
  const manualFallbackAssessment = assessManualVerificationFallback({
    proofSource: context.proofSource,
    signedFirstSeenAt: context.qrCode.signedFirstSeenAt,
    lastSignedVerificationAt: context.qrCode.lastSignedVerificationAt,
    signals: postScanInsight.signals,
  });

  let classification: "FIRST_SCAN" | "LEGIT_REPEAT" | "SUSPICIOUS_DUPLICATE" | "BLOCKED_BY_SECURITY";
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

  if (!isBlocked && context.proofSource === "MANUAL_CODE_LOOKUP" && manualFallbackAssessment.hasSignedHistory) {
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
    (context.proofSource === "MANUAL_CODE_LOOKUP" && manualFallbackAssessment.rescanRecommended
      ? "This code has prior signed-label history. If the original label is available, re-scan it instead of relying on manual entry."
      : null) ||
    (context.proofSource === "SIGNED_LABEL" && postReadiness.limitedProvenance
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
    ? await verifyStepUpChallenge(context.req)
    : { ok: true };
  const stepUpEligible = Boolean(replayAssessment.reviewRequired);
  const stepUpRequired =
    classification === "SUSPICIOUS_DUPLICATE" &&
    !context.customerUserId &&
    Boolean(replayAssessment.stepUpRecommended) &&
    !stepUp.ok;
  const trustSignal = await resolveCustomerTrustSignal({
    qrCodeId: updated.id,
    customerUserId: context.customerUserId,
    deviceTokenHash: context.deviceTokenHash,
    ownershipStatus,
    customerAuthStrength: context.req.customer?.authStrength || null,
  });
  const customerTrustLevel = trustSignal.trustLevel;
  const printTrustState = resolvePrintTrustState(
    {
      ...updated,
      printJobId: context.qrCode.printJobId,
      printJob: context.qrCode.printJob,
    },
    postReadiness
  );

  if (context.proofSource === "SIGNED_LABEL" && (prisma as any)?.qRCode?.update) {
    const shouldAdvanceSignedBaseline = !isBlocked && classification !== "SUSPICIOUS_DUPLICATE";
    const signedVerificationTimestamp = new Date();
    const signedVerificationUpdate = await prisma.qRCode.update({
      where: { id: updated.id },
      data: {
        signedFirstSeenAt: context.qrCode.signedFirstSeenAt || signedVerificationTimestamp,
        ...(shouldAdvanceSignedBaseline
          ? {
              lastSignedVerificationAt: signedVerificationTimestamp,
              lastSignedVerificationIpHash: context.requesterIpHash || null,
              lastSignedVerificationDeviceHash: context.actorDeviceHash || null,
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

    updated = { ...updated, ...signedVerificationUpdate };
  } else if (context.proofSource === "SIGNED_LABEL") {
    const signedVerificationTimestamp = new Date();
    updated = {
      ...updated,
      signedFirstSeenAt: updated.signedFirstSeenAt || context.qrCode.signedFirstSeenAt || signedVerificationTimestamp,
    };
  }

  await recordCustomerTrustCredential({
    qrCodeId: updated.id,
    customerUserId: context.customerUserId,
    customerEmail: context.req.customer?.email || null,
    deviceTokenHash: context.deviceTokenHash,
    trustLevel: customerTrustLevel,
    source: "VERIFY_SCAN",
    lastVerifiedAt: new Date(),
    lastAssertionAt:
      context.req.customer?.authStrength === "PASSKEY" && context.req.customer?.webauthnVerifiedAt
        ? new Date(context.req.customer.webauthnVerifiedAt)
        : null,
    metadata: {
      proofSource: context.proofSource,
      classification,
      replacementStatus: context.replacement.replacementStatus,
      customerAuthStrength: context.req.customer?.authStrength || null,
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
    proofSource: context.proofSource,
    replacementStatus: context.replacement.replacementStatus,
    isFirstScan,
    limitedProvenance: context.proofSource === "SIGNED_LABEL" && Boolean(postReadiness.limitedProvenance),
    manualSignedHistory:
      context.proofSource === "MANUAL_CODE_LOOKUP" &&
      manualFallbackAssessment.hasSignedHistory &&
      !manualFallbackAssessment.reviewRequired,
  });
  const isPositiveVerification = !isBlocked && classification !== "SUSPICIOUS_DUPLICATE";

  const decision = await persistVerificationDecision({
    qrCodeId: updated.id,
    code: updated.code,
    licenseeId: updated.licenseeId || null,
    batchId: updated.batchId || null,
    proofSource: context.proofSource,
    classification,
    reasons: decisionReasons,
    extraReasonCodes: trustSignal.reasonCodes,
    isAuthentic: isPositiveVerification,
    scanCount: postScanSummary.totalScans,
    riskScore,
    replacementStatus: context.replacement.replacementStatus,
    customerTrustLevel,
    degradationMode: auditDegradationMode,
    actorIpHash: context.requesterIpHash,
    actorDeviceHash: context.actorDeviceHash,
    replacementChainId: context.replacement.replacementChainId,
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
      replacementStatus: context.replacement.replacementStatus,
      issuanceMode: postReadiness.issuanceMode || null,
      customerVerifiableAt: postReadiness.customerVerifiableAt || null,
      governedProofEligible: Boolean(postReadiness.governedProofEligible),
      replayEpoch: Number(context.qrCode.replayEpoch || 1),
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
      proofSource: context.proofSource,
      signing: context.verifiedSigningMetadata,
      replayAssessment: replayAssessment.metadata,
      manualFallbackAssessment: manualFallbackAssessment.metadata,
      stepUpRequired,
      stepUpSatisfied: stepUpEligible ? (context.customerUserId ? true : stepUp.ok) : null,
      stepUpCompletedBy:
        stepUpEligible && !stepUpRequired
          ? (context.customerUserId ? "CUSTOMER_IDENTITY" : stepUp.ok ? "CAPTCHA" : null)
          : null,
    },
  });

  return buildDecisionResponseBody(
    applyPublicSemantics(
      {
        isAuthentic: isPositiveVerification,
        message: verifiedSemantics.headline,
        proofSource: context.proofSource,
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
        replacementStatus: context.replacement.replacementStatus,
        replacementChainId: context.replacement.replacementChainId,
        verificationTimeline,
        riskExplanation,
        verifyUxPolicy: context.verifyUxPolicy,
        isBlocked,
        isReady,
        totalScans: postScanSummary.totalScans,
        firstVerifiedAt: postScanSummary.firstVerifiedAt,
        latestVerifiedAt: postScanSummary.latestVerifiedAt,
        riskScore,
        riskThreshold: duplicateRisk.threshold,
        riskSignals,
        proof: describeVerificationProof(context.proofSource),
        challenge: {
          required: stepUpRequired,
          methods: stepUpRequired ? ["SIGN_IN"] : [],
          reason: stepUpRequired
            ? "Sign in with a verified identity so MSCQR can re-check this repeat scan before it should be trusted normally."
            : null,
          completed: stepUpEligible && !stepUpRequired && (Boolean(context.customerUserId) || stepUp.ok),
          completedBy:
            stepUpEligible && !stepUpRequired
              ? (context.customerUserId ? "CUSTOMER_IDENTITY" : stepUp.ok ? "CAPTCHA" : null)
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
      },
      verifiedSemantics
    ),
    decision
  );
};
