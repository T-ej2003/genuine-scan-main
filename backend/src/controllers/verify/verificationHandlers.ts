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
  resolveCustomerTrustLevel,
  resolveCustomerTrustSignal,
} from "../../services/customerTrustService";
import { resolveVerifyUxPolicy } from "../../services/governanceService";
import { getScanInsight } from "../../services/scanInsightService";
import { resolveReplacementStatus } from "../../services/replacementChainService";
import { runPostScanVerificationFlow } from "../../services/publicVerificationPostScanService";
import {
  hashToken as hashQrToken,
  isPrinterTestQrId,
  verifyQrToken,
} from "../../services/qrTokenService";
import { persistVerificationDecision } from "../../services/verificationDecisionService";
import {
  buildPublicIntegrityErrorBody,
  isPublicIntegrityDependencyError,
} from "../../utils/publicIntegrityGuard";
import {
  QRStatus,
  buildPublicVerificationSemantics,
  VerificationProofSource,
  buildContainment,
  buildOwnershipStatus,
  buildOwnershipTransferView,
  buildScanSummary,
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
import {
  applyPublicSemantics,
  buildDecisionResponseBody,
  resolvePrintTrustState,
  safeCreateAuditLog,
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

    return res.json({
      success: true,
      data: await runPostScanVerificationFlow({
        actorDeviceHash,
        baseOwnership,
        baseOwnershipStatus,
        customerUserId,
        deviceTokenHash,
        proofSource,
        qrCode,
        replacement,
        requestDeviceFingerprint,
        requesterIpHash,
        requestQuery,
        requestedTransferToken,
        req,
        riskProfile,
        signedPayload,
        signedToken,
        verifiedSigningMetadata,
        verifyUxPolicy,
      }),
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
