import { VerificationDecisionOutcome } from "@prisma/client";

import prisma from "../../config/database";
import { persistVerificationDecision } from "../../services/verificationDecisionService";
import { resolveCustomerTrustLevel } from "../../services/customerTrustService";
import {
  hashToken as hashQrToken,
  isPrinterTestQrId,
  verifyQrToken,
} from "../../services/qrTokenService";
import { buildPublicVerificationSemantics, type VerificationProofSource } from "./shared";
import { buildMissingQrVerificationPayload } from "./verificationResponseBuilders";
import {
  applyPublicSemantics,
  buildDecisionResponseBody,
  buildSignedTokenErrorResponse,
} from "./verificationDecisionHelpers";

type SignedVerificationResolution = {
  qrCode: any;
  signedPayload: ReturnType<typeof verifyQrToken>["payload"];
  verifiedSigningMetadata: Record<string, unknown> | null;
};

type SignedVerificationOutcome =
  | { kind: "continue"; value: SignedVerificationResolution }
  | { kind: "response"; statusCode: number; body: Record<string, unknown> };

type SignedVerificationContext = {
  actorDeviceHash: string | null;
  customerAuthStrength: Parameters<typeof resolveCustomerTrustLevel>[0]["customerAuthStrength"];
  customerUserId: string | null;
  defaultVerifyUxPolicy: Record<string, unknown>;
  deviceTokenHash: string | null;
  normalizedCode: string | null;
  originalUrl: string;
  proofSource: VerificationProofSource;
  qrVerificationInclude: any;
  queryToken: string | null;
  requestUrl: string;
  requesterIpHash: string | null;
};

const responseDecisionBase = (context: SignedVerificationContext) => ({
  customerTrustLevel: resolveCustomerTrustLevel({
    customerUserId: context.customerUserId,
    deviceTokenHash: context.deviceTokenHash,
    customerAuthStrength: context.customerAuthStrength,
  }),
  actorIpHash: context.requesterIpHash,
  actorDeviceHash: context.actorDeviceHash,
});

export const resolveSignedVerificationTarget = async (
  context: SignedVerificationContext
): Promise<SignedVerificationOutcome> => {
  const respondSignedTokenFailure = async (
    statusCode: number,
    message: string,
    scanOutcome: string,
    errorOutcome: VerificationDecisionOutcome
  ): Promise<SignedVerificationOutcome> => {
    const semantics = buildPublicVerificationSemantics({
      classification: "BLOCKED_BY_SECURITY",
      proofSource: "SIGNED_LABEL",
      integrityError: true,
    });
    const decision = await persistVerificationDecision({
      code: context.normalizedCode || null,
      proofSource: "SIGNED_LABEL",
      isAuthentic: false,
      errorOutcome,
      reasons: [message, scanOutcome],
      publicOutcome: semantics.publicOutcome,
      riskDisposition: semantics.riskDisposition,
      messageKey: semantics.messageKey,
      nextActionKey: semantics.nextActionKey,
      metadata: {
        route: context.originalUrl || context.requestUrl,
        signedToken: true,
        invalidOutcome: scanOutcome,
      },
      ...responseDecisionBase(context),
    });
    const response = buildSignedTokenErrorResponse(message, scanOutcome);
    return {
      kind: "response",
      statusCode,
      body: {
        success: true,
        data: await buildDecisionResponseBody(applyPublicSemantics(response.data, semantics), decision),
      },
    };
  };

  if (!context.queryToken) {
    throw new Error("resolveSignedVerificationTarget requires a signed token");
  }

  let signedPayload: ReturnType<typeof verifyQrToken>["payload"];
  let verifiedSigningMetadata: Record<string, unknown> | null = null;

  try {
    const verifiedToken = verifyQrToken(context.queryToken);
    signedPayload = verifiedToken.payload;
    verifiedSigningMetadata = verifiedToken.signing;
  } catch {
    return respondSignedTokenFailure(
      400,
      "Invalid or tampered QR token.",
      "INVALID_SIGNATURE",
      VerificationDecisionOutcome.INVALID_SIGNATURE
    );
  }

  if (!signedPayload.qr_id || !signedPayload.licensee_id || !signedPayload.nonce) {
    return respondSignedTokenFailure(400, "Invalid QR token payload.", "INVALID_PAYLOAD", VerificationDecisionOutcome.INVALID_PAYLOAD);
  }

  if (signedPayload.exp && signedPayload.exp * 1000 < Date.now()) {
    return respondSignedTokenFailure(400, "QR token expired.", "EXPIRED", VerificationDecisionOutcome.EXPIRED);
  }

  if (isPrinterTestQrId(signedPayload.qr_id)) {
    const semantics = buildPublicVerificationSemantics({
      classification: "LEGIT_REPEAT",
      proofSource: context.proofSource,
      printerSetupOnly: true,
    });
    const decision = await persistVerificationDecision({
      code: "PRINTER_SETUP_TEST",
      proofSource: context.proofSource,
      classification: "LEGIT_REPEAT",
      reasons: ["Printer setup test label verified."],
      isAuthentic: true,
      publicOutcome: semantics.publicOutcome,
      riskDisposition: semantics.riskDisposition,
      messageKey: semantics.messageKey,
      nextActionKey: semantics.nextActionKey,
      metadata: {
        route: context.originalUrl || context.requestUrl,
        signedToken: true,
        scanOutcome: "PRINTER_SETUP_TEST",
      },
      ...responseDecisionBase(context),
    });

    return {
      kind: "response",
      statusCode: 200,
      body: {
        success: true,
        data: await buildDecisionResponseBody(
          applyPublicSemantics(
            {
              isAuthentic: true,
              message:
                "MSCQR printer setup test label verified. This QR is for printer setup only and does not represent a product.",
              scanOutcome: "PRINTER_SETUP_TEST",
              classification: "LEGIT_REPEAT",
              code: "PRINTER_SETUP_TEST",
              status: "TEST_ONLY",
              proofSource: context.proofSource,
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
            semantics
          ),
          decision
        ),
      },
    };
  }

  const qrCode: any = await prisma.qRCode.findUnique({
    where: { id: signedPayload.qr_id },
    include: context.qrVerificationInclude,
  });

  if (!qrCode) {
    const semantics = buildPublicVerificationSemantics({
      classification: "NOT_FOUND",
      proofSource: context.proofSource,
      notFound: true,
    });
    const decision = await persistVerificationDecision({
      code: context.normalizedCode || null,
      proofSource: context.proofSource,
      classification: "NOT_FOUND",
      notFound: true,
      isAuthentic: false,
      reasons: ["Code not found in registry."],
      publicOutcome: semantics.publicOutcome,
      riskDisposition: semantics.riskDisposition,
      messageKey: semantics.messageKey,
      nextActionKey: semantics.nextActionKey,
      metadata: {
        route: context.originalUrl || context.requestUrl,
        signedToken: true,
      },
      ...responseDecisionBase(context),
    });

    return {
      kind: "response",
      statusCode: 404,
      body: {
        success: true,
        data: await buildDecisionResponseBody(
          applyPublicSemantics(
            buildMissingQrVerificationPayload({
              normalizedCode: context.normalizedCode || null,
              reasons: ["Code not found in registry."],
              verifyUxPolicy: context.defaultVerifyUxPolicy,
              proofSource: context.proofSource,
            }),
            semantics
          ),
          decision
        ),
      },
    };
  }

  if (context.normalizedCode && context.normalizedCode !== qrCode.code) {
    return respondSignedTokenFailure(
      400,
      "QR token does not match this verification URL.",
      "TOKEN_MISMATCH",
      VerificationDecisionOutcome.TOKEN_MISMATCH
    );
  }

  const tokenHash = hashQrToken(context.queryToken);
  if (!qrCode.tokenHash) {
    return respondSignedTokenFailure(400, "QR token has not been issued.", "NOT_ISSUED", VerificationDecisionOutcome.INVALID_PAYLOAD);
  }
  if (qrCode.tokenHash !== tokenHash || (qrCode.tokenNonce && signedPayload.nonce !== qrCode.tokenNonce)) {
    return respondSignedTokenFailure(400, "QR token revoked or mismatched.", "TOKEN_MISMATCH", VerificationDecisionOutcome.TOKEN_MISMATCH);
  }
  if (
    signedPayload.epoch !== undefined &&
    Number.isFinite(Number(signedPayload.epoch)) &&
    Number(signedPayload.epoch) !== Number(qrCode.replayEpoch || 1)
  ) {
    return respondSignedTokenFailure(400, "QR token replay epoch mismatch.", "TOKEN_MISMATCH", VerificationDecisionOutcome.TOKEN_MISMATCH);
  }
  if (signedPayload.epoch === undefined && Number(qrCode.replayEpoch || 1) > 1) {
    return respondSignedTokenFailure(400, "QR token replay epoch missing.", "TOKEN_MISMATCH", VerificationDecisionOutcome.TOKEN_MISMATCH);
  }
  if (signedPayload.licensee_id !== qrCode.licenseeId) {
    return respondSignedTokenFailure(400, "QR token invalid for this licensee.", "TOKEN_MISMATCH", VerificationDecisionOutcome.TOKEN_MISMATCH);
  }
  if (signedPayload.batch_id !== (qrCode.batchId ?? null)) {
    return respondSignedTokenFailure(400, "QR token invalid for this batch.", "TOKEN_MISMATCH", VerificationDecisionOutcome.TOKEN_MISMATCH);
  }
  if (signedPayload.manufacturer_id !== undefined && signedPayload.manufacturer_id !== ((qrCode.batch as any)?.manufacturer?.id ?? null)) {
    return respondSignedTokenFailure(400, "QR token invalid for this manufacturer.", "TOKEN_MISMATCH", VerificationDecisionOutcome.TOKEN_MISMATCH);
  }

  return {
    kind: "continue",
    value: {
      qrCode,
      signedPayload,
      verifiedSigningMetadata,
    },
  };
};
