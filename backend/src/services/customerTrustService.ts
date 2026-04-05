import { CustomerTrustLevel, CustomerTrustReviewState } from "@prisma/client";

import prisma from "../config/database";

type OwnershipLike = {
  isOwnedByRequester?: boolean;
  matchMethod?: "user" | "device_token" | null;
};

type CustomerAuthStrength = "EMAIL_OTP" | "PASSKEY";

const getStore = () => (prisma as any).customerTrustCredential;

const resolveBaseTrustLevel = (input: {
  customerUserId?: string | null;
  deviceTokenHash?: string | null;
  ownershipStatus?: OwnershipLike | null;
  customerAuthStrength?: CustomerAuthStrength | null;
}): CustomerTrustLevel => {
  if (input.customerAuthStrength === "PASSKEY" && String(input.customerUserId || "").trim()) {
    return CustomerTrustLevel.PASSKEY_VERIFIED;
  }
  if (input.ownershipStatus?.isOwnedByRequester && input.ownershipStatus.matchMethod === "user") {
    return CustomerTrustLevel.ACCOUNT_TRUSTED;
  }
  if (input.ownershipStatus?.isOwnedByRequester && input.ownershipStatus.matchMethod === "device_token") {
    return CustomerTrustLevel.DEVICE_TRUSTED;
  }
  if (String(input.customerUserId || "").trim()) return CustomerTrustLevel.ACCOUNT_TRUSTED;
  if (String(input.deviceTokenHash || "").trim()) return CustomerTrustLevel.DEVICE_TRUSTED;
  return CustomerTrustLevel.ANONYMOUS;
};

export const resolveCustomerTrustLevel = (input: {
  customerUserId?: string | null;
  deviceTokenHash?: string | null;
  ownershipStatus?: OwnershipLike | null;
  operatorReviewed?: boolean;
  customerAuthStrength?: CustomerAuthStrength | null;
}): CustomerTrustLevel => {
  if (input.operatorReviewed) return CustomerTrustLevel.OPERATOR_REVIEWED;
  return resolveBaseTrustLevel(input);
};

export const recordCustomerTrustCredential = async (input: {
  qrCodeId: string;
  customerUserId?: string | null;
  customerEmail?: string | null;
  deviceTokenHash?: string | null;
  trustLevel: CustomerTrustLevel;
  source: string;
  reviewState?: CustomerTrustReviewState;
  reviewNote?: string | null;
  reviewedByUserId?: string | null;
  reviewedAt?: Date | null;
  revokedAt?: Date | null;
  revokedReason?: string | null;
  lastAssertionAt?: Date | null;
  lastVerifiedAt?: Date | null;
  claimedAt?: Date | null;
  linkedAt?: Date | null;
  metadata?: Record<string, unknown> | null;
}) => {
  const store = getStore();
  if (!store?.findFirst || !store?.create || !store?.update) return null;

  const qrCodeId = String(input.qrCodeId || "").trim();
  if (!qrCodeId) return null;

  const customerUserId = String(input.customerUserId || "").trim() || null;
  const deviceTokenHash = String(input.deviceTokenHash || "").trim() || null;

  try {
    const where =
      customerUserId || deviceTokenHash
        ? {
            qrCodeId,
            OR: [
              ...(customerUserId ? [{ customerUserId }] : []),
              ...(deviceTokenHash ? [{ deviceTokenHash }] : []),
            ],
          }
        : {
            qrCodeId,
            trustLevel: input.trustLevel,
            source: input.source,
          };

    const existing = await store.findFirst({
      where,
      orderBy: [{ updatedAt: "desc" }],
    });

    const nextReviewState = input.reviewState || existing?.reviewState || CustomerTrustReviewState.UNREVIEWED;
    const reviewTimestamp =
      nextReviewState === CustomerTrustReviewState.UNREVIEWED ? null : input.reviewedAt || existing?.reviewedAt || new Date();

    const data = {
      qrCodeId,
      customerUserId,
      customerEmail: String(input.customerEmail || "").trim() || null,
      deviceTokenHash,
      trustLevel: input.trustLevel,
      reviewState: nextReviewState,
      source: input.source,
      reviewNote:
        nextReviewState === CustomerTrustReviewState.UNREVIEWED
          ? null
          : String(input.reviewNote || existing?.reviewNote || "").trim() || null,
      reviewedByUserId:
        nextReviewState === CustomerTrustReviewState.UNREVIEWED
          ? null
          : String(input.reviewedByUserId || existing?.reviewedByUserId || "").trim() || null,
      reviewedAt: reviewTimestamp || undefined,
      revokedAt:
        nextReviewState === CustomerTrustReviewState.REVOKED
          ? input.revokedAt || existing?.revokedAt || reviewTimestamp || undefined
          : null,
      revokedReason:
        nextReviewState === CustomerTrustReviewState.REVOKED
          ? String(input.revokedReason || existing?.revokedReason || input.reviewNote || "").trim() || null
          : null,
      metadata: input.metadata ?? undefined,
      lastAssertionAt: input.lastAssertionAt ?? existing?.lastAssertionAt ?? undefined,
      lastVerifiedAt: input.lastVerifiedAt ?? existing?.lastVerifiedAt ?? undefined,
      claimedAt: input.claimedAt ?? existing?.claimedAt ?? undefined,
      linkedAt: input.linkedAt ?? existing?.linkedAt ?? undefined,
    };

    if (existing?.id) {
      return await store.update({
        where: { id: existing.id },
        data,
      });
    }

    return await store.create({ data });
  } catch (error) {
    console.warn("customer trust credential skipped:", error);
    return null;
  }
};

export const getLatestCustomerTrustCredential = async (input: {
  qrCodeId: string;
  customerUserId?: string | null;
  deviceTokenHash?: string | null;
}) => {
  const store = getStore();
  if (!store?.findFirst) return null;

  const qrCodeId = String(input.qrCodeId || "").trim();
  if (!qrCodeId) return null;

  const customerUserId = String(input.customerUserId || "").trim();
  const deviceTokenHash = String(input.deviceTokenHash || "").trim();

  const where =
    customerUserId || deviceTokenHash
      ? {
          qrCodeId,
          OR: [
            ...(customerUserId ? [{ customerUserId }] : []),
            ...(deviceTokenHash ? [{ deviceTokenHash }] : []),
          ],
        }
      : { qrCodeId };

  try {
    return await store.findFirst({
      where,
      orderBy: [{ updatedAt: "desc" }],
    });
  } catch (error) {
    console.warn("customer trust lookup skipped:", error);
    return null;
  }
};

export const resolveCustomerTrustSignal = async (input: {
  qrCodeId?: string | null;
  customerUserId?: string | null;
  deviceTokenHash?: string | null;
  ownershipStatus?: OwnershipLike | null;
  customerAuthStrength?: CustomerAuthStrength | null;
}) => {
  const baseTrustLevel = resolveBaseTrustLevel(input);
  const fallbackTrustLevel = resolveBaseTrustLevel({
    customerUserId: input.customerUserId,
    deviceTokenHash: input.deviceTokenHash,
    ownershipStatus: input.ownershipStatus,
    customerAuthStrength: null,
  });

  const trustCredential =
    input.qrCodeId
      ? await getLatestCustomerTrustCredential({
          qrCodeId: input.qrCodeId,
          customerUserId: input.customerUserId,
          deviceTokenHash: input.deviceTokenHash,
        })
      : null;

  const reviewState = (trustCredential?.reviewState as CustomerTrustReviewState | undefined) || CustomerTrustReviewState.UNREVIEWED;
  const reasonCodes: string[] = [];
  const messages: string[] = [];
  let trustLevel = baseTrustLevel;

  if (reviewState === CustomerTrustReviewState.VERIFIED) {
    trustLevel = CustomerTrustLevel.OPERATOR_REVIEWED;
  } else if (reviewState === CustomerTrustReviewState.DISPUTED) {
    trustLevel = fallbackTrustLevel;
    reasonCodes.push("TRUST_DISPUTED");
    messages.push("Requester trust is currently disputed and under operator review.");
  } else if (reviewState === CustomerTrustReviewState.REVOKED) {
    trustLevel = CustomerTrustLevel.ANONYMOUS;
    reasonCodes.push("TRUST_REVOKED");
    messages.push("Requester trust was revoked by MSCQR operations.");
  } else if (baseTrustLevel === CustomerTrustLevel.PASSKEY_VERIFIED) {
    reasonCodes.push("PASSKEY_VERIFIED");
  }

  return {
    trustLevel,
    reviewState,
    reasonCodes,
    messages,
    credentialId: String(trustCredential?.id || "").trim() || null,
  };
};

export const listCustomerTrustCredentialsForQr = async (qrCodeId: string) => {
  const store = getStore();
  if (!store?.findMany) return [];

  const normalizedQrCodeId = String(qrCodeId || "").trim();
  if (!normalizedQrCodeId) return [];

  try {
    return await store.findMany({
      where: { qrCodeId: normalizedQrCodeId },
      orderBy: [{ updatedAt: "desc" }],
    });
  } catch (error) {
    console.warn("customer trust credential list skipped:", error);
    return [];
  }
};

export const updateCustomerTrustCredentialReview = async (input: {
  credentialId: string;
  reviewState: CustomerTrustReviewState;
  reviewedByUserId?: string | null;
  reviewNote?: string | null;
}) => {
  const store = getStore();
  if (!store?.update || !store?.findUnique) return null;

  const credentialId = String(input.credentialId || "").trim();
  if (!credentialId) return null;

  const now = new Date();
  try {
    const existing = await store.findUnique({ where: { id: credentialId } });
    if (!existing) return null;

    return await store.update({
      where: { id: credentialId },
      data: {
        reviewState: input.reviewState,
        reviewNote:
          input.reviewState === CustomerTrustReviewState.UNREVIEWED
            ? null
            : String(input.reviewNote || "").trim() || null,
        reviewedByUserId:
          input.reviewState === CustomerTrustReviewState.UNREVIEWED
            ? null
            : String(input.reviewedByUserId || "").trim() || null,
        reviewedAt: input.reviewState === CustomerTrustReviewState.UNREVIEWED ? null : now,
        revokedAt: input.reviewState === CustomerTrustReviewState.REVOKED ? now : null,
        revokedReason:
          input.reviewState === CustomerTrustReviewState.REVOKED
            ? String(input.reviewNote || "").trim() || existing?.revokedReason || null
            : null,
      },
    });
  } catch (error) {
    console.warn("customer trust credential review update skipped:", error);
    return null;
  }
};
