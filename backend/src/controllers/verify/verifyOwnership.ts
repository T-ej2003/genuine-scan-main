import { OwnershipTransferStatus, Prisma } from "@prisma/client";

import prisma from "../../config/database";
import { maskEmail } from "../../services/customerVerifyAuthService";
import { buildVerifyUrl } from "../../services/qrService";
import { buildTokenHashCandidates, hashToken } from "../../utils/security";
import { guardPublicIntegrityFallback } from "../../utils/publicIntegrityGuard";

export type OwnershipStatus = {
  isClaimed: boolean;
  claimedAt: string | null;
  isOwnedByRequester: boolean;
  isClaimedByAnother: boolean;
  canClaim: boolean;
  state?: "unclaimed" | "owned_by_you" | "owned_by_someone_else" | "claim_not_available";
  matchMethod?: "user" | "device_token" | "ip_fallback" | null;
};

export type OwnershipRecord = {
  id: string;
  userId: string | null;
  claimedAt: Date;
  deviceTokenHash: string | null;
  ipHash: string | null;
  userAgentHash: string | null;
  claimSource: string | null;
  linkedAt: Date | null;
};

export type OwnershipTransferRecord = {
  id: string;
  qrCodeId: string;
  ownershipId: string;
  initiatedByCustomerId: string;
  initiatedByEmail: string | null;
  recipientEmail: string | null;
  status: OwnershipTransferStatus;
  expiresAt: Date;
  acceptedAt: Date | null;
  cancelledAt: Date | null;
  lastViewedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
};

export type OwnershipTransferState =
  | "none"
  | "pending_owner_action"
  | "pending_buyer_action"
  | "ready_to_accept"
  | "accepted"
  | "cancelled"
  | "expired"
  | "invalid";

export type OwnershipTransferStatusView = {
  state: OwnershipTransferState;
  active: boolean;
  canCreate: boolean;
  canCancel: boolean;
  canAccept: boolean;
  initiatedByYou: boolean;
  recipientEmailMasked: string | null;
  initiatedAt: string | null;
  expiresAt: string | null;
  acceptedAt: string | null;
  invalidReason?: string | null;
  transferId?: string | null;
  acceptUrl?: string | null;
};

export const buildOwnershipStatus = (params: {
  ownership: OwnershipRecord | null;
  customerUserId?: string | null;
  deviceTokenHash?: string | null;
  ipHash?: string | null;
  isReady: boolean;
  isBlocked: boolean;
  allowClaim?: boolean;
}): OwnershipStatus => {
  const ownership = params.ownership;
  const customerUserId = String(params.customerUserId || "").trim();
  const deviceTokenHash = String(params.deviceTokenHash || "").trim();
  const allowClaim = params.allowClaim !== false;
  const claimUnavailable = !params.isReady || params.isBlocked || !allowClaim;

  if (!ownership) {
    return {
      isClaimed: false,
      claimedAt: null,
      isOwnedByRequester: false,
      isClaimedByAnother: false,
      canClaim: !claimUnavailable,
      state: claimUnavailable ? "claim_not_available" : "unclaimed",
      matchMethod: null,
    };
  }

  let isOwnedByRequester = false;
  let matchMethod: OwnershipStatus["matchMethod"] = null;

  if (customerUserId && ownership.userId === customerUserId) {
    isOwnedByRequester = true;
    matchMethod = "user";
  } else if (deviceTokenHash && ownership.deviceTokenHash && ownership.deviceTokenHash === deviceTokenHash) {
    isOwnedByRequester = true;
    matchMethod = "device_token";
  }

  return {
    isClaimed: true,
    claimedAt: ownership.claimedAt.toISOString(),
    isOwnedByRequester,
    isClaimedByAnother: !isOwnedByRequester && (Boolean(customerUserId) || Boolean(deviceTokenHash)),
    canClaim: false,
    state: isOwnedByRequester ? "owned_by_you" : "owned_by_someone_else",
    matchMethod,
  };
};

export const isOwnershipStorageMissingError = (error: unknown) => {
  if (!(error instanceof Prisma.PrismaClientKnownRequestError)) return false;
  if (error.code !== "P2021" && error.code !== "P2022") return false;

  const meta = (error.meta || {}) as Record<string, unknown>;
  const metaInfo = `${String(meta.table || "")} ${String(meta.modelName || "")} ${String(meta.column || "")}`.toLowerCase();
  if (metaInfo.includes("ownership")) return true;

  return String(error.message || "").toLowerCase().includes("ownership");
};

export const loadOwnershipByQrCodeId = async (
  qrCodeId: string,
  options?: { strictStorage?: boolean }
): Promise<OwnershipRecord | null> => {
  try {
    return await prisma.ownership.findUnique({
      where: { qrCodeId },
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
  } catch (error) {
    if (isOwnershipStorageMissingError(error)) {
      guardPublicIntegrityFallback({
        strictStorage: options?.strictStorage,
        warningKey: "verify-ownership-storage",
        warningMessage:
          "[verify] Ownership table is unavailable. Continuing verification without ownership data. Apply ownership migrations.",
        degradedMessage: "Verification is temporarily unavailable because ownership records are not ready.",
        degradedCode: "PUBLIC_OWNERSHIP_UNAVAILABLE",
      });
      return null;
    }
    throw error;
  }
};

export const expirePendingOwnershipTransfers = async (where?: Prisma.OwnershipTransferWhereInput) => {
  await prisma.ownershipTransfer.updateMany({
    where: {
      status: OwnershipTransferStatus.PENDING,
      expiresAt: { lt: new Date() },
      ...(where || {}),
    },
    data: {
      status: OwnershipTransferStatus.EXPIRED,
    },
  });
};

export const loadPendingOwnershipTransferForQr = async (qrCodeId: string): Promise<OwnershipTransferRecord | null> => {
  try {
    await expirePendingOwnershipTransfers({ qrCodeId });
    return await prisma.ownershipTransfer.findFirst({
      where: {
        qrCodeId,
        status: OwnershipTransferStatus.PENDING,
      },
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
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
  } catch (error) {
    if (error instanceof Prisma.PrismaClientKnownRequestError && (error.code === "P2021" || error.code === "P2022")) {
      return null;
    }
    throw error;
  }
};

export const loadOwnershipTransferByRawToken = async (rawToken: string): Promise<OwnershipTransferRecord | null> => {
  const token = String(rawToken || "").trim();
  if (!token) return null;

  try {
    const tokenHashCandidates = buildTokenHashCandidates(token);
    await expirePendingOwnershipTransfers({ tokenHash: { in: tokenHashCandidates } });
    const transfer = await prisma.ownershipTransfer.findFirst({
      where: { tokenHash: { in: tokenHashCandidates } },
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
    if (transfer && transfer.status === OwnershipTransferStatus.PENDING) {
      await prisma.ownershipTransfer.update({
        where: { id: transfer.id },
        data: { lastViewedAt: new Date() },
      });
    }
    return transfer;
  } catch (error) {
    if (error instanceof Prisma.PrismaClientKnownRequestError && (error.code === "P2021" || error.code === "P2022")) {
      return null;
    }
    throw error;
  }
};

export const buildOwnershipTransferLink = (code: string, rawToken: string) => {
  const url = new URL(buildVerifyUrl(code));
  url.searchParams.set("transfer", rawToken);
  return url.toString();
};

export const createOwnershipTransferView = (params: {
  code: string;
  transfer: OwnershipTransferRecord | null;
  rawToken?: string | null;
  customerUserId?: string | null;
  ownershipStatus: OwnershipStatus;
  isReady: boolean;
  isBlocked: boolean;
  transferRequested?: boolean;
}): OwnershipTransferStatusView => {
  const transfer = params.transfer;
  const initiatedByYou = Boolean(
    transfer &&
      params.customerUserId &&
      transfer.initiatedByCustomerId &&
      transfer.initiatedByCustomerId === params.customerUserId
  );
  const tokenMatched = Boolean(transfer && params.rawToken);

  if (!transfer) {
    return {
      state: params.transferRequested ? "invalid" : "none",
      active: false,
      canCreate: Boolean(
        params.isReady &&
          !params.isBlocked &&
          params.ownershipStatus.isOwnedByRequester &&
          params.customerUserId
      ),
      canCancel: false,
      canAccept: false,
      initiatedByYou: false,
      recipientEmailMasked: null,
      initiatedAt: null,
      expiresAt: null,
      acceptedAt: null,
      invalidReason: params.transferRequested ? "Transfer link is invalid or has expired." : null,
      transferId: null,
      acceptUrl: null,
    };
  }

  const canAccept =
    tokenMatched &&
    transfer.status === OwnershipTransferStatus.PENDING &&
    Boolean(params.customerUserId) &&
    transfer.initiatedByCustomerId !== params.customerUserId &&
    !params.ownershipStatus.isOwnedByRequester &&
    params.isReady &&
    !params.isBlocked;

  let state: OwnershipTransferState = "pending_buyer_action";
  if (transfer.status === OwnershipTransferStatus.ACCEPTED) state = "accepted";
  else if (transfer.status === OwnershipTransferStatus.CANCELLED) state = "cancelled";
  else if (transfer.status === OwnershipTransferStatus.EXPIRED) state = "expired";
  else if (canAccept) state = "ready_to_accept";
  else if (initiatedByYou) state = "pending_owner_action";
  else if (tokenMatched) state = "pending_buyer_action";

  return {
    state,
    active: transfer.status === OwnershipTransferStatus.PENDING,
    canCreate: false,
    canCancel: initiatedByYou && transfer.status === OwnershipTransferStatus.PENDING,
    canAccept,
    initiatedByYou,
    recipientEmailMasked: transfer.recipientEmail ? maskEmail(transfer.recipientEmail) : null,
    initiatedAt: transfer.createdAt.toISOString(),
    expiresAt: transfer.expiresAt.toISOString(),
    acceptedAt: transfer.acceptedAt?.toISOString() || null,
    invalidReason: null,
    transferId: transfer.id,
    acceptUrl: tokenMatched && params.rawToken ? buildOwnershipTransferLink(params.code, params.rawToken) : null,
  };
};
