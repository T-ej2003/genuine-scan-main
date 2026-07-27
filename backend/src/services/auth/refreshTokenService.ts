import { Prisma } from "@prisma/client";

import { getB01PreAuthPrisma } from "../../rls-waves/session-b/b01/runtimeClients";
import {
  claimRefreshTokenRotation,
  completeRefreshTokenRotation,
  createRefreshTokenRecord,
  findRefreshTokenByIdentifier,
  listActiveRefreshTokenRecords,
  revokeAllRefreshTokenRecords,
  revokeRefreshTokenByIdentifier,
  revokeRefreshTokenRotationScope,
  type SessionCredentialClient,
} from "../../rls-waves/session-b/b01/sessionCredentialRepository";
import { buildTokenHashCandidates } from "../../utils/security";
import { hashRefreshToken, getRefreshTokenTtlDays, newRefreshToken } from "./tokenService";

const addDays = (d: Date, days: number) => new Date(d.getTime() + days * 24 * 60 * 60 * 1000);

type RefreshRotationToken = {
  id: string;
  userId: string;
  orgId: string | null;
  expiresAt: Date;
  authenticatedAt: Date | null;
  mfaVerifiedAt: Date | null;
};

export type RefreshRotationDecision<TRotated, TConsumed = TRotated> =
  | {
      action: "rotate";
      value: TRotated;
      orgId: string | null;
      authenticatedAt: Date;
      mfaVerifiedAt: Date | null;
      expiresAt?: Date;
    }
  | {
      action: "consume";
      value: TConsumed;
      revokeScope: "password-only" | "all";
      revokeReason: string;
    }
  | {
      action: "deny";
      reason: "REVOKED";
      revokeScope: "token" | "all";
      revokeReason: string;
    };

export const createRefreshToken = async (input: {
  userId: string;
  orgId: string | null;
  rawToken: string;
  ipHash: string | null;
  userAgent: string | null;
  authenticatedAt?: Date | null;
  mfaVerifiedAt?: Date | null;
  now?: Date;
  expiresAt?: Date;
}, db: SessionCredentialClient) => {
  const now = input.now || new Date();
  const expiresAt = input.expiresAt || addDays(now, getRefreshTokenTtlDays());
  const tokenHash = hashRefreshToken(input.rawToken);

  const row = await createRefreshTokenRecord(db, {
    userId: input.userId,
    orgId: input.orgId,
    tokenHash,
    expiresAt,
    ipHash: input.ipHash,
    userAgent: input.userAgent,
    authenticatedAt: input.authenticatedAt || now,
    mfaVerifiedAt: input.mfaVerifiedAt || null,
    createdAt: now,
  });

  return { row, expiresAt, tokenHash };
};

export const revokeAllUserRefreshTokens = async (input: {
  userId: string;
  reason: string;
  now?: Date;
}, db: SessionCredentialClient) => {
  const now = input.now || new Date();
  return revokeAllRefreshTokenRecords(db, {
    userId: input.userId,
    reason: input.reason,
    revokedAt: now,
  });
};

export const findRefreshTokenById = async (
  input: { sessionId: string; userId: string },
  db: SessionCredentialClient
) => findRefreshTokenByIdentifier(db, input);

export const listActiveRefreshTokensForUser = async (
  userId: string,
  db: SessionCredentialClient,
  checkedAt = new Date()
) => listActiveRefreshTokenRecords(db, { userId, checkedAt });

export const revokeRefreshTokenById = async (input: {
  sessionId: string;
  userId: string;
  reason: string;
  now?: Date;
}, db: SessionCredentialClient) => {
  const now = input.now || new Date();
  const result = await revokeRefreshTokenByIdentifier(db, {
    sessionId: input.sessionId,
    userId: input.userId,
    reason: input.reason,
    revokedAt: now,
  });
  return result.revoked;
};

export async function rotateRefreshToken<TRotated = undefined, TConsumed = TRotated, TRotation = undefined>(input: {
  rawToken: string;
  ipHash: string | null;
  userAgent: string | null;
  requestId: string;
  now?: Date;
  decide?: (input: {
    tx: Prisma.TransactionClient;
    token: RefreshRotationToken;
    tokenHashCandidates: string[];
    now: Date;
  }) => Promise<RefreshRotationDecision<TRotated, TConsumed>>;
  afterRotate?: (input: {
    tx: Prisma.TransactionClient;
    predecessor: RefreshRotationToken;
    successor: { id: string; expiresAt: Date; tokenHash: string };
    now: Date;
    value: TRotated;
  }) => Promise<TRotation>;
}): Promise<
  | {
      ok: true;
      rotated: true;
      userId: string;
      orgId: string | null;
      newRawToken: string;
      newTokenId: string;
      newTokenHash: string;
      newExpiresAt: Date;
      authenticatedAt: Date | null;
      mfaVerifiedAt: Date | null;
      value: TRotated;
      rotation: TRotation;
    }
  | {
      ok: true;
      rotated: false;
      userId: string;
      value: TConsumed;
    }
  | {
      ok: false;
      reason: "INVALID" | "EXPIRED" | "REVOKED" | "REUSE_DETECTED";
      userId?: string;
  }
> {
  const now = input.now || new Date();
  const presentedHashCandidates = buildTokenHashCandidates(input.rawToken);

  return getB01PreAuthPrisma().$transaction(async (tx) => {
    const claim = await claimRefreshTokenRotation(tx, {
      tokenHashCandidates: presentedHashCandidates,
      checkedAt: now,
      requestId: input.requestId,
    });
    if (!claim) {
      return { ok: false, reason: "INVALID" } as const;
    }
    if (claim.disposition !== "ACTIVE") {
      return {
        ok: false,
        reason: claim.disposition,
        ...(claim.userId ? { userId: claim.userId } : {}),
      } as const;
    }

    if (!claim.tokenId || !claim.userId || !claim.role || !claim.authAssurance || !claim.expiresAt) {
      throw new Error("app_auth.claim_refresh_token_rotation omitted active authority");
    }
    const tokenRow: RefreshRotationToken = {
      id: claim.tokenId,
      userId: claim.userId,
      orgId: claim.organizationId,
      expiresAt: claim.expiresAt,
      authenticatedAt: claim.authenticatedAt,
      mfaVerifiedAt: claim.mfaVerifiedAt,
    };

    const decision = input.decide
      ? await input.decide({ tx, token: tokenRow, tokenHashCandidates: presentedHashCandidates, now })
      : ({
          action: "rotate",
          value: undefined as TRotated,
          orgId: tokenRow.orgId,
          authenticatedAt: tokenRow.authenticatedAt || now,
          mfaVerifiedAt: tokenRow.mfaVerifiedAt || null,
        } satisfies RefreshRotationDecision<TRotated, TConsumed>);

    const revoke = async (scope: "token" | "password-only" | "all", reason: string) => {
      await revokeRefreshTokenRotationScope(tx, {
        tokenId: tokenRow.id,
        tokenHashCandidates: presentedHashCandidates,
        userId: tokenRow.userId,
        scope,
        reason,
        revokedAt: now,
        requestId: input.requestId,
      });
    };

    if (decision.action === "deny") {
      await revoke(decision.revokeScope, decision.revokeReason);
      return { ok: false, reason: decision.reason, userId: tokenRow.userId } as const;
    }
    if (decision.action === "consume") {
      await revoke(decision.revokeScope, decision.revokeReason);
      return { ok: true, rotated: false, userId: tokenRow.userId, value: decision.value } as const;
    }

    const newRawToken = newRefreshToken();
    const newHash = hashRefreshToken(newRawToken);
    const newExpiresAt = decision.expiresAt || addDays(now, getRefreshTokenTtlDays());

    const successor = await completeRefreshTokenRotation(tx, {
      tokenId: tokenRow.id,
      tokenHashCandidates: presentedHashCandidates,
      userId: tokenRow.userId,
      orgId: decision.orgId,
      tokenHash: newHash,
      expiresAt: newExpiresAt,
      ipHash: input.ipHash,
      userAgent: input.userAgent,
      authenticatedAt: decision.authenticatedAt,
      mfaVerifiedAt: decision.mfaVerifiedAt,
      rotatedAt: now,
      requestId: input.requestId,
    });
    const rotation = input.afterRotate
      ? await input.afterRotate({ tx, predecessor: tokenRow, successor: { ...successor, tokenHash: newHash }, now, value: decision.value })
      : undefined as TRotation;

    return {
      ok: true,
      rotated: true,
      userId: tokenRow.userId,
      orgId: decision.orgId,
      newRawToken,
      newTokenId: successor.id,
      newTokenHash: newHash,
      newExpiresAt: successor.expiresAt,
      authenticatedAt: decision.authenticatedAt,
      mfaVerifiedAt: decision.mfaVerifiedAt,
      value: decision.value,
      rotation,
    } as const;
  }, { timeout: 15_000 });
}
