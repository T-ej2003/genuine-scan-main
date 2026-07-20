import { Prisma } from "@prisma/client";

import prisma from "../../config/database";
import { buildTokenHashCandidates } from "../../utils/security";
import { hashRefreshToken, getRefreshTokenTtlDays, newRefreshToken } from "./tokenService";

const addDays = (d: Date, days: number) => new Date(d.getTime() + days * 24 * 60 * 60 * 1000);

type RefreshRotationToken = {
  id: string;
  userId: string;
  orgId: string | null;
  expiresAt: Date;
  revokedAt: Date | null;
  replacedByTokenHash: string | null;
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
}, db: Pick<Prisma.TransactionClient, "refreshToken"> = prisma) => {
  const now = input.now || new Date();
  const expiresAt = addDays(now, getRefreshTokenTtlDays());
  const tokenHash = hashRefreshToken(input.rawToken);

  const row = await db.refreshToken.create({
    data: {
      userId: input.userId,
      orgId: input.orgId,
      tokenHash,
      expiresAt,
      createdIpHash: input.ipHash,
      createdUserAgent: input.userAgent,
      authenticatedAt: input.authenticatedAt || now,
      mfaVerifiedAt: input.mfaVerifiedAt || null,
      lastUsedAt: now,
    },
    select: { id: true },
  });

  return { row, expiresAt, tokenHash };
};

export const revokeRefreshTokenByRaw = async (input: {
  rawToken: string;
  reason: string;
  now?: Date;
}, db: Pick<Prisma.TransactionClient, "refreshToken"> = prisma) => {
  const now = input.now || new Date();
  const tokenHashCandidates = buildTokenHashCandidates(input.rawToken);

  await db.refreshToken.updateMany({
    where: {
      tokenHash: { in: tokenHashCandidates },
      revokedAt: null,
    },
    data: {
      revokedAt: now,
      revokedReason: input.reason,
      lastUsedAt: now,
    },
  });
};

export const revokeAllUserRefreshTokens = async (input: {
  userId: string;
  reason: string;
  now?: Date;
}, db: Pick<Prisma.TransactionClient, "refreshToken"> = prisma) => {
  const now = input.now || new Date();
  await db.refreshToken.updateMany({
    where: {
      userId: input.userId,
      revokedAt: null,
    },
    data: {
      revokedAt: now,
      revokedReason: input.reason,
      lastUsedAt: now,
    },
  });
};

export const revokePasswordOnlyRefreshTokensForUser = async (input: {
  userId: string;
  reason: string;
  now?: Date;
}) => {
  const now = input.now || new Date();
  await prisma.refreshToken.updateMany({
    where: {
      userId: input.userId,
      revokedAt: null,
      mfaVerifiedAt: null,
    },
    data: {
      revokedAt: now,
      revokedReason: input.reason,
      lastUsedAt: now,
    },
  });
};

export const findRefreshTokenByRaw = async (rawToken: string) => {
  const tokenHashCandidates = buildTokenHashCandidates(rawToken);
  return prisma.refreshToken.findFirst({
    where: {
      tokenHash: { in: tokenHashCandidates },
    },
    select: {
      id: true,
      userId: true,
      orgId: true,
      expiresAt: true,
      createdAt: true,
      createdIpHash: true,
      createdUserAgent: true,
      authenticatedAt: true,
      mfaVerifiedAt: true,
      lastUsedAt: true,
      revokedAt: true,
      revokedReason: true,
    },
  });
};

export const listActiveRefreshTokensForUser = async (userId: string) =>
  prisma.refreshToken.findMany({
    where: {
      userId,
      revokedAt: null,
      expiresAt: { gt: new Date() },
    },
    orderBy: [{ createdAt: "desc" }],
    select: {
      id: true,
      userId: true,
      expiresAt: true,
      createdAt: true,
      createdIpHash: true,
      createdUserAgent: true,
      authenticatedAt: true,
      mfaVerifiedAt: true,
      lastUsedAt: true,
    },
  });

export const revokeRefreshTokenById = async (input: {
  sessionId: string;
  userId: string;
  reason: string;
  now?: Date;
}) => {
  const now = input.now || new Date();
  const updated = await prisma.refreshToken.updateMany({
    where: {
      id: input.sessionId,
      userId: input.userId,
      revokedAt: null,
    },
    data: {
      revokedAt: now,
      revokedReason: input.reason,
      lastUsedAt: now,
    },
  });

  return updated.count > 0;
};

export async function rotateRefreshToken<TRotated = undefined, TConsumed = TRotated>(input: {
  rawToken: string;
  ipHash: string | null;
  userAgent: string | null;
  now?: Date;
  decide?: (input: {
    tx: Prisma.TransactionClient;
    token: RefreshRotationToken;
    now: Date;
  }) => Promise<RefreshRotationDecision<TRotated, TConsumed>>;
}): Promise<
  | {
      ok: true;
      rotated: true;
      userId: string;
      orgId: string | null;
      newRawToken: string;
      newTokenId: string;
      newExpiresAt: Date;
      authenticatedAt: Date | null;
      mfaVerifiedAt: Date | null;
      value: TRotated;
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

  return prisma.$transaction(async (tx) => {
    const candidate = await tx.refreshToken.findFirst({
      where: { tokenHash: { in: presentedHashCandidates } },
      select: { id: true },
    });

    if (!candidate) {
      return { ok: false, reason: "INVALID" } as const;
    }

    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${`refresh_token:${candidate.id}`}, 0))`;
    const tokenRow = await tx.refreshToken.findUnique({
      where: { id: candidate.id },
      select: {
        id: true,
        userId: true,
        orgId: true,
        expiresAt: true,
        revokedAt: true,
        replacedByTokenHash: true,
        authenticatedAt: true,
        mfaVerifiedAt: true,
      },
    });
    if (!tokenRow) return { ok: false, reason: "INVALID" } as const;

    if (tokenRow.revokedAt) {
      // Reuse detection: a rotated token was presented again.
      if (tokenRow.replacedByTokenHash) {
        await tx.refreshToken.updateMany({
          where: { userId: tokenRow.userId, revokedAt: null },
          data: {
            revokedAt: now,
            revokedReason: "REUSE_DETECTED",
            lastUsedAt: now,
          },
        });
        return { ok: false, reason: "REUSE_DETECTED", userId: tokenRow.userId } as const;
      }
      return { ok: false, reason: "REVOKED", userId: tokenRow.userId } as const;
    }

    if (tokenRow.expiresAt.getTime() <= now.getTime()) {
      await tx.refreshToken.updateMany({
        where: { id: tokenRow.id, revokedAt: null },
        data: { revokedAt: now, revokedReason: "EXPIRED", lastUsedAt: now },
      });
      return { ok: false, reason: "EXPIRED", userId: tokenRow.userId } as const;
    }

    const decision = input.decide
      ? await input.decide({ tx, token: tokenRow, now })
      : ({
          action: "rotate",
          value: undefined as TRotated,
          orgId: tokenRow.orgId,
          authenticatedAt: tokenRow.authenticatedAt || now,
          mfaVerifiedAt: tokenRow.mfaVerifiedAt || null,
        } satisfies RefreshRotationDecision<TRotated, TConsumed>);

    const revoke = async (scope: "token" | "password-only" | "all", reason: string) => {
      await tx.refreshToken.updateMany({
        where: {
          userId: tokenRow.userId,
          revokedAt: null,
          ...(scope === "token" ? { id: tokenRow.id } : {}),
          ...(scope === "password-only" ? { mfaVerifiedAt: null } : {}),
        },
        data: { revokedAt: now, revokedReason: reason, lastUsedAt: now },
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
    const newExpiresAt = addDays(now, getRefreshTokenTtlDays());

    const successor = await tx.refreshToken.create({
      data: {
        userId: tokenRow.userId,
        orgId: decision.orgId,
        tokenHash: newHash,
        expiresAt: newExpiresAt,
        createdIpHash: input.ipHash,
        createdUserAgent: input.userAgent,
        authenticatedAt: decision.authenticatedAt,
        mfaVerifiedAt: decision.mfaVerifiedAt,
        lastUsedAt: now,
      },
      select: { id: true },
    });

    const claimed = await tx.refreshToken.updateMany({
      where: { id: tokenRow.id, revokedAt: null },
      data: {
        revokedAt: now,
        revokedReason: "ROTATED",
        replacedByTokenHash: newHash,
        lastUsedAt: now,
      },
    });
    if (claimed.count !== 1) throw new Error("REFRESH_TOKEN_ROTATION_LOST");

    return {
      ok: true,
      rotated: true,
      userId: tokenRow.userId,
      orgId: decision.orgId,
      newRawToken,
      newTokenId: successor.id,
      newExpiresAt,
      authenticatedAt: decision.authenticatedAt,
      mfaVerifiedAt: decision.mfaVerifiedAt,
      value: decision.value,
    } as const;
  });
}
