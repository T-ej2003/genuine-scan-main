import prisma from "../../config/database";
import { buildTokenHashCandidates } from "../../utils/security";
import { hashRefreshToken, getRefreshTokenTtlDays, newRefreshToken } from "./tokenService";

const addDays = (d: Date, days: number) => new Date(d.getTime() + days * 24 * 60 * 60 * 1000);

export const createRefreshToken = async (input: {
  userId: string;
  orgId: string | null;
  rawToken: string;
  ipHash: string | null;
  userAgent: string | null;
  now?: Date;
}) => {
  const now = input.now || new Date();
  const expiresAt = addDays(now, getRefreshTokenTtlDays());
  const tokenHash = hashRefreshToken(input.rawToken);

  const row = await prisma.refreshToken.create({
    data: {
      userId: input.userId,
      orgId: input.orgId,
      tokenHash,
      expiresAt,
      createdIpHash: input.ipHash,
      createdUserAgent: input.userAgent,
      lastUsedAt: now,
    },
  });

  return { row, expiresAt, tokenHash };
};

export const revokeRefreshTokenByRaw = async (input: {
  rawToken: string;
  reason: string;
  now?: Date;
}) => {
  const now = input.now || new Date();
  const tokenHashCandidates = buildTokenHashCandidates(input.rawToken);

  await prisma.refreshToken.updateMany({
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
}) => {
  const now = input.now || new Date();
  await prisma.refreshToken.updateMany({
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

export const rotateRefreshToken = async (input: {
  rawToken: string;
  ipHash: string | null;
  userAgent: string | null;
  now?: Date;
}): Promise<
  | {
      ok: true;
      userId: string;
      orgId: string | null;
      newRawToken: string;
      newExpiresAt: Date;
    }
  | {
      ok: false;
      reason: "INVALID" | "EXPIRED" | "REVOKED" | "REUSE_DETECTED";
      userId?: string;
    }
> => {
  const now = input.now || new Date();
  const presentedHashCandidates = buildTokenHashCandidates(input.rawToken);

  return prisma.$transaction(async (tx) => {
    const tokenRow = await tx.refreshToken.findFirst({
      where: { tokenHash: { in: presentedHashCandidates } },
      select: {
        id: true,
        userId: true,
        orgId: true,
        tokenHash: true,
        expiresAt: true,
        revokedAt: true,
        replacedByTokenHash: true,
      },
    });

    if (!tokenRow) {
      return { ok: false, reason: "INVALID" } as const;
    }

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
      await tx.refreshToken.update({
        where: { id: tokenRow.id },
        data: { revokedAt: now, revokedReason: "EXPIRED", lastUsedAt: now },
      });
      return { ok: false, reason: "EXPIRED", userId: tokenRow.userId } as const;
    }

    const newRawToken = newRefreshToken();
    const newHash = hashRefreshToken(newRawToken);
    const newExpiresAt = addDays(now, getRefreshTokenTtlDays());

    await tx.refreshToken.create({
      data: {
        userId: tokenRow.userId,
        orgId: tokenRow.orgId,
        tokenHash: newHash,
        expiresAt: newExpiresAt,
        createdIpHash: input.ipHash,
        createdUserAgent: input.userAgent,
        lastUsedAt: now,
      },
    });

    await tx.refreshToken.update({
      where: { id: tokenRow.id },
      data: {
        revokedAt: now,
        revokedReason: "ROTATED",
        replacedByTokenHash: newHash,
        lastUsedAt: now,
      },
    });

    return {
      ok: true,
      userId: tokenRow.userId,
      orgId: tokenRow.orgId,
      newRawToken,
      newExpiresAt,
    } as const;
  });
};
