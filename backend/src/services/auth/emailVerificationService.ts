import prisma from "../../config/database";
import { UserStatus } from "@prisma/client";
import { createAuditLog } from "../auditService";
import { sendAuthEmail } from "./authEmailService";
import { buildTokenHashCandidates, hashIp, hashToken, normalizeUserAgent, randomOpaqueToken } from "../../utils/security";
import { normalizeEmailAddress } from "../../utils/email";
import { getTokenHashSecretSet } from "../../utils/secretConfig";

const parseIntEnv = (key: string, fallback: number) => {
  const raw = String(process.env[key] || "").trim();
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
};

const getEmailVerificationTtlHours = () => parseIntEnv("EMAIL_VERIFICATION_TTL_HOURS", 24);

const addHours = (d: Date, hours: number) => new Date(d.getTime() + hours * 60 * 60 * 1000);

const resolveWebAppBaseUrl = () => {
  const explicit = String(process.env.WEB_APP_BASE_URL || "").trim();
  if (explicit) return explicit.replace(/\/+$/, "");
  const cors = String(process.env.CORS_ORIGIN || "").split(",")[0]?.trim() || "";
  if (cors) return cors.replace(/\/+$/, "");
  return "http://localhost:8080";
};

const buildVerificationUrl = (rawToken: string) =>
  `${resolveWebAppBaseUrl()}/verify-email?token=${encodeURIComponent(rawToken)}`;

const userAgentHash = (userAgent: string | null) => {
  const normalized = normalizeUserAgent(userAgent);
  return normalized ? hashToken(`ua:${normalized}`) : null;
};

const tokenSecretVersion = () => getTokenHashSecretSet().current.id;

export const isVerifiedAccount = (user: { emailVerifiedAt?: Date | null }) => Boolean(user.emailVerifiedAt);

export const requestEmailChangeVerification = async (input: {
  userId: string;
  nextEmail: string;
  actorUserId: string;
  actorIpAddress: string | null | undefined;
  actorUserAgent: string | null | undefined;
}) => {
  const nextEmail = normalizeEmailAddress(input.nextEmail);
  if (!nextEmail) throw new Error("Invalid email address");

  const now = new Date();
  const expiresAt = addHours(now, getEmailVerificationTtlHours());
  const rawToken = randomOpaqueToken(32);
  const tokenHash = hashToken(rawToken);

  const user = await prisma.user.findUnique({
    where: { id: input.userId },
    select: {
      id: true,
      email: true,
      name: true,
      orgId: true,
      licenseeId: true,
      pendingEmail: true,
    },
  });

  if (!user) throw new Error("User not found");
  if (normalizeEmailAddress(user.email) === nextEmail) {
    return {
      changed: false as const,
      verificationRequired: false,
      message: "That email is already active on your account.",
    };
  }

  const collision = await prisma.user.findFirst({
    where: {
      id: { not: user.id },
      OR: [{ email: nextEmail }, { pendingEmail: nextEmail }],
    },
    select: { id: true },
  });
  if (collision) throw new Error("Email already in use");

  await prisma.$transaction(async (tx) => {
    await tx.emailVerificationToken.updateMany({
      where: {
        userId: user.id,
        purpose: "EMAIL_CHANGE",
        usedAt: null,
        expiresAt: { gt: now },
      },
      data: { usedAt: now },
    });

    await tx.user.update({
      where: { id: user.id },
      data: {
        pendingEmail: nextEmail,
        pendingEmailRequestedAt: now,
      },
    });

    await tx.emailVerificationToken.create({
      data: {
        userId: user.id,
        email: user.email,
        pendingEmail: nextEmail,
        purpose: "EMAIL_CHANGE",
        tokenHash,
        secretVersion: tokenSecretVersion(),
        expiresAt,
        createdIpHash: hashIp(input.actorIpAddress || null),
        userAgentHash: userAgentHash(input.actorUserAgent || null),
      },
    });
  });

  const verifyUrl = buildVerificationUrl(rawToken);
  const subject = "Confirm your new MSCQR email address";
  const text =
    `A request was made to change the email address on your MSCQR account.\n\n` +
    `Confirm the new address by opening this secure link within ${getEmailVerificationTtlHours()} hours:\n` +
    `${verifyUrl}\n\n` +
    `If you did not request this change, you can ignore this email and keep using ${user.email}.`;

  const delivery = await sendAuthEmail({
    toAddress: nextEmail,
    subject,
    text,
    template: "account_email_change_verification",
    orgId: user.orgId,
    licenseeId: user.licenseeId,
    actorUserId: input.actorUserId,
    ipHash: hashIp(input.actorIpAddress || null),
    userAgent: normalizeUserAgent(input.actorUserAgent),
  });

  await createAuditLog({
    userId: input.actorUserId,
    licenseeId: user.licenseeId || undefined,
    orgId: user.orgId || undefined,
    action: "AUTH_EMAIL_CHANGE_REQUESTED",
    entityType: "User",
    entityId: user.id,
    details: {
      currentEmail: user.email,
      pendingEmail: nextEmail,
      expiresAt,
      emailDelivered: delivery.delivered,
      emailError: delivery.error || null,
    },
    ipAddress: input.actorIpAddress || undefined,
    userAgent: normalizeUserAgent(input.actorUserAgent) || undefined,
  });

  return {
    changed: false as const,
    verificationRequired: true as const,
    pendingEmail: nextEmail,
    expiresAt: expiresAt.toISOString(),
  };
};

export const confirmEmailVerification = async (input: {
  rawToken: string;
  actorIpAddress: string | null | undefined;
  actorUserAgent: string | null | undefined;
}) => {
  const now = new Date();
  const tokenHashCandidates = buildTokenHashCandidates(input.rawToken);

  const result = await prisma.$transaction(async (tx) => {
    const token = await tx.emailVerificationToken.findFirst({
      where: { tokenHash: { in: tokenHashCandidates } },
      select: {
        id: true,
        userId: true,
        email: true,
        pendingEmail: true,
        purpose: true,
        expiresAt: true,
        usedAt: true,
        user: {
          select: {
            id: true,
            email: true,
            pendingEmail: true,
            orgId: true,
            licenseeId: true,
            status: true,
            isActive: true,
            deletedAt: true,
          },
        },
      },
    });

    if (!token || !token.user) throw new Error("Invalid or expired verification link");
    if (token.usedAt) throw new Error("Verification link already used");
    if (token.expiresAt.getTime() <= now.getTime()) throw new Error("Verification link expired");
    if (token.user.deletedAt || token.user.isActive === false) throw new Error("Account is disabled");

    let nextEmail: string | null = token.user.email;
    const updateData: Record<string, unknown> = {
      emailVerifiedAt: now,
    };

    if (token.purpose === "EMAIL_CHANGE") {
      nextEmail = normalizeEmailAddress(token.pendingEmail || token.user.pendingEmail || "");
      if (!nextEmail) throw new Error("Verification link is missing the pending email");

      const collision = await tx.user.findFirst({
        where: {
          id: { not: token.user.id },
          OR: [{ email: nextEmail }, { pendingEmail: nextEmail }],
        },
        select: { id: true },
      });
      if (collision) throw new Error("Email already in use");

      updateData.email = nextEmail;
      updateData.pendingEmail = null;
      updateData.pendingEmailRequestedAt = null;
    }

    const updatedUser = await tx.user.update({
      where: { id: token.user.id },
      data: {
        ...updateData,
        status: token.user.status === UserStatus.INVITED ? UserStatus.ACTIVE : undefined,
      },
      select: {
        id: true,
        email: true,
        orgId: true,
        licenseeId: true,
        role: true,
        emailVerifiedAt: true,
      },
    });

    await tx.emailVerificationToken.update({
      where: { id: token.id },
      data: { usedAt: now },
    });

    if (token.purpose === "EMAIL_CHANGE") {
      await tx.refreshToken.updateMany({
        where: { userId: token.user.id, revokedAt: null },
        data: {
          revokedAt: now,
          revokedReason: "EMAIL_CHANGED",
          lastUsedAt: now,
        },
      });
    }

    return {
      user: updatedUser,
      purpose: token.purpose,
      previousEmail: token.user.email,
      pendingEmail: nextEmail,
    };
  });

  await createAuditLog({
    userId: result.user.id,
    licenseeId: result.user.licenseeId || undefined,
    orgId: result.user.orgId || undefined,
    action: result.purpose === "EMAIL_CHANGE" ? "AUTH_EMAIL_CHANGE_CONFIRMED" : "AUTH_EMAIL_VERIFIED",
    entityType: "User",
    entityId: result.user.id,
    details: {
      email: result.user.email,
      previousEmail: result.previousEmail,
      purpose: result.purpose,
    },
    ipAddress: input.actorIpAddress || undefined,
    userAgent: normalizeUserAgent(input.actorUserAgent) || undefined,
  });

  return {
    verified: true as const,
    purpose: result.purpose,
    email: result.user.email,
  };
};
