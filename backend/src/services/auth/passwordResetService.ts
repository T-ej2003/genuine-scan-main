import prisma from "../../config/database";
import { UserStatus } from "@prisma/client";
import { hashPassword } from "./passwordService";
import { hashToken, randomOpaqueToken } from "../../utils/security";
import { sendAuthEmail } from "./authEmailService";
import { createAuditLog } from "../auditService";

const addMinutes = (d: Date, minutes: number) => new Date(d.getTime() + minutes * 60 * 1000);

const parseIntEnv = (key: string, fallback: number) => {
  const raw = String(process.env[key] || "").trim();
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
};

const getResetTtlMinutes = () => parseIntEnv("PASSWORD_RESET_TTL_MINUTES", 60);

const resolveWebAppBaseUrl = () => {
  const explicit = String(process.env.WEB_APP_BASE_URL || "").trim();
  if (explicit) return explicit.replace(/\/+$/, "");
  const cors = String(process.env.CORS_ORIGIN || "").split(",")[0]?.trim() || "";
  if (cors) return cors.replace(/\/+$/, "");
  return "http://localhost:8080";
};

export const requestPasswordReset = async (input: {
  email: string;
  ipHash: string | null;
  userAgent: string | null;
}) => {
  const email = String(input.email || "").trim().toLowerCase();
  if (!email) throw new Error("Email is required");

  const user = await prisma.user.findUnique({
    where: { email },
    select: { id: true, email: true, isActive: true, deletedAt: true, licenseeId: true, orgId: true },
  });

  // Always return success for privacy; only create token when a valid account exists.
  if (!user || user.deletedAt || user.isActive === false) {
    return { ok: true as const };
  }

  const rawToken = randomOpaqueToken(32);
  const tokenHash = hashToken(rawToken);
  const now = new Date();
  const expiresAt = addMinutes(now, getResetTtlMinutes());

  await prisma.passwordReset.create({
    data: {
      orgId: user.orgId,
      userId: user.id,
      tokenHash,
      expiresAt,
      createdIpHash: input.ipHash,
      userAgentHash: input.userAgent,
    },
  });

  const baseUrl = resolveWebAppBaseUrl();
  const resetUrl = `${baseUrl}/reset-password?token=${encodeURIComponent(rawToken)}`;

  const subject = "Reset your AuthenticQR password";
  const text =
    `We received a request to reset your password.\n\n` +
    `Open this link to set a new password (expires in ${getResetTtlMinutes()} minutes):\n` +
    `${resetUrl}\n\n` +
    `If you did not request this, you can ignore this email.`;

  await sendAuthEmail({
    toAddress: user.email,
    subject,
    text,
    template: "reset_password",
    orgId: user.orgId,
    licenseeId: user.licenseeId,
    actorUserId: null,
    ipHash: input.ipHash,
    userAgent: input.userAgent,
  });

  await createAuditLog({
    userId: user.id,
    licenseeId: user.licenseeId || undefined,
    orgId: user.orgId || undefined,
    action: "AUTH_PASSWORD_RESET_REQUESTED",
    entityType: "PasswordReset",
    entityId: null,
    details: { expiresAt },
    ipHash: input.ipHash || undefined,
    userAgent: input.userAgent || undefined,
  } as any);

  return { ok: true as const };
};

export const resetPasswordWithToken = async (input: {
  rawToken: string;
  newPassword: string;
  ipHash: string | null;
  userAgent: string | null;
}) => {
  const tokenHash = hashToken(input.rawToken);
  const now = new Date();

  const out = await prisma.$transaction(async (tx) => {
    const pr = await tx.passwordReset.findUnique({
      where: { tokenHash },
      select: { id: true, userId: true, usedAt: true, expiresAt: true },
    });

    if (!pr || pr.usedAt) throw new Error("Invalid or expired reset token");
    if (pr.expiresAt.getTime() <= now.getTime()) throw new Error("Reset token expired");

    const passwordHash = await hashPassword(input.newPassword);

    const user = await tx.user.update({
      where: { id: pr.userId },
      data: {
        passwordHash,
        status: UserStatus.ACTIVE,
        failedLoginAttempts: 0,
        lockedUntil: null,
      },
      select: { id: true, email: true, name: true, role: true, licenseeId: true, orgId: true },
    });

    await tx.passwordReset.update({
      where: { id: pr.id },
      data: { usedAt: now },
    });

    // Revoke all refresh tokens (reset should invalidate existing sessions)
    await tx.refreshToken.updateMany({
      where: { userId: user.id, revokedAt: null },
      data: { revokedAt: now, revokedReason: "PASSWORD_RESET", lastUsedAt: now },
    });

    return user;
  });

  await createAuditLog({
    userId: out.id,
    licenseeId: out.licenseeId || undefined,
    orgId: out.orgId || undefined,
    action: "AUTH_PASSWORD_RESET_COMPLETED",
    entityType: "User",
    entityId: out.id,
    details: {},
    ipHash: input.ipHash || undefined,
    userAgent: input.userAgent || undefined,
  } as any);

  return out;
};

