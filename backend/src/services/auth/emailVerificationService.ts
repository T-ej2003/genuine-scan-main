import { Prisma } from "@prisma/client";
import { createAuditLog } from "../auditService";
import { sendAuthEmail } from "./authEmailService";
import { renderActionEmail } from "../emailTemplateService";
import { buildTokenHashCandidates, hashIp, hashToken, normalizeUserAgent, randomOpaqueToken } from "../../utils/security";
import { normalizeEmailAddress } from "../../utils/email";
import { getTokenHashSecretSet } from "../../utils/secretConfig";
import { consumeEmailVerificationBoundary } from "../../rls-waves/session-b/b01/preAuthRepository";
import { prepareAuthenticatedEmailChange } from "../../rls-waves/session-b/b01/authenticatedSecurityRepository";

type EmailChangeDb = Pick<Prisma.TransactionClient, "$queryRaw">;

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
}, db: EmailChangeDb) => {
  const nextEmail = normalizeEmailAddress(input.nextEmail);
  if (!nextEmail) throw new Error("Invalid email address");

  const now = new Date();
  const expiresAt = addHours(now, getEmailVerificationTtlHours());
  const rawToken = randomOpaqueToken(32);
  const tokenHash = hashToken(rawToken);

  const prepared = await prepareAuthenticatedEmailChange({
    nextEmail,
    tokenHash,
    secretVersion: tokenSecretVersion(),
    expiresAt,
    requestedAt: now,
    ipHash: hashIp(input.actorIpAddress || null),
    userAgentHash: userAgentHash(input.actorUserAgent || null),
  }, db);
  if (prepared.userId !== input.userId) throw new Error("Email-change boundary returned the wrong actor");
  if (!prepared.verificationRequired) {
    return {
      changed: false as const,
      verificationRequired: false as const,
      pendingEmail: null,
      expiresAt: null,
      deliver: async () => undefined,
    };
  }
  if (prepared.pendingEmail !== nextEmail || !(prepared.expiresAt instanceof Date)) {
    throw new Error("Email-change boundary returned an invalid verification result");
  }

  const verifyUrl = buildVerificationUrl(rawToken);
  const subject = "Confirm your new MSCQR email address";
  const emailBody = renderActionEmail({
    heading: subject,
    intro: "A request was made to change the email address on your MSCQR account.",
    actionLabel: "Confirm email address",
    actionUrl: verifyUrl,
    expiryText: `in ${getEmailVerificationTtlHours()} hours`,
    reason: "You received this email because an authenticated MSCQR account requested an email address change.",
    extraText: `If you did not request this change, keep using ${prepared.currentEmail} and review your account security settings.`,
  });

  const deliver = async () => {
    const delivery = await sendAuthEmail({
      toAddress: nextEmail,
      subject,
      text: emailBody.text,
      html: emailBody.html,
      template: "account_email_change_verification",
      orgId: prepared.orgId,
      licenseeId: prepared.licenseeId,
      actorUserId: input.actorUserId,
      ipHash: hashIp(input.actorIpAddress || null),
      userAgent: normalizeUserAgent(input.actorUserAgent),
    });

    await createAuditLog({
      userId: input.actorUserId,
      licenseeId: prepared.licenseeId || undefined,
      orgId: prepared.orgId || undefined,
      action: "AUTH_EMAIL_CHANGE_REQUESTED",
      entityType: "User",
      entityId: prepared.userId,
      details: {
        currentEmail: prepared.currentEmail,
        pendingEmail: nextEmail,
        expiresAt: prepared.expiresAt,
        emailDelivered: delivery.delivered,
        emailError: delivery.error || null,
      },
      ipAddress: input.actorIpAddress || undefined,
      userAgent: normalizeUserAgent(input.actorUserAgent) || undefined,
    });
  };

  return {
    changed: false as const,
    verificationRequired: true as const,
    pendingEmail: nextEmail,
    expiresAt: prepared.expiresAt.toISOString(),
    deliver,
  };
};

export const confirmEmailVerification = async (input: {
  rawToken: string;
  actorIpAddress: string | null | undefined;
  actorUserAgent: string | null | undefined;
}) => {
  const now = new Date();
  const tokenHashCandidates = buildTokenHashCandidates(input.rawToken);
  const result = await consumeEmailVerificationBoundary({ tokenHashCandidates, consumedAt: now });
  if (!result?.verified) throw new Error("Invalid or expired verification link");

  return {
    verified: true as const,
    purpose: result.purpose,
    email: result.email,
  };
};
