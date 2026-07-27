import { hashPassword } from "./passwordService";
import { buildTokenHashCandidates, hashToken, randomOpaqueToken } from "../../utils/security";
import { sendAuthEmail } from "./authEmailService";
import { renderActionEmail } from "../emailTemplateService";
import {
  consumePasswordResetBoundary,
  requestPasswordResetBoundary,
} from "../../rls-waves/session-b/b01/preAuthRepository";

const addMinutes = (d: Date, minutes: number) => new Date(d.getTime() + minutes * 60 * 1000);

const parseIntEnv = (key: string, fallback: number) => {
  const raw = String(process.env[key] || "").trim();
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
};

const getResetTtlMinutes = () => Math.min(1440, parseIntEnv("PASSWORD_RESET_TTL_MINUTES", 60));

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

  const rawToken = randomOpaqueToken(32);
  const tokenHash = hashToken(rawToken);
  const now = new Date();
  const expiresAt = addMinutes(now, getResetTtlMinutes());
  const request = await requestPasswordResetBoundary({
    normalizedEmail: email,
    tokenHash,
    expiresAt,
    requestedAt: now,
    ipHash: input.ipHash,
    userAgentHash: input.userAgent ? hashToken(input.userAgent) : null,
  });

  // Preserve the constant-success response: no account existence signal leaves this service.
  if (!request?.accepted || !request.deliveryRequired || !request.userId || !request.email) {
    return { ok: true as const };
  }

  const baseUrl = resolveWebAppBaseUrl();
  const resetUrl = `${baseUrl}/reset-password?token=${encodeURIComponent(rawToken)}`;

  const subject = "Reset your MSCQR password";
  const emailBody = renderActionEmail({
    heading: subject,
    intro: "We received a request to reset the password for your MSCQR account.",
    actionLabel: "Reset password",
    actionUrl: resetUrl,
    expiryText: `in ${getResetTtlMinutes()} minutes`,
    reason: "You received this email because a password reset was requested for your MSCQR account.",
  });

  await sendAuthEmail({
    toAddress: request.email,
    subject,
    text: emailBody.text,
    html: emailBody.html,
    template: "reset_password",
    orgId: request.orgId,
    licenseeId: request.licenseeId,
    actorUserId: null,
    ipHash: input.ipHash,
    userAgent: input.userAgent,
  });

  return { ok: true as const };
};

export const resetPasswordWithToken = async (input: {
  rawToken: string;
  newPassword: string;
  ipHash: string | null;
  userAgent: string | null;
}) => {
  const now = new Date();
  const tokenHashCandidates = buildTokenHashCandidates(input.rawToken);
  const passwordHash = await hashPassword(input.newPassword);
  const out = await consumePasswordResetBoundary({ tokenHashCandidates, passwordHash, consumedAt: now });
  if (!out) throw new Error("Invalid or expired reset token");

  return out;
};
