import { Request, Response } from "express";

import { createAuditLog } from "../../services/auditService";
import { sendAuthEmail } from "../../services/auth/authEmailService";
import {
  clearCustomerVerifySessionCookie,
  setCustomerVerifySessionCookie,
} from "../../services/customerVerifyCookieService";
import {
  createCustomerOtpChallenge,
  issueCustomerVerifyToken,
  maskEmail,
  requestOtpSchema,
  verifyCustomerOtpChallenge,
  verifyOtpSchema,
} from "./shared";

export const requestCustomerEmailOtp = async (req: Request, res: Response) => {
  try {
    const parsed = requestOtpSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: parsed.error.errors[0]?.message || "Invalid email address",
      });
    }

    const challenge = createCustomerOtpChallenge(parsed.data.email);

    const subject = "Your MSCQR sign-in code";
    const text =
      `Use this one-time code to continue product protection sign-in: ${challenge.otp}\n\n` +
      `This code expires in 10 minutes. If you did not request this code, you can ignore this message.`;

    const emailResult = await sendAuthEmail({
      toAddress: challenge.email,
      subject,
      text,
      template: "verify_customer_email_otp",
      actorUserId: null,
      ipHash: null,
      userAgent: req.get("user-agent") || undefined,
    });

    if (!emailResult.delivered) {
      return res.status(500).json({
        success: false,
        error: emailResult.error || "Could not send OTP email",
      });
    }

    await createAuditLog({
      action: "VERIFY_CUSTOMER_OTP_SENT",
      entityType: "CustomerVerifyAuth",
      entityId: challenge.email,
      details: {
        maskedEmail: maskEmail(challenge.email),
        expiresAt: challenge.expiresAt,
      },
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
    });

    return res.json({
      success: true,
      data: {
        challengeToken: challenge.challengeToken,
        expiresAt: challenge.expiresAt,
        maskedEmail: maskEmail(challenge.email),
      },
    });
  } catch (error) {
    console.error("requestCustomerEmailOtp error:", error);
    return res.status(500).json({
      success: false,
      error: "Could not start email verification",
    });
  }
};

export const verifyCustomerEmailOtp = async (req: Request, res: Response) => {
  try {
    const parsed = verifyOtpSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: parsed.error.errors[0]?.message || "Invalid OTP payload",
      });
    }

    const identity = verifyCustomerOtpChallenge({
      challengeToken: parsed.data.challengeToken,
      otp: parsed.data.otp,
    });

    const token = issueCustomerVerifyToken(identity);
    setCustomerVerifySessionCookie(res, token);

    await createAuditLog({
      action: "VERIFY_CUSTOMER_OTP_VERIFIED",
      entityType: "CustomerVerifyAuth",
      entityId: identity.userId,
      details: {
        maskedEmail: maskEmail(identity.email),
      },
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
    });

    return res.json({
      success: true,
      data: {
        token,
        customer: {
          userId: identity.userId,
          email: identity.email,
          maskedEmail: maskEmail(identity.email),
        },
      },
    });
  } catch (error: any) {
    return res.status(400).json({
      success: false,
      error: error?.message || "Invalid OTP code",
    });
  }
};

export const logoutCustomerVerifySession = async (req: Request, res: Response) => {
  clearCustomerVerifySessionCookie(res);
  await createAuditLog({
    action: "VERIFY_CUSTOMER_LOGOUT",
    entityType: "CustomerVerifyAuth",
    entityId: "cookie_session",
    details: {
      source: "verify_auth_logout",
    },
    ipAddress: req.ip,
    userAgent: req.get("user-agent") || undefined,
  }).catch(() => {});

  return res.json({
    success: true,
    data: {
      cleared: true,
    },
  });
};
