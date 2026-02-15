import { Request, Response } from "express";
import { z } from "zod";

import prisma from "../config/database";
import {
  clearCustomerSession,
  getCustomerIdentityContext,
  issueCustomerSession,
} from "../services/customerSessionService";
import {
  authenticateWithGoogle,
  requestEmailOtp,
  verifyEmailOtp,
} from "../services/customerAuthService";

const googleAuthSchema = z.object({
  idToken: z.string().trim().min(20),
});

const otpRequestSchema = z.object({
  email: z.string().trim().email().max(160),
  name: z.string().trim().max(120).optional(),
});

const otpVerifySchema = z.object({
  email: z.string().trim().email().max(160),
  otp: z.string().trim().min(4).max(10),
  name: z.string().trim().max(120).optional(),
});

const asCustomerPayload = (user: {
  id: string;
  email: string;
  name: string | null;
  provider: string;
  createdAt: Date;
}) => ({
  id: user.id,
  email: user.email,
  name: user.name,
  provider: user.provider,
  createdAt: user.createdAt,
});

export const getCurrentCustomer = async (req: Request, res: Response) => {
  try {
    const identity = getCustomerIdentityContext(req, res);

    if (!identity.customerUserId) {
      return res.json({
        success: true,
        data: {
          user: null,
          anonVisitorId: identity.anonVisitorId,
        },
      });
    }

    const user = await prisma.customerUser.findUnique({
      where: { id: identity.customerUserId },
      select: {
        id: true,
        email: true,
        name: true,
        provider: true,
        createdAt: true,
      },
    });

    if (!user) {
      clearCustomerSession(res);
      return res.json({
        success: true,
        data: {
          user: null,
          anonVisitorId: identity.anonVisitorId,
        },
      });
    }

    return res.json({
      success: true,
      data: {
        user: asCustomerPayload(user),
        anonVisitorId: identity.anonVisitorId,
      },
    });
  } catch (error) {
    console.error("getCurrentCustomer error:", error);
    return res.status(500).json({ success: false, error: "Failed to load current customer" });
  }
};

export const googleCustomerAuth = async (req: Request, res: Response) => {
  try {
    const parsed = googleAuthSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });
    }

    const user = await authenticateWithGoogle({ idToken: parsed.data.idToken });
    issueCustomerSession(res, {
      id: user.id,
      email: user.email,
      name: user.name,
      provider: user.provider,
    });

    const identity = getCustomerIdentityContext(req, res);

    return res.json({
      success: true,
      data: {
        user: asCustomerPayload(user),
        anonVisitorId: identity.anonVisitorId,
      },
    });
  } catch (error: any) {
    const msg = error?.message || "Google sign-in failed";
    return res.status(400).json({ success: false, error: msg });
  }
};

export const requestCustomerOtp = async (req: Request, res: Response) => {
  try {
    const parsed = otpRequestSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });
    }

    const out = await requestEmailOtp({
      email: parsed.data.email,
      name: parsed.data.name,
    });

    return res.json({
      success: true,
      data: {
        delivered: out.delivered,
        expiresAt: out.expiresAt,
      },
    });
  } catch (error: any) {
    return res.status(400).json({ success: false, error: error?.message || "Could not send OTP" });
  }
};

export const verifyCustomerOtp = async (req: Request, res: Response) => {
  try {
    const parsed = otpVerifySchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });
    }

    const user = await verifyEmailOtp({
      email: parsed.data.email,
      otp: parsed.data.otp,
      name: parsed.data.name,
    });

    issueCustomerSession(res, {
      id: user.id,
      email: user.email,
      name: user.name,
      provider: user.provider,
    });

    const identity = getCustomerIdentityContext(req, res);

    return res.json({
      success: true,
      data: {
        user: asCustomerPayload(user),
        anonVisitorId: identity.anonVisitorId,
      },
    });
  } catch (error: any) {
    return res.status(400).json({ success: false, error: error?.message || "OTP verification failed" });
  }
};

export const logoutCustomer = async (_req: Request, res: Response) => {
  clearCustomerSession(res);
  return res.json({ success: true, data: { loggedOut: true } });
};
