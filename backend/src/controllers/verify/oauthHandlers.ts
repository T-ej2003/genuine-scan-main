import { Request, Response } from "express";
import { z } from "zod";

import { createAuditLogSafely } from "../../services/auditService";
import {
  buildCustomerOAuthAuthorizationUrl,
  exchangeCustomerOAuthTicketForSession,
  finishCustomerOAuthCallback,
  listConfiguredCustomerOAuthProviders,
  type CustomerOAuthProvider,
} from "../../services/customerVerifyOAuthService";

const providerSchema = z.enum(["google"]);

const startSchema = z.object({
  returnTo: z.string().trim().url(),
});

const exchangeSchema = z.object({
  ticket: z.string().trim().min(24),
});

const parseProvider = (req: Request) => providerSchema.safeParse(req.params?.provider);

export const listCustomerOAuthProviders = async (_req: Request, res: Response) => {
  return res.json({
    success: true,
    data: {
      items: listConfiguredCustomerOAuthProviders(),
    },
  });
};

export const startCustomerOAuth = async (req: Request, res: Response) => {
  const provider = parseProvider(req);
  if (!provider.success) {
    return res.status(400).json({ success: false, error: "Invalid OAuth provider" });
  }

  const parsed = startSchema.safeParse(req.query || {});
  if (!parsed.success) {
    return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid return URL" });
  }

  try {
    const authorizationUrl = buildCustomerOAuthAuthorizationUrl({
      provider: provider.data,
      returnTo: parsed.data.returnTo,
      req,
    });

    await createAuditLogSafely({
      action: "VERIFY_CUSTOMER_OAUTH_START",
      entityType: "CustomerVerifyAuth",
      entityId: provider.data.toUpperCase(),
      details: {
        provider: provider.data,
      },
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
    });

    return res.redirect(302, authorizationUrl);
  } catch (error: any) {
    return res.status(400).json({
      success: false,
      error: String(error?.message || "Could not start customer sign-in"),
    });
  }
};

export const completeCustomerOAuth = async (req: Request, res: Response) => {
  const provider = parseProvider(req);
  if (!provider.success) {
    return res.status(400).json({ success: false, error: "Invalid OAuth provider" });
  }

  const body = (req.body && typeof req.body === "object" ? req.body : {}) as Record<string, unknown>;
  const source = { ...(req.query || {}), ...body };

  try {
    const redirectUrl = await finishCustomerOAuthCallback({
      provider: provider.data as CustomerOAuthProvider,
      code: typeof source.code === "string" ? source.code : null,
      state: typeof source.state === "string" ? source.state : null,
      error: typeof source.error === "string" ? source.error : null,
      req,
    });

    await createAuditLogSafely({
      action: "VERIFY_CUSTOMER_OAUTH_CALLBACK",
      entityType: "CustomerVerifyAuth",
      entityId: provider.data.toUpperCase(),
      details: {
        provider: provider.data,
        status: typeof source.error === "string" ? "error" : "success",
      },
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
    });

    return res.redirect(302, redirectUrl);
  } catch (error: any) {
    return res.status(400).json({
      success: false,
      error: String(error?.message || "Could not complete customer sign-in"),
    });
  }
};

export const exchangeCustomerOAuth = async (req: Request, res: Response) => {
  const parsed = exchangeSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid exchange request" });
  }

  try {
    const session = exchangeCustomerOAuthTicketForSession(parsed.data.ticket);

    await createAuditLogSafely({
      action: "VERIFY_CUSTOMER_OAUTH_EXCHANGE",
      entityType: "CustomerVerifyAuth",
      entityId: session.customer.userId,
      details: {
        authProvider: session.customer.authProvider,
      },
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
    });

    return res.json({
      success: true,
      data: session,
    });
  } catch (error: any) {
    return res.status(400).json({
      success: false,
      error: String(error?.message || "Could not finish social sign-in"),
    });
  }
};
