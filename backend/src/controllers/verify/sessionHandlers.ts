import { Response } from "express";
import { CustomerVerificationEntryMethod } from "@prisma/client";
import { z } from "zod";

import { CustomerVerifyRequest } from "../../middleware/customerVerifyAuth";
import { createAuditLogSafely } from "../../services/auditService";
import {
  createCustomerVerificationSession,
  getCustomerVerificationSession,
  revealCustomerVerificationSession,
  saveCustomerTrustIntake,
} from "../../services/customerVerificationSessionService";

const startSessionSchema = z
  .object({
    decisionId: z.string().trim().min(8).max(128),
    entryMethod: z.nativeEnum(CustomerVerificationEntryMethod),
  })
  .strict();

const sessionParamsSchema = z
  .object({
    id: z.string().trim().min(8).max(128),
  })
  .strict();

const intakeSchema = z
  .object({
    purchaseChannel: z.enum(["online", "offline", "gifted", "unknown"]),
    sourceCategory: z.enum(["marketplace", "direct_brand", "retail_store", "reseller", "gift", "unknown"]).optional().nullable(),
    platformName: z.string().trim().max(160).optional().nullable(),
    sellerName: z.string().trim().max(160).optional().nullable(),
    listingUrl: z.string().trim().max(1000).optional().nullable(),
    orderReference: z.string().trim().max(160).optional().nullable(),
    storeName: z.string().trim().max(160).optional().nullable(),
    purchaseCity: z.string().trim().max(120).optional().nullable(),
    purchaseCountry: z.string().trim().max(120).optional().nullable(),
    purchaseDate: z.string().trim().max(64).optional().nullable(),
    packagingState: z.enum(["sealed", "opened", "damaged", "unsure"]).optional().nullable(),
    packagingConcern: z.enum(["none", "minor", "major", "unsure"]).optional().nullable(),
    scanReason: z.enum(["routine_check", "new_seller", "pricing_concern", "packaging_concern", "authenticity_concern"]),
    ownershipIntent: z.enum(["verify_only", "claim_ownership", "report_concern", "contact_support"]),
    notes: z.string().trim().max(2000).optional().nullable(),
  })
  .strict();

const requireCustomerIdentity = (req: CustomerVerifyRequest, res: Response) => {
  if (!req.customer?.userId || !req.customer?.email) {
    res.status(401).json({
      success: false,
      error: "Customer authentication required",
    });
    return null;
  }

  return {
    userId: req.customer.userId,
    email: req.customer.email,
  };
};

export const startCustomerVerificationSession = async (req: CustomerVerifyRequest, res: Response) => {
  try {
    const parsed = startSessionSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: parsed.error.errors[0]?.message || "Invalid verification session request",
      });
    }

    const session = await createCustomerVerificationSession({
      decisionId: parsed.data.decisionId,
      entryMethod: parsed.data.entryMethod,
      customer: req.customer || null,
    });

    await createAuditLogSafely({
      action: "CUSTOMER_VERIFICATION_SESSION_STARTED",
      entityType: "CustomerVerificationSession",
      entityId: session.sessionId,
      details: {
        decisionId: session.decisionId,
        entryMethod: session.entryMethod,
      },
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
    });

    return res.status(201).json({
      success: true,
      data: session,
    });
  } catch (error: any) {
    return res.status(/not found/i.test(String(error?.message || "")) ? 404 : 500).json({
      success: false,
      error: error?.message || "Could not start verification session",
    });
  }
};

export const getCustomerVerificationSessionState = async (req: CustomerVerifyRequest, res: Response) => {
  try {
    const parsed = sessionParamsSchema.safeParse(req.params || {});
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: parsed.error.errors[0]?.message || "Invalid session id",
      });
    }

    const session = await getCustomerVerificationSession({
      sessionId: parsed.data.id,
      customer: req.customer || null,
    });

    if (!session) {
      return res.status(404).json({
        success: false,
        error: "Verification session not found",
      });
    }

    return res.json({
      success: true,
      data: session,
    });
  } catch (error: any) {
    return res.status(500).json({
      success: false,
      error: error?.message || "Could not load verification session",
    });
  }
};

export const submitCustomerVerificationIntake = async (req: CustomerVerifyRequest, res: Response) => {
  try {
    const params = sessionParamsSchema.safeParse(req.params || {});
    const parsed = intakeSchema.safeParse(req.body || {});
    if (!params.success || !parsed.success) {
      const error = !params.success ? params.error.errors[0] : !parsed.success ? parsed.error.errors[0] : undefined;
      return res.status(400).json({
        success: false,
        error: error?.message || "Invalid verification intake",
      });
    }

    const customer = requireCustomerIdentity(req, res);
    if (!customer) return;

    const intake = await saveCustomerTrustIntake({
      sessionId: params.data.id,
      intake: {
        ...parsed.data,
        purchaseDate: parsed.data.purchaseDate || null,
        answers: parsed.data as Record<string, unknown>,
      },
      customer,
    });

    await createAuditLogSafely({
      action: "CUSTOMER_VERIFICATION_INTAKE_SUBMITTED",
      entityType: "CustomerVerificationSession",
      entityId: params.data.id,
      details: {
        customerUserId: customer.userId,
        purchaseChannel: intake.purchaseChannel,
        scanReason: intake.scanReason,
        ownershipIntent: intake.ownershipIntent,
      },
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
    });

    return res.json({
      success: true,
      data: {
        intakeSaved: true,
      },
    });
  } catch (error: any) {
    return res.status(/not found/i.test(String(error?.message || "")) ? 404 : 500).json({
      success: false,
      error: error?.message || "Could not save verification intake",
    });
  }
};

export const revealCustomerVerificationResult = async (req: CustomerVerifyRequest, res: Response) => {
  try {
    const params = sessionParamsSchema.safeParse(req.params || {});
    if (!params.success) {
      return res.status(400).json({
        success: false,
        error: params.error.errors[0]?.message || "Invalid session id",
      });
    }

    const customer = requireCustomerIdentity(req, res);
    if (!customer) return;

    const reveal = await revealCustomerVerificationSession({
      sessionId: params.data.id,
      customer,
    });

    await createAuditLogSafely({
      action: "CUSTOMER_VERIFICATION_RESULT_REVEALED",
      entityType: "CustomerVerificationSession",
      entityId: params.data.id,
      details: {
        decisionId: reveal.decisionId,
        customerUserId: customer.userId,
      },
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
    });

    return res.json({
      success: true,
      data: reveal,
    });
  } catch (error: any) {
    return res.status(/not found/i.test(String(error?.message || "")) ? 404 : 400).json({
      success: false,
      error: error?.message || "Could not reveal verification result",
    });
  }
};
