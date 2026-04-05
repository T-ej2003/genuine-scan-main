import { Response } from "express";
import { z } from "zod";

import { CustomerVerifyRequest } from "../../middleware/customerVerifyAuth";
import { createAuditLogSafely } from "../../services/auditService";
import {
  beginCustomerWebAuthnAssertion,
  beginCustomerWebAuthnRegistration,
  completeCustomerWebAuthnAssertion,
  completeCustomerWebAuthnRegistration,
  deleteCustomerWebAuthnCredential,
  listCustomerWebAuthnCredentials,
} from "../../services/customerWebauthnService";
import {
  deriveCustomerVerifyUserId,
  issueCustomerVerifyToken,
  maskEmail,
  normalizeCustomerVerifyEmail,
} from "../../services/customerVerifyAuthService";
import { hashIp } from "../../utils/security";

const passkeyLabelSchema = z.string().trim().min(1).max(120).optional();

const registrationCredentialSchema = z
  .object({
    id: z.string().trim().min(1),
    rawId: z.string().trim().min(1),
    type: z.string().trim().min(1),
    response: z
      .object({
        clientDataJSON: z.string().trim().min(1),
        attestationObject: z.string().trim().min(1),
        authenticatorData: z.string().trim().min(1),
        publicKey: z.string().trim().min(1),
        publicKeyAlgorithm: z.number(),
        transports: z.array(z.string().trim().min(1)).optional(),
      })
      .strict(),
  })
  .strict();

const assertionCredentialSchema = z
  .object({
    id: z.string().trim().min(1),
    rawId: z.string().trim().min(1),
    type: z.string().trim().min(1),
    response: z
      .object({
        clientDataJSON: z.string().trim().min(1),
        authenticatorData: z.string().trim().min(1),
        signature: z.string().trim().min(1),
        userHandle: z.string().trim().min(1).nullable().optional(),
      })
      .strict(),
  })
  .strict();

const beginAssertionSchema = z
  .object({
    email: z.string().trim().email().optional(),
  })
  .strict();

const finishRegistrationSchema = z
  .object({
    ticket: z.string().trim().min(12),
    label: passkeyLabelSchema,
    credential: registrationCredentialSchema,
  })
  .strict();

const finishAssertionSchema = z
  .object({
    ticket: z.string().trim().min(12),
    credential: assertionCredentialSchema,
  })
  .strict();

const beginRegistrationSchema = z
  .object({
    label: passkeyLabelSchema,
  })
  .strict();

const handlePasskeyError = (res: Response, error: any, fallback = "Passkey request failed") => {
  const message = String(error?.message || fallback);
  if (
    message === "WEBAUTHN_NOT_ENROLLED" ||
    message === "WEBAUTHN_CREDENTIAL_NOT_FOUND" ||
    message === "WEBAUTHN_CHALLENGE_NOT_FOUND"
  ) {
    return res.status(404).json({ success: false, error: message });
  }
  if (
    message.includes("INVALID_WEBAUTHN") ||
    message.includes("WEBAUTHN_COUNTER_REPLAY") ||
    message.includes("WEBAUTHN_CHALLENGE_USER_MISMATCH") ||
    message.includes("WEBAUTHN_USER_PRESENCE_REQUIRED")
  ) {
    return res.status(400).json({ success: false, error: message });
  }
  if (message === "WEBAUTHN_STORAGE_UNAVAILABLE") {
    return res.status(503).json({ success: false, error: "Passkey storage is temporarily unavailable." });
  }
  return res.status(500).json({ success: false, error: fallback });
};

export const beginCustomerPasskeyRegistration = async (req: CustomerVerifyRequest, res: Response) => {
  try {
    const customer = req.customer;
    if (!customer) {
      return res.status(401).json({ success: false, error: "Customer authentication required" });
    }

    const parsed = beginRegistrationSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid passkey request" });
    }

    const options = await beginCustomerWebAuthnRegistration({
      customerUserId: customer.userId,
      email: customer.email,
      displayName: customer.email,
      ipHash: hashIp(req.ip),
      userAgent: req.get("user-agent") || null,
    });

    await createAuditLogSafely({
      action: "VERIFY_CUSTOMER_PASSKEY_REGISTER_BEGIN",
      entityType: "CustomerVerifyPasskey",
      entityId: customer.userId,
      details: {
        maskedEmail: maskEmail(customer.email),
        label: parsed.data.label || null,
      },
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
    });

    return res.json({ success: true, data: options });
  } catch (error: any) {
    return handlePasskeyError(res, error, "Could not start passkey registration");
  }
};

export const finishCustomerPasskeyRegistration = async (req: CustomerVerifyRequest, res: Response) => {
  try {
    const customer = req.customer;
    if (!customer) {
      return res.status(401).json({ success: false, error: "Customer authentication required" });
    }

    const parsed = finishRegistrationSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid passkey payload" });
    }

    const result = await completeCustomerWebAuthnRegistration({
      customerUserId: customer.userId,
      ticket: parsed.data.ticket,
      label: parsed.data.label,
      credential: parsed.data.credential,
    });

    const token = issueCustomerVerifyToken(
      {
        userId: customer.userId,
        email: customer.email,
      },
      {
        authStrength: "PASSKEY",
        webauthnVerifiedAt: new Date(),
      }
    );

    await createAuditLogSafely({
      action: "VERIFY_CUSTOMER_PASSKEY_REGISTER_FINISH",
      entityType: "CustomerVerifyPasskey",
      entityId: result.credentialId,
      details: {
        customerUserId: customer.userId,
        maskedEmail: maskEmail(customer.email),
      },
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
    });

    return res.json({
      success: true,
      data: {
        enrolled: true,
        token,
        customer: {
          userId: customer.userId,
          email: customer.email,
          maskedEmail: maskEmail(customer.email),
        },
      },
    });
  } catch (error: any) {
    return handlePasskeyError(res, error, "Could not finish passkey registration");
  }
};

export const beginCustomerPasskeyAssertion = async (req: CustomerVerifyRequest, res: Response) => {
  try {
    const parsed = beginAssertionSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid passkey request" });
    }

    const email = req.customer?.email || normalizeCustomerVerifyEmail(parsed.data.email || "");
    const customerUserId = req.customer?.userId || (email ? deriveCustomerVerifyUserId(email) : "");
    if (!email || !customerUserId) {
      return res.status(400).json({ success: false, error: "Email is required to start passkey sign-in." });
    }

    const options = await beginCustomerWebAuthnAssertion({
      customerUserId,
      email,
      purpose: req.customer ? "STEP_UP" : "LOGIN",
      ipHash: hashIp(req.ip),
      userAgent: req.get("user-agent") || null,
    });

    await createAuditLogSafely({
      action: "VERIFY_CUSTOMER_PASSKEY_ASSERT_BEGIN",
      entityType: "CustomerVerifyPasskey",
      entityId: customerUserId,
      details: {
        maskedEmail: maskEmail(email),
        sessionUpgrade: Boolean(req.customer),
      },
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
    });

    return res.json({ success: true, data: options });
  } catch (error: any) {
    return handlePasskeyError(res, error, "Could not start passkey sign-in");
  }
};

export const finishCustomerPasskeyAssertion = async (req: CustomerVerifyRequest, res: Response) => {
  try {
    const parsed = finishAssertionSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid passkey payload" });
    }

    const result = await completeCustomerWebAuthnAssertion({
      ticket: parsed.data.ticket,
      customerUserId: req.customer?.userId || null,
      credential: parsed.data.credential,
    });

    const email = normalizeCustomerVerifyEmail(result.customerEmail || req.customer?.email || "");
    if (!email || !result.customerUserId) {
      return res.status(500).json({ success: false, error: "Passkey assertion completed without a customer identity." });
    }

    const token = issueCustomerVerifyToken(
      {
        userId: result.customerUserId,
        email,
      },
      {
        authStrength: "PASSKEY",
        webauthnVerifiedAt: result.assertedAt,
      }
    );

    await createAuditLogSafely({
      action: "VERIFY_CUSTOMER_PASSKEY_ASSERT_FINISH",
      entityType: "CustomerVerifyPasskey",
      entityId: result.customerUserId,
      details: {
        maskedEmail: maskEmail(email),
        purpose: result.purpose,
      },
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
    });

    return res.json({
      success: true,
      data: {
        token,
        customer: {
          userId: result.customerUserId,
          email,
          maskedEmail: maskEmail(email),
        },
        assertedAt: result.assertedAt.toISOString(),
      },
    });
  } catch (error: any) {
    return handlePasskeyError(res, error, "Could not finish passkey sign-in");
  }
};

export const listCustomerPasskeyCredentials = async (req: CustomerVerifyRequest, res: Response) => {
  try {
    const customer = req.customer;
    if (!customer) {
      return res.status(401).json({ success: false, error: "Customer authentication required" });
    }

    const items = await listCustomerWebAuthnCredentials(customer.userId);
    return res.json({ success: true, data: { items } });
  } catch (error: any) {
    return handlePasskeyError(res, error, "Could not load passkeys");
  }
};

export const deleteCustomerPasskeyCredential = async (req: CustomerVerifyRequest, res: Response) => {
  try {
    const customer = req.customer;
    if (!customer) {
      return res.status(401).json({ success: false, error: "Customer authentication required" });
    }

    const credentialId = String(req.params.id || "").trim();
    if (!credentialId) {
      return res.status(400).json({ success: false, error: "Missing passkey credential id" });
    }

    const result = await deleteCustomerWebAuthnCredential({
      customerUserId: customer.userId,
      credentialId,
    });

    await createAuditLogSafely({
      action: "VERIFY_CUSTOMER_PASSKEY_DELETE",
      entityType: "CustomerVerifyPasskey",
      entityId: credentialId,
      details: {
        customerUserId: customer.userId,
        maskedEmail: maskEmail(customer.email),
        deleted: result.deleted,
      },
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
    });

    return res.json({ success: true, data: result });
  } catch (error: any) {
    return handlePasskeyError(res, error, "Could not delete passkey");
  }
};
