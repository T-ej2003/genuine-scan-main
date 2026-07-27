import { randomUUID } from "crypto";
import { Request, Response } from "express";

import { getB01PreAuthPrisma } from "../../rls-waves/session-b/b01/runtimeClients";
import {
  b02IdempotencyDigest,
  submitProductFeedback as submitProductFeedbackBoundary,
  submitPublicIncident,
} from "../../rls-waves/session-b/b02/publicBoundaryRepository";
import {
  deriveRequestDeviceFingerprint,
  enforceIncidentRateLimit,
  hashIp,
  hashToken,
  inferIncidentType,
  mapUploadedEvidence,
  normalizeCode,
  parseBoolean,
  productFeedbackSchema,
  reportFraudSchema,
  verifyCaptchaToken,
} from "./shared";

const requestId = (req: Request) =>
  String((req as Request & { requestId?: string }).requestId || randomUUID());

export const reportFraud = async (req: Request, res: Response) => {
  const parsed = reportFraudSchema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid report payload" });
  const payload = parsed.data;
  const sessionId = String(payload.sessionId || req.get("x-verification-session-id") || "").trim();
  const sessionProof = String(req.get("x-verification-session-proof") || "").trim();
  const fingerprint = deriveRequestDeviceFingerprint(req, { allowClientHint: false });
  const limit = await enforceIncidentRateLimit({ ip: req.ip, qrCode: sessionId, deviceFp: fingerprint });
  if (limit.blocked) {
    res.setHeader("Retry-After", String(limit.retryAfterSec));
    return res.status(429).json({ success: false, error: "Too many reports submitted. Please try again later." });
  }
  const captcha = await verifyCaptchaToken(String(req.headers["x-captcha-token"] || req.body?.captchaToken || ""), req.ip);
  if (!captcha.ok) return res.status(400).json({ success: false, error: captcha.reason || "Captcha verification failed" });

  try {
    const submittedAt = new Date();
    const id = requestId(req);
    const incidentType = String(inferIncidentType({ reason: payload.reason, incidentType: payload.incidentType })).toLowerCase();
    const description = String(payload.description || payload.notes || payload.reason || "Suspected counterfeit report from verify page.").trim();
    const contactEmail = String(payload.contactEmail || payload.customerEmail || "").trim() || null;
    const result = await submitPublicIncident(getB01PreAuthPrisma(), {
      sessionId,
      sessionProofHash: hashToken(sessionProof),
      incidentType,
      description,
      contactEmail,
      consentToContact: parseBoolean(payload.consentToContact, Boolean(contactEmail)),
      evidence: mapUploadedEvidence(Array.isArray(req.files) ? req.files as Express.Multer.File[] : []),
      submittedAt,
      requestId: id,
      actorIpHash: hashIp(req.ip),
      actorDeviceHash: fingerprint ? hashToken(`device:${fingerprint}`) : null,
      idempotencyDigest: b02IdempotencyDigest({ workflow: "public-concern", sessionId, description, contactEmail }),
    });
    if (!result) throw new Error("Public concern boundary returned no result");
    return res.status(201).json({
      success: true,
      data: { supportTicketRef: result.publicReference, message: result.message },
    });
  } catch {
    return res.status(404).json({ success: false, error: "The concern could not be bound to a verified item." });
  }
};

export const submitProductFeedback = async (req: Request, res: Response) => {
  const parsed = productFeedbackSchema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid feedback payload" });
  const payload = parsed.data;
  const code = normalizeCode(payload.code);
  const limit = await enforceIncidentRateLimit({
    ip: req.ip,
    qrCode: code,
    deviceFp: deriveRequestDeviceFingerprint(req, { allowClientHint: false }),
  });
  if (limit.blocked) {
    res.setHeader("Retry-After", String(limit.retryAfterSec));
    return res.status(429).json({ success: false, error: "Too many feedback attempts. Please try again later." });
  }
  try {
    const submittedAt = new Date();
    const id = requestId(req);
    const result = await submitProductFeedbackBoundary(getB01PreAuthPrisma(), {
      requestedCode: code,
      rating: payload.rating,
      satisfaction: payload.satisfaction,
      notes: payload.notes || null,
      observedStatus: payload.observedStatus || null,
      observedOutcome: payload.observedOutcome || null,
      pageUrl: payload.pageUrl || null,
      submittedAt,
      requestId: id,
      actorIpHash: hashIp(req.ip),
      idempotencyDigest: b02IdempotencyDigest({ workflow: "product-feedback", id, code, payload }),
    });
    if (!result) throw new Error("Public feedback boundary returned no result");
    return res.status(201).json({ success: true, data: result });
  } catch {
    return res.status(404).json({ success: false, error: "Feedback could not be bound to a verified item." });
  }
};
