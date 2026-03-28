import { Request, Response } from "express";

import { createAuditLog } from "../../services/auditService";
import { getSuperadminAlertEmails, sendIncidentEmail } from "../../services/incidentEmailService";
import { runTamperEvidenceChecks, summarizeTamperFindings } from "../../services/tamperEvidenceService";
import { ticketSlaSnapshot } from "../../services/supportWorkflowService";
import {
  IncidentActorType,
  buildFraudVerificationSnapshot,
  createIncidentFromReport,
  deriveRequestDeviceFingerprint,
  enforceIncidentRateLimit,
  incidentSummaryText,
  inferIncidentType,
  mapUploadedEvidence,
  normalizeCode,
  parseBoolean,
  parseTags,
  prisma,
  productFeedbackSchema,
  reportFraudSchema,
  verifyCaptchaToken,
} from "./shared";

export const reportFraud = async (req: Request, res: Response) => {
  try {
    const parsed = reportFraudSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: parsed.error.errors[0]?.message || "Invalid report payload",
      });
    }

    const payload = parsed.data;
    const normalizedCode = normalizeCode(payload.code || payload.qrCodeValue || "");
    const fingerprint = deriveRequestDeviceFingerprint(req, { allowClientHint: false });
    const rateLimit = await enforceIncidentRateLimit({
      ip: req.ip,
      qrCode: normalizedCode,
      deviceFp: fingerprint,
    });
    if (rateLimit.blocked) {
      res.setHeader("Retry-After", String(rateLimit.retryAfterSec));
      return res.status(429).json({
        success: false,
        error: "Too many reports submitted. Please try again later.",
      });
    }

    const captchaToken = String(req.headers["x-captcha-token"] || req.body?.captchaToken || "").trim();
    const captcha = await verifyCaptchaToken(captchaToken, req.ip);
    if (!captcha.ok) {
      return res.status(400).json({
        success: false,
        error: captcha.reason || "Captcha verification failed",
      });
    }

    const incidentType = inferIncidentType({
      reason: payload.reason,
      incidentType: payload.incidentType,
    });

    const snapshot = await buildFraudVerificationSnapshot(normalizedCode);

    const metadataLines = [
      `Classification: ${snapshot.classification}`,
      `Reasons: ${snapshot.reasons.join(" | ") || "n/a"}`,
      `Scan summary: total=${snapshot.scanSummary.totalScans}, first=${snapshot.scanSummary.firstVerifiedAt || "n/a"}, latest=${snapshot.scanSummary.latestVerifiedAt || "n/a"}`,
      `Ownership: claimed=${String(snapshot.ownershipStatus.isClaimed)}, ownedByRequester=${String(snapshot.ownershipStatus.isOwnedByRequester)}`,
    ];

    const userDescription =
      String(payload.description || "").trim() ||
      String(payload.notes || "").trim() ||
      String(payload.reason || "").trim() ||
      "Suspected counterfeit report from verify page.";

    const finalDescription = `${userDescription}\n\n--- Verification metadata ---\n${metadataLines.join("\n")}`.slice(0, 2000);

    const uploadedFiles = Array.isArray(req.files) ? (req.files as Express.Multer.File[]) : [];
    const uploadRecords = mapUploadedEvidence(uploadedFiles);

    const tags = [
      ...parseTags(payload.tags),
      "verify_fraud_report",
      `classification_${snapshot.classification.toLowerCase()}`,
      snapshot.ownershipStatus.isClaimed ? "ownership_claimed" : "ownership_unclaimed",
    ].slice(0, 10);

    const customerEmail = String(payload.contactEmail || payload.customerEmail || "").trim() || undefined;

    const incident = await createIncidentFromReport(
      {
        qrCodeValue: normalizedCode,
        incidentType,
        description: finalDescription,
        consentToContact: parseBoolean(payload.consentToContact, Boolean(customerEmail)),
        customerEmail,
        preferredContactMethod: customerEmail ? "email" : payload.preferredContactMethod || "none",
        tags,
      },
      {
        actorType: IncidentActorType.CUSTOMER,
        ipAddress: req.ip,
        userAgent: req.get("user-agent") || undefined,
      },
      uploadRecords
    );

    const evidenceRows = await prisma.incidentEvidence.findMany({
      where: { incidentId: incident.id },
      select: {
        id: true,
        incidentId: true,
        storageKey: true,
        fileType: true,
      },
    });
    const tamperFindings = await runTamperEvidenceChecks(evidenceRows);
    const tamperSummary = summarizeTamperFindings(tamperFindings);

    if (tamperSummary.hasWarnings) {
      const nextTags = Array.from(new Set([...(incident.tags || []), "tamper_check_warning"]));
      await prisma.incident.update({
        where: { id: incident.id },
        data: { tags: nextTags },
      });
    }

    const supportTicket = await prisma.supportTicket.findUnique({
      where: { incidentId: incident.id },
      select: {
        id: true,
        referenceCode: true,
        status: true,
        slaDueAt: true,
      },
    });

    const superadminEmails = await getSuperadminAlertEmails();
    const alertSubject = `[Incident][${incident.severity}] New fraud report ${incident.id}`;
    const alertBody = incidentSummaryText(incident);

    for (const email of superadminEmails) {
      await sendIncidentEmail({
        incidentId: incident.id,
        licenseeId: incident.licenseeId || null,
        toAddress: email,
        subject: alertSubject,
        text: alertBody,
        senderMode: "system",
        template: "superadmin_alert",
      });
    }

    return res.status(201).json({
      success: true,
      data: {
        reportId: incident.id,
        supportTicketRef: supportTicket?.referenceCode || null,
        supportTicketStatus: supportTicket?.status || null,
        supportTicketSla: supportTicket ? ticketSlaSnapshot(supportTicket.slaDueAt) : null,
        message: "Fraud report submitted successfully.",
        classification: snapshot.classification,
        reasons: snapshot.reasons,
        scanSummary: snapshot.scanSummary,
        ownershipStatus: snapshot.ownershipStatus,
        tamperChecks: {
          summary: tamperSummary.summary,
          highestRisk: tamperSummary.highestRisk,
          hasWarnings: tamperSummary.hasWarnings,
        },
      },
    });
  } catch (error) {
    console.error("reportFraud error:", error);
    return res.status(500).json({
      success: false,
      error: "Failed to submit fraud report",
    });
  }
};

export const submitProductFeedback = async (req: Request, res: Response) => {
  try {
    const parsed = productFeedbackSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: parsed.error.errors[0]?.message || "Invalid feedback payload",
      });
    }

    const payload = parsed.data;
    const normalizedCode = payload.code.toUpperCase();
    const feedbackRate = await enforceIncidentRateLimit({
      ip: req.ip,
      qrCode: normalizedCode,
      deviceFp: deriveRequestDeviceFingerprint(req, { allowClientHint: false }),
    });
    if (feedbackRate.blocked) {
      res.setHeader("Retry-After", String(feedbackRate.retryAfterSec));
      return res.status(429).json({
        success: false,
        error: "Too many feedback attempts. Please try again later.",
      });
    }

    const qrCode = await prisma.qRCode.findUnique({
      where: { code: normalizedCode },
      select: {
        id: true,
        code: true,
        licenseeId: true,
        batchId: true,
        batch: {
          select: {
            manufacturerId: true,
          },
        },
      },
    });

    const feedbackLog = await createAuditLog({
      action: "CUSTOMER_PRODUCT_FEEDBACK",
      entityType: "CustomerFeedback",
      entityId: qrCode?.id || normalizedCode,
      licenseeId: qrCode?.licenseeId || undefined,
      ipAddress: req.ip,
      details: {
        code: normalizedCode,
        rating: payload.rating,
        satisfaction: payload.satisfaction,
        notes: payload.notes || null,
        observedStatus: payload.observedStatus || null,
        observedOutcome: payload.observedOutcome || null,
        qrCodeId: qrCode?.id || null,
        batchId: qrCode?.batchId || null,
        manufacturerId: qrCode?.batch?.manufacturerId || null,
        pageUrl: payload.pageUrl || null,
        userAgent: req.get("user-agent") || null,
        submittedAt: new Date().toISOString(),
      },
    });

    return res.status(201).json({
      success: true,
      data: {
        feedbackId: feedbackLog.id,
        message: "Feedback submitted successfully.",
      },
    });
  } catch (error) {
    console.error("submitProductFeedback error:", error);
    return res.status(500).json({
      success: false,
      error: "Failed to submit product feedback",
    });
  }
};
