import fs from "fs";
import path from "path";
import { Request, Response } from "express";
import { IncidentActorType, IncidentEventType, IncidentSeverity, IncidentStatus, UserRole } from "@prisma/client";
import { z } from "zod";

import prisma from "../config/database";
import { AuthRequest } from "../middleware/auth";
import { verifyCaptchaToken } from "../services/captchaService";
import { enforceIncidentRateLimit } from "../services/incidentRateLimitService";
import {
  buildIncidentAdminUrl,
  computeSlaDueAt,
  createIncidentFromReport,
  isIncidentAdminRole,
  getIncidentByIdScoped,
  listIncidentsScoped,
  recordIncidentEvent,
  sanitizeIncidentSeverity,
  sanitizeIncidentStatus,
  sanitizeResolutionOutcome,
  toHumanIncidentSeverity,
  toHumanIncidentStatus,
  toHumanIncidentType,
} from "../services/incidentService";
import { getSuperadminAlertEmails, sendIncidentEmail } from "../services/incidentEmailService";
import { createAuditLog } from "../services/auditService";
import { incidentEvidenceUpload, incidentReportUpload, resolveUploadPath } from "../middleware/incidentUpload";

const publicIncidentSchema = z.object({
  qrCodeValue: z.string().trim().min(2).max(128),
  incidentType: z.enum(["counterfeit_suspected", "duplicate_scan", "tampered_label", "wrong_product", "other"]),
  description: z.string().trim().min(5).max(2000),
  customerName: z.string().trim().max(120).optional(),
  customerEmail: z.string().trim().email().max(160).optional(),
  customerPhone: z.string().trim().max(40).optional(),
  customerCountry: z.string().trim().max(80).optional(),
  preferredContactMethod: z.enum(["email", "phone", "whatsapp", "none"]).optional(),
  consentToContact: z.boolean().optional().default(false),
  purchasePlace: z.string().trim().max(240).optional(),
  purchaseDate: z.string().trim().max(32).optional(),
  productBatchNo: z.string().trim().max(120).optional(),
  locationLat: z.number().min(-90).max(90).optional().nullable(),
  locationLng: z.number().min(-180).max(180).optional().nullable(),
  tags: z.array(z.string().trim().max(40)).optional(),
  photoUrls: z.array(z.string().trim().url().max(1000)).optional(),
});

const incidentPatchSchema = z.object({
  status: z
    .enum([
      "NEW",
      "TRIAGED",
      "INVESTIGATING",
      "AWAITING_CUSTOMER",
      "AWAITING_LICENSEE",
      "MITIGATED",
      "RESOLVED",
      "CLOSED",
      "REJECTED_SPAM",
    ])
    .optional(),
  assignedToUserId: z.string().trim().uuid().nullable().optional(),
  internalNotes: z.string().trim().max(5000).optional(),
  tags: z.array(z.string().trim().max(40)).optional(),
  severity: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]).optional(),
  resolutionSummary: z.string().trim().max(3000).optional(),
  resolutionOutcome: z.enum(["CONFIRMED_FRAUD", "NOT_FRAUD", "INCONCLUSIVE"]).nullable().optional(),
});

const incidentNoteSchema = z.object({
  note: z.string().trim().min(2).max(3000),
});

const notifyCustomerSchema = z.object({
  subject: z.string().trim().min(3).max(200),
  message: z.string().trim().min(3).max(5000),
});

const parseBoolean = (value: unknown) => {
  if (typeof value === "boolean") return value;
  const normalized = String(value || "").toLowerCase().trim();
  if (normalized === "true" || normalized === "1" || normalized === "yes") return true;
  if (normalized === "false" || normalized === "0" || normalized === "no") return false;
  return false;
};

const parseNumber = (value: unknown): number | null => {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  const n = Number(String(value ?? ""));
  return Number.isFinite(n) ? n : null;
};

const parseJsonArray = (value: unknown): string[] => {
  if (Array.isArray(value)) {
    return value.map((v) => String(v || "").trim()).filter(Boolean);
  }
  const raw = String(value || "").trim();
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return parsed.map((v) => String(v || "").trim()).filter(Boolean);
  } catch {
    return raw
      .split(",")
      .map((v) => v.trim())
      .filter(Boolean);
  }
  return [];
};

const mapFileToStorageRecord = (file: Express.Multer.File) => {
  const fileName = path.basename(file.filename || "");
  return {
    fileUrl: `/api/incidents/evidence-files/${encodeURIComponent(fileName)}`,
    storageKey: fileName,
    fileType: String(file.mimetype || "application/octet-stream"),
  };
};

const incidentSummaryText = (incident: any) =>
  [
    `Incident ID: ${incident.id}`,
    `QR Code: ${incident.qrCodeValue}`,
    `Type: ${toHumanIncidentType(incident.incidentType)}`,
    `Severity: ${toHumanIncidentSeverity(incident.severity)}`,
    `Status: ${toHumanIncidentStatus(incident.status)}`,
    `Description: ${incident.description}`,
    incident.locationName ? `Location: ${incident.locationName}` : null,
    incident.customerEmail ? `Customer Email: ${incident.customerEmail}` : null,
    incident.customerPhone ? `Customer Phone: ${incident.customerPhone}` : null,
    `Open in admin: ${buildIncidentAdminUrl(incident.id)}`,
  ]
    .filter(Boolean)
    .join("\n");

const asIncidentPayload = (req: Request) => {
  return {
    qrCodeValue: String(req.body?.qrCodeValue || req.body?.code || "").trim(),
    incidentType: String(req.body?.incidentType || "other").trim().toLowerCase(),
    description: String(req.body?.description || req.body?.notes || "").trim(),
    customerName: String(req.body?.customerName || "").trim() || undefined,
    customerEmail: String(req.body?.customerEmail || req.body?.contactEmail || "").trim() || undefined,
    customerPhone: String(req.body?.customerPhone || "").trim() || undefined,
    customerCountry: String(req.body?.customerCountry || "").trim() || undefined,
    preferredContactMethod: String(req.body?.preferredContactMethod || "none").trim().toLowerCase() || "none",
    consentToContact: parseBoolean(req.body?.consentToContact),
    purchasePlace: String(req.body?.purchasePlace || "").trim() || undefined,
    purchaseDate: String(req.body?.purchaseDate || "").trim() || undefined,
    productBatchNo: String(req.body?.productBatchNo || "").trim() || undefined,
    locationLat: parseNumber(req.body?.locationLat),
    locationLng: parseNumber(req.body?.locationLng),
    tags: parseJsonArray(req.body?.tags),
    photoUrls: parseJsonArray(req.body?.photoUrls),
  };
};

export const uploadIncidentReportPhotos = incidentReportUpload.array("photos", 4);
export const uploadIncidentEvidence = incidentEvidenceUpload.single("file");

export const reportIncident = async (req: Request, res: Response) => {
  try {
    const parsed = publicIncidentSchema.safeParse(asIncidentPayload(req));
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: parsed.error.errors[0]?.message || "Invalid incident payload",
      });
    }

    const captchaToken = String(req.headers["x-captcha-token"] || req.body?.captchaToken || "").trim();
    const captcha = await verifyCaptchaToken(captchaToken, req.ip);
    if (!captcha.ok) {
      return res.status(400).json({ success: false, error: captcha.reason || "Captcha verification failed" });
    }

    const deviceFp =
      String(req.headers["x-device-fp"] || "").trim() ||
      String(req.headers["user-agent"] || "").trim();
    const rate = enforceIncidentRateLimit({
      ip: req.ip || "",
      qrCode: parsed.data.qrCodeValue,
      deviceFp,
    });
    if (rate.blocked) {
      return res.status(429).json({
        success: false,
        error: "Too many incident reports from this device. Please try again later.",
        retryAfterSec: rate.retryAfterSec,
      });
    }

    const files = (req.files || []) as Express.Multer.File[];
    const uploadedRecords = files.map(mapFileToStorageRecord);

    const incident = await createIncidentFromReport(
      parsed.data,
      {
        actorType: IncidentActorType.CUSTOMER,
        actorUserId: null,
        ipAddress: req.ip,
        userAgent: req.get("user-agent"),
        deviceFingerprint: String(req.headers["x-device-fp"] || ""),
      },
      uploadedRecords
    );

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

    if (incident.consentToContact && incident.customerEmail) {
      const subject = `We received your report (${incident.id})`;
      const body =
        `Thanks for contacting AuthenticQR support.\n\n` +
        `Reference ID: ${incident.id}\n` +
        `Current status: ${toHumanIncidentStatus(incident.status)}\n` +
        `What next: Our team will review your report and update you if needed.\n\n` +
        `For your privacy, we only use your contact details for this incident workflow.`;

      await sendIncidentEmail({
        incidentId: incident.id,
        licenseeId: incident.licenseeId || null,
        toAddress: incident.customerEmail,
        subject,
        text: body,
        senderMode: "system",
        template: "customer_acknowledgement",
      });
    }

    return res.status(201).json({
      success: true,
      data: {
        incidentId: incident.id,
        reference: incident.id,
        status: incident.status,
        severity: incident.severity,
      },
    });
  } catch (error) {
    console.error("reportIncident error:", error);
    return res.status(500).json({
      success: false,
      error: "Could not create incident report",
    });
  }
};

export const listIncidents = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });

    const limit = Math.min(Math.max(Number(req.query.limit || 50), 1), 200);
    const offset = Math.max(Number(req.query.offset || 0), 0);
    const status = sanitizeIncidentStatus(String(req.query.status || ""));
    const severity = sanitizeIncidentSeverity(String(req.query.severity || ""));
    const qr = String(req.query.qr || "").trim() || undefined;
    const search = String(req.query.search || "").trim() || undefined;
    const dateFromRaw = String(req.query.date_from || "").trim();
    const dateToRaw = String(req.query.date_to || "").trim();
    const assignedTo = String(req.query.assigned_to || "").trim() || undefined;
    const licenseeId =
      req.user.role === UserRole.SUPER_ADMIN
        ? String(req.query.licenseeId || "").trim() || undefined
        : undefined;

    const dateFrom = dateFromRaw ? new Date(dateFromRaw) : undefined;
    const dateTo = dateToRaw ? new Date(dateToRaw) : undefined;

    const result = await listIncidentsScoped({
      role: req.user.role,
      actorLicenseeId: req.user.licenseeId,
      filters: {
        status: status || undefined,
        severity: severity || undefined,
        qr,
        search,
        dateFrom: dateFrom && Number.isFinite(dateFrom.getTime()) ? dateFrom : undefined,
        dateTo: dateTo && Number.isFinite(dateTo.getTime()) ? dateTo : undefined,
        assignedTo,
        licenseeId,
        limit,
        offset,
      },
    });

    return res.json({
      success: true,
      data: {
        incidents: result.rows,
        total: result.total,
        limit,
        offset,
      },
    });
  } catch (error) {
    console.error("listIncidents error:", error);
    return res.status(500).json({ success: false, error: "Failed to list incidents" });
  }
};

export const getIncident = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });
    const incidentId = String(req.params.id || "").trim();
    if (!incidentId) return res.status(400).json({ success: false, error: "Missing incident id" });

    const incident = await getIncidentByIdScoped(incidentId, {
      role: req.user.role,
      licenseeId: req.user.licenseeId,
    });
    if (!incident) return res.status(404).json({ success: false, error: "Incident not found" });

    return res.json({ success: true, data: incident });
  } catch (error) {
    console.error("getIncident error:", error);
    return res.status(500).json({ success: false, error: "Failed to load incident" });
  }
};

export const patchIncident = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });
    const incidentId = String(req.params.id || "").trim();
    if (!incidentId) return res.status(400).json({ success: false, error: "Missing incident id" });

    const parsed = incidentPatchSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: parsed.error.errors[0]?.message || "Invalid update payload",
      });
    }

    const incident = await getIncidentByIdScoped(incidentId, {
      role: req.user.role,
      licenseeId: req.user.licenseeId,
    });
    if (!incident) return res.status(404).json({ success: false, error: "Incident not found" });

    const payload = parsed.data;
    const updateData: any = {};
    const changedFields: string[] = [];

    if (payload.status && payload.status !== incident.status) {
      updateData.status = payload.status;
      changedFields.push("status");
    }
    if (payload.assignedToUserId !== undefined && payload.assignedToUserId !== incident.assignedToUserId) {
      updateData.assignedToUserId = payload.assignedToUserId || null;
      changedFields.push("assignedToUserId");
    }
    if (payload.internalNotes !== undefined && payload.internalNotes !== incident.internalNotes) {
      updateData.internalNotes = payload.internalNotes || null;
      changedFields.push("internalNotes");
    }
    if (payload.tags && JSON.stringify(payload.tags) !== JSON.stringify(incident.tags || [])) {
      updateData.tags = payload.tags;
      changedFields.push("tags");
    }
    if (payload.severity && payload.severity !== incident.severity) {
      updateData.severity = payload.severity;
      updateData.severityOverridden = true;
      updateData.slaDueAt = computeSlaDueAt(payload.severity as IncidentSeverity);
      changedFields.push("severity");
    }
    if (payload.resolutionSummary !== undefined && payload.resolutionSummary !== incident.resolutionSummary) {
      updateData.resolutionSummary = payload.resolutionSummary || null;
      changedFields.push("resolutionSummary");
    }
    const nextResolution = sanitizeResolutionOutcome(payload.resolutionOutcome || "");
    if (payload.resolutionOutcome !== undefined && nextResolution !== incident.resolutionOutcome) {
      updateData.resolutionOutcome = nextResolution;
      changedFields.push("resolutionOutcome");
    }

    if (changedFields.length === 0) {
      return res.json({ success: true, data: incident });
    }

    const updated = await prisma.incident.update({
      where: { id: incident.id },
      data: updateData,
    });

    if (changedFields.includes("status")) {
      await recordIncidentEvent({
        incidentId: incident.id,
        actorType: IncidentActorType.ADMIN,
        actorUserId: req.user.userId,
        eventType: IncidentEventType.STATUS_CHANGED,
        eventPayload: { from: incident.status, to: updated.status },
      });
    }

    if (changedFields.includes("assignedToUserId")) {
      await recordIncidentEvent({
        incidentId: incident.id,
        actorType: IncidentActorType.ADMIN,
        actorUserId: req.user.userId,
        eventType: IncidentEventType.ASSIGNED,
        eventPayload: { from: incident.assignedToUserId, to: updated.assignedToUserId },
      });
    }

    await recordIncidentEvent({
      incidentId: incident.id,
      actorType: IncidentActorType.ADMIN,
      actorUserId: req.user.userId,
      eventType: IncidentEventType.UPDATED_FIELDS,
      eventPayload: { changedFields },
    });

    await createAuditLog({
      userId: req.user.userId,
      licenseeId: updated.licenseeId || undefined,
      action: "INCIDENT_UPDATED",
      entityType: "Incident",
      entityId: updated.id,
      ipAddress: req.ip,
      details: {
        changedFields,
        status: updated.status,
        severity: updated.severity,
        assignedToUserId: updated.assignedToUserId,
      },
    });

    return res.json({ success: true, data: updated });
  } catch (error) {
    console.error("patchIncident error:", error);
    return res.status(500).json({ success: false, error: "Failed to update incident" });
  }
};

export const addIncidentEventNote = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });
    const incidentId = String(req.params.id || "").trim();
    if (!incidentId) return res.status(400).json({ success: false, error: "Missing incident id" });

    const parsed = incidentNoteSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid note payload" });
    }

    const incident = await getIncidentByIdScoped(incidentId, {
      role: req.user.role,
      licenseeId: req.user.licenseeId,
    });
    if (!incident) return res.status(404).json({ success: false, error: "Incident not found" });

    const evt = await recordIncidentEvent({
      incidentId: incident.id,
      actorType: IncidentActorType.ADMIN,
      actorUserId: req.user.userId,
      eventType: IncidentEventType.NOTE_ADDED,
      eventPayload: { note: parsed.data.note },
    });

    await createAuditLog({
      userId: req.user.userId,
      licenseeId: incident.licenseeId || undefined,
      action: "INCIDENT_NOTE_ADDED",
      entityType: "Incident",
      entityId: incident.id,
      ipAddress: req.ip,
      details: { noteLength: parsed.data.note.length },
    });

    return res.status(201).json({ success: true, data: evt });
  } catch (error) {
    console.error("addIncidentEventNote error:", error);
    return res.status(500).json({ success: false, error: "Failed to add note" });
  }
};

export const addIncidentEvidence = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });
    const incidentId = String(req.params.id || "").trim();
    if (!incidentId) return res.status(400).json({ success: false, error: "Missing incident id" });

    const incident = await getIncidentByIdScoped(incidentId, {
      role: req.user.role,
      licenseeId: req.user.licenseeId,
    });
    if (!incident) return res.status(404).json({ success: false, error: "Incident not found" });

    const file = req.file;
    if (!file) return res.status(400).json({ success: false, error: "Missing evidence file" });

    const mapped = mapFileToStorageRecord(file);
    const evidence = await prisma.incidentEvidence.create({
      data: {
        incidentId: incident.id,
        fileUrl: mapped.fileUrl,
        storageKey: mapped.storageKey,
        fileType: mapped.fileType,
        uploadedBy: IncidentActorType.ADMIN,
        uploadedByUserId: req.user.userId,
      },
    });

    await recordIncidentEvent({
      incidentId: incident.id,
      actorType: IncidentActorType.ADMIN,
      actorUserId: req.user.userId,
      eventType: IncidentEventType.EVIDENCE_ADDED,
      eventPayload: {
        evidenceId: evidence.id,
        fileType: evidence.fileType,
      },
    });

    await createAuditLog({
      userId: req.user.userId,
      licenseeId: incident.licenseeId || undefined,
      action: "INCIDENT_EVIDENCE_ADDED",
      entityType: "Incident",
      entityId: incident.id,
      ipAddress: req.ip,
      details: {
        evidenceId: evidence.id,
        fileType: evidence.fileType,
      },
    });

    return res.status(201).json({ success: true, data: evidence });
  } catch (error) {
    console.error("addIncidentEvidence error:", error);
    return res.status(500).json({ success: false, error: "Failed to upload evidence" });
  }
};

export const notifyIncidentCustomer = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });
    if (!isIncidentAdminRole(req.user.role)) {
      return res.status(403).json({ success: false, error: "Only admin users can send incident emails" });
    }

    const incidentId = String(req.params.id || "").trim();
    if (!incidentId) return res.status(400).json({ success: false, error: "Missing incident id" });

    const parsed = notifyCustomerSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: parsed.error.errors[0]?.message || "Invalid customer notify payload",
      });
    }

    const incident = await getIncidentByIdScoped(incidentId, {
      role: req.user.role,
      licenseeId: req.user.licenseeId,
    });
    if (!incident) return res.status(404).json({ success: false, error: "Incident not found" });

    if (!incident.consentToContact || !incident.customerEmail) {
      return res.status(400).json({
        success: false,
        error: "Customer has not provided consent/email for incident updates",
      });
    }

    const mail = await sendIncidentEmail({
      incidentId: incident.id,
      licenseeId: incident.licenseeId || null,
      toAddress: incident.customerEmail,
      subject: parsed.data.subject,
      text:
        `${parsed.data.message}\n\n` +
        `Reference ID: ${incident.id}\n` +
        `Current status: ${toHumanIncidentStatus(incident.status)}\n`,
      actorUser: {
        id: req.user.userId,
        role: req.user.role,
        email: req.user.email,
      },
      senderMode: "actor",
      template: "customer_update",
    });

    if (!mail.delivered) {
      return res.status(502).json({
        success: false,
        error: mail.error || "Email delivery failed",
        data: {
          delivered: false,
          providerMessageId: mail.providerMessageId || null,
          attemptedFrom: mail.attemptedFrom || null,
          usedFrom: mail.usedFrom || null,
          replyTo: mail.replyTo || null,
        },
      });
    }

    return res.json({
      success: true,
      data: {
        delivered: mail.delivered,
        providerMessageId: mail.providerMessageId || null,
        error: mail.error || null,
        attemptedFrom: mail.attemptedFrom || null,
        usedFrom: mail.usedFrom || null,
        replyTo: mail.replyTo || null,
      },
    });
  } catch (error) {
    console.error("notifyIncidentCustomer error:", error);
    return res.status(500).json({ success: false, error: "Failed to notify customer" });
  }
};

export const exportIncidentPdfHook = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });
    const incidentId = String(req.params.id || "").trim();
    if (!incidentId) return res.status(400).json({ success: false, error: "Missing incident id" });

    const incident = await getIncidentByIdScoped(incidentId, {
      role: req.user.role,
      licenseeId: req.user.licenseeId,
    });
    if (!incident) return res.status(404).json({ success: false, error: "Incident not found" });

    await recordIncidentEvent({
      incidentId: incident.id,
      actorType: IncidentActorType.ADMIN,
      actorUserId: req.user.userId,
      eventType: IncidentEventType.EXPORTED,
      eventPayload: { format: "pdf", status: "not_implemented" },
    });

    await createAuditLog({
      userId: req.user.userId,
      licenseeId: incident.licenseeId || undefined,
      action: "INCIDENT_EXPORT_REQUESTED",
      entityType: "Incident",
      entityId: incident.id,
      details: { format: "pdf", status: "not_implemented" },
    });

    return res.status(501).json({
      success: false,
      error: "Incident PDF export is not implemented yet. Hook is ready for future integration.",
    });
  } catch (error) {
    console.error("exportIncidentPdfHook error:", error);
    return res.status(500).json({ success: false, error: "Failed to process export hook" });
  }
};

export const serveIncidentEvidenceFile = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });
    const fileName = String(req.params.fileName || "").trim();
    if (!fileName) return res.status(404).json({ success: false, error: "File not found" });

    const evidence = await prisma.incidentEvidence.findFirst({
      where: {
        storageKey: fileName,
        incident:
          req.user.role === UserRole.SUPER_ADMIN
            ? undefined
            : { licenseeId: req.user.licenseeId || "__none__" },
      },
      select: { id: true },
    });
    if (!evidence) return res.status(404).json({ success: false, error: "File not found" });

    const resolved = resolveUploadPath(fileName);
    if (!resolved.startsWith(path.resolve(__dirname, "../../uploads/incidents"))) {
      return res.status(400).json({ success: false, error: "Invalid file path" });
    }
    if (!fs.existsSync(resolved)) return res.status(404).json({ success: false, error: "File not found" });
    return res.sendFile(resolved);
  } catch (error) {
    return res.status(500).json({ success: false, error: "Failed to read file" });
  }
};
