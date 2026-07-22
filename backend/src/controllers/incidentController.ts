import fs from "fs";
import path from "path";
import { Request, Response } from "express";
import { IncidentActorType, IncidentEventType, IncidentSeverity, IncidentStatus, IncidentType, UserRole } from "@prisma/client";
import { z } from "zod";

import { AuthRequest } from "../middleware/auth";
import { verifyCaptchaToken } from "../services/captchaService";
import { enforceIncidentRateLimit } from "../services/incidentRateLimitService";
import {
  createIncidentFromReport,
  isIncidentAdminRole,
  getIncidentByIdScoped,
  listIncidentsScoped,
  recordIncidentEvent,
  sanitizeIncidentSeverity,
  sanitizeIncidentStatus,
  toHumanIncidentStatus,
} from "../services/incidentService";
import { sendIncidentEmail } from "../services/incidentEmailService";
import { createAuditLogInTransaction } from "../services/auditService";
import { incidentEvidenceUpload, incidentReportUpload, resolveUploadPath } from "../middleware/incidentUpload";
import { buildIncidentPdfBuffer } from "../services/incidentPdfService";
import { downloadObjectBuffer, isObjectStorageConfigured, removeLocalFileIfExists, uploadObjectFromFile } from "../services/objectStorageService";
import { buildPublicIncidentReportResponse } from "./incidents/publicIncidentResponse";
import {
  C03AccessError,
  c03DatabaseSessionCapability,
  c03RequestId,
  withC03ActorTransaction,
  withC03ResourceTransaction,
} from "../rls-waves/session-c/c03/c03ActorBoundary";
import {
  addIncidentEvidenceInTransaction,
  loadIncidentEvidenceFileInTransaction,
  patchIncidentInTransaction,
} from "../rls-waves/session-c/c03/c03IncidentRepository";

const publicIncidentRawSchema = z.object({
  qrCodeValue: z.string().trim().max(128).optional(),
  code: z.string().trim().max(128).optional(),
  incidentType: z.enum(["counterfeit_suspected", "duplicate_scan", "tampered_label", "wrong_product", "other"]).optional(),
  description: z.string().trim().max(2000).optional(),
  notes: z.string().trim().max(2000).optional(),
  customerName: z.string().trim().max(120).optional(),
  customerEmail: z.string().trim().email().max(160).optional(),
  contactEmail: z.string().trim().email().max(160).optional(),
  customerPhone: z.string().trim().max(40).optional(),
  customerCountry: z.string().trim().max(80).optional(),
  preferredContactMethod: z.enum(["email", "phone", "whatsapp", "none"]).optional(),
  consentToContact: z.union([z.boolean(), z.string()]).optional(),
  purchasePlace: z.string().trim().max(240).optional(),
  purchaseDate: z.string().trim().max(32).optional(),
  productBatchNo: z.string().trim().max(120).optional(),
  locationLat: z.union([z.number(), z.string().trim().max(40)]).optional().nullable(),
  locationLng: z.union([z.number(), z.string().trim().max(40)]).optional().nullable(),
  tags: z.union([z.string(), z.array(z.string().trim().max(40))]).optional(),
  photoUrls: z.union([z.string(), z.array(z.string().trim().max(1000))]).optional(),
  captchaToken: z.string().trim().max(4000).optional(),
}).strict();

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
}).strict();

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
}).strict();

const incidentNoteSchema = z.object({
  note: z.string().trim().min(2).max(3000),
}).strict();

const notifyCustomerSchema = z.object({
  subject: z.string().trim().min(3).max(200),
  message: z.string().trim().min(3).max(5000),
  senderMode: z.enum(["actor", "system"]).optional(),
}).strict();

const incidentListQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(200).optional(),
  offset: z.coerce.number().int().min(0).max(20_000).optional(),
  status: z
    .enum(["NEW", "TRIAGED", "INVESTIGATING", "AWAITING_CUSTOMER", "AWAITING_LICENSEE", "MITIGATED", "RESOLVED", "CLOSED", "REJECTED_SPAM"])
    .optional(),
  severity: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]).optional(),
  qr: z.string().trim().max(128).optional(),
  search: z.string().trim().max(120).optional(),
  date_from: z.string().trim().max(64).optional(),
  date_to: z.string().trim().max(64).optional(),
  assigned_to: z.string().uuid().optional(),
  licenseeId: z.string().uuid().optional(),
}).strict();

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

const asIncidentPayload = (input: z.infer<typeof publicIncidentRawSchema>) => {
  return {
    qrCodeValue: String(input.qrCodeValue || input.code || "").trim(),
    incidentType: String(input.incidentType || "other").trim().toLowerCase(),
    description: String(input.description || input.notes || "").trim(),
    customerName: String(input.customerName || "").trim() || undefined,
    customerEmail: String(input.customerEmail || input.contactEmail || "").trim() || undefined,
    customerPhone: String(input.customerPhone || "").trim() || undefined,
    customerCountry: String(input.customerCountry || "").trim() || undefined,
    preferredContactMethod: String(input.preferredContactMethod || "none").trim().toLowerCase() || "none",
    consentToContact: parseBoolean(input.consentToContact),
    purchasePlace: String(input.purchasePlace || "").trim() || undefined,
    purchaseDate: String(input.purchaseDate || "").trim() || undefined,
    productBatchNo: String(input.productBatchNo || "").trim() || undefined,
    locationLat: parseNumber(input.locationLat),
    locationLng: parseNumber(input.locationLng),
    tags: parseJsonArray(input.tags),
    photoUrls: parseJsonArray(input.photoUrls),
  };
};

export const uploadIncidentReportPhotos = incidentReportUpload.array("photos", 4);
export const uploadIncidentEvidence = incidentEvidenceUpload.single("file");

export const reportIncident = async (req: Request, res: Response) => {
  try {
    const rawParsed = publicIncidentRawSchema.safeParse(req.body || {});
    if (!rawParsed.success) {
      return res.status(400).json({
        success: false,
        error: rawParsed.error.errors[0]?.message || "Invalid incident payload",
      });
    }

    const parsed = publicIncidentSchema.safeParse(asIncidentPayload(rawParsed.data));
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
    const rate = await enforceIncidentRateLimit({
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
    if (isObjectStorageConfigured()) {
      await Promise.all(
        files.map(async (file) => {
          if (!file?.path || !file.filename) return;
          await uploadObjectFromFile({
            objectKey: file.filename,
            filePath: file.path,
            contentType: file.mimetype,
          });
          await removeLocalFileIfExists(file.path);
        })
      );
    }
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
      uploadedRecords,
      {
        requestId: c03RequestId(req),
        idempotencyKey: String(req.get("idempotency-key") || "").trim(),
      }
    );
    const supportTicket = incident.supportTicket || null;
    const tamperSummary = incident.tamperSummary || {
      highestRisk: 0,
      hasWarnings: false,
      summary: "Evidence analysis is queued.",
    };

    return res.status(201).json({
      success: true,
      data: buildPublicIncidentReportResponse(incident, supportTicket, tamperSummary),
    });
  } catch (error) {
    console.error("reportIncident error:", error);
    if (error instanceof C03AccessError) {
      return res.status(error.statusCode).json({ success: false, error: error.message });
    }
    return res.status(500).json({
      success: false,
      error: "Could not create incident report",
    });
  }
};

export const listIncidents = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });
    const parsed = incidentListQuerySchema.safeParse(req.query || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid incident filters" });
    }

    const limit = parsed.data.limit ?? 50;
    const offset = parsed.data.offset ?? 0;
    const status = sanitizeIncidentStatus(String(parsed.data.status || ""));
    const severity = sanitizeIncidentSeverity(String(parsed.data.severity || ""));
    const qr = parsed.data.qr || undefined;
    const search = parsed.data.search || undefined;
    const dateFromRaw = String(parsed.data.date_from || "").trim();
    const dateToRaw = String(parsed.data.date_to || "").trim();
    const assignedTo = parsed.data.assigned_to || undefined;
    const licenseeId =
      req.user.role === UserRole.SUPER_ADMIN || req.user.role === UserRole.PLATFORM_SUPER_ADMIN
        ? parsed.data.licenseeId || undefined
        : req.user.licenseeId || undefined;
    if (!licenseeId) return res.status(400).json({ success: false, error: "licenseeId is required" });

    const dateFrom = dateFromRaw ? new Date(dateFromRaw) : undefined;
    const dateTo = dateToRaw ? new Date(dateToRaw) : undefined;

    const result = await withC03ActorTransaction(
      {
        databaseSessionCapability: c03DatabaseSessionCapability(req),
        requestId: c03RequestId(req),
        purpose: "incident-list",
        licenseeId,
        allowedRoles: [UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN, UserRole.LICENSEE_ADMIN, UserRole.ORG_ADMIN],
        requiredAssurance: "password-verified",
      },
      async (tx, context) => {
        const rows = await listIncidentsScoped({
          role: req.user!.role,
          actorUserId: req.user!.userId,
          actorLicenseeId: req.user!.licenseeId,
          linkedLicenseeIds: req.user!.linkedLicenseeIds,
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
        }, tx);
        await createAuditLogInTransaction(tx, context, {
          action: "INCIDENTS_LISTED",
          entityType: "Incident",
          entityId: licenseeId,
          details: { count: rows.rows.length },
          ipAddress: req.ip,
        });
        return rows;
      }
    );

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
    if (error instanceof C03AccessError) return res.status(error.statusCode).json({ success: false, error: error.message });
    return res.status(500).json({ success: false, error: "Failed to list incidents" });
  }
};

export const getIncident = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });
    const incidentId = String(req.params.id || "").trim();
    if (!incidentId) return res.status(400).json({ success: false, error: "Missing incident id" });

    const incident = await withC03ResourceTransaction(
      {
        databaseSessionCapability: c03DatabaseSessionCapability(req),
        requestId: c03RequestId(req),
        purpose: "incident-detail",
        resourceId: incidentId,
        resourceType: "incident",
        allowedRoles: [UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN, UserRole.LICENSEE_ADMIN, UserRole.ORG_ADMIN],
        requiredAssurance: "password-verified",
      },
      async (tx, context) => {
        const row = await getIncidentByIdScoped(incidentId, {
          role: req.user!.role,
          userId: req.user!.userId,
          licenseeId: req.user!.licenseeId,
          linkedLicenseeIds: req.user!.linkedLicenseeIds,
        }, tx);
        await createAuditLogInTransaction(tx, context, {
          action: "INCIDENT_DETAIL_READ",
          entityType: "Incident",
          entityId: incidentId,
          ipAddress: req.ip,
        });
        return row;
      }
    );
    if (!incident) return res.status(404).json({ success: false, error: "Incident not found" });

    return res.json({ success: true, data: incident });
  } catch (error) {
    console.error("getIncident error:", error);
    if (error instanceof C03AccessError) return res.status(error.statusCode).json({ success: false, error: error.message });
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

    const result = await withC03ResourceTransaction(
      {
        databaseSessionCapability: c03DatabaseSessionCapability(req),
        requestId: c03RequestId(req),
        purpose: "incident-update",
        resourceId: incidentId,
        resourceType: "incident",
        allowedRoles: [UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN, UserRole.LICENSEE_ADMIN, UserRole.ORG_ADMIN],
        requiredAssurance: "mfa-verified",
      },
      async (tx, context) => {
        const changed = await patchIncidentInTransaction<any>(tx, incidentId, parsed.data);
        await createAuditLogInTransaction(tx, context, {
          action: "INCIDENT_UPDATED",
          entityType: "Incident",
          entityId: incidentId,
          ipAddress: req.ip,
          details: { changedFields: changed.changedFields || [] },
        });
        return changed;
      }
    );
    return res.json({ success: true, data: result.incident });
  } catch (error) {
    console.error("patchIncident error:", error);
    if (error instanceof C03AccessError) return res.status(error.statusCode).json({ success: false, error: error.message });
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

    const evt = await withC03ResourceTransaction(
      {
        databaseSessionCapability: c03DatabaseSessionCapability(req),
        requestId: c03RequestId(req),
        purpose: "incident-note-add",
        resourceId: incidentId,
        resourceType: "incident",
        allowedRoles: [UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN, UserRole.LICENSEE_ADMIN, UserRole.ORG_ADMIN],
        requiredAssurance: "mfa-verified",
      },
      async (tx, context) => {
        const row = await recordIncidentEvent({
          incidentId,
          actorType: IncidentActorType.ADMIN,
          actorUserId: req.user!.userId,
          eventType: IncidentEventType.NOTE_ADDED,
          eventPayload: { note: parsed.data.note },
        }, tx);
        await createAuditLogInTransaction(tx, context, {
          action: "INCIDENT_NOTE_ADDED",
          entityType: "Incident",
          entityId: incidentId,
          ipAddress: req.ip,
          details: { noteLength: parsed.data.note.length },
        });
        return row;
      }
    );

    return res.status(201).json({ success: true, data: evt });
  } catch (error) {
    console.error("addIncidentEventNote error:", error);
    if (error instanceof C03AccessError) return res.status(error.statusCode).json({ success: false, error: error.message });
    return res.status(500).json({ success: false, error: "Failed to add note" });
  }
};

export const addIncidentEvidence = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });
    const incidentId = String(req.params.id || "").trim();
    if (!incidentId) return res.status(400).json({ success: false, error: "Missing incident id" });

    const file = req.file;
    if (!file) return res.status(400).json({ success: false, error: "Missing evidence file" });
    const idempotencyKey = String(req.get("idempotency-key") || "").trim();
    if (idempotencyKey.length < 8 || idempotencyKey.length > 200) {
      return res.status(400).json({ success: false, error: "A bounded idempotency key is required" });
    }

    if (isObjectStorageConfigured() && file.path && file.filename) {
      await uploadObjectFromFile({
        objectKey: file.filename,
        filePath: file.path,
        contentType: file.mimetype,
      });
      await removeLocalFileIfExists(file.path);
    }

    const mapped = mapFileToStorageRecord(file);
    const result = await withC03ResourceTransaction(
      {
        databaseSessionCapability: c03DatabaseSessionCapability(req),
        requestId: c03RequestId(req),
        purpose: "incident-evidence-add",
        resourceId: incidentId,
        resourceType: "incident",
        allowedRoles: [UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN],
        requiredAssurance: "mfa-verified",
      },
      async (tx, context) => {
        const row = await addIncidentEvidenceInTransaction<any>(tx, incidentId, mapped, idempotencyKey);
        await createAuditLogInTransaction(tx, context, {
          action: "INCIDENT_EVIDENCE_ADDED",
          entityType: "Incident",
          entityId: incidentId,
          ipAddress: req.ip,
          details: { evidenceId: row.evidence.id, fileType: row.evidence.fileType },
        });
        return row;
      }
    );

    return res.status(201).json({
      success: true,
      data: {
        ...result.evidence,
        tamperChecks: result.tamperChecks || null,
      },
    });
  } catch (error) {
    console.error("addIncidentEvidence error:", error);
    if (error instanceof C03AccessError) return res.status(error.statusCode).json({ success: false, error: error.message });
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

    const incident = await withC03ResourceTransaction(
      {
        databaseSessionCapability: c03DatabaseSessionCapability(req),
        requestId: c03RequestId(req),
        purpose: "incident-customer-notification-read",
        resourceId: incidentId,
        resourceType: "incident",
        allowedRoles: [UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN, UserRole.LICENSEE_ADMIN, UserRole.ORG_ADMIN],
        requiredAssurance: "mfa-verified",
      },
      (tx) => getIncidentByIdScoped(incidentId, {
        role: req.user!.role,
        userId: req.user!.userId,
        licenseeId: req.user!.licenseeId,
        linkedLicenseeIds: req.user!.linkedLicenseeIds,
      }, tx)
    );
    if (!incident) return res.status(404).json({ success: false, error: "Incident not found" });

    if (!incident.consentToContact || !incident.customerEmail) {
      return res.status(400).json({
        success: false,
        error: "Customer has not provided consent/email for incident updates",
      });
    }

    const isSuperadminSender =
      req.user.role === UserRole.SUPER_ADMIN || req.user.role === UserRole.PLATFORM_SUPER_ADMIN;
    const senderMode = parsed.data.senderMode === "system" && isSuperadminSender ? "system" : "actor";

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
      senderMode,
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
          senderMode,
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
        senderMode,
      },
    });
  } catch (error) {
    console.error("notifyIncidentCustomer error:", error);
    if (error instanceof C03AccessError) return res.status(error.statusCode).json({ success: false, error: error.message });
    return res.status(500).json({ success: false, error: "Failed to notify customer" });
  }
};

export const exportIncidentPdfHook = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });
    const incidentId = String(req.params.id || "").trim();
    if (!incidentId) return res.status(400).json({ success: false, error: "Missing incident id" });

    const incident = await withC03ResourceTransaction(
      {
        databaseSessionCapability: c03DatabaseSessionCapability(req),
        requestId: c03RequestId(req),
        purpose: "incident-pdf-export",
        resourceId: incidentId,
        resourceType: "incident",
        allowedRoles: [UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN, UserRole.LICENSEE_ADMIN, UserRole.ORG_ADMIN],
        requiredAssurance: "mfa-verified",
      },
      async (tx, context) => {
        const row = await getIncidentByIdScoped(incidentId, {
          role: req.user!.role,
          userId: req.user!.userId,
          licenseeId: req.user!.licenseeId,
          linkedLicenseeIds: req.user!.linkedLicenseeIds,
        }, tx);
        await recordIncidentEvent({
          incidentId,
          actorType: IncidentActorType.ADMIN,
          actorUserId: req.user!.userId,
          eventType: IncidentEventType.EXPORTED,
          eventPayload: { format: "pdf", status: "requested" },
        }, tx);
        await createAuditLogInTransaction(tx, context, {
          action: "INCIDENT_EXPORT_REQUESTED",
          entityType: "Incident",
          entityId: incidentId,
          details: { format: "pdf", status: "requested" },
          ipAddress: req.ip,
        });
        return row;
      }
    );
    if (!incident) return res.status(404).json({ success: false, error: "Incident not found" });

    const pdfBuffer = await buildIncidentPdfBuffer(incident);
    const fileName = `incident-${incident.id}.pdf`;

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename="${fileName}"`);
    return res.status(200).send(pdfBuffer);
  } catch (error) {
    console.error("exportIncidentPdfHook error:", error);
    if (error instanceof C03AccessError) return res.status(error.statusCode).json({ success: false, error: error.message });
    return res.status(500).json({ success: false, error: "Failed to export incident PDF" });
  }
};

export const serveIncidentEvidenceFile = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });
    const fileName = String(req.params.fileName || "").trim();
    if (!fileName) return res.status(404).json({ success: false, error: "File not found" });

    const evidence = await withC03ResourceTransaction(
      {
        databaseSessionCapability: c03DatabaseSessionCapability(req),
        requestId: c03RequestId(req),
        purpose: "incident-evidence-file-read",
        resourceId: fileName,
        resourceType: "incidentEvidenceStorage",
        allowedRoles: [UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN, UserRole.LICENSEE_ADMIN, UserRole.ORG_ADMIN],
        requiredAssurance: "mfa-verified",
      },
      async (tx, context) => {
        const row = await loadIncidentEvidenceFileInTransaction<any>(tx, context, fileName);
        await createAuditLogInTransaction(tx, context, {
          action: "INCIDENT_EVIDENCE_FILE_READ",
          entityType: "IncidentEvidence",
          entityId: row.id,
          ipAddress: req.ip,
        });
        return row;
      }
    );

    if (isObjectStorageConfigured()) {
      const buffer = await downloadObjectBuffer(evidence.storageKey);
      if (buffer) {
        if (evidence.fileType) {
          res.setHeader("Content-Type", evidence.fileType);
        }
        return res.send(buffer);
      }
    }

    const resolved = resolveUploadPath(evidence.storageKey);
    const incidentRoot = path.resolve(__dirname, "../../uploads/incidents");
    if (!resolved.startsWith(`${incidentRoot}${path.sep}`)) {
      return res.status(400).json({ success: false, error: "Invalid file path" });
    }
    if (!fs.existsSync(resolved)) return res.status(404).json({ success: false, error: "File not found" });
    return res.sendFile(resolved);
  } catch (error) {
    if (error instanceof C03AccessError) return res.status(error.statusCode).json({ success: false, error: error.message });
    return res.status(500).json({ success: false, error: "Failed to read file" });
  }
};
