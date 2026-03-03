import { Response } from "express";
import { z } from "zod";
import {
  IncidentActorType,
  IncidentEventType,
  IncidentPriority,
  IncidentResolutionOutcome,
  IncidentSeverity,
  IncidentStatus,
  IncidentType,
  UserRole,
} from "@prisma/client";

import prisma from "../config/database";
import { AuthRequest } from "../middleware/auth";
import { createAuditLog } from "../services/auditService";
import { computeSlaDueAt, recordIncidentEvent, sanitizeResolutionOutcome, sanitizeIncidentStatus, sanitizeIncidentSeverity } from "../services/incidentService";
import { sendIncidentEmail } from "../services/incidentEmailService";
import { applyContainmentAction, type IrContainmentAction } from "../services/ir/incidentActionsService";
import { ensureIncidentWorkflowArtifacts } from "../services/supportWorkflowService";
import { notifyIncidentLifecycle } from "../services/notificationService";
import { runIncidentAutoContainment } from "../services/soarService";

const paginationSchema = z.object({
  limit: z.coerce.number().int().min(1).max(200).default(50),
  offset: z.coerce.number().int().min(0).default(0),
});

const listIncidentsQuerySchema = z.object({
  status: z.string().trim().optional(),
  severity: z.string().trim().optional(),
  priority: z.string().trim().optional(),
  licenseeId: z.string().trim().optional(),
  manufacturerId: z.string().trim().optional(),
  qr: z.string().trim().optional(),
  search: z.string().trim().optional(),
  date_from: z.string().trim().optional(),
  date_to: z.string().trim().optional(),
  assigned_to: z.string().trim().optional(),
});

const createIncidentSchema = z.object({
  qrCodeValue: z.string().trim().min(2).max(128),
  incidentType: z.nativeEnum(IncidentType),
  severity: z.nativeEnum(IncidentSeverity).optional(),
  priority: z.nativeEnum(IncidentPriority).optional(),
  description: z.string().trim().min(6).max(2000),
  licenseeId: z.string().uuid().optional(),
  tags: z.array(z.string().trim().min(1).max(40)).max(10).optional(),
});

const patchIncidentSchema = z
  .object({
    status: z.nativeEnum(IncidentStatus).optional(),
    severity: z.nativeEnum(IncidentSeverity).optional(),
    priority: z.nativeEnum(IncidentPriority).optional(),
    assignedToUserId: z.string().uuid().nullable().optional(),
    internalNotes: z.string().trim().max(5000).nullable().optional(),
    tags: z.array(z.string().trim().min(1).max(40)).max(20).optional(),
    resolutionSummary: z.string().trim().max(3000).nullable().optional(),
    resolutionOutcome: z.nativeEnum(IncidentResolutionOutcome).nullable().optional(),
  })
  .refine((val) => Object.keys(val).length > 0, { message: "No fields provided" });

const noteSchema = z.object({
  note: z.string().trim().min(2).max(4000),
});

const actionSchema = z.object({
  action: z.enum([
    "FLAG_QR_UNDER_INVESTIGATION",
    "UNFLAG_QR_UNDER_INVESTIGATION",
    "SUSPEND_BATCH",
    "REINSTATE_BATCH",
    "SUSPEND_ORG",
    "REINSTATE_ORG",
    "SUSPEND_MANUFACTURER_USERS",
    "REINSTATE_MANUFACTURER_USERS",
  ]),
  reason: z.string().trim().min(3).max(600),
  qrCodeId: z.string().uuid().optional(),
  batchId: z.string().uuid().optional(),
  licenseeId: z.string().uuid().optional(),
  manufacturerUserIds: z.array(z.string().uuid()).optional(),
});

const commSchema = z.object({
  recipient: z.enum(["reporter", "org_admin"]).optional(),
  toAddress: z.string().trim().email().optional(),
  subject: z.string().trim().min(3).max(200),
  message: z.string().trim().min(1).max(5000),
  template: z.string().trim().max(80).optional(),
  senderMode: z.enum(["actor", "system"]).optional(),
});

const normalizeCode = (value: string) => String(value || "").trim().toUpperCase();

export const listIrIncidents = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });

    const paged = paginationSchema.safeParse(req.query || {});
    if (!paged.success) return res.status(400).json({ success: false, error: "Invalid pagination" });
    const queryParsed = listIncidentsQuerySchema.safeParse(req.query || {});
    if (!queryParsed.success) return res.status(400).json({ success: false, error: "Invalid filters" });

    const status = sanitizeIncidentStatus(queryParsed.data.status || "") || undefined;
    const severity = sanitizeIncidentSeverity(queryParsed.data.severity || "") || undefined;
    const priorityRaw = String(queryParsed.data.priority || "").trim().toUpperCase();
    const priority = priorityRaw && (priorityRaw in IncidentPriority) ? (priorityRaw as IncidentPriority) : undefined;
    const licenseeId = String(queryParsed.data.licenseeId || "").trim() || undefined;
    const manufacturerId = String(queryParsed.data.manufacturerId || "").trim() || undefined;
    const qr = queryParsed.data.qr ? normalizeCode(queryParsed.data.qr) : undefined;
    const search = queryParsed.data.search ? String(queryParsed.data.search).trim() : undefined;
    const assignedTo = String(queryParsed.data.assigned_to || "").trim() || undefined;

    const dateFromRaw = String(queryParsed.data.date_from || "").trim();
    const dateToRaw = String(queryParsed.data.date_to || "").trim();
    const dateFrom = dateFromRaw ? new Date(dateFromRaw) : undefined;
    const dateTo = dateToRaw ? new Date(dateToRaw) : undefined;

    const where: any = {};
    if (status) where.status = status;
    if (severity) where.severity = severity;
    if (priority) where.priority = priority;
    if (assignedTo) where.assignedToUserId = assignedTo;
    if (licenseeId) where.licenseeId = licenseeId;
    if (qr) where.qrCodeValue = { contains: qr, mode: "insensitive" };

    if (manufacturerId) {
      where.OR = [
        { qrCode: { batch: { manufacturerId } } },
        { scanEvent: { batch: { manufacturerId } } },
      ];
    }

    if (dateFrom || dateTo) {
      where.createdAt = {};
      if (dateFrom && Number.isFinite(dateFrom.getTime())) where.createdAt.gte = dateFrom;
      if (dateTo && Number.isFinite(dateTo.getTime())) where.createdAt.lte = dateTo;
    }

    if (search) {
      const q = String(search).slice(0, 120);
      where.OR = [
        ...(Array.isArray(where.OR) ? where.OR : []),
        { qrCodeValue: { contains: q, mode: "insensitive" } },
        { description: { contains: q, mode: "insensitive" } },
        { customerEmail: { contains: q, mode: "insensitive" } },
        { customerPhone: { contains: q, mode: "insensitive" } },
        { productBatchNo: { contains: q, mode: "insensitive" } },
      ];
    }

    const [incidents, total] = await Promise.all([
      prisma.incident.findMany({
        where,
        orderBy: [{ createdAt: "desc" }],
        take: paged.data.limit,
        skip: paged.data.offset,
        include: {
          licensee: { select: { id: true, name: true, prefix: true } },
          assignedToUser: { select: { id: true, name: true, email: true } },
          qrCode: { select: { id: true, code: true, underInvestigationAt: true } },
        },
      }),
      prisma.incident.count({ where }),
    ]);

    return res.json({
      success: true,
      data: {
        incidents,
        total,
        limit: paged.data.limit,
        offset: paged.data.offset,
      },
    });
  } catch (e) {
    console.error("listIrIncidents error:", e);
    return res.status(500).json({ success: false, error: "Failed to list incidents" });
  }
};

export const createIrIncident = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });

    const parsed = createIncidentSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid payload" });
    }

    const normalizedCode = normalizeCode(parsed.data.qrCodeValue);
    const qr = await prisma.qRCode.findUnique({
      where: { code: normalizedCode },
      select: { id: true, licenseeId: true },
    });

    const licenseeId = parsed.data.licenseeId || qr?.licenseeId || null;
    if (!licenseeId) return res.status(400).json({ success: false, error: "licenseeId is required" });
    if (parsed.data.licenseeId && qr?.licenseeId && parsed.data.licenseeId !== qr.licenseeId) {
      return res.status(400).json({ success: false, error: "licenseeId does not match QR code tenant" });
    }

    const severity = parsed.data.severity || IncidentSeverity.MEDIUM;
    const priority = parsed.data.priority || IncidentPriority.P3;

    const created = await prisma.incident.create({
      data: {
        qrCodeId: qr?.id || null,
        qrCodeValue: normalizedCode,
        licenseeId,
        reportedBy: "ADMIN",
        incidentType: parsed.data.incidentType,
        severity,
        severityOverridden: true,
        priority,
        description: parsed.data.description,
        photos: [],
        tags: parsed.data.tags || [],
        status: IncidentStatus.NEW,
        slaDueAt: computeSlaDueAt(severity),
      } as any,
    });

    await recordIncidentEvent({
      incidentId: created.id,
      actorType: IncidentActorType.ADMIN,
      actorUserId: req.user.userId,
      eventType: IncidentEventType.CREATED,
      eventPayload: { source: "ir_create" },
    });

    await createAuditLog({
      userId: req.user.userId,
      licenseeId,
      action: "IR_INCIDENT_CREATED",
      entityType: "Incident",
      entityId: created.id,
      details: { qrCodeValue: normalizedCode, incidentType: created.incidentType, severity, priority },
      ipAddress: req.ip,
    });

    await ensureIncidentWorkflowArtifacts({
      incidentId: created.id,
      actorUserId: req.user.userId,
      actorType: IncidentActorType.ADMIN,
      emitEvents: false,
    });
    await notifyIncidentLifecycle({
      incidentId: created.id,
      licenseeId,
      type: "ir_incident_created",
      title: "IR incident created",
      body: `A new incident was created with priority ${priority} and severity ${severity}.`,
      data: { priority, severity, status: created.status, incidentType: created.incidentType, qrCodeValue: created.qrCodeValue },
    });

    try {
      await runIncidentAutoContainment({
        incidentId: created.id,
        trigger: "IR_CREATE",
        actorUserId: req.user.userId,
        ipAddress: req.ip,
      });
    } catch (autoContainmentError) {
      console.error("runIncidentAutoContainment(ir_create) error:", autoContainmentError);
    }

    return res.status(201).json({ success: true, data: created });
  } catch (e) {
    console.error("createIrIncident error:", e);
    return res.status(500).json({ success: false, error: "Failed to create incident" });
  }
};

export const getIrIncident = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });
    const id = String(req.params.id || "").trim();
    if (!id) return res.status(400).json({ success: false, error: "Missing incident id" });

    const incident = await prisma.incident.findUnique({
      where: { id },
      include: {
        licensee: { select: { id: true, name: true, prefix: true, supportEmail: true, supportPhone: true } },
        assignedToUser: { select: { id: true, name: true, email: true } },
        qrCode: {
          select: {
            id: true,
            code: true,
            underInvestigationAt: true,
            underInvestigationReason: true,
            batch: { select: { id: true, name: true, suspendedAt: true, suspendedReason: true, manufacturer: { select: { id: true, name: true, email: true } } } },
          },
        },
        scanEvent: {
          select: {
            id: true,
            scannedAt: true,
            locationCountry: true,
            locationCity: true,
            batch: { select: { id: true, name: true, manufacturer: { select: { id: true, name: true, email: true } } } },
          },
        },
        events: { orderBy: { createdAt: "asc" }, include: { actorUser: { select: { id: true, name: true, email: true } } } },
        communications: { orderBy: { createdAt: "desc" } },
        evidence: { orderBy: { createdAt: "desc" } },
        policyAlerts: { orderBy: { createdAt: "desc" }, take: 25 },
      },
    });
    if (!incident) return res.status(404).json({ success: false, error: "Incident not found" });

    return res.json({ success: true, data: incident });
  } catch (e) {
    console.error("getIrIncident error:", e);
    return res.status(500).json({ success: false, error: "Failed to load incident" });
  }
};

export const patchIrIncident = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });
    const id = String(req.params.id || "").trim();
    if (!id) return res.status(400).json({ success: false, error: "Missing incident id" });

    const parsed = patchIncidentSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid payload" });
    }

    const existing = await prisma.incident.findUnique({
      where: { id },
      select: {
        id: true,
        licenseeId: true,
        status: true,
        severity: true,
        priority: true,
        assignedToUserId: true,
        internalNotes: true,
        tags: true,
        resolutionSummary: true,
        resolutionOutcome: true,
      },
    });
    if (!existing) return res.status(404).json({ success: false, error: "Incident not found" });

    const updateData: any = {};
    const changedFields: string[] = [];

    if (parsed.data.status && parsed.data.status !== existing.status) {
      updateData.status = parsed.data.status;
      changedFields.push("status");
    }
    if (parsed.data.severity && parsed.data.severity !== existing.severity) {
      updateData.severity = parsed.data.severity;
      updateData.severityOverridden = true;
      updateData.slaDueAt = computeSlaDueAt(parsed.data.severity);
      changedFields.push("severity");
    }
    if (parsed.data.priority && parsed.data.priority !== existing.priority) {
      updateData.priority = parsed.data.priority;
      changedFields.push("priority");
    }
    if (parsed.data.assignedToUserId !== undefined && parsed.data.assignedToUserId !== existing.assignedToUserId) {
      updateData.assignedToUserId = parsed.data.assignedToUserId || null;
      changedFields.push("assignedToUserId");
    }
    if (parsed.data.internalNotes !== undefined && parsed.data.internalNotes !== existing.internalNotes) {
      updateData.internalNotes = parsed.data.internalNotes || null;
      changedFields.push("internalNotes");
    }
    if (parsed.data.tags && JSON.stringify(parsed.data.tags) !== JSON.stringify(existing.tags || [])) {
      updateData.tags = parsed.data.tags;
      changedFields.push("tags");
    }
    if (parsed.data.resolutionSummary !== undefined && parsed.data.resolutionSummary !== existing.resolutionSummary) {
      updateData.resolutionSummary = parsed.data.resolutionSummary || null;
      changedFields.push("resolutionSummary");
    }
    if (parsed.data.resolutionOutcome !== undefined) {
      const next = sanitizeResolutionOutcome(parsed.data.resolutionOutcome);
      if (next !== existing.resolutionOutcome) {
        updateData.resolutionOutcome = next;
        changedFields.push("resolutionOutcome");
      }
    }

    if (changedFields.length === 0) return res.json({ success: true, data: existing });

    const updated = await prisma.incident.update({
      where: { id },
      data: updateData,
    });

    if (changedFields.includes("status")) {
      await recordIncidentEvent({
        incidentId: id,
        actorType: IncidentActorType.ADMIN,
        actorUserId: req.user.userId,
        eventType: IncidentEventType.STATUS_CHANGED,
        eventPayload: { from: existing.status, to: updated.status },
      });
    }
    if (changedFields.includes("assignedToUserId")) {
      await recordIncidentEvent({
        incidentId: id,
        actorType: IncidentActorType.ADMIN,
        actorUserId: req.user.userId,
        eventType: IncidentEventType.ASSIGNED,
        eventPayload: { from: existing.assignedToUserId, to: updated.assignedToUserId },
      });
    }

    await recordIncidentEvent({
      incidentId: id,
      actorType: IncidentActorType.ADMIN,
      actorUserId: req.user.userId,
      eventType: IncidentEventType.UPDATED_FIELDS,
      eventPayload: { changedFields },
    });

    await createAuditLog({
      userId: req.user.userId,
      licenseeId: existing.licenseeId || undefined,
      action: "IR_INCIDENT_UPDATED",
      entityType: "Incident",
      entityId: id,
      details: { changedFields },
      ipAddress: req.ip,
    });

    await ensureIncidentWorkflowArtifacts({
      incidentId: id,
      actorUserId: req.user.userId,
      actorType: IncidentActorType.ADMIN,
      emitEvents: false,
    });

    await notifyIncidentLifecycle({
      incidentId: id,
      licenseeId: existing.licenseeId || null,
      type: "ir_incident_updated",
      title: "IR incident updated",
      body: changedFields.length
        ? `Updated: ${changedFields.map((f) => String(f).replace(/_/g, " ")).join(", ")}.`
        : "Incident details were updated.",
      data: { changedFields },
    });

    return res.json({ success: true, data: updated });
  } catch (e) {
    console.error("patchIrIncident error:", e);
    return res.status(500).json({ success: false, error: "Failed to update incident" });
  }
};

export const addIrIncidentEvent = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });
    const id = String(req.params.id || "").trim();
    if (!id) return res.status(400).json({ success: false, error: "Missing incident id" });

    const parsed = noteSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid note payload" });
    }

    const incident = await prisma.incident.findUnique({ where: { id }, select: { id: true, licenseeId: true } });
    if (!incident) return res.status(404).json({ success: false, error: "Incident not found" });

    const evt = await recordIncidentEvent({
      incidentId: id,
      actorType: IncidentActorType.ADMIN,
      actorUserId: req.user.userId,
      eventType: IncidentEventType.NOTE_ADDED,
      eventPayload: { note: parsed.data.note },
    });

    await createAuditLog({
      userId: req.user.userId,
      licenseeId: incident.licenseeId || undefined,
      action: "IR_INCIDENT_NOTE_ADDED",
      entityType: "Incident",
      entityId: id,
      details: { noteLength: parsed.data.note.length },
      ipAddress: req.ip,
    });

    return res.status(201).json({ success: true, data: evt });
  } catch (e) {
    console.error("addIrIncidentEvent error:", e);
    return res.status(500).json({ success: false, error: "Failed to add event" });
  }
};

export const applyIrIncidentAction = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });
    const id = String(req.params.id || "").trim();
    if (!id) return res.status(400).json({ success: false, error: "Missing incident id" });

    const parsed = actionSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid payload" });
    }

    const result = await applyContainmentAction({
      incidentId: id,
      actorUserId: req.user.userId,
      action: parsed.data.action as IrContainmentAction,
      reason: parsed.data.reason,
      qrCodeId: parsed.data.qrCodeId || null,
      batchId: parsed.data.batchId || null,
      licenseeId: parsed.data.licenseeId || null,
      manufacturerUserIds: parsed.data.manufacturerUserIds,
      ipAddress: req.ip,
    });

    return res.json({ success: true, data: result });
  } catch (e: any) {
    console.error("applyIrIncidentAction error:", e);
    const msg = String(e?.message || "");
    if (msg.includes("MISSING_")) return res.status(400).json({ success: false, error: msg });
    if (msg.includes("INCIDENT_NOT_FOUND")) return res.status(404).json({ success: false, error: "Incident not found" });
    if (msg.includes("TARGET_NOT_MANUFACTURER")) return res.status(400).json({ success: false, error: "Target user must be a manufacturer role" });
    return res.status(500).json({ success: false, error: "Failed to apply action" });
  }
};

const resolveOrgAdminEmail = async (licenseeId: string) => {
  const adminUser = await prisma.user.findFirst({
    where: {
      licenseeId,
      role: { in: [UserRole.LICENSEE_ADMIN, UserRole.ORG_ADMIN] },
      isActive: true,
      deletedAt: null,
    },
    orderBy: { createdAt: "asc" },
    select: { email: true },
  });
  if (adminUser?.email) return String(adminUser.email).trim();

  const licensee = await prisma.licensee.findUnique({
    where: { id: licenseeId },
    select: { supportEmail: true },
  });
  return String(licensee?.supportEmail || "").trim() || null;
};

export const sendIrIncidentCommunication = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });
    const id = String(req.params.id || "").trim();
    if (!id) return res.status(400).json({ success: false, error: "Missing incident id" });

    const parsed = commSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid payload" });
    }

    const incident = await prisma.incident.findUnique({
      where: { id },
      select: { id: true, licenseeId: true, customerEmail: true },
    });
    if (!incident) return res.status(404).json({ success: false, error: "Incident not found" });

    let toAddress = parsed.data.toAddress || "";
    const recipient = parsed.data.recipient || "reporter";

    if (!toAddress) {
      if (recipient === "reporter") {
        toAddress = String(incident.customerEmail || "").trim();
      } else if (incident.licenseeId) {
        toAddress = (await resolveOrgAdminEmail(incident.licenseeId)) || "";
      }
    }

    if (!toAddress) {
      return res.status(400).json({ success: false, error: "Recipient email is not available for this incident" });
    }

    const delivery = await sendIncidentEmail({
      incidentId: id,
      licenseeId: incident.licenseeId || null,
      toAddress,
      subject: parsed.data.subject,
      text: parsed.data.message,
      actorUser: { id: req.user.userId, role: req.user.role },
      senderMode: parsed.data.senderMode || "system",
      template: parsed.data.template || "ir_manual",
    });

    return res.status(delivery.delivered ? 200 : 502).json({ success: delivery.delivered, data: delivery });
  } catch (e) {
    console.error("sendIrIncidentCommunication error:", e);
    return res.status(500).json({ success: false, error: "Failed to send communication" });
  }
};
