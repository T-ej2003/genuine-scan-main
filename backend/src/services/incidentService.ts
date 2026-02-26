import {
  IncidentActorType,
  IncidentContactMethod,
  IncidentEventType,
  IncidentResolutionOutcome,
  IncidentSeverity,
  IncidentStatus,
  IncidentType,
  UserRole,
} from "@prisma/client";
import prisma from "../config/database";
import { createAuditLog } from "./auditService";
import { deviceFingerprintFromRequest, sha256Hash } from "./securityHashService";
import { reverseGeocode } from "./locationService";
import { evaluatePolicyRulesForIncidentVolume } from "./ir/policyRuleEngineService";
import { ensureIncidentWorkflowArtifacts } from "./supportWorkflowService";
import { notifyIncidentLifecycle } from "./notificationService";

type IncidentReportInput = {
  qrCodeValue: string;
  customerName?: string;
  customerEmail?: string;
  customerPhone?: string;
  customerCountry?: string;
  preferredContactMethod?: "email" | "phone" | "whatsapp" | "none";
  consentToContact: boolean;
  incidentType: "counterfeit_suspected" | "duplicate_scan" | "tampered_label" | "wrong_product" | "other";
  description: string;
  purchasePlace?: string;
  purchaseDate?: string;
  productBatchNo?: string;
  locationLat?: number | null;
  locationLng?: number | null;
  photoUrls?: string[];
  tags?: string[];
};

type IncidentActor = {
  actorType: IncidentActorType;
  actorUserId?: string | null;
  licenseeId?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
  deviceFingerprint?: string | null;
};

const MAX_SAFE_TEXT = 3000;

const cleanText = (value: unknown, max = MAX_SAFE_TEXT): string => {
  const raw = String(value || "").trim();
  if (!raw) return "";
  const withoutTags = raw.replace(/<[^>]*>/g, "");
  return withoutTags.replace(/\s+/g, " ").trim().slice(0, max);
};

const normalizeCode = (value: string) => cleanText(value, 128).toUpperCase();

const incidentTypeMap: Record<IncidentReportInput["incidentType"], IncidentType> = {
  counterfeit_suspected: IncidentType.COUNTERFEIT_SUSPECTED,
  duplicate_scan: IncidentType.DUPLICATE_SCAN,
  tampered_label: IncidentType.TAMPERED_LABEL,
  wrong_product: IncidentType.WRONG_PRODUCT,
  other: IncidentType.OTHER,
};

const contactMethodMap: Record<NonNullable<IncidentReportInput["preferredContactMethod"]>, IncidentContactMethod> = {
  email: IncidentContactMethod.EMAIL,
  phone: IncidentContactMethod.PHONE,
  whatsapp: IncidentContactMethod.WHATSAPP,
  none: IncidentContactMethod.NONE,
};

const sanitizeTags = (tags?: string[]) =>
  Array.from(
    new Set(
      (Array.isArray(tags) ? tags : [])
        .map((t) => cleanText(t, 40).toLowerCase())
        .filter(Boolean)
        .slice(0, 10)
    )
  );

const toDateOrNull = (input?: string) => {
  if (!input) return null;
  const dt = new Date(input);
  return Number.isFinite(dt.getTime()) ? dt : null;
};

const severitySlaHours: Record<IncidentSeverity, number> = {
  [IncidentSeverity.CRITICAL]: 4,
  [IncidentSeverity.HIGH]: 24,
  [IncidentSeverity.MEDIUM]: 72,
  [IncidentSeverity.LOW]: 168,
};

export const computeSlaDueAt = (severity: IncidentSeverity) => {
  const hours = severitySlaHours[severity] || 72;
  return new Date(Date.now() + hours * 60 * 60_000);
};

const toPreferredContactMethod = (method?: IncidentReportInput["preferredContactMethod"]) => {
  const key = (method || "none").toLowerCase() as NonNullable<IncidentReportInput["preferredContactMethod"]>;
  return contactMethodMap[key] || IncidentContactMethod.NONE;
};

export const normalizeCustomerContact = (input: {
  consentToContact: boolean;
  customerName?: string;
  customerEmail?: string;
  customerPhone?: string;
  customerCountry?: string;
  preferredContactMethod?: IncidentReportInput["preferredContactMethod"];
}) => {
  const consentToContact = Boolean(input.consentToContact);
  const customerEmail = consentToContact ? cleanText(input.customerEmail, 160).toLowerCase() || null : null;
  const customerPhone = consentToContact ? cleanText(input.customerPhone, 40) || null : null;
  const customerName = consentToContact ? cleanText(input.customerName, 120) || null : null;
  const customerCountry = consentToContact ? cleanText(input.customerCountry, 80) || null : null;
  const preferredContactMethod = consentToContact
    ? toPreferredContactMethod(input.preferredContactMethod)
    : IncidentContactMethod.NONE;

  return {
    consentToContact,
    customerName,
    customerEmail,
    customerPhone,
    customerCountry,
    preferredContactMethod,
  };
};

export const isIncidentAdminRole = (role: UserRole) =>
  role === UserRole.SUPER_ADMIN ||
  role === UserRole.PLATFORM_SUPER_ADMIN ||
  role === UserRole.LICENSEE_ADMIN ||
  role === UserRole.ORG_ADMIN;

const computeSpamSignal = async (input: { email?: string | null; phone?: string | null }) => {
  const maxPerHour = Number(process.env.INCIDENT_SPAM_MAX_PER_HOUR || "5");
  const since = new Date(Date.now() - 60 * 60_000);

  if (!input.email && !input.phone) return false;

  const matches = await prisma.incident.count({
    where: {
      createdAt: { gte: since },
      OR: [
        input.email ? { customerEmail: input.email } : undefined,
        input.phone ? { customerPhone: input.phone } : undefined,
      ].filter(Boolean) as any[],
    },
  });
  return matches >= maxPerHour;
};

const computeSeverity = async (params: {
  incidentType: IncidentType;
  qrCodeId?: string | null;
  scanCount?: number | null;
  locationLat?: number | null;
  locationLng?: number | null;
}) => {
  const { incidentType, qrCodeId, scanCount, locationLat, locationLng } = params;

  if (incidentType === IncidentType.TAMPERED_LABEL) return IncidentSeverity.CRITICAL;

  let priorIncidentCount = 0;
  if (qrCodeId) {
    priorIncidentCount = await prisma.incident.count({
      where: {
        qrCodeId,
        status: { not: IncidentStatus.REJECTED_SPAM },
      },
    });
  }

  if ((scanCount || 0) >= 5 || priorIncidentCount >= 2) {
    return IncidentSeverity.CRITICAL;
  }

  if (incidentType === IncidentType.DUPLICATE_SCAN) {
    const hasLocation = locationLat != null && locationLng != null;
    if ((scanCount || 0) >= 2 || hasLocation) return IncidentSeverity.HIGH;
    return IncidentSeverity.MEDIUM;
  }

  if (incidentType === IncidentType.COUNTERFEIT_SUSPECTED) return IncidentSeverity.HIGH;
  if (incidentType === IncidentType.WRONG_PRODUCT) return IncidentSeverity.MEDIUM;
  return IncidentSeverity.LOW;
};

export const recordIncidentEvent = async (input: {
  incidentId: string;
  actorType: IncidentActorType;
  actorUserId?: string | null;
  eventType: IncidentEventType;
  eventPayload?: any;
}) => {
  return prisma.incidentEvent.create({
    data: {
      incidentId: input.incidentId,
      actorType: input.actorType,
      actorUserId: input.actorUserId || null,
      eventType: input.eventType,
      eventPayload: input.eventPayload ?? null,
    },
  });
};

export const createIncidentFromReport = async (
  payload: IncidentReportInput,
  actor: IncidentActor,
  uploads?: Array<{ fileUrl?: string | null; storageKey?: string | null; fileType?: string | null }>
) => {
  const qrCodeValue = normalizeCode(payload.qrCodeValue);
  const incidentType = incidentTypeMap[payload.incidentType];
  const description = cleanText(payload.description, 2000);
  const purchasePlace = cleanText(payload.purchasePlace, 240) || null;
  const productBatchNo = cleanText(payload.productBatchNo, 120) || null;
  const locationLat = typeof payload.locationLat === "number" ? payload.locationLat : null;
  const locationLng = typeof payload.locationLng === "number" ? payload.locationLng : null;
  const location = await reverseGeocode(locationLat, locationLng);

  const qrCode = await prisma.qRCode.findUnique({
    where: { code: qrCodeValue },
    select: {
      id: true,
      code: true,
      scanCount: true,
      licenseeId: true,
      scanLogs: {
        orderBy: { scannedAt: "desc" },
        take: 1,
        select: { id: true },
      },
    },
  });

  const normalizedContact = normalizeCustomerContact({
    consentToContact: payload.consentToContact,
    customerName: payload.customerName,
    customerEmail: payload.customerEmail,
    customerPhone: payload.customerPhone,
    customerCountry: payload.customerCountry,
    preferredContactMethod: payload.preferredContactMethod,
  });
  const consentToContact = normalizedContact.consentToContact;
  const customerEmail = normalizedContact.customerEmail;
  const customerPhone = normalizedContact.customerPhone;
  const customerName = normalizedContact.customerName;
  const customerCountry = normalizedContact.customerCountry;
  const preferredContactMethod = normalizedContact.preferredContactMethod;

  const suspectedSpam = await computeSpamSignal({
    email: customerEmail,
    phone: customerPhone,
  });

  const severity = await computeSeverity({
    incidentType,
    qrCodeId: qrCode?.id || null,
    scanCount: qrCode?.scanCount || 0,
    locationLat,
    locationLng,
  });

  const status = suspectedSpam ? IncidentStatus.REJECTED_SPAM : IncidentStatus.NEW;
  const tags = sanitizeTags(payload.tags);
  if (suspectedSpam && !tags.includes("suspected_spam")) tags.push("suspected_spam");
  const photoUrls = (Array.isArray(payload.photoUrls) ? payload.photoUrls : [])
    .map((v) => cleanText(v, 1000))
    .filter(Boolean)
    .slice(0, 8);

  const ipHash = sha256Hash(actor.ipAddress);
  const userAgentHash = sha256Hash(actor.userAgent);
  const deviceFingerprintHash = deviceFingerprintFromRequest(
    actor.ipAddress,
    actor.userAgent,
    actor.deviceFingerprint
  );

  const incident = await prisma.$transaction(async (tx) => {
    const created = await tx.incident.create({
      data: {
        qrCodeId: qrCode?.id || null,
        qrCodeValue,
        scanEventId: qrCode?.scanLogs?.[0]?.id || null,
        licenseeId: qrCode?.licenseeId || actor.licenseeId || null,
        reportedBy: actor.actorType === IncidentActorType.CUSTOMER ? "CUSTOMER" : "ADMIN",
        customerName,
        customerEmail,
        customerPhone,
        customerCountry,
        preferredContactMethod,
        consentToContact,
        incidentType,
        severity,
        description,
        photos: photoUrls,
        purchasePlace,
        purchaseDate: toDateOrNull(payload.purchaseDate),
        productBatchNo,
        locationLat,
        locationLng,
        locationName: location?.name || null,
        locationCountry: location?.country || null,
        locationRegion: location?.region || null,
        locationCity: location?.city || null,
        ipHash,
        userAgentHash,
        deviceFingerprintHash,
        status,
        slaDueAt: computeSlaDueAt(severity),
        tags,
      },
    });

    await tx.incidentEvent.create({
      data: {
        incidentId: created.id,
        actorType: actor.actorType,
        actorUserId: actor.actorUserId || null,
        eventType: IncidentEventType.CREATED,
        eventPayload: {
          incidentType,
          severity,
          status,
          consentToContact,
          hasUploads: Boolean(uploads && uploads.length > 0),
          suspectedSpam,
        },
      },
    });

    if (uploads && uploads.length > 0) {
      for (const upload of uploads) {
        await tx.incidentEvidence.create({
          data: {
            incidentId: created.id,
            fileUrl: upload.fileUrl || null,
            storageKey: upload.storageKey || null,
            fileType: upload.fileType || null,
            uploadedBy: actor.actorType,
            uploadedByUserId: actor.actorUserId || null,
          },
        });
      }
    }

    return created;
  });

  await createAuditLog({
    userId: actor.actorUserId || undefined,
    licenseeId: incident.licenseeId || undefined,
    action: "INCIDENT_CREATED",
    entityType: "Incident",
    entityId: incident.id,
    ipAddress: actor.ipAddress || undefined,
    details: {
      qrCodeValue: incident.qrCodeValue,
      incidentType: incident.incidentType,
      severity: incident.severity,
      status: incident.status,
      consentToContact: incident.consentToContact,
      suspectedSpam,
    },
  });

  // IR volume rules - best effort and never block incident creation.
  try {
    await evaluatePolicyRulesForIncidentVolume({
      incidentId: incident.id,
      licenseeId: incident.licenseeId || null,
    });
  } catch (e) {
    console.error("evaluatePolicyRulesForIncidentVolume failed:", e);
  }

  // Workflow artifacts and role-aware notifications are best-effort.
  try {
    await ensureIncidentWorkflowArtifacts({
      incidentId: incident.id,
      actorUserId: actor.actorUserId || null,
      actorType: actor.actorType,
      emitEvents: false,
    });

    await notifyIncidentLifecycle({
      incidentId: incident.id,
      licenseeId: incident.licenseeId || null,
      type: "incident_created",
      title: "New incident reported",
      body: `A ${toHumanIncidentType(incident.incidentType).toLowerCase()} case entered intake (severity ${toHumanIncidentSeverity(incident.severity)}).`,
      data: {
        severity: incident.severity,
        status: incident.status,
        qrCodeValue: incident.qrCodeValue,
        incidentType: incident.incidentType,
      },
    });
  } catch (e) {
    console.error("Incident workflow/notification setup failed:", e);
  }

  return incident;
};

export const getIncidentByIdScoped = async (incidentId: string, actor: { role: UserRole; licenseeId?: string | null }) => {
  const where: any = { id: incidentId };
  if (actor.role !== UserRole.SUPER_ADMIN && actor.role !== UserRole.PLATFORM_SUPER_ADMIN) {
    where.licenseeId = actor.licenseeId || "__none__";
  }

  return prisma.incident.findFirst({
    where,
    include: {
      assignedToUser: { select: { id: true, name: true, email: true } },
      handoff: true,
      supportTicket: {
        include: {
          messages: {
            orderBy: { createdAt: "desc" },
            take: 50,
            include: {
              actorUser: { select: { id: true, name: true, email: true } },
            },
          },
        },
      },
      events: {
        orderBy: { createdAt: "asc" },
        include: { actorUser: { select: { id: true, name: true, email: true } } },
      },
      communications: { orderBy: { createdAt: "desc" } },
      evidence: { orderBy: { createdAt: "desc" } },
    },
  });
};

export const listIncidentsScoped = async (input: {
  role: UserRole;
  actorLicenseeId?: string | null;
  filters: {
    status?: IncidentStatus;
    severity?: IncidentSeverity;
    qr?: string;
    search?: string;
    dateFrom?: Date;
    dateTo?: Date;
    assignedTo?: string;
    licenseeId?: string;
    limit: number;
    offset: number;
  };
}) => {
  const where: any = {};
  if (input.role !== UserRole.SUPER_ADMIN && input.role !== UserRole.PLATFORM_SUPER_ADMIN) {
    where.licenseeId = input.actorLicenseeId || "__none__";
  } else if (input.filters.licenseeId) {
    where.licenseeId = input.filters.licenseeId;
  }
  if (input.filters.status) where.status = input.filters.status;
  if (input.filters.severity) where.severity = input.filters.severity;
  if (input.filters.assignedTo) where.assignedToUserId = input.filters.assignedTo;
  if (input.filters.qr) where.qrCodeValue = { contains: input.filters.qr.toUpperCase(), mode: "insensitive" };

  if (input.filters.dateFrom || input.filters.dateTo) {
    where.createdAt = {};
    if (input.filters.dateFrom) where.createdAt.gte = input.filters.dateFrom;
    if (input.filters.dateTo) where.createdAt.lte = input.filters.dateTo;
  }

  if (input.filters.search) {
    const q = cleanText(input.filters.search, 120);
    where.OR = [
      { qrCodeValue: { contains: q, mode: "insensitive" } },
      { description: { contains: q, mode: "insensitive" } },
      { customerEmail: { contains: q, mode: "insensitive" } },
      { customerPhone: { contains: q, mode: "insensitive" } },
      { productBatchNo: { contains: q, mode: "insensitive" } },
    ];
  }

  const [rows, total] = await Promise.all([
    prisma.incident.findMany({
      where,
      orderBy: [{ createdAt: "desc" }],
      take: input.filters.limit,
      skip: input.filters.offset,
      include: {
        assignedToUser: { select: { id: true, name: true, email: true } },
        handoff: true,
        supportTicket: {
          select: {
            id: true,
            referenceCode: true,
            status: true,
            slaDueAt: true,
          },
        },
        evidence: {
          orderBy: { createdAt: "desc" },
          take: 3,
        },
      },
    }),
    prisma.incident.count({ where }),
  ]);

  return { rows, total };
};

export const sanitizeResolutionOutcome = (value?: string | null): IncidentResolutionOutcome | null => {
  const normalized = String(value || "").toUpperCase();
  if (!normalized) return null;
  if (normalized === "CONFIRMED_FRAUD") return IncidentResolutionOutcome.CONFIRMED_FRAUD;
  if (normalized === "NOT_FRAUD") return IncidentResolutionOutcome.NOT_FRAUD;
  if (normalized === "INCONCLUSIVE") return IncidentResolutionOutcome.INCONCLUSIVE;
  return null;
};

export const sanitizeIncidentStatus = (value?: string | null): IncidentStatus | null => {
  const normalized = String(value || "").toUpperCase();
  if (!normalized) return null;
  if (normalized === "NEW") return IncidentStatus.NEW;
  if (normalized === "TRIAGED") return IncidentStatus.TRIAGED;
  if (normalized === "TRIAGE") return IncidentStatus.TRIAGE;
  if (normalized === "INVESTIGATING") return IncidentStatus.INVESTIGATING;
  if (normalized === "CONTAINMENT") return IncidentStatus.CONTAINMENT;
  if (normalized === "ERADICATION") return IncidentStatus.ERADICATION;
  if (normalized === "RECOVERY") return IncidentStatus.RECOVERY;
  if (normalized === "AWAITING_CUSTOMER") return IncidentStatus.AWAITING_CUSTOMER;
  if (normalized === "AWAITING_LICENSEE") return IncidentStatus.AWAITING_LICENSEE;
  if (normalized === "MITIGATED") return IncidentStatus.MITIGATED;
  if (normalized === "RESOLVED") return IncidentStatus.RESOLVED;
  if (normalized === "CLOSED") return IncidentStatus.CLOSED;
  if (normalized === "REOPENED") return IncidentStatus.REOPENED;
  if (normalized === "REJECTED_SPAM") return IncidentStatus.REJECTED_SPAM;
  return null;
};

export const sanitizeIncidentSeverity = (value?: string | null): IncidentSeverity | null => {
  const normalized = String(value || "").toUpperCase();
  if (!normalized) return null;
  if (normalized === "LOW") return IncidentSeverity.LOW;
  if (normalized === "MEDIUM") return IncidentSeverity.MEDIUM;
  if (normalized === "HIGH") return IncidentSeverity.HIGH;
  if (normalized === "CRITICAL") return IncidentSeverity.CRITICAL;
  return null;
};

export const toHumanIncidentType = (type: IncidentType) => {
  const map: Record<IncidentType, string> = {
    COUNTERFEIT_SUSPECTED: "Counterfeit suspected",
    DUPLICATE_SCAN: "Duplicate scan",
    TAMPERED_LABEL: "Tampered label",
    WRONG_PRODUCT: "Wrong product",
    OTHER: "Other",
  };
  return map[type] || type;
};

export const toHumanIncidentSeverity = (severity: IncidentSeverity) => {
  const map: Record<IncidentSeverity, string> = {
    LOW: "Low",
    MEDIUM: "Medium",
    HIGH: "High",
    CRITICAL: "Critical",
  };
  return map[severity] || severity;
};

export const toHumanIncidentStatus = (status: IncidentStatus) => {
  const map: Record<IncidentStatus, string> = {
    NEW: "New",
    TRIAGED: "Triaged",
    TRIAGE: "Triage",
    INVESTIGATING: "Investigating",
    CONTAINMENT: "Containment",
    ERADICATION: "Eradication",
    RECOVERY: "Recovery",
    AWAITING_CUSTOMER: "Awaiting customer",
    AWAITING_LICENSEE: "Awaiting licensee",
    MITIGATED: "Mitigated",
    RESOLVED: "Resolved",
    CLOSED: "Closed",
    REOPENED: "Reopened",
    REJECTED_SPAM: "Rejected as spam",
  };
  return map[status] || status;
};

export const buildIncidentAdminUrl = (incidentId: string) => {
  const base =
    String(process.env.PUBLIC_ADMIN_WEB_BASE_URL || "").trim() ||
    String(process.env.PUBLIC_VERIFY_WEB_BASE_URL || "").trim() ||
    "http://localhost:8080";
  return `${base.replace(/\/+$/, "")}/incidents?incidentId=${encodeURIComponent(incidentId)}`;
};
