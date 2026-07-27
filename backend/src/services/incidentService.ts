import {
  IncidentActorType,
  IncidentContactMethod,
  IncidentEventType,
  IncidentResolutionOutcome,
  IncidentSeverity,
  IncidentStatus,
  IncidentType,
  Prisma,
  UserRole,
} from "@prisma/client";

import { deviceFingerprintFromRequest, sha256Hash } from "./securityHashService";
import { reverseGeocode } from "./locationService";
import { withC03PreAuthTransaction } from "../rls-waves/session-c/c03/c03RestrictedDatabase";
import {
  computeIncidentSeverityInTransaction,
  computeIncidentSpamSignalInTransaction,
  createPublicIncidentReportInTransaction,
  getIncidentDetailInTransaction,
  listIncidentsInTransaction,
  recordIncidentEventInTransaction,
} from "../rls-waves/session-c/c03/c03IncidentRepository";
import { C03AccessError } from "../rls-waves/session-c/c03/c03ActorBoundary";

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

type IncidentTransaction = Pick<Prisma.TransactionClient, "$queryRaw">;

const MAX_SAFE_TEXT = 3000;
const decodeMarkupDelimiters = (value: string) => value
  .replace(/&(?:lt|#0*60|#x0*3c);/gi, "<")
  .replace(/&(?:gt|#0*62|#x0*3e);/gi, ">");
const startsMarkup = (value: string, index: number) =>
  value[index + 1] === "<" || /[A-Za-z/!?]/.test(value[index + 1] || "");
export const sanitizeIncidentText = (value: unknown, max = MAX_SAFE_TEXT) => {
  const input = decodeMarkupDelimiters(String(value || "").trim());
  let output = "";
  let insideMarkup = false;
  for (let index = 0; index < input.length; index += 1) {
    const character = input[index];
    if (!insideMarkup && character === "<" && startsMarkup(input, index)) {
      insideMarkup = true;
      continue;
    }
    if (insideMarkup) {
      if (character === ">") insideMarkup = false;
      continue;
    }
    output += character;
  }
  return output.replace(/\s+/g, " ").trim().slice(0, max);
};
const cleanText = sanitizeIncidentText;
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
const sanitizeTags = (tags?: string[]) => Array.from(new Set(
  (Array.isArray(tags) ? tags : [])
    .map((tag) => cleanText(tag, 40).toLowerCase())
    .filter(Boolean)
    .slice(0, 10)
));
const toDateOrNull = (value?: string) => {
  if (!value) return null;
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) ? parsed.toISOString() : null;
};
const requireIncidentTransaction = (db?: IncidentTransaction) => {
  if (!db) throw new C03AccessError("C03 canonical incident transaction is required", 500);
  return db;
};

const severitySlaHours: Record<IncidentSeverity, number> = {
  [IncidentSeverity.CRITICAL]: 4,
  [IncidentSeverity.HIGH]: 24,
  [IncidentSeverity.MEDIUM]: 72,
  [IncidentSeverity.LOW]: 168,
};

export const computeSlaDueAt = (severity: IncidentSeverity) =>
  new Date(Date.now() + (severitySlaHours[severity] || 72) * 60 * 60_000);

export const normalizeCustomerContact = (input: {
  consentToContact: boolean;
  customerName?: string;
  customerEmail?: string;
  customerPhone?: string;
  customerCountry?: string;
  preferredContactMethod?: IncidentReportInput["preferredContactMethod"];
}) => {
  const consentToContact = Boolean(input.consentToContact);
  const method = String(input.preferredContactMethod || "none").toLowerCase() as NonNullable<IncidentReportInput["preferredContactMethod"]>;
  return {
    consentToContact,
    customerName: consentToContact ? cleanText(input.customerName, 120) || null : null,
    customerEmail: consentToContact ? cleanText(input.customerEmail, 160).toLowerCase() || null : null,
    customerPhone: consentToContact ? cleanText(input.customerPhone, 40) || null : null,
    customerCountry: consentToContact ? cleanText(input.customerCountry, 80) || null : null,
    preferredContactMethod: consentToContact ? contactMethodMap[method] || IncidentContactMethod.NONE : IncidentContactMethod.NONE,
  };
};

const incidentAdminRoles = new Set<UserRole>([
  UserRole.SUPER_ADMIN,
  UserRole.PLATFORM_SUPER_ADMIN,
  UserRole.LICENSEE_ADMIN,
  UserRole.ORG_ADMIN,
]);
export const isIncidentAdminRole = (role: UserRole) => incidentAdminRoles.has(role);

const computeSpamSignal = (
  tx: IncidentTransaction,
  qrProof: string,
  input: { email?: string | null; phone?: string | null }
) => computeIncidentSpamSignalInTransaction(tx, qrProof, {
  emailHash: sha256Hash(input.email),
  phoneHash: sha256Hash(input.phone),
});

const computeSeverity = (
  tx: IncidentTransaction,
  qrProof: string,
  input: { incidentType: IncidentType; locationLat?: number | null; locationLng?: number | null }
) => computeIncidentSeverityInTransaction(tx, qrProof, input);

export const recordIncidentEvent = async (input: {
  incidentId: string;
  actorType: IncidentActorType;
  actorUserId?: string | null;
  eventType: IncidentEventType;
  eventPayload?: any;
}, db?: IncidentTransaction) =>
  recordIncidentEventInTransaction<any>(
    requireIncidentTransaction(db),
    input.incidentId,
    input.eventType,
    input.eventPayload
  );

export const createIncidentFromReport = async (
  payload: IncidentReportInput,
  actor: IncidentActor,
  uploads: Array<{ fileUrl?: string | null; storageKey?: string | null; fileType?: string | null }> = [],
  boundary?: { requestId: string; idempotencyKey: string }
) => {
  if (actor.actorType !== IncidentActorType.CUSTOMER || actor.actorUserId || actor.licenseeId) {
    throw new C03AccessError("Public incident intake cannot install caller actor or tenant authority");
  }
  const requestId = String(boundary?.requestId || "").trim();
  const idempotencyKey = String(boundary?.idempotencyKey || "").trim();
  if (idempotencyKey.length < 8 || idempotencyKey.length > 200) {
    throw new C03AccessError("Public incident intake requires a bounded idempotency key", 400);
  }

  const qrProof = normalizeCode(payload.qrCodeValue);
  const incidentType = incidentTypeMap[payload.incidentType];
  const contact = normalizeCustomerContact(payload);
  const locationLat = typeof payload.locationLat === "number" ? payload.locationLat : null;
  const locationLng = typeof payload.locationLng === "number" ? payload.locationLng : null;
  const location = await reverseGeocode(locationLat, locationLng);
  const prepared = {
    incidentType,
    description: cleanText(payload.description, 2000),
    ...contact,
    purchasePlace: cleanText(payload.purchasePlace, 240) || null,
    purchaseDate: toDateOrNull(payload.purchaseDate),
    productBatchNo: cleanText(payload.productBatchNo, 120) || null,
    locationLat,
    locationLng,
    locationName: location?.name || null,
    locationCountry: location?.country || null,
    locationRegion: location?.region || null,
    locationCity: location?.city || null,
    photos: (payload.photoUrls || []).map((value) => cleanText(value, 1000)).filter(Boolean).slice(0, 8),
    tags: sanitizeTags(payload.tags),
    ipHash: sha256Hash(actor.ipAddress),
    userAgentHash: sha256Hash(actor.userAgent),
    deviceFingerprintHash: deviceFingerprintFromRequest(actor.ipAddress, actor.userAgent, actor.deviceFingerprint),
  };

  return withC03PreAuthTransaction(requestId, "public-incident-intake", async (tx) => {
    const suspectedSpam = await computeSpamSignal(tx, qrProof, {
      email: contact.customerEmail,
      phone: contact.customerPhone,
    });
    const severity = await computeSeverity(tx, qrProof, { incidentType, locationLat, locationLng });
    return createPublicIncidentReportInTransaction<any>(tx, {
      qrProof,
      report: { ...prepared, suspectedSpam, severity },
      uploads: uploads.map((upload) => ({
        fileUrl: cleanText(upload.fileUrl, 1000) || null,
        storageKey: cleanText(upload.storageKey, 1000) || null,
        fileType: cleanText(upload.fileType, 160) || null,
      })),
      idempotencyKey,
    });
  });
};

export const getIncidentByIdScoped = async (
  incidentId: string,
  _actor: { role: UserRole; userId?: string | null; licenseeId?: string | null; linkedLicenseeIds?: string[] | null },
  db?: IncidentTransaction
) => getIncidentDetailInTransaction<any>(requireIncidentTransaction(db), incidentId);

export const listIncidentsScoped = async (input: {
  role: UserRole;
  actorUserId?: string | null;
  actorLicenseeId?: string | null;
  linkedLicenseeIds?: string[] | null;
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
}, db?: IncidentTransaction) =>
  listIncidentsInTransaction<{ rows: any[]; total: number }>(requireIncidentTransaction(db), {
    filters: {
      status: input.filters.status,
      severity: input.filters.severity,
      qr: cleanText(input.filters.qr, 128) || undefined,
      search: cleanText(input.filters.search, 120) || undefined,
      dateFrom: input.filters.dateFrom?.toISOString(),
      dateTo: input.filters.dateTo?.toISOString(),
      assignedTo: input.filters.assignedTo,
    },
    limit: input.filters.limit,
    offset: input.filters.offset,
  });

export const sanitizeResolutionOutcome = (value?: string | null): IncidentResolutionOutcome | null => {
  const normalized = String(value || "").toUpperCase();
  return Object.values(IncidentResolutionOutcome).includes(normalized as IncidentResolutionOutcome)
    ? normalized as IncidentResolutionOutcome
    : null;
};

export const sanitizeIncidentStatus = (value?: string | null): IncidentStatus | null => {
  const normalized = String(value || "").toUpperCase();
  return Object.values(IncidentStatus).includes(normalized as IncidentStatus) ? normalized as IncidentStatus : null;
};

export const sanitizeIncidentSeverity = (value?: string | null): IncidentSeverity | null => {
  const normalized = String(value || "").toUpperCase();
  return Object.values(IncidentSeverity).includes(normalized as IncidentSeverity) ? normalized as IncidentSeverity : null;
};

export const toHumanIncidentType = (type: IncidentType) => ({
  COUNTERFEIT_SUSPECTED: "Counterfeit suspected",
  DUPLICATE_SCAN: "Duplicate scan",
  TAMPERED_LABEL: "Tampered label",
  WRONG_PRODUCT: "Wrong product",
  OTHER: "Other",
}[type] || type);

export const toHumanIncidentSeverity = (severity: IncidentSeverity) => ({
  LOW: "Low",
  MEDIUM: "Medium",
  HIGH: "High",
  CRITICAL: "Critical",
}[severity] || severity);

export const toHumanIncidentStatus = (status: IncidentStatus) => ({
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
}[status] || status);

export const buildIncidentAdminUrl = (incidentId: string) => {
  const base = String(process.env.PUBLIC_ADMIN_WEB_BASE_URL || process.env.PUBLIC_VERIFY_WEB_BASE_URL || "http://localhost:8080").trim();
  return `${base.replace(/\/+$/, "")}/incidents?incidentId=${encodeURIComponent(incidentId)}`;
};
