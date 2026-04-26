import {
  IncidentStatus,
  Prisma,
  PrintJobStatus,
  PrintPipelineState,
  SupportTicketStatus,
  UserRole,
} from "@prisma/client";

import prisma from "../config/database";
import { AuthRequest } from "../middleware/auth";
import { getEffectiveLicenseeId } from "../middleware/tenantIsolation";
import { isManufacturerRole, resolveAccessibleLicenseeIdsForUser } from "./manufacturerScopeService";
import { listNotificationsForUser } from "./notificationService";

export type AttentionQueueItemTone = "neutral" | "verified" | "review" | "blocked" | "audit" | "support" | "print";

export type AttentionQueueItem = {
  id: string;
  type: "notification" | "incident" | "policy_alert" | "print_job" | "support_ticket" | "audit_event";
  title: string;
  body: string;
  tone: AttentionQueueItemTone;
  route: string;
  createdAt?: string | null;
  count?: number;
};

export type AttentionQueueSnapshot = {
  generatedAt: string;
  summary: {
    unreadNotifications: number;
    reviewSignals: number;
    printOperations: number;
    supportEscalations: number;
    auditEvents24h: number;
  };
  items: AttentionQueueItem[];
};

const OPEN_INCIDENT_STATUSES = [
  IncidentStatus.NEW,
  IncidentStatus.TRIAGED,
  IncidentStatus.TRIAGE,
  IncidentStatus.INVESTIGATING,
  IncidentStatus.CONTAINMENT,
  IncidentStatus.ERADICATION,
  IncidentStatus.RECOVERY,
  IncidentStatus.AWAITING_CUSTOMER,
  IncidentStatus.AWAITING_LICENSEE,
  IncidentStatus.REOPENED,
];

const ACTIVE_PRINT_STATUSES = [PrintJobStatus.PENDING, PrintJobStatus.SENT];
const ACTIVE_PRINT_PIPELINE_STATES = [
  PrintPipelineState.QUEUED,
  PrintPipelineState.PREFLIGHT_OK,
  PrintPipelineState.SENT_TO_PRINTER,
  PrintPipelineState.PRINTER_ACKNOWLEDGED,
  PrintPipelineState.NEEDS_OPERATOR_ACTION,
];

const OPEN_SUPPORT_STATUSES = [
  SupportTicketStatus.OPEN,
  SupportTicketStatus.IN_PROGRESS,
  SupportTicketStatus.WAITING_CUSTOMER,
];

const isPlatformRole = (role: UserRole) => role === UserRole.SUPER_ADMIN || role === UserRole.PLATFORM_SUPER_ADMIN;
const isLicenseeAdminRole = (role: UserRole) => role === UserRole.LICENSEE_ADMIN || role === UserRole.ORG_ADMIN;

const ADMIN_ROUTE_PREFIXES = ["/dashboard", "/batches", "/scan-activity", "/audit-history", "/settings", "/verify"];
const PLATFORM_ROUTE_PREFIXES = [
  ...ADMIN_ROUTE_PREFIXES,
  "/licensees",
  "/code-requests",
  "/manufacturers",
  "/incident-response",
  "/support",
  "/governance",
  "/release-readiness",
];
const LICENSEE_ROUTE_PREFIXES = [...ADMIN_ROUTE_PREFIXES, "/code-requests", "/manufacturers"];
const MANUFACTURER_ROUTE_PREFIXES = [...ADMIN_ROUTE_PREFIXES, "/printer-setup", "/connector-download"];

const routeMatchesPrefix = (route: string, prefix: string) => route === prefix || route.startsWith(`${prefix}/`) || route.startsWith(`${prefix}?`);

const safeRouteForRole = (value: unknown, role: UserRole, fallback = "/dashboard") => {
  const route = typeof value === "string" ? value.trim() : "";
  if (!route || !route.startsWith("/") || route.startsWith("//") || route.includes("://") || route.includes("\\")) {
    return fallback;
  }

  const allowedPrefixes = isPlatformRole(role)
    ? PLATFORM_ROUTE_PREFIXES
    : isLicenseeAdminRole(role)
      ? LICENSEE_ROUTE_PREFIXES
      : isManufacturerRole(role)
        ? MANUFACTURER_ROUTE_PREFIXES
        : ADMIN_ROUTE_PREFIXES;

  return allowedPrefixes.some((prefix) => routeMatchesPrefix(route, prefix)) ? route : fallback;
};

const humanizeEnum = (value?: string | null) =>
  String(value || "")
    .toLowerCase()
    .split("_")
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ") || "Unknown";

const buildIncidentWhere = (req: AuthRequest): Prisma.IncidentWhereInput => {
  const role = req.user?.role;
  const scopedLicenseeId = getEffectiveLicenseeId(req);
  const where: Prisma.IncidentWhereInput = { status: { in: OPEN_INCIDENT_STATUSES } };

  if (!role || isPlatformRole(role)) {
    if (scopedLicenseeId) where.licenseeId = scopedLicenseeId;
    return where;
  }

  if (isManufacturerRole(role)) {
    where.OR = [
      { qrCode: { batch: { manufacturerId: req.user?.userId } } },
      { scanEvent: { batch: { manufacturerId: req.user?.userId } } },
    ];
    return where;
  }

  if (isLicenseeAdminRole(role) && scopedLicenseeId) where.licenseeId = scopedLicenseeId;
  return where;
};

const buildPolicyAlertWhere = (req: AuthRequest): Prisma.PolicyAlertWhereInput => {
  const role = req.user?.role;
  const scopedLicenseeId = getEffectiveLicenseeId(req);
  const where: Prisma.PolicyAlertWhereInput = { acknowledgedAt: null };

  if (!role || isPlatformRole(role)) {
    if (scopedLicenseeId) where.licenseeId = scopedLicenseeId;
    return where;
  }

  if (isManufacturerRole(role)) {
    where.manufacturerId = req.user?.userId;
    return where;
  }

  if (isLicenseeAdminRole(role) && scopedLicenseeId) where.licenseeId = scopedLicenseeId;
  return where;
};

const buildPrintJobWhere = (req: AuthRequest): Prisma.PrintJobWhereInput => {
  const role = req.user?.role;
  const scopedLicenseeId = getEffectiveLicenseeId(req);
  const where: Prisma.PrintJobWhereInput = {
    OR: [{ status: { in: ACTIVE_PRINT_STATUSES } }, { pipelineState: { in: ACTIVE_PRINT_PIPELINE_STATES } }],
  };

  if (!role || isPlatformRole(role)) {
    if (scopedLicenseeId) where.batch = { licenseeId: scopedLicenseeId };
    return where;
  }

  if (isManufacturerRole(role)) {
    where.manufacturerId = req.user?.userId;
    return where;
  }

  if (isLicenseeAdminRole(role) && scopedLicenseeId) where.batch = { licenseeId: scopedLicenseeId };
  return where;
};

const buildSupportTicketWhere = (req: AuthRequest): Prisma.SupportTicketWhereInput => {
  const role = req.user?.role;
  const scopedLicenseeId = getEffectiveLicenseeId(req);
  const where: Prisma.SupportTicketWhereInput = { status: { in: OPEN_SUPPORT_STATUSES } };

  if (!role || !isPlatformRole(role)) {
    return { ...where, id: "__no_support_ticket_scope__" };
  }

  if (!role || isPlatformRole(role)) {
    if (scopedLicenseeId) where.licenseeId = scopedLicenseeId;
    return where;
  }
  return where;
};

const buildAuditWhere = (req: AuthRequest, since: Date): Prisma.AuditLogWhereInput => {
  const role = req.user?.role;
  const scopedLicenseeId = getEffectiveLicenseeId(req);
  const where: Prisma.AuditLogWhereInput = { createdAt: { gte: since } };

  if (!role || isPlatformRole(role)) {
    if (scopedLicenseeId) where.licenseeId = scopedLicenseeId;
    return where;
  }

  if (isManufacturerRole(role)) where.userId = req.user?.userId;
  if (isLicenseeAdminRole(role) && scopedLicenseeId) where.licenseeId = scopedLicenseeId;
  return where;
};

const firstIso = (value?: Date | string | null) => {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isFinite(date.getTime()) ? date.toISOString() : null;
};

const notificationRoute = (data: Prisma.JsonValue | null | undefined, role: UserRole) => {
  if (!data || typeof data !== "object" || Array.isArray(data)) return "/dashboard";
  const route = data.targetRoute;
  return safeRouteForRole(route, role);
};

export const getAttentionQueueSnapshot = async (req: AuthRequest): Promise<AttentionQueueSnapshot> => {
  if (!req.user) throw new Error("Not authenticated");

  const canOpenIncidentRoute = isPlatformRole(req.user.role);
  const licenseeIds = await resolveAccessibleLicenseeIdsForUser(req.user);
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000);

  const notificationPromise = listNotificationsForUser({
    userId: req.user.userId,
    role: req.user.role,
    licenseeId: req.user.licenseeId,
    licenseeIds,
    orgId: req.user.orgId,
    limit: 5,
    offset: 0,
    unreadOnly: true,
  });

  const incidentWhere = buildIncidentWhere(req);
  const policyAlertWhere = buildPolicyAlertWhere(req);
  const printJobWhere = buildPrintJobWhere(req);
  const supportTicketWhere = buildSupportTicketWhere(req);
  const auditWhere = buildAuditWhere(req, since);

  const [
    notifications,
    incidentCount,
    policyAlertCount,
    printJobCount,
    supportTicketCount,
    auditEvents24h,
    latestIncident,
    latestPolicyAlert,
    latestPrintJob,
    latestSupportTicket,
    latestAuditEvent,
  ] = await Promise.all([
    notificationPromise,
    prisma.incident.count({ where: incidentWhere }),
    prisma.policyAlert.count({ where: policyAlertWhere }),
    prisma.printJob.count({ where: printJobWhere }),
    prisma.supportTicket.count({ where: supportTicketWhere }),
    prisma.auditLog.count({ where: auditWhere }),
    prisma.incident.findFirst({
      where: incidentWhere,
      orderBy: { createdAt: "desc" },
      select: { id: true, qrCodeValue: true, severity: true, status: true, createdAt: true },
    }),
    prisma.policyAlert.findFirst({
      where: policyAlertWhere,
      orderBy: { createdAt: "desc" },
      select: { id: true, alertType: true, severity: true, message: true, createdAt: true },
    }),
    prisma.printJob.findFirst({
      where: printJobWhere,
      orderBy: { updatedAt: "desc" },
      select: { id: true, jobNumber: true, status: true, pipelineState: true, updatedAt: true },
    }),
    prisma.supportTicket.findFirst({
      where: supportTicketWhere,
      orderBy: { updatedAt: "desc" },
      select: { id: true, referenceCode: true, status: true, priority: true, updatedAt: true },
    }),
    prisma.auditLog.findFirst({
      where: auditWhere,
      orderBy: { createdAt: "desc" },
      select: { id: true, action: true, entityType: true, entityId: true, createdAt: true },
    }),
  ]);

  const items: AttentionQueueItem[] = [];
  const firstNotification = notifications.notifications[0];
  if (firstNotification) {
    items.push({
      id: firstNotification.id,
      type: "notification",
      title: firstNotification.title,
      body: firstNotification.body,
      tone: "neutral",
      route: notificationRoute(firstNotification.data, req.user.role),
      createdAt: firstIso(firstNotification.createdAt),
      count: notifications.unread,
    });
  }
  if (latestIncident) {
    items.push({
      id: latestIncident.id,
      type: "incident",
      title: `${incidentCount} open incident${incidentCount === 1 ? "" : "s"}`,
      body: `${humanizeEnum(latestIncident.severity)} severity signal for label ${latestIncident.qrCodeValue || "under review"}.`,
      tone: latestIncident.severity === "CRITICAL" || latestIncident.severity === "HIGH" ? "blocked" : "review",
      route: canOpenIncidentRoute ? `/incident-response?incidentId=${encodeURIComponent(latestIncident.id)}` : "/scan-activity",
      createdAt: latestIncident.createdAt.toISOString(),
      count: incidentCount,
    });
  }
  if (latestPolicyAlert) {
    items.push({
      id: latestPolicyAlert.id,
      type: "policy_alert",
      title: `${policyAlertCount} unacknowledged policy alert${policyAlertCount === 1 ? "" : "s"}`,
      body: latestPolicyAlert.message || `${humanizeEnum(latestPolicyAlert.alertType)} requires operator review.`,
      tone: latestPolicyAlert.severity === "CRITICAL" || latestPolicyAlert.severity === "HIGH" ? "blocked" : "review",
      route: canOpenIncidentRoute ? "/incident-response" : "/scan-activity",
      createdAt: latestPolicyAlert.createdAt.toISOString(),
      count: policyAlertCount,
    });
  }
  if (latestPrintJob) {
    items.push({
      id: latestPrintJob.id,
      type: "print_job",
      title: `${printJobCount} active print operation${printJobCount === 1 ? "" : "s"}`,
      body: `${latestPrintJob.jobNumber || "A print job"} is ${humanizeEnum(latestPrintJob.pipelineState || latestPrintJob.status)}.`,
      tone: latestPrintJob.pipelineState === "NEEDS_OPERATOR_ACTION" ? "review" : "print",
      route: "/batches",
      createdAt: latestPrintJob.updatedAt.toISOString(),
      count: printJobCount,
    });
  }
  if (latestSupportTicket) {
    items.push({
      id: latestSupportTicket.id,
      type: "support_ticket",
      title: `${supportTicketCount} open support escalation${supportTicketCount === 1 ? "" : "s"}`,
      body: `${latestSupportTicket.referenceCode} is ${humanizeEnum(latestSupportTicket.status)} with ${humanizeEnum(latestSupportTicket.priority)} priority.`,
      tone: "support",
      route: `/support?ticketId=${encodeURIComponent(latestSupportTicket.id)}`,
      createdAt: latestSupportTicket.updatedAt.toISOString(),
      count: supportTicketCount,
    });
  }
  if (latestAuditEvent) {
    items.push({
      id: latestAuditEvent.id,
      type: "audit_event",
      title: `${auditEvents24h} audit event${auditEvents24h === 1 ? "" : "s"} in 24h`,
      body: `${humanizeEnum(latestAuditEvent.action)} on ${humanizeEnum(latestAuditEvent.entityType)}${latestAuditEvent.entityId ? ` ${latestAuditEvent.entityId}` : ""}.`,
      tone: "audit",
      route: "/audit-history",
      createdAt: latestAuditEvent.createdAt.toISOString(),
      count: auditEvents24h,
    });
  }

  return {
    generatedAt: new Date().toISOString(),
    summary: {
      unreadNotifications: notifications.unread,
      reviewSignals: incidentCount + policyAlertCount,
      printOperations: printJobCount,
      supportEscalations: supportTicketCount,
      auditEvents24h,
    },
    items: items.slice(0, 6),
  };
};
