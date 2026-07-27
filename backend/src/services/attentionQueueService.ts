import {
  Prisma,
  UserRole,
} from "@prisma/client";

import { AuthRequest } from "../middleware/auth";
import { getEffectiveLicenseeId } from "../middleware/tenantIsolation";
import { readAttentionQueueProjection } from "../rls-waves/session-b/b03/repositoryFunctions";
import { b03BoundaryForRequest } from "../rls-waves/session-b/b03/requestBoundary";
import { isManufacturerRole, resolveAccessibleLicenseeIdsForUser } from "./manufacturerScopeService";
import { listNotificationsForUser } from "./notificationService";
import { getOrComputeVersionedCache } from "./versionedCacheService";
import { readPrintingProjection } from "../rls-waves/session-c/c02/printingLifecycleRepository";

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

const attentionQueueScopeKey = (req: AuthRequest) =>
  [
    req.user?.role || "anonymous",
    req.user?.userId || "none",
    req.user?.licenseeId || "none",
    req.user?.orgId || "none",
    getEffectiveLicenseeId(req) || "all",
  ].join(":");

const getAttentionQueueSnapshotUncached = async (req: AuthRequest): Promise<AttentionQueueSnapshot> => {
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
    databaseBoundary: b03BoundaryForRequest(req, "notification-list"),
  });

  const attentionBoundary = b03BoundaryForRequest(req, "attention-queue");
  const attentionPromise = attentionBoundary.run((db) => readAttentionQueueProjection(db, {
    licenseeId: getEffectiveLicenseeId(req),
    since,
    requestId: attentionBoundary.requestId,
  }));
  const printingAttentionPromise = readPrintingProjection({
    capability: String(req.databaseSessionCapability || ""),
    requestId: String((req as AuthRequest & { requestId?: string }).requestId || ""),
    operation: "ATTENTION_QUEUE",
    subjectId: "00000000-0000-4000-8000-000000000000",
    options: { licenseeId: getEffectiveLicenseeId(req) || null },
  });

  const [
    notifications,
    attention,
    printingAttention,
  ] = await Promise.all([
    notificationPromise,
    attentionPromise,
    printingAttentionPromise,
  ]);

  const { count: incidentCount, latest: latestIncident } = attention.incidents;
  const { count: policyAlertCount, latest: latestPolicyAlert } = attention.policyAlerts;
  const { count: supportTicketCount, latest: latestSupportTicket } = attention.supportTickets;
  const { count: auditEvents24h, latest: latestAuditEvent } = attention.auditEvents;
  const printJobCount = Number(printingAttention?.count || 0);
  const latestPrintJob = printingAttention?.latest || null;
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
      createdAt: firstIso(latestIncident.createdAt),
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
      createdAt: firstIso(latestPolicyAlert.createdAt),
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
      createdAt: firstIso(latestPrintJob.updatedAt),
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
      createdAt: firstIso(latestSupportTicket.updatedAt),
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
      createdAt: firstIso(latestAuditEvent.createdAt),
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

export const getAttentionQueueSnapshot = async (req: AuthRequest): Promise<AttentionQueueSnapshot> =>
  getOrComputeVersionedCache("attention-queue", attentionQueueScopeKey(req), 20, () =>
    getAttentionQueueSnapshotUncached(req)
  );
