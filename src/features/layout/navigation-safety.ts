import { APP_PATHS } from "@/app/route-metadata";
import type { DashboardNotification } from "@/features/layout/components/NotificationsDropdown";

export const NOTIFICATION_FETCH_LIMIT = 24;

export const sidebarGroupOrder = ["Command", "Lifecycle", "Review", "Evidence", "Governance", "Settings"] as const;

const INTERNAL_ROUTE_PREFIXES = [
  APP_PATHS.dashboard,
  APP_PATHS.batches,
  APP_PATHS.scanActivity,
  APP_PATHS.auditHistory,
  APP_PATHS.settings,
  APP_PATHS.verify,
  APP_PATHS.support,
  APP_PATHS.incidentResponse,
  APP_PATHS.licensees,
  APP_PATHS.codeRequests,
  APP_PATHS.manufacturers,
  APP_PATHS.releaseReadiness,
  APP_PATHS.printerSetup,
  APP_PATHS.connectorDownload,
] as const;

export const isSafeInternalRoute = (value: unknown) => {
  const route = typeof value === "string" ? value.trim() : "";
  if (!route || !route.startsWith("/") || route.startsWith("//") || route.includes("://") || route.includes("\\")) {
    return false;
  }

  return INTERNAL_ROUTE_PREFIXES.some((prefix) => route === prefix || route.startsWith(`${prefix}/`) || route.startsWith(`${prefix}?`));
};

export const resolveNotificationTarget = (notification: DashboardNotification) => {
  const data =
    notification?.data && typeof notification.data === "object"
      ? (notification.data as Record<string, unknown>)
      : {};

  if (isSafeInternalRoute(data.targetRoute)) return String(data.targetRoute).trim();
  if (data.ticketId) return `${APP_PATHS.support}?ticketId=${encodeURIComponent(String(data.ticketId))}`;
  if (data.ticketReference) return `${APP_PATHS.support}?reference=${encodeURIComponent(String(data.ticketReference))}`;
  if (notification?.incidentId) return `${APP_PATHS.incidentResponse}?incidentId=${encodeURIComponent(String(notification.incidentId))}`;
  return APP_PATHS.dashboard;
};

export const resolveWorkspaceLabel = (user?: {
  role?: string | null;
  licensee?: { brandName?: string | null; name?: string | null } | null;
} | null) => {
  if (user?.role === "manufacturer") return user.licensee?.brandName || user.licensee?.name || "Manufacturer workspace";
  if (user?.role === "licensee_admin") return user.licensee?.brandName || user.licensee?.name || "Licensee workspace";
  return "Platform operations";
};
