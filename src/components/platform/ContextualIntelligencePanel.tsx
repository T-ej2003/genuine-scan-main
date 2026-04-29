import { Link } from "react-router-dom";
import { ArrowRight, Bell, CircleHelp, Printer, ScanEye } from "lucide-react";

import { APP_PATHS, getAppRouteLabel, getRoleDisplayLabel } from "@/app/route-metadata";
import { StatusBadge } from "@/components/mscqr/status";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import type { UserRole } from "@/types";

export type ContextualPrinterSummary = {
  visible: boolean;
  modeLabel: string;
  title: string;
  ready: boolean;
  degraded: boolean;
  onOpen: () => void;
};

type ContextualIntelligencePanelProps = {
  pathname: string;
  role?: UserRole | null;
  unreadCount: number;
  notificationsLive: boolean;
  printer?: ContextualPrinterSummary;
  attentionQueue?: {
    generatedAt: string;
    summary: {
      unreadNotifications: number;
      reviewSignals: number;
      printOperations: number;
      supportEscalations: number;
      auditEvents24h: number;
    };
    items: Array<{
      id: string;
      type: string;
      title: string;
      body: string;
      tone: "neutral" | "verified" | "review" | "blocked" | "audit" | "support" | "print";
      route: string;
      createdAt?: string | null;
      count?: number;
    }>;
  } | null;
  attentionQueueLoading?: boolean;
  className?: string;
};

const PANEL_ROUTE_PREFIXES = [
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
];

const safePanelRoute = (value: string) => {
  const route = value.trim();
  if (!route || !route.startsWith("/") || route.startsWith("//") || route.includes("://") || route.includes("\\")) {
    return APP_PATHS.dashboard;
  }
  return PANEL_ROUTE_PREFIXES.some((prefix) => route === prefix || route.startsWith(`${prefix}/`) || route.startsWith(`${prefix}?`))
    ? route
    : APP_PATHS.dashboard;
};

export function ContextualIntelligencePanel({
  pathname,
  role,
  unreadCount,
  notificationsLive,
  printer,
  attentionQueue,
  attentionQueueLoading = false,
  className,
}: ContextualIntelligencePanelProps) {
  const routeLabel = getAppRouteLabel(pathname, role) || "Workspace";
  const queueSummary = attentionQueue?.summary;
  const effectiveUnread = queueSummary?.unreadNotifications ?? unreadCount;
  const reviewSignals = queueSummary?.reviewSignals ?? 0;
  const printOperations = queueSummary?.printOperations ?? 0;
  const supportEscalations = queueSummary?.supportEscalations ?? 0;
  const historyEvents24h = queueSummary?.auditEvents24h ?? 0;

  return (
    <section
      className={cn(
        "rounded-[1.5rem] border border-mscqr-border bg-white p-4 shadow-sm",
        className,
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-mscqr-primary">Workspace activity</h2>
          <p className="mt-1 text-sm leading-6 text-mscqr-secondary">
            {routeLabel} · {getRoleDisplayLabel(role)}
          </p>
        </div>
        <StatusBadge tone={notificationsLive ? "verified" : "issued"}>
          {notificationsLive ? "Updated just now" : "Refreshes regularly"}
        </StatusBadge>
      </div>

      <div className="mt-5 grid gap-3">
        <div className="rounded-2xl border border-mscqr-border bg-mscqr-surface-muted/50 p-4">
          <div className="flex items-center gap-3">
            <div className="flex size-10 items-center justify-center rounded-2xl border border-mscqr-border bg-white text-mscqr-accent">
              <Bell className="size-4" />
            </div>
            <div className="min-w-0">
              <p className="text-sm font-semibold text-mscqr-primary">Today’s updates</p>
              <p className="text-sm text-mscqr-secondary">
                {attentionQueueLoading
                  ? "Checking workspace updates..."
                  : effectiveUnread > 0
                    ? `${effectiveUnread} unread update${effectiveUnread === 1 ? "" : "s"}.`
                    : "No unread updates."}
              </p>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-2">
          {[
            ["Scans to review", reviewSignals],
            ["Printing", printOperations],
            ["Issues", supportEscalations],
            ["History", historyEvents24h],
          ].map(([label, value]) => (
            <div key={label} className="rounded-2xl border border-mscqr-border bg-white p-3">
              <p className="text-xs font-medium text-mscqr-secondary">{label}</p>
              <p className="mt-2 text-xl font-semibold text-mscqr-primary">{Number(value).toLocaleString()}</p>
            </div>
          ))}
        </div>

        {printer?.visible ? (
          <button
            type="button"
            onClick={printer.onOpen}
            className="rounded-2xl border border-mscqr-border bg-white p-4 text-left transition hover:border-mscqr-accent/45 hover:bg-mscqr-surface-muted/70 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-mscqr-accent/35"
            title={printer.title}
          >
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <div className="flex size-10 items-center justify-center rounded-2xl border border-mscqr-border bg-mscqr-surface-muted text-mscqr-accent">
                  <Printer className="size-4" />
                </div>
                <div>
                  <p className="text-sm font-semibold text-mscqr-primary">Printing</p>
                  <p className="text-sm text-mscqr-secondary">{printer.title}</p>
                </div>
              </div>
              <StatusBadge tone={printer.ready ? "verified" : printer.degraded ? "review" : "issued"}>{printer.modeLabel}</StatusBadge>
            </div>
          </button>
        ) : null}
      </div>

      {attentionQueue?.items.length ? (
        <div className="mt-6 rounded-2xl border border-mscqr-border bg-mscqr-surface-muted/45 p-4">
          <p className="mb-3 text-sm font-semibold text-mscqr-primary">Recent updates</p>
          <div className="space-y-2">
            {attentionQueue.items.slice(0, 4).map((item) => (
              <Link
                key={`${item.type}-${item.id}`}
                to={safePanelRoute(item.route)}
                className="block rounded-2xl border border-mscqr-border bg-white px-3 py-3 transition hover:border-mscqr-accent/40 hover:bg-mscqr-surface-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-mscqr-accent/35"
              >
                <div className="flex items-start justify-between gap-3">
                  <p className="text-sm font-semibold text-mscqr-primary">{item.title}</p>
                  {item.count != null ? <span className="rounded-full bg-mscqr-surface-muted px-2 py-0.5 text-xs text-mscqr-secondary">{item.count}</span> : null}
                </div>
                <p className="mt-1 line-clamp-2 text-xs leading-5 text-mscqr-secondary">{item.body}</p>
              </Link>
            ))}
          </div>
        </div>
      ) : null}

      <div className="mt-5 grid gap-2">
        <Button asChild variant="outline" className="justify-between">
          <Link to={APP_PATHS.scanActivity}>
            Open scans <ScanEye className="size-4" />
          </Link>
        </Button>
        <Button asChild variant="ghost" className="justify-between">
          <Link to={APP_PATHS.auditHistory}>
            Open history <ArrowRight className="size-4" />
          </Link>
        </Button>
        <p className="flex items-start gap-2 rounded-2xl border border-mscqr-border bg-mscqr-surface-muted/45 p-3 text-xs leading-5 text-mscqr-secondary">
          <CircleHelp className="mt-0.5 size-4 shrink-0 text-mscqr-accent" />
          Updates shown here are limited to pages your role can open.
        </p>
      </div>
    </section>
  );
}
