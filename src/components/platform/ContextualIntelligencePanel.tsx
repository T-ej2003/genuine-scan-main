import { Link } from "react-router-dom";
import { AlertTriangle, ArrowRight, Bell, FileCheck2, Printer, ScanEye, ShieldCheck } from "lucide-react";

import { APP_PATHS, getAppRouteLabel, getRoleDisplayLabel } from "@/app/route-metadata";
import { AuditTimeline } from "@/components/mscqr/audit-timeline";
import { LabelLifecycleRail } from "@/components/mscqr/lifecycle";
import { MotionPanel } from "@/components/mscqr/motion";
import { PrintStateIndicator, RiskSignal, StatusBadge } from "@/components/mscqr/status";
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

const lifecycleSteps = [
  { label: "01", title: "Issue", body: "Codes are created as governed records.", state: "complete" as const },
  { label: "02", title: "Assign", body: "Inventory is scoped to the authorized operator.", state: "complete" as const },
  { label: "03", title: "Print", body: "Print state is confirmed before customer trust.", state: "current" as const },
  { label: "04", title: "Verify", body: "Public checks resolve against label state.", state: "pending" as const },
  { label: "05", title: "Review", body: "Duplicates and anomalies stay reviewable.", state: "pending" as const },
];

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
  const auditEvents24h = queueSummary?.auditEvents24h ?? 0;
  const riskLevel = reviewSignals > 0 || supportEscalations > 0 ? "watch" : effectiveUnread > 0 ? "watch" : "low";

  return (
    <MotionPanel
      className={cn(
        "rounded-[1.7rem] border border-mscqr-border bg-mscqr-surface/88 p-4 shadow-[0_18px_55px_rgba(2,6,23,0.08)] backdrop-blur",
        "dark:shadow-[0_22px_70px_rgba(0,0,0,0.38)]",
        className,
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="font-mono text-[11px] uppercase tracking-[0.22em] text-mscqr-accent">Context</p>
          <h2 className="mt-2 text-lg font-semibold text-mscqr-primary">{routeLabel}</h2>
          <p className="mt-1 text-sm leading-6 text-mscqr-secondary">{getRoleDisplayLabel(role)} operating boundary</p>
        </div>
        <StatusBadge tone={notificationsLive ? "verified" : "degraded"}>{notificationsLive ? "Live signals" : "Periodic refresh"}</StatusBadge>
      </div>

      <div className="mt-5 grid gap-3">
        <div className="rounded-2xl border border-mscqr-border bg-mscqr-surface-elevated p-4">
          <div className="flex items-center gap-3">
            <div className="flex size-10 items-center justify-center rounded-2xl border border-mscqr-border bg-mscqr-accent-soft/50 text-mscqr-accent">
              <Bell className="size-4" />
            </div>
            <div className="min-w-0">
              <p className="text-sm font-semibold text-mscqr-primary">Attention queue</p>
              <p className="text-sm text-mscqr-secondary">
                {attentionQueueLoading
                  ? "Resolving live queue..."
                  : effectiveUnread > 0
                    ? `${effectiveUnread} unread operational signal${effectiveUnread === 1 ? "" : "s"}.`
                    : "No unread operational signals."}
              </p>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-2">
          {[
            ["Review", reviewSignals],
            ["Print", printOperations],
            ["Support", supportEscalations],
            ["Audit 24h", auditEvents24h],
          ].map(([label, value]) => (
            <div key={label} className="rounded-2xl border border-mscqr-border bg-mscqr-surface-elevated p-3">
              <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-mscqr-muted">{label}</p>
              <p className="mt-2 text-xl font-semibold text-mscqr-primary">{Number(value).toLocaleString()}</p>
            </div>
          ))}
        </div>

        {printer?.visible ? (
          <button
            type="button"
            onClick={printer.onOpen}
            className="rounded-2xl border border-mscqr-border bg-mscqr-surface-elevated p-4 text-left transition hover:border-mscqr-accent/45 hover:bg-mscqr-surface-muted/70 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-mscqr-accent"
            title={printer.title}
          >
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <div className="flex size-10 items-center justify-center rounded-2xl border border-mscqr-border bg-mscqr-surface-muted text-mscqr-primary">
                  <Printer className="size-4" />
                </div>
                <div>
                  <p className="text-sm font-semibold text-mscqr-primary">Controlled print</p>
                  <p className="text-sm text-mscqr-secondary">{printer.title}</p>
                </div>
              </div>
              <PrintStateIndicator value={printer.ready ? "PRINT_CONFIRMED" : printer.degraded ? "FAILED" : "PENDING"} label={printer.modeLabel} />
            </div>
          </button>
        ) : null}

        <RiskSignal
          level={riskLevel}
          label={reviewSignals > 0 ? "Review signals waiting" : "No active review signal"}
          detail="Signals are scoped to your role and point back to the source workspace for any operator action."
        />
      </div>

      {attentionQueue?.items.length ? (
        <div className="mt-6 rounded-2xl border border-mscqr-border bg-mscqr-surface-elevated p-4">
          <p className="mb-3 text-sm font-semibold text-mscqr-primary">Attention queue</p>
          <div className="space-y-2">
            {attentionQueue.items.slice(0, 4).map((item) => (
              <Link
                key={`${item.type}-${item.id}`}
                to={safePanelRoute(item.route)}
                className="block rounded-2xl border border-mscqr-border bg-mscqr-surface px-3 py-3 transition hover:border-mscqr-accent/40 hover:bg-mscqr-surface-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-mscqr-accent"
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

      <div className="mt-6">
        <p className="mb-3 flex items-center gap-2 text-sm font-semibold text-mscqr-primary">
          <ScanEye className="size-4 text-mscqr-accent" />
          Label lifecycle lens
        </p>
        <LabelLifecycleRail steps={lifecycleSteps} compact />
      </div>

      <div className="mt-6 rounded-2xl border border-mscqr-border bg-mscqr-surface-elevated p-4">
        <p className="mb-3 flex items-center gap-2 text-sm font-semibold text-mscqr-primary">
          <FileCheck2 className="size-4 text-mscqr-audit" />
          Audit posture
        </p>
        <AuditTimeline
          items={[
            { label: "Current workspace", value: routeLabel, tone: "audit" },
            { label: "Access boundary", value: getRoleDisplayLabel(role), tone: "verified" },
            { label: "Action model", meta: "Review and mutation actions stay inside their source workspace.", tone: "neutral" },
          ]}
        />
      </div>

      <div className="mt-5 grid gap-2">
        <Button asChild variant="outline" className="justify-between">
          <Link to={APP_PATHS.scanActivity}>
            Verification activity <ArrowRight className="size-4" />
          </Link>
        </Button>
        <Button asChild variant="ghost" className="justify-between">
          <Link to={APP_PATHS.auditHistory}>
            Audit evidence <ShieldCheck className="size-4" />
          </Link>
        </Button>
        {effectiveUnread > 0 ? (
          <p className="flex items-start gap-2 rounded-2xl border border-mscqr-review/30 bg-mscqr-review/10 p-3 text-xs leading-5 text-mscqr-secondary">
            <AlertTriangle className="mt-0.5 size-4 shrink-0 text-mscqr-review" />
            Review notifications in the topbar before changing label, batch, or print state.
          </p>
        ) : null}
      </div>
    </MotionPanel>
  );
}
