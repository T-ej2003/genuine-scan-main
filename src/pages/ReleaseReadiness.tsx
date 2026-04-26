import React, { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  AlertTriangle,
  CheckCircle2,
  FileBadge2,
  Gauge,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
} from "lucide-react";

import { APP_PATHS } from "@/app/route-metadata";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { useToast } from "@/hooks/use-toast";
import apiClient from "@/lib/api-client";

type ReleaseMetadata = {
  name: string;
  version: string;
  gitSha: string;
  environment: string;
  release: string;
  signing?: {
    mode: string;
    provider: string;
    keyVersion: string;
    keyRef?: string | null;
  } | null;
};

type RateLimitAnalytics = {
  generatedAt: string;
  totalEvents: number;
  uniqueOffenders: number;
  uniqueTenants: number;
  preAuthRate: number;
  familyTotals: Array<{ family: string; count: number }>;
  topLimitedRoutes: Array<{ route: string; family: string; count: number }>;
  repeatedOffenders: Array<{ offenderRef: string; offenderKind: string; count: number }>;
  tenantBurstAnomalies: Array<{ tenantRef: string; family: string; count: number; severity: string }>;
  exportAbusePatterns: Array<{ family: string; count: number; uniqueOffenders: number; uniqueTenants: number }>;
};

type RateLimitAlerts = RateLimitAnalytics & {
  alerts: Array<{ severity: "high" | "medium"; family: string; reason: string; count: number }>;
};

type ComplianceReport = {
  generatedAt?: string;
  scope?: { licenseeId?: string | null };
  metrics?: {
    incidents?: { resolved?: number; total?: number; slaBreachedOpen?: number };
    auditEvents?: number;
    failedLogins?: number;
  };
  compliance?: {
    securityAccess?: {
      passwordHandling?: string;
      roleBasedAccess?: string[];
    };
  };
  controlSummary?: Record<string, number>;
};

type CompliancePackJob = {
  id: string;
  status?: string;
  startedAt?: string | null;
  triggerType?: string | null;
};

type CompliancePackJobsPayload = {
  jobs?: CompliancePackJob[];
};

type RouteTelemetry = {
  verifyFunnel?: {
    dropped?: number;
    avgTransitionMs?: number;
  };
};

const toneClasses: Record<"healthy" | "warning" | "critical", string> = {
  healthy: "border-emerald-200 bg-emerald-50 text-emerald-900",
  warning: "border-amber-200 bg-amber-50 text-amber-900",
  critical: "border-red-200 bg-red-50 text-red-900",
};

const sectionCardClass = "rounded-2xl border border-slate-200 bg-white shadow-sm";

const formatWhen = (value?: string | null) => {
  if (!value) return "Not available";
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime())) return value;
  return parsed.toLocaleString();
};

const formatRouteForOperators = (value?: string | null) => {
  const route = String(value || "").trim();
  if (!route) return "No recent limiter events";
  if (/\/internal\/release\b/i.test(route)) return "Release metadata route";
  return route.replace(/^([A-Z]+)\s+/, "");
};

const renderHealthBadge = (tone: "healthy" | "warning" | "critical", label: string) => (
  <Badge className={`border ${toneClasses[tone]}`}>{label}</Badge>
);

export default function ReleaseReadiness() {
  const { toast } = useToast();
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [releaseMetadata, setReleaseMetadata] = useState<ReleaseMetadata | null>(null);
  const [compliance, setCompliance] = useState<ComplianceReport | null>(null);
  const [complianceJobs, setComplianceJobs] = useState<CompliancePackJob[]>([]);
  const [routeTelemetry, setRouteTelemetry] = useState<RouteTelemetry | null>(null);
  const [rateLimitAnalytics, setRateLimitAnalytics] = useState<RateLimitAnalytics | null>(null);
  const [rateLimitAlerts, setRateLimitAlerts] = useState<RateLimitAlerts | null>(null);
  const [loadIssues, setLoadIssues] = useState<string[]>([]);

  const latestComplianceJob = useMemo(() => complianceJobs[0] || null, [complianceJobs]);

  const loadAll = useCallback(
    async (showToast = false) => {
      setRefreshing(true);
      if (!showToast) setLoading(true);

      const failures: string[] = [];
      const [
        releaseRes,
        complianceRes,
        complianceJobsRes,
        telemetryRes,
        rateLimitAnalyticsRes,
        rateLimitAlertsRes,
      ] = await Promise.allSettled([
        apiClient.getInternalReleaseMetadata(),
        apiClient.getComplianceReport(),
        apiClient.getCompliancePackJobs({ limit: 10, offset: 0 }),
        apiClient.getRouteTransitionSummary(),
        apiClient.getRateLimitAnalytics({ windowMs: 60 * 60 * 1000 }),
        apiClient.getRateLimitAlerts({ windowMs: 60 * 60 * 1000 }),
      ]);

      if (releaseRes.status === "fulfilled" && releaseRes.value.success) {
        setReleaseMetadata((releaseRes.value.data || null) as ReleaseMetadata | null);
      } else {
        failures.push("release metadata");
      }

      if (complianceRes.status === "fulfilled" && complianceRes.value.success) {
        setCompliance(complianceRes.value.data || null);
      } else {
        failures.push("compliance summary");
      }

      if (complianceJobsRes.status === "fulfilled" && complianceJobsRes.value.success) {
        const jobs = (complianceJobsRes.value.data as CompliancePackJobsPayload | undefined)?.jobs;
        setComplianceJobs(Array.isArray(jobs) ? jobs : []);
      } else {
        failures.push("compliance pack jobs");
      }

      if (telemetryRes.status === "fulfilled" && telemetryRes.value.success) {
        setRouteTelemetry(telemetryRes.value.data || null);
      } else {
        failures.push("route telemetry");
      }

      if (rateLimitAnalyticsRes.status === "fulfilled" && rateLimitAnalyticsRes.value.success) {
        setRateLimitAnalytics((rateLimitAnalyticsRes.value.data || null) as RateLimitAnalytics | null);
      } else {
        failures.push("rate-limit analytics");
      }

      if (rateLimitAlertsRes.status === "fulfilled" && rateLimitAlertsRes.value.success) {
        setRateLimitAlerts((rateLimitAlertsRes.value.data || null) as RateLimitAlerts | null);
      } else {
        failures.push("rate-limit alerts");
      }

      setLoadIssues(failures);
      setLoading(false);
      setRefreshing(false);

      if (showToast) {
        if (failures.length > 0) {
          toast({
            title: "Release readiness refreshed with gaps",
            description: `Still missing: ${failures.join(", ")}.`,
            variant: "destructive",
          });
        } else {
          toast({
            title: "Release readiness refreshed",
            description: "Runtime release checks, evidence, and guardrails are current.",
          });
        }
      }
    },
    [toast]
  );

  useEffect(() => {
    void loadAll(false);
  }, [loadAll]);

  const releaseHealthTone: "healthy" | "warning" | "critical" = !releaseMetadata
    ? "critical"
    : releaseMetadata.signing?.keyVersion
      ? "healthy"
      : "warning";

  const alertTone: "healthy" | "warning" | "critical" =
    !rateLimitAlerts?.alerts?.length
      ? "healthy"
      : rateLimitAlerts.alerts.some((alert) => alert.severity === "high")
        ? "critical"
        : "warning";

  const evidenceTone: "healthy" | "warning" | "critical" =
    latestComplianceJob?.status === "COMPLETED"
      ? "healthy"
      : compliance
        ? "warning"
        : "critical";

  const actionItems = useMemo(() => {
    const items: Array<{ tone: "healthy" | "warning" | "critical"; title: string; body: string }> = [];

    if (!releaseMetadata) {
      items.push({
        tone: "critical",
        title: "Release metadata unavailable",
        body: "Release metadata is not returning build identity. Platform operators should treat release promotion as blocked until metadata is visible again.",
      });
    } else if (!releaseMetadata.signing?.keyVersion) {
      items.push({
        tone: "warning",
        title: "Signing profile needs verification",
        body: "Release metadata is present, but the signing profile does not expose a key version. Confirm the signer configuration before promoting the next release.",
      });
    }

    if (rateLimitAlerts?.alerts?.length) {
      items.push({
        tone: alertTone,
        title: `${rateLimitAlerts.alerts.length} active guardrail alert${rateLimitAlerts.alerts.length === 1 ? "" : "s"}`,
        body: `Top family: ${rateLimitAlerts.alerts[0]?.family}. Clear high-noise limiter families before broad rollout.`,
      });
    }

    if (!latestComplianceJob) {
      items.push({
        tone: "warning",
        title: "No recent compliance pack",
        body: "Generate a signed compliance pack so audit evidence is attached to the release window rather than reconstructed later.",
      });
    } else if (latestComplianceJob.status !== "COMPLETED") {
      items.push({
        tone: "warning",
        title: "Latest compliance pack is not complete",
        body: `Latest job ${latestComplianceJob.id} is ${latestComplianceJob.status}. Finish or rerun it before release approval.`,
      });
    }

    const attentionControls = compliance?.controlSummary?.ATTENTION || 0;
    if (attentionControls > 0) {
      items.push({
        tone: "warning",
        title: "Governance controls need attention",
        body: `${attentionControls} control area(s) are marked Attention in the current governance summary.`,
      });
    }

    const verifyFunnelDrops = routeTelemetry?.verifyFunnel?.dropped || 0;
    if (verifyFunnelDrops > 0) {
      items.push({
        tone: "warning",
        title: "Verify funnel drops detected",
        body: `${verifyFunnelDrops} route-transition drop(s) were recorded in the current telemetry window.`,
      });
    }

    if (items.length === 0) {
      items.push({
        tone: "healthy",
        title: "Release posture is aligned",
        body: "Release metadata, evidence, and guardrail telemetry are all in a healthy state for operator review.",
      });
    }

    return items;
  }, [alertTone, compliance?.controlSummary?.ATTENTION, latestComplianceJob, rateLimitAlerts?.alerts, releaseMetadata, routeTelemetry?.verifyFunnel?.dropped]);

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
          <div className="space-y-2">
            <div className="text-[11px] font-semibold uppercase tracking-[0.26em] text-slate-500">Super admin only</div>
            <h1 className="text-3xl font-semibold tracking-tight text-slate-950">Release readiness</h1>
            <p className="max-w-3xl text-sm leading-7 text-slate-600">
              One operator view for release identity, audit evidence completeness, signer posture, and runtime guardrails.
              This keeps release security operational instead of scattered across CI tabs.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {renderHealthBadge(releaseHealthTone, releaseHealthTone === "healthy" ? "Signer visible" : releaseHealthTone === "warning" ? "Signer needs review" : "Signer missing")}
            {renderHealthBadge(evidenceTone, evidenceTone === "healthy" ? "Evidence current" : evidenceTone === "warning" ? "Evidence incomplete" : "Evidence missing")}
            {renderHealthBadge(alertTone, alertTone === "healthy" ? "Guardrails calm" : alertTone === "warning" ? "Guardrails elevated" : "Guardrails hot")}
            <Button variant="outline" onClick={() => void loadAll(true)} disabled={refreshing}>
              {refreshing ? <RefreshCw className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
              Refresh
            </Button>
          </div>
        </div>

        {loadIssues.length > 0 ? (
          <div className="rounded-2xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">
            Partial data is missing right now: {loadIssues.join(", ")}.
          </div>
        ) : null}

        {loading ? (
          <div className="rounded-2xl border border-slate-200 bg-white px-4 py-6 text-sm text-slate-600">
            Loading release posture, governance evidence, and guardrail telemetry...
          </div>
        ) : null}

        <div className="grid gap-4 xl:grid-cols-3">
          <Card className={sectionCardClass}>
            <CardHeader className="border-b bg-slate-50/70">
              <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
                <ShieldCheck className="h-4 w-4" />
                Release identity
              </div>
            </CardHeader>
            <CardContent className="space-y-3 pt-4 text-sm text-slate-700">
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="rounded-lg border border-slate-200 bg-white p-3">
                  <div className="text-xs uppercase tracking-wide text-slate-500">Environment</div>
                  <div className="mt-1 font-medium text-slate-900">{releaseMetadata?.environment || "Unavailable"}</div>
                </div>
                <div className="rounded-lg border border-slate-200 bg-white p-3">
                  <div className="text-xs uppercase tracking-wide text-slate-500">Release label</div>
                  <div className="mt-1 font-medium text-slate-900">{releaseMetadata?.release || "Unavailable"}</div>
                </div>
              </div>
              <div className="rounded-lg border border-slate-200 bg-white p-3">
                <div className="text-xs uppercase tracking-wide text-slate-500">Git SHA</div>
                <div className="mt-1 font-mono text-xs text-slate-900">{releaseMetadata?.gitSha || "Unavailable"}</div>
              </div>
              <div className="rounded-lg border border-slate-200 bg-white p-3">
                <div className="text-xs uppercase tracking-wide text-slate-500">Backend release</div>
                <div className="mt-1 font-medium text-slate-900">
                  {releaseMetadata?.name || "Unknown"} {releaseMetadata?.version || ""}
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className={sectionCardClass}>
            <CardHeader className="border-b bg-slate-50/70">
              <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
                <FileBadge2 className="h-4 w-4" />
                Signing & release evidence
              </div>
            </CardHeader>
            <CardContent className="space-y-3 pt-4 text-sm text-slate-700">
              <div className="rounded-lg border border-slate-200 bg-white p-3">
                <div className="text-xs uppercase tracking-wide text-slate-500">QR signing profile</div>
                {releaseMetadata?.signing ? (
                  <>
                    <div className="mt-1 font-medium text-slate-900">
                      {releaseMetadata.signing.provider} · {releaseMetadata.signing.mode}
                    </div>
                    <div className="mt-1 text-xs text-slate-600">Key version: {releaseMetadata.signing.keyVersion}</div>
                    <div className="text-xs text-slate-600">Key ref: {releaseMetadata.signing.keyRef || "Hidden / platform-managed"}</div>
                  </>
                ) : (
                  <div className="mt-1 text-sm text-red-700">Release metadata did not expose a signing profile.</div>
                )}
              </div>
              <div className="rounded-lg border border-slate-200 bg-slate-50 p-3">
                <div className="text-xs uppercase tracking-wide text-slate-500">Notarization & installer evidence</div>
                <div className="mt-1 text-sm text-slate-700">
                  Connector signing and notarization evidence are still external to runtime metadata. Use the release checklist
                  artifact and signed compliance pack as the operational source of truth until connector evidence is surfaced here.
                </div>
              </div>
              <div className="rounded-lg border border-slate-200 bg-slate-50 p-3">
                <div className="text-xs uppercase tracking-wide text-slate-500">Latest compliance pack</div>
                <div className="mt-1 font-medium text-slate-900">
                  {latestComplianceJob ? `${latestComplianceJob.status} · ${latestComplianceJob.id}` : "No pack generated"}
                </div>
                <div className="text-xs text-slate-600">{latestComplianceJob ? formatWhen(latestComplianceJob.startedAt) : "Generate a signed pack from Governance."}</div>
              </div>
            </CardContent>
          </Card>

          <Card className={sectionCardClass}>
            <CardHeader className="border-b bg-slate-50/70">
              <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
                <ShieldAlert className="h-4 w-4" />
                Guardrail pressure
              </div>
            </CardHeader>
            <CardContent className="space-y-3 pt-4 text-sm text-slate-700">
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="rounded-lg border border-slate-200 bg-white p-3">
                  <div className="text-xs uppercase tracking-wide text-slate-500">Active alerts</div>
                  <div className="mt-1 text-2xl font-semibold text-slate-900">{rateLimitAlerts?.alerts?.length || 0}</div>
                  <div className="text-xs text-slate-600">High severity: {rateLimitAlerts?.alerts?.filter((item) => item.severity === "high").length || 0}</div>
                </div>
                <div className="rounded-lg border border-slate-200 bg-white p-3">
                  <div className="text-xs uppercase tracking-wide text-slate-500">Verify drops</div>
                  <div className="mt-1 text-2xl font-semibold text-slate-900">{routeTelemetry?.verifyFunnel?.dropped || 0}</div>
                  <div className="text-xs text-slate-600">Avg {Math.round(Number(routeTelemetry?.verifyFunnel?.avgTransitionMs || 0))}ms</div>
                </div>
              </div>
              <div className="rounded-lg border border-slate-200 bg-white p-3">
                <div className="text-xs uppercase tracking-wide text-slate-500">Top limited route</div>
                <div className="mt-1 text-sm font-medium text-slate-900">
                  {formatRouteForOperators(rateLimitAnalytics?.topLimitedRoutes?.[0]?.route)}
                </div>
                <div className="text-xs text-slate-600">
                  {rateLimitAnalytics?.topLimitedRoutes?.[0]
                    ? `${rateLimitAnalytics.topLimitedRoutes[0].count} hits in ${rateLimitAnalytics.topLimitedRoutes[0].family}`
                    : "Limiter telemetry is quiet in the current window."}
                </div>
              </div>
              <div className="rounded-lg border border-slate-200 bg-slate-50 p-3">
                <div className="text-xs uppercase tracking-wide text-slate-500">Export abuse posture</div>
                <div className="mt-1 text-sm text-slate-700">
                  {rateLimitAnalytics?.exportAbusePatterns?.[0]
                    ? `${rateLimitAnalytics.exportAbusePatterns[0].family} has ${rateLimitAnalytics.exportAbusePatterns[0].count} recent limiter hits across ${rateLimitAnalytics.exportAbusePatterns[0].uniqueOffenders} offender(s).`
                    : "No export-abuse limiter patterns in the current window."}
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        <div className="grid gap-4 xl:grid-cols-[1.05fr,0.95fr]">
          <Card className={sectionCardClass}>
            <CardHeader className="border-b bg-slate-50/70">
              <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
                <Gauge className="h-4 w-4" />
                Audit evidence completeness
              </div>
            </CardHeader>
            <CardContent className="space-y-3 pt-4 text-sm text-slate-700">
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="rounded-lg border border-slate-200 bg-white p-3">
                  <div className="text-xs uppercase tracking-wide text-slate-500">Compliance generated</div>
                  <div className="mt-1 font-medium text-slate-900">{formatWhen(compliance?.generatedAt)}</div>
                </div>
                <div className="rounded-lg border border-slate-200 bg-white p-3">
                  <div className="text-xs uppercase tracking-wide text-slate-500">Scope</div>
                  <div className="mt-1 font-medium text-slate-900">{compliance?.scope?.licenseeId || "Global"}</div>
                </div>
              </div>

              <div className="grid gap-3 sm:grid-cols-3">
                <div className="rounded-lg border border-slate-200 bg-slate-50 p-3">
                  <div className="text-xs uppercase tracking-wide text-slate-500">Incidents</div>
                  <div className="mt-1 font-medium text-slate-900">
                    {compliance?.metrics?.incidents?.resolved || 0}/{compliance?.metrics?.incidents?.total || 0}
                  </div>
                  <div className="text-xs text-slate-600">SLA open breaches: {compliance?.metrics?.incidents?.slaBreachedOpen || 0}</div>
                </div>
                <div className="rounded-lg border border-slate-200 bg-slate-50 p-3">
                  <div className="text-xs uppercase tracking-wide text-slate-500">Audit events</div>
                  <div className="mt-1 font-medium text-slate-900">{compliance?.metrics?.auditEvents || 0}</div>
                  <div className="text-xs text-slate-600">Failed logins: {compliance?.metrics?.failedLogins || 0}</div>
                </div>
                <div className="rounded-lg border border-slate-200 bg-slate-50 p-3">
                  <div className="text-xs uppercase tracking-wide text-slate-500">Control summary</div>
                  <div className="mt-1 font-medium text-slate-900">
                    {compliance?.controlSummary?.EFFECTIVE || 0} effective
                  </div>
                  <div className="text-xs text-slate-600">Attention: {compliance?.controlSummary?.ATTENTION || 0}</div>
                </div>
              </div>

              <div className="rounded-lg border border-slate-200 bg-white p-3">
                <div className="text-xs uppercase tracking-wide text-slate-500">Security & access control</div>
                <div className="mt-1 text-sm text-slate-700">{compliance?.compliance?.securityAccess?.passwordHandling || "Not available"}</div>
                <div className="mt-1 text-xs text-slate-600">
                  Roles: {(compliance?.compliance?.securityAccess?.roleBasedAccess || []).join(", ") || "Not available"}
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className={sectionCardClass}>
            <CardHeader className="border-b bg-slate-50/70">
              <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
                <AlertTriangle className="h-4 w-4" />
                Action queue
              </div>
            </CardHeader>
            <CardContent className="space-y-3 pt-4">
              {actionItems.map((item) => (
                <div key={item.title} className={`rounded-lg border px-4 py-3 ${toneClasses[item.tone]}`}>
                  <div className="flex items-start gap-3">
                    {item.tone === "healthy" ? (
                      <CheckCircle2 className="mt-0.5 h-4 w-4" />
                    ) : item.tone === "warning" ? (
                      <ShieldQuestion className="mt-0.5 h-4 w-4" />
                    ) : (
                      <ShieldAlert className="mt-0.5 h-4 w-4" />
                    )}
                    <div>
                      <div className="font-medium">{item.title}</div>
                      <div className="mt-1 text-sm">{item.body}</div>
                    </div>
                  </div>
                </div>
              ))}

              <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 text-sm text-slate-700">
                <div className="font-medium text-slate-900">Next operator actions</div>
                <div className="mt-2 flex flex-wrap gap-2">
                  <Button asChild variant="outline" size="sm">
                    <Link to={APP_PATHS.governance}>Open Governance</Link>
                  </Button>
                  <Button asChild variant="outline" size="sm">
                    <Link to={APP_PATHS.support}>Open Support</Link>
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </DashboardLayout>
  );
}
