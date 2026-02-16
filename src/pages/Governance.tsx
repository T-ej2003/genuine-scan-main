import React, { useEffect, useMemo, useState } from "react";
import { saveAs } from "file-saver";
import { FileDown, Loader2, RefreshCw, ShieldCheck, SlidersHorizontal } from "lucide-react";

import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import apiClient from "@/lib/api-client";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/contexts/AuthContext";

const VERIFY_FLAG_KEYS = [
  { key: "verify_show_timeline_card", label: "Show timeline card" },
  { key: "verify_show_risk_cards", label: "Show dynamic risk cards" },
  { key: "verify_allow_ownership_claim", label: "Allow ownership claim" },
  { key: "verify_allow_fraud_report", label: "Allow fraud report" },
  { key: "verify_mobile_camera_assist", label: "Enable mobile camera assist" },
] as const;

export default function Governance() {
  const { user } = useAuth();
  const { toast } = useToast();

  const [loading, setLoading] = useState(false);
  const [licensees, setLicensees] = useState<any[]>([]);
  const [activeLicenseeId, setActiveLicenseeId] = useState<string>(user?.licenseeId || "");

  const [flags, setFlags] = useState<any[]>([]);
  const [retention, setRetention] = useState<any | null>(null);
  const [retentionSaving, setRetentionSaving] = useState(false);
  const [retentionRunLoading, setRetentionRunLoading] = useState(false);
  const [retentionPreview, setRetentionPreview] = useState<any | null>(null);

  const [compliance, setCompliance] = useState<any | null>(null);
  const [complianceLoading, setComplianceLoading] = useState(false);

  const [telemetry, setTelemetry] = useState<any | null>(null);
  const [telemetryLoading, setTelemetryLoading] = useState(false);

  const [incidentBundleId, setIncidentBundleId] = useState("");
  const [exportingBundle, setExportingBundle] = useState(false);

  const [retentionForm, setRetentionForm] = useState({
    retentionDays: "180",
    purgeEnabled: false,
    exportBeforePurge: true,
    legalHoldTags: "legal_hold, compliance_hold",
  });

  const canSelectLicensee = user?.role === "super_admin";

  const resolveLicenseeId = () => {
    if (canSelectLicensee) return activeLicenseeId;
    return user?.licenseeId || "";
  };

  const loadAll = async () => {
    const licenseeId = resolveLicenseeId();
    if (!licenseeId && canSelectLicensee) return;

    setLoading(true);
    try {
      const [flagsRes, retentionRes] = await Promise.all([
        apiClient.getGovernanceFeatureFlags(licenseeId || undefined),
        apiClient.getEvidenceRetentionPolicy(licenseeId || undefined),
      ]);

      if (flagsRes.success) {
        const payload: any = flagsRes.data || {};
        setFlags(Array.isArray(payload.flags) ? payload.flags : []);
      }

      if (retentionRes.success) {
        const policy: any = retentionRes.data || null;
        setRetention(policy);
        if (policy) {
          setRetentionForm({
            retentionDays: String(policy.retentionDays || 180),
            purgeEnabled: Boolean(policy.purgeEnabled),
            exportBeforePurge: Boolean(policy.exportBeforePurge),
            legalHoldTags: Array.isArray(policy.legalHoldTags) ? policy.legalHoldTags.join(", ") : "",
          });
        }
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (user?.role !== "super_admin") return;
    apiClient.getLicensees().then((res) => {
      if (!res.success) return;
      const rows = (res.data as any[]) || [];
      setLicensees(rows);
      if (!activeLicenseeId && rows[0]?.id) {
        setActiveLicenseeId(rows[0].id);
      }
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.role]);

  useEffect(() => {
    loadAll();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeLicenseeId, user?.licenseeId, user?.role]);

  const flagMap = useMemo(() => {
    const map = new Map<string, any>();
    for (const flag of flags) {
      map.set(flag.key, flag);
    }
    return map;
  }, [flags]);

  const toggleFlag = async (key: string, enabled: boolean) => {
    const licenseeId = resolveLicenseeId();
    if (!licenseeId) {
      toast({ title: "Licensee required", description: "Select a licensee scope first.", variant: "destructive" });
      return;
    }

    const response = await apiClient.upsertGovernanceFeatureFlag({
      licenseeId,
      key,
      enabled,
    });

    if (!response.success) {
      toast({ title: "Flag update failed", description: response.error || "Could not update feature flag.", variant: "destructive" });
      return;
    }

    await loadAll();
  };

  const saveRetentionPolicy = async () => {
    const licenseeId = resolveLicenseeId();
    if (!licenseeId) {
      toast({ title: "Licensee required", description: "Select a licensee scope first.", variant: "destructive" });
      return;
    }

    setRetentionSaving(true);
    try {
      const response = await apiClient.patchEvidenceRetentionPolicy({
        licenseeId,
        retentionDays: Number(retentionForm.retentionDays || 180),
        purgeEnabled: retentionForm.purgeEnabled,
        exportBeforePurge: retentionForm.exportBeforePurge,
        legalHoldTags: retentionForm.legalHoldTags
          .split(",")
          .map((tag) => tag.trim())
          .filter(Boolean),
      });

      if (!response.success) {
        toast({ title: "Policy update failed", description: response.error || "Could not save retention policy.", variant: "destructive" });
        return;
      }

      toast({ title: "Retention policy saved", description: "Lifecycle policy updated." });
      await loadAll();
    } finally {
      setRetentionSaving(false);
    }
  };

  const runRetention = async (mode: "PREVIEW" | "APPLY") => {
    const licenseeId = resolveLicenseeId();
    if (!licenseeId) {
      toast({ title: "Licensee required", description: "Select a licensee scope first.", variant: "destructive" });
      return;
    }

    setRetentionRunLoading(true);
    try {
      const response = await apiClient.runEvidenceRetentionJob({
        licenseeId,
        mode,
      });

      if (!response.success) {
        toast({ title: "Retention run failed", description: response.error || "Could not run retention lifecycle.", variant: "destructive" });
        return;
      }

      const payload: any = response.data || null;
      setRetentionPreview(payload);
      toast({ title: `${mode} completed`, description: `Evaluated ${payload?.evaluated || 0} evidence records.` });
    } finally {
      setRetentionRunLoading(false);
    }
  };

  const loadCompliance = async () => {
    const licenseeId = resolveLicenseeId();
    setComplianceLoading(true);
    try {
      const response = await apiClient.getComplianceReport({
        licenseeId: licenseeId || undefined,
      });
      if (!response.success) {
        toast({ title: "Compliance report failed", description: response.error || "Could not load compliance report.", variant: "destructive" });
        return;
      }
      setCompliance(response.data || null);
    } finally {
      setComplianceLoading(false);
    }
  };

  const loadTelemetry = async () => {
    const licenseeId = resolveLicenseeId();
    setTelemetryLoading(true);
    try {
      const response = await apiClient.getRouteTransitionSummary({ licenseeId: licenseeId || undefined });
      if (!response.success) {
        toast({ title: "Telemetry load failed", description: response.error || "Could not load route telemetry.", variant: "destructive" });
        return;
      }
      setTelemetry(response.data || null);
    } finally {
      setTelemetryLoading(false);
    }
  };

  const exportIncidentBundle = async () => {
    const incidentId = incidentBundleId.trim();
    if (!incidentId) {
      toast({ title: "Incident ID required", description: "Enter an incident ID to export the evidence bundle.", variant: "destructive" });
      return;
    }

    setExportingBundle(true);
    try {
      const blob = await apiClient.exportIncidentEvidenceBundle(incidentId);
      saveAs(blob, `incident-${incidentId}-evidence-audit.zip`);
    } catch (error: any) {
      toast({ title: "Export failed", description: error?.message || "Could not export incident evidence bundle.", variant: "destructive" });
    } finally {
      setExportingBundle(false);
    }
  };

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-slate-200 bg-gradient-to-r from-slate-50 via-white to-cyan-50 p-4">
          <div className="flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-cyan-200 bg-cyan-50">
              <SlidersHorizontal className="h-5 w-5 text-cyan-700" />
            </div>
            <div>
              <h1 className="text-3xl font-bold tracking-tight text-slate-900">Governance & Reliability</h1>
              <p className="text-sm text-slate-600">Manage tenant policy flags, retention lifecycle, compliance reports, and route telemetry.</p>
            </div>
          </div>
          <Button variant="outline" onClick={loadAll}>
            <RefreshCw className="mr-2 h-4 w-4" />
            Refresh
          </Button>
        </div>

        {canSelectLicensee ? (
          <Card>
            <CardHeader className="border-b bg-slate-50/70">
              <p className="text-sm font-semibold">Tenant scope</p>
            </CardHeader>
            <CardContent className="pt-4">
              <Select value={activeLicenseeId} onValueChange={setActiveLicenseeId}>
                <SelectTrigger className="max-w-md">
                  <SelectValue placeholder="Select licensee" />
                </SelectTrigger>
                <SelectContent>
                  {licensees.map((licensee) => (
                    <SelectItem key={licensee.id} value={licensee.id}>
                      {licensee.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </CardContent>
          </Card>
        ) : null}

        <div className="grid gap-6 xl:grid-cols-2">
          <Card>
            <CardHeader className="border-b bg-slate-50/70">
              <p className="text-sm font-semibold">Verification UX feature flags</p>
            </CardHeader>
            <CardContent className="space-y-3 pt-4">
              {VERIFY_FLAG_KEYS.map((flag) => {
                const row = flagMap.get(flag.key);
                return (
                  <div key={flag.key} className="flex items-center justify-between rounded-lg border border-slate-200 bg-white px-3 py-2">
                    <div>
                      <p className="text-sm font-medium text-slate-900">{flag.label}</p>
                      <p className="font-mono text-xs text-slate-500">{flag.key}</p>
                    </div>
                    <Switch checked={Boolean(row?.enabled)} onCheckedChange={(checked) => toggleFlag(flag.key, checked)} disabled={loading} />
                  </div>
                );
              })}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="border-b bg-slate-50/70">
              <p className="text-sm font-semibold">Evidence retention lifecycle</p>
            </CardHeader>
            <CardContent className="space-y-3 pt-4">
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="space-y-2">
                  <Label>Retention days</Label>
                  <Input
                    value={retentionForm.retentionDays}
                    onChange={(e) => setRetentionForm((prev) => ({ ...prev, retentionDays: e.target.value }))}
                  />
                </div>
                <div className="space-y-2">
                  <Label>Legal hold tags</Label>
                  <Input
                    value={retentionForm.legalHoldTags}
                    onChange={(e) => setRetentionForm((prev) => ({ ...prev, legalHoldTags: e.target.value }))}
                  />
                </div>
              </div>

              <label className="flex items-center justify-between rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm">
                <span>Purge enabled</span>
                <Switch
                  checked={retentionForm.purgeEnabled}
                  onCheckedChange={(value) => setRetentionForm((prev) => ({ ...prev, purgeEnabled: value }))}
                />
              </label>

              <label className="flex items-center justify-between rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm">
                <span>Export before purge</span>
                <Switch
                  checked={retentionForm.exportBeforePurge}
                  onCheckedChange={(value) => setRetentionForm((prev) => ({ ...prev, exportBeforePurge: value }))}
                />
              </label>

              <div className="flex flex-wrap gap-2">
                <Button onClick={saveRetentionPolicy} disabled={retentionSaving} className="bg-slate-900 text-white hover:bg-slate-800">
                  {retentionSaving ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                  Save policy
                </Button>
                <Button variant="outline" onClick={() => runRetention("PREVIEW")} disabled={retentionRunLoading}>
                  Preview run
                </Button>
                <Button variant="outline" onClick={() => runRetention("APPLY")} disabled={retentionRunLoading || !retentionForm.purgeEnabled}>
                  Apply run
                </Button>
              </div>

              {retentionPreview ? (
                <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-xs text-slate-700">
                  <p>Evaluated: {retentionPreview.evaluated}</p>
                  <p>Eligible: {retentionPreview.eligible}</p>
                  <p>Purged: {retentionPreview.purged}</p>
                  <p>Exported: {retentionPreview.exported}</p>
                </div>
              ) : null}

              {retention ? (
                <p className="text-xs text-slate-500">Current policy ID: {retention.id}</p>
              ) : null}
            </CardContent>
          </Card>
        </div>

        <div className="grid gap-6 xl:grid-cols-2">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between border-b bg-slate-50/70">
              <p className="text-sm font-semibold">Automated compliance report</p>
              <Button variant="outline" onClick={loadCompliance} disabled={complianceLoading}>
                {complianceLoading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                Generate
              </Button>
            </CardHeader>
            <CardContent className="pt-4">
              {compliance ? (
                <div className="space-y-3 text-sm text-slate-700">
                  <div className="grid gap-3 sm:grid-cols-2">
                    <div className="rounded-lg border border-slate-200 bg-white p-3">
                      <p className="text-xs uppercase tracking-wide text-slate-500">Generated</p>
                      <p className="mt-1 font-medium text-slate-900">{new Date(compliance.generatedAt).toLocaleString()}</p>
                    </div>
                    <div className="rounded-lg border border-slate-200 bg-white p-3">
                      <p className="text-xs uppercase tracking-wide text-slate-500">Scope</p>
                      <p className="mt-1 font-medium text-slate-900">{compliance.scope?.licenseeId || "Global"}</p>
                    </div>
                  </div>

                  <div className="grid gap-3 sm:grid-cols-2">
                    <div className="rounded-lg border border-slate-200 bg-slate-50 p-3">
                      <p className="text-xs uppercase tracking-wide text-slate-500">Incidents</p>
                      <p className="mt-1 font-medium text-slate-900">
                        {compliance.metrics?.incidents?.resolved || 0} resolved / {compliance.metrics?.incidents?.total || 0} total
                      </p>
                      <p className="text-xs text-slate-600">
                        SLA breached (open): {compliance.metrics?.incidents?.slaBreachedOpen || 0}
                      </p>
                    </div>
                    <div className="rounded-lg border border-slate-200 bg-slate-50 p-3">
                      <p className="text-xs uppercase tracking-wide text-slate-500">Audit events</p>
                      <p className="mt-1 font-medium text-slate-900">{compliance.metrics?.auditEvents || 0}</p>
                      <p className="text-xs text-slate-600">Failed logins: {compliance.metrics?.failedLogins || 0}</p>
                    </div>
                  </div>

                  <div className="rounded-lg border border-slate-200 bg-white p-3">
                    <p className="text-xs uppercase tracking-wide text-slate-500">UK GDPR & Data Protection</p>
                    <p className="mt-1">{compliance.compliance?.ukGdpr?.statement}</p>
                    <p className="mt-1 text-xs text-slate-600">Contact: {compliance.compliance?.ukGdpr?.contact}</p>
                  </div>

                  <div className="rounded-lg border border-slate-200 bg-white p-3">
                    <p className="text-xs uppercase tracking-wide text-slate-500">Security & Access Control</p>
                    <p className="mt-1">{compliance.compliance?.securityAccess?.passwordHandling}</p>
                    <p className="mt-1 text-xs text-slate-600">
                      Roles: {(compliance.compliance?.securityAccess?.roleBasedAccess || []).join(", ")}
                    </p>
                  </div>

                  <div className="rounded-lg border border-slate-200 bg-white p-3">
                    <p className="text-xs uppercase tracking-wide text-slate-500">Incident Response Workflow</p>
                    <p className="mt-1">
                      {(compliance.compliance?.incidentResponse?.workflow || []).join(" -> ")}
                    </p>
                  </div>
                </div>
              ) : (
                <p className="text-sm text-slate-500">Run the compliance generator to view UK GDPR, retention, and incident workflow controls.</p>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between border-b bg-slate-50/70">
              <p className="text-sm font-semibold">Route transition telemetry</p>
              <Button variant="outline" onClick={loadTelemetry} disabled={telemetryLoading}>
                {telemetryLoading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                Load
              </Button>
            </CardHeader>
            <CardContent className="space-y-3 pt-4">
              {telemetry ? (
                <>
                  <div className="grid gap-3 sm:grid-cols-2">
                    <div className="rounded-lg border border-slate-200 bg-white p-3">
                      <p className="text-xs text-slate-500">Total transitions</p>
                      <p className="text-2xl font-semibold text-slate-900">{telemetry.totals?.transitions || 0}</p>
                      <p className="text-xs text-slate-500">Avg {Math.round(Number(telemetry.totals?.avgTransitionMs || 0))}ms</p>
                    </div>
                    <div className="rounded-lg border border-slate-200 bg-white p-3">
                      <p className="text-xs text-slate-500">Verify funnel drops</p>
                      <p className="text-2xl font-semibold text-slate-900">{telemetry.verifyFunnel?.dropped || 0}</p>
                      <p className="text-xs text-slate-500">Avg {Math.round(Number(telemetry.verifyFunnel?.avgTransitionMs || 0))}ms</p>
                    </div>
                  </div>

                  <div className="space-y-2">
                    {(telemetry.routes || []).map((route: any) => (
                      <div key={route.routeTo} className="flex items-center justify-between rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-sm">
                        <span className="font-mono text-xs">{route.routeTo}</span>
                        <span>
                          <Badge variant="outline">{route.count}</Badge>
                          <span className="ml-2 text-xs text-slate-500">{Math.round(Number(route.avgTransitionMs || 0))}ms</span>
                        </span>
                      </div>
                    ))}
                  </div>
                </>
              ) : (
                <p className="text-sm text-slate-500">Load telemetry to inspect verify funnel latency and route transitions.</p>
              )}
            </CardContent>
          </Card>
        </div>

        <Card>
          <CardHeader className="border-b bg-slate-50/70">
            <p className="text-sm font-semibold">Incident evidence audit bundle</p>
          </CardHeader>
          <CardContent className="space-y-3 pt-4">
            <div className="grid gap-3 sm:grid-cols-[1fr_auto]">
              <Input
                value={incidentBundleId}
                onChange={(e) => setIncidentBundleId(e.target.value)}
                placeholder="Enter incident ID"
              />
              <Button onClick={exportIncidentBundle} disabled={exportingBundle}>
                {exportingBundle ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <FileDown className="mr-2 h-4 w-4" />}
                Export bundle
              </Button>
            </div>
            <p className="text-xs text-slate-500">Bundle includes incident metadata, evidence fingerprints, workflow timeline, and files.</p>
          </CardContent>
        </Card>

        <div className="rounded-xl border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-900">
          <div className="flex items-start gap-2">
            <ShieldCheck className="mt-0.5 h-4 w-4" />
            <div>
              <p className="font-semibold">Compliance alignment active</p>
              <p className="mt-1">
                UK GDPR, retention, incident response workflow, and route reliability telemetry are now managed in one governance console.
              </p>
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
