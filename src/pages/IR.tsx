import React, { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { formatDistanceToNow } from "date-fns";
import { Plus, RefreshCw, Search, ShieldAlert } from "lucide-react";

import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import apiClient from "@/lib/api-client";
import { friendlyReferenceLabel, shortRawReference } from "@/lib/friendly-reference";
import { useToast } from "@/hooks/use-toast";

type LicenseeLite = { id: string; name: string; prefix: string };

const STATUS_TONE: Record<string, string> = {
  NEW: "border-red-200 bg-red-50 text-red-700",
  TRIAGE: "border-amber-200 bg-amber-50 text-amber-700",
  TRIAGED: "border-amber-200 bg-amber-50 text-amber-700",
  INVESTIGATING: "border-cyan-200 bg-cyan-50 text-cyan-700",
  CONTAINMENT: "border-orange-200 bg-orange-50 text-orange-700",
  ERADICATION: "border-orange-200 bg-orange-50 text-orange-700",
  RECOVERY: "border-emerald-200 bg-emerald-50 text-emerald-700",
  CLOSED: "border-slate-300 bg-slate-100 text-slate-700",
  REOPENED: "border-red-200 bg-red-50 text-red-700",
};

const SEVERITY_TONE: Record<string, string> = {
  LOW: "border-emerald-200 bg-emerald-50 text-emerald-700",
  MEDIUM: "border-amber-200 bg-amber-50 text-amber-700",
  HIGH: "border-orange-200 bg-orange-50 text-orange-700",
  CRITICAL: "border-red-200 bg-red-50 text-red-700",
};

const RULE_TYPE_LABEL: Record<string, string> = {
  DISTINCT_DEVICES: "Distinct devices",
  MULTI_COUNTRY: "Multi-country",
  BURST_SCANS: "Burst scans",
  TOO_MANY_REPORTS: "Too many reports",
};

const ALERT_TYPE_LABEL: Record<string, string> = {
  MULTI_SCAN: "Multi-scan",
  GEO_DRIFT: "Geo drift",
  VELOCITY_SPIKE: "Velocity spike",
  STUCK_BATCH: "Stuck batch",
  AUTO_BLOCK_QR: "Auto-block QR",
  AUTO_BLOCK_BATCH: "Auto-block batch",
  POLICY_RULE: "Policy rule",
};

const INCIDENT_TYPE_OPTIONS = [
  { value: "COUNTERFEIT_SUSPECTED", label: "Counterfeit suspected" },
  { value: "DUPLICATE_SCAN", label: "Duplicate scan" },
  { value: "TAMPERED_LABEL", label: "Tampered label" },
  { value: "WRONG_PRODUCT", label: "Wrong product" },
  { value: "OTHER", label: "Other" },
] as const;

export default function IR() {
  const navigate = useNavigate();
  const { toast } = useToast();

  const [activeTab, setActiveTab] = useState<"incidents" | "alerts" | "policies">("incidents");

  const [licensees, setLicensees] = useState<LicenseeLite[]>([]);

  const [incidentsLoading, setIncidentsLoading] = useState(false);
  const [incidents, setIncidents] = useState<any[]>([]);
  const [incidentsTotal, setIncidentsTotal] = useState(0);
  const [incidentFilters, setIncidentFilters] = useState({
    status: "all",
    severity: "all",
    priority: "all",
    licenseeId: "all",
    search: "",
  });

  const [alertsLoading, setAlertsLoading] = useState(false);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [alertsTotal, setAlertsTotal] = useState(0);
  const [alertFilters, setAlertFilters] = useState({
    acknowledged: "false",
    severity: "all",
    alertType: "all",
    licenseeId: "all",
  });

  const [policiesLoading, setPoliciesLoading] = useState(false);
  const [policies, setPolicies] = useState<any[]>([]);
  const [policiesTotal, setPoliciesTotal] = useState(0);

  const [newIncidentOpen, setNewIncidentOpen] = useState(false);
  const [creatingIncident, setCreatingIncident] = useState(false);
  const [newIncident, setNewIncident] = useState({
    qrCodeValue: "",
    incidentType: INCIDENT_TYPE_OPTIONS[0].value,
    severity: "MEDIUM",
    priority: "P3",
    licenseeId: "auto",
    description: "",
  });

  const [policyDialogOpen, setPolicyDialogOpen] = useState(false);
  const [policySaving, setPolicySaving] = useState(false);
  const [editingPolicy, setEditingPolicy] = useState<any | null>(null);
  const [policyForm, setPolicyForm] = useState({
    name: "",
    description: "",
    ruleType: "DISTINCT_DEVICES",
    isActive: true,
    threshold: "5",
    windowMinutes: "60",
    severity: "MEDIUM",
    autoCreateIncident: false,
    incidentSeverity: "MEDIUM",
    incidentPriority: "P3",
    licenseeId: "all",
  });

  const loadLicensees = async () => {
    const res = await apiClient.getLicensees();
    if (!res.success) return;
    const list = (res.data as any[]) || [];
    setLicensees(list.map((l) => ({ id: l.id, name: l.name, prefix: l.prefix })));
  };

  const loadIncidents = async () => {
    setIncidentsLoading(true);
    try {
      const res = await apiClient.getIrIncidents({
        status: incidentFilters.status !== "all" ? incidentFilters.status : undefined,
        severity: incidentFilters.severity !== "all" ? incidentFilters.severity : undefined,
        priority: incidentFilters.priority !== "all" ? incidentFilters.priority : undefined,
        licenseeId: incidentFilters.licenseeId !== "all" ? incidentFilters.licenseeId : undefined,
        search: incidentFilters.search.trim() || undefined,
        limit: 100,
      });
      if (!res.success) {
        setIncidents([]);
        setIncidentsTotal(0);
        toast({
          title: "Could not load incidents",
          description: res.error || "Please refresh and retry.",
          variant: "destructive",
        });
        return;
      }
      const payload: any = res.data || {};
      setIncidents(Array.isArray(payload?.incidents) ? payload.incidents : []);
      setIncidentsTotal(Number(payload?.total || 0));
    } finally {
      setIncidentsLoading(false);
    }
  };

  const loadAlerts = async () => {
    setAlertsLoading(true);
    try {
      const res = await apiClient.getIrAlerts({
        acknowledged: alertFilters.acknowledged === "all" ? undefined : alertFilters.acknowledged === "true",
        severity: alertFilters.severity !== "all" ? alertFilters.severity : undefined,
        alertType: alertFilters.alertType !== "all" ? alertFilters.alertType : undefined,
        licenseeId: alertFilters.licenseeId !== "all" ? alertFilters.licenseeId : undefined,
        limit: 100,
      });
      if (!res.success) {
        setAlerts([]);
        setAlertsTotal(0);
        toast({
          title: "Could not load alerts",
          description: res.error || "Please refresh and retry.",
          variant: "destructive",
        });
        return;
      }
      const payload: any = res.data || {};
      setAlerts(Array.isArray(payload?.alerts) ? payload.alerts : []);
      setAlertsTotal(Number(payload?.total || 0));
    } finally {
      setAlertsLoading(false);
    }
  };

  const loadPolicies = async () => {
    setPoliciesLoading(true);
    try {
      const res = await apiClient.getIrPolicies({ limit: 100 });
      if (!res.success) {
        setPolicies([]);
        setPoliciesTotal(0);
        toast({
          title: "Could not load policy rules",
          description: res.error || "Please refresh and retry.",
          variant: "destructive",
        });
        return;
      }
      const payload: any = res.data || {};
      setPolicies(Array.isArray(payload?.rules) ? payload.rules : []);
      setPoliciesTotal(Number(payload?.total || 0));
    } finally {
      setPoliciesLoading(false);
    }
  };

  const refreshActiveTab = async () => {
    if (activeTab === "incidents") return loadIncidents();
    if (activeTab === "alerts") return loadAlerts();
    return loadPolicies();
  };

  useEffect(() => {
    loadLicensees();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (activeTab === "incidents") loadIncidents();
    if (activeTab === "alerts") loadAlerts();
    if (activeTab === "policies") loadPolicies();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab]);

  useEffect(() => {
    if (activeTab !== "incidents") return;
    loadIncidents();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [incidentFilters.status, incidentFilters.severity, incidentFilters.priority, incidentFilters.licenseeId]);

  useEffect(() => {
    if (activeTab !== "alerts") return;
    loadAlerts();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [alertFilters.acknowledged, alertFilters.severity, alertFilters.alertType, alertFilters.licenseeId]);

  const licenseeOptions = useMemo(
    () => [{ id: "all", name: "All licensees", prefix: "ALL" } as any, ...licensees],
    [licensees]
  );

  const openCreatePolicy = () => {
    setEditingPolicy(null);
    setPolicyForm({
      name: "",
      description: "",
      ruleType: "DISTINCT_DEVICES",
      isActive: true,
      threshold: "5",
      windowMinutes: "60",
      severity: "MEDIUM",
      autoCreateIncident: false,
      incidentSeverity: "MEDIUM",
      incidentPriority: "P3",
      licenseeId: "all",
    });
    setPolicyDialogOpen(true);
  };

  const openEditPolicy = (rule: any) => {
    setEditingPolicy(rule);
    setPolicyForm({
      name: String(rule?.name || ""),
      description: String(rule?.description || ""),
      ruleType: String(rule?.ruleType || "DISTINCT_DEVICES"),
      isActive: Boolean(rule?.isActive),
      threshold: String(rule?.threshold ?? 5),
      windowMinutes: String(rule?.windowMinutes ?? 60),
      severity: String(rule?.severity || "MEDIUM"),
      autoCreateIncident: Boolean(rule?.autoCreateIncident),
      incidentSeverity: String(rule?.incidentSeverity || "MEDIUM"),
      incidentPriority: String(rule?.incidentPriority || "P3"),
      licenseeId: rule?.licenseeId ? String(rule.licenseeId) : "all",
    });
    setPolicyDialogOpen(true);
  };

  const savePolicy = async () => {
    const name = policyForm.name.trim();
    if (name.length < 3) {
      toast({ title: "Name required", description: "Policy name must be at least 3 characters.", variant: "destructive" });
      return;
    }
    const threshold = Number(policyForm.threshold);
    const windowMinutes = Number(policyForm.windowMinutes);
    if (!Number.isFinite(threshold) || threshold <= 0 || !Number.isFinite(windowMinutes) || windowMinutes <= 0) {
      toast({ title: "Invalid policy", description: "Threshold and window must be positive numbers.", variant: "destructive" });
      return;
    }

    setPolicySaving(true);
    try {
      const payload: any = {
        name,
        description: policyForm.description.trim() || undefined,
        ruleType: policyForm.ruleType as any,
        isActive: policyForm.isActive,
        threshold,
        windowMinutes,
        severity: policyForm.severity as any,
        autoCreateIncident: policyForm.autoCreateIncident,
        incidentSeverity: policyForm.autoCreateIncident ? (policyForm.incidentSeverity as any) : undefined,
        incidentPriority: policyForm.autoCreateIncident ? (policyForm.incidentPriority as any) : undefined,
        licenseeId: policyForm.licenseeId !== "all" ? policyForm.licenseeId : undefined,
      };

      const res = editingPolicy?.id
        ? await apiClient.patchIrPolicy(editingPolicy.id, payload)
        : await apiClient.createIrPolicy(payload);

      if (!res.success) {
        toast({ title: "Save failed", description: res.error || "Could not save policy.", variant: "destructive" });
        return;
      }

      toast({ title: "Policy saved", description: editingPolicy ? "Policy updated." : "Policy created." });
      setPolicyDialogOpen(false);
      setEditingPolicy(null);
      await loadPolicies();
    } finally {
      setPolicySaving(false);
    }
  };

  const createIncident = async () => {
    const qrCodeValue = newIncident.qrCodeValue.trim().toUpperCase();
    const description = newIncident.description.trim();
    if (!qrCodeValue || qrCodeValue.length < 2) {
      toast({ title: "Missing QR code", description: "Enter the QR code value.", variant: "destructive" });
      return;
    }
    if (description.length < 6) {
      toast({ title: "Description required", description: "Add a short description for investigators.", variant: "destructive" });
      return;
    }

    setCreatingIncident(true);
    try {
      const res = await apiClient.createIrIncident({
        qrCodeValue,
        incidentType: newIncident.incidentType as any,
        severity: newIncident.severity as any,
        priority: newIncident.priority as any,
        description,
        licenseeId: newIncident.licenseeId !== "auto" ? newIncident.licenseeId : undefined,
        tags: ["ir_manual"],
      });
      if (!res.success) {
        toast({ title: "Create failed", description: res.error || "Could not create incident.", variant: "destructive" });
        return;
      }
      const created: any = res.data;
      toast({ title: "Incident created", description: `Incident ${created?.id || ""} created.` });
      setNewIncidentOpen(false);
      setNewIncident({
        qrCodeValue: "",
        incidentType: INCIDENT_TYPE_OPTIONS[0].value,
        severity: "MEDIUM",
        priority: "P3",
        licenseeId: "auto",
        description: "",
      });
      await loadIncidents();
      if (created?.id) navigate(`/ir/incidents/${created.id}`);
    } finally {
      setCreatingIncident(false);
    }
  };

  const toggleAlertAck = async (alert: any, nextAck: boolean) => {
    const res = await apiClient.patchIrAlert(alert.id, { acknowledged: nextAck });
    if (!res.success) {
      toast({ title: "Update failed", description: res.error || "Could not update alert.", variant: "destructive" });
      return;
    }
    await loadAlerts();
  };

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Incident Response</h1>
            <p className="text-sm text-muted-foreground">
              Policy alerts, incident triage, containment actions, and communications.
            </p>
          </div>

          <div className="flex flex-col gap-2 sm:flex-row">
            <Button variant="outline" onClick={refreshActiveTab}>
              <RefreshCw className="mr-2 h-4 w-4" />
              Refresh
            </Button>
            {activeTab === "incidents" ? (
              <Button onClick={() => setNewIncidentOpen(true)}>
                <Plus className="mr-2 h-4 w-4" />
                New incident
              </Button>
            ) : null}
            {activeTab === "policies" ? (
              <Button onClick={openCreatePolicy}>
                <Plus className="mr-2 h-4 w-4" />
                New policy
              </Button>
            ) : null}
          </div>
        </div>

        <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as any)}>
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="incidents">Incidents</TabsTrigger>
            <TabsTrigger value="alerts">Policy alerts</TabsTrigger>
            <TabsTrigger value="policies">Policies</TabsTrigger>
          </TabsList>

          <TabsContent value="incidents" className="space-y-4">
            <Card>
              <CardHeader className="pb-4">
                <div className="flex flex-col gap-3 md:flex-row md:items-center">
                  <div className="relative flex-1">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                    <Input
                      placeholder="Search QR / description / reporter fields..."
                      value={incidentFilters.search}
                      onChange={(e) => setIncidentFilters((p) => ({ ...p, search: e.target.value }))}
                      className="pl-9"
                      onKeyDown={(e) => {
                        if (e.key === "Enter") loadIncidents();
                      }}
                    />
                  </div>

                  <Select value={incidentFilters.status} onValueChange={(v) => setIncidentFilters((p) => ({ ...p, status: v }))}>
                    <SelectTrigger className="w-[180px]">
                      <SelectValue placeholder="Status" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All status</SelectItem>
                      <SelectItem value="NEW">NEW</SelectItem>
                      <SelectItem value="TRIAGE">TRIAGE</SelectItem>
                      <SelectItem value="INVESTIGATING">INVESTIGATING</SelectItem>
                      <SelectItem value="CONTAINMENT">CONTAINMENT</SelectItem>
                      <SelectItem value="ERADICATION">ERADICATION</SelectItem>
                      <SelectItem value="RECOVERY">RECOVERY</SelectItem>
                      <SelectItem value="CLOSED">CLOSED</SelectItem>
                      <SelectItem value="REOPENED">REOPENED</SelectItem>
                    </SelectContent>
                  </Select>

                  <Select value={incidentFilters.severity} onValueChange={(v) => setIncidentFilters((p) => ({ ...p, severity: v }))}>
                    <SelectTrigger className="w-[180px]">
                      <SelectValue placeholder="Severity" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All severity</SelectItem>
                      <SelectItem value="LOW">LOW</SelectItem>
                      <SelectItem value="MEDIUM">MEDIUM</SelectItem>
                      <SelectItem value="HIGH">HIGH</SelectItem>
                      <SelectItem value="CRITICAL">CRITICAL</SelectItem>
                    </SelectContent>
                  </Select>

                  <Select value={incidentFilters.priority} onValueChange={(v) => setIncidentFilters((p) => ({ ...p, priority: v }))}>
                    <SelectTrigger className="w-[140px]">
                      <SelectValue placeholder="Priority" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All</SelectItem>
                      <SelectItem value="P1">P1</SelectItem>
                      <SelectItem value="P2">P2</SelectItem>
                      <SelectItem value="P3">P3</SelectItem>
                      <SelectItem value="P4">P4</SelectItem>
                    </SelectContent>
                  </Select>

                  <Select value={incidentFilters.licenseeId} onValueChange={(v) => setIncidentFilters((p) => ({ ...p, licenseeId: v }))}>
                    <SelectTrigger className="w-[220px]">
                      <SelectValue placeholder="Licensee" />
                    </SelectTrigger>
                    <SelectContent>
                      {licenseeOptions.map((l: any) => (
                        <SelectItem key={l.id} value={l.id}>
                          {l.id === "all" ? "All licensees" : `${l.name} (${l.prefix})`}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </CardHeader>
              <CardContent>
                {incidentsLoading ? (
                  <div className="text-sm text-muted-foreground">Loading incidents...</div>
                ) : incidents.length === 0 ? (
                  <div className="rounded-lg border p-6 text-sm text-muted-foreground">
                    No incidents match your filters.
                  </div>
                ) : (
                  <div className="rounded-md border">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>ID</TableHead>
                          <TableHead>Status</TableHead>
                          <TableHead>Severity</TableHead>
                          <TableHead>Priority</TableHead>
                          <TableHead>Licensee</TableHead>
                          <TableHead>QR</TableHead>
                          <TableHead>Assignee</TableHead>
                          <TableHead>Created</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {incidents.map((row) => (
                          <TableRow
                            key={row.id}
                            className="cursor-pointer"
                            onClick={() => navigate(`/ir/incidents/${row.id}`)}
                          >
                            <TableCell className="text-xs" title={row.id}>
                              <div className="font-semibold">{friendlyReferenceLabel(row.id, "Case")}</div>
                              <div className="font-mono text-[10px] text-muted-foreground">#{shortRawReference(row.id, 8)}</div>
                            </TableCell>
                            <TableCell>
                              <Badge variant="outline" className={STATUS_TONE[row.status] || "border-slate-200 bg-slate-50 text-slate-700"}>
                                {row.status}
                              </Badge>
                            </TableCell>
                            <TableCell>
                              <Badge variant="outline" className={SEVERITY_TONE[row.severity] || "border-slate-200 bg-slate-50 text-slate-700"}>
                                {row.severity}
                              </Badge>
                            </TableCell>
                            <TableCell className="font-medium">{row.priority}</TableCell>
                            <TableCell className="text-sm">
                              {row.licensee ? `${row.licensee.name} (${row.licensee.prefix})` : "—"}
                            </TableCell>
                            <TableCell className="font-mono text-xs">{row.qrCodeValue || "—"}</TableCell>
                            <TableCell className="text-sm">{row.assignedToUser?.name || row.assignedToUser?.email || "Unassigned"}</TableCell>
                            <TableCell className="text-sm text-muted-foreground">
                              {row.createdAt ? formatDistanceToNow(new Date(row.createdAt), { addSuffix: true }) : "—"}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                )}

                <div className="mt-3 text-xs text-muted-foreground">
                  Showing {incidents.length} of {incidentsTotal}.
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="alerts" className="space-y-4">
            <Card>
              <CardHeader className="pb-4">
                <div className="flex flex-col gap-3 md:flex-row md:items-center">
                  <Select value={alertFilters.acknowledged} onValueChange={(v) => setAlertFilters((p) => ({ ...p, acknowledged: v }))}>
                    <SelectTrigger className="w-[200px]">
                      <SelectValue placeholder="Acknowledged" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="false">Unacknowledged</SelectItem>
                      <SelectItem value="true">Acknowledged</SelectItem>
                      <SelectItem value="all">All</SelectItem>
                    </SelectContent>
                  </Select>

                  <Select value={alertFilters.severity} onValueChange={(v) => setAlertFilters((p) => ({ ...p, severity: v }))}>
                    <SelectTrigger className="w-[180px]">
                      <SelectValue placeholder="Severity" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All severity</SelectItem>
                      <SelectItem value="LOW">LOW</SelectItem>
                      <SelectItem value="MEDIUM">MEDIUM</SelectItem>
                      <SelectItem value="HIGH">HIGH</SelectItem>
                      <SelectItem value="CRITICAL">CRITICAL</SelectItem>
                    </SelectContent>
                  </Select>

                  <Select value={alertFilters.alertType} onValueChange={(v) => setAlertFilters((p) => ({ ...p, alertType: v }))}>
                    <SelectTrigger className="w-[220px]">
                      <SelectValue placeholder="Alert type" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All types</SelectItem>
                      <SelectItem value="POLICY_RULE">POLICY_RULE</SelectItem>
                      <SelectItem value="MULTI_SCAN">MULTI_SCAN</SelectItem>
                      <SelectItem value="GEO_DRIFT">GEO_DRIFT</SelectItem>
                      <SelectItem value="VELOCITY_SPIKE">VELOCITY_SPIKE</SelectItem>
                      <SelectItem value="AUTO_BLOCK_QR">AUTO_BLOCK_QR</SelectItem>
                      <SelectItem value="AUTO_BLOCK_BATCH">AUTO_BLOCK_BATCH</SelectItem>
                    </SelectContent>
                  </Select>

                  <Select value={alertFilters.licenseeId} onValueChange={(v) => setAlertFilters((p) => ({ ...p, licenseeId: v }))}>
                    <SelectTrigger className="w-[220px]">
                      <SelectValue placeholder="Licensee" />
                    </SelectTrigger>
                    <SelectContent>
                      {licenseeOptions.map((l: any) => (
                        <SelectItem key={l.id} value={l.id}>
                          {l.id === "all" ? "All licensees" : `${l.name} (${l.prefix})`}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </CardHeader>
              <CardContent>
                {alertsLoading ? (
                  <div className="text-sm text-muted-foreground">Loading alerts...</div>
                ) : alerts.length === 0 ? (
                  <div className="rounded-lg border p-6 text-sm text-muted-foreground">
                    No policy alerts match your filters.
                  </div>
                ) : (
                  <div className="rounded-md border">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Severity</TableHead>
                          <TableHead>Type</TableHead>
                          <TableHead>Licensee</TableHead>
                          <TableHead>QR</TableHead>
                          <TableHead>Message</TableHead>
                          <TableHead>Created</TableHead>
                          <TableHead className="text-right">Action</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {alerts.map((a) => (
                          <TableRow key={a.id}>
                            <TableCell>
                              <Badge variant="outline" className={SEVERITY_TONE[a.severity] || "border-slate-200 bg-slate-50 text-slate-700"}>
                                {a.severity}
                              </Badge>
                            </TableCell>
                            <TableCell className="text-sm font-medium">
                              {ALERT_TYPE_LABEL[a.alertType] || a.alertType}
                            </TableCell>
                            <TableCell className="text-sm">
                              {a.licensee ? `${a.licensee.name} (${a.licensee.prefix})` : "—"}
                            </TableCell>
                            <TableCell className="font-mono text-xs">{a.qrCode?.code || "—"}</TableCell>
                            <TableCell className="text-sm">{a.message}</TableCell>
                            <TableCell className="text-sm text-muted-foreground">
                              {a.createdAt ? formatDistanceToNow(new Date(a.createdAt), { addSuffix: true }) : "—"}
                            </TableCell>
                            <TableCell className="text-right">
                              {a.acknowledgedAt ? (
                                <Button size="sm" variant="outline" onClick={() => toggleAlertAck(a, false)}>
                                  Unack
                                </Button>
                              ) : (
                                <Button size="sm" onClick={() => toggleAlertAck(a, true)}>
                                  Acknowledge
                                </Button>
                              )}
                              {a.incidentId ? (
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  className="ml-2"
                                  asChild
                                >
                                  <Link to={`/ir/incidents/${a.incidentId}`}>Open</Link>
                                </Button>
                              ) : null}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                )}

                <div className="mt-3 text-xs text-muted-foreground">
                  Showing {alerts.length} of {alertsTotal}.
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="policies" className="space-y-4">
            <Card>
              <CardHeader className="pb-4">
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <ShieldAlert className="h-4 w-4" />
                  Policy rules are evaluated on scans and can auto-create incidents.
                </div>
              </CardHeader>
              <CardContent>
                {policiesLoading ? (
                  <div className="text-sm text-muted-foreground">Loading policies...</div>
                ) : policies.length === 0 ? (
                  <div className="rounded-lg border p-6 text-sm text-muted-foreground">
                    No policy rules configured.
                  </div>
                ) : (
                  <div className="rounded-md border">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Name</TableHead>
                          <TableHead>Type</TableHead>
                          <TableHead>Threshold</TableHead>
                          <TableHead>Window</TableHead>
                          <TableHead>Severity</TableHead>
                          <TableHead>Active</TableHead>
                          <TableHead>Auto incident</TableHead>
                          <TableHead>Scope</TableHead>
                          <TableHead>Updated</TableHead>
                          <TableHead className="text-right">Action</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {policies.map((r) => (
                          <TableRow key={r.id}>
                            <TableCell className="font-medium">{r.name}</TableCell>
                            <TableCell className="text-sm">{RULE_TYPE_LABEL[r.ruleType] || r.ruleType}</TableCell>
                            <TableCell className="text-sm">{r.threshold}</TableCell>
                            <TableCell className="text-sm">{r.windowMinutes} min</TableCell>
                            <TableCell>
                              <Badge variant="outline" className={SEVERITY_TONE[r.severity] || "border-slate-200 bg-slate-50 text-slate-700"}>
                                {r.severity}
                              </Badge>
                            </TableCell>
                            <TableCell className="text-sm">{r.isActive ? "Yes" : "No"}</TableCell>
                            <TableCell className="text-sm">{r.autoCreateIncident ? "Yes" : "No"}</TableCell>
                            <TableCell className="text-sm">
                              {r.licensee ? `${r.licensee.name} (${r.licensee.prefix})` : "All"}
                            </TableCell>
                            <TableCell className="text-sm text-muted-foreground">
                              {r.updatedAt ? formatDistanceToNow(new Date(r.updatedAt), { addSuffix: true }) : "—"}
                            </TableCell>
                            <TableCell className="text-right">
                              <Button size="sm" variant="outline" onClick={() => openEditPolicy(r)}>
                                Edit
                              </Button>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                )}

                <div className="mt-3 text-xs text-muted-foreground">
                  Showing {policies.length} of {policiesTotal}.
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>

      {/* New incident dialog */}
      <Dialog open={newIncidentOpen} onOpenChange={setNewIncidentOpen}>
        <DialogContent className="sm:max-w-[720px]">
          <DialogHeader>
            <DialogTitle>Create incident</DialogTitle>
            <DialogDescription>
              Use this for manual cases or escalations from policy alerts.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label>QR code value</Label>
                <Input value={newIncident.qrCodeValue} onChange={(e) => setNewIncident((p) => ({ ...p, qrCodeValue: e.target.value }))} placeholder="A0000000001" />
              </div>

              <div className="space-y-2">
                <Label>Licensee (optional)</Label>
                <Select value={newIncident.licenseeId} onValueChange={(v) => setNewIncident((p) => ({ ...p, licenseeId: v }))}>
                  <SelectTrigger>
                    <SelectValue placeholder="Auto-detect from QR" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="auto">Auto-detect from QR</SelectItem>
                    {licensees.map((l) => (
                      <SelectItem key={l.id} value={l.id}>
                        {l.name} ({l.prefix})
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="grid gap-4 md:grid-cols-3">
              <div className="space-y-2">
                <Label>Type</Label>
                <Select value={newIncident.incidentType} onValueChange={(v) => setNewIncident((p) => ({ ...p, incidentType: v as any }))}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select type" />
                  </SelectTrigger>
                  <SelectContent>
                    {INCIDENT_TYPE_OPTIONS.map((o) => (
                      <SelectItem key={o.value} value={o.value}>
                        {o.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label>Severity</Label>
                <Select value={newIncident.severity} onValueChange={(v) => setNewIncident((p) => ({ ...p, severity: v }))}>
                  <SelectTrigger>
                    <SelectValue placeholder="Severity" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="LOW">LOW</SelectItem>
                    <SelectItem value="MEDIUM">MEDIUM</SelectItem>
                    <SelectItem value="HIGH">HIGH</SelectItem>
                    <SelectItem value="CRITICAL">CRITICAL</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label>Priority</Label>
                <Select value={newIncident.priority} onValueChange={(v) => setNewIncident((p) => ({ ...p, priority: v }))}>
                  <SelectTrigger>
                    <SelectValue placeholder="Priority" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="P1">P1</SelectItem>
                    <SelectItem value="P2">P2</SelectItem>
                    <SelectItem value="P3">P3</SelectItem>
                    <SelectItem value="P4">P4</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="space-y-2">
              <Label>Description</Label>
              <Textarea value={newIncident.description} onChange={(e) => setNewIncident((p) => ({ ...p, description: e.target.value }))} rows={4} placeholder="What happened and why this needs investigation." />
            </div>

            <div className="flex justify-end gap-2">
              <Button type="button" variant="outline" onClick={() => setNewIncidentOpen(false)} disabled={creatingIncident}>
                Cancel
              </Button>
              <Button type="button" onClick={createIncident} disabled={creatingIncident}>
                {creatingIncident ? "Creating..." : "Create incident"}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Policy dialog */}
      <Dialog open={policyDialogOpen} onOpenChange={setPolicyDialogOpen}>
        <DialogContent className="sm:max-w-[760px]">
          <DialogHeader>
            <DialogTitle>{editingPolicy ? "Edit policy rule" : "Create policy rule"}</DialogTitle>
            <DialogDescription>
              Configure when the platform should raise alerts and optionally auto-create incidents.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label>Name</Label>
                <Input value={policyForm.name} onChange={(e) => setPolicyForm((p) => ({ ...p, name: e.target.value }))} placeholder="e.g., Multi-country scans" />
              </div>
              <div className="space-y-2">
                <Label>Scope</Label>
                <Select value={policyForm.licenseeId} onValueChange={(v) => setPolicyForm((p) => ({ ...p, licenseeId: v }))}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select scope" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All licensees</SelectItem>
                    {licensees.map((l) => (
                      <SelectItem key={l.id} value={l.id}>
                        {l.name} ({l.prefix})
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="space-y-2">
              <Label>Description (optional)</Label>
              <Input value={policyForm.description} onChange={(e) => setPolicyForm((p) => ({ ...p, description: e.target.value }))} placeholder="What this rule detects." />
            </div>

            <div className="grid gap-4 md:grid-cols-3">
              <div className="space-y-2">
                <Label>Rule type</Label>
                <Select value={policyForm.ruleType} onValueChange={(v) => setPolicyForm((p) => ({ ...p, ruleType: v }))}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select rule type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="DISTINCT_DEVICES">Distinct devices</SelectItem>
                    <SelectItem value="MULTI_COUNTRY">Multi-country</SelectItem>
                    <SelectItem value="BURST_SCANS">Burst scans</SelectItem>
                    <SelectItem value="TOO_MANY_REPORTS">Too many reports</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>Threshold</Label>
                <Input value={policyForm.threshold} onChange={(e) => setPolicyForm((p) => ({ ...p, threshold: e.target.value }))} />
              </div>
              <div className="space-y-2">
                <Label>Window (minutes)</Label>
                <Input value={policyForm.windowMinutes} onChange={(e) => setPolicyForm((p) => ({ ...p, windowMinutes: e.target.value }))} />
              </div>
            </div>

            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label>Alert severity</Label>
                <Select value={policyForm.severity} onValueChange={(v) => setPolicyForm((p) => ({ ...p, severity: v }))}>
                  <SelectTrigger>
                    <SelectValue placeholder="Severity" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="LOW">LOW</SelectItem>
                    <SelectItem value="MEDIUM">MEDIUM</SelectItem>
                    <SelectItem value="HIGH">HIGH</SelectItem>
                    <SelectItem value="CRITICAL">CRITICAL</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="flex items-center gap-2 pt-7 text-sm">
                <input
                  type="checkbox"
                  checked={policyForm.isActive}
                  onChange={(e) => setPolicyForm((p) => ({ ...p, isActive: e.target.checked }))}
                  className="h-4 w-4 rounded border-slate-300"
                />
                <span>Active</span>
              </div>
            </div>

            <div className="rounded-lg border bg-slate-50 p-3 space-y-3">
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={policyForm.autoCreateIncident}
                  onChange={(e) => setPolicyForm((p) => ({ ...p, autoCreateIncident: e.target.checked }))}
                  className="h-4 w-4 rounded border-slate-300"
                />
                <span>Auto-create incident when this rule triggers</span>
              </label>

              {policyForm.autoCreateIncident ? (
                <div className="grid gap-4 md:grid-cols-2">
                  <div className="space-y-2">
                    <Label>Incident severity</Label>
                    <Select value={policyForm.incidentSeverity} onValueChange={(v) => setPolicyForm((p) => ({ ...p, incidentSeverity: v }))}>
                      <SelectTrigger>
                        <SelectValue placeholder="Severity" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="LOW">LOW</SelectItem>
                        <SelectItem value="MEDIUM">MEDIUM</SelectItem>
                        <SelectItem value="HIGH">HIGH</SelectItem>
                        <SelectItem value="CRITICAL">CRITICAL</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label>Incident priority</Label>
                    <Select value={policyForm.incidentPriority} onValueChange={(v) => setPolicyForm((p) => ({ ...p, incidentPriority: v }))}>
                      <SelectTrigger>
                        <SelectValue placeholder="Priority" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="P1">P1</SelectItem>
                        <SelectItem value="P2">P2</SelectItem>
                        <SelectItem value="P3">P3</SelectItem>
                        <SelectItem value="P4">P4</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              ) : null}
            </div>

            <div className="flex justify-end gap-2">
              <Button type="button" variant="outline" onClick={() => setPolicyDialogOpen(false)} disabled={policySaving}>
                Cancel
              </Button>
              <Button type="button" onClick={savePolicy} disabled={policySaving}>
                {policySaving ? "Saving..." : "Save"}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </DashboardLayout>
  );
}
