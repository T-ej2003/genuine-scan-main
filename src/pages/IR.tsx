import React, { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";

import { DashboardLayout } from "@/components/layout/DashboardLayout";
import apiClient from "@/lib/api-client";
import { useToast } from "@/hooks/use-toast";
import { IncidentResponseAdminWorkspace } from "@/features/ir/components/IncidentResponseAdminWorkspace";
import {
  INCIDENT_TYPE_OPTIONS,
  type AlertFiltersState,
  type IncidentFiltersState,
  type LicenseeLite,
  type NewIncidentState,
  type PolicyFormState,
} from "@/features/ir/types";

export default function IR() {
  const navigate = useNavigate();
  const { toast } = useToast();

  const [activeTab, setActiveTab] = useState<"incidents" | "alerts" | "policies">("incidents");

  const [licensees, setLicensees] = useState<LicenseeLite[]>([]);

  const [incidentsLoading, setIncidentsLoading] = useState(false);
  const [incidents, setIncidents] = useState<any[]>([]);
  const [incidentsTotal, setIncidentsTotal] = useState(0);
  const [incidentFilters, setIncidentFilters] = useState<IncidentFiltersState>({
    status: "all",
    severity: "all",
    priority: "all",
    licenseeId: "all",
    search: "",
  });

  const [alertsLoading, setAlertsLoading] = useState(false);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [alertsTotal, setAlertsTotal] = useState(0);
  const [alertFilters, setAlertFilters] = useState<AlertFiltersState>({
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
  const [newIncident, setNewIncident] = useState<NewIncidentState>({
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
  const [policyForm, setPolicyForm] = useState<PolicyFormState>({
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
      <IncidentResponseAdminWorkspace
        activeTab={activeTab}
        onActiveTabChange={setActiveTab}
        onRefreshActiveTab={refreshActiveTab}
        onOpenCreateIncident={() => setNewIncidentOpen(true)}
        onOpenCreatePolicy={openCreatePolicy}
        incidentFilters={incidentFilters}
        onIncidentFiltersChange={setIncidentFilters}
        onLoadIncidents={loadIncidents}
        licenseeOptions={licenseeOptions}
        incidentsLoading={incidentsLoading}
        incidents={incidents}
        incidentsTotal={incidentsTotal}
        onOpenIncident={(incidentId) => navigate(`/ir/incidents/${incidentId}`)}
        alertFilters={alertFilters}
        onAlertFiltersChange={setAlertFilters}
        alertsLoading={alertsLoading}
        alerts={alerts}
        alertsTotal={alertsTotal}
        onToggleAlertAck={toggleAlertAck}
        policiesLoading={policiesLoading}
        policies={policies}
        policiesTotal={policiesTotal}
        onEditPolicy={openEditPolicy}
        newIncidentOpen={newIncidentOpen}
        onNewIncidentOpenChange={setNewIncidentOpen}
        newIncident={newIncident}
        onNewIncidentChange={setNewIncident}
        creatingIncident={creatingIncident}
        onCreateIncident={createIncident}
        licensees={licensees}
        policyDialogOpen={policyDialogOpen}
        onPolicyDialogOpenChange={setPolicyDialogOpen}
        editingPolicy={editingPolicy}
        policyForm={policyForm}
        onPolicyFormChange={setPolicyForm}
        policySaving={policySaving}
        onSavePolicy={savePolicy}
      />
    </DashboardLayout>
  );
}
