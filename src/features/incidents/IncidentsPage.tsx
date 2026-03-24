import React, { useEffect, useMemo, useState } from "react";
import { saveAs } from "file-saver";

import { DashboardLayout } from "@/components/layout/DashboardLayout";
import apiClient from "@/lib/api-client";
import { friendlyReferenceLabel, shortRawReference } from "@/lib/friendly-reference";
import { useAuth } from "@/contexts/AuthContext";
import { useToast } from "@/hooks/use-toast";
import { IncidentResponseWorkspace } from "@/features/incidents/components/IncidentResponseWorkspace";
import { useIncident, useIncidents } from "@/features/incidents/hooks";
import { toIncidentLabel } from "@/features/incidents/types";
import type { IncidentDetail, IncidentEmailDeliveryInfo, IncidentRow, IncidentUpdatePayload } from "@/features/incidents/types";

export default function Incidents() {
  const { user } = useAuth();
  const { toast } = useToast();

  const [loading, setLoading] = useState(false);
  const [incidents, setIncidents] = useState<IncidentRow[]>([]);
  const [selectedId, setSelectedId] = useState<string>("");
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [saving, setSaving] = useState(false);

  const [users, setUsers] = useState<any[]>([]);
  const [licensees, setLicensees] = useState<any[]>([]);

  const [filters, setFilters] = useState({
    status: "all",
    severity: "all",
    search: "",
    dateFrom: "",
    dateTo: "",
    licenseeId: "all",
  });

  const [updatePayload, setUpdatePayload] = useState<IncidentUpdatePayload>({
    status: "",
    assignedToUserId: "",
    severity: "",
    internalNotes: "",
    resolutionSummary: "",
    resolutionOutcome: "",
    tags: "",
  });

  const [newNote, setNewNote] = useState("");
  const [customerMessage, setCustomerMessage] = useState("");
  const [customerSubject, setCustomerSubject] = useState("Update on your incident report");
  const [customerSenderMode, setCustomerSenderMode] = useState<"actor" | "system">("actor");
  const [sendingCustomerEmail, setSendingCustomerEmail] = useState(false);
  const [lastCustomerEmailDelivery, setLastCustomerEmailDelivery] = useState<IncidentEmailDeliveryInfo | null>(null);
  const [evidenceFile, setEvidenceFile] = useState<File | null>(null);
  const [exportingPdf, setExportingPdf] = useState(false);

  const selectedIncident = useMemo(
    () => incidents.find((i) => i.id === selectedId) || null,
    [incidents, selectedId]
  );
  const incidentFilters = useMemo(
    () => ({
      status: filters.status !== "all" ? filters.status : undefined,
      severity: filters.severity !== "all" ? filters.severity : undefined,
      search: filters.search.trim() || undefined,
      dateFrom: filters.dateFrom || undefined,
      dateTo: filters.dateTo || undefined,
      licenseeId: user?.role === "super_admin" && filters.licenseeId !== "all" ? filters.licenseeId : undefined,
      limit: 120,
    }),
    [filters.dateFrom, filters.dateTo, filters.licenseeId, filters.search, filters.severity, filters.status, user?.role]
  );
  const incidentsQuery = useIncidents(incidentFilters, false);
  const incidentDetailQuery = useIncident(selectedId || undefined, false);
  const canUseSystemIncidentSender = user?.role === "super_admin";

  const loadIncidents = async () => {
    setLoading(true);
    try {
      const res = await incidentsQuery.refetch();
      if (!res.data) {
        setIncidents([]);
        toast({
          title: "Could not load incidents",
          description: res.error instanceof Error ? res.error.message : "Please refresh and retry.",
          variant: "destructive",
        });
        return;
      }
      setIncidents(res.data as IncidentRow[]);
      const list = res.data as IncidentRow[];
      if (!selectedId && list[0]?.id) setSelectedId(list[0].id);
    } finally {
      setLoading(false);
    }
  };

  const loadDetail = async (id: string) => {
    if (!id) return;
    const res = await incidentDetailQuery.refetch();
    if (!res.data) {
      setDetail(null);
      toast({
        title: "Could not load incident detail",
        description: res.error instanceof Error ? res.error.message : "Select another incident or retry.",
        variant: "destructive",
      });
      return;
    }
    const d = (res.data || null) as IncidentDetail | null;
    setDetail(d);
    if (d) {
      setLastCustomerEmailDelivery(null);
      setUpdatePayload({
        status: d.status || "",
        assignedToUserId: d.assignedToUserId || "unassigned",
        severity: d.severity || "",
        internalNotes: d.internalNotes || "",
        resolutionSummary: d.resolutionSummary || "",
        resolutionOutcome: d.resolutionOutcome || "none",
        tags: Array.isArray((d as any).tags) ? (d as any).tags.join(", ") : "",
      });
      setCustomerMessage(
        `Your report (${friendlyReferenceLabel(d.id, "Case")}) is now "${toIncidentLabel(d.status)}". We will continue to keep you informed if further action is needed.`
      );
    }
  };

  useEffect(() => {
    loadIncidents();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filters.status, filters.severity, filters.dateFrom, filters.dateTo, filters.licenseeId]);

  useEffect(() => {
    if (!selectedId) return;
    loadDetail(selectedId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedId]);

  useEffect(() => {
    setCustomerSenderMode(user?.role === "super_admin" ? "system" : "actor");
  }, [user?.role]);

  useEffect(() => {
    apiClient.getUsers().then((res) => {
      if (res.success) {
        const list = (res.data as any[]) || [];
        setUsers(list.filter((u) => u.role === "LICENSEE_ADMIN" || u.role === "SUPER_ADMIN"));
      }
    });
    if (user?.role === "super_admin") {
      apiClient.getLicensees().then((res) => {
        if (res.success) setLicensees((res.data as any[]) || []);
      });
    }
  }, [user?.role]);

  const buildPatchPayload = (payload: typeof updatePayload) => ({
    status: payload.status || undefined,
    assignedToUserId:
      payload.assignedToUserId && payload.assignedToUserId !== "unassigned"
        ? payload.assignedToUserId
        : null,
    severity: payload.severity || undefined,
    internalNotes: payload.internalNotes || undefined,
    resolutionSummary: payload.resolutionSummary || undefined,
    resolutionOutcome:
      payload.resolutionOutcome && payload.resolutionOutcome !== "none"
        ? (payload.resolutionOutcome as any)
        : null,
    tags: payload.tags
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
  });

  const applyIncidentUpdate = async (
    overrides: Partial<typeof updatePayload>,
    successToast: { title: string; description: string }
  ) => {
    if (!detail) return;
    setSaving(true);
    try {
      const nextPayload = { ...updatePayload, ...overrides };
      const res = await apiClient.patchIncident(detail.id, buildPatchPayload(nextPayload));
      if (!res.success) {
        toast({
          title: "Update failed",
          description: res.error || "Could not save incident updates.",
          variant: "destructive",
        });
        return;
      }
      setUpdatePayload(nextPayload);
      toast(successToast);
      await loadIncidents();
      await loadDetail(detail.id);
    } finally {
      setSaving(false);
    }
  };

  const saveUpdates = async () => {
    await applyIncidentUpdate({}, { title: "Incident updated", description: "Changes saved." });
  };

  const applyQuickStatus = async (status: "RESOLVED" | "REJECTED_SPAM") => {
    const label = status === "RESOLVED" ? "marked as resolved" : "marked as spam";
    await applyIncidentUpdate(
      { status },
      {
        title: "Incident updated",
        description: `Incident ${label}.`,
      }
    );
  };

  const addNote = async () => {
    if (!detail || !newNote.trim()) return;
    const res = await apiClient.addIncidentNote(detail.id, newNote.trim());
    if (!res.success) {
      toast({
        title: "Note failed",
        description: res.error || "Could not add note.",
        variant: "destructive",
      });
      return;
    }
    setNewNote("");
    await loadDetail(detail.id);
  };

  const sendCustomerUpdate = async () => {
    if (!detail) return;
    const subject = customerSubject.trim();
    const message = customerMessage.trim();

    if (subject.length < 3 || message.length < 3) {
      toast({
        title: "Missing message",
        description: "Subject and message are required.",
        variant: "destructive",
      });
      return;
    }

    if (!detail.customerEmail || !detail.consentToContact) {
      toast({
        title: "Customer email unavailable",
        description: "Customer email updates require consent and a valid customer email address.",
        variant: "destructive",
      });
      return;
    }

    const senderEmail = String(user?.email || "").trim();
    if (customerSenderMode === "actor" && !senderEmail) {
      toast({
        title: "Missing sender email",
        description: "Update your account email before sending incident emails.",
        variant: "destructive",
      });
      return;
    }

    setSendingCustomerEmail(true);
    try {
      const res = await apiClient.sendIncidentEmail(detail.id, {
        subject,
        message,
        senderMode: canUseSystemIncidentSender ? customerSenderMode : "actor",
      });

      const deliveryRaw = (res.data || {}) as any;
      setLastCustomerEmailDelivery({
        delivered: Boolean(deliveryRaw?.delivered ?? res.success),
        providerMessageId: deliveryRaw?.providerMessageId || null,
        attemptedFrom: deliveryRaw?.attemptedFrom || null,
        usedFrom: deliveryRaw?.usedFrom || null,
        replyTo: deliveryRaw?.replyTo || null,
        senderMode: (deliveryRaw?.senderMode as "actor" | "system" | undefined) || customerSenderMode,
        error: deliveryRaw?.error || (res.success ? null : res.error || "Email delivery failed"),
      });

      if (!res.success) {
        toast({
          title: "Email failed",
          description: res.error || "Could not send update.",
          variant: "destructive",
        });
        return;
      }

      const fromLabel = deliveryRaw?.usedFrom || deliveryRaw?.attemptedFrom || "configured SMTP sender";
      toast({ title: "Customer update sent", description: `Email delivered via ${fromLabel}.` });
      await loadDetail(detail.id);
    } finally {
      setSendingCustomerEmail(false);
    }
  };

  const uploadEvidence = async () => {
    if (!detail || !evidenceFile) return;
    const res = await apiClient.uploadIncidentEvidence(detail.id, evidenceFile);
    if (!res.success) {
      toast({
        title: "Upload failed",
        description: res.error || "Could not upload evidence.",
        variant: "destructive",
      });
      return;
    }
    toast({ title: "Evidence uploaded", description: "Evidence attached to incident." });
    setEvidenceFile(null);
    await loadDetail(detail.id);
  };

  const downloadEvidence = async (storageKey: string) => {
    try {
      const blob = await apiClient.downloadIncidentEvidence(storageKey);
      saveAs(blob, storageKey);
    } catch (error: any) {
      toast({
        title: "Download failed",
        description: error?.message || "Could not download file.",
        variant: "destructive",
      });
    }
  };

  const exportIncidentPdf = async () => {
    if (!detail) return;
    setExportingPdf(true);
    try {
      const blob = await apiClient.requestIncidentPdfExport(detail.id);
      saveAs(blob, `incident-${detail.id}.pdf`);
    } catch (error: any) {
      toast({
        title: "PDF export failed",
        description: error?.message || "Could not export incident PDF.",
        variant: "destructive",
      });
    } finally {
      setExportingPdf(false);
    }
  };

  return (
    <DashboardLayout>
      <IncidentResponseWorkspace
        userRole={user?.role}
        userEmail={user?.email}
        loading={loading}
        filters={filters}
        setFilters={setFilters}
        licensees={licensees}
        incidents={incidents}
        selectedId={selectedId}
        setSelectedId={setSelectedId}
        selectedIncident={selectedIncident}
        detail={detail}
        updatePayload={updatePayload}
        setUpdatePayload={setUpdatePayload}
        users={users}
        saving={saving}
        onRefresh={loadIncidents}
        onSaveUpdates={saveUpdates}
        onQuickStatus={applyQuickStatus}
        exportingPdf={exportingPdf}
        onExportPdf={exportIncidentPdf}
        canUseSystemIncidentSender={canUseSystemIncidentSender}
        customerSenderMode={customerSenderMode}
        setCustomerSenderMode={setCustomerSenderMode}
        customerSubject={customerSubject}
        setCustomerSubject={setCustomerSubject}
        customerMessage={customerMessage}
        setCustomerMessage={setCustomerMessage}
        sendingCustomerEmail={sendingCustomerEmail}
        lastCustomerEmailDelivery={lastCustomerEmailDelivery}
        onSendCustomerUpdate={sendCustomerUpdate}
        evidenceFile={evidenceFile}
        setEvidenceFile={setEvidenceFile}
        onUploadEvidence={uploadEvidence}
        onDownloadEvidence={downloadEvidence}
        newNote={newNote}
        setNewNote={setNewNote}
        onAddNote={addNote}
      />
    </DashboardLayout>
  );
}
