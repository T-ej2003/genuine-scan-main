import React, { useEffect, useMemo, useState } from "react";
import { format } from "date-fns";
import { AlertTriangle, CheckCircle2, FileText, Filter, Loader2, Mail, RefreshCw, Search, ShieldAlert, Upload } from "lucide-react";
import { saveAs } from "file-saver";

import { DashboardLayout } from "@/components/layout/DashboardLayout";
import apiClient from "@/lib/api-client";
import { friendlyReferenceLabel, shortRawReference } from "@/lib/friendly-reference";
import { useAuth } from "@/contexts/AuthContext";
import { useToast } from "@/hooks/use-toast";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { useIncident, useIncidents } from "@/features/incidents/hooks";

type IncidentRow = {
  id: string;
  createdAt: string;
  qrCodeValue: string;
  incidentType: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  status: string;
  description: string;
  consentToContact: boolean;
  customerEmail?: string | null;
  customerPhone?: string | null;
  locationName?: string | null;
  assignedToUserId?: string | null;
  assignedToUser?: { id: string; name?: string | null; email?: string | null } | null;
  handoff?: {
    currentStage?: string | null;
    slaDueAt?: string | null;
  } | null;
  supportTicket?: {
    id: string;
    referenceCode?: string | null;
    status?: string | null;
    slaDueAt?: string | null;
  } | null;
};

type IncidentDetail = IncidentRow & {
  events: Array<{
    id: string;
    createdAt: string;
    actorType: string;
    eventType: string;
    eventPayload?: any;
    actorUser?: { id: string; name?: string | null; email?: string | null } | null;
  }>;
  evidence: Array<{
    id: string;
    storageKey?: string | null;
    fileType?: string | null;
    createdAt: string;
  }>;
  internalNotes?: string | null;
  resolutionSummary?: string | null;
  resolutionOutcome?: string | null;
};

type IncidentEmailDeliveryInfo = {
  delivered: boolean;
  providerMessageId?: string | null;
  attemptedFrom?: string | null;
  usedFrom?: string | null;
  replyTo?: string | null;
  senderMode?: "actor" | "system";
  error?: string | null;
};

const STATUS_TONE: Record<string, string> = {
  NEW: "border-red-200 bg-red-50 text-red-700",
  TRIAGED: "border-amber-200 bg-amber-50 text-amber-700",
  INVESTIGATING: "border-cyan-200 bg-cyan-50 text-cyan-700",
  AWAITING_CUSTOMER: "border-slate-300 bg-slate-100 text-slate-700",
  AWAITING_LICENSEE: "border-slate-300 bg-slate-100 text-slate-700",
  MITIGATED: "border-emerald-200 bg-emerald-50 text-emerald-700",
  RESOLVED: "border-emerald-200 bg-emerald-50 text-emerald-700",
  CLOSED: "border-slate-300 bg-slate-100 text-slate-700",
  REJECTED_SPAM: "border-slate-300 bg-slate-100 text-slate-700",
};

const SEVERITY_TONE: Record<string, string> = {
  LOW: "border-emerald-200 bg-emerald-50 text-emerald-700",
  MEDIUM: "border-amber-200 bg-amber-50 text-amber-700",
  HIGH: "border-orange-200 bg-orange-50 text-orange-700",
  CRITICAL: "border-red-200 bg-red-50 text-red-700",
};

const toLabel = (value: string) =>
  String(value || "")
    .toLowerCase()
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());

const payloadValueToText = (value: unknown): string => {
  if (value == null) return "";
  if (Array.isArray(value)) return value.map((v) => String(v)).join(", ");
  if (typeof value === "object") {
    return Object.entries(value as Record<string, unknown>)
      .map(([k, v]) => `${toLabel(k)} ${String(v)}`)
      .join(", ");
  }
  return String(value);
};

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

  const [updatePayload, setUpdatePayload] = useState({
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
        `Your report (${friendlyReferenceLabel(d.id, "Case")}) is now "${toLabel(d.status)}". We will continue to keep you informed if further action is needed.`
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
      <div className="space-y-6">
        <div className="flex flex-col gap-3 rounded-2xl border border-slate-200 bg-gradient-to-r from-slate-50 via-white to-cyan-50 p-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-red-200 bg-red-50">
              <ShieldAlert className="h-5 w-5 text-red-600" />
            </div>
            <div>
              <h1 className="text-3xl font-bold tracking-tight text-slate-900">Incident Response</h1>
              <p className="text-sm text-slate-600">Triage customer fraud reports, assign actions, and track resolution.</p>
            </div>
          </div>
          <Button variant="outline" onClick={loadIncidents}>
            <RefreshCw className="mr-2 h-4 w-4" />
            Refresh
          </Button>
        </div>

        <Card className="border-slate-200">
          <CardHeader className="flex flex-col gap-3 border-b bg-slate-50/70 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4 text-slate-500" />
              <span className="font-semibold">Filters</span>
            </div>
            <div className="relative w-full sm:max-w-sm">
              <Search className="absolute left-3 top-3 h-4 w-4 text-slate-400" />
              <Input
                className="pl-9"
                placeholder="Search by code / description / contact"
                value={filters.search}
                onChange={(e) => setFilters((prev) => ({ ...prev, search: e.target.value }))}
              />
            </div>
          </CardHeader>
          <CardContent className="grid gap-3 pt-4 md:grid-cols-2 xl:grid-cols-6">
            {user?.role === "super_admin" && (
              <Select
                value={filters.licenseeId}
                onValueChange={(value) => setFilters((prev) => ({ ...prev, licenseeId: value }))}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Licensee" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All licensees</SelectItem>
                  {licensees.map((l) => (
                    <SelectItem key={l.id} value={l.id}>
                      {l.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}

            <Select value={filters.status} onValueChange={(value) => setFilters((prev) => ({ ...prev, status: value }))}>
              <SelectTrigger>
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All statuses</SelectItem>
                {["NEW", "TRIAGED", "INVESTIGATING", "AWAITING_CUSTOMER", "AWAITING_LICENSEE", "MITIGATED", "RESOLVED", "CLOSED", "REJECTED_SPAM"].map((status) => (
                  <SelectItem key={status} value={status}>
                    {toLabel(status)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select value={filters.severity} onValueChange={(value) => setFilters((prev) => ({ ...prev, severity: value }))}>
              <SelectTrigger>
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All severities</SelectItem>
                {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((severity) => (
                  <SelectItem key={severity} value={severity}>
                    {toLabel(severity)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <div className="space-y-1">
              <Label className="text-xs font-medium text-slate-600">From date</Label>
              <Input
                type="date"
                value={filters.dateFrom}
                onChange={(e) => setFilters((prev) => ({ ...prev, dateFrom: e.target.value }))}
              />
            </div>
            <div className="space-y-1">
              <Label className="text-xs font-medium text-slate-600">To date</Label>
              <Input
                type="date"
                value={filters.dateTo}
                onChange={(e) => setFilters((prev) => ({ ...prev, dateTo: e.target.value }))}
              />
            </div>
            <Button onClick={loadIncidents} disabled={loading} className="bg-slate-900 text-white hover:bg-slate-800">
              {loading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
              Apply
            </Button>
          </CardContent>
        </Card>

        <div className="grid gap-6 xl:grid-cols-[1.1fr,1fr]">
          <Card className="border-slate-200">
            <CardHeader className="flex flex-row items-center justify-between border-b bg-slate-50/70">
              <span className="font-semibold">Incidents</span>
              <Badge className="border-slate-200 bg-white text-slate-700">{incidents.length} items</Badge>
            </CardHeader>
            <CardContent className="pt-4">
              <div className="max-h-[700px] overflow-auto rounded-lg border">
                <Table>
                  <TableHeader>
                    <TableRow className="bg-slate-50">
                      <TableHead>Incident</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Severity</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Created</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {incidents.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={5} className="text-slate-500">
                          No incidents found.
                        </TableCell>
                      </TableRow>
                    ) : (
                      incidents.map((item) => (
                        <TableRow
                          key={item.id}
                          onClick={() => setSelectedId(item.id)}
                          className={item.id === selectedId ? "bg-cyan-50/60 cursor-pointer" : "cursor-pointer"}
                        >
                          <TableCell>
                            <div className="text-xs font-semibold" title={item.id}>
                              {friendlyReferenceLabel(item.id, "Case")}
                            </div>
                            <div className="font-mono text-[10px] text-slate-500">#{shortRawReference(item.id, 8)}</div>
                            <div className="text-sm text-slate-700">{item.qrCodeValue}</div>
                            <div className="text-xs text-slate-500">{item.locationName || "Location unknown"}</div>
                          </TableCell>
                          <TableCell className="text-sm text-slate-700">{toLabel(item.incidentType)}</TableCell>
                          <TableCell>
                            <Badge className={SEVERITY_TONE[item.severity] || "border-slate-300 bg-slate-100 text-slate-700"}>
                              {toLabel(item.severity)}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <Badge className={STATUS_TONE[item.status] || "border-slate-300 bg-slate-100 text-slate-700"}>
                              {toLabel(item.status)}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-xs text-slate-600">{format(new Date(item.createdAt), "PPp")}</TableCell>
                        </TableRow>
                      ))
                    )}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>

          <Card className="border-slate-200">
            <CardHeader className="flex flex-row items-center justify-between border-b bg-slate-50/70">
              <span className="font-semibold">Incident Detail</span>
              {selectedIncident ? (
                <Badge className={STATUS_TONE[selectedIncident.status] || "border-slate-300 bg-slate-100 text-slate-700"}>
                  {toLabel(selectedIncident.status)}
                </Badge>
              ) : null}
            </CardHeader>
            <CardContent className="space-y-4 pt-4">
              {!detail ? (
                <div className="text-sm text-slate-500">Select an incident to view details.</div>
              ) : (
                <>
                  <div className="rounded-xl border border-slate-200 bg-white p-3">
                    <div className="grid gap-2 text-sm sm:grid-cols-2">
                      <div>
                        <span className="text-slate-500">Reference</span>
                        <div className="font-semibold" title={detail.id}>{friendlyReferenceLabel(detail.id, "Case")}</div>
                        <div className="font-mono text-xs text-slate-500">{detail.id}</div>
                      </div>
                      <div>
                        <span className="text-slate-500">QR</span>
                        <div className="font-mono font-semibold">{detail.qrCodeValue}</div>
                      </div>
                      <div>
                        <span className="text-slate-500">Reported</span>
                        <div>{format(new Date(detail.createdAt), "PPp")}</div>
                      </div>
                      <div>
                        <span className="text-slate-500">Contact</span>
                        <div>{detail.customerEmail || detail.customerPhone || "Not shared"}</div>
                      </div>
                      <div>
                        <span className="text-slate-500">Workflow stage</span>
                        <div>{toLabel(detail.handoff?.currentStage || "INTAKE")}</div>
                      </div>
                      <div>
                        <span className="text-slate-500">Support ticket</span>
                        {detail.supportTicket?.referenceCode ? (
                          <div>
                            <div className="font-medium">{friendlyReferenceLabel(detail.supportTicket.referenceCode, "Ticket")}</div>
                            <div className="font-mono text-xs text-slate-500">{detail.supportTicket.referenceCode}</div>
                          </div>
                        ) : (
                          <div className="font-mono">Pending</div>
                        )}
                      </div>
                    </div>
                    <p className="mt-3 text-sm text-slate-700">{detail.description}</p>
                    {detail.supportTicket?.slaDueAt ? (
                      <p className="mt-2 text-xs text-slate-600">
                        SLA due by: {format(new Date(detail.supportTicket.slaDueAt), "PPp")}
                      </p>
                    ) : null}
                    <p className="mt-2 text-xs text-slate-600">
                      Guided handoff: Intake to Review to Containment to Documentation to Resolution.
                    </p>
                  </div>

                  <div className="grid gap-3 sm:grid-cols-2">
                    <div className="space-y-2">
                      <Label>Status</Label>
                      <Select
                        value={updatePayload.status}
                        onValueChange={(value) => setUpdatePayload((prev) => ({ ...prev, status: value }))}
                      >
                        <SelectTrigger>
                          <SelectValue placeholder="Status" />
                        </SelectTrigger>
                        <SelectContent>
                          {["NEW", "TRIAGED", "INVESTIGATING", "AWAITING_CUSTOMER", "AWAITING_LICENSEE", "MITIGATED", "RESOLVED", "CLOSED", "REJECTED_SPAM"].map((status) => (
                            <SelectItem key={status} value={status}>
                              {toLabel(status)}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label>Assign to</Label>
                      <Select
                        value={updatePayload.assignedToUserId || "unassigned"}
                        onValueChange={(value) => setUpdatePayload((prev) => ({ ...prev, assignedToUserId: value }))}
                      >
                        <SelectTrigger>
                          <SelectValue placeholder="Select admin" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="unassigned">Unassigned</SelectItem>
                          {users.map((u) => (
                            <SelectItem key={u.id} value={u.id}>
                              {u.name || u.email}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                  </div>

                  <div className="grid gap-3 sm:grid-cols-2">
                    <div className="space-y-2">
                      <Label>Severity</Label>
                      <Select
                        value={updatePayload.severity}
                        onValueChange={(value) => setUpdatePayload((prev) => ({ ...prev, severity: value }))}
                      >
                        <SelectTrigger>
                          <SelectValue placeholder="Severity" />
                        </SelectTrigger>
                        <SelectContent>
                          {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((severity) => (
                            <SelectItem key={severity} value={severity}>
                              {toLabel(severity)}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label>Resolution outcome</Label>
                      <Select
                        value={updatePayload.resolutionOutcome || "none"}
                        onValueChange={(value) => setUpdatePayload((prev) => ({ ...prev, resolutionOutcome: value }))}
                      >
                        <SelectTrigger>
                          <SelectValue placeholder="Outcome" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="none">None</SelectItem>
                          <SelectItem value="CONFIRMED_FRAUD">Confirmed fraud</SelectItem>
                          <SelectItem value="NOT_FRAUD">Not fraud</SelectItem>
                          <SelectItem value="INCONCLUSIVE">Inconclusive</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label>Tags (comma separated)</Label>
                    <Input
                      value={updatePayload.tags}
                      onChange={(e) => setUpdatePayload((prev) => ({ ...prev, tags: e.target.value }))}
                      placeholder="priority,market-check,follow-up"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label>Internal notes</Label>
                    <Textarea
                      rows={3}
                      value={updatePayload.internalNotes}
                      onChange={(e) => setUpdatePayload((prev) => ({ ...prev, internalNotes: e.target.value }))}
                    />
                  </div>

                  <div className="space-y-2">
                    <Label>Resolution summary</Label>
                    <Textarea
                      rows={3}
                      value={updatePayload.resolutionSummary}
                      onChange={(e) => setUpdatePayload((prev) => ({ ...prev, resolutionSummary: e.target.value }))}
                    />
                  </div>

                  <div className="flex flex-wrap gap-2">
                    <Button onClick={saveUpdates} disabled={saving} className="bg-slate-900 text-white hover:bg-slate-800">
                      {saving ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <CheckCircle2 className="mr-2 h-4 w-4" />}
                      Save updates
                    </Button>
                    <Button variant="outline" onClick={exportIncidentPdf} disabled={exportingPdf}>
                      {exportingPdf ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <FileText className="mr-2 h-4 w-4" />}
                      Export PDF
                    </Button>
                    <Button variant="outline" onClick={() => applyQuickStatus("RESOLVED")} disabled={saving}>
                      Mark resolved
                    </Button>
                    <Button variant="outline" onClick={() => applyQuickStatus("REJECTED_SPAM")} disabled={saving}>
                      Reject as spam
                    </Button>
                  </div>

                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
                    <p className="mb-2 text-sm font-semibold">Customer update</p>
                    <div className="mb-2 space-y-1 text-xs text-slate-500">
                      <p>To: {detail.customerEmail || "No customer email on file"}</p>
                      <p>Consent: {detail.consentToContact ? "Yes" : "No"}</p>
                      {canUseSystemIncidentSender ? (
                        <div className="max-w-xs">
                          <Label className="mb-1 block text-xs font-medium text-slate-600">Sender mode</Label>
                          <Select
                            value={customerSenderMode}
                            onValueChange={(value) => setCustomerSenderMode(value as "actor" | "system")}
                          >
                            <SelectTrigger className="h-8 bg-white text-xs">
                              <SelectValue placeholder="Sender mode" />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="system">System sender (superadmin mailbox)</SelectItem>
                              <SelectItem value="actor">My profile email</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                      ) : null}
                      <p>
                        From preview:{" "}
                        {customerSenderMode === "system"
                          ? "Superadmin system mailbox (server `SUPER_ADMIN_EMAIL` / SMTP sender)"
                          : user?.email || "No sender email configured"}
                      </p>
                    </div>
                    <div className="space-y-2">
                      <Input value={customerSubject} onChange={(e) => setCustomerSubject(e.target.value)} placeholder="Email subject" />
                      <Textarea rows={3} value={customerMessage} onChange={(e) => setCustomerMessage(e.target.value)} placeholder="Write update message..." />
                      <Button
                        onClick={sendCustomerUpdate}
                        disabled={
                          sendingCustomerEmail ||
                          !detail.customerEmail ||
                          !detail.consentToContact ||
                          customerSubject.trim().length < 3 ||
                          customerMessage.trim().length < 3
                        }
                        className="bg-cyan-700 text-white hover:bg-cyan-800"
                      >
                        <Mail className="mr-2 h-4 w-4" />
                        {sendingCustomerEmail ? "Sending..." : "Send update to customer"}
                      </Button>
                      {lastCustomerEmailDelivery ? (
                        <div
                          className={`rounded-md border px-3 py-2 text-xs ${
                            lastCustomerEmailDelivery.delivered
                              ? "border-emerald-200 bg-emerald-50 text-emerald-800"
                              : "border-red-200 bg-red-50 text-red-800"
                          }`}
                        >
                          <p className="font-medium">
                            {lastCustomerEmailDelivery.delivered ? "Live delivery confirmed" : "Delivery failed"}
                          </p>
                          <p>
                            Sender mode: {lastCustomerEmailDelivery.senderMode || customerSenderMode} | Used from:{" "}
                            {lastCustomerEmailDelivery.usedFrom || "—"}
                          </p>
                          <p>
                            Reply-to: {lastCustomerEmailDelivery.replyTo || "—"} | Message ID:{" "}
                            {lastCustomerEmailDelivery.providerMessageId || "—"}
                          </p>
                          {!lastCustomerEmailDelivery.delivered && lastCustomerEmailDelivery.error ? (
                            <p>Error: {lastCustomerEmailDelivery.error}</p>
                          ) : null}
                        </div>
                      ) : null}
                    </div>
                  </div>

                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
                    <p className="mb-2 text-sm font-semibold">Evidence</p>
                    <div className="flex flex-wrap items-center gap-2">
                      <Input type="file" onChange={(e) => setEvidenceFile(e.target.files?.[0] || null)} />
                      <Button onClick={uploadEvidence} disabled={!evidenceFile}>
                        <Upload className="mr-2 h-4 w-4" />
                        Upload
                      </Button>
                    </div>
                    <div className="mt-3 space-y-2">
                      {detail.evidence.length === 0 ? (
                        <p className="text-xs text-slate-500">No evidence files uploaded.</p>
                      ) : (
                        detail.evidence.map((ev) => (
                          <div key={ev.id} className="flex items-center justify-between rounded-md border bg-white px-3 py-2 text-sm">
                            <span>{ev.storageKey || `${ev.fileType || "file"} evidence`}</span>
                            {ev.storageKey ? (
                              <Button size="sm" variant="outline" onClick={() => downloadEvidence(ev.storageKey!)}>
                                <FileText className="mr-1 h-3 w-3" />
                                Download
                              </Button>
                            ) : null}
                          </div>
                        ))
                      )}
                    </div>
                  </div>

                  <div className="rounded-xl border border-slate-200 bg-white p-3">
                    <p className="mb-2 text-sm font-semibold">Timeline</p>
                    <div className="max-h-56 space-y-2 overflow-auto">
                      {detail.events.length === 0 ? (
                        <p className="text-xs text-slate-500">No timeline events yet.</p>
                      ) : (
                        detail.events.map((event) => (
                          <div key={event.id} className="rounded-md border bg-slate-50 px-3 py-2">
                            <div className="flex flex-wrap items-center gap-2 text-xs">
                              <Badge className="border-slate-300 bg-white text-slate-700">{toLabel(event.eventType)}</Badge>
                              <span className="text-slate-500">{format(new Date(event.createdAt), "PPp")}</span>
                              <span className="text-slate-500">{event.actorUser?.name || toLabel(event.actorType)}</span>
                            </div>
                            {event.eventPayload ? (
                              <p className="mt-1 text-xs text-slate-700">
                                {Object.entries(event.eventPayload)
                                  .map(([k, v]) => `${toLabel(k)}: ${payloadValueToText(v)}`)
                                  .join(" • ")}
                              </p>
                            ) : null}
                          </div>
                        ))
                      )}
                    </div>

                    <div className="mt-3 space-y-2">
                      <Textarea rows={2} value={newNote} onChange={(e) => setNewNote(e.target.value)} placeholder="Add investigation note..." />
                      <Button variant="outline" onClick={addNote} disabled={!newNote.trim()}>
                        <AlertTriangle className="mr-2 h-4 w-4" />
                        Add note
                      </Button>
                    </div>
                  </div>
                </>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </DashboardLayout>
  );
}
