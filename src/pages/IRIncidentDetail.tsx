import React, { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { formatDistanceToNow } from "date-fns";
import {
  ArrowLeft,
  CheckCircle2,
  FileDown,
  Flag,
  Loader2,
  Mail,
  RefreshCw,
  ShieldAlert,
  Upload,
} from "lucide-react";
import { saveAs } from "file-saver";

import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import apiClient from "@/lib/api-client";
import { useToast } from "@/hooks/use-toast";

const STATUS_TONE: Record<string, string> = {
  NEW: "border-red-200 bg-red-50 text-red-700",
  TRIAGE: "border-amber-200 bg-amber-50 text-amber-700",
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

const INCIDENT_STATUS_OPTIONS = [
  "NEW",
  "TRIAGE",
  "INVESTIGATING",
  "CONTAINMENT",
  "ERADICATION",
  "RECOVERY",
  "CLOSED",
  "REOPENED",
] as const;

const INCIDENT_SEVERITY_OPTIONS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;
const INCIDENT_PRIORITY_OPTIONS = ["P1", "P2", "P3", "P4"] as const;
const RESOLUTION_OUTCOME_OPTIONS = ["CONFIRMED_FRAUD", "NOT_FRAUD", "INCONCLUSIVE"] as const;

type ContainmentAction =
  | "FLAG_QR_UNDER_INVESTIGATION"
  | "UNFLAG_QR_UNDER_INVESTIGATION"
  | "SUSPEND_BATCH"
  | "REINSTATE_BATCH"
  | "SUSPEND_ORG"
  | "REINSTATE_ORG"
  | "SUSPEND_MANUFACTURER_USERS"
  | "REINSTATE_MANUFACTURER_USERS";

const ACTION_LABEL: Record<ContainmentAction, string> = {
  FLAG_QR_UNDER_INVESTIGATION: "Flag QR under investigation",
  UNFLAG_QR_UNDER_INVESTIGATION: "Remove QR investigation flag",
  SUSPEND_BATCH: "Suspend batch",
  REINSTATE_BATCH: "Reinstate batch",
  SUSPEND_ORG: "Suspend organization",
  REINSTATE_ORG: "Reinstate organization",
  SUSPEND_MANUFACTURER_USERS: "Suspend manufacturer users",
  REINSTATE_MANUFACTURER_USERS: "Reinstate manufacturer users",
};

const humanKey = (key: string) =>
  String(key || "")
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/_/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (c) => c.toUpperCase());

const humanValue = (rawValue: unknown): string => {
  if (rawValue == null || rawValue === "") return "";
  if (typeof rawValue === "boolean") return rawValue ? "Yes" : "No";
  if (Array.isArray(rawValue)) {
    return rawValue
      .map((item) => humanValue(item))
      .filter(Boolean)
      .join(", ");
  }
  if (typeof rawValue === "object") {
    const pairs = Object.entries(rawValue as Record<string, unknown>)
      .map(([key, value]) => `${humanKey(key)}: ${humanValue(value)}`)
      .filter((line) => !line.endsWith(": "));
    return pairs.join(" • ");
  }
  return String(rawValue);
};

const readableDetailEntries = (details: unknown): Array<{ label: string; value: string }> => {
  if (!details || typeof details !== "object" || Array.isArray(details)) return [];

  const entries: Array<{ label: string; value: string }> = [];
  for (const [key, value] of Object.entries(details as Record<string, unknown>)) {
    const formatted = humanValue(value);
    if (!formatted) continue;
    entries.push({ label: humanKey(key), value: formatted });
  }
  return entries;
};

export default function IRIncidentDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { toast } = useToast();

  const [loading, setLoading] = useState(false);
  const [incident, setIncident] = useState<any | null>(null);
  const [users, setUsers] = useState<any[]>([]);
  const [saving, setSaving] = useState(false);

  const [patch, setPatch] = useState({
    status: "NEW",
    severity: "MEDIUM",
    priority: "P3",
    assignedToUserId: "unassigned",
    internalNotes: "",
    tags: "",
    resolutionSummary: "",
    resolutionOutcome: "none",
  });

  const [newNote, setNewNote] = useState("");

  const [emailSubject, setEmailSubject] = useState("Update on your incident");
  const [emailBody, setEmailBody] = useState("");
  const [emailRecipient, setEmailRecipient] = useState<"reporter" | "org_admin">("reporter");
  const [sendingEmail, setSendingEmail] = useState(false);

  const [uploading, setUploading] = useState(false);
  const [attachmentFile, setAttachmentFile] = useState<File | null>(null);

  const [actionDialog, setActionDialog] = useState<{
    open: boolean;
    action: ContainmentAction | null;
    reason: string;
  }>({ open: false, action: null, reason: "" });
  const [applyingAction, setApplyingAction] = useState(false);

  const load = async () => {
    if (!id) return;
    setLoading(true);
    try {
      const res = await apiClient.getIrIncidentById(id);
      if (!res.success) {
        setIncident(null);
        toast({ title: "Load failed", description: res.error || "Could not load incident.", variant: "destructive" });
        return;
      }
      const data: any = res.data;
      setIncident(data);
      setPatch({
        status: data.status || "NEW",
        severity: data.severity || "MEDIUM",
        priority: data.priority || "P3",
        assignedToUserId: data.assignedToUserId || "unassigned",
        internalNotes: data.internalNotes || "",
        tags: Array.isArray(data.tags) ? data.tags.join(", ") : "",
        resolutionSummary: data.resolutionSummary || "",
        resolutionOutcome: data.resolutionOutcome || "none",
      });
      setEmailBody(
        `We are reviewing your report${data?.id ? ` (${data.id})` : ""}. If we need more information, we will contact you.`
      );
    } finally {
      setLoading(false);
    }
  };

  const loadUsers = async () => {
    const res = await apiClient.getUsers();
    if (!res.success) return;
    const list = (res.data as any[]) || [];
    // Only show platform admins in assignee list.
    setUsers(list.filter((u) => String(u.role || "").toUpperCase().includes("SUPER_ADMIN")));
  };

  useEffect(() => {
    load();
    loadUsers();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  const savePatch = async () => {
    if (!id || !incident) return;
    setSaving(true);
    try {
      const payload: any = {
        status: patch.status,
        severity: patch.severity,
        priority: patch.priority,
        assignedToUserId: patch.assignedToUserId !== "unassigned" ? patch.assignedToUserId : null,
        internalNotes: patch.internalNotes || null,
        resolutionSummary: patch.resolutionSummary || null,
        resolutionOutcome: patch.resolutionOutcome !== "none" ? patch.resolutionOutcome : null,
        tags: patch.tags
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
      };

      const res = await apiClient.patchIrIncident(id, payload);
      if (!res.success) {
        toast({ title: "Save failed", description: res.error || "Could not save incident.", variant: "destructive" });
        return;
      }
      toast({ title: "Saved", description: "Incident updated." });
      await load();
    } finally {
      setSaving(false);
    }
  };

  const addNote = async () => {
    if (!id) return;
    const note = newNote.trim();
    if (note.length < 2) return;
    const res = await apiClient.addIrIncidentNote(id, note);
    if (!res.success) {
      toast({ title: "Note failed", description: res.error || "Could not add note.", variant: "destructive" });
      return;
    }
    setNewNote("");
    await load();
  };

  const sendEmail = async () => {
    if (!id) return;
    if (emailSubject.trim().length < 3 || emailBody.trim().length < 1) {
      toast({ title: "Missing message", description: "Subject and message are required.", variant: "destructive" });
      return;
    }
    setSendingEmail(true);
    try {
      const res = await apiClient.sendIrIncidentCommunication(id, {
        recipient: emailRecipient,
        subject: emailSubject.trim(),
        message: emailBody.trim(),
        template: "ir_manual",
        senderMode: "system",
      });
      if (!res.success) {
        toast({ title: "Send failed", description: res.error || "Could not send email.", variant: "destructive" });
        return;
      }
      toast({ title: "Email queued", description: "Message added to the incident timeline." });
      await load();
    } finally {
      setSendingEmail(false);
    }
  };

  const uploadAttachment = async () => {
    if (!id || !attachmentFile) return;
    setUploading(true);
    try {
      const res = await apiClient.uploadIrIncidentAttachment(id, attachmentFile);
      if (!res.success) {
        toast({ title: "Upload failed", description: res.error || "Could not upload.", variant: "destructive" });
        return;
      }
      toast({ title: "Uploaded", description: "Attachment added to the incident." });
      setAttachmentFile(null);
      await load();
    } finally {
      setUploading(false);
    }
  };

  const downloadEvidence = async (storageKey: string) => {
    try {
      const blob = await apiClient.downloadIncidentEvidence(storageKey);
      saveAs(blob, storageKey);
    } catch (e: any) {
      toast({ title: "Download failed", description: e?.message || "Could not download file.", variant: "destructive" });
    }
  };

  const openAction = (action: ContainmentAction) => {
    setActionDialog({ open: true, action, reason: "" });
  };

  const applyAction = async () => {
    if (!id || !actionDialog.action) return;
    const reason = actionDialog.reason.trim();
    if (reason.length < 3) {
      toast({ title: "Reason required", description: "Add a short reason (min 3 characters).", variant: "destructive" });
      return;
    }

    setApplyingAction(true);
    try {
      const payload: any = { action: actionDialog.action, reason };

      // Help the backend resolve targets faster when present.
      if (incident?.qrCode?.id) payload.qrCodeId = incident.qrCode.id;
      if (incident?.qrCode?.batch?.id) payload.batchId = incident.qrCode.batch.id;
      if (incident?.licenseeId) payload.licenseeId = incident.licenseeId;

      const res = await apiClient.applyIrIncidentAction(id, payload);
      if (!res.success) {
        toast({ title: "Action failed", description: res.error || "Could not apply containment action.", variant: "destructive" });
        return;
      }
      toast({ title: "Action applied", description: ACTION_LABEL[actionDialog.action] });
      setActionDialog({ open: false, action: null, reason: "" });
      await load();
    } finally {
      setApplyingAction(false);
    }
  };

  const codeValue = incident?.qrCodeValue || incident?.qrCode?.code || "";

  const evidenceRows = useMemo(() => {
    const arr = Array.isArray(incident?.evidence) ? incident.evidence : [];
    return arr.filter(Boolean);
  }, [incident?.evidence]);

  const commRows = useMemo(() => {
    const arr = Array.isArray(incident?.communications) ? incident.communications : [];
    return arr.filter(Boolean);
  }, [incident?.communications]);

  const eventRows = useMemo(() => {
    const arr = Array.isArray(incident?.events) ? incident.events : [];
    return arr.filter(Boolean);
  }, [incident?.events]);

  const policyAlertRows = useMemo(() => {
    const arr = Array.isArray(incident?.policyAlerts) ? incident.policyAlerts : [];
    return arr.filter(Boolean);
  }, [incident?.policyAlerts]);

  if (!id) {
    return (
      <DashboardLayout>
        <div className="rounded-lg border p-6 text-sm text-muted-foreground">Missing incident id.</div>
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-3">
            <Button variant="outline" size="icon" onClick={() => navigate("/ir")}>
              <ArrowLeft className="h-4 w-4" />
            </Button>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h1 className="text-2xl font-bold tracking-tight">Incident {id.slice(0, 8)}</h1>
                {incident?.status ? (
                  <Badge variant="outline" className={STATUS_TONE[incident.status] || "border-slate-200 bg-slate-50 text-slate-700"}>
                    {incident.status}
                  </Badge>
                ) : null}
                {incident?.severity ? (
                  <Badge variant="outline" className={SEVERITY_TONE[incident.severity] || "border-slate-200 bg-slate-50 text-slate-700"}>
                    {incident.severity}
                  </Badge>
                ) : null}
                {incident?.priority ? <Badge variant="secondary">{incident.priority}</Badge> : null}
              </div>
              <p className="text-sm text-muted-foreground">
                {incident?.licensee ? `${incident.licensee.name} (${incident.licensee.prefix})` : "—"} ·{" "}
                {incident?.createdAt ? formatDistanceToNow(new Date(incident.createdAt), { addSuffix: true }) : "—"}
              </p>
            </div>
          </div>

          <div className="flex flex-col gap-2 sm:flex-row">
            {codeValue ? (
              <Button variant="outline" asChild>
                <Link to={`/verify/${encodeURIComponent(codeValue)}`} target="_blank" rel="noreferrer">
                  Open verify page
                </Link>
              </Button>
            ) : null}
            <Button variant="outline" onClick={load} disabled={loading}>
              <RefreshCw className="mr-2 h-4 w-4" />
              Refresh
            </Button>
          </div>
        </div>

        {loading && !incident ? (
          <div className="rounded-lg border p-6 text-sm text-muted-foreground">Loading incident...</div>
        ) : !incident ? (
          <div className="rounded-lg border p-6 text-sm text-muted-foreground">Incident not found.</div>
        ) : (
          <div className="grid gap-6 lg:grid-cols-3">
            <div className="space-y-6 lg:col-span-2">
              <Card>
                <CardHeader className="pb-4">
                  <div className="flex items-center gap-2 text-sm text-muted-foreground">
                    <ShieldAlert className="h-4 w-4" />
                    Overview
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="rounded-lg border bg-slate-50 p-3 text-sm">
                    <div className="flex flex-col gap-1 md:flex-row md:items-center md:justify-between">
                      <div>
                        <span className="text-muted-foreground">QR:</span>{" "}
                        <span className="font-mono font-semibold">{incident.qrCodeValue || "—"}</span>
                      </div>
                      <div className="text-muted-foreground">
                        {incident.incidentType ? String(incident.incidentType).replace(/_/g, " ") : ""}
                      </div>
                    </div>
                  </div>

                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="space-y-2">
                      <Label>Status</Label>
                      <Select value={patch.status} onValueChange={(v) => setPatch((p) => ({ ...p, status: v }))}>
                        <SelectTrigger>
                          <SelectValue placeholder="Status" />
                        </SelectTrigger>
                        <SelectContent>
                          {INCIDENT_STATUS_OPTIONS.map((s) => (
                            <SelectItem key={s} value={s}>
                              {s}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label>Assignee</Label>
                      <Select
                        value={patch.assignedToUserId}
                        onValueChange={(v) => setPatch((p) => ({ ...p, assignedToUserId: v }))}
                      >
                        <SelectTrigger>
                          <SelectValue placeholder="Assignee" />
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

                  <div className="grid gap-4 md:grid-cols-3">
                    <div className="space-y-2">
                      <Label>Severity</Label>
                      <Select value={patch.severity} onValueChange={(v) => setPatch((p) => ({ ...p, severity: v }))}>
                        <SelectTrigger>
                          <SelectValue placeholder="Severity" />
                        </SelectTrigger>
                        <SelectContent>
                          {INCIDENT_SEVERITY_OPTIONS.map((s) => (
                            <SelectItem key={s} value={s}>
                              {s}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>

                    <div className="space-y-2">
                      <Label>Priority</Label>
                      <Select value={patch.priority} onValueChange={(v) => setPatch((p) => ({ ...p, priority: v }))}>
                        <SelectTrigger>
                          <SelectValue placeholder="Priority" />
                        </SelectTrigger>
                        <SelectContent>
                          {INCIDENT_PRIORITY_OPTIONS.map((p) => (
                            <SelectItem key={p} value={p}>
                              {p}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>

                    <div className="space-y-2">
                      <Label>Resolution outcome</Label>
                      <Select
                        value={patch.resolutionOutcome}
                        onValueChange={(v) => setPatch((p) => ({ ...p, resolutionOutcome: v }))}
                      >
                        <SelectTrigger>
                          <SelectValue placeholder="Outcome" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="none">Not set</SelectItem>
                          {RESOLUTION_OUTCOME_OPTIONS.map((o) => (
                            <SelectItem key={o} value={o}>
                              {o}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label>Internal notes</Label>
                    <Textarea
                      value={patch.internalNotes}
                      onChange={(e) => setPatch((p) => ({ ...p, internalNotes: e.target.value }))}
                      rows={4}
                      placeholder="Internal triage notes..."
                    />
                  </div>

                  <div className="space-y-2">
                    <Label>Resolution summary</Label>
                    <Textarea
                      value={patch.resolutionSummary}
                      onChange={(e) => setPatch((p) => ({ ...p, resolutionSummary: e.target.value }))}
                      rows={3}
                      placeholder="What happened and what was done."
                    />
                  </div>

                  <div className="space-y-2">
                    <Label>Tags</Label>
                    <Input
                      value={patch.tags}
                      onChange={(e) => setPatch((p) => ({ ...p, tags: e.target.value }))}
                      placeholder="comma, separated, tags"
                    />
                  </div>

                  <div className="flex justify-end gap-2">
                    <Button type="button" variant="outline" onClick={load} disabled={saving}>
                      Reset
                    </Button>
                    <Button type="button" onClick={savePatch} disabled={saving}>
                      {saving ? (
                        <>
                          <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                          Saving...
                        </>
                      ) : (
                        <>
                          <CheckCircle2 className="mr-2 h-4 w-4" />
                          Save
                        </>
                      )}
                    </Button>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="pb-4">
                  <div className="flex items-center gap-2 text-sm text-muted-foreground">
                    <Flag className="h-4 w-4" />
                    Containment actions
                  </div>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="grid gap-2 md:grid-cols-2">
                    <Button type="button" variant="outline" onClick={() => openAction("FLAG_QR_UNDER_INVESTIGATION")}>
                      Flag QR
                    </Button>
                    <Button type="button" variant="outline" onClick={() => openAction("UNFLAG_QR_UNDER_INVESTIGATION")}>
                      Unflag QR
                    </Button>
                    <Button type="button" variant="outline" onClick={() => openAction("SUSPEND_BATCH")}>
                      Suspend batch
                    </Button>
                    <Button type="button" variant="outline" onClick={() => openAction("REINSTATE_BATCH")}>
                      Reinstate batch
                    </Button>
                    <Button type="button" variant="outline" onClick={() => openAction("SUSPEND_ORG")}>
                      Suspend org
                    </Button>
                    <Button type="button" variant="outline" onClick={() => openAction("REINSTATE_ORG")}>
                      Reinstate org
                    </Button>
                    <Button type="button" variant="outline" onClick={() => openAction("SUSPEND_MANUFACTURER_USERS")}>
                      Suspend manufacturer user
                    </Button>
                    <Button type="button" variant="outline" onClick={() => openAction("REINSTATE_MANUFACTURER_USERS")}>
                      Reinstate manufacturer user
                    </Button>
                  </div>

                  <p className="text-xs text-muted-foreground">
                    Each action is logged to the incident timeline and audit log. Reason is required.
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="pb-4">
                  <div className="flex items-center gap-2 text-sm text-muted-foreground">
                    <Mail className="h-4 w-4" />
                    Communications
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="space-y-2">
                      <Label>Recipient</Label>
                      <Select value={emailRecipient} onValueChange={(v) => setEmailRecipient(v as any)}>
                        <SelectTrigger>
                          <SelectValue placeholder="Recipient" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="reporter">Reporter</SelectItem>
                          <SelectItem value="org_admin">Org admin</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label>Subject</Label>
                      <Input value={emailSubject} onChange={(e) => setEmailSubject(e.target.value)} />
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label>Message</Label>
                    <Textarea value={emailBody} onChange={(e) => setEmailBody(e.target.value)} rows={4} />
                  </div>

                  <div className="flex justify-end">
                    <Button type="button" onClick={sendEmail} disabled={sendingEmail}>
                      {sendingEmail ? "Sending..." : "Send email"}
                    </Button>
                  </div>

                  {commRows.length === 0 ? (
                    <div className="rounded-lg border p-4 text-sm text-muted-foreground">No messages yet.</div>
                  ) : (
                    <div className="space-y-2">
                      {commRows.map((c) => (
                        <div key={c.id} className="rounded-lg border p-3 text-sm">
                          <div className="flex flex-col gap-1 md:flex-row md:items-center md:justify-between">
                            <div className="font-medium">{c.subject}</div>
                            <div className="text-xs text-muted-foreground">
                              {c.createdAt ? formatDistanceToNow(new Date(c.createdAt), { addSuffix: true }) : "—"} ·{" "}
                              {c.status}
                            </div>
                          </div>
                          <div className="mt-2 text-muted-foreground">
                            {c.bodyPreview || c.errorMessage || "—"}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>

            <div className="space-y-6">
              <Card>
                <CardHeader className="pb-4">
                  <div className="flex items-center gap-2 text-sm text-muted-foreground">
                    <Upload className="h-4 w-4" />
                    Evidence
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <Label>Upload attachment</Label>
                    <Input
                      type="file"
                      onChange={(e) => setAttachmentFile(e.target.files?.[0] || null)}
                      disabled={uploading}
                    />
                    <div className="flex justify-end">
                      <Button type="button" onClick={uploadAttachment} disabled={!attachmentFile || uploading}>
                        {uploading ? "Uploading..." : "Upload"}
                      </Button>
                    </div>
                  </div>

                  {evidenceRows.length === 0 ? (
                    <div className="rounded-lg border p-4 text-sm text-muted-foreground">No evidence uploaded.</div>
                  ) : (
                    <div className="space-y-2">
                      {evidenceRows.map((ev: any) => (
                        <div key={ev.id} className="rounded-lg border p-3 text-sm">
                          <div className="flex items-start justify-between gap-2">
                            <div>
                              <div className="font-medium">{ev.fileType || "File"}</div>
                              <div className="text-xs text-muted-foreground">
                                {ev.createdAt ? formatDistanceToNow(new Date(ev.createdAt), { addSuffix: true }) : "—"}
                              </div>
                              <div className="mt-1 font-mono text-xs text-muted-foreground break-all">
                                {ev.storageKey || ev.fileUrl || "—"}
                              </div>
                            </div>
                            {ev.storageKey ? (
                              <Button
                                type="button"
                                size="sm"
                                variant="outline"
                                onClick={() => downloadEvidence(ev.storageKey)}
                              >
                                <FileDown className="mr-2 h-4 w-4" />
                                Download
                              </Button>
                            ) : null}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="pb-4">
                  <div className="flex items-center gap-2 text-sm text-muted-foreground">
                    <ShieldAlert className="h-4 w-4" />
                    Timeline
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <Label>Add internal note</Label>
                    <Textarea value={newNote} onChange={(e) => setNewNote(e.target.value)} rows={3} placeholder="Note for investigators..." />
                    <div className="flex justify-end">
                      <Button type="button" variant="outline" onClick={addNote}>
                        Add note
                      </Button>
                    </div>
                  </div>

                  {eventRows.length === 0 ? (
                    <div className="rounded-lg border p-4 text-sm text-muted-foreground">No timeline events.</div>
                  ) : (
                    <div className="space-y-2">
                      {eventRows.map((ev: any) => {
                        const payloadEntries = readableDetailEntries(ev.eventPayload);
                        return (
                          <div key={ev.id} className="rounded-lg border p-3 text-sm">
                            <div className="flex flex-col gap-1 md:flex-row md:items-center md:justify-between">
                              <div className="font-medium">{ev.eventType}</div>
                              <div className="text-xs text-muted-foreground">
                                {ev.createdAt ? formatDistanceToNow(new Date(ev.createdAt), { addSuffix: true }) : "—"}
                              </div>
                            </div>
                            <div className="mt-1 text-xs text-muted-foreground">
                              {ev.actorUser?.email || ev.actorType}
                            </div>
                            {payloadEntries.length > 0 ? (
                              <dl className="mt-2 grid gap-1 rounded bg-slate-50 p-2 text-xs text-slate-700">
                                {payloadEntries.map((entry) => (
                                  <div key={`${ev.id}-${entry.label}`} className="grid gap-1 sm:grid-cols-[160px_1fr]">
                                    <dt className="font-medium text-slate-600">{entry.label}</dt>
                                    <dd className="break-words">{entry.value}</dd>
                                  </div>
                                ))}
                              </dl>
                            ) : null}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="pb-4">
                  <div className="flex items-center gap-2 text-sm text-muted-foreground">
                    <ShieldAlert className="h-4 w-4" />
                    Related policy alerts
                  </div>
                </CardHeader>
                <CardContent>
                  {policyAlertRows.length === 0 ? (
                    <div className="rounded-lg border p-4 text-sm text-muted-foreground">No linked alerts.</div>
                  ) : (
                    <div className="space-y-2">
                      {policyAlertRows.map((a: any) => {
                        const detailEntries = readableDetailEntries(a.details);
                        return (
                          <div key={a.id} className="rounded-lg border p-3 text-sm">
                            <div className="flex items-center justify-between gap-2">
                              <Badge variant="outline" className={SEVERITY_TONE[a.severity] || "border-slate-200 bg-slate-50 text-slate-700"}>
                                {a.severity}
                              </Badge>
                              <div className="text-xs text-muted-foreground">
                                {a.createdAt ? formatDistanceToNow(new Date(a.createdAt), { addSuffix: true }) : "—"}
                              </div>
                            </div>
                            <div className="mt-2">{a.message}</div>
                            {detailEntries.length > 0 ? (
                              <dl className="mt-2 grid gap-1 rounded bg-slate-50 p-2 text-xs text-slate-700">
                                {detailEntries.map((entry) => (
                                  <div key={`${a.id}-${entry.label}`} className="grid gap-1 sm:grid-cols-[160px_1fr]">
                                    <dt className="font-medium text-slate-600">{entry.label}</dt>
                                    <dd className="break-words">{entry.value}</dd>
                                  </div>
                                ))}
                              </dl>
                            ) : null}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          </div>
        )}
      </div>

      <Dialog
        open={actionDialog.open}
        onOpenChange={(v) => {
          if (!v) setActionDialog({ open: false, action: null, reason: "" });
        }}
      >
        <DialogContent className="sm:max-w-[620px]">
          <DialogHeader>
            <DialogTitle>{actionDialog.action ? ACTION_LABEL[actionDialog.action] : "Containment action"}</DialogTitle>
            <DialogDescription>Reason is required and will be recorded in the audit log.</DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Reason</Label>
              <Textarea
                value={actionDialog.reason}
                onChange={(e) => setActionDialog((p) => ({ ...p, reason: e.target.value }))}
                rows={4}
                placeholder="Why are you applying this action?"
              />
            </div>

            <div className="flex justify-end gap-2">
              <Button type="button" variant="outline" onClick={() => setActionDialog({ open: false, action: null, reason: "" })} disabled={applyingAction}>
                Cancel
              </Button>
              <Button type="button" onClick={applyAction} disabled={applyingAction}>
                {applyingAction ? "Applying..." : "Confirm"}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </DashboardLayout>
  );
}
