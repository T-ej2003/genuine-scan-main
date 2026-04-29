import React, { useMemo } from "react";
import { Link } from "react-router-dom";
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

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { friendlyReferenceLabel, shortRawReference } from "@/lib/friendly-reference";
import {
  decisionOutcomeTone,
  decisionRiskTone,
  decisionTrustTone,
  presentPrintTrustState,
  titleCaseDecisionValue,
} from "@/lib/verification-decision";

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

const INCIDENT_STATUS_OPTIONS = ["NEW", "TRIAGE", "INVESTIGATING", "CONTAINMENT", "ERADICATION", "RECOVERY", "CLOSED", "REOPENED"] as const;
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
    .replace(/\b\w/g, (char) => char.toUpperCase());

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

type EmailDeliverySummary = {
  delivered: boolean;
  providerMessageId?: string | null;
  attemptedFrom?: string | null;
  usedFrom?: string | null;
  replyTo?: string | null;
  error?: string | null;
};

type IRIncidentDetailWorkspaceProps = {
  id: string;
  loading: boolean;
  incident: any | null;
  users: any[];
  saving: boolean;
  patch: {
    status: string;
    severity: string;
    priority: string;
    assignedToUserId: string;
    internalNotes: string;
    tags: string;
    resolutionSummary: string;
    resolutionOutcome: string;
  };
  onPatchChange: React.Dispatch<
    React.SetStateAction<{
      status: string;
      severity: string;
      priority: string;
      assignedToUserId: string;
      internalNotes: string;
      tags: string;
      resolutionSummary: string;
      resolutionOutcome: string;
    }>
  >;
  onSavePatch: () => Promise<void> | void;
  onLoad: () => Promise<void> | void;
  onNavigateBack: () => void;
  newNote: string;
  onNewNoteChange: (value: string) => void;
  onAddNote: () => Promise<void> | void;
  emailSubject: string;
  onEmailSubjectChange: (value: string) => void;
  emailBody: string;
  onEmailBodyChange: (value: string) => void;
  emailRecipient: "reporter" | "org_admin";
  onEmailRecipientChange: (value: "reporter" | "org_admin") => void;
  sendingEmail: boolean;
  onSendEmail: () => Promise<void> | void;
  lastEmailDelivery: EmailDeliverySummary | null;
  uploading: boolean;
  attachmentFile: File | null;
  onAttachmentFileChange: (file: File | null) => void;
  onUploadAttachment: () => Promise<void> | void;
  onDownloadEvidence: (storageKey: string) => Promise<void> | void;
  onOpenAction: (action: ContainmentAction) => void;
  actionDialog: { open: boolean; action: ContainmentAction | null; reason: string };
  onActionDialogChange: React.Dispatch<
    React.SetStateAction<{ open: boolean; action: ContainmentAction | null; reason: string }>
  >;
  applyingAction: boolean;
  onApplyAction: () => Promise<void> | void;
  trustReview: {
    credentialId: string;
    reviewState: string;
    reviewNote: string;
  };
  onTrustReviewChange: React.Dispatch<
    React.SetStateAction<{
      credentialId: string;
      reviewState: string;
      reviewNote: string;
    }>
  >;
  reviewingTrust: boolean;
  onApplyTrustReview: () => Promise<void> | void;
};

export function IRIncidentDetailWorkspace({
  id,
  loading,
  incident,
  users,
  saving,
  patch,
  onPatchChange,
  onSavePatch,
  onLoad,
  onNavigateBack,
  newNote,
  onNewNoteChange,
  onAddNote,
  emailSubject,
  onEmailSubjectChange,
  emailBody,
  onEmailBodyChange,
  emailRecipient,
  onEmailRecipientChange,
  sendingEmail,
  onSendEmail,
  lastEmailDelivery,
  uploading,
  attachmentFile,
  onAttachmentFileChange,
  onUploadAttachment,
  onDownloadEvidence,
  onOpenAction,
  actionDialog,
  onActionDialogChange,
  applyingAction,
  onApplyAction,
  trustReview,
  onTrustReviewChange,
  reviewingTrust,
  onApplyTrustReview,
}: IRIncidentDetailWorkspaceProps) {
  const evidenceRows = useMemo(() => (Array.isArray(incident?.evidence) ? incident.evidence.filter(Boolean) : []), [incident?.evidence]);
  const commRows = useMemo(() => (Array.isArray(incident?.communications) ? incident.communications.filter(Boolean) : []), [incident?.communications]);
  const eventRows = useMemo(() => (Array.isArray(incident?.events) ? incident.events.filter(Boolean) : []), [incident?.events]);
  const policyAlertRows = useMemo(() => (Array.isArray(incident?.policyAlerts) ? incident.policyAlerts.filter(Boolean) : []), [incident?.policyAlerts]);
  const trustCredentialRows = useMemo(
    () => (Array.isArray(incident?.customerTrustCredentials) ? incident.customerTrustCredentials.filter(Boolean) : []),
    [incident?.customerTrustCredentials]
  );
  const codeValue = incident?.qrCodeValue || incident?.qrCode?.code || "";

  if (!incident && !loading) {
    return <div className="rounded-lg border p-6 text-sm text-muted-foreground">Incident not found.</div>;
  }

  return (
    <>
      <div className="space-y-6">
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-3">
            <Button variant="outline" size="icon" onClick={onNavigateBack}>
              <ArrowLeft className="h-4 w-4" />
            </Button>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h1 className="text-2xl font-bold tracking-tight" title={id}>
                  {friendlyReferenceLabel(id, "Case")}
                </h1>
                <span className="font-mono text-xs text-muted-foreground">#{shortRawReference(id, 8)}</span>
                {incident?.status ? <Badge variant="outline" className={STATUS_TONE[incident.status] || "border-slate-200 bg-slate-50 text-slate-700"}>{incident.status}</Badge> : null}
                {incident?.severity ? <Badge variant="outline" className={SEVERITY_TONE[incident.severity] || "border-slate-200 bg-slate-50 text-slate-700"}>{incident.severity}</Badge> : null}
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
            <Button variant="outline" onClick={onLoad} disabled={loading}>
              <RefreshCw className="mr-2 h-4 w-4" />
              Refresh
            </Button>
          </div>
        </div>

        {loading && !incident ? (
          <div className="rounded-lg border p-6 text-sm text-muted-foreground">Loading incident...</div>
        ) : incident ? (
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
                        <span className="text-muted-foreground">QR:</span> <span className="font-mono font-semibold">{incident.qrCodeValue || "—"}</span>
                      </div>
                      <div className="text-muted-foreground">{incident.incidentType ? String(incident.incidentType).replace(/_/g, " ") : ""}</div>
                    </div>
                  </div>

                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="space-y-2">
                      <Label>Status</Label>
                      <Select value={patch.status} onValueChange={(value) => onPatchChange((prev) => ({ ...prev, status: value }))}>
                        <SelectTrigger><SelectValue placeholder="Status" /></SelectTrigger>
                        <SelectContent>{INCIDENT_STATUS_OPTIONS.map((status) => <SelectItem key={status} value={status}>{status}</SelectItem>)}</SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label>Assignee</Label>
                      <Select value={patch.assignedToUserId} onValueChange={(value) => onPatchChange((prev) => ({ ...prev, assignedToUserId: value }))}>
                        <SelectTrigger><SelectValue placeholder="Assignee" /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="unassigned">Unassigned</SelectItem>
                          {users.map((user) => <SelectItem key={user.id} value={user.id}>{user.name || user.email}</SelectItem>)}
                        </SelectContent>
                      </Select>
                    </div>
                  </div>

                  <div className="grid gap-4 md:grid-cols-3">
                    <div className="space-y-2">
                      <Label>Severity</Label>
                      <Select value={patch.severity} onValueChange={(value) => onPatchChange((prev) => ({ ...prev, severity: value }))}>
                        <SelectTrigger><SelectValue placeholder="Severity" /></SelectTrigger>
                        <SelectContent>{INCIDENT_SEVERITY_OPTIONS.map((severity) => <SelectItem key={severity} value={severity}>{severity}</SelectItem>)}</SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label>Priority</Label>
                      <Select value={patch.priority} onValueChange={(value) => onPatchChange((prev) => ({ ...prev, priority: value }))}>
                        <SelectTrigger><SelectValue placeholder="Priority" /></SelectTrigger>
                        <SelectContent>{INCIDENT_PRIORITY_OPTIONS.map((priority) => <SelectItem key={priority} value={priority}>{priority}</SelectItem>)}</SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label>Resolution outcome</Label>
                      <Select value={patch.resolutionOutcome} onValueChange={(value) => onPatchChange((prev) => ({ ...prev, resolutionOutcome: value }))}>
                        <SelectTrigger><SelectValue placeholder="Outcome" /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="none">Not set</SelectItem>
                          {RESOLUTION_OUTCOME_OPTIONS.map((outcome) => <SelectItem key={outcome} value={outcome}>{outcome}</SelectItem>)}
                        </SelectContent>
                      </Select>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label>Internal notes</Label>
                    <Textarea value={patch.internalNotes} onChange={(event) => onPatchChange((prev) => ({ ...prev, internalNotes: event.target.value }))} rows={4} placeholder="Internal triage notes..." />
                  </div>

                  <div className="space-y-2">
                    <Label>Resolution summary</Label>
                    <Textarea value={patch.resolutionSummary} onChange={(event) => onPatchChange((prev) => ({ ...prev, resolutionSummary: event.target.value }))} rows={3} placeholder="What happened and what was done." />
                  </div>

                  <div className="space-y-2">
                    <Label>Tags</Label>
                    <Input value={patch.tags} onChange={(event) => onPatchChange((prev) => ({ ...prev, tags: event.target.value }))} placeholder="comma, separated, tags" />
                  </div>

                  <div className="flex justify-end gap-2">
                    <Button type="button" variant="outline" onClick={onLoad} disabled={saving}>Reset</Button>
                    <Button type="button" onClick={onSavePatch} disabled={saving}>
                      {saving ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" />Saving...</> : <><CheckCircle2 className="mr-2 h-4 w-4" />Save</>}
                    </Button>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="pb-4">
                  <div className="flex items-center gap-2 text-sm text-muted-foreground">
                    <ShieldAlert className="h-4 w-4" />
                    Verifier decision and customer trust
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  {incident?.latestDecision ? (
                    <div className="rounded-lg border bg-slate-50 p-3">
                      <div className="flex flex-wrap gap-2">
                        <Badge className={decisionOutcomeTone(incident.latestDecision.outcome)}>
                          {titleCaseDecisionValue(incident.latestDecision.outcome)}
                        </Badge>
                        <Badge className={decisionRiskTone(incident.latestDecision.riskBand)}>
                          {titleCaseDecisionValue(incident.latestDecision.riskBand)}
                        </Badge>
                        <Badge className={decisionTrustTone(incident.latestDecision.customerTrustReviewState)}>
                          {titleCaseDecisionValue(incident.latestDecision.customerTrustReviewState)}
                        </Badge>
                        <Badge className={presentPrintTrustState(incident.latestDecision).tone}>
                          {presentPrintTrustState(incident.latestDecision).label}
                        </Badge>
                      </div>
                      <div className="mt-2 text-sm text-slate-700">
                        Proof tier: {titleCaseDecisionValue(incident.latestDecision.proofTier)}.
                        {incident.latestDecision.replacementStatus && incident.latestDecision.replacementStatus !== "NONE"
                          ? ` Replacement: ${titleCaseDecisionValue(incident.latestDecision.replacementStatus)}.`
                          : ""}
                      </div>
                      <div className="mt-2 text-sm text-slate-600">{presentPrintTrustState(incident.latestDecision).guidance}</div>
                    </div>
                  ) : (
                    <div className="rounded-lg border p-4 text-sm text-muted-foreground">No verification decision has been recorded for this QR yet.</div>
                  )}

                  {trustCredentialRows.length > 0 ? (
                    <div className="space-y-4 rounded-lg border p-4">
                      <div>
                        <div className="font-medium">Team review</div>
                        <div className="text-sm text-muted-foreground">
                          Review the customer trust record linked to this QR so operator and public trust states stay aligned.
                        </div>
                      </div>

                      <div className="grid gap-4 md:grid-cols-2">
                        <div className="space-y-2">
                          <Label>Trust record</Label>
                          <Select
                            value={trustReview.credentialId || "none"}
                            onValueChange={(value) =>
                              onTrustReviewChange((previous) => ({
                                ...previous,
                                credentialId: value === "none" ? "" : value,
                              }))
                            }
                          >
                            <SelectTrigger><SelectValue placeholder="Select trust record" /></SelectTrigger>
                            <SelectContent>
                              <SelectItem value="none">Select trust record</SelectItem>
                              {trustCredentialRows.map((row: any) => (
                                <SelectItem key={row.id} value={row.id}>
                                  {row.customerEmail || row.customerUserId || row.deviceTokenHash || row.id}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        </div>
                        <div className="space-y-2">
                          <Label>Review state</Label>
                          <Select
                            value={trustReview.reviewState}
                            onValueChange={(value) =>
                              onTrustReviewChange((previous) => ({
                                ...previous,
                                reviewState: value,
                              }))
                            }
                          >
                            <SelectTrigger><SelectValue placeholder="Review state" /></SelectTrigger>
                            <SelectContent>
                              <SelectItem value="UNREVIEWED">Unreviewed</SelectItem>
                              <SelectItem value="VERIFIED">Verified</SelectItem>
                              <SelectItem value="DISPUTED">Disputed</SelectItem>
                              <SelectItem value="REVOKED">Revoked</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                      </div>

                      <div className="space-y-2">
                        <Label>Review note</Label>
                        <Textarea
                          value={trustReview.reviewNote}
                          onChange={(event) =>
                            onTrustReviewChange((previous) => ({
                              ...previous,
                              reviewNote: event.target.value,
                            }))
                          }
                          rows={3}
                          placeholder="Why was this trust state reviewed, disputed, or revoked?"
                        />
                      </div>

                      <div className="flex justify-end">
                        <Button type="button" onClick={onApplyTrustReview} disabled={reviewingTrust || !trustReview.credentialId}>
                          {reviewingTrust ? "Updating..." : "Apply trust review"}
                        </Button>
                      </div>
                    </div>
                  ) : (
                    <div className="rounded-lg border p-4 text-sm text-muted-foreground">No customer trust records exist for this QR yet.</div>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="pb-4">
                  <div className="flex items-center gap-2 text-sm text-muted-foreground">
                    <Flag className="h-4 w-4" />
                    Advanced actions
                  </div>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="grid gap-2 md:grid-cols-2">
                    <Button type="button" variant="outline" onClick={() => onOpenAction("FLAG_QR_UNDER_INVESTIGATION")}>Flag QR</Button>
                    <Button type="button" variant="outline" onClick={() => onOpenAction("UNFLAG_QR_UNDER_INVESTIGATION")}>Unflag QR</Button>
                    <Button type="button" variant="outline" onClick={() => onOpenAction("SUSPEND_BATCH")}>Suspend batch</Button>
                    <Button type="button" variant="outline" onClick={() => onOpenAction("REINSTATE_BATCH")}>Reinstate batch</Button>
                    <Button type="button" variant="outline" onClick={() => onOpenAction("SUSPEND_ORG")}>Suspend org</Button>
                    <Button type="button" variant="outline" onClick={() => onOpenAction("REINSTATE_ORG")}>Reinstate org</Button>
                    <Button type="button" variant="outline" onClick={() => onOpenAction("SUSPEND_MANUFACTURER_USERS")}>Suspend manufacturer user</Button>
                    <Button type="button" variant="outline" onClick={() => onOpenAction("REINSTATE_MANUFACTURER_USERS")}>Reinstate manufacturer user</Button>
                  </div>
                  <p className="text-xs text-muted-foreground">Each action is logged to the incident timeline and audit log. Reason is required.</p>
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
                      <Select value={emailRecipient} onValueChange={(value) => onEmailRecipientChange(value as "reporter" | "org_admin")}>
                        <SelectTrigger><SelectValue placeholder="Recipient" /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="reporter">Reporter</SelectItem>
                          <SelectItem value="org_admin">Org admin</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-2">
                      <Label>Subject</Label>
                      <Input value={emailSubject} onChange={(event) => onEmailSubjectChange(event.target.value)} />
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label>Message</Label>
                    <Textarea value={emailBody} onChange={(event) => onEmailBodyChange(event.target.value)} rows={4} />
                  </div>

                  <div className="rounded-md border border-slate-200 bg-slate-50 p-3 text-xs text-slate-600">
                    Sender mode: <span className="font-medium text-slate-800">System (superadmin mailbox)</span>
                    <div>Configure backend `SUPER_ADMIN_EMAIL=administration@mscqr.com` and valid SMTP credentials for live delivery.</div>
                  </div>

                  <div className="flex justify-end">
                    <Button type="button" onClick={onSendEmail} disabled={sendingEmail}>{sendingEmail ? "Sending..." : "Send email"}</Button>
                  </div>

                  {lastEmailDelivery ? (
                    <div className={`rounded-md border px-3 py-2 text-xs ${lastEmailDelivery.delivered ? "border-emerald-200 bg-emerald-50 text-emerald-800" : "border-red-200 bg-red-50 text-red-800"}`}>
                      <div className="font-medium">{lastEmailDelivery.delivered ? "Live delivery confirmed" : "Delivery failed"}</div>
                      <div>Used from: {lastEmailDelivery.usedFrom || "—"} | Reply-to: {lastEmailDelivery.replyTo || "—"}</div>
                      <details>
                        <summary className="cursor-pointer">Technical details</summary>
                        <div className="mt-1 break-all">Message reference: {lastEmailDelivery.providerMessageId || "—"}</div>
                      </details>
                      {!lastEmailDelivery.delivered && lastEmailDelivery.error ? <div>Error: {lastEmailDelivery.error}</div> : null}
                    </div>
                  ) : null}

                  {commRows.length === 0 ? (
                    <div className="rounded-lg border p-4 text-sm text-muted-foreground">No messages yet.</div>
                  ) : (
                    <div className="space-y-2">
                      {commRows.map((communication: any) => (
                        <div key={communication.id} className="rounded-lg border p-3 text-sm">
                          <div className="flex flex-col gap-1 md:flex-row md:items-center md:justify-between">
                            <div className="font-medium">{communication.subject}</div>
                            <div className="text-xs text-muted-foreground">
                              {communication.createdAt ? formatDistanceToNow(new Date(communication.createdAt), { addSuffix: true }) : "—"} · {communication.status}
                            </div>
                          </div>
                          <div className="mt-2 text-muted-foreground">{communication.bodyPreview || communication.errorMessage || "—"}</div>
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
                    History files
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <Label>Upload attachment</Label>
                    <Input type="file" onChange={(event) => onAttachmentFileChange(event.target.files?.[0] || null)} disabled={uploading} />
                    <div className="flex justify-end">
                      <Button type="button" onClick={onUploadAttachment} disabled={!attachmentFile || uploading}>{uploading ? "Uploading..." : "Upload"}</Button>
                    </div>
                  </div>

                  {evidenceRows.length === 0 ? (
                    <div className="rounded-lg border p-4 text-sm text-muted-foreground">No evidence uploaded.</div>
                  ) : (
                    <div className="space-y-2">
                      {evidenceRows.map((evidence: any) => (
                        <div key={evidence.id} className="rounded-lg border p-3 text-sm">
                          <div className="flex items-start justify-between gap-2">
                            <div>
                              <div className="font-medium">{evidence.fileType || "File"}</div>
                              <div className="text-xs text-muted-foreground">{evidence.createdAt ? formatDistanceToNow(new Date(evidence.createdAt), { addSuffix: true }) : "—"}</div>
                              <div className="mt-1 break-all font-mono text-xs text-muted-foreground">{evidence.storageKey || evidence.fileUrl || "—"}</div>
                            </div>
                            {evidence.storageKey ? (
                              <Button type="button" size="sm" variant="outline" onClick={() => onDownloadEvidence(evidence.storageKey)}>
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
                    <Textarea value={newNote} onChange={(event) => onNewNoteChange(event.target.value)} rows={3} placeholder="Note for investigators..." />
                    <div className="flex justify-end">
                      <Button type="button" variant="outline" onClick={onAddNote}>Add note</Button>
                    </div>
                  </div>

                  {eventRows.length === 0 ? (
                    <div className="rounded-lg border p-4 text-sm text-muted-foreground">No timeline events.</div>
                  ) : (
                    <div className="space-y-2">
                      {eventRows.map((eventRow: any) => {
                        const payloadEntries = readableDetailEntries(eventRow.eventPayload);
                        return (
                          <div key={eventRow.id} className="rounded-lg border p-3 text-sm">
                            <div className="flex flex-col gap-1 md:flex-row md:items-center md:justify-between">
                              <div className="font-medium">{eventRow.eventType}</div>
                              <div className="text-xs text-muted-foreground">{eventRow.createdAt ? formatDistanceToNow(new Date(eventRow.createdAt), { addSuffix: true }) : "—"}</div>
                            </div>
                            <div className="mt-1 text-xs text-muted-foreground">{eventRow.actorUser?.email || eventRow.actorType}</div>
                            {payloadEntries.length > 0 ? (
                              <dl className="mt-2 grid gap-1 rounded bg-slate-50 p-2 text-xs text-slate-700">
                                {payloadEntries.map((entry) => (
                                  <div key={`${eventRow.id}-${entry.label}`} className="grid gap-1 sm:grid-cols-[160px_1fr]">
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
                      {policyAlertRows.map((alert: any) => {
                        const detailEntries = readableDetailEntries(alert.details);
                        return (
                          <div key={alert.id} className="rounded-lg border p-3 text-sm">
                            <div className="flex items-center justify-between gap-2">
                              <Badge variant="outline" className={SEVERITY_TONE[alert.severity] || "border-slate-200 bg-slate-50 text-slate-700"}>{alert.severity}</Badge>
                              <div className="text-xs text-muted-foreground">{alert.createdAt ? formatDistanceToNow(new Date(alert.createdAt), { addSuffix: true }) : "—"}</div>
                            </div>
                            <div className="mt-2">{alert.message}</div>
                            {detailEntries.length > 0 ? (
                              <dl className="mt-2 grid gap-1 rounded bg-slate-50 p-2 text-xs text-slate-700">
                                {detailEntries.map((entry) => (
                                  <div key={`${alert.id}-${entry.label}`} className="grid gap-1 sm:grid-cols-[160px_1fr]">
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
        ) : null}
      </div>

      <Dialog
        open={actionDialog.open}
        onOpenChange={(open) => {
          if (!open) onActionDialogChange({ open: false, action: null, reason: "" });
        }}
      >
        <DialogContent className="sm:max-w-[620px]">
          <DialogHeader>
            <DialogTitle>{actionDialog.action ? ACTION_LABEL[actionDialog.action] : "Advanced action"}</DialogTitle>
            <DialogDescription>Reason is required and will be recorded in the audit log.</DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Reason</Label>
              <Textarea value={actionDialog.reason} onChange={(event) => onActionDialogChange((prev) => ({ ...prev, reason: event.target.value }))} rows={4} placeholder="Why are you applying this action?" />
            </div>

            <div className="flex justify-end gap-2">
              <Button type="button" variant="outline" onClick={() => onActionDialogChange({ open: false, action: null, reason: "" })} disabled={applyingAction}>Cancel</Button>
              <Button type="button" onClick={onApplyAction} disabled={applyingAction}>{applyingAction ? "Applying..." : "Confirm"}</Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
