import type { Dispatch, SetStateAction } from "react";
import { format } from "date-fns";
import { AlertTriangle, CheckCircle2, FileText, Filter, Loader2, Mail, RefreshCw, Search, ShieldAlert, Upload } from "lucide-react";

import { friendlyReferenceLabel, shortRawReference } from "@/lib/friendly-reference";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";

import {
  incidentPayloadValueToText,
  IncidentDetail,
  IncidentEmailDeliveryInfo,
  IncidentFiltersState,
  INCIDENT_SEVERITY_TONE,
  INCIDENT_STATUS_TONE,
  IncidentRow,
  IncidentUpdatePayload,
  toIncidentLabel,
} from "../types";

type UserOption = { id: string; name?: string | null; email?: string | null; role?: string };
type LicenseeOption = { id: string; name: string };

type Props = {
  userRole?: string | null;
  userEmail?: string | null;
  loading: boolean;
  filters: IncidentFiltersState;
  setFilters: Dispatch<SetStateAction<IncidentFiltersState>>;
  licensees: LicenseeOption[];
  incidents: IncidentRow[];
  selectedId: string;
  setSelectedId: Dispatch<SetStateAction<string>>;
  selectedIncident: IncidentRow | null;
  detail: IncidentDetail | null;
  updatePayload: IncidentUpdatePayload;
  setUpdatePayload: Dispatch<SetStateAction<IncidentUpdatePayload>>;
  users: UserOption[];
  saving: boolean;
  onRefresh: () => Promise<void> | void;
  onSaveUpdates: () => Promise<void> | void;
  onQuickStatus: (status: "RESOLVED" | "REJECTED_SPAM") => Promise<void> | void;
  exportingPdf: boolean;
  onExportPdf: () => Promise<void> | void;
  canUseSystemIncidentSender: boolean;
  customerSenderMode: "actor" | "system";
  setCustomerSenderMode: Dispatch<SetStateAction<"actor" | "system">>;
  customerSubject: string;
  setCustomerSubject: Dispatch<SetStateAction<string>>;
  customerMessage: string;
  setCustomerMessage: Dispatch<SetStateAction<string>>;
  sendingCustomerEmail: boolean;
  lastCustomerEmailDelivery: IncidentEmailDeliveryInfo | null;
  onSendCustomerUpdate: () => Promise<void> | void;
  evidenceFile: File | null;
  setEvidenceFile: Dispatch<SetStateAction<File | null>>;
  onUploadEvidence: () => Promise<void> | void;
  onDownloadEvidence: (storageKey: string) => Promise<void> | void;
  newNote: string;
  setNewNote: Dispatch<SetStateAction<string>>;
  onAddNote: () => Promise<void> | void;
};

export function IncidentResponseWorkspace({
  userRole,
  userEmail,
  loading,
  filters,
  setFilters,
  licensees,
  incidents,
  selectedId,
  setSelectedId,
  selectedIncident,
  detail,
  updatePayload,
  setUpdatePayload,
  users,
  saving,
  onRefresh,
  onSaveUpdates,
  onQuickStatus,
  exportingPdf,
  onExportPdf,
  canUseSystemIncidentSender,
  customerSenderMode,
  setCustomerSenderMode,
  customerSubject,
  setCustomerSubject,
  customerMessage,
  setCustomerMessage,
  sendingCustomerEmail,
  lastCustomerEmailDelivery,
  onSendCustomerUpdate,
  evidenceFile,
  setEvidenceFile,
  onUploadEvidence,
  onDownloadEvidence,
  newNote,
  setNewNote,
  onAddNote,
}: Props) {
  return (
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
        <Button variant="outline" onClick={() => void onRefresh()}>
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
          {userRole === "super_admin" ? (
            <Select value={filters.licenseeId} onValueChange={(value) => setFilters((prev) => ({ ...prev, licenseeId: value }))}>
              <SelectTrigger>
                <SelectValue placeholder="Licensee" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All licensees</SelectItem>
                {licensees.map((licensee) => (
                  <SelectItem key={licensee.id} value={licensee.id}>
                    {licensee.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          ) : null}

          <Select value={filters.status} onValueChange={(value) => setFilters((prev) => ({ ...prev, status: value }))}>
            <SelectTrigger>
              <SelectValue placeholder="Status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All statuses</SelectItem>
              {["NEW", "TRIAGED", "INVESTIGATING", "AWAITING_CUSTOMER", "AWAITING_LICENSEE", "MITIGATED", "RESOLVED", "CLOSED", "REJECTED_SPAM"].map((status) => (
                <SelectItem key={status} value={status}>
                  {toIncidentLabel(status)}
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
                  {toIncidentLabel(severity)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <div className="space-y-1">
            <Label className="text-xs font-medium text-slate-600">From date</Label>
            <Input type="date" value={filters.dateFrom} onChange={(e) => setFilters((prev) => ({ ...prev, dateFrom: e.target.value }))} />
          </div>
          <div className="space-y-1">
            <Label className="text-xs font-medium text-slate-600">To date</Label>
            <Input type="date" value={filters.dateTo} onChange={(e) => setFilters((prev) => ({ ...prev, dateTo: e.target.value }))} />
          </div>
          <Button onClick={() => void onRefresh()} disabled={loading} className="bg-slate-900 text-white hover:bg-slate-800">
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
                        className={item.id === selectedId ? "cursor-pointer bg-cyan-50/60" : "cursor-pointer"}
                      >
                        <TableCell>
                          <div className="text-xs font-semibold" title={item.id}>
                            {friendlyReferenceLabel(item.id, "Case")}
                          </div>
                          <div className="font-mono text-[10px] text-slate-500">#{shortRawReference(item.id, 8)}</div>
                          <div className="text-sm text-slate-700">{item.qrCodeValue}</div>
                          <div className="text-xs text-slate-500">{item.locationName || "Location unknown"}</div>
                        </TableCell>
                        <TableCell className="text-sm text-slate-700">{toIncidentLabel(item.incidentType)}</TableCell>
                        <TableCell>
                          <Badge className={INCIDENT_SEVERITY_TONE[item.severity] || "border-slate-300 bg-slate-100 text-slate-700"}>
                            {toIncidentLabel(item.severity)}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Badge className={INCIDENT_STATUS_TONE[item.status] || "border-slate-300 bg-slate-100 text-slate-700"}>
                            {toIncidentLabel(item.status)}
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
              <Badge className={INCIDENT_STATUS_TONE[selectedIncident.status] || "border-slate-300 bg-slate-100 text-slate-700"}>
                {toIncidentLabel(selectedIncident.status)}
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
                      <span className="text-slate-500">Code</span>
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
                      <div>{toIncidentLabel(detail.handoff?.currentStage || "INTAKE")}</div>
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
                    <Select value={updatePayload.status} onValueChange={(value) => setUpdatePayload((prev) => ({ ...prev, status: value }))}>
                      <SelectTrigger>
                        <SelectValue placeholder="Status" />
                      </SelectTrigger>
                      <SelectContent>
                        {["NEW", "TRIAGED", "INVESTIGATING", "AWAITING_CUSTOMER", "AWAITING_LICENSEE", "MITIGATED", "RESOLVED", "CLOSED", "REJECTED_SPAM"].map((status) => (
                          <SelectItem key={status} value={status}>
                            {toIncidentLabel(status)}
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
                        {users.map((userOption) => (
                          <SelectItem key={userOption.id} value={userOption.id}>
                            {userOption.name || userOption.email}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="space-y-2">
                    <Label>Severity</Label>
                    <Select value={updatePayload.severity} onValueChange={(value) => setUpdatePayload((prev) => ({ ...prev, severity: value }))}>
                      <SelectTrigger>
                        <SelectValue placeholder="Severity" />
                      </SelectTrigger>
                      <SelectContent>
                        {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((severity) => (
                          <SelectItem key={severity} value={severity}>
                            {toIncidentLabel(severity)}
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
                  <Textarea rows={3} value={updatePayload.internalNotes} onChange={(e) => setUpdatePayload((prev) => ({ ...prev, internalNotes: e.target.value }))} />
                </div>

                <div className="space-y-2">
                  <Label>Resolution summary</Label>
                  <Textarea rows={3} value={updatePayload.resolutionSummary} onChange={(e) => setUpdatePayload((prev) => ({ ...prev, resolutionSummary: e.target.value }))} />
                </div>

                <div className="flex flex-wrap gap-2">
                  <Button onClick={() => void onSaveUpdates()} disabled={saving} className="bg-slate-900 text-white hover:bg-slate-800">
                    {saving ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <CheckCircle2 className="mr-2 h-4 w-4" />}
                    Save updates
                  </Button>
                  <Button variant="outline" onClick={() => void onExportPdf()} disabled={exportingPdf}>
                    {exportingPdf ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <FileText className="mr-2 h-4 w-4" />}
                    Export PDF
                  </Button>
                  <Button variant="outline" onClick={() => void onQuickStatus("RESOLVED")} disabled={saving}>
                    Mark resolved
                  </Button>
                  <Button variant="outline" onClick={() => void onQuickStatus("REJECTED_SPAM")} disabled={saving}>
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
                        <Select value={customerSenderMode} onValueChange={(value) => setCustomerSenderMode(value as "actor" | "system")}>
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
                        : userEmail || "No sender email configured"}
                    </p>
                  </div>
                  <div className="space-y-2">
                    <Input value={customerSubject} onChange={(e) => setCustomerSubject(e.target.value)} placeholder="Email subject" />
                    <Textarea rows={3} value={customerMessage} onChange={(e) => setCustomerMessage(e.target.value)} placeholder="Write update message..." />
                    <Button
                      onClick={() => void onSendCustomerUpdate()}
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
                    <Button onClick={() => void onUploadEvidence()} disabled={!evidenceFile}>
                      <Upload className="mr-2 h-4 w-4" />
                      Upload
                    </Button>
                  </div>
                  <div className="mt-3 space-y-2">
                    {detail.evidence.length === 0 ? (
                      <p className="text-xs text-slate-500">No evidence files uploaded.</p>
                    ) : (
                      detail.evidence.map((evidence) => (
                        <div key={evidence.id} className="flex items-center justify-between rounded-md border bg-white px-3 py-2 text-sm">
                          <span>{evidence.storageKey || `${evidence.fileType || "file"} evidence`}</span>
                          {evidence.storageKey ? (
                            <Button size="sm" variant="outline" onClick={() => void onDownloadEvidence(evidence.storageKey!)}>
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
                            <Badge className="border-slate-300 bg-white text-slate-700">{toIncidentLabel(event.eventType)}</Badge>
                            <span className="text-slate-500">{format(new Date(event.createdAt), "PPp")}</span>
                            <span className="text-slate-500">{event.actorUser?.name || toIncidentLabel(event.actorType)}</span>
                          </div>
                          {event.eventPayload ? (
                            <p className="mt-1 text-xs text-slate-700">
                              {Object.entries(event.eventPayload)
                                .map(([key, value]) => `${toIncidentLabel(key)}: ${incidentPayloadValueToText(value)}`)
                                .join(" • ")}
                            </p>
                          ) : null}
                        </div>
                      ))
                    )}
                  </div>

                  <div className="mt-3 space-y-2">
                    <Textarea rows={2} value={newNote} onChange={(e) => setNewNote(e.target.value)} placeholder="Add investigation note..." />
                    <Button variant="outline" onClick={() => void onAddNote()} disabled={!newNote.trim()}>
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
  );
}
