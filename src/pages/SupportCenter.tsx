import React, { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { formatDistanceToNowStrict } from "date-fns";
import { Bug, Loader2, MessageSquareText, RefreshCw, ShieldCheck, TimerReset } from "lucide-react";

import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import apiClient from "@/lib/api-client";
import { friendlyReferenceLabel, shortRawReference } from "@/lib/friendly-reference";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/contexts/AuthContext";

type SupportTicket = {
  id: string;
  referenceCode: string;
  status: "OPEN" | "IN_PROGRESS" | "WAITING_CUSTOMER" | "RESOLVED" | "CLOSED";
  priority: "P1" | "P2" | "P3" | "P4";
  subject: string;
  createdAt: string;
  updatedAt: string;
  assignedToUserId?: string | null;
  assignedToUser?: { id: string; name?: string; email?: string } | null;
  incidentId: string;
  incident?: {
    id: string;
    qrCodeValue?: string;
    status?: string;
    severity?: string;
    handoff?: { currentStage?: string | null } | null;
  } | null;
  sla?: {
    hasSla?: boolean;
    dueAt?: string;
    remainingMinutes?: number;
    isBreached?: boolean;
  } | null;
};

type SupportIssueReport = {
  id: string;
  title: string;
  description?: string | null;
  status: string;
  sourcePath?: string | null;
  pageUrl?: string | null;
  autoDetected?: boolean;
  screenshotPath?: string | null;
  createdAt: string;
  reporterUser?: { id: string; name?: string | null; email?: string | null; role?: string | null } | null;
  licensee?: { id: string; name: string; prefix: string } | null;
};

const STATUS_TONE: Record<string, string> = {
  OPEN: "border-slate-300 bg-slate-100 text-slate-700",
  IN_PROGRESS: "border-cyan-200 bg-cyan-50 text-cyan-800",
  WAITING_CUSTOMER: "border-amber-200 bg-amber-50 text-amber-800",
  RESOLVED: "border-emerald-200 bg-emerald-50 text-emerald-800",
  CLOSED: "border-slate-300 bg-slate-100 text-slate-700",
};

const PRIORITY_TONE: Record<string, string> = {
  P1: "border-red-200 bg-red-50 text-red-700",
  P2: "border-orange-200 bg-orange-50 text-orange-700",
  P3: "border-amber-200 bg-amber-50 text-amber-700",
  P4: "border-emerald-200 bg-emerald-50 text-emerald-700",
};

const toLabel = (value?: string | null) =>
  String(value || "")
    .toLowerCase()
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());

export default function SupportCenter() {
  const { user } = useAuth();
  const { toast } = useToast();
  const [searchParams] = useSearchParams();

  const [loading, setLoading] = useState(false);
  const [tickets, setTickets] = useState<SupportTicket[]>([]);
  const [issueReports, setIssueReports] = useState<SupportIssueReport[]>([]);
  const [total, setTotal] = useState(0);
  const [selectedId, setSelectedId] = useState("");
  const [detail, setDetail] = useState<any | null>(null);
  const [users, setUsers] = useState<any[]>([]);
  const [saving, setSaving] = useState(false);
  const [newMessage, setNewMessage] = useState("");

  const [filters, setFilters] = useState({
    status: "all",
    priority: "all",
    search: "",
  });

  const [editState, setEditState] = useState({
    status: "OPEN",
    assignedToUserId: "unassigned",
    isInternal: true,
  });

  const canEdit = user?.role === "super_admin";

  const loadTickets = async () => {
    setLoading(true);
    try {
      const [response, reportsResponse] = await Promise.all([
        apiClient.getSupportTickets({
          status: filters.status !== "all" ? (filters.status as any) : undefined,
          priority: filters.priority !== "all" ? (filters.priority as any) : undefined,
          search: filters.search.trim() || undefined,
          limit: 120,
        }),
        apiClient.getSupportIssueReports({ limit: 60 }),
      ]);

      if (!response.success) {
        toast({ title: "Support load failed", description: response.error || "Could not load support tickets.", variant: "destructive" });
        setTickets([]);
        return;
      }

      const payload: any = response.data || {};
      const rows = Array.isArray(payload.tickets) ? payload.tickets : [];
      setTickets(rows);
      setTotal(Number(payload.total || rows.length));

      const queryTicketId = String(searchParams.get("ticketId") || "").trim();
      if (queryTicketId) {
        const found = rows.find((row: SupportTicket) => row.id === queryTicketId);
        if (found) setSelectedId(found.id);
      }

      if (!selectedId && rows[0]?.id) {
        setSelectedId(rows[0].id);
      }

      if (reportsResponse.success) {
        const reportsPayload: any = reportsResponse.data || {};
        const reportsRows = Array.isArray(reportsPayload.reports) ? reportsPayload.reports : [];
        setIssueReports(reportsRows as SupportIssueReport[]);
      } else {
        setIssueReports([]);
      }
    } finally {
      setLoading(false);
    }
  };

  const loadDetail = async (ticketId: string) => {
    if (!ticketId) return;
    const response = await apiClient.getSupportTicket(ticketId);
    if (!response.success) {
      setDetail(null);
      return;
    }

    const data: any = response.data || null;
    setDetail(data);
    setEditState({
      status: data?.status || "OPEN",
      assignedToUserId: data?.assignedToUserId || "unassigned",
      isInternal: true,
    });
  };

  useEffect(() => {
    loadTickets();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filters.status, filters.priority]);

  useEffect(() => {
    if (!selectedId) return;
    loadDetail(selectedId);
  }, [selectedId]);

  useEffect(() => {
    if (!canEdit) return;
    apiClient.getUsers().then((res) => {
      if (!res.success) return;
      const rows = (res.data as any[]) || [];
      setUsers(rows.filter((u) => u.role === "LICENSEE_ADMIN" || u.role === "SUPER_ADMIN" || u.role === "ORG_ADMIN"));
    });
  }, [canEdit]);

  useEffect(() => {
    const reference = String(searchParams.get("reference") || "").trim();
    const incidentId = String(searchParams.get("incidentId") || "").trim();
    if (reference) setFilters((prev) => ({ ...prev, search: reference }));
    if (incidentId) setFilters((prev) => ({ ...prev, search: incidentId }));
  }, [searchParams]);

  const selected = useMemo(() => tickets.find((t) => t.id === selectedId) || null, [tickets, selectedId]);

  const saveTicket = async () => {
    if (!detail || !canEdit) return;
    setSaving(true);
    try {
      const response = await apiClient.patchSupportTicket(detail.id, {
        status: editState.status as any,
        assignedToUserId: editState.assignedToUserId !== "unassigned" ? editState.assignedToUserId : null,
      });

      if (!response.success) {
        toast({ title: "Save failed", description: response.error || "Could not update support ticket.", variant: "destructive" });
        return;
      }

      toast({ title: "Support ticket updated", description: "Status and assignment saved." });
      await loadTickets();
      await loadDetail(detail.id);
    } finally {
      setSaving(false);
    }
  };

  const sendMessage = async () => {
    if (!detail || !newMessage.trim()) return;
    const response = await apiClient.addSupportTicketMessage(detail.id, {
      message: newMessage.trim(),
      isInternal: editState.isInternal,
    });

    if (!response.success) {
      toast({ title: "Message failed", description: response.error || "Could not add support message.", variant: "destructive" });
      return;
    }

    setNewMessage("");
    await loadDetail(detail.id);
  };

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-slate-200 bg-gradient-to-r from-slate-50 via-white to-emerald-50 p-4">
          <div className="flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-emerald-200 bg-emerald-50">
              <ShieldCheck className="h-5 w-5 text-emerald-700" />
            </div>
            <div>
              <h1 className="text-3xl font-bold tracking-tight text-slate-900">Support Tickets</h1>
              <p className="text-sm text-slate-600">Track customer reports with workflow stage and SLA timing.</p>
            </div>
          </div>
          <Button variant="outline" onClick={loadTickets}>
            <RefreshCw className="mr-2 h-4 w-4" />
            Refresh
          </Button>
        </div>

        <Card>
          <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-3 border-b bg-slate-50/70">
            <div className="text-sm font-semibold">Filters</div>
            <div className="flex w-full flex-wrap gap-2 md:w-auto">
              <Input
                value={filters.search}
                onChange={(e) => setFilters((prev) => ({ ...prev, search: e.target.value }))}
                placeholder="Search by reference / incident / subject"
                className="w-full md:w-[280px]"
              />
              <Select value={filters.status} onValueChange={(value) => setFilters((prev) => ({ ...prev, status: value }))}>
                <SelectTrigger className="w-[180px]">
                  <SelectValue placeholder="Status" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All statuses</SelectItem>
                  {(["OPEN", "IN_PROGRESS", "WAITING_CUSTOMER", "RESOLVED", "CLOSED"] as const).map((status) => (
                    <SelectItem key={status} value={status}>
                      {toLabel(status)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Select value={filters.priority} onValueChange={(value) => setFilters((prev) => ({ ...prev, priority: value }))}>
                <SelectTrigger className="w-[150px]">
                  <SelectValue placeholder="Priority" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All priorities</SelectItem>
                  {(["P1", "P2", "P3", "P4"] as const).map((priority) => (
                    <SelectItem key={priority} value={priority}>
                      {priority}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button onClick={loadTickets} disabled={loading} className="bg-slate-900 text-white hover:bg-slate-800">
                {loading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                Apply
              </Button>
            </div>
          </CardHeader>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between border-b bg-slate-50/70">
            <div className="flex items-center gap-2 text-sm font-semibold">
              <Bug className="h-4 w-4 text-amber-600" />
              Incoming User Issue Reports
            </div>
            <Badge variant="outline">{issueReports.length}</Badge>
          </CardHeader>
          <CardContent className="pt-4">
            {issueReports.length === 0 ? (
              <div className="text-sm text-slate-500">No user issue reports submitted yet.</div>
            ) : (
              <div className="grid gap-3 md:grid-cols-2">
                {issueReports.slice(0, 8).map((report) => (
                  <div key={report.id} className="rounded-xl border p-3">
                    <div className="flex items-start justify-between gap-3">
                      <div className="space-y-1">
                        <p className="text-sm font-semibold leading-5">{report.title}</p>
                        <p className="text-xs text-slate-500">
                          {report.reporterUser?.name || report.reporterUser?.email || "Unknown user"}
                          {report.licensee?.name ? ` · ${report.licensee.name}` : ""}
                        </p>
                      </div>
                      <Badge variant={report.autoDetected ? "default" : "outline"}>
                        {report.autoDetected ? "Auto-captured" : "Manual"}
                      </Badge>
                    </div>
                    {report.description ? (
                      <p className="mt-2 line-clamp-2 text-xs text-slate-600">{report.description}</p>
                    ) : null}
                    <div className="mt-3 flex flex-wrap items-center gap-2 text-[11px] text-slate-500">
                      <span>{formatDistanceToNowStrict(new Date(report.createdAt), { addSuffix: true })}</span>
                      {report.sourcePath ? <span>Path: {report.sourcePath}</span> : null}
                    </div>
                    {report.screenshotPath ? (
                      <a
                        className="mt-3 inline-flex text-xs font-medium text-cyan-700 hover:underline"
                        href={apiClient.getSupportIssueScreenshotUrl(report.screenshotPath)}
                        target="_blank"
                        rel="noreferrer"
                      >
                        Open screenshot
                      </a>
                    ) : null}
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <div className="grid gap-6 xl:grid-cols-[1.1fr,1fr]">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between border-b bg-slate-50/70">
              <span className="font-semibold">Ticket Queue</span>
              <Badge variant="outline">{total} tickets</Badge>
            </CardHeader>
            <CardContent className="pt-4">
              <div className="max-h-[680px] overflow-auto rounded-lg border">
                <Table>
                  <TableHeader>
                    <TableRow className="bg-slate-50">
                      <TableHead>Reference</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Priority</TableHead>
                      <TableHead>SLA</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {tickets.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={4} className="text-slate-500">No support tickets found.</TableCell>
                      </TableRow>
                    ) : (
                      tickets.map((ticket) => (
                        <TableRow
                          key={ticket.id}
                          onClick={() => setSelectedId(ticket.id)}
                          className={ticket.id === selectedId ? "cursor-pointer bg-cyan-50/70" : "cursor-pointer"}
                        >
                          <TableCell>
                            <div className="text-xs font-semibold" title={ticket.referenceCode}>
                              {friendlyReferenceLabel(ticket.referenceCode, "Ticket")}
                            </div>
                            <div className="font-mono text-[10px] text-slate-500">{ticket.referenceCode}</div>
                            <div className="text-xs text-slate-500" title={ticket.incidentId}>
                              {friendlyReferenceLabel(ticket.incidentId, "Case")} · #{shortRawReference(ticket.incidentId, 8)}
                            </div>
                            <div className="line-clamp-1 text-xs text-slate-600">{ticket.subject}</div>
                          </TableCell>
                          <TableCell>
                            <Badge className={STATUS_TONE[ticket.status] || "border-slate-300 bg-slate-100 text-slate-700"}>{toLabel(ticket.status)}</Badge>
                          </TableCell>
                          <TableCell>
                            <Badge className={PRIORITY_TONE[ticket.priority] || "border-slate-300 bg-slate-100 text-slate-700"}>{ticket.priority}</Badge>
                          </TableCell>
                          <TableCell>
                            {ticket.sla?.hasSla ? (
                              <div className={ticket.sla?.isBreached ? "text-xs font-medium text-rose-700" : "text-xs text-slate-600"}>
                                {ticket.sla?.isBreached ? "Breached" : `${ticket.sla?.remainingMinutes || 0}m left`}
                              </div>
                            ) : (
                              <span className="text-xs text-slate-500">No SLA</span>
                            )}
                          </TableCell>
                        </TableRow>
                      ))
                    )}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between border-b bg-slate-50/70">
              <span className="font-semibold">Ticket Detail</span>
              {selected ? <Badge variant="outline">{friendlyReferenceLabel(selected.referenceCode, "Ticket")}</Badge> : null}
            </CardHeader>
            <CardContent className="space-y-4 pt-4">
              {!detail ? (
                <p className="text-sm text-slate-500">Select a support ticket to view the workflow timeline.</p>
              ) : (
                <>
                  <div className="rounded-xl border border-slate-200 bg-white p-3">
                    <div className="grid gap-2 text-sm sm:grid-cols-2">
                      <div>
                        <span className="text-slate-500">Reference</span>
                        <div className="font-semibold" title={detail.referenceCode}>
                          {friendlyReferenceLabel(detail.referenceCode, "Ticket")}
                        </div>
                        <div className="font-mono text-xs text-slate-500">{detail.referenceCode}</div>
                      </div>
                      <div>
                        <span className="text-slate-500">Incident status</span>
                        <div className="font-medium">{toLabel(detail.incident?.status)}</div>
                      </div>
                      <div>
                        <span className="text-slate-500">Workflow stage</span>
                        <div className="font-medium">{toLabel(detail.incident?.handoff?.currentStage || "intake")}</div>
                      </div>
                      <div>
                        <span className="text-slate-500">SLA</span>
                        <div className="font-medium">
                          {detail.sla?.hasSla
                            ? detail.sla?.isBreached
                              ? "Breached"
                              : `${Math.max(0, detail.sla?.remainingMinutes || 0)} minutes remaining`
                            : "No SLA"}
                        </div>
                      </div>
                    </div>
                    <p className="mt-3 text-sm text-slate-700">{detail.subject}</p>
                  </div>

                  <div className="grid gap-3 sm:grid-cols-2">
                    <div className="space-y-2">
                      <Label>Status</Label>
                      <Select value={editState.status} onValueChange={(value) => setEditState((prev) => ({ ...prev, status: value }))}>
                        <SelectTrigger>
                          <SelectValue placeholder="Status" />
                        </SelectTrigger>
                        <SelectContent>
                          {(["OPEN", "IN_PROGRESS", "WAITING_CUSTOMER", "RESOLVED", "CLOSED"] as const).map((status) => (
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
                        value={editState.assignedToUserId || "unassigned"}
                        onValueChange={(value) => setEditState((prev) => ({ ...prev, assignedToUserId: value }))}
                        disabled={!canEdit}
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

                  <div className="flex flex-wrap gap-2">
                    <Button onClick={saveTicket} disabled={!canEdit || saving} className="bg-slate-900 text-white hover:bg-slate-800">
                      {saving ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <TimerReset className="mr-2 h-4 w-4" />}
                      Save workflow update
                    </Button>
                  </div>

                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
                    <p className="mb-2 text-sm font-semibold">Ticket messages</p>
                    <div className="max-h-48 space-y-2 overflow-auto rounded-md border bg-white p-2">
                      {detail.messages?.length ? (
                        detail.messages.map((message: any) => (
                          <div key={message.id} className="rounded-md border bg-slate-50 px-2 py-1.5 text-xs">
                            <div className="flex flex-wrap items-center gap-2 text-slate-500">
                              <span className="font-medium text-slate-700">{message.actorUser?.name || toLabel(message.actorType)}</span>
                              <span>{new Date(message.createdAt).toLocaleString()}</span>
                              {message.isInternal ? <Badge variant="outline">Internal</Badge> : null}
                            </div>
                            <p className="mt-1 whitespace-pre-wrap text-slate-800">{message.message}</p>
                          </div>
                        ))
                      ) : (
                        <p className="px-2 py-3 text-xs text-slate-500">No messages yet.</p>
                      )}
                    </div>

                    <div className="mt-3 space-y-2">
                      <Textarea
                        rows={3}
                        value={newMessage}
                        onChange={(e) => setNewMessage(e.target.value)}
                        placeholder="Add handoff or customer-support note..."
                      />
                      <div className="flex flex-wrap items-center gap-3">
                        <label className="flex items-center gap-2 text-xs text-slate-600">
                          <input
                            type="checkbox"
                            checked={editState.isInternal}
                            onChange={(e) => setEditState((prev) => ({ ...prev, isInternal: e.target.checked }))}
                          />
                          Internal note
                        </label>
                        <Button onClick={sendMessage} disabled={!newMessage.trim()}>
                          <MessageSquareText className="mr-2 h-4 w-4" />
                          Add message
                        </Button>
                      </div>
                    </div>
                  </div>

                  <p className="text-xs text-slate-500">
                    Last updated {detail.updatedAt ? formatDistanceToNowStrict(new Date(detail.updatedAt), { addSuffix: true }) : "just now"}.
                  </p>
                </>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </DashboardLayout>
  );
}
