import { useEffect, useMemo, useState } from "react";
import { Bug, Loader2, MessageSquareText, RefreshCw, Send, ShieldCheck, TimerReset } from "lucide-react";
import { useSearchParams } from "react-router-dom";
import { formatDistanceToNowStrict } from "date-fns";

import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { DataTablePagePattern, PageEmptyState, PageInlineNotice, PageSection } from "@/components/page-patterns/PagePatterns";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { useAuth } from "@/contexts/AuthContext";
import {
  PRIORITY_TONE,
  STATUS_TONE,
  SUPPORT_PRIORITIES,
  SUPPORT_STATUSES,
  toLabel,
  type SupportIssueReport,
  type SupportQueueFilters,
} from "@/features/support/types";
import {
  useAddSupportTicketMessageMutation,
  useRespondToIssueReportMutation,
  useSupportAssignableUsers,
  useSupportIssueReports,
  useSupportTicketDetail,
  useSupportTickets,
  useUpdateSupportTicketMutation,
} from "@/features/support/hooks";
import { friendlyReferenceLabel, shortRawReference } from "@/lib/friendly-reference";
import apiClient from "@/lib/api-client";
import { useToast } from "@/hooks/use-toast";

const DEFAULT_FILTERS: SupportQueueFilters = {
  status: "all",
  priority: "all",
  search: "",
};

export default function SupportCenterPage() {
  const { user } = useAuth();
  const { toast } = useToast();
  const [searchParams] = useSearchParams();

  const canEdit = user?.role === "super_admin";

  const [draftFilters, setDraftFilters] = useState<SupportQueueFilters>(DEFAULT_FILTERS);
  const [appliedFilters, setAppliedFilters] = useState<SupportQueueFilters>(DEFAULT_FILTERS);
  const [selectedId, setSelectedId] = useState("");
  const [newMessage, setNewMessage] = useState("");
  const [issueReplyDrafts, setIssueReplyDrafts] = useState<Record<string, string>>({});
  const [editState, setEditState] = useState({
    status: "OPEN",
    assignedToUserId: "unassigned",
    isInternal: true,
  });

  useEffect(() => {
    const reference = String(searchParams.get("reference") || "").trim();
    const incidentId = String(searchParams.get("incidentId") || "").trim();
    const seededSearch = reference || incidentId || "";
    if (!seededSearch) return;

    setDraftFilters((prev) => ({ ...prev, search: seededSearch }));
    setAppliedFilters((prev) => ({ ...prev, search: seededSearch }));
  }, [searchParams]);

  const ticketsQuery = useSupportTickets(appliedFilters);
  const reportsQuery = useSupportIssueReports();
  const detailQuery = useSupportTicketDetail(selectedId);
  const assigneesQuery = useSupportAssignableUsers(canEdit);

  const updateTicketMutation = useUpdateSupportTicketMutation();
  const addMessageMutation = useAddSupportTicketMessageMutation();
  const respondToReportMutation = useRespondToIssueReportMutation();

  const tickets = ticketsQuery.data?.tickets || [];
  const total = ticketsQuery.data?.total || 0;
  const issueReports = reportsQuery.data?.reports || [];

  useEffect(() => {
    if (tickets.length === 0) {
      setSelectedId("");
      return;
    }

    const queryTicketId = String(searchParams.get("ticketId") || "").trim();
    if (queryTicketId) {
      const found = tickets.find((ticket) => ticket.id === queryTicketId);
      if (found) {
        setSelectedId(found.id);
        return;
      }
    }

    setSelectedId((current) => {
      if (current && tickets.some((ticket) => ticket.id === current)) return current;
      return tickets[0].id;
    });
  }, [searchParams, tickets]);

  useEffect(() => {
    if (!detailQuery.data) return;
    setEditState({
      status: detailQuery.data.status || "OPEN",
      assignedToUserId: detailQuery.data.assignedToUserId || "unassigned",
      isInternal: true,
    });
  }, [detailQuery.data]);

  const selected = useMemo(() => tickets.find((ticket) => ticket.id === selectedId) || null, [tickets, selectedId]);

  const refreshAll = async () => {
    await Promise.all([ticketsQuery.refetch(), reportsQuery.refetch(), detailQuery.refetch()]);
  };

  const saveTicket = async () => {
    if (!detailQuery.data || !canEdit) return;

    try {
      await updateTicketMutation.mutateAsync({
        ticketId: detailQuery.data.id,
        status: editState.status as typeof detailQuery.data.status,
        assignedToUserId: editState.assignedToUserId !== "unassigned" ? editState.assignedToUserId : null,
      });

      toast({
        title: "Support ticket updated",
        description: "Status and assignment saved.",
      });
      await detailQuery.refetch();
    } catch (error) {
      toast({
        title: "Save failed",
        description: error instanceof Error ? error.message : "Could not update support ticket.",
        variant: "destructive",
      });
    }
  };

  const sendMessage = async () => {
    if (!detailQuery.data || !newMessage.trim()) return;

    try {
      await addMessageMutation.mutateAsync({
        ticketId: detailQuery.data.id,
        message: newMessage.trim(),
        isInternal: editState.isInternal,
      });
      setNewMessage("");
      await detailQuery.refetch();
    } catch (error) {
      toast({
        title: "Message failed",
        description: error instanceof Error ? error.message : "Could not add support message.",
        variant: "destructive",
      });
    }
  };

  const respondToIssueReport = async (report: SupportIssueReport) => {
    const message = String(issueReplyDrafts[report.id] || "").trim();
    if (!message) {
      toast({
        title: "Response required",
        description: "Enter the reply that should be sent to the reporting user.",
        variant: "destructive",
      });
      return;
    }

    try {
      await respondToReportMutation.mutateAsync({
        reportId: report.id,
        message,
      });
      toast({
        title: "Reporter notified",
        description: "The response was sent through both in-app notification and email.",
      });
      setIssueReplyDrafts((prev) => ({ ...prev, [report.id]: "" }));
    } catch (error) {
      toast({
        title: "Response failed",
        description: error instanceof Error ? error.message : "Could not send support response.",
        variant: "destructive",
      });
    }
  };

  const actions = (
    <Button variant="outline" onClick={() => void refreshAll()} disabled={ticketsQuery.isFetching || reportsQuery.isFetching}>
      <RefreshCw className="mr-2 h-4 w-4" />
      {ticketsQuery.isFetching || reportsQuery.isFetching ? "Refreshing..." : "Refresh"}
    </Button>
  );

  const filters = (
    <div className="flex flex-wrap gap-2">
      <Input
        data-testid="support-search-input"
        value={draftFilters.search}
        onChange={(event) => setDraftFilters((prev) => ({ ...prev, search: event.target.value }))}
        placeholder="Search by reference, incident, or subject"
        className="w-full md:w-[320px]"
      />
      <Select value={draftFilters.status} onValueChange={(value) => setDraftFilters((prev) => ({ ...prev, status: value as SupportQueueFilters["status"] }))}>
        <SelectTrigger data-testid="support-status-filter" className="w-[180px]">
          <SelectValue placeholder="Status" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All statuses</SelectItem>
          {SUPPORT_STATUSES.map((status) => (
            <SelectItem key={status} value={status}>
              {toLabel(status)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <Select value={draftFilters.priority} onValueChange={(value) => setDraftFilters((prev) => ({ ...prev, priority: value as SupportQueueFilters["priority"] }))}>
        <SelectTrigger data-testid="support-priority-filter" className="w-[150px]">
          <SelectValue placeholder="Priority" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All priorities</SelectItem>
          {SUPPORT_PRIORITIES.map((priority) => (
            <SelectItem key={priority} value={priority}>
              {priority}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <Button
        data-testid="support-apply-filters"
        onClick={() => setAppliedFilters(draftFilters)}
        disabled={ticketsQuery.isFetching}
      >
        {ticketsQuery.isFetching ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
        Apply
      </Button>
    </div>
  );

  return (
    <DashboardLayout>
      <DataTablePagePattern
        eyebrow="Operations"
        title="Support"
        description="Work the support inbox, respond to incoming issue reports, and keep every ticket moving to the next clear action."
        actions={actions}
        filters={filters}
      >
        {ticketsQuery.error ? (
          <PageInlineNotice
            variant="destructive"
            title="Could not load support tickets"
            description={ticketsQuery.error instanceof Error ? ticketsQuery.error.message : "Please refresh and try again."}
          />
        ) : null}

        <PageSection
          title="Incoming issue reports"
          description="Respond to newly reported issues without leaving the support workspace."
          action={<Badge variant="outline">{issueReports.length}</Badge>}
        >
          {reportsQuery.isLoading ? (
            <div className="text-sm text-muted-foreground">Loading issue reports...</div>
          ) : issueReports.length === 0 ? (
            <PageEmptyState
              title="No incoming issue reports"
              description="When a user submits a support issue from the app, it will appear here."
            />
          ) : (
            <div className="grid gap-3 md:grid-cols-2">
              {issueReports.slice(0, 8).map((report) => (
                <div key={report.id} className="rounded-2xl border p-4">
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1">
                      <p className="text-sm font-semibold leading-5">{report.title}</p>
                      <p className="text-xs text-muted-foreground">
                        {report.reporterUser?.name || report.reporterUser?.email || "Unknown user"}
                        {report.licensee?.name ? ` · ${report.licensee.name}` : ""}
                      </p>
                    </div>
                    <div className="flex flex-col items-end gap-2">
                      <Badge variant={report.autoDetected ? "default" : "outline"}>
                        {report.autoDetected ? "Auto-captured" : "Manual"}
                      </Badge>
                      <Badge variant="outline">{toLabel(report.status)}</Badge>
                    </div>
                  </div>

                  {report.description ? <p className="mt-2 line-clamp-2 text-xs text-muted-foreground">{report.description}</p> : null}

                  <div className="mt-3 flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
                    <span>{formatDistanceToNowStrict(new Date(report.createdAt), { addSuffix: true })}</span>
                    {report.sourcePath ? <span>Path: {report.sourcePath}</span> : null}
                  </div>

                  {report.screenshotPath ? (
                    <a
                      className="mt-3 inline-flex text-xs font-medium text-primary hover:underline"
                      href={apiClient.getSupportIssueScreenshotUrl(report.screenshotPath)}
                      rel="noreferrer"
                      target="_blank"
                    >
                      Open screenshot
                    </a>
                  ) : null}

                  {report.responseMessage ? (
                    <div className="mt-3 rounded-lg border border-emerald-200 bg-emerald-50/70 p-3">
                      <div className="flex flex-wrap items-center gap-2 text-[11px] text-emerald-800">
                        <span className="font-semibold">Latest response sent</span>
                        {report.respondedByUser?.name || report.respondedByUser?.email ? (
                          <span>by {report.respondedByUser?.name || report.respondedByUser?.email}</span>
                        ) : null}
                        {report.respondedAt ? (
                          <span>{formatDistanceToNowStrict(new Date(report.respondedAt), { addSuffix: true })}</span>
                        ) : null}
                      </div>
                      <p className="mt-2 whitespace-pre-wrap text-xs text-slate-700">{report.responseMessage}</p>
                    </div>
                  ) : null}

                  {canEdit ? (
                    <div className="mt-3 space-y-2 rounded-lg border bg-muted/30 p-3">
                      <Label htmlFor={`issue-response-${report.id}`} className="text-xs font-semibold">
                        Respond to reporter
                      </Label>
                      <Textarea
                        id={`issue-response-${report.id}`}
                        rows={3}
                        value={issueReplyDrafts[report.id] ?? ""}
                        onChange={(event) =>
                          setIssueReplyDrafts((prev) => ({
                            ...prev,
                            [report.id]: event.target.value,
                          }))
                        }
                        placeholder="Send remediation guidance, status update, or next step."
                      />
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <p className="text-[11px] text-muted-foreground">
                          This reply is delivered through email and the reporter&apos;s notification feed.
                        </p>
                        <Button
                          size="sm"
                          onClick={() => void respondToIssueReport(report)}
                          disabled={respondToReportMutation.isPending && respondToReportMutation.variables?.reportId === report.id}
                        >
                          {respondToReportMutation.isPending && respondToReportMutation.variables?.reportId === report.id ? (
                            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                          ) : (
                            <Send className="mr-2 h-4 w-4" />
                          )}
                          {report.responseMessage ? "Update response" : "Send response"}
                        </Button>
                      </div>
                    </div>
                  ) : null}
                </div>
              ))}
            </div>
          )}
        </PageSection>

        <PageSection
          title="Support inbox"
          description="Select a ticket on the left, then update its workflow, assignee, and messages on the right."
          action={<Badge variant="outline">{total} tickets</Badge>}
        >
          <div className="grid gap-6 xl:grid-cols-[1.05fr,1fr]">
            <div className="rounded-2xl border">
              <div className="border-b px-5 py-4 text-sm font-semibold">Ticket queue</div>
              <div className="max-h-[680px] overflow-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Reference</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Priority</TableHead>
                      <TableHead>SLA</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {tickets.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={4} className="text-muted-foreground">No support tickets found.</TableCell>
                      </TableRow>
                    ) : (
                      tickets.map((ticket) => (
                        <TableRow
                          data-testid="support-ticket-row"
                          key={ticket.id}
                          onClick={() => setSelectedId(ticket.id)}
                          className={ticket.id === selectedId ? "cursor-pointer bg-cyan-50/70" : "cursor-pointer"}
                        >
                          <TableCell>
                            <div className="text-xs font-semibold" title={ticket.referenceCode}>
                              {friendlyReferenceLabel(ticket.referenceCode, "Ticket")}
                            </div>
                            <div className="font-mono text-[10px] text-muted-foreground">{ticket.referenceCode}</div>
                            <div className="text-xs text-muted-foreground" title={ticket.incidentId}>
                              {friendlyReferenceLabel(ticket.incidentId, "Case")} · #{shortRawReference(ticket.incidentId, 8)}
                            </div>
                            <div className="line-clamp-1 text-xs text-slate-600">{ticket.subject}</div>
                          </TableCell>
                          <TableCell>
                            <Badge className={STATUS_TONE[ticket.status] || STATUS_TONE.OPEN}>{toLabel(ticket.status)}</Badge>
                          </TableCell>
                          <TableCell>
                            <Badge className={PRIORITY_TONE[ticket.priority] || PRIORITY_TONE.P3}>{ticket.priority}</Badge>
                          </TableCell>
                          <TableCell>
                            {ticket.sla?.hasSla ? (
                              <div className={ticket.sla?.isBreached ? "text-xs font-medium text-rose-700" : "text-xs text-muted-foreground"}>
                                {ticket.sla?.isBreached ? "Breached" : `${ticket.sla?.remainingMinutes || 0}m left`}
                              </div>
                            ) : (
                              <span className="text-xs text-muted-foreground">No SLA</span>
                            )}
                          </TableCell>
                        </TableRow>
                      ))
                    )}
                  </TableBody>
                </Table>
              </div>
            </div>

            <div className="rounded-2xl border bg-card p-5">
              {!detailQuery.data ? (
                <PageEmptyState
                  title={ticketsQuery.isLoading ? "Loading ticket detail" : "Select a support ticket"}
                  description="Choose a ticket from the queue to review workflow status, SLA, and message history."
                />
              ) : (
                <div className="space-y-4">
                  <div className="rounded-xl border bg-muted/20 p-4">
                    <div className="grid gap-3 text-sm sm:grid-cols-2">
                      <div>
                        <span className="text-muted-foreground">Reference</span>
                        <div className="font-semibold" title={detailQuery.data.referenceCode}>
                          {friendlyReferenceLabel(detailQuery.data.referenceCode, "Ticket")}
                        </div>
                        <div className="font-mono text-xs text-muted-foreground">{detailQuery.data.referenceCode}</div>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Incident status</span>
                        <div className="font-medium">{toLabel(detailQuery.data.incident?.status)}</div>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Workflow stage</span>
                        <div className="font-medium">{toLabel(detailQuery.data.incident?.handoff?.currentStage || "intake")}</div>
                      </div>
                      <div>
                        <span className="text-muted-foreground">SLA</span>
                        <div className="font-medium">
                          {detailQuery.data.sla?.hasSla
                            ? detailQuery.data.sla?.isBreached
                              ? "Breached"
                              : `${Math.max(0, detailQuery.data.sla?.remainingMinutes || 0)} minutes remaining`
                            : "No SLA"}
                        </div>
                      </div>
                    </div>
                    <p className="mt-3 text-sm text-slate-700">{detailQuery.data.subject}</p>
                  </div>

                  <div className="grid gap-3 sm:grid-cols-2">
                    <div className="space-y-2">
                      <Label>Status</Label>
                      <Select value={editState.status} onValueChange={(value) => setEditState((prev) => ({ ...prev, status: value }))}>
                        <SelectTrigger data-testid="support-ticket-status">
                          <SelectValue placeholder="Status" />
                        </SelectTrigger>
                        <SelectContent>
                          {SUPPORT_STATUSES.map((status) => (
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
                          {(assigneesQuery.data || []).map((assignee) => (
                            <SelectItem key={assignee.id} value={assignee.id}>
                              {assignee.name || assignee.email}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                  </div>

                  <div className="flex flex-wrap gap-2">
                    <Button
                      data-testid="support-ticket-save"
                      onClick={() => void saveTicket()}
                      disabled={!canEdit || updateTicketMutation.isPending}
                    >
                      {updateTicketMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <TimerReset className="mr-2 h-4 w-4" />}
                      Save workflow update
                    </Button>
                  </div>

                  <div className="rounded-xl border bg-muted/20 p-4">
                    <p className="mb-2 text-sm font-semibold">Ticket messages</p>
                    <div className="max-h-48 space-y-2 overflow-auto rounded-md border bg-white p-2">
                      {detailQuery.data.messages?.length ? (
                        detailQuery.data.messages.map((message) => (
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
                        <p className="px-2 py-3 text-xs text-muted-foreground">No messages yet.</p>
                      )}
                    </div>

                    <div className="mt-3 space-y-2">
                      <Textarea
                        data-testid="support-ticket-message-input"
                        rows={3}
                        value={newMessage}
                        onChange={(event) => setNewMessage(event.target.value)}
                        placeholder="Add handoff or customer-support note..."
                      />
                      <div className="flex flex-wrap items-center gap-3">
                        <label className="flex items-center gap-2 text-xs text-muted-foreground">
                          <input
                            type="checkbox"
                            checked={editState.isInternal}
                            onChange={(event) => setEditState((prev) => ({ ...prev, isInternal: event.target.checked }))}
                          />
                          Internal note
                        </label>
                        <Button data-testid="support-ticket-message-submit" onClick={() => void sendMessage()} disabled={!newMessage.trim() || addMessageMutation.isPending}>
                          {addMessageMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <MessageSquareText className="mr-2 h-4 w-4" />}
                          Add message
                        </Button>
                      </div>
                    </div>
                  </div>

                  <p className="text-xs text-muted-foreground">
                    Last updated {detailQuery.data.updatedAt ? formatDistanceToNowStrict(new Date(detailQuery.data.updatedAt), { addSuffix: true }) : "just now"}.
                  </p>
                </div>
              )}
            </div>
          </div>
        </PageSection>
      </DataTablePagePattern>
    </DashboardLayout>
  );
}
