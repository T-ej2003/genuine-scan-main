import { useEffect, useMemo, useState } from "react";
import { MessageSquareText, RefreshCw, TimerReset } from "lucide-react";
import { useSearchParams } from "react-router-dom";
import { formatDistanceToNowStrict } from "date-fns";

import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { DataTablePagePattern, PageEmptyState, PageInlineNotice, PageSection } from "@/components/page-patterns/PagePatterns";
import { Badge } from "@/components/ui/badge";
import { ActionButton } from "@/components/ui/action-button";
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
  type RequestAccessRecord,
  type SupportIssueReport,
  type SupportQueueFilters,
} from "@/features/support/types";
import {
  useAddSupportTicketMessageMutation,
  useRequestAccessRecords,
  useRespondToIssueReportMutation,
  useSupportAssignableUsers,
  useSupportIssueReports,
  useSupportTicketDetail,
  useSupportTickets,
  useUpdateRequestAccessMutation,
  useUpdateSupportTicketMutation,
} from "@/features/support/hooks";
import { SupportIssueReportsPanel } from "@/features/support/SupportIssueReportsPanel";
import { SupportRequestAccessPanel } from "@/features/support/SupportRequestAccessPanel";
import { friendlyReferenceLabel, shortRawReference } from "@/lib/friendly-reference";
import { createUiActionState } from "@/lib/ui-actions";
import { getSupportStatusLabel } from "@/lib/ui-copy";
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
  const [requestNotes, setRequestNotes] = useState<Record<string, string>>({});
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
  const requestAccessQuery = useRequestAccessRecords();
  const detailQuery = useSupportTicketDetail(selectedId);
  const assigneesQuery = useSupportAssignableUsers(canEdit);

  const updateTicketMutation = useUpdateSupportTicketMutation();
  const addMessageMutation = useAddSupportTicketMessageMutation();
  const respondToReportMutation = useRespondToIssueReportMutation();
  const updateRequestAccessMutation = useUpdateRequestAccessMutation();

  const tickets = ticketsQuery.data?.tickets || [];
  const total = ticketsQuery.data?.total || 0;
  const issueReports = reportsQuery.data?.reports || [];
  const requestAccessRecords = requestAccessQuery.data?.records || [];

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
    await Promise.all([ticketsQuery.refetch(), reportsQuery.refetch(), requestAccessQuery.refetch(), detailQuery.refetch()]);
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

  const updateRequestAccess = async (record: RequestAccessRecord, status: RequestAccessRecord["status"]) => {
    try {
      await updateRequestAccessMutation.mutateAsync({
        id: record.id,
        status,
        internalNote: requestNotes[record.id]?.trim() || record.internalNote || null,
      });
      toast({
        title: "Access request updated",
        description: `${record.referenceCode} moved to ${toLabel(status)}.`,
      });
    } catch (error) {
      toast({
        title: "Update failed",
        description: error instanceof Error ? error.message : "Could not update access request.",
        variant: "destructive",
      });
    }
  };

  const actions = (
    <ActionButton
      variant="outline"
      onClick={() => void refreshAll()}
      state={
        ticketsQuery.isFetching || reportsQuery.isFetching
          ? createUiActionState("pending", "Refreshing the latest help requests and case details.")
          : createUiActionState("enabled")
      }
      idleLabel={
        <>
          <RefreshCw className="mr-2 h-4 w-4" />
          Refresh
        </>
      }
      pendingLabel="Refreshing..."
      showReasonBelow={false}
    />
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
      <ActionButton
        data-testid="support-apply-filters"
        onClick={() => setAppliedFilters(draftFilters)}
        state={
          ticketsQuery.isFetching
            ? createUiActionState("pending", "Refreshing the help queue with these filters.")
            : createUiActionState("enabled")
        }
        idleLabel="Apply filters"
        pendingLabel="Refreshing..."
        showReasonBelow={false}
      />
    </div>
  );

  return (
    <DashboardLayout>
      <DataTablePagePattern
        eyebrow="Operations"
        title="Issues"
        description="Review help requests, reply to users, and keep every issue moving to the next clear step."
        actions={actions}
        filters={filters}
      >
        {ticketsQuery.error ? (
          <PageInlineNotice
            variant="destructive"
            title="Could not load issues"
            description={ticketsQuery.error instanceof Error ? ticketsQuery.error.message : "Please refresh and try again."}
          />
        ) : null}

        {requestAccessQuery.error ? (
          <PageInlineNotice
            variant="destructive"
            title="Could not load access requests"
            description={requestAccessQuery.error instanceof Error ? requestAccessQuery.error.message : "Please refresh and try again."}
          />
        ) : null}

        <SupportIssueReportsPanel
          reports={issueReports}
          isLoading={reportsQuery.isLoading}
          canEdit={canEdit}
          replyDrafts={issueReplyDrafts}
          respondingReportId={respondToReportMutation.variables?.reportId}
          isResponding={respondToReportMutation.isPending}
          onDraftChange={(reportId, value) => setIssueReplyDrafts((prev) => ({ ...prev, [reportId]: value }))}
          onRespond={(report) => void respondToIssueReport(report)}
        />

        <SupportRequestAccessPanel
          records={requestAccessRecords}
          isLoading={requestAccessQuery.isLoading}
          canEdit={canEdit}
          notes={requestNotes}
          isUpdating={updateRequestAccessMutation.isPending}
          onNoteChange={(recordId, value) => setRequestNotes((prev) => ({ ...prev, [recordId]: value }))}
          onUpdate={(record, status) => void updateRequestAccess(record, status)}
        />

        <PageSection
          title="Case queue"
          description="Choose a case on the left, then update its status, owner, and notes on the right."
          action={<Badge variant="outline">{total} issues</Badge>}
        >
          <div className="grid min-w-0 gap-6 xl:grid-cols-[minmax(0,1.05fr),minmax(0,1fr)]">
            <div className="min-w-0 rounded-2xl border">
              <div className="border-b px-5 py-4 text-sm font-semibold">Case list</div>
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
                        <TableCell colSpan={4} className="text-muted-foreground">No issues found.</TableCell>
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
                            <details className="text-xs text-muted-foreground">
                              <summary className="cursor-pointer">Support reference</summary>
                              <div className="mt-1 font-mono text-[10px]">{ticket.referenceCode}</div>
                            </details>
                            <div className="text-xs text-muted-foreground" title={ticket.incidentId}>
                              {friendlyReferenceLabel(ticket.incidentId, "Case")} · #{shortRawReference(ticket.incidentId, 8)}
                            </div>
                            <div className="line-clamp-1 text-xs text-slate-600">{ticket.subject}</div>
                          </TableCell>
                          <TableCell>
                            <Badge className={STATUS_TONE[ticket.status] || STATUS_TONE.OPEN}>
                              {getSupportStatusLabel(ticket.status)}
                            </Badge>
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

            <div className="min-w-0 rounded-2xl border bg-card p-5">
              {!detailQuery.data ? (
                <PageEmptyState
                  title={ticketsQuery.isLoading ? "Loading case details" : "Select a case"}
                  description="Choose a case from the list to review status, SLA, and message history."
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
                        <details className="text-xs text-muted-foreground">
                          <summary className="cursor-pointer">Support reference</summary>
                          <div className="mt-1 font-mono">{detailQuery.data.referenceCode}</div>
                        </details>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Case status</span>
                        <div className="font-medium">{getSupportStatusLabel(detailQuery.data.status)}</div>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Case stage</span>
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
                    <ActionButton
                      data-testid="support-ticket-save"
                      onClick={() => void saveTicket()}
                      state={
                        updateTicketMutation.isPending
                          ? createUiActionState("pending", "Saving the latest case changes.")
                          : !canEdit
                            ? createUiActionState("disabled", "Only super admins can change case owner or status.")
                            : createUiActionState("enabled")
                      }
                      idleLabel={
                        <>
                          <TimerReset className="mr-2 h-4 w-4" />
                          Save changes
                        </>
                      }
                      pendingLabel="Saving..."
                    />
                  </div>

                  <div className="rounded-xl border bg-muted/20 p-4">
                    <p className="mb-2 text-sm font-semibold">Conversation</p>
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
                        placeholder="Add a note for the team or a customer-ready message..."
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
                        <ActionButton
                          data-testid="support-ticket-message-submit"
                          onClick={() => void sendMessage()}
                          state={
                            addMessageMutation.isPending
                              ? createUiActionState("pending", "Adding the note to this case.")
                              : !newMessage.trim()
                                ? createUiActionState("disabled", "Write the note before you add it.")
                                : createUiActionState("enabled")
                          }
                          idleLabel={
                            <>
                              <MessageSquareText className="mr-2 h-4 w-4" />
                              Add note
                            </>
                          }
                          pendingLabel="Adding..."
                          showReasonBelow={false}
                        />
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
