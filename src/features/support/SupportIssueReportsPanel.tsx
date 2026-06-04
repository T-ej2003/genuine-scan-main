import { formatDistanceToNowStrict } from "date-fns";
import { Send } from "lucide-react";

import { ActionButton } from "@/components/ui/action-button";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { PageEmptyState, PageSection } from "@/components/page-patterns/PagePatterns";
import type { SupportIssueReport } from "@/features/support/types";
import { toLabel } from "@/features/support/types";
import apiClient from "@/lib/api-client";
import { createUiActionState } from "@/lib/ui-actions";

type SupportIssueReportsPanelProps = {
  reports: SupportIssueReport[];
  isLoading: boolean;
  canEdit: boolean;
  replyDrafts: Record<string, string>;
  respondingReportId?: string;
  isResponding: boolean;
  onDraftChange: (reportId: string, value: string) => void;
  onRespond: (report: SupportIssueReport) => void;
};

export function SupportIssueReportsPanel({
  reports,
  isLoading,
  canEdit,
  replyDrafts,
  respondingReportId,
  isResponding,
  onDraftChange,
  onRespond,
}: SupportIssueReportsPanelProps) {
  return (
    <PageSection
      title="New help requests"
      description="Reply to newly reported issues without leaving the help desk."
      action={<Badge variant="outline">{reports.length}</Badge>}
    >
      {isLoading ? (
        <div className="text-sm text-muted-foreground">Loading issue reports...</div>
      ) : reports.length === 0 ? (
        <PageEmptyState
          title="No new help requests"
          description="When a user asks for help from the app, it will appear here."
        />
      ) : (
        <div className="grid gap-3 md:grid-cols-2">
          {reports.slice(0, 8).map((report) => (
            <IssueReportCard
              key={report.id}
              report={report}
              canEdit={canEdit}
              replyDraft={replyDrafts[report.id] ?? ""}
              isResponding={isResponding && respondingReportId === report.id}
              onDraftChange={(value) => onDraftChange(report.id, value)}
              onRespond={() => onRespond(report)}
            />
          ))}
        </div>
      )}
    </PageSection>
  );
}

function IssueReportCard({
  report,
  canEdit,
  replyDraft,
  isResponding,
  onDraftChange,
  onRespond,
}: {
  report: SupportIssueReport;
  canEdit: boolean;
  replyDraft: string;
  isResponding: boolean;
  onDraftChange: (value: string) => void;
  onRespond: () => void;
}) {
  const reporterLabel = report.publicName || report.reporterUser?.name || report.reporterUser?.email || "Unknown user";
  const hasDraft = replyDraft.trim().length > 0;

  return (
    <div className="rounded-2xl border p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="space-y-1">
          <p className="text-sm font-semibold leading-5">{report.title}</p>
          <p className="text-xs text-muted-foreground">
            {reporterLabel}
            {report.publicEmail ? ` · ${report.publicEmail}` : ""}
            {report.licensee?.name ? ` · ${report.licensee.name}` : ""}
          </p>
        </div>
        <div className="flex flex-col items-end gap-2">
          <Badge variant={report.autoDetected ? "default" : "outline"}>
            {report.autoDetected ? "Reported by app" : "Manual"}
          </Badge>
          <Badge variant="outline">{toLabel(report.status)}</Badge>
        </div>
      </div>

      {report.description ? <p className="mt-2 line-clamp-2 text-xs text-muted-foreground">{report.description}</p> : null}

      <div className="mt-3 flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
        {report.referenceCode ? <span className="font-mono">{report.referenceCode}</span> : null}
        {report.issueType ? <span>{toLabel(report.issueType)}</span> : null}
        {report.priority ? <span>{report.priority}</span> : null}
        <span>{formatDistanceToNowStrict(new Date(report.createdAt), { addSuffix: true })}</span>
        {report.sourcePath ? <span>Screen: {report.sourcePath}</span> : null}
        {report.emailDeliveryStatus ? <span>Email: {toLabel(report.emailDeliveryStatus)}</span> : null}
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
            value={replyDraft}
            onChange={(event) => onDraftChange(event.target.value)}
            placeholder="Tell the user what happens next."
          />
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="text-[11px] text-muted-foreground">
              This reply is sent by email and also appears in the user&apos;s notification feed.
            </p>
            <ActionButton
              data-testid="support-issue-report-reply"
              size="sm"
              onClick={onRespond}
              state={
                isResponding
                  ? createUiActionState("pending", "Sending the reply now.")
                  : !hasDraft
                    ? createUiActionState("disabled", "Write the reply before you send it.")
                    : createUiActionState("enabled")
              }
              idleLabel={
                <>
                  <Send className="mr-2 h-4 w-4" />
                  {report.responseMessage ? "Update reply" : "Send reply"}
                </>
              }
              pendingLabel="Sending..."
              showReasonBelow={false}
            />
          </div>
        </div>
      ) : null}
    </div>
  );
}
