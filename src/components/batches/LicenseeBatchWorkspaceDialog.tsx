import React from "react";
import { format } from "date-fns";
import { Activity, AlertTriangle, CheckCircle2, Download, PackageCheck, PencilLine, RefreshCcw, Trash2, UserCog, Boxes, Factory, Printer, ShieldCheck } from "lucide-react";

import type { BatchWorkspaceAllocation, StableBatchOverviewRow } from "@/lib/batch-workspace";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type { PrintJobRow } from "@/features/batches/types";
import {
  decisionOutcomeTone,
  decisionRiskTone,
  decisionTrustTone,
  presentPrintTrustState,
  titleCaseDecisionValue,
} from "@/lib/verification-decision";
import { humanStatusLabel } from "@/lib/audit-display";

type ManufacturerRow = {
  id: string;
  name: string;
  email: string;
  isActive: boolean;
};

type TraceEventType = "COMMISSIONED" | "ASSIGNED" | "PRINTED" | "REDEEMED" | "BLOCKED";

type TraceEventRow = {
  id: string;
  eventType?: TraceEventType;
  action?: string;
  sourceAction?: string | null;
  createdAt: string;
  details?: any;
  user?: { id: string; name?: string | null; email?: string | null } | null;
  manufacturer?: { id: string; name?: string | null; email?: string | null } | null;
  qrCode?: { id: string; code?: string | null } | null;
  userId?: string | null;
};

type LicenseeBatchWorkspaceDialogProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  role?: string | null;
  workspace: StableBatchOverviewRow | null;
  manufacturers: ManufacturerRow[];
  assignManufacturerId: string;
  assignQuantity: string;
  assigning: boolean;
  onAssignManufacturerChange: (value: string) => void;
  onAssignQuantityChange: (value: string) => void;
  onSubmitAssign: () => void;
  onOpenRename: () => void;
  onOpenAllocationMap: () => void;
  onDownloadAudit: () => void;
  onDelete: () => void;
  canAssignManufacturer: boolean;
  canDelete: boolean;
  exportingAudit: boolean;
  historyLoading: boolean;
  historyLogs: TraceEventRow[];
  historyLastUpdatedAt: Date | null;
  onRefreshHistory: () => void;
  recentPrintJobs: PrintJobRow[];
  printJobsLoading: boolean;
  canRequestReissue: boolean;
  reissueReason: string;
  onReissueReasonChange: (value: string) => void;
  onRequestReissue: (jobId: string) => void;
  reissuingJobId: string | null;
  reissueRequests?: any[];
  reissueRequestsMode?: "review" | "print";
  reissueRequestsLoading?: boolean;
  reissueDecisionNote?: string;
  decidingReissueRequestId?: string | null;
  printingReissueRequestId?: string | null;
  reissuePrintRecoveryById?: Record<string, string>;
  onReissueDecisionNoteChange?: (value: string) => void;
  onRefreshReissueRequests?: () => void;
  onDecideReissueRequest?: (requestId: string, decision: "approve" | "reject") => void;
  onPrintApprovedReissueRequest?: (requestId: string) => void;
  onContinuePrintRecovery?: (job: PrintJobRow) => void;
  onRefreshPrinterStatus?: () => void;
  securePrinterReady?: boolean;
  initialTab?: "overview" | "operations" | "audit";
  highlightedReissueRequestId?: string | null;
};

const eventBadgeClass = (eventType?: string) => {
  if (eventType === "COMMISSIONED") return "bg-sky-500/10 text-sky-700";
  if (eventType === "ASSIGNED") return "bg-cyan-500/10 text-cyan-700";
  if (eventType === "PRINTED") return "bg-amber-500/10 text-amber-700";
  if (eventType === "REDEEMED") return "bg-emerald-500/10 text-emerald-700";
  if (eventType === "BLOCKED") return "bg-red-500/10 text-red-700";
  return "bg-muted text-muted-foreground";
};

const historySummary = (log: TraceEventRow) => {
  const d = log?.details || {};
  const eventType = log?.eventType || "";
  if (eventType === "COMMISSIONED") {
    const qty = d.quantity ?? d.created ?? d.totalCodes;
    return `Added ${qty ?? "-"} labels to this batch.`;
  }
  if (eventType === "ASSIGNED") {
    return `Assigned ${d.quantity ?? "-"} labels to ${d.manufacturerName || log.manufacturer?.name || "a manufacturer"}.`;
  }
  if (eventType === "PRINTED") {
    return `Printed ${d.printedCodes ?? d.codes ?? "-"} labels.`;
  }
  if (eventType === "REDEEMED") {
    return `Redeemed on scan${d.scanCount != null ? ` (scan #${d.scanCount})` : ""}.`;
  }
  if (eventType === "BLOCKED") {
    return `Blocked${d.reason ? `: ${d.reason}` : ""}${d.blockedCodes ? ` (${d.blockedCodes} codes)` : ""}.`;
  }
  if (d.context === "ASSIGN_MANUFACTURER_QUANTITY_CHILD") {
    return `Allocated ${d.quantity ?? "-"} labels to ${d.manufacturerName || log.manufacturer?.name || "a manufacturer"}.`;
  }
  return humanStatusLabel(log?.sourceAction || log?.action || "Activity");
};

const historyActor = (log: TraceEventRow) => {
  if (log?.user?.name) return log.user.name;
  if (log?.manufacturer?.name) return log.manufacturer.name;
  if (log?.user?.email) return log.user.email;
  return "System";
};

const statusTone = (value: number) => (value > 0 ? "default" : "secondary");

const getPrintJobStatusBadgeVariant = (job: PrintJobRow): "default" | "secondary" | "destructive" | "outline" => {
  if (job.pipelineState === "LOCKED" || job.status === "CONFIRMED") return "default";
  if (job.pipelineState === "FAILED" || job.status === "FAILED") return "destructive";
  if (job.pipelineState === "NEEDS_OPERATOR_ACTION") return "secondary";
  return "outline";
};

const getPrintJobStageLabel = (job: PrintJobRow) => {
  if (job.pipelineState === "LOCKED" || job.pipelineState === "PRINT_CONFIRMED" || job.status === "CONFIRMED") {
    return "Print confirmed";
  }
  if (job.pipelineState === "NEEDS_OPERATOR_ACTION") return "Needs operator review";
  if (job.pipelineState === "FAILED" || job.status === "FAILED") return "Needs attention";
  return titleCaseDecisionValue(job.pipelineState || job.status || "Queued");
};

const isEligibleForReissue = (job: PrintJobRow) =>
  job.pipelineState === "LOCKED" || job.pipelineState === "PRINT_CONFIRMED" || job.status === "CONFIRMED";

const getPrintRunCounts = (job: PrintJobRow) => {
  const requested = Number(job.itemCount || job.quantity || 0);
  const confirmed = Number(job.session?.confirmedItems || 0);
  const failed = Number(job.session?.failedItems || 0);
  const pending = Number(job.session?.pendingUnconfirmedItems ?? Math.max(0, requested - confirmed - failed));
  const remaining = Number(job.session?.remainingToPrint ?? pending);
  return { requested, confirmed, failed, pending, remaining };
};

const formatCodeRange = (range?: { startCode?: string | null; endCode?: string | null } | null) => {
  const start = String(range?.startCode || "").trim();
  const end = String(range?.endCode || "").trim();
  if (start && end) return start === end ? start : `${start} to ${end}`;
  return start || end || "";
};

const needsRecovery = (job: PrintJobRow) => {
  const counts = getPrintRunCounts(job);
  return Boolean(
    job.session?.recoveryNeeded ||
    job.session?.recoveryRange ||
    (
    counts.remaining > 0 &&
    (job.status === "STOPPED" ||
      job.status === "PARTIALLY_COMPLETED" ||
      job.status === "FAILED" ||
      job.pipelineState === "STOPPED" ||
      job.pipelineState === "NEEDS_OPERATOR_ACTION")
    )
  );
};

const getRecoveryInstruction = (job: PrintJobRow) => {
  const recoveryRange = job.session?.recoveryRange;
  const pendingRange = job.session?.pendingRange;
  const start = recoveryRange?.startCode || job.session?.nextPrintableIndex || pendingRange?.startCode || null;
  const end = recoveryRange?.endCode || pendingRange?.endCode || start;
  const range = formatCodeRange({ startCode: start, endCode: end });
  if (start && range) {
    return {
      firstLine: `Continue from label ${start}.`,
      secondLine: `Recover unconfirmed label range ${range}. Do not start a later range until this recovery is resolved.`,
    };
  }
  return {
    firstLine: "Continue from the first unconfirmed label.",
    secondLine: "Recover the unconfirmed remaining labels before starting a later range.",
  };
};

const printJobOperator = (job: PrintJobRow) =>
  job.operator?.name || job.operator?.email || "Operator not recorded";

const printJobRange = (job: PrintJobRow) => {
  const requestedRange = formatCodeRange(job.session?.requestedRange);
  if (requestedRange) return requestedRange;
  const start = String((job as any).rangeStart || job.session?.pendingRange?.startCode || job.session?.confirmedRange?.startCode || "").trim();
  const end = String((job as any).rangeEnd || job.session?.pendingRange?.endCode || job.session?.confirmedRange?.endCode || "").trim();
  if (start && end) return `${start} to ${end}`;
  if (start) return start;
  return "Range not recorded";
};

const formatDateTime = (value?: string | Date | null) => {
  if (!value) return "Time not recorded";
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return "Time not recorded";
  return format(date, "PPp");
};

const reissueRange = (request: any) =>
  formatCodeRange({
    startCode: request.requestedRangeStart || request.affectedRangeStart || request.recoveryStartLabel,
    endCode: request.requestedRangeEnd || request.affectedRangeEnd || request.recoveryEndLabel,
  }) || "Range not recorded";

const reissueRequestedCount = (request: any) =>
  Number(request.requestedCount || request.quantity || request.originalPendingCount || 0);

const reissueRequester = (request: any) =>
  request.requestedBy?.name || request.requestedBy?.email || request.requestedByName || "Requester not recorded";

const reissueStatusLabel = (request: any) => {
  if (request.status === "APPROVED") return "Approved and ready to print";
  if (request.status === "EXECUTED") return "Replacement print job created";
  if (request.status === "REJECTED") return "Rejected";
  if (request.targetApproverRole === "SUPER_ADMIN") return "Super admin review";
  return "Brand admin review";
};

const reissueSafeEvidenceLabel = (request: any) => {
  const pending = Number(request.originalPendingCount || 0);
  const failed = Number(request.originalFailedCount || 0);
  if (pending > 0 || failed > 0) return "Recovery evidence found";
  if (request.status === "APPROVED" || request.status === "EXECUTED") return "Approved exception";
  return "Review print evidence";
};

const isConfirmedPrintRun = (job: PrintJobRow) =>
  job.pipelineState === "LOCKED" ||
  job.pipelineState === "PRINT_CONFIRMED" ||
  job.status === "CONFIRMED" ||
  Boolean(job.confirmedAt);

const isStoppedPrintRun = (job: PrintJobRow) =>
  needsRecovery(job) ||
  job.status === "STOPPED" ||
  job.status === "PARTIALLY_COMPLETED" ||
  job.status === "FAILED" ||
  job.pipelineState === "STOPPED" ||
  job.pipelineState === "FAILED" ||
  job.pipelineState === "NEEDS_OPERATOR_ACTION";

const canRequestReissueForJob = (job: PrintJobRow) => isEligibleForReissue(job) || isStoppedPrintRun(job);

const workspacePrimaryRange = (workspace: StableBatchOverviewRow) => {
  const allocation = workspace.allocations[0] || null;
  return {
    start: allocation?.batchRangeStart || workspace.sourceOriginalRangeStart,
    end: allocation?.batchRangeEnd || workspace.sourceOriginalRangeEnd,
  };
};

const manufacturerRemainingLabels = (workspace: StableBatchOverviewRow) =>
  Number(workspace.pendingPrintableCodes || 0);

const renderManufacturerLine = (allocation: BatchWorkspaceAllocation) => (
  <div key={`${allocation.batchId}:${allocation.manufacturerId}`} className="rounded-xl border bg-muted/20 p-4">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div>
        <div className="font-semibold">{allocation.manufacturerName}</div>
        <div className="mt-1 text-xs text-muted-foreground break-all">{allocation.manufacturerEmail || "Manufacturer account"}</div>
      </div>
      <Badge variant="secondary">{allocation.allocatedCodes.toLocaleString()} assigned</Badge>
    </div>
    <div className="mt-3 grid gap-2 text-xs text-muted-foreground sm:grid-cols-2 xl:grid-cols-4">
      <div>
        <div className="font-medium text-foreground">Ready to print</div>
        <div>{allocation.printableCodes.toLocaleString()}</div>
      </div>
      <div>
        <div className="font-medium text-foreground">Printed</div>
        <div>{allocation.printedCodes.toLocaleString()}</div>
      </div>
      <div>
        <div className="font-medium text-foreground">Redeemed</div>
        <div>{allocation.redeemedCodes.toLocaleString()}</div>
      </div>
      <div>
        <div className="font-medium text-foreground">Blocked</div>
        <div>{allocation.blockedCodes.toLocaleString()}</div>
      </div>
    </div>
    <div className="mt-3 text-xs text-muted-foreground font-mono break-all">
      Label range: {allocation.batchRangeStart} to {allocation.batchRangeEnd}
    </div>
    {(allocation.currentRangeStart || allocation.currentRangeEnd) && (
      <div className="mt-1 text-xs text-muted-foreground font-mono break-all">
        Ready-to-print range: {allocation.currentRangeStart || "-"} to {allocation.currentRangeEnd || "-"}
      </div>
    )}
  </div>
);

export function LicenseeBatchWorkspaceDialog({
  open,
  onOpenChange,
  role,
  workspace,
  manufacturers,
  assignManufacturerId,
  assignQuantity,
  assigning,
  onAssignManufacturerChange,
  onAssignQuantityChange,
  onSubmitAssign,
  onOpenRename,
  onOpenAllocationMap,
  onDownloadAudit,
  onDelete,
  canAssignManufacturer,
  canDelete,
  exportingAudit,
  historyLoading,
  historyLogs,
  historyLastUpdatedAt,
  onRefreshHistory,
  recentPrintJobs,
  printJobsLoading,
  canRequestReissue,
  reissueReason,
  onReissueReasonChange,
  onRequestReissue,
  reissuingJobId,
  reissueRequests = [],
  reissueRequestsMode = "review",
  reissueRequestsLoading = false,
  reissueDecisionNote = "",
  decidingReissueRequestId = null,
  printingReissueRequestId = null,
  reissuePrintRecoveryById = {},
  onReissueDecisionNoteChange = () => undefined,
  onRefreshReissueRequests = () => undefined,
  onDecideReissueRequest = () => undefined,
  onPrintApprovedReissueRequest = () => undefined,
  onRefreshPrinterStatus = () => undefined,
  securePrinterReady = false,
  initialTab = "overview",
  highlightedReissueRequestId = null,
}: LicenseeBatchWorkspaceDialogProps) {
  const remaining = Number(workspace?.remainingUnassignedCodes || 0);
  const assignQuantityValue = Number(assignQuantity || 0);
  const sourceBatch = workspace?.sourceBatchRow || null;
  const showingApprovedReissueRequests =
    reissueRequestsMode === "print" || reissueRequests.some((request) => request.status === "APPROVED");
  const isManufacturerMode = role === "manufacturer";
  const isSuperAdminMode = role === "super_admin" || role === "platform_super_admin";
  const [selectedPrintJobDetail, setSelectedPrintJobDetail] = React.useState<PrintJobRow | null>(null);
  const [manufacturerOperationSection, setManufacturerOperationSection] = React.useState<
    "menu" | "confirmed" | "stopped" | "replacement" | "pending"
  >("menu");
  const manufacturerOps = workspace?.manufacturerOperational || null;
  const blockingRecoveryJob = recentPrintJobs.find(needsRecovery) || null;
  const confirmedPrintJobs = React.useMemo(
    () => recentPrintJobs.filter((job) => isConfirmedPrintRun(job) && !isStoppedPrintRun(job)),
    [recentPrintJobs]
  );
  const stoppedPrintJobs = React.useMemo(
    () => recentPrintJobs.filter(isStoppedPrintRun),
    [recentPrintJobs]
  );
  const replacementRequests = React.useMemo(
    () => reissueRequests.filter((request) => request.status === "APPROVED" || request.status === "EXECUTED"),
    [reissueRequests]
  );
  const pendingReissueRequests = React.useMemo(
    () => reissueRequests.filter((request) => request.status !== "APPROVED" && request.status !== "EXECUTED"),
    [reissueRequests]
  );
  const existingReissueJobIds = React.useMemo(
    () =>
      new Set(
        reissueRequests
          .map((request) => String(request.originalPrintJobId || request.printJobId || request.printJob?.id || "").trim())
          .filter(Boolean)
      ),
    [reissueRequests]
  );
  const hasExistingReissue = (job: PrintJobRow) => existingReissueJobIds.has(job.id);
  const manufacturerNextLabel = blockingRecoveryJob
    ? "Recovery required before next range"
    : manufacturerOps?.nextPrintableLabelCode || null;
  const manufacturerRemainingRange =
    manufacturerOps?.remainingPrintableRangeStart && manufacturerOps.remainingPrintableRangeEnd
      ? formatCodeRange({
          startCode: manufacturerOps.remainingPrintableRangeStart,
          endCode: manufacturerOps.remainingPrintableRangeEnd,
        })
      : "";
  React.useEffect(() => {
    setManufacturerOperationSection("menu");
  }, [workspace?.sourceBatchId, workspace?.focusBatchId]);

  return (
    <>
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent data-testid="batch-workspace-dialog" className="flex h-[90vh] max-h-[90vh] flex-col overflow-hidden p-0 sm:max-w-[980px]">
        {!workspace ? null : isManufacturerMode ? (
          <>
            <DialogHeader className="border-b px-6 py-5">
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div className="space-y-2">
                  <DialogTitle className="text-2xl">{workspace.sourceBatchName}</DialogTitle>
                  <DialogDescription className="max-w-2xl">
                    Manufacturer operations for assigned labels, print recovery, replacement requests, and audit history.
                  </DialogDescription>
                  <div className="flex flex-wrap items-center gap-2 text-xs">
                    <Badge variant="secondary">Assigned batch</Badge>
                    <Badge variant={statusTone(manufacturerOps?.remainingLabelCount ?? manufacturerRemainingLabels(workspace))}>
                      {(manufacturerOps?.remainingLabelCount ?? manufacturerRemainingLabels(workspace)).toLocaleString()} remaining labels
                    </Badge>
                    <Badge variant="outline">{(manufacturerOps?.assignedLabelCount ?? workspace.originalTotalCodes).toLocaleString()} assigned labels</Badge>
                  </div>
                </div>
                <div className="min-w-[16rem] rounded-lg border bg-muted/20 px-4 py-3 text-sm">
                  <div className="text-xs font-medium uppercase text-muted-foreground">Assigned label range</div>
                  <div className="mt-2 font-mono text-xs break-all">
                    {formatCodeRange({
                      startCode: manufacturerOps?.originalAssignedRangeStart || workspacePrimaryRange(workspace).start,
                      endCode: manufacturerOps?.originalAssignedRangeEnd || workspacePrimaryRange(workspace).end,
                    })}
                  </div>
                  <div className="mt-3 text-xs text-muted-foreground">
                    Next printable label: <span className="font-mono">{manufacturerNextLabel || "No printable labels remain"}</span>
                  </div>
                </div>
              </div>
            </DialogHeader>

            <Tabs key={`${workspace.sourceBatchId}:manufacturer:${initialTab}`} defaultValue={initialTab} className="flex min-h-0 flex-1 flex-col">
              <div className="border-b px-6 py-3">
                <TabsList className="grid w-full grid-cols-3 sm:w-[26rem]">
                  <TabsTrigger value="overview">Overview</TabsTrigger>
                  <TabsTrigger value="operations">Operations</TabsTrigger>
                  <TabsTrigger value="audit">Audit</TabsTrigger>
                </TabsList>
              </div>
              <ScrollArea type="always" scrollHideDelay={0} className="min-h-0 flex-1">
                <div className="px-6 py-5 pr-8">
                  <TabsContent value="overview" className="mt-0 space-y-6">
                    <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                      <div className="rounded-lg border bg-muted/20 p-4">
                        <div className="text-xs font-medium uppercase text-muted-foreground">Assigned labels</div>
                        <div className="mt-3 text-3xl font-semibold">{(manufacturerOps?.assignedLabelCount ?? workspace.originalTotalCodes).toLocaleString()}</div>
                      </div>
                      <div className="rounded-lg border bg-muted/20 p-4">
                        <div className="text-xs font-medium uppercase text-muted-foreground">Confirmed printed</div>
                        <div className="mt-3 text-3xl font-semibold">{(manufacturerOps?.confirmedPrintedCount ?? workspace.printedCodes).toLocaleString()}</div>
                      </div>
                      <div className="rounded-lg border bg-muted/20 p-4">
                        <div className="text-xs font-medium uppercase text-muted-foreground">Remaining labels</div>
                        <div className="mt-3 text-3xl font-semibold">{(manufacturerOps?.remainingLabelCount ?? manufacturerRemainingLabels(workspace)).toLocaleString()}</div>
                        <div className="mt-2 text-xs text-muted-foreground font-mono break-all">
                          {blockingRecoveryJob
                            ? getRecoveryInstruction(blockingRecoveryJob).secondLine
                            : manufacturerRemainingRange || "No printable range remains."}
                        </div>
                      </div>
                      <div className="rounded-lg border bg-muted/20 p-4">
                        <div className="text-xs font-medium uppercase text-muted-foreground">Scanned / blocked</div>
                        <div className="mt-3 text-3xl font-semibold">{(manufacturerOps?.scannedCount ?? workspace.redeemedCodes).toLocaleString()} / {(manufacturerOps?.blockedCount ?? workspace.blockedCodes).toLocaleString()}</div>
                      </div>
                    </div>

                    <div className="rounded-lg border p-4">
                      <div className="font-semibold">Label ranges</div>
                      <div className="mt-3 grid gap-3 text-sm md:grid-cols-2">
                        <div>
                          <div className="text-xs font-medium text-muted-foreground">Original assigned range</div>
                          <div className="font-mono text-xs break-all">
                            {formatCodeRange({
                              startCode: manufacturerOps?.originalAssignedRangeStart || workspacePrimaryRange(workspace).start,
                              endCode: manufacturerOps?.originalAssignedRangeEnd || workspacePrimaryRange(workspace).end,
                            })}
                          </div>
                        </div>
                        <div>
                          <div className="text-xs font-medium text-muted-foreground">Remaining available range</div>
                          <div className="font-mono text-xs break-all">
                            {blockingRecoveryJob
                              ? "Recovery required before next range"
                              : manufacturerRemainingRange || "No printable range remains"}
                          </div>
                        </div>
                      </div>
                    </div>
                  </TabsContent>

                  <TabsContent value="operations" className="mt-0 space-y-5">
                    {manufacturerOperationSection === "menu" ? (
                      <>
                        <div className="grid gap-3 md:grid-cols-2">
                          {[
                            {
                              key: "confirmed" as const,
                              title: "Confirmed prints",
                              count: confirmedPrintJobs.length,
                              detail: "Print runs with backend-confirmed labels.",
                              icon: CheckCircle2,
                            },
                            {
                              key: "stopped" as const,
                              title: "Stopped prints",
                              count: stoppedPrintJobs.length,
                              detail: "Runs that need recovery or replacement approval.",
                              icon: AlertTriangle,
                            },
                            {
                              key: "replacement" as const,
                              title: "Replacement labels",
                              count: replacementRequests.length,
                              detail: "Approved or already-created replacement jobs.",
                              icon: PackageCheck,
                            },
                            {
                              key: "pending" as const,
                              title: "Pending re-issue requests",
                              count: pendingReissueRequests.length,
                              detail: "Requests waiting for brand or super admin review.",
                              icon: RefreshCcw,
                            },
                          ].map((item) => {
                            const Icon = item.icon;
                            return (
                              <button
                                key={item.key}
                                type="button"
                                onClick={() => setManufacturerOperationSection(item.key)}
                                className="rounded-lg border bg-background p-4 text-left transition hover:border-primary/40 hover:bg-muted/20"
                              >
                                <div className="flex items-start justify-between gap-3">
                                  <div className="flex items-center gap-3">
                                    <span className="flex h-9 w-9 items-center justify-center rounded-md border bg-muted/30">
                                      <Icon className="h-4 w-4" />
                                    </span>
                                    <div>
                                      <div className="font-semibold">{item.title}</div>
                                      <div className="mt-1 text-sm text-muted-foreground">{item.detail}</div>
                                    </div>
                                  </div>
                                  <Badge variant={item.count > 0 ? "default" : "secondary"}>{item.count}</Badge>
                                </div>
                              </button>
                            );
                          })}
                        </div>

                        <div className="rounded-lg border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900">
                          {blockingRecoveryJob
                            ? `${getRecoveryInstruction(blockingRecoveryJob).firstLine} ${getRecoveryInstruction(blockingRecoveryJob).secondLine}`
                            : manufacturerOps?.nextPrintableLabelCode
                              ? `Next printable label is ${manufacturerOps.nextPrintableLabelCode}.`
                              : "No recovery task is currently open for this batch."}
                        </div>
                      </>
                    ) : (
                      <div className="space-y-4">
                        <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border bg-muted/20 px-4 py-3">
                          <div>
                            <div className="font-semibold">
                              {manufacturerOperationSection === "confirmed"
                                ? "Confirmed prints"
                                : manufacturerOperationSection === "stopped"
                                  ? "Stopped prints"
                                  : manufacturerOperationSection === "replacement"
                                    ? "Replacement labels"
                                    : "Pending re-issue requests"}
                            </div>
                            <div className="text-xs text-muted-foreground">
                              {manufacturerOperationSection === "stopped"
                                ? "Resolve the earliest unconfirmed range before starting a later range."
                                : "Select a card to review the print job or request details."}
                            </div>
                          </div>
                          <div className="flex flex-wrap gap-2">
                            {manufacturerOperationSection === "replacement" || manufacturerOperationSection === "pending" ? (
                              <Button variant="outline" size="sm" onClick={onRefreshReissueRequests} disabled={reissueRequestsLoading}>
                                {reissueRequestsLoading ? "Refreshing..." : "Refresh"}
                              </Button>
                            ) : null}
                            <Button variant="outline" size="sm" onClick={() => setManufacturerOperationSection("menu")}>
                              Back to operations
                            </Button>
                          </div>
                        </div>

                        {manufacturerOperationSection === "confirmed" || manufacturerOperationSection === "stopped" ? (
                          <div className="space-y-3">
                            {canRequestReissue ? (
                              <div className="space-y-2 rounded-lg border bg-muted/10 p-4">
                                <Label htmlFor="manufacturer-print-run-reissue-reason">Re-issue request reason</Label>
                                <Input
                                  id="manufacturer-print-run-reissue-reason"
                                  value={reissueReason}
                                  onChange={(event) => onReissueReasonChange(event.target.value)}
                                  placeholder="Explain why replacement labels are required"
                                />
                                <div className="text-xs text-muted-foreground">
                                  The backend decides the safe recovery range. This note is kept with the approval request.
                                </div>
                              </div>
                            ) : null}
                            {(manufacturerOperationSection === "confirmed" ? confirmedPrintJobs : stoppedPrintJobs).length === 0 ? (
                              <div className="rounded-lg border border-dashed bg-muted/10 p-5 text-sm text-muted-foreground">
                                {manufacturerOperationSection === "confirmed"
                                  ? "No confirmed print runs found for this batch."
                                  : "No stopped or failed print runs need recovery right now."}
                              </div>
                            ) : (
                              (manufacturerOperationSection === "confirmed" ? confirmedPrintJobs : stoppedPrintJobs).map((job) => (
                                <div key={job.id} className="rounded-lg border bg-background p-4">
                                  <div className="flex flex-wrap items-start justify-between gap-3">
                                    <div className="space-y-2">
                                      <div className="flex flex-wrap items-center gap-2">
                                        <div className="font-medium">{job.jobNumber || job.id}</div>
                                        <Badge variant={getPrintJobStatusBadgeVariant(job)}>{getPrintJobStageLabel(job)}</Badge>
                                        {job.reprintOfJobId ? <Badge variant="outline">Replacement</Badge> : null}
                                      </div>
                                      <div className="grid gap-2 text-xs text-muted-foreground sm:grid-cols-2 lg:grid-cols-3">
                                        <div>Range <span className="font-mono">{printJobRange(job)}</span></div>
                                        <div>Requested {getPrintRunCounts(job).requested.toLocaleString()}</div>
                                        <div>Confirmed {getPrintRunCounts(job).confirmed.toLocaleString()}</div>
                                        <div>Pending {getPrintRunCounts(job).pending.toLocaleString()}</div>
                                        <div>Failed {getPrintRunCounts(job).failed.toLocaleString()}</div>
                                        <div>Printer {job.printer?.name || "Not recorded"}</div>
                                        <div>Operator {printJobOperator(job)}</div>
                                        <div>Created {formatDateTime(job.createdAt)}</div>
                                        <div>Updated {formatDateTime(job.updatedAt)}</div>
                                      </div>
                                      {needsRecovery(job) ? (
                                        <div className="rounded-md border border-amber-200 bg-amber-50 p-2 text-xs text-amber-800">
                                          <div>{getRecoveryInstruction(job).firstLine}</div>
                                          <div>{getRecoveryInstruction(job).secondLine}</div>
                                        </div>
                                      ) : null}
                                      {job.failureReason ? <div className="text-xs text-destructive">Failure: {job.failureReason}</div> : null}
                                    </div>
                                    <div className="flex flex-wrap justify-end gap-2">
                                      <Button size="sm" variant="outline" onClick={() => setSelectedPrintJobDetail(job)}>View details</Button>
                                      {canRequestReissue && canRequestReissueForJob(job) ? (
                                        <Button
                                          size="sm"
                                          variant="outline"
                                          disabled={!reissueReason.trim() || reissuingJobId === job.id || hasExistingReissue(job)}
                                          title={hasExistingReissue(job) ? "A replacement request already exists for this print run." : undefined}
                                          onClick={() => onRequestReissue(job.id)}
                                        >
                                          {hasExistingReissue(job) ? "Reissue requested" : reissuingJobId === job.id ? "Submitting..." : "Request re-issue"}
                                        </Button>
                                      ) : null}
                                    </div>
                                  </div>
                                </div>
                              ))
                            )}
                          </div>
                        ) : null}

                        {manufacturerOperationSection === "replacement" || manufacturerOperationSection === "pending" ? (
                          <div className="space-y-4">
                            {manufacturerOperationSection === "pending" ? (
                              <div className="space-y-2">
                                <Label htmlFor="manufacturer-reissue-reason">Re-issue request reason</Label>
                                <Input
                                  id="manufacturer-reissue-reason"
                                  value={reissueReason}
                                  onChange={(event) => onReissueReasonChange(event.target.value)}
                                  placeholder="Explain why replacement labels are required"
                                />
                              </div>
                            ) : null}
                            {(manufacturerOperationSection === "replacement" ? replacementRequests : pendingReissueRequests).length === 0 ? (
                              <div className="rounded-lg border border-dashed bg-muted/10 p-5 text-sm text-muted-foreground">
                                {manufacturerOperationSection === "replacement"
                                  ? "No approved replacement labels are ready for this batch."
                                  : "No pending re-issue requests are waiting right now."}
                              </div>
                            ) : (
                              (manufacturerOperationSection === "replacement" ? replacementRequests : pendingReissueRequests).map((request) => (
                                <div
                                  key={request.id}
                                  data-testid={highlightedReissueRequestId === request.id ? "highlighted-reissue-request" : undefined}
                                  className={`rounded-lg border bg-background p-4 text-sm ${
                                    highlightedReissueRequestId === request.id ? "border-emerald-300 bg-emerald-50/60" : ""
                                  }`}
                                >
                                  <div className="flex flex-wrap items-start justify-between gap-3">
                                    <div className="space-y-2">
                                      <div className="flex flex-wrap items-center gap-2">
                                        <div className="font-medium">{request.batch?.name || "Replacement request"}</div>
                                        <Badge variant="secondary">{reissueStatusLabel(request)}</Badge>
                                      </div>
                                      <div className="grid gap-2 text-xs text-muted-foreground sm:grid-cols-2 lg:grid-cols-3">
                                        <div>Requested {reissueRequestedCount(request).toLocaleString()} labels</div>
                                        <div>Range <span className="font-mono">{reissueRange(request)}</span></div>
                                        <div>Requester {reissueRequester(request)}</div>
                                        <div>Requested {formatDateTime(request.requestedAt)}</div>
                                        <div>Related print job {request.originalPrintJobNumber || request.originalPrintJobId || "Not recorded"}</div>
                                        <div>{reissueSafeEvidenceLabel(request)}</div>
                                      </div>
                                      <div className="text-xs text-muted-foreground">Reason: {request.reason || "No reason recorded"}</div>
                                      {request.nextAction ? <div className="text-xs text-muted-foreground">Next action: {request.nextAction}</div> : null}
                                    </div>
                                  </div>
                                  {request.status === "APPROVED" ? (
                                    <div className="mt-3 space-y-2">
                                      {reissuePrintRecoveryById[request.id] || !securePrinterReady ? (
                                        <div className="rounded-md border border-amber-200 bg-amber-50 p-2 text-xs text-amber-800">
                                          {reissuePrintRecoveryById[request.id] || "Printer verification expired. Refresh printer helper before printing."}
                                        </div>
                                      ) : null}
                                      <div className="flex flex-wrap justify-end gap-2">
                                        <Button size="sm" variant="outline" onClick={onRefreshPrinterStatus}>
                                          Refresh printer helper
                                        </Button>
                                        <Button
                                          size="sm"
                                          disabled={!securePrinterReady || printingReissueRequestId === request.id}
                                          onClick={() => onPrintApprovedReissueRequest(request.id)}
                                        >
                                          {printingReissueRequestId === request.id ? "Checking printer..." : "Print replacement labels"}
                                        </Button>
                                      </div>
                                    </div>
                                  ) : null}
                                </div>
                              ))
                            )}
                          </div>
                        ) : null}
                      </div>
                    )}
                  </TabsContent>

                  <TabsContent value="audit" className="mt-0 space-y-4">
                    <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border bg-muted/20 px-4 py-3 text-sm">
                      <div>
                        <div className="font-semibold">Manufacturer-safe audit</div>
                        <div className="text-xs text-muted-foreground">
                          {historyLastUpdatedAt ? `Updated ${format(historyLastUpdatedAt, "PPp")}` : "Waiting for first snapshot..."}
                        </div>
                      </div>
                      <Button variant="outline" size="sm" onClick={onRefreshHistory} disabled={historyLoading}>
                        <RefreshButtonLabel loading={historyLoading} />
                      </Button>
                    </div>
                    {historyLoading ? (
                      <div className="rounded-lg border border-dashed bg-muted/10 p-6 text-sm text-muted-foreground">Loading audit history...</div>
                    ) : historyLogs.length === 0 ? (
                      <div className="rounded-lg border border-dashed bg-muted/10 p-6 text-sm text-muted-foreground">No manufacturer-safe history found for this batch.</div>
                    ) : (
                      <div className="space-y-3">
                        {historyLogs.map((log, index) => (
                          <div key={log.id || `${log.createdAt}-${index}`} className="rounded-lg border p-4">
                            {log.eventType ? <Badge className={eventBadgeClass(log.eventType)}>{humanStatusLabel(log.eventType)}</Badge> : null}
                            <div className="mt-2 font-medium">{historySummary(log)}</div>
                            <div className="mt-2 text-xs text-muted-foreground">By {historyActor(log)} · {log.createdAt ? format(new Date(log.createdAt), "PPp") : "-"}</div>
                          </div>
                        ))}
                      </div>
                    )}
                  </TabsContent>
                </div>
              </ScrollArea>
            </Tabs>
          </>
        ) : isSuperAdminMode ? (
          <>
            <DialogHeader className="border-b px-6 py-5">
              <DialogTitle className="text-2xl">{workspace.sourceBatchName}</DialogTitle>
              <DialogDescription className="max-w-2xl">
                Super admin governance view for ownership, allocation ranges, reissue decisions, QR state, and audit oversight.
              </DialogDescription>
              <div className="flex flex-wrap items-center gap-2 text-xs">
                <Badge variant="secondary">Platform governance</Badge>
                <Badge variant="outline">{workspace.originalTotalCodes.toLocaleString()} total labels</Badge>
                <Badge variant={workspace.blockedCodes > 0 ? "destructive" : "secondary"}>{workspace.blockedCodes.toLocaleString()} canceled/replaced or blocked</Badge>
              </div>
            </DialogHeader>
            <Tabs key={`${workspace.sourceBatchId}:super:${initialTab}`} defaultValue={initialTab} className="flex min-h-0 flex-1 flex-col">
              <div className="border-b px-6 py-3">
                <TabsList className="grid w-full grid-cols-3 sm:w-[28rem]">
                  <TabsTrigger value="overview">Overview</TabsTrigger>
                  <TabsTrigger value="operations">Governance</TabsTrigger>
                  <TabsTrigger value="audit">Audit</TabsTrigger>
                </TabsList>
              </div>
              <ScrollArea type="always" scrollHideDelay={0} className="min-h-0 flex-1">
                <div className="px-6 py-5 pr-8">
                  <TabsContent value="overview" className="mt-0 space-y-5">
                    <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                      <div className="rounded-lg border bg-muted/20 p-4">
                        <div className="text-xs font-medium uppercase text-muted-foreground">Ownership chain</div>
                        <div className="mt-3 text-sm font-semibold">{workspace.licensee?.name || "Licensee not recorded"}</div>
                        <div className="text-xs text-muted-foreground">{workspace.manufacturerCount.toLocaleString()} manufacturer allocation{workspace.manufacturerCount === 1 ? "" : "s"}</div>
                      </div>
                      <div className="rounded-lg border bg-muted/20 p-4">
                        <div className="text-xs font-medium uppercase text-muted-foreground">Original QR range</div>
                        <div className="mt-3 font-mono text-xs break-all">{workspace.sourceOriginalRangeStart} to {workspace.sourceOriginalRangeEnd}</div>
                      </div>
                      <div className="rounded-lg border bg-muted/20 p-4">
                        <div className="text-xs font-medium uppercase text-muted-foreground">Printed / remaining</div>
                        <div className="mt-3 text-2xl font-semibold">{workspace.printedCodes.toLocaleString()} / {workspace.pendingPrintableCodes.toLocaleString()}</div>
                      </div>
                      <div className="rounded-lg border bg-muted/20 p-4">
                        <div className="text-xs font-medium uppercase text-muted-foreground">Public QR state</div>
                        <div className="mt-3 text-sm">Canceled/replaced: {workspace.blockedCodes.toLocaleString()}</div>
                        <div className="text-xs text-muted-foreground">Original and replacement QR verification state is controlled by backend policy.</div>
                      </div>
                    </div>
                    <div className="rounded-lg border p-4">
                      <div className="font-semibold">Allocation / ranges</div>
                      <div className="mt-3 space-y-3">
                        {workspace.allocations.length === 0 ? (
                          <div className="rounded-md border border-dashed p-3 text-sm text-muted-foreground">No manufacturer allocations found.</div>
                        ) : workspace.allocations.map((allocation) => (
                          <div key={allocation.batchId} className="rounded-md border bg-muted/10 p-3 text-sm">
                            <div className="flex flex-wrap items-start justify-between gap-3">
                              <div>
                                <div className="font-medium">{allocation.manufacturerName}</div>
                                <div className="font-mono text-xs text-muted-foreground">{allocation.batchRangeStart} to {allocation.batchRangeEnd}</div>
                              </div>
                              <Badge variant="secondary">{allocation.allocatedCodes.toLocaleString()} assigned</Badge>
                            </div>
                            <div className="mt-2 grid gap-2 text-xs text-muted-foreground sm:grid-cols-4">
                              <div>Confirmed {allocation.printedCodes.toLocaleString()}</div>
                              <div>Remaining {allocation.printableCodes.toLocaleString()}</div>
                              <div>Scanned {allocation.redeemedCodes.toLocaleString()}</div>
                              <div>Canceled/replaced {allocation.blockedCodes.toLocaleString()}</div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </TabsContent>
                  <TabsContent value="operations" className="mt-0 space-y-5">
                    <div className="rounded-lg border p-4">
                      <div className="font-semibold">Reissue / replacement approvals</div>
                      <p className="mt-1 text-sm text-muted-foreground">
                        Super admin approves or rejects replacement allocation. Manufacturer-local print jobs are not started from this governance view.
                      </p>
                      <div className="mt-3 space-y-2">
                        <Label htmlFor="super-reissue-decision-note">Decision note</Label>
                        <Input
                          id="super-reissue-decision-note"
                          value={reissueDecisionNote}
                          onChange={(event) => onReissueDecisionNoteChange(event.target.value)}
                          placeholder="Explain the platform decision"
                        />
                      </div>
                      {reissueRequests.length === 0 ? (
                        <div className="mt-3 rounded-lg border border-dashed bg-muted/10 p-4 text-sm text-muted-foreground">No forwarded reissue requests are waiting for super admin decision.</div>
                      ) : (
                        <div className="mt-3 space-y-2">
                          {reissueRequests.map((request) => (
                            <div
                              key={request.id}
                              data-testid={highlightedReissueRequestId === request.id ? "highlighted-reissue-request" : undefined}
                              className={`rounded-lg border bg-background p-3 text-sm ${
                                highlightedReissueRequestId === request.id ? "border-emerald-300 bg-emerald-50/60" : ""
                              }`}
                            >
                              <div className="flex flex-wrap items-start justify-between gap-3">
                                <div>
                                  <div className="font-medium">{request.batch?.name || "Forwarded reissue request"}</div>
                                  <div className="mt-1 text-xs text-muted-foreground">
                                    Requested by {request.requestedBy?.name || "User"} · {request.quantity ? `${Number(request.quantity).toLocaleString()} labels` : "Quantity pending"}
                                  </div>
                                  <div className="mt-2 text-xs text-muted-foreground">{request.reason}</div>
                                </div>
                                <Badge variant="secondary">{request.targetApproverRole === "SUPER_ADMIN" ? "Super admin review" : humanStatusLabel(request.status || "review")}</Badge>
                              </div>
                              {request.status === "PENDING" || request.targetApproverRole === "SUPER_ADMIN" ? (
                                <div className="mt-3 flex flex-wrap justify-end gap-2">
                                  <Button
                                    size="sm"
                                    variant="outline"
                                    disabled={decidingReissueRequestId === request.id || reissueDecisionNote.trim().length < 8}
                                    onClick={() => onDecideReissueRequest(request.id, "reject")}
                                  >
                                    Reject
                                  </Button>
                                  <Button
                                    size="sm"
                                    disabled={decidingReissueRequestId === request.id || reissueDecisionNote.trim().length < 8}
                                    onClick={() => onDecideReissueRequest(request.id, "approve")}
                                  >
                                    {decidingReissueRequestId === request.id ? "Saving..." : "Approve replacement allocation"}
                                  </Button>
                                </div>
                              ) : null}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                    <div className="rounded-lg border p-4">
                      <div className="font-semibold">Print recovery oversight</div>
                      <div className="mt-2 text-sm text-muted-foreground">
                        Recovery-needed range: <span className="font-mono">{workspace.remainingRangeStart && workspace.remainingRangeEnd ? `${workspace.remainingRangeStart} to ${workspace.remainingRangeEnd}` : "None reported"}</span>
                      </div>
                    </div>
                  </TabsContent>
                  <TabsContent value="audit" className="mt-0 space-y-4">
                    <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border bg-muted/20 px-4 py-3 text-sm">
                      <div>
                        <div className="font-semibold">Platform audit trail</div>
                        <div className="text-xs text-muted-foreground">
                          {historyLastUpdatedAt ? `Updated ${format(historyLastUpdatedAt, "PPp")}` : "Waiting for first snapshot..."}
                        </div>
                      </div>
                      <Button variant="outline" size="sm" onClick={onRefreshHistory} disabled={historyLoading}>
                        <RefreshButtonLabel loading={historyLoading} />
                      </Button>
                    </div>
                    {historyLoading ? (
                      <div className="rounded-lg border border-dashed bg-muted/10 p-6 text-sm text-muted-foreground">Loading audit history...</div>
                    ) : historyLogs.length === 0 ? (
                      <div className="rounded-lg border border-dashed bg-muted/10 p-6 text-sm text-muted-foreground">No audit history found for this batch.</div>
                    ) : (
                      <div className="space-y-3">
                        {historyLogs.map((log, index) => (
                          <div key={log.id || `${log.createdAt}-${index}`} className="rounded-lg border p-4">
                            {log.eventType ? <Badge className={eventBadgeClass(log.eventType)}>{humanStatusLabel(log.eventType)}</Badge> : null}
                            <div className="mt-2 font-medium">{historySummary(log)}</div>
                            <div className="mt-2 text-xs text-muted-foreground">By {historyActor(log)} · {log.createdAt ? format(new Date(log.createdAt), "PPp") : "-"}</div>
                          </div>
                        ))}
                      </div>
                    )}
                  </TabsContent>
                </div>
              </ScrollArea>
            </Tabs>
          </>
        ) : (
          <>
            <DialogHeader className="border-b px-6 py-5">
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div className="space-y-2">
                  <DialogTitle className="text-2xl">{workspace.sourceBatchName}</DialogTitle>
                  <DialogDescription className="max-w-2xl">
                    Stable batch workspace for licensee operations. The main list stays clean while allocation, print status, and audit details are managed here.
                  </DialogDescription>
                  <div className="flex flex-wrap items-center gap-2 text-xs">
                    <Badge variant="secondary">Source batch</Badge>
                    <Badge variant={statusTone(workspace.remainingUnassignedCodes)}>
                      {workspace.remainingUnassignedCodes.toLocaleString()} unassigned remaining
                    </Badge>
                    <Badge variant={statusTone(workspace.assignedCodes)}>
                      {workspace.assignedCodes.toLocaleString()} assigned
                    </Badge>
                    <Badge variant="outline">{workspace.originalTotalCodes.toLocaleString()} total QR codes</Badge>
                  </div>
                </div>
                <div className="min-w-[16rem] rounded-2xl border bg-muted/20 px-4 py-3 text-sm">
	                  <div className="text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground">Label range</div>
                  <div className="mt-2 font-mono text-xs break-all">
                    {workspace.sourceOriginalRangeStart}{" -> "}{workspace.sourceOriginalRangeEnd}
                  </div>
                  <div className="mt-3 text-xs text-muted-foreground">
                    Updated {workspace.sourceUpdatedAt ? format(new Date(workspace.sourceUpdatedAt), "PPp") : "-"}
                  </div>
                </div>
              </div>
            </DialogHeader>

            <Tabs key={`${workspace.sourceBatchId}:${initialTab}`} defaultValue={initialTab} className="flex min-h-0 flex-1 flex-col">
              <div className="border-b px-6 py-3">
                <TabsList className="grid w-full grid-cols-3 sm:w-[26rem]">
                  <TabsTrigger data-testid="batch-workspace-tab-overview" value="overview">Overview</TabsTrigger>
                  <TabsTrigger data-testid="batch-workspace-tab-operations" value="operations">Operations</TabsTrigger>
                  <TabsTrigger data-testid="batch-workspace-tab-audit" value="audit">Audit</TabsTrigger>
                </TabsList>
              </div>

              <ScrollArea type="always" scrollHideDelay={0} className="min-h-0 flex-1">
                <div className="px-6 py-5 pr-8">
                  <TabsContent value="overview" className="mt-0 space-y-6">
                    <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                      <div className="rounded-2xl border bg-muted/20 p-4">
                        <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground">
                          <Boxes className="h-4 w-4" />
                          Total QR count
                        </div>
                        <div className="mt-3 text-3xl font-semibold">{workspace.originalTotalCodes.toLocaleString()}</div>
                        <div className="mt-2 text-xs text-muted-foreground">Original quantity received into this source batch.</div>
                      </div>
                      <div className="rounded-2xl border bg-muted/20 p-4">
                        <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground">
                          <ShieldCheck className="h-4 w-4" />
                          Remaining unassigned
                        </div>
                        <div className="mt-3 text-3xl font-semibold">{workspace.remainingUnassignedCodes.toLocaleString()}</div>
                        <div className="mt-2 text-xs text-muted-foreground font-mono break-all">
                          {workspace.remainingRangeStart && workspace.remainingRangeEnd
	                            ? `${workspace.remainingRangeStart} to ${workspace.remainingRangeEnd}`
                            : "No unassigned range remains."}
                        </div>
                      </div>
                      <div className="rounded-2xl border bg-muted/20 p-4">
                        <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground">
                          <Factory className="h-4 w-4" />
                          Assigned to manufacturers
                        </div>
                        <div className="mt-3 text-3xl font-semibold">{workspace.assignedCodes.toLocaleString()}</div>
                        <div className="mt-2 text-xs text-muted-foreground">Across {workspace.manufacturerCount.toLocaleString()} manufacturer account{workspace.manufacturerCount === 1 ? "" : "s"}.</div>
                      </div>
                      <div className="rounded-2xl border bg-muted/20 p-4">
                        <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground">
                          <Printer className="h-4 w-4" />
                          Print progress
                        </div>
                        <div className="mt-3 text-3xl font-semibold">{workspace.printedCodes.toLocaleString()}</div>
                        <div className="mt-2 text-xs text-muted-foreground">Printed {workspace.printedCodes.toLocaleString()} · Ready {workspace.pendingPrintableCodes.toLocaleString()}</div>
                      </div>
                    </div>

                    <div className="grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
                      <div className="space-y-4">
                        <div>
                          <div className="text-sm font-semibold">Assigned quantities by manufacturer</div>
                          <p className="mt-1 text-sm text-muted-foreground">
                            Every manufacturer allocation remains traceable under this source batch.
                          </p>
                        </div>
                        {workspace.manufacturerSummary.length === 0 ? (
                          <div className="rounded-2xl border border-dashed bg-muted/10 p-6 text-sm text-muted-foreground">
                            No manufacturer allocations yet. Use the operations tab to allocate a controlled quantity.
                          </div>
                        ) : (
                          <div className="space-y-3">{workspace.manufacturerSummary.map(renderManufacturerLine)}</div>
                        )}
                      </div>

                      <div className="space-y-4">
                        <div className="rounded-2xl border bg-muted/20 p-4">
                          <div className="text-sm font-semibold">Print status</div>
                          <div className="mt-4 grid gap-3 text-sm">
                            <div className="flex items-center justify-between">
                              <span className="text-muted-foreground">Ready to print</span>
                              <Badge variant={statusTone(workspace.pendingPrintableCodes)}>{workspace.pendingPrintableCodes.toLocaleString()}</Badge>
                            </div>
                            <div className="flex items-center justify-between">
                              <span className="text-muted-foreground">Printed</span>
                              <Badge variant={statusTone(workspace.printedCodes)}>{workspace.printedCodes.toLocaleString()}</Badge>
                            </div>
                            <div className="flex items-center justify-between">
                              <span className="text-muted-foreground">Redeemed</span>
                              <Badge variant={statusTone(workspace.redeemedCodes)}>{workspace.redeemedCodes.toLocaleString()}</Badge>
                            </div>
                            <div className="flex items-center justify-between">
                              <span className="text-muted-foreground">Blocked</span>
                              <Badge variant={workspace.blockedCodes > 0 ? "destructive" : "secondary"}>{workspace.blockedCodes.toLocaleString()}</Badge>
                            </div>
                          </div>
                        </div>

                        <div className="rounded-2xl border bg-muted/20 p-4 text-sm">
                          <div className="font-semibold">Source batch details</div>
                          <div className="mt-3 space-y-2 text-muted-foreground">
                            <div className="flex items-start justify-between gap-3">
                              <span>Licensee</span>
                              <span className="text-right text-foreground">{workspace.licensee?.name || "-"}</span>
                            </div>
                            <div className="flex items-start justify-between gap-3">
                              <span>Created</span>
                              <span className="text-right text-foreground">{workspace.sourceCreatedAt ? format(new Date(workspace.sourceCreatedAt), "PPp") : "-"}</span>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </TabsContent>

                  <TabsContent value="operations" className="mt-0 space-y-6">
                    <div className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
                      <div className="rounded-2xl border p-5">
                        <div className="flex items-center gap-2 text-base font-semibold">
                          <UserCog className="h-4 w-4" />
                          Allocate to manufacturer
                        </div>
                        <p className="mt-2 text-sm text-muted-foreground">
                          The source batch remains the stable operational record. Only the allocated quantity is created as a manufacturer batch.
                        </p>

                        {!canAssignManufacturer ? (
                          <div className="mt-4 rounded-xl border border-dashed bg-muted/10 p-4 text-sm text-muted-foreground">
                            You do not have permission to allocate batches.
                          </div>
                        ) : !sourceBatch ? (
                          <div className="mt-4 rounded-xl border border-dashed bg-muted/10 p-4 text-sm text-muted-foreground">
                            The source batch record is unavailable for allocation.
                          </div>
                        ) : (
                          <div className="mt-5 space-y-4">
                            <div className="space-y-2">
                              <Label>Manufacturer</Label>
                              <Select value={assignManufacturerId} onValueChange={onAssignManufacturerChange}>
                                <SelectTrigger data-testid="batch-workspace-manufacturer-select">
                                  <SelectValue placeholder="Select manufacturer" />
                                </SelectTrigger>
                                <SelectContent>
                                  {manufacturers.length === 0 ? (
                                    <SelectItem value="__none__" disabled>
                                      No manufacturers available
                                    </SelectItem>
                                  ) : (
                                    manufacturers.map((manufacturer) => (
                                      <SelectItem key={manufacturer.id} value={manufacturer.id}>
                                        {manufacturer.name} ({manufacturer.email})
                                      </SelectItem>
                                    ))
                                  )}
                                </SelectContent>
                              </Select>
                            </div>
                            <div className="space-y-2">
                              <Label>Quantity to allocate</Label>
                              <Input
                                data-testid="batch-workspace-assign-quantity"
                                type="number"
                                min={1}
                                value={assignQuantity}
                                onChange={(event) => onAssignQuantityChange(event.target.value)}
                                placeholder="Enter quantity"
                              />
                              <div className="text-xs text-muted-foreground">
                                Remaining unassigned in source batch: {remaining.toLocaleString()}
                              </div>
                              {assignQuantityValue > 0 && remaining >= 0 ? (
                                <div className="text-xs text-muted-foreground">
                                  Remaining after this allocation: {Math.max(remaining - assignQuantityValue, 0).toLocaleString()}
                                </div>
                              ) : null}
                            </div>
                            <div className="flex justify-end">
                              <Button data-testid="batch-workspace-assign-submit" onClick={onSubmitAssign} disabled={assigning || remaining <= 0}>
                                {assigning ? "Allocating..." : "Allocate quantity"}
                              </Button>
                            </div>
                          </div>
                        )}
                      </div>

                      <div className="rounded-2xl border p-5">
                        <div className="text-base font-semibold">Manage source batch</div>
                        <p className="mt-2 text-sm text-muted-foreground">
                          Review split structure, rename the source batch label, export the audit package, or remove the source batch when it is safe to do so.
                        </p>
                        <Separator className="my-4" />
                        <div className="grid gap-2">
                          <Button variant="outline" className="justify-start" onClick={onOpenRename} disabled={!sourceBatch}>
                            <PencilLine className="mr-2 h-4 w-4" />
                            Rename source batch
                          </Button>
                          <Button variant="outline" className="justify-start" onClick={onOpenAllocationMap}>
                            <Activity className="mr-2 h-4 w-4" />
                            View allocation structure
                          </Button>
                          <Button variant="outline" className="justify-start" onClick={onDownloadAudit} disabled={exportingAudit}>
                            <Download className="mr-2 h-4 w-4" />
                            {exportingAudit ? "Preparing audit package..." : "Download audit package"}
                          </Button>
                          {canDelete ? (
                            <Button variant="outline" className="justify-start text-destructive" onClick={onDelete} disabled={!sourceBatch}>
                              <Trash2 className="mr-2 h-4 w-4" />
                              Delete source batch
                            </Button>
                          ) : null}
                        </div>
                        <div className="mt-4 rounded-xl border bg-muted/20 p-4 text-xs text-muted-foreground">
	                          If manufacturers have already received allocations, deletion is blocked to preserve traceability.
                        </div>
                      </div>
                    </div>

                    <div className="rounded-2xl border p-5">
                      <div className="flex flex-wrap items-start justify-between gap-3">
                        <div>
                          <div className="text-base font-semibold">Controlled reissue</div>
                          <p className="mt-2 max-w-3xl text-sm text-muted-foreground">
                            Reissue is an exception path only. Manufacturers request replacement labels for brand-admin approval; brand admins request source-batch reissue for super-admin approval.
                          </p>
                        </div>
                        <Badge variant="secondary">{recentPrintJobs.length} recent job{recentPrintJobs.length === 1 ? "" : "s"}</Badge>
                      </div>

                      {!canRequestReissue ? (
                        <div className="mt-4 rounded-xl border border-dashed bg-muted/10 p-4 text-sm text-muted-foreground">
                          Reissue requests are only available to users with batch print responsibility.
                        </div>
                      ) : (
                        <div className="mt-5 space-y-4">
                          <div className="space-y-2">
                            <Label htmlFor="batch-reissue-reason">Request reason</Label>
                            <Input
                              id="batch-reissue-reason"
                              value={reissueReason}
                              onChange={(event) => onReissueReasonChange(event.target.value)}
                              placeholder="Explain why replacement labels are required"
                            />
                            <div className="text-xs text-muted-foreground">
                              This reason is written to the audit trail and reviewed before replacement labels can be printed.
                            </div>
                          </div>

                          <div className="rounded-xl border bg-muted/10 p-4">
                            <div className="flex flex-wrap items-center justify-between gap-3">
                              <div>
                                <div className="font-medium">
                                  {showingApprovedReissueRequests ? "Replacement labels ready" : "Pending reissue reviews"}
                                </div>
                                <div className="mt-1 text-xs text-muted-foreground">
                                  {showingApprovedReissueRequests
                                    ? "Approved replacement labels wait here until the manufacturer starts secure printing."
                                    : "Only requests in your approval scope are shown here."}
                                </div>
                              </div>
                              <Button variant="outline" size="sm" onClick={onRefreshReissueRequests} disabled={reissueRequestsLoading}>
                                {reissueRequestsLoading ? "Refreshing..." : "Refresh"}
                              </Button>
                            </div>
                            {!showingApprovedReissueRequests ? (
                              <div className="mt-3 space-y-2">
                                <Label htmlFor="batch-reissue-decision-note">Decision note</Label>
                                <Input
                                  id="batch-reissue-decision-note"
                                  value={reissueDecisionNote}
                                  onChange={(event) => onReissueDecisionNoteChange(event.target.value)}
                                  placeholder="Explain the approval or rejection"
                                />
                              </div>
                            ) : null}
                            {reissueRequestsLoading ? (
                              <div className="mt-3 rounded-lg border border-dashed bg-background p-3 text-sm text-muted-foreground">
                                Loading requests...
                              </div>
                            ) : reissueRequests.length === 0 ? (
                              <div className="mt-3 rounded-lg border border-dashed bg-background p-3 text-sm text-muted-foreground">
                                {showingApprovedReissueRequests
                                  ? "No approved replacement labels are ready to print."
                                  : "No pending reissue requests in this scope."}
                              </div>
                            ) : (
                              <div className="mt-3 space-y-2">
                                {reissueRequests.map((request) => (
                                  <div
                                    key={request.id}
                                    data-testid={highlightedReissueRequestId === request.id ? "highlighted-reissue-request" : undefined}
                                    className={`rounded-lg border bg-background p-3 text-sm ${
                                      highlightedReissueRequestId === request.id ? "border-emerald-300 bg-emerald-50/60" : ""
                                    }`}
                                  >
                                    <div className="flex flex-wrap items-start justify-between gap-3">
                                      <div>
                                        <div className="font-medium">{request.batch?.name || "Batch reissue request"}</div>
                                        <div className="mt-2 grid gap-2 text-xs text-muted-foreground sm:grid-cols-2 lg:grid-cols-3">
                                          <div>Requested {reissueRequestedCount(request).toLocaleString()} labels</div>
                                          <div>Range <span className="font-mono">{reissueRange(request)}</span></div>
                                          <div>Requester {reissueRequester(request)}</div>
                                          <div>Requested {formatDateTime(request.requestedAt)}</div>
                                          <div>Related print job {request.originalPrintJobNumber || request.originalPrintJobId || "Not recorded"}</div>
                                          <div>{reissueSafeEvidenceLabel(request)}</div>
                                        </div>
                                        <div className="mt-2 text-xs text-muted-foreground">Reason: {request.reason || "No reason recorded"}</div>
                                        <div className="mt-1 text-xs text-muted-foreground">
                                          Status: {reissueStatusLabel(request)}
                                          {request.nextAction ? ` · Next action: ${request.nextAction}` : ""}
                                        </div>
                                      </div>
                                      <Badge variant="secondary">
                                        {request.status === "APPROVED"
                                          ? "Ready to print"
                                          : request.status === "EXECUTED"
                                            ? "Replacement allocated"
                                          : request.targetApproverRole === "SUPER_ADMIN"
                                            ? "Forwarded to super admin"
                                            : "Brand admin review"}
                                      </Badge>
                                    </div>
                                    {request.status === "APPROVED" ? (
                                      <div className="mt-3 space-y-2">
                                        {reissuePrintRecoveryById[request.id] ? (
                                          <div className="rounded-md border border-amber-200 bg-amber-50 p-2 text-xs text-amber-800">
                                            {reissuePrintRecoveryById[request.id]}
                                          </div>
                                        ) : null}
                                        <div className="flex flex-wrap justify-end gap-2">
                                          {reissuePrintRecoveryById[request.id] ? (
                                            <Button size="sm" variant="outline" onClick={onRefreshPrinterStatus}>
                                              Refresh printer status
                                            </Button>
                                          ) : null}
                                          <Button
                                            size="sm"
                                            disabled={printingReissueRequestId === request.id}
                                            onClick={() => onPrintApprovedReissueRequest(request.id)}
                                          >
                                            {printingReissueRequestId === request.id ? "Checking printer..." : "Print replacement labels"}
                                          </Button>
                                        </div>
                                      </div>
                                    ) : (
                                      <div className="mt-3 flex flex-wrap justify-end gap-2">
                                        <Button
                                          size="sm"
                                          variant="outline"
                                          disabled={decidingReissueRequestId === request.id || reissueDecisionNote.trim().length < 8}
                                          onClick={() => onDecideReissueRequest(request.id, "reject")}
                                        >
                                          Reject
                                        </Button>
                                        <Button
                                          size="sm"
                                          disabled={decidingReissueRequestId === request.id || reissueDecisionNote.trim().length < 8}
                                          onClick={() => onDecideReissueRequest(request.id, "approve")}
                                        >
                                          {decidingReissueRequestId === request.id ? "Saving..." : "Approve"}
                                        </Button>
                                      </div>
                                    )}
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>

                          {printJobsLoading ? (
                            <div className="rounded-xl border border-dashed bg-muted/10 p-4 text-sm text-muted-foreground">
                              Loading recent print jobs...
                            </div>
                          ) : recentPrintJobs.length === 0 ? (
                            <div className="rounded-xl border border-dashed bg-muted/10 p-4 text-sm text-muted-foreground">
                              No recent print jobs were found for this source batch yet.
                            </div>
                          ) : (
                            <div className="space-y-3">
                              {recentPrintJobs.map((job) => (
                                <div key={job.id} className="rounded-xl border bg-muted/10 p-4">
                                  <div className="flex flex-wrap items-start justify-between gap-3">
                                    <div className="space-y-2">
                                      <div className="flex flex-wrap items-center gap-2">
                                        <div className="font-medium text-foreground">{job.jobNumber || "Print job"}</div>
                                        <Badge variant={getPrintJobStatusBadgeVariant(job)}>
                                          {getPrintJobStageLabel(job)}
                                        </Badge>
                                        {job.reprintOfJobId ? <Badge variant="outline">Replacement</Badge> : null}
                                      </div>
                                      <div className="text-xs text-muted-foreground">
                                        {job.printer?.name || "Saved printer"} · requested {getPrintRunCounts(job).requested.toLocaleString()} labels
                                        {job.confirmedAt ? ` · confirmed ${format(new Date(job.confirmedAt), "PPp")}` : ""}
                                      </div>
                                      <div className="text-xs text-muted-foreground">
                                        Operator: {printJobOperator(job)}
                                      </div>
                                      <div className="flex flex-wrap gap-1 text-xs">
                                        <Badge variant="outline">Confirmed {getPrintRunCounts(job).confirmed.toLocaleString()}</Badge>
                                        <Badge variant="outline">Pending/unconfirmed {getPrintRunCounts(job).pending.toLocaleString()}</Badge>
                                        <Badge variant={getPrintRunCounts(job).failed > 0 ? "destructive" : "outline"}>
                                          Failed {getPrintRunCounts(job).failed.toLocaleString()}
                                        </Badge>
                                      </div>
                                      {needsRecovery(job) ? (
                                        <div className="rounded-md border border-amber-200 bg-amber-50 p-2 text-xs text-amber-800">
                                          <div>{getRecoveryInstruction(job).firstLine}</div>
                                          <div>{getRecoveryInstruction(job).secondLine}</div>
                                        </div>
                                      ) : null}
                                      {job.reprintReason ? (
                                        <div className="text-xs text-muted-foreground">Reason: {job.reprintReason}</div>
                                      ) : null}
                                      {job.latestDecision ? (
                                        <div className="space-y-2">
                                          <div className="flex flex-wrap gap-1">
                                            <Badge className={decisionOutcomeTone(job.latestDecision.outcome)}>
                                              {titleCaseDecisionValue(job.latestDecision.outcome)}
                                            </Badge>
                                            <Badge className={decisionRiskTone(job.latestDecision.riskBand)}>
                                              {titleCaseDecisionValue(job.latestDecision.riskBand)}
                                            </Badge>
                                            <Badge className={decisionTrustTone(job.latestDecision.customerTrustReviewState)}>
                                              {titleCaseDecisionValue(job.latestDecision.customerTrustReviewState)}
                                            </Badge>
                                            <Badge className={presentPrintTrustState(job.latestDecision).tone}>
                                              {presentPrintTrustState(job.latestDecision).label}
                                            </Badge>
                                          </div>
                                          <div className="text-xs text-muted-foreground">
                                            {presentPrintTrustState(job.latestDecision).guidance}
                                          </div>
                                        </div>
                                      ) : null}
                                      {job.failureReason ? (
                                        <div className="text-xs text-destructive">Failure: {job.failureReason}</div>
                                      ) : null}
                                    </div>
                                    <div className="flex items-center gap-2">
                                      <Button
                                        size="sm"
                                        variant="outline"
                                        disabled={!isEligibleForReissue(job) || !reissueReason.trim() || reissuingJobId === job.id}
                                        onClick={() => onRequestReissue(job.id)}
                                      >
                                        {reissuingJobId === job.id ? "Submitting..." : "Request reissue"}
                                      </Button>
                                    </div>
                                  </div>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  </TabsContent>

                  <TabsContent value="audit" className="mt-0 space-y-4">
                    <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border bg-muted/20 px-4 py-3 text-sm">
                      <div>
                        <div className="font-semibold">History and audit</div>
                        <div className="text-xs text-muted-foreground">
                          {historyLastUpdatedAt ? `Updated ${format(historyLastUpdatedAt, "PPp")}` : "Waiting for first snapshot..."}
                        </div>
                      </div>
                      <Button variant="outline" size="sm" onClick={onRefreshHistory} disabled={historyLoading}>
                        <RefreshButtonLabel loading={historyLoading} />
                      </Button>
                    </div>

                    {historyLoading ? (
                      <div className="rounded-2xl border border-dashed bg-muted/10 p-6 text-sm text-muted-foreground">Loading audit history...</div>
                    ) : historyLogs.length === 0 ? (
                      <div className="rounded-2xl border border-dashed bg-muted/10 p-6 text-sm text-muted-foreground">No history found for this source batch and its allocations.</div>
                    ) : (
                      <div className="space-y-3">
                        {historyLogs.map((log, index) => (
                          <div key={log.id || `${log.createdAt}-${index}`} className="rounded-2xl border p-4">
                            <div className="flex flex-wrap items-start justify-between gap-3">
                              <div className="space-y-2">
	                                {log.eventType ? <Badge className={eventBadgeClass(log.eventType)}>{humanStatusLabel(log.eventType)}</Badge> : null}
                                <div className="font-medium">{historySummary(log)}</div>
                              </div>
                              <div className="text-xs text-muted-foreground">
                                {log.createdAt ? format(new Date(log.createdAt), "PPp") : "-"}
                              </div>
                            </div>
                            <div className="mt-2 text-xs text-muted-foreground">By {historyActor(log)}</div>
                          </div>
                        ))}
                      </div>
                    )}
                  </TabsContent>
                </div>
              </ScrollArea>
            </Tabs>
          </>
        )}
      </DialogContent>
    </Dialog>
    <Dialog open={Boolean(selectedPrintJobDetail)} onOpenChange={(nextOpen) => !nextOpen && setSelectedPrintJobDetail(null)}>
      <DialogContent className="sm:max-w-[620px]">
        <DialogHeader>
          <DialogTitle>{selectedPrintJobDetail?.jobNumber || "Print run details"}</DialogTitle>
          <DialogDescription>
            Requested range, confirmed range, pending recovery, printer, operator, and current status.
          </DialogDescription>
        </DialogHeader>
        {selectedPrintJobDetail ? (
          <div className="space-y-4 text-sm">
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="rounded-md border p-3">
                <div className="text-xs font-medium text-muted-foreground">Requested label range</div>
                <div className="mt-1 font-mono text-xs break-all">{printJobRange(selectedPrintJobDetail)}</div>
              </div>
              <div className="rounded-md border p-3">
                <div className="text-xs font-medium text-muted-foreground">Confirmed label range</div>
                <div className="mt-1 font-mono text-xs break-all">{formatCodeRange(selectedPrintJobDetail.session?.confirmedRange) || "Not confirmed yet"}</div>
              </div>
              <div className="rounded-md border p-3">
                <div className="text-xs font-medium text-muted-foreground">Pending / recovery range</div>
                <div className="mt-1 font-mono text-xs break-all">
                  {formatCodeRange(selectedPrintJobDetail.session?.recoveryRange) ||
                    formatCodeRange(selectedPrintJobDetail.session?.pendingRange) ||
                    "No pending range"}
                </div>
              </div>
              <div className="rounded-md border p-3">
                <div className="text-xs font-medium text-muted-foreground">Status</div>
                <div className="mt-1">{getPrintJobStageLabel(selectedPrintJobDetail)}</div>
              </div>
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <div className="text-xs font-medium text-muted-foreground">Print job ID</div>
                <div className="font-mono text-xs break-all">{selectedPrintJobDetail.id}</div>
              </div>
              <div>
                <div className="text-xs font-medium text-muted-foreground">Operator</div>
                <div>{printJobOperator(selectedPrintJobDetail)}</div>
              </div>
              <div>
                <div className="text-xs font-medium text-muted-foreground">Printer</div>
                <div>{selectedPrintJobDetail.printer?.name || "Saved printer"}</div>
              </div>
              <div>
                <div className="text-xs font-medium text-muted-foreground">Created</div>
                <div>{formatDateTime(selectedPrintJobDetail.createdAt)}</div>
              </div>
              <div>
                <div className="text-xs font-medium text-muted-foreground">Updated</div>
                <div>{formatDateTime(selectedPrintJobDetail.updatedAt)}</div>
              </div>
            </div>
            <div className="grid gap-2 text-xs text-muted-foreground sm:grid-cols-4">
              <div>Requested {getPrintRunCounts(selectedPrintJobDetail).requested.toLocaleString()}</div>
              <div>Confirmed {getPrintRunCounts(selectedPrintJobDetail).confirmed.toLocaleString()}</div>
              <div>Pending {getPrintRunCounts(selectedPrintJobDetail).pending.toLocaleString()}</div>
              <div>Failed {getPrintRunCounts(selectedPrintJobDetail).failed.toLocaleString()}</div>
            </div>
            {needsRecovery(selectedPrintJobDetail) ? (
              <div className="rounded-md border border-amber-200 bg-amber-50 p-3 text-xs text-amber-800">
                <div>{getRecoveryInstruction(selectedPrintJobDetail).firstLine}</div>
                <div>{getRecoveryInstruction(selectedPrintJobDetail).secondLine}</div>
                <div className="mt-1 font-medium">Next action: request re-issue, then print approved replacement labels.</div>
              </div>
            ) : null}
          </div>
        ) : null}
      </DialogContent>
    </Dialog>
    </>
  );
}

function RefreshButtonLabel({ loading }: { loading: boolean }) {
  return <>{loading ? "Refreshing..." : "Refresh history"}</>;
}
