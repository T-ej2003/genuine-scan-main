import { RefreshCw } from "lucide-react";
import { Link } from "react-router-dom";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ActionButton } from "@/components/ui/action-button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { DialogEmptyState } from "@/components/ui/dialog-empty-state";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { getPrinterDispatchLabel, sanitizePrinterUiError } from "@/lib/printer-user-facing";
import { getPlainPrintStatusLabel } from "@/lib/ui-copy";
import { createUiActionState } from "@/lib/ui-actions";

import type {
  BatchRow,
  LocalPrinterRow,
  PrintJobRow,
  PrinterSelectionNotice,
  RegisteredPrinterRow,
} from "@/features/batches/types";

type RenameBatchDialogProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  batch: BatchRow | null;
  value: string;
  onValueChange: (value: string) => void;
  onSubmit: () => void;
  saving: boolean;
};

export function RenameBatchDialog({
  open,
  onOpenChange,
  batch,
  value,
  onValueChange,
  onSubmit,
  saving,
}: RenameBatchDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[520px]">
        <DialogHeader>
          <DialogTitle>Rename batch</DialogTitle>
          <DialogDescription>Update the batch label for easier operations tracking.</DialogDescription>
        </DialogHeader>

        {!batch ? (
          <DialogEmptyState
            title="Choose a batch to rename"
            description="Close this dialog, reopen Rename from the batch you want to update, and MSCQR will restore the current batch context."
            onClose={() => onOpenChange(false)}
          />
        ) : (
          <div className="mt-2 space-y-4">
            <div className="rounded-md border p-3 text-sm">
              <div className="font-medium">{batch.name}</div>
            </div>

            <div className="space-y-2">
              <Label>Batch name</Label>
              <Input
                value={value}
                onChange={(event) => onValueChange(event.target.value)}
                maxLength={120}
                placeholder="Enter batch name"
              />
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <Button variant="outline" onClick={() => onOpenChange(false)} disabled={saving}>
                Cancel
              </Button>
              <Button onClick={onSubmit} disabled={saving}>
                Save
              </Button>
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

type DeleteBatchDialogProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  batch: BatchRow | null;
  deleting: boolean;
  onConfirm: () => void;
};

export function DeleteBatchDialog({
  open,
  onOpenChange,
  batch,
  deleting,
  onConfirm,
}: DeleteBatchDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[560px]">
        <DialogHeader>
          <DialogTitle>Delete batch</DialogTitle>
          <DialogDescription>
            This removes the batch and returns every code in it to the unassigned state.
          </DialogDescription>
        </DialogHeader>

        {!batch ? (
          <DialogEmptyState
            title="Choose a batch to delete"
            description="This action only works from a specific batch row. Close this dialog, return to Batches, and reopen Delete from the batch you want to remove."
            onClose={() => onOpenChange(false)}
          />
        ) : (
          <div className="mt-2 space-y-4">
            <div className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-900">
              <div className="font-medium">{batch.name}</div>
              <div className="mt-1 text-xs">
                This action removes the batch and clears all current manufacturer allocation from this batch.
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <Button variant="outline" onClick={() => onOpenChange(false)} disabled={deleting}>
                Cancel
              </Button>
              <Button variant="destructive" onClick={onConfirm} disabled={deleting}>
                Delete batch
              </Button>
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

type PrintJobDialogProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  isManufacturerMode?: boolean;
  manufacturerRecoveryContext?: {
    printJobId: string;
    jobNumber?: string | null;
    rangeLabel?: string | null;
  } | null;
  printBatch: BatchRow | null;
  selectedPrinterNotice: PrinterSelectionNotice;
  connectorVersionLabel?: string | null;
  printQuantity: string;
  onPrintQuantityChange: (value: string) => void;
  readyToPrintCount: number;
  maxRunQuantity: number;
  registeredPrinters: RegisteredPrinterRow[];
  onRefreshPrinters: () => void;
  selectedPrinterProfileId: string;
  onSelectedPrinterProfileIdChange: (value: string) => void;
  selectedPrinterProfile: RegisteredPrinterRow | null;
  detectedPrinters: LocalPrinterRow[];
  selectedPrinterId: string;
  onSelectedPrinterIdChange: (value: string) => void;
  switchingPrinter: boolean;
  onSwitchSelectedPrinter: () => void;
  relinkingPrinter: boolean;
  selectedLocalProfileRegistrationStale: boolean;
  onRelinkSelectedPrinter: () => void;
  onPrintDiagnosticTestLabel: () => void;
  printing: boolean;
  onStartPrint: () => void;
  selectedPrinterCanPrint: boolean;
  printJobId: string | null;
  printProgressPrinterName: string | null;
  printProgressDispatchMode: string | null;
  printProgressPhase?: string | null;
  printProgressTotal?: number;
  printProgressPrinted?: number;
  formatDispatchModeLabel: (mode?: string | null) => string;
  directRemainingToPrint: number | null;
  printControlDialog?: {
    action: "pause" | "stop" | null;
    job: PrintJobRow | null;
    reason: string;
    submitting: boolean;
  };
  printReissueDialog?: {
    job: PrintJobRow | null;
    reason: string;
    submitting: boolean;
  };
  printControlBusyJobId?: string | null;
  printCooldownRemainingSeconds?: number;
  onOpenPrintControlDialog?: (action: "pause" | "stop", job: PrintJobRow) => void;
  onClosePrintControlDialog?: () => void;
  onPrintControlReasonChange?: (reason: string) => void;
  onSubmitPrintControlDialog?: () => void;
  onResumePrintJob?: (jobId: string) => void;
  onOpenPrintReissueDialog?: (job: PrintJobRow) => void;
  onClosePrintReissueDialog?: () => void;
  onPrintReissueReasonChange?: (reason: string) => void;
  onSubmitPrintReissueRequest?: () => void;
  onRefreshPrintStatus: () => void;
  recentPrintJobs: PrintJobRow[];
  releaseApprovalState?: {
    approvalRequired: boolean;
    approvalId: string;
    status: string;
    expiresAt?: string | null;
    threshold?: number | null;
  } | null;
  onAbandonPrintJob: (jobId: string) => void;
  sampleScanCodeByJobId?: Record<string, string>;
  onSampleScanCodeChange?: (jobId: string, value: string) => void;
  onVerifySampleScan?: (jobId: string) => void;
  onReleaseBatch?: () => void;
  onClose: () => void;
};

type WorkflowStepState = "done" | "current" | "blocked";

const completedLifecycleStates = new Set(["CODES_GENERATED", "PRINT_ACKNOWLEDGED", "PRINT_CONFIRMED", "SAMPLE_VERIFIED", "RELEASED"]);

const buildPrintReleaseChecklist = (params: {
  batch: BatchRow;
  readyToPrintCount: number;
  recentPrintJobs: PrintJobRow[];
  releaseApprovalState: PrintJobDialogProps["releaseApprovalState"];
}) => {
  const latestJob = params.recentPrintJobs[0] || null;
  const lifecycleState = params.batch.lifecycleState || "DRAFT";
  const labelsGenerated =
    completedLifecycleStates.has(lifecycleState) || params.readyToPrintCount > 0 || params.recentPrintJobs.length > 0;
  const sentToPrinter =
    lifecycleState === "PRINT_ACKNOWLEDGED" ||
    lifecycleState === "PRINT_CONFIRMED" ||
    lifecycleState === "SAMPLE_VERIFIED" ||
    lifecycleState === "RELEASED" ||
    Boolean(latestJob?.sentAt) ||
    latestJob?.status === "SENT" ||
    latestJob?.status === "CONFIRMED";
  const printConfirmed =
    lifecycleState === "PRINT_CONFIRMED" ||
    lifecycleState === "SAMPLE_VERIFIED" ||
    lifecycleState === "RELEASED" ||
    latestJob?.status === "CONFIRMED";
  const sampleVerified =
    lifecycleState === "SAMPLE_VERIFIED" ||
    lifecycleState === "RELEASED" ||
    Boolean(latestJob?.sampleScanPolicy?.satisfied);
  const released = lifecycleState === "RELEASED";
  const waitingApproval = Boolean(params.releaseApprovalState?.approvalRequired);
  const releaseLabel = released ? "Released" : waitingApproval ? "Waiting for checker approval" : "Ready to release";
  const releaseDetail = released
    ? "Batch is locked for supply-chain release."
    : waitingApproval
      ? "A second authorized checker must approve this high-value release."
      : sampleVerified
        ? "Release is available after the sample scan proof."
        : "Sample scan proof is required before release.";

  const steps: Array<{ label: string; detail: string; state: WorkflowStepState }> = [
    {
      label: "Labels generated",
      detail: labelsGenerated ? `${params.batch.totalCodes.toLocaleString()} labels are database-backed.` : "Generate labels before printing.",
      state: labelsGenerated ? "done" : "current",
    },
    {
      label: "Sent to printer",
      detail: sentToPrinter ? "Printer acknowledgement recorded." : "Choose the printer and send the print run.",
      state: sentToPrinter ? "done" : labelsGenerated ? "current" : "blocked",
    },
    {
      label: "Printed confirmed",
      detail: printConfirmed ? "An operator confirmed the physical labels." : "Confirm only after labels physically print.",
      state: printConfirmed ? "done" : sentToPrinter ? "current" : "blocked",
    },
    {
      label: "Sample verified",
      detail: sampleVerified ? "One printed label from this run verified." : "Scan one printed QR from this exact run.",
      state: sampleVerified ? "done" : printConfirmed ? "current" : "blocked",
    },
    {
      label: releaseLabel,
      detail: releaseDetail,
      state: released ? "done" : sampleVerified ? "current" : "blocked",
    },
  ];

  return { latestJob, steps };
};

export function BatchPrintJobDialog({
  open,
  onOpenChange,
  isManufacturerMode = false,
  manufacturerRecoveryContext = null,
  printBatch,
  selectedPrinterNotice,
  connectorVersionLabel,
  printQuantity,
  onPrintQuantityChange,
  readyToPrintCount,
  maxRunQuantity,
  registeredPrinters,
  onRefreshPrinters,
  selectedPrinterProfileId,
  onSelectedPrinterProfileIdChange,
  selectedPrinterProfile,
  detectedPrinters,
  selectedPrinterId,
  onSelectedPrinterIdChange,
  switchingPrinter,
  onSwitchSelectedPrinter,
  relinkingPrinter,
  selectedLocalProfileRegistrationStale,
  onRelinkSelectedPrinter,
  onPrintDiagnosticTestLabel,
  printing,
  onStartPrint,
  selectedPrinterCanPrint,
  printJobId,
  printProgressPrinterName,
  printProgressDispatchMode,
  printProgressPhase = null,
  printProgressTotal = 0,
  printProgressPrinted = 0,
  formatDispatchModeLabel,
  directRemainingToPrint,
  printControlDialog = { action: null, job: null, reason: "", submitting: false },
  printReissueDialog = { job: null, reason: "", submitting: false },
  printControlBusyJobId = null,
  printCooldownRemainingSeconds = 0,
  onOpenPrintControlDialog = () => undefined,
  onClosePrintControlDialog = () => undefined,
  onPrintControlReasonChange = () => undefined,
  onSubmitPrintControlDialog = () => undefined,
  onResumePrintJob = () => undefined,
  onOpenPrintReissueDialog = () => undefined,
  onClosePrintReissueDialog = () => undefined,
  onPrintReissueReasonChange = () => undefined,
  onSubmitPrintReissueRequest = () => undefined,
  onRefreshPrintStatus,
  recentPrintJobs,
  releaseApprovalState = null,
  onAbandonPrintJob,
  sampleScanCodeByJobId = {},
  onSampleScanCodeChange = () => undefined,
  onVerifySampleScan = () => undefined,
  onReleaseBatch = () => undefined,
  onClose,
}: PrintJobDialogProps) {
  const workflow = printBatch
    ? isManufacturerMode
      ? null
      : buildPrintReleaseChecklist({
        batch: printBatch,
        readyToPrintCount,
        recentPrintJobs,
        releaseApprovalState,
      })
    : null;
  const batchPrintReadiness = printBatch?.printReadiness || null;
  const batchLifecycleBlocked =
    Boolean(batchPrintReadiness && batchPrintReadiness.printable === false && readyToPrintCount > 0);
  const batchLifecycleBlockReason =
    batchPrintReadiness?.userMessage ||
    batchPrintReadiness?.requiredPreviousStep ||
    "Complete the previous batch step first.";
  const isJobActive = (job: PrintJobRow) =>
    ["PENDING", "SENT"].includes(job.status) ||
    ["ACTIVE", "RESUME_PENDING", "RETRY_WAITING"].includes(String(job.session?.status || "").toUpperCase()) ||
    ["PRINT_CONFIRMED", "PRINTER_ACKNOWLEDGED", "QUEUED"].includes(String(job.pipelineState || "").toUpperCase());
  const isJobPaused = (job: PrintJobRow) =>
    job.status === "PAUSED" || String(job.session?.status || "").toUpperCase() === "PAUSED";
  const canStopJob = (job: PrintJobRow) =>
    isJobActive(job) || isJobPaused(job);
  const canRequestReissue = (job: PrintJobRow) =>
    job.status === "CONFIRMED" || job.pipelineState === "LOCKED" || job.pipelineState === "PRINT_CONFIRMED";
  const printControlTitle =
    printControlDialog.action === "stop" ? "Stop print run" : "Pause print run";
  const printControlDescription =
    printControlDialog.action === "stop"
      ? "Stopping prevents any new label dispatch. Already confirmed labels stay printed and the remaining labels stay visible for controlled recovery."
      : "Pausing stops new label dispatch while preserving labels already confirmed by MSCQR.";
  const activePrintJob =
    (printJobId ? recentPrintJobs.find((job) => job.id === printJobId) : null) ||
    (printJobId
      ? ({
          id: printJobId,
          status: "SENT",
          printMode: printProgressDispatchMode || selectedPrinterProfile?.connectionType || "LOCAL_AGENT",
          quantity: printProgressTotal || directRemainingToPrint || Number(printQuantity || 0) || 0,
          itemCount: printProgressTotal || directRemainingToPrint || Number(printQuantity || 0) || 0,
          createdAt: new Date().toISOString(),
          printer: { name: printProgressPrinterName || selectedPrinterProfile?.name || "Selected printer" },
          session: {
            status: "ACTIVE",
            totalItems: printProgressTotal || directRemainingToPrint || Number(printQuantity || 0) || 0,
            confirmedItems: printProgressPrinted || 0,
            remainingToPrint:
              directRemainingToPrint ??
              Math.max(0, (printProgressTotal || Number(printQuantity || 0) || 0) - (printProgressPrinted || 0)),
          },
        } as PrintJobRow)
      : null);
  const activeTotal = Number(activePrintJob?.session?.totalItems || activePrintJob?.itemCount || activePrintJob?.quantity || printProgressTotal || 0);
  const activeConfirmed = Number(activePrintJob?.session?.confirmedItems ?? printProgressPrinted ?? 0);
  const activeRemaining =
    typeof activePrintJob?.session?.remainingToPrint === "number"
      ? Math.max(0, activePrintJob.session.remainingToPrint)
      : activeTotal > 0
        ? Math.max(0, activeTotal - activeConfirmed)
        : Math.max(0, Number(directRemainingToPrint || 0));
  const activeSessionStatus = String(activePrintJob?.session?.status || "").toUpperCase();
  const activePipelineState = String(activePrintJob?.pipelineState || "").toUpperCase();
  const activeStoppedOrPartial =
    activePrintJob?.status === "PARTIALLY_COMPLETED" ||
    activePrintJob?.status === "STOPPED" ||
    activePipelineState === "STOPPED" ||
    activeSessionStatus === "STOPPED";
  const activeCompleted =
    !activeStoppedOrPartial &&
    (activePrintJob?.status === "CONFIRMED" ||
      activeSessionStatus === "COMPLETED" ||
      (activeTotal > 0 && activeConfirmed >= activeTotal));
  const activeWaitingForConfirmation =
    Boolean(activePrintJob?.awaitingConfirmation) ||
    /waiting for printer confirmation/i.test(String(printProgressPhase || "")) ||
    Number(activePrintJob?.session?.awaitingConfirmationCount || 0) > 0;
  const showActivePrintControls = Boolean(
    activePrintJob &&
      !activeStoppedOrPartial &&
      !activeCompleted &&
      (activePrintJob.status === "SENT" ||
        activePrintJob.status === "PAUSED" ||
        activePrintJob.status === "PENDING" ||
        activeSessionStatus === "ACTIVE" ||
        activeSessionStatus === "PAUSED" ||
        activeSessionStatus === "RETRY_WAITING" ||
        activePipelineState === "PRINT_CONFIRMED" ||
        activePipelineState === "PRINTER_ACKNOWLEDGED" ||
        /local print session active/i.test(String(printProgressPhase || "")) ||
        activeWaitingForConfirmation ||
        (activeTotal > 0 && activeConfirmed < activeTotal))
  );

  return (
    <>
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent data-testid="create-print-job-dialog" className="max-h-[85vh] overflow-y-auto sm:max-w-[640px]">
        <DialogHeader>
          <DialogTitle>Start print run</DialogTitle>
          <DialogDescription>
            {isManufacturerMode
              ? "Choose the assigned label quantity and verified printer for this manufacturing run."
              : "Choose how many labels to print and the saved printer MSCQR should use for this run."}
          </DialogDescription>
        </DialogHeader>

        {!printBatch ? (
          <DialogEmptyState
            title="Choose a batch before starting a print run"
            description="Close this dialog, reopen Create Print Job from an assigned batch, and MSCQR will reload printer readiness for that batch."
            onClose={onClose}
          />
        ) : (
          <div className="mt-2 space-y-4">
            {workflow ? (
              <div className="rounded-md border bg-background p-3 text-sm">
                <div className="font-medium">Batch release checklist</div>
                <div className="mt-3 grid gap-2">
                  {workflow.steps.map((step, index) => (
                    <div key={step.label} className="flex items-start gap-3">
                      <div
                        className={
                          step.state === "done"
                            ? "flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-emerald-100 text-xs font-semibold text-emerald-800"
                            : step.state === "current"
                              ? "flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-primary text-xs font-semibold text-primary-foreground"
                              : "flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-muted text-xs font-semibold text-muted-foreground"
                        }
                      >
                        {step.state === "done" ? "OK" : index + 1}
                      </div>
                      <div className="min-w-0">
                        <div className="font-medium">{step.label}</div>
                        <div className="text-xs text-muted-foreground">{step.detail}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}

            {isManufacturerMode ? (
              <div className="rounded-md border bg-background p-3 text-sm">
                <div className="font-medium">Manufacturer print readiness</div>
                <div className="mt-3 grid gap-2 text-xs text-muted-foreground sm:grid-cols-2">
                  <div>
                    <div className="font-medium text-foreground">Assigned range</div>
                    <div className="font-mono break-all">{printBatch.startCode} to {printBatch.endCode}</div>
                  </div>
                  <div>
                    <div className="font-medium text-foreground">Remaining labels</div>
                    <div>{readyToPrintCount.toLocaleString()}</div>
                  </div>
                  <div>
                    <div className="font-medium text-foreground">Selected printer</div>
                    <div>{selectedPrinterProfile?.name || "Choose saved printer"}</div>
                  </div>
                  <div>
                    <div className="font-medium text-foreground">Secure verification</div>
                    <div>{selectedPrinterCanPrint ? "Fresh" : "Refresh printer helper before starting this print run."}</div>
                  </div>
                  <div>
                    <div className="font-medium text-foreground">Connector version</div>
                    <div>{connectorVersionLabel || "Not reported"}</div>
                  </div>
                  {manufacturerRecoveryContext ? (
                    <div className="sm:col-span-2">
                      <div className="font-medium text-foreground">Recovery status</div>
                      <div>
                        {manufacturerRecoveryContext.jobNumber || manufacturerRecoveryContext.printJobId}
                        {manufacturerRecoveryContext.rangeLabel ? ` · ${manufacturerRecoveryContext.rangeLabel}` : ""}
                      </div>
                    </div>
                  ) : null}
                </div>
              </div>
            ) : null}

            <div
              className={
                selectedPrinterNotice.tone === "success"
                  ? "rounded-md border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-800"
                  : selectedPrinterNotice.tone === "warning"
                    ? "rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-800"
                    : selectedPrinterNotice.tone === "neutral"
                      ? "rounded-md border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700"
                      : "rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-800"
              }
            >
              <div className="font-medium">{selectedPrinterNotice.title}</div>
              <div className="text-xs">{selectedPrinterNotice.summary}</div>
              <div className="mt-2 text-[11px]">{selectedPrinterNotice.detail}</div>
            </div>

            <div className="rounded-md border p-3 text-sm">
              <div className="font-medium">{printBatch.name}</div>
              <div className="text-xs text-muted-foreground">
                {Number(printBatch.totalCodes || 0).toLocaleString()} QR labels assigned
              </div>
	              {printBatch.startCode && printBatch.endCode ? (
	                <div className="mt-2 text-xs text-muted-foreground">
	                  Label range: <span className="font-mono">{printBatch.startCode} to {printBatch.endCode}</span>
	                </div>
	              ) : null}
            </div>

            <div className="space-y-2">
              <Label>Quantity to print</Label>
              <Input
                data-testid="print-job-quantity-input"
                type="number"
                min={1}
                max={maxRunQuantity || undefined}
                value={printQuantity}
                onChange={(event) => onPrintQuantityChange(event.target.value)}
                placeholder="Enter quantity"
              />
              <div className="space-y-1 text-xs text-muted-foreground">
                <div>QR labels ready to print: {readyToPrintCount.toLocaleString()}</div>
                <div>Maximum per run: {maxRunQuantity.toLocaleString()} labels</div>
              </div>
              {batchLifecycleBlocked ? (
                <div className="rounded-md border border-amber-200 bg-amber-50 p-2 text-xs text-amber-800">
                  {batchLifecycleBlockReason}
                </div>
              ) : null}
            </div>

            <div className="space-y-3 rounded-md border p-3">
              <div className="text-sm font-medium">Printer selection</div>
              {registeredPrinters.length === 0 ? (
                <div className="rounded-md border border-amber-200 bg-amber-50 p-3 text-xs text-amber-800">
                  No saved printers are ready yet. Refresh after printer setup changes, then try this print run again.
                  <div className="mt-2 flex flex-wrap gap-2">
                    <Button size="sm" variant="ghost" onClick={onRefreshPrinters}>
                      Refresh printers
                    </Button>
                  </div>
                </div>
              ) : null}

              {registeredPrinters.length > 0 ? (
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <div className="space-y-1">
                    <Label className="text-xs">Saved printer</Label>
                    <Select
                      value={selectedPrinterProfileId || "__none__"}
                      onValueChange={(value) => onSelectedPrinterProfileIdChange(value === "__none__" ? "" : value)}
                    >
                      <SelectTrigger data-testid="print-job-printer-profile">
                        <SelectValue placeholder="Choose saved printer" />
                      </SelectTrigger>
                      <SelectContent>
                        {registeredPrinters.map((row) => (
                          <SelectItem key={row.id} value={row.id}>
                            {row.name}
                            {` · ${getPrinterDispatchLabel(row)}`}
                            {!row.isActive ? " · unavailable" : ""}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              ) : null}

              {selectedPrinterProfile ? (
                <div className="rounded-md border bg-muted/20 px-3 py-3 text-sm">
                  <div className="font-medium">{selectedPrinterProfile.name}</div>
                  <div className="mt-1 text-xs text-muted-foreground">{getPrinterDispatchLabel(selectedPrinterProfile)}</div>
                </div>
              ) : null}

              {selectedPrinterProfile?.connectionType === "LOCAL_AGENT" ? (
                <>
                  <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                    <div className="space-y-1">
                      <Label className="text-xs">Printer on this computer</Label>
                      <Select
                        value={selectedPrinterId || "__none__"}
                        onValueChange={(value) => onSelectedPrinterIdChange(value === "__none__" ? "" : value)}
                      >
                        <SelectTrigger data-testid="print-job-workstation-printer">
                          <SelectValue placeholder="Choose printer" />
                        </SelectTrigger>
                        <SelectContent>
                          {detectedPrinters.length === 0 ? (
                            <SelectItem value="__none__">No printers found yet</SelectItem>
                          ) : (
                            detectedPrinters.map((row) => (
                              <SelectItem key={row.printerId} value={row.printerId}>
                                {row.printerName}
                                {row.connection ? ` · ${row.connection}` : ""}
                                {row.online === false ? " · needs review" : ""}
                              </SelectItem>
                            ))
                          )}
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                  <div className="rounded-md border bg-muted/20 p-3 text-xs text-muted-foreground">
                    Printing from this computer uses the printer selected here. Change it before the next run if needed.
                  </div>
                  {selectedLocalProfileRegistrationStale ? (
                    <div className="rounded-md border border-amber-200 bg-amber-50 p-3 text-xs text-amber-900">
                      <div className="font-medium">Saved printer link is stale</div>
                      <div className="mt-1">
                        The connector was reinstalled. Relink this saved printer to the current connector before starting.
                      </div>
                      <div className="mt-3 flex justify-end">
                        <ActionButton
                          variant="outline"
                          size="sm"
                          state={
                            relinkingPrinter
                              ? createUiActionState("pending", "Relinking the saved printer to this computer.")
                              : createUiActionState("enabled")
                          }
                          onClick={onRelinkSelectedPrinter}
                          idleLabel="Relink saved printer"
                          pendingLabel="Relinking..."
                        />
                      </div>
                    </div>
                  ) : null}
                  <div className="flex flex-wrap justify-end gap-2">
                    <ActionButton
                      variant="outline"
                      size="sm"
                      state={
                        switchingPrinter
                          ? createUiActionState("pending", "Saving the printer choice on this computer.")
                          : !selectedPrinterId
                            ? createUiActionState("disabled", "Choose a printer on this computer first.")
                            : detectedPrinters.length <= 1
                              ? createUiActionState("disabled", "Only one printer is available on this computer right now.")
                              : createUiActionState("enabled")
                      }
                      onClick={onSwitchSelectedPrinter}
                      idleLabel="Use selected printer"
                      pendingLabel="Saving..."
                    />
                  </div>
                </>
              ) : (
                <div className="rounded-md border bg-muted/20 p-3 text-sm">
                  <div className="font-medium">{selectedPrinterProfile?.name || "Network printer"}</div>
                  <div className="mt-1 text-xs text-muted-foreground">
                    {getPrinterDispatchLabel(selectedPrinterProfile)}
                  </div>
                  <div className="mt-2 text-xs text-muted-foreground">
                    {sanitizePrinterUiError(
                      selectedPrinterProfile?.registryStatus?.detail,
                      selectedPrinterProfile?.connectionType === "NETWORK_IPP"
                        ? "MSCQR will send this run to the saved shared printer using its saved setup."
                        : "MSCQR will send this run to the saved label printer using its saved setup."
                    )}
                  </div>
                </div>
              )}
            </div>

            <div className="flex gap-2">
              <Button asChild variant="outline">
                <Link to="/printer-setup">Open printer setup</Link>
              </Button>
              {selectedPrinterProfile?.connectionType === "LOCAL_AGENT" ? (
                <ActionButton
                  variant="outline"
                  onClick={onPrintDiagnosticTestLabel}
                  state={
                    printing
                      ? createUiActionState("pending", "Printing a diagnostic test label.")
                      : !selectedPrinterProfile
                        ? createUiActionState("disabled", "Choose a saved printer before printing a diagnostic label.")
                        : createUiActionState("enabled")
                  }
                  idleLabel="Print diagnostic test label"
                  pendingLabel="Printing..."
                />
              ) : null}
              <ActionButton
                data-testid="print-job-start-button"
                onClick={onStartPrint}
                state={
                  printing
                    ? createUiActionState("pending", "Starting the print run now.")
                      : printJobId
                        ? createUiActionState("disabled", "Finish or stop the current print run before starting another one.")
                      : !selectedPrinterProfile
                        ? createUiActionState("disabled", "Choose a saved printer before you start this run.")
                      : batchLifecycleBlocked
                        ? createUiActionState("disabled", batchLifecycleBlockReason)
                      : !selectedPrinterCanPrint
                        ? createUiActionState(
                            "disabled",
                            isManufacturerMode
                              ? selectedPrinterNotice.detail || selectedPrinterNotice.summary || "Refresh printer helper before starting this print run."
                              : selectedPrinterNotice.detail || "This printer needs attention before it can print."
                          )
                        : createUiActionState("enabled")
                }
                idleLabel={printJobId ? "Print run active" : "Start print run"}
                pendingLabel="Starting..."
              />
            </div>

            {!printJobId ? (
              <div className="rounded-md border bg-muted/20 p-3 text-xs text-muted-foreground">
                Stop and refresh appear after a print run starts.
              </div>
            ) : null}

            {printJobId ? (
              <div className="space-y-2 rounded-md border p-3 text-sm">
                <div className="text-xs text-muted-foreground">Current print run</div>
                <div className="font-medium">
                  {activeStoppedOrPartial ? "Print run stopped" : activeCompleted ? "Print run completed" : "Printing in progress"}
                </div>
                <div className="text-xs text-muted-foreground">
                  Using {printProgressPrinterName || selectedPrinterProfile?.name || "—"} ·{" "}
                  {formatDispatchModeLabel(printProgressDispatchMode || selectedPrinterProfile?.connectionType || null)}
                </div>
                {activeTotal > 0 ? (
                  <div className="grid grid-cols-3 gap-2 text-xs text-muted-foreground">
                    <div>{Math.min(activeTotal, activeCompleted ? activeTotal : activeConfirmed).toLocaleString()} printed</div>
                    <div>{(activeCompleted ? 0 : activeRemaining).toLocaleString()} remaining</div>
                    <div>{activeTotal.toLocaleString()} total labels</div>
                  </div>
                ) : null}
                {directRemainingToPrint != null ? (
                  <div className="text-xs text-muted-foreground">Remaining to print: {activeCompleted ? 0 : directRemainingToPrint}</div>
                ) : null}
                <div className="text-xs text-muted-foreground">
                  {activeStoppedOrPartial
                    ? "Confirmed labels stay printed. Unprinted labels remain recoverable through the controlled recovery flow."
                    : activeCompleted
                    ? "MSCQR received backend confirmation for this print run."
                    : activeWaitingForConfirmation
                      ? "MSCQR is waiting for printer confirmation before marking the remaining labels printed."
                      : "MSCQR waits for final printer confirmation before marking these labels printed."}
                </div>
                {showActivePrintControls && activePrintJob ? (
                  <div className="mt-3 flex flex-wrap justify-end gap-2">
                    {canStopJob(activePrintJob) ? (
                      <ActionButton
                        variant="outline"
                        size="sm"
                        onClick={() => onOpenPrintControlDialog("stop", activePrintJob)}
                        state={
                          printControlBusyJobId === activePrintJob.id || printControlDialog.submitting
                            ? createUiActionState("pending", "Stopping the print run.")
                            : createUiActionState("enabled")
                        }
                        idleLabel="Stop print run"
                        pendingLabel="Stopping..."
                        showReasonBelow={false}
                      />
                    ) : null}
                    <ActionButton
                      variant="outline"
                      size="sm"
                      onClick={onRefreshPrintStatus}
                      state={
                        printing
                          ? createUiActionState("pending", "Refreshing the live print progress.")
                          : createUiActionState("enabled")
                      }
                      idleLabel="Refresh status"
                      pendingLabel="Refreshing..."
                      showReasonBelow={false}
                    />
                  </div>
                ) : null}
              </div>
            ) : null}

            {printJobId && selectedPrinterProfile?.connectionType === "LOCAL_AGENT" && directRemainingToPrint !== 0 && !showActivePrintControls ? (
              <div className="space-y-3 rounded-md border border-emerald-200 bg-emerald-50 p-3 text-sm">
                <div className="font-medium text-emerald-900">Printer helper is finishing this run</div>
                <div className="text-xs text-emerald-900">
                  The printer helper keeps printing and confirming labels in the background. Refresh when you want the latest confirmed count.
                </div>
                <div className="flex justify-end">
                  <ActionButton
                    variant="outline"
                    onClick={onRefreshPrintStatus}
                    state={
                      printing
                        ? createUiActionState("pending", "Refreshing the live print progress.")
                        : !printJobId
                          ? createUiActionState("disabled", "Start a print run first.")
                          : createUiActionState("enabled")
                    }
                    idleLabel="Refresh print progress"
                    pendingLabel="Refreshing..."
                    showReasonBelow={false}
                  />
                </div>
              </div>
            ) : null}

            {printCooldownRemainingSeconds > 0 ? (
              <div className="rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
                <div className="font-medium">Printing is cooling down</div>
                <div className="mt-1 text-xs">
                  Try again after {printCooldownRemainingSeconds} seconds. Printed labels are preserved; MSCQR will continue from the last safe point.
                </div>
              </div>
            ) : null}

            {recentPrintJobs.length > 0 ? (
              <div className="space-y-3 rounded-md border p-3 text-sm">
                <div className="font-medium">Recent print runs</div>
                <div className="space-y-2">
                  {recentPrintJobs.map((job) => (
                    <div key={job.id} className="rounded-md border bg-muted/20 px-3 py-2">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="font-medium">{job.jobNumber || "Print run"}</div>
                        <Badge variant={job.status === "FAILED" ? "destructive" : "secondary"}>
                          {getPlainPrintStatusLabel(job.status)}
                        </Badge>
                      </div>
                      <div className="mt-1 text-xs text-muted-foreground">
                        {formatDispatchModeLabel(job.printMode)} · {job.printer?.name || "Unknown printer"} ·{" "}
                        {job.itemCount || job.quantity} labels
                      </div>
                      <div className="mt-1 text-xs text-muted-foreground">
                        {job.awaitingConfirmation
                          ? "Sent to printer, awaiting/manual confirmation"
                          : job.pipelineState === "NEEDS_OPERATOR_ACTION" && job.status !== "FAILED"
                            ? "Queue confirmation unavailable"
                            : job.status === "FAILED"
                              ? "Needs attention"
                              : `Confirmed ${job.session?.confirmedItems || 0}`}
                        {!job.awaitingConfirmation &&
                        job.status !== "FAILED" &&
                        typeof job.session?.remainingToPrint === "number" &&
                        job.session.remainingToPrint > 0
                          ? ` · Remaining ${job.session.remainingToPrint}`
                          : ""}
                        {job.failureReason
                          ? ` · ${sanitizePrinterUiError(job.failureReason, "This print job needs attention.")}`
                          : ""}
                      </div>
                      <div className="mt-2 grid grid-cols-2 gap-2 text-xs text-muted-foreground sm:grid-cols-4">
                        <div>Requested {Number(job.itemCount || job.quantity || 0).toLocaleString()}</div>
                        <div>Printed {Number(job.session?.confirmedItems || 0).toLocaleString()}</div>
                        <div>Pending {Number(job.session?.remainingToPrint || 0).toLocaleString()}</div>
                        <div>Failed {Number(job.session?.failedItems || job.session?.counts?.FAILED || 0).toLocaleString()}</div>
                      </div>
                      {isJobActive(job) || isJobPaused(job) ? (
                        <div className="mt-3 flex flex-wrap justify-end gap-2">
                          {isJobActive(job) ? (
                            <ActionButton
                              variant="outline"
                              size="sm"
                              onClick={() => onOpenPrintControlDialog("pause", job)}
                              state={
                                printControlBusyJobId === job.id || printControlDialog.submitting
                                  ? createUiActionState("pending", "Pausing the print run.")
                                  : createUiActionState("enabled")
                              }
                              idleLabel="Pause printing"
                              pendingLabel="Pausing..."
                              showReasonBelow={false}
                            />
                          ) : null}
                          {isJobPaused(job) || String(job.session?.status || "") === "RETRY_WAITING" ? (
                            <ActionButton
                              variant="outline"
                              size="sm"
                              onClick={() => onResumePrintJob(job.id)}
                              state={
                                printCooldownRemainingSeconds > 0
                                  ? createUiActionState("disabled", `Try again after ${printCooldownRemainingSeconds} seconds.`)
                                  : printControlBusyJobId === job.id
                                    ? createUiActionState("pending", "Resuming the print run.")
                                    : createUiActionState("enabled")
                              }
                              idleLabel="Resume printing"
                              pendingLabel="Resuming..."
                              showReasonBelow={false}
                            />
                          ) : null}
                          {canStopJob(job) ? (
                            <ActionButton
                              variant="outline"
                              size="sm"
                              onClick={() => onOpenPrintControlDialog("stop", job)}
                              state={
                                printControlBusyJobId === job.id || printControlDialog.submitting
                                  ? createUiActionState("pending", "Stopping the print run.")
                                  : createUiActionState("enabled")
                              }
                              idleLabel="Stop printing"
                              pendingLabel="Stopping..."
                              showReasonBelow={false}
                            />
                          ) : null}
                        </div>
                      ) : null}
                      {canRequestReissue(job) ? (
                        <div className="mt-3 flex justify-end">
                          <ActionButton
                            variant="outline"
                            size="sm"
                            onClick={() => onOpenPrintReissueDialog(job)}
                            state={
                              printReissueDialog.submitting
                                ? createUiActionState("pending", "Submitting the reissue request.")
                                : createUiActionState("enabled")
                            }
                            idleLabel="Request reissue"
                            pendingLabel="Submitting..."
                            showReasonBelow={false}
                          />
                        </div>
                      ) : null}
                      {job.status === "FAILED" && (job.session?.confirmedItems || 0) === 0 ? (
                        <div className="mt-2 flex justify-end">
                          <ActionButton
                            variant="outline"
                            size="sm"
                            onClick={() => onAbandonPrintJob(job.id)}
                            state={
                              printing
                                ? createUiActionState("pending", "Closing the print run.")
                                : createUiActionState("enabled")
                            }
                            idleLabel="Close and release labels"
                            pendingLabel="Closing..."
                            showReasonBelow={false}
                          />
                        </div>
                      ) : null}
                      {job.status === "SENT" && job.awaitingConfirmation ? (
                        <div className="mt-2 rounded-md border border-amber-200 bg-amber-50 p-2 text-xs text-amber-800">
                          Waiting for connector physical confirmation. Stop and recover the run if the printer did not finish.
                        </div>
                      ) : null}
                      {job.status === "CONFIRMED" ? (
                        <div className="mt-3 rounded-md border bg-background p-3">
                          <div className="text-xs font-medium">Sample scan proof</div>
                          <div className="mt-1 text-xs text-muted-foreground">
                            {job.sampleScanPolicy
                              ? `${job.sampleScanPolicy.passed}/${job.sampleScanPolicy.required} sample scans verified for this print run.`
                              : "Scan one printed label from this run to prove the QR resolves to this job."}
                          </div>
                          {releaseApprovalState?.approvalRequired ? (
                            <div className="mt-3 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-900">
                              Release is waiting for a different authorized checker from the platform, brand, or assigned manufacturer.
                              {releaseApprovalState.threshold
                                ? ` Policy threshold: ${releaseApprovalState.threshold.toLocaleString()} labels.`
                                : ""}
                            </div>
                          ) : null}
                          <div className="mt-3 flex flex-col gap-2 sm:flex-row">
                            <Input
                              value={sampleScanCodeByJobId[job.id] || ""}
                              onChange={(event) => onSampleScanCodeChange(job.id, event.target.value)}
                              placeholder="Scan MSCQR code or verify URL"
                              maxLength={1024}
                            />
                            <ActionButton
                              variant="outline"
                              size="sm"
                              onClick={() => onVerifySampleScan(job.id)}
                              state={
                                printing
                                  ? createUiActionState("pending", "Verifying the sample scan.")
                                  : !String(sampleScanCodeByJobId[job.id] || "").trim()
                                    ? createUiActionState("disabled", "Scan one printed QR before verifying.")
                                    : createUiActionState("enabled")
                              }
                              idleLabel="Verify sample"
                              pendingLabel="Verifying..."
                              showReasonBelow
                            />
                          </div>
                          <div className="mt-3 flex justify-end">
                            <ActionButton
                              variant={printBatch?.lifecycleState === "RELEASED" ? "outline" : "default"}
                              size="sm"
                              onClick={onReleaseBatch}
                              state={
                                printing
                                  ? createUiActionState("pending", "Releasing the batch.")
                                  : printBatch?.lifecycleState === "RELEASED"
                                    ? createUiActionState("disabled", "Batch has already been released.")
                                    : releaseApprovalState?.approvalRequired
                                      ? createUiActionState("disabled", "A different authorized checker must approve this release.")
                                    : job.sampleScanPolicy?.satisfied
                                      ? createUiActionState("enabled")
                                      : createUiActionState("disabled", "Complete required sample scan proof before release.")
                              }
                              idleLabel={
                                printBatch?.lifecycleState === "RELEASED"
                                  ? "Batch released"
                                  : releaseApprovalState?.approvalRequired
                                    ? "Approval pending"
                                    : "Release batch"
                              }
                              pendingLabel="Releasing..."
                              showReasonBelow
                            />
                          </div>
                        </div>
                      ) : null}
                    </div>
                  ))}
                </div>
              </div>
            ) : null}

            <div className="flex justify-end gap-3 pt-2">
              <Button variant="outline" onClick={onClose} disabled={printing}>
                Close
              </Button>
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
    <Dialog open={Boolean(printControlDialog.action && printControlDialog.job)} onOpenChange={(nextOpen) => {
      if (!nextOpen) onClosePrintControlDialog();
    }}>
      <DialogContent className="sm:max-w-[520px]">
        <DialogHeader>
          <DialogTitle>{printControlTitle}</DialogTitle>
          <DialogDescription>{printControlDescription}</DialogDescription>
        </DialogHeader>
        <div className="mt-2 space-y-4">
          {printControlDialog.job ? (
            <div className="rounded-md border bg-muted/20 p-3 text-sm">
              <div className="font-medium">{printControlDialog.job.jobNumber || "Print run"}</div>
              <div className="mt-1 text-xs text-muted-foreground">
                {Number(printControlDialog.job.session?.confirmedItems || 0).toLocaleString()} printed ·{" "}
                {Number(printControlDialog.job.session?.remainingToPrint || 0).toLocaleString()} remaining
              </div>
            </div>
          ) : null}
          <div className="space-y-2">
            <Label>{printControlDialog.action === "stop" ? "Stop reason" : "Pause reason"}</Label>
            <Input
              value={printControlDialog.reason}
              onChange={(event) => onPrintControlReasonChange(event.target.value)}
              placeholder={printControlDialog.action === "stop" ? "Example: media jam after confirmed labels" : "Example: operator checking label alignment"}
              maxLength={500}
            />
            <div className="text-xs text-muted-foreground">A reason is required for the audit trail.</div>
          </div>
          {printControlDialog.action === "stop" ? (
            <div className="rounded-md border border-amber-200 bg-amber-50 p-3 text-xs text-amber-900">
              Stopping does not mark unconfirmed labels as printed. Remaining labels stay recoverable through controlled reissue or a new approved run.
            </div>
          ) : null}
          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={onClosePrintControlDialog} disabled={printControlDialog.submitting}>
              Cancel
            </Button>
            <ActionButton
              variant={printControlDialog.action === "stop" ? "destructive" : "default"}
              onClick={onSubmitPrintControlDialog}
              state={
                printControlDialog.submitting
                  ? createUiActionState("pending", "Saving the print run control action.")
                  : printControlDialog.reason.trim().length < 8
                    ? createUiActionState("disabled", "Enter a clear audit reason.")
                    : createUiActionState("enabled")
              }
              idleLabel={printControlDialog.action === "stop" ? "Stop print run" : "Pause print run"}
              pendingLabel={printControlDialog.action === "stop" ? "Stopping..." : "Pausing..."}
              showReasonBelow
            />
          </div>
        </div>
      </DialogContent>
    </Dialog>
    <Dialog open={Boolean(printReissueDialog.job)} onOpenChange={(nextOpen) => {
      if (!nextOpen) onClosePrintReissueDialog();
    }}>
      <DialogContent className="sm:max-w-[520px]">
        <DialogHeader>
          <DialogTitle>Request reissue</DialogTitle>
          <DialogDescription>
            Ask an admin to approve replacement labels. MSCQR will not create another print run until the request is approved.
          </DialogDescription>
        </DialogHeader>
        <div className="mt-2 space-y-4">
          {printReissueDialog.job ? (
            <div className="rounded-md border bg-muted/20 p-3 text-sm">
              <div className="font-medium">{printReissueDialog.job.jobNumber || "Print run"}</div>
              <div className="mt-1 text-xs text-muted-foreground">
                {Number(printReissueDialog.job.itemCount || printReissueDialog.job.quantity || 0).toLocaleString()} labels ·{" "}
                {printReissueDialog.job.printer?.name || "Saved printer"}
              </div>
            </div>
          ) : null}
          <div className="space-y-2">
            <Label>Reason</Label>
            <Input
              value={printReissueDialog.reason}
              onChange={(event) => onPrintReissueReasonChange(event.target.value)}
              placeholder="Example: confirmed labels damaged during packaging"
              maxLength={500}
            />
            <div className="text-xs text-muted-foreground">This request is scoped to your batch and reviewed by the correct admin.</div>
          </div>
          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={onClosePrintReissueDialog} disabled={printReissueDialog.submitting}>
              Cancel
            </Button>
            <ActionButton
              onClick={onSubmitPrintReissueRequest}
              state={
                printReissueDialog.submitting
                  ? createUiActionState("pending", "Submitting the reissue request.")
                  : printReissueDialog.reason.trim().length < 8
                    ? createUiActionState("disabled", "Enter a clear request reason.")
                    : createUiActionState("enabled")
              }
              idleLabel="Submit request"
              pendingLabel="Submitting..."
              showReasonBelow
            />
          </div>
        </div>
      </DialogContent>
    </Dialog>
    </>
  );
}
