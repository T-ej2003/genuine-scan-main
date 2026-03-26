import { RefreshCw } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { getPrinterDispatchLabel, sanitizePrinterUiError } from "@/lib/printer-user-facing";

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
          <DialogTitle>Rename Batch</DialogTitle>
          <DialogDescription>Update the batch label for easier operations tracking.</DialogDescription>
        </DialogHeader>

        {!batch ? (
          <div className="text-sm text-muted-foreground">No batch selected.</div>
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
          <DialogTitle>Delete Batch</DialogTitle>
          <DialogDescription>
            This removes the batch and returns every code in it to the unassigned state.
          </DialogDescription>
        </DialogHeader>

        {!batch ? (
          <div className="text-sm text-muted-foreground">No batch selected.</div>
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
  printBatch: BatchRow | null;
  selectedPrinterNotice: PrinterSelectionNotice;
  printQuantity: string;
  onPrintQuantityChange: (value: string) => void;
  readyToPrintCount: number;
  registeredPrinters: RegisteredPrinterRow[];
  onOpenPrinterSetup: () => void;
  onRefreshPrinters: () => void;
  selectedPrinterProfileId: string;
  onSelectedPrinterProfileIdChange: (value: string) => void;
  selectedPrinterProfile: RegisteredPrinterRow | null;
  detectedPrinters: LocalPrinterRow[];
  selectedPrinterId: string;
  onSelectedPrinterIdChange: (value: string) => void;
  switchingPrinter: boolean;
  onSwitchSelectedPrinter: () => void;
  printing: boolean;
  onStartPrint: () => void;
  selectedPrinterCanPrint: boolean;
  printJobId: string | null;
  printProgressPrinterName: string | null;
  printProgressDispatchMode: string | null;
  formatDispatchModeLabel: (mode?: string | null) => string;
  directRemainingToPrint: number | null;
  onRefreshPrintStatus: () => void;
  recentPrintJobs: PrintJobRow[];
  onClose: () => void;
};

export function BatchPrintJobDialog({
  open,
  onOpenChange,
  printBatch,
  selectedPrinterNotice,
  printQuantity,
  onPrintQuantityChange,
  readyToPrintCount,
  registeredPrinters,
  onOpenPrinterSetup,
  onRefreshPrinters,
  selectedPrinterProfileId,
  onSelectedPrinterProfileIdChange,
  selectedPrinterProfile,
  detectedPrinters,
  selectedPrinterId,
  onSelectedPrinterIdChange,
  switchingPrinter,
  onSwitchSelectedPrinter,
  printing,
  onStartPrint,
  selectedPrinterCanPrint,
  printJobId,
  printProgressPrinterName,
  printProgressDispatchMode,
  formatDispatchModeLabel,
  directRemainingToPrint,
  onRefreshPrintStatus,
  recentPrintJobs,
  onClose,
}: PrintJobDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent data-testid="create-print-job-dialog" className="max-h-[85vh] overflow-y-auto sm:max-w-[640px]">
        <DialogHeader>
          <DialogTitle>Create Print Job</DialogTitle>
          <DialogDescription>
            Select quantity and a saved printer. MSCQR will use the approved printing path for that printer
            automatically.
          </DialogDescription>
        </DialogHeader>

        {!printBatch ? (
          <div className="text-sm text-muted-foreground">No batch selected.</div>
        ) : (
          <div className="mt-2 space-y-4">
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
              <div className="font-mono text-xs text-muted-foreground">
                {printBatch.startCode} → {printBatch.endCode}
              </div>
            </div>

            <div className="space-y-2">
              <Label>Quantity to print</Label>
              <Input
                data-testid="print-job-quantity-input"
                type="number"
                min={1}
                value={printQuantity}
                onChange={(event) => onPrintQuantityChange(event.target.value)}
                placeholder="Enter quantity"
              />
              <div className="text-xs text-muted-foreground">Ready to print: {readyToPrintCount}</div>
            </div>

            <div className="space-y-3 rounded-md border p-3">
              <div className="text-sm font-medium">Printer selection</div>
              {registeredPrinters.length === 0 ? (
                <div className="rounded-md border border-amber-200 bg-amber-50 p-3 text-xs text-amber-800">
                  No saved printer profiles are available yet. Open Printer Setup, add or check a printer, then return
                  here and refresh this dialog.
                  <div className="mt-2 flex flex-wrap gap-2">
                    <Button size="sm" variant="outline" onClick={onOpenPrinterSetup}>
                      Open Printer Setup
                    </Button>
                    <Button size="sm" variant="ghost" onClick={onRefreshPrinters}>
                      Refresh printers
                    </Button>
                  </div>
                </div>
              ) : null}

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div className="space-y-1">
                  <Label className="text-xs">Registered printer profile</Label>
                  <Select
                    value={selectedPrinterProfileId || "__none__"}
                    onValueChange={(value) => onSelectedPrinterProfileIdChange(value === "__none__" ? "" : value)}
                  >
                    <SelectTrigger data-testid="print-job-printer-profile">
                      <SelectValue placeholder="Select printer profile" />
                    </SelectTrigger>
                    <SelectContent>
                      {registeredPrinters.length === 0 ? (
                        <SelectItem value="__none__">No registered printers</SelectItem>
                      ) : (
                        registeredPrinters.map((row) => (
                          <SelectItem key={row.id} value={row.id}>
                            {row.name}
                            {` · ${getPrinterDispatchLabel(row)}`}
                            {!row.isActive ? " · inactive" : ""}
                          </SelectItem>
                        ))
                      )}
                    </SelectContent>
                  </Select>
                </div>
              </div>

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
                      <Label className="text-xs">Active workstation printer</Label>
                      <Select
                        value={selectedPrinterId || "__none__"}
                        onValueChange={(value) => onSelectedPrinterIdChange(value === "__none__" ? "" : value)}
                      >
                        <SelectTrigger data-testid="print-job-workstation-printer">
                          <SelectValue placeholder="Select printer" />
                        </SelectTrigger>
                        <SelectContent>
                          {detectedPrinters.length === 0 ? (
                            <SelectItem value="__none__">No printers discovered</SelectItem>
                          ) : (
                            detectedPrinters.map((row) => (
                              <SelectItem key={row.printerId} value={row.printerId}>
                                {row.printerName}
                                {row.connection ? ` · ${row.connection}` : ""}
                                {row.online === false ? " · offline" : ""}
                              </SelectItem>
                            ))
                          )}
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                  <div className="rounded-md border bg-muted/20 p-3 text-xs text-muted-foreground">
                    Use <strong>Printer Setup</strong> if this workstation printer needs alignment or setup changes before
                    the next run.
                  </div>
                  <div className="flex flex-wrap justify-end gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={switchingPrinter || !selectedPrinterId || detectedPrinters.length <= 1}
                      onClick={onSwitchSelectedPrinter}
                    >
                      {switchingPrinter ? "Switching..." : "Switch workstation printer"}
                    </Button>
                    <Button variant="outline" size="sm" onClick={onOpenPrinterSetup}>
                      Open Printer Setup
                    </Button>
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
                        ? "MSCQR will send the approved job to this office printer using its saved setup."
                        : "MSCQR will send the approved job to this factory label printer using its saved setup."
                    )}
                  </div>
                  <div className="mt-3 flex justify-end">
                    <Button variant="outline" size="sm" onClick={onOpenPrinterSetup}>
                      Open Printer Setup
                    </Button>
                  </div>
                </div>
              )}
            </div>

            <div className="flex gap-2">
              <Button
                data-testid="print-job-start-button"
                onClick={onStartPrint}
                disabled={printing || !selectedPrinterProfile || !selectedPrinterCanPrint}
              >
                {printing ? "Starting..." : "Start print"}
              </Button>
            </div>

            {printJobId ? (
              <div className="space-y-2 rounded-md border p-3 text-sm">
                <div className="text-xs text-muted-foreground">Current print job</div>
                <div className="font-medium">Printing in progress</div>
                <div className="text-xs text-muted-foreground">
                  Target printer: {printProgressPrinterName || selectedPrinterProfile?.name || "—"} ·{" "}
                  {formatDispatchModeLabel(printProgressDispatchMode || selectedPrinterProfile?.connectionType || null)}
                </div>
                {directRemainingToPrint != null ? (
                  <div className="text-xs text-muted-foreground">Remaining to print: {directRemainingToPrint}</div>
                ) : null}
              </div>
            ) : null}

            {printJobId && selectedPrinterProfile?.connectionType === "LOCAL_AGENT" && directRemainingToPrint !== 0 ? (
              <div className="space-y-3 rounded-md border border-emerald-200 bg-emerald-50 p-3 text-sm">
                <div className="font-medium text-emerald-900">Connector is processing this run</div>
                <div className="text-xs text-emerald-900">
                  The connector continues claiming and confirming labels in the background. Refresh the job status when you
                  need the latest confirmed count.
                </div>
                <div className="flex justify-end">
                  <Button variant="outline" onClick={onRefreshPrintStatus} disabled={printing || !printJobId}>
                    Refresh print status
                  </Button>
                </div>
              </div>
            ) : null}

            {recentPrintJobs.length > 0 ? (
              <div className="space-y-3 rounded-md border p-3 text-sm">
                <div className="font-medium">Recent print jobs</div>
                <div className="space-y-2">
                  {recentPrintJobs.map((job) => (
                    <div key={job.id} className="rounded-md border bg-muted/20 px-3 py-2">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="font-medium">{job.jobNumber || "Print job"}</div>
                        <Badge variant={job.status === "FAILED" ? "destructive" : "secondary"}>{job.status}</Badge>
                      </div>
                      <div className="mt-1 text-xs text-muted-foreground">
                        {formatDispatchModeLabel(job.printMode)} · {job.printer?.name || "Unknown printer"} ·{" "}
                        {job.itemCount || job.quantity} labels
                      </div>
                      <div className="mt-1 text-xs text-muted-foreground">
                        Confirmed {job.session?.confirmedItems || 0}
                        {typeof job.session?.remainingToPrint === "number" ? ` · Remaining ${job.session.remainingToPrint}` : ""}
                        {job.failureReason
                          ? ` · ${sanitizePrinterUiError(job.failureReason, "This print job needs attention.")}`
                          : ""}
                      </div>
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
  );
}
