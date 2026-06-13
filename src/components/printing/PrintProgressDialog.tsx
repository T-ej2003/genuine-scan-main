import React from "react";
import { CircleCheckBig, Loader2, Printer } from "lucide-react";

import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import type { PrintJobRow } from "@/features/batches/types";

type PrintProgressDialogProps = {
  open: boolean;
  phase: string;
  total: number;
  printed: number;
  remaining: number;
  currentCode?: string | null;
  printerName?: string | null;
  modeLabel?: string;
  error?: string | null;
  notice?: string | null;
  printJobId?: string;
  activeJob?: PrintJobRow | null;
  onPause?: (job: PrintJobRow) => void;
  onStop?: (job: PrintJobRow) => void;
  onResume?: (jobId: string) => void;
  onRefresh?: () => void;
  printControlBusyJobId?: string | null;
  printControlSubmitting?: boolean;
  printCooldownRemainingSeconds?: number;
  onOpenChange?: (open: boolean) => void;
};

export function PrintProgressDialog(props: PrintProgressDialogProps) {
  const safeTotal = Math.max(0, Number(props.total || 0));
  const safePrinted = Math.max(0, Number(props.printed || 0));
  const safeRemaining = Math.max(0, Number(props.remaining || Math.max(0, safeTotal - safePrinted)));
  const progressValue = safeTotal > 0 ? Math.max(0, Math.min(100, Math.round((safePrinted / safeTotal) * 100))) : 0;
  const normalizedPhase = String(props.phase || "").trim().toLowerCase();
  const isCompleted = !props.error && normalizedPhase.includes("complete");
  const activeJob = props.activeJob || null;
  const activeSessionStatus = String(activeJob?.session?.status || "").toUpperCase();
  const activePipelineState = String(activeJob?.pipelineState || "").toUpperCase();
  const activeStatus = String(activeJob?.status || "").toUpperCase();
  const activeTotal = Number(activeJob?.session?.totalItems || activeJob?.itemCount || activeJob?.quantity || safeTotal || 0);
  const activeConfirmed = Number(activeJob?.session?.confirmedItems ?? safePrinted ?? 0);
  const activeTerminal =
    isCompleted ||
    activeStatus === "CONFIRMED" ||
    ["COMPLETED", "FAILED", "CANCELLED", "STOPPED"].includes(activeSessionStatus) ||
    ["FAILED", "CANCELLED", "STOPPED"].includes(activeStatus) ||
    (activeTotal > 0 && activeConfirmed >= activeTotal);
  const activePaused = activeStatus === "PAUSED" || activeSessionStatus === "PAUSED";
  const activeRunnable =
    ["PENDING", "SENT", "PARTIALLY_COMPLETED"].includes(activeStatus) ||
    ["ACTIVE", "RESUME_PENDING", "RETRY_WAITING"].includes(activeSessionStatus) ||
    ["PRINT_CONFIRMED", "PRINTER_ACKNOWLEDGED", "QUEUED"].includes(activePipelineState) ||
    normalizedPhase.includes("local print session active") ||
    normalizedPhase.includes("waiting for printer confirmation") ||
    normalizedPhase.includes("preparing printer job") ||
    normalizedPhase.includes("waiting for connector") ||
    (activeTotal > 0 && activeConfirmed < activeTotal);
  const showControls = Boolean(activeJob && !activeTerminal && (activeRunnable || activePaused));
  const controlsBusy = Boolean(
    activeJob && (props.printControlBusyJobId === activeJob.id || props.printControlSubmitting)
  );
  const dialogTitle = props.error ? "Print needs attention" : isCompleted ? "Print completed" : "Printing in progress";
  const dialogDescription = props.error
    ? "Review the failure details before retrying or closing this session."
    : isCompleted
      ? "All labels for the current secure print session were confirmed."
      : "Live direct-print status for your current secure print session.";

  return (
    <Dialog open={props.open} onOpenChange={props.onOpenChange}>
      <DialogContent className="sm:max-w-[560px]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Printer className="h-4 w-4" />
            {dialogTitle}
          </DialogTitle>
          <DialogDescription>{dialogDescription}</DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="rounded-md border p-3">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="secondary">{props.modeLabel || "Auto path"}</Badge>
              <Badge variant="outline">{props.printerName || "Default printer"}</Badge>
              <Badge variant={props.error ? "destructive" : "default"}>{props.phase}</Badge>
            </div>
            {props.currentCode ? <div className="mt-2 text-xs text-muted-foreground">Processing the next approved label.</div> : null}
            {props.error ? <div className="mt-2 text-xs text-destructive">{props.error}</div> : null}
            {!props.error && props.notice ? <div className="mt-2 text-xs text-amber-700">{props.notice}</div> : null}
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span>{safePrinted.toLocaleString()} printed</span>
              <span>{safeRemaining.toLocaleString()} remaining</span>
            </div>
            <Progress value={progressValue} className="h-3" />
            <div className="text-xs text-muted-foreground">
              {safeTotal.toLocaleString()} total labels · {progressValue}% complete
            </div>
          </div>

          {isCompleted ? (
            <div className="flex items-center gap-2 text-xs text-emerald-700">
              <CircleCheckBig className="h-3.5 w-3.5" />
              Print run completed.
            </div>
          ) : (
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
              Keep this window open until all labels are confirmed.
            </div>
          )}

          {showControls && activeJob ? (
            <div className="flex flex-wrap justify-end gap-2 border-t pt-3">
              {!activePaused ? (
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => props.onPause?.(activeJob)}
                  disabled={controlsBusy}
                >
                  Pause print run
                </Button>
              ) : null}
              {activePaused || activeSessionStatus === "RETRY_WAITING" ? (
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => props.onResume?.(activeJob.id)}
                  disabled={controlsBusy || Number(props.printCooldownRemainingSeconds || 0) > 0}
                >
                  Resume print run
                </Button>
              ) : null}
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => props.onStop?.(activeJob)}
                disabled={controlsBusy}
              >
                Stop print run
              </Button>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={props.onRefresh}
                disabled={controlsBusy}
              >
                Refresh status
              </Button>
            </div>
          ) : null}
        </div>
      </DialogContent>
    </Dialog>
  );
}
