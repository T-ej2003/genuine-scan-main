import type { PrintJobRow } from "@/features/batches/types";
import { printRunCount } from "@/lib/print-job-view";

export function ManufacturerPrintRunFacts({ job }: { job: PrintJobRow }) {
  const summary = job.runSummary;
  const range = summary?.serialRange;
  const serials = [range?.startCode, range?.endCode].filter(Boolean);
  return (
    <div className="space-y-2 text-xs text-muted-foreground">
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
        <div>Requested {printRunCount(summary?.requestedCount ?? job.itemCount ?? job.quantity)}</div>
        <div>Confirmed {printRunCount(summary?.confirmedCount)}</div>
        <div>Pending {printRunCount(summary?.pendingCount)}</div>
        <div>Failed {printRunCount(summary?.failedCount)}</div>
        <div>Uncertain {printRunCount(summary?.uncertainCount)}</div>
        <div>Cancelled / retired {printRunCount(summary?.cancelledOrRetiredCount)}</div>
        <div>Range {Array.from(new Set(serials)).join(" to ") || "Not recorded"}</div>
        <div>Printer {summary?.printer?.name || summary?.printer?.id || "Not recorded"}</div>
        <div>Operator {summary?.operator?.name || summary?.operator?.id || "Not recorded"}</div>
      </div>
      {summary?.recoveryReason ? <p>{summary.recoveryReason}</p> : null}
      {!summary?.complete ? <p>Some print-run details could not be verified.</p> : null}
    </div>
  );
}
