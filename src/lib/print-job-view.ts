import type { PrintJobRow } from "@/features/batches/types";
import { getPlainPrintStatusLabel } from "@/lib/ui-copy";

export const printRunCount = (count: number | null | undefined) => count?.toLocaleString() ?? "Unknown";

export const manufacturerRunStatus = (job: PrintJobRow) => {
  const status = job.runSummary?.operationalStatus ?? job.status;
  return status === "NEEDS_OPERATOR_ACTION" ? "Needs operator review" : getPlainPrintStatusLabel(status);
};

// printing_readiness('JOB') returns a projection; consumers use the job row
// with its session and items attached.
export const normalizePrintJobView = (view: any) => {
  if (!view || typeof view !== "object" || !view.job || typeof view.job !== "object") return view;
  return {
    ...view.job,
    session: view.session ?? view.job.session ?? null,
    items: view.items ?? view.job.items ?? [],
  };
};
