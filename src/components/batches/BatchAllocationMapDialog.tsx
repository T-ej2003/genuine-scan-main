import React from "react";
import { format } from "date-fns";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

type AllocationBatchRow = {
  id: string;
  name: string;
  manufacturer?: { id: string; name: string; email: string } | null;
  totalCodes: number;
  printableCodes: number;
  printedCodes: number;
  redeemedCodes: number;
  unassignedRemainingCodes: number;
  remainingStartCode?: string | null;
  remainingEndCode?: string | null;
  createdAt?: string;
  batchKind?: "RECEIVED_PARENT" | "MANUFACTURER_CHILD";
};

type AllocationMapPayload = {
  sourceBatchId: string;
  focusBatchId: string;
  sourceBatch: AllocationBatchRow | null;
  selectedBatch: AllocationBatchRow | null;
  allocations: AllocationBatchRow[];
  totals: {
    totalDistributedCodes: number;
    sourceRemainingCodes: number;
    pendingPrintableCodes: number;
    printedCodes: number;
  };
};

type BatchAllocationMapDialogProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  loading?: boolean;
  payload: AllocationMapPayload | null;
  title?: string;
  description?: string;
  onOpenBatches?: (batchId: string) => void;
};

const rangeLabel = (row: AllocationBatchRow | null) => {
  if (!row) return "—";
  if (row.remainingStartCode && row.remainingEndCode) {
    return `${row.remainingStartCode} → ${row.remainingEndCode}`;
  }
  return "No in-scope range available";
};

export function BatchAllocationMapDialog({
  open,
  onOpenChange,
  loading,
  payload,
  title = "Allocation Map",
  description = "Trace the source batch, the current unassigned remainder, and each allocated manufacturer batch.",
  onOpenBatches,
}: BatchAllocationMapDialogProps) {
  const source = payload?.sourceBatch || null;
  const selected = payload?.selectedBatch || null;
  const allocations = payload?.allocations || [];
  const handleOpenBatches = (batchId: string) => {
    // Close the allocation map before routing so users never end up with stacked overlays.
    onOpenChange(false);
    onOpenBatches?.(batchId);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[880px] max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>

        {loading ? (
          <div className="text-sm text-muted-foreground">Loading allocation map…</div>
        ) : !payload || !source ? (
          <div className="text-sm text-muted-foreground">Allocation details are unavailable for this batch.</div>
        ) : (
          <div className="space-y-5">
            <div className="grid gap-3 md:grid-cols-4">
              <div className="rounded-lg border bg-slate-50 p-3">
                <p className="text-[11px] uppercase tracking-wide text-slate-500">Distributed</p>
                <p className="mt-1 text-2xl font-semibold text-slate-900">{payload.totals.totalDistributedCodes.toLocaleString()}</p>
              </div>
              <div className="rounded-lg border bg-slate-50 p-3">
                <p className="text-[11px] uppercase tracking-wide text-slate-500">Still Unassigned</p>
                <p className="mt-1 text-2xl font-semibold text-slate-900">{payload.totals.sourceRemainingCodes.toLocaleString()}</p>
              </div>
              <div className="rounded-lg border bg-slate-50 p-3">
                <p className="text-[11px] uppercase tracking-wide text-slate-500">Ready To Print</p>
                <p className="mt-1 text-2xl font-semibold text-slate-900">{payload.totals.pendingPrintableCodes.toLocaleString()}</p>
              </div>
              <div className="rounded-lg border bg-slate-50 p-3">
                <p className="text-[11px] uppercase tracking-wide text-slate-500">Printed Or Redeemed</p>
                <p className="mt-1 text-2xl font-semibold text-slate-900">{payload.totals.printedCodes.toLocaleString()}</p>
              </div>
            </div>

            <section className="rounded-xl border bg-white p-4">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <div className="flex items-center gap-2">
                    <p className="text-sm font-semibold text-slate-900">Source Batch</p>
                    <Badge variant="outline">Remainder stays here</Badge>
                    {selected?.id === source.id ? <Badge>Selected</Badge> : null}
                  </div>
                  <p className="mt-1 text-sm text-slate-700">{source.name}</p>
                  <p className="font-mono text-[11px] text-slate-500">{source.id}</p>
                </div>
                {onOpenBatches ? (
                  <Button type="button" variant="outline" size="sm" onClick={() => handleOpenBatches(source.id)}>
                    Open in batches
                  </Button>
                ) : null}
              </div>
              <div className="mt-3 grid gap-3 md:grid-cols-4">
                <div>
                  <p className="text-[11px] uppercase tracking-wide text-slate-500">Original Total</p>
                  <p className="text-sm font-semibold text-slate-900">{source.totalCodes.toLocaleString()}</p>
                </div>
                <div>
                  <p className="text-[11px] uppercase tracking-wide text-slate-500">Unassigned Remaining</p>
                  <p className="text-sm font-semibold text-slate-900">{source.unassignedRemainingCodes.toLocaleString()}</p>
                </div>
                <div>
                  <p className="text-[11px] uppercase tracking-wide text-slate-500">Current Range</p>
                  <p className="text-xs font-mono text-slate-700">{rangeLabel(source)}</p>
                </div>
                <div>
                  <p className="text-[11px] uppercase tracking-wide text-slate-500">Created</p>
                  <p className="text-sm text-slate-700">{source.createdAt ? format(new Date(source.createdAt), "PPp") : "—"}</p>
                </div>
              </div>
            </section>

            <section className="space-y-3">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <p className="text-sm font-semibold text-slate-900">Allocated Batches</p>
                  <p className="text-xs text-slate-500">Each row shows where a portion of the source inventory went.</p>
                </div>
                <Badge variant="outline">{allocations.length} allocated batch{allocations.length === 1 ? "" : "es"}</Badge>
              </div>

              {allocations.length === 0 ? (
                <div className="rounded-lg border border-dashed p-4 text-sm text-slate-500">
                  No manufacturer allocations have been created from this source batch yet.
                </div>
              ) : (
                <div className="space-y-3">
                  {allocations.map((row) => {
                    const isSelected = selected?.id === row.id;
                    return (
                      <article
                        key={row.id}
                        className={`rounded-xl border p-4 ${isSelected ? "border-emerald-300 bg-emerald-50/50" : "bg-white"}`}
                      >
                        <div className="flex flex-wrap items-start justify-between gap-3">
                          <div>
                            <div className="flex items-center gap-2">
                              <p className="text-sm font-semibold text-slate-900">{row.name}</p>
                              {isSelected ? <Badge>Selected</Badge> : null}
                            </div>
                            <p className="font-mono text-[11px] text-slate-500">{row.id}</p>
                            <p className="mt-1 text-xs text-slate-600">
                              {row.manufacturer?.name || "Manufacturer not set"}
                              {row.manufacturer?.email ? ` · ${row.manufacturer.email}` : ""}
                            </p>
                          </div>
                          {onOpenBatches ? (
                            <Button type="button" variant="outline" size="sm" onClick={() => handleOpenBatches(row.id)}>
                              Open in batches
                            </Button>
                          ) : null}
                        </div>

                        <div className="mt-3 grid gap-3 md:grid-cols-5">
                          <div>
                            <p className="text-[11px] uppercase tracking-wide text-slate-500">Allocated Qty</p>
                            <p className="text-sm font-semibold text-slate-900">{row.totalCodes.toLocaleString()}</p>
                          </div>
                          <div>
                            <p className="text-[11px] uppercase tracking-wide text-slate-500">Ready To Print</p>
                            <p className="text-sm font-semibold text-slate-900">{row.printableCodes.toLocaleString()}</p>
                          </div>
                          <div>
                            <p className="text-[11px] uppercase tracking-wide text-slate-500">Printed</p>
                            <p className="text-sm font-semibold text-slate-900">{row.printedCodes.toLocaleString()}</p>
                          </div>
                          <div>
                            <p className="text-[11px] uppercase tracking-wide text-slate-500">Redeemed</p>
                            <p className="text-sm font-semibold text-slate-900">{row.redeemedCodes.toLocaleString()}</p>
                          </div>
                          <div>
                            <p className="text-[11px] uppercase tracking-wide text-slate-500">Current Range</p>
                            <p className="text-xs font-mono text-slate-700">{rangeLabel(row)}</p>
                          </div>
                        </div>
                      </article>
                    );
                  })}
                </div>
              )}
            </section>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
