import { Copy, PackageCheck } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { DialogEmptyState } from "@/components/ui/dialog-empty-state";

import {
  formatAssignmentTimestamp,
  manufacturerOperationalStatus,
  type ManufacturerRow,
  type ManufacturerStats,
} from "@/features/manufacturers/types";
import { friendlyReferenceLabel } from "@/lib/friendly-reference";

type ManufacturerDetailsDialogProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  manufacturer: ManufacturerRow | null;
  stats?: ManufacturerStats;
  onCopyId: (id: string) => void;
  onOpenBatches: (manufacturer: ManufacturerRow) => void;
};

export function ManufacturerDetailsDialog({
  open,
  onOpenChange,
  manufacturer,
  stats,
  onCopyId,
  onOpenBatches,
}: ManufacturerDetailsDialogProps) {
  const operationalStatus = manufacturerOperationalStatus(stats);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[760px]">
        <DialogHeader>
          <DialogTitle>Manufacturer details</DialogTitle>
          <DialogDescription>
            Review current activity, print progress, and recent assigned batches in one place.
          </DialogDescription>
        </DialogHeader>

        {!manufacturer ? (
          <DialogEmptyState
            title="Choose a manufacturer to review"
            description="Close this dialog, reopen View details from the manufacturer row or card you want, and MSCQR will reload the latest assignment and printing summary."
            onClose={() => onOpenChange(false)}
          />
        ) : (
          <div className="space-y-5">
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="rounded-2xl border bg-muted/20 p-4">
                <div className="text-sm font-medium text-muted-foreground">Manufacturer</div>
                <div className="mt-2 text-lg font-semibold">{manufacturer.name}</div>
                <div className="mt-1 text-sm text-muted-foreground">{friendlyReferenceLabel(manufacturer.id, "Factory")}</div>
              </div>
              <div className="rounded-2xl border bg-muted/20 p-4">
                <div className="text-sm font-medium text-muted-foreground">Current status</div>
                <div className="mt-2 text-lg font-semibold">{operationalStatus.label}</div>
                <div className="mt-1 text-sm text-muted-foreground">
                  Last assignment: {formatAssignmentTimestamp(stats?.lastBatchAt)}
                </div>
              </div>
            </div>

            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <div className="rounded-2xl border p-4">
                <div className="text-sm text-muted-foreground">Assigned batches</div>
                <div className="mt-2 text-2xl font-semibold">{stats?.assignedBatches || 0}</div>
              </div>
              <div className="rounded-2xl border p-4">
                <div className="text-sm text-muted-foreground">Assigned QR labels</div>
                <div className="mt-2 text-2xl font-semibold">{stats?.assignedCodes || 0}</div>
              </div>
              <div className="rounded-2xl border p-4">
                <div className="text-sm text-muted-foreground">Printed batches</div>
                <div className="mt-2 text-2xl font-semibold">{stats?.printedBatches || 0}</div>
              </div>
              <div className="rounded-2xl border p-4">
                <div className="text-sm text-muted-foreground">Needs print action</div>
                <div className="mt-2 text-2xl font-semibold">{stats?.pendingPrintBatches || 0}</div>
              </div>
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <div className="rounded-2xl border p-4">
                <div className="text-sm text-muted-foreground">Admin contact</div>
                <div className="mt-2 font-medium">{manufacturer.email}</div>
                <div className="mt-1 text-sm text-muted-foreground">{manufacturer.location || "Location not added yet"}</div>
              </div>
              <div className="rounded-2xl border p-4">
                <div className="text-sm text-muted-foreground">Website</div>
                <div className="mt-2 font-medium">
                  {manufacturer.website ? (
                    <a className="text-primary hover:underline" href={manufacturer.website} rel="noreferrer" target="_blank">
                      {manufacturer.website}
                    </a>
                  ) : (
                    "No website added"
                  )}
                </div>
                <div className="mt-1 text-sm text-muted-foreground">
                  {manufacturer.isActive ? "Manufacturer account is active." : "Manufacturer account is inactive."}
                </div>
              </div>
            </div>

            <div className="rounded-2xl border">
              <div className="border-b px-5 py-4">
                <div className="text-sm font-semibold">Recent assigned batches</div>
              </div>
              <div className="space-y-3 p-5">
                {(stats?.recentBatches || []).length === 0 ? (
                  <div className="text-sm text-muted-foreground">No assigned batches yet.</div>
                ) : (
                  stats?.recentBatches.map((batch) => (
                    <div key={batch.id} className="flex flex-col gap-2 rounded-2xl border bg-muted/20 p-4 sm:flex-row sm:items-center sm:justify-between">
                      <div>
                        <div className="font-medium">{batch.name || "Unnamed batch"}</div>
                        <details className="mt-1 text-xs text-muted-foreground">
                          <summary className="cursor-pointer">Technical details</summary>
                          <div className="mt-1 break-all font-mono">{batch.startCode || "?"} to {batch.endCode || "?"}</div>
                        </details>
                      </div>
                      <div className="text-sm text-muted-foreground sm:text-right">
                        <div className="font-medium text-foreground">{batch.totalCodes || 0} QR labels</div>
                        <div>{batch.printedAt ? "Printed" : "Ready to print"}</div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>

            <div className="flex flex-wrap justify-end gap-2">
              <Button variant="outline" onClick={() => onCopyId(manufacturer.id)}>
                <Copy className="mr-2 h-4 w-4" />
                Copy support reference
              </Button>
              <Button onClick={() => onOpenBatches(manufacturer)}>
                <PackageCheck className="mr-2 h-4 w-4" />
                Open manufacturer batches
              </Button>
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
