import { format } from "date-fns";
import { Download, RefreshCw, Search } from "lucide-react";

import { OperationalTableShell } from "@/components/platform/OperationalTableShell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { DataTablePagePattern } from "@/components/page-patterns/PagePatterns";
import { buildStableBatchOverviewRows, type StableBatchOverviewRow } from "@/lib/batch-workspace";
import { ActionButton } from "@/components/ui/action-button";
import { createUiActionState } from "@/lib/ui-actions";

import type { BatchRow } from "@/features/batches/types";

type BatchesWorkspaceTableProps = {
  role?: string | null;
  isManufacturer: boolean;
  loading: boolean;
  error: string | null;
  allocationHint: { title: string; body: string } | null;
  q: string;
  assignmentFilter: "all" | "assigned" | "unassigned";
  printFilter: "all" | "printed" | "unprinted";
  rows: BatchRow[];
  filteredRows: BatchRow[];
  stableRows: StableBatchOverviewRow[];
  filteredStableRows: StableBatchOverviewRow[];
  printerDiagnostics: {
    tone: "success" | "warning" | "neutral" | "danger";
    summary: string;
    badgeLabel: string;
  };
  onDismissAllocationHint: () => void;
  onSearchChange: (value: string) => void;
  onAssignmentFilterChange: (value: "all" | "assigned" | "unassigned") => void;
  onPrintFilterChange: (value: "all" | "printed" | "unprinted") => void;
  onRefreshPrinterStatus: () => void;
  onRefreshBatches: () => void;
  onOpenPrintPack: (batch: BatchRow) => void;
  onOpenWorkspace: (workspace: StableBatchOverviewRow) => void;
  getAvailableInventory: (batch: BatchRow) => number;
  getAvailabilityTone: (quantity: number) => "default" | "secondary" | "destructive" | "outline";
  getAvailabilityTitle: (batch: BatchRow) => string;
};

export function BatchesWorkspaceTable({
  role,
  isManufacturer,
  loading,
  error,
  allocationHint,
  q,
  assignmentFilter,
  printFilter,
  rows,
  filteredRows,
  stableRows,
  filteredStableRows,
  printerDiagnostics,
  onDismissAllocationHint,
  onSearchChange,
  onAssignmentFilterChange,
  onPrintFilterChange,
  onRefreshPrinterStatus,
  onRefreshBatches,
  onOpenPrintPack,
  onOpenWorkspace,
  getAvailableInventory,
  getAvailabilityTone,
  getAvailabilityTitle,
}: BatchesWorkspaceTableProps) {
  return (
    <DataTablePagePattern
      title="Batches"
      description={
        isManufacturer
          ? "See your assigned batches, start print runs, recover interrupted work, and confirm what has finished printing."
          : "Review source batches, assign stock, check print progress, and open each batch workspace without split-row confusion."
      }
      actions={
        <>
          {isManufacturer ? (
            <Button
              variant="outline"
              onClick={onRefreshPrinterStatus}
              className={
                printerDiagnostics.tone === "success"
                  ? "border-emerald-300 bg-emerald-50 text-emerald-700 hover:bg-emerald-100"
                  : printerDiagnostics.tone === "warning"
                    ? "border-amber-300 bg-amber-50 text-amber-700 hover:bg-amber-100"
                    : printerDiagnostics.tone === "neutral"
                      ? "border-slate-300 bg-slate-100 text-slate-700 hover:bg-slate-200"
                      : "border-red-300 bg-red-50 text-red-700 hover:bg-red-100"
              }
              title={printerDiagnostics.summary}
            >
              {`Printing ${printerDiagnostics.badgeLabel}`}
            </Button>
          ) : null}
          <ActionButton
            variant="outline"
            onClick={onRefreshBatches}
            state={loading ? createUiActionState("pending", "Refreshing the latest batch and print status.") : createUiActionState("enabled")}
            idleLabel={
              <>
                <RefreshCw className="h-4 w-4" />
                Refresh
              </>
            }
            pendingLabel="Refreshing..."
            showReasonBelow={false}
            data-testid="refresh-batches"
          />
        </>
      }
    >
      {error && (
        <div className="rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">
          {error}
        </div>
      )}

      {allocationHint ? (
        <div className="rounded-xl border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-900">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <p className="font-semibold">{allocationHint.title}</p>
              <p className="mt-1">{allocationHint.body}</p>
            </div>
            <Button type="button" variant="outline" size="sm" onClick={onDismissAllocationHint}>
              Dismiss
            </Button>
          </div>
        </div>
      ) : null}

      <OperationalTableShell
        title={isManufacturer ? "Controlled print queue" : "Batch lifecycle registry"}
        description={
          isManufacturer
            ? "Start governed print runs only from batches with available inventory and confirmed printer readiness."
            : "Inspect source batches, assignment state, print progress, and allocation evidence without changing scope rules."
        }
      >
        <div className="border-b border-mscqr-border p-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                data-testid="batches-search-input"
                placeholder="Search batches..."
                value={q}
                onChange={(e) => onSearchChange(e.target.value)}
                className="pl-9"
              />
            </div>
            {role !== "manufacturer" ? (
              <Select value={assignmentFilter} onValueChange={(v) => onAssignmentFilterChange(v as "all" | "assigned" | "unassigned")}>
                <SelectTrigger data-testid="batches-assignment-filter" className="w-[220px]">
                  <SelectValue placeholder="Assignment filter" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All source batches</SelectItem>
                  <SelectItem value="assigned">With manufacturer assignments</SelectItem>
                  <SelectItem value="unassigned">With unassigned inventory</SelectItem>
                </SelectContent>
              </Select>
            ) : (
              <Select value={printFilter} onValueChange={(v) => onPrintFilterChange(v as "all" | "printed" | "unprinted")}>
                <SelectTrigger data-testid="batches-print-filter" className="w-[220px]">
                  <SelectValue placeholder="Printed filter" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All batches</SelectItem>
                  <SelectItem value="printed">Printed</SelectItem>
                  <SelectItem value="unprinted">Not printed</SelectItem>
                </SelectContent>
              </Select>
            )}
          </div>
        </div>

        <div className="p-4">
          {isManufacturer ? (
            <>
              <div className="rounded-2xl border border-mscqr-border">
                <Table className="table-fixed">
                  <TableHeader>
                    <TableRow>
                      <TableHead>Batch</TableHead>
                      <TableHead>Range</TableHead>
                      <TableHead>Inventory State</TableHead>
                      <TableHead>Manufacturer</TableHead>
                      <TableHead>Printed</TableHead>
                      <TableHead>Created</TableHead>
                      <TableHead>Controls</TableHead>
                    </TableRow>
                  </TableHeader>

                  <TableBody>
                    {loading ? (
                      <TableRow>
                        <TableCell colSpan={7} className="text-muted-foreground">
                          Loading...
                        </TableCell>
                      </TableRow>
                    ) : filteredRows.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={7} className="text-muted-foreground">
                          No batches found.
                        </TableCell>
                      </TableRow>
                    ) : (
                      filteredRows.map((batch) => {
                        const printed = !!batch.printedAt;

                        return (
                          <TableRow key={batch.id}>
                            <TableCell>
                              <div className="space-y-1">
                                <div className="font-medium break-words">{batch.name}</div>
                                {batch.licensee?.name ? (
                                  <div className="text-xs text-muted-foreground">
                                    {batch.licensee.name} ({batch.licensee.prefix})
                                  </div>
                                ) : (
                                  <div className="text-xs text-muted-foreground">Brand owner view</div>
                                )}
                                <div className="flex items-center gap-2 text-xs">
                                  <Badge variant="default">Allocated batch</Badge>
                                  <Badge variant={Number(batch.totalCodes || 0) > 0 ? "outline" : "secondary"}>
                                    {Number(batch.totalCodes || 0).toLocaleString()} total
                                  </Badge>
                                </div>
                              </div>
                            </TableCell>

                            <TableCell className="font-mono text-xs">
                              <div className="break-all">{batch.startCode}</div>
                              <div className="break-all">{batch.endCode}</div>
                            </TableCell>

                            <TableCell>
                              <div className="space-y-1">
                                <Badge variant={getAvailabilityTone(getAvailableInventory(batch))}>
                                  {getAvailabilityTitle(batch)}: {getAvailableInventory(batch).toLocaleString()}
                                </Badge>
                                <div className="text-[11px] text-muted-foreground">
                                  Printed {Number(batch.printedCodes || 0).toLocaleString()} · Scanned {Number(batch.redeemedCodes || 0).toLocaleString()}
                                </div>
                                <div className="text-[11px] text-muted-foreground font-mono break-all">
                                  {batch.remainingStartCode && batch.remainingEndCode
                                    ? `${batch.remainingStartCode} -> ${batch.remainingEndCode}`
                                    : "-"}
                                </div>
                              </div>
                            </TableCell>

                            <TableCell>
                              {batch.manufacturer ? (
                                <div className="space-y-1">
                                  <div>{batch.manufacturer.name}</div>
                                  <div className="text-xs text-muted-foreground break-all">{batch.manufacturer.email}</div>
                                </div>
                              ) : (
                                <span className="text-muted-foreground">Unassigned</span>
                              )}
                            </TableCell>

                            <TableCell>
                              {printed ? (
                                <Badge className="bg-success/10 text-success">
                                  {format(new Date(batch.printedAt as string), "MMM d, yyyy")}
                                </Badge>
                              ) : (
                                <Badge className="bg-muted text-muted-foreground">Not printed</Badge>
                              )}
                            </TableCell>

                            <TableCell className="text-muted-foreground">
                              {batch.createdAt ? format(new Date(batch.createdAt), "MMM d, yyyy") : "-"}
                            </TableCell>

                            <TableCell>
                              <ActionButton
                                data-testid="manufacturer-create-print-job"
                                size="sm"
                                variant="outline"
                                onClick={() => onOpenPrintPack(batch)}
                                state={
                                  loading
                                    ? createUiActionState("pending", "Checking whether this batch is ready to print.")
                                    : getAvailableInventory(batch) <= 0
                                      ? createUiActionState("disabled", "Nothing is waiting to print in this batch right now.")
                                      : createUiActionState("enabled")
                                }
                                idleLabel={
                                  <>
                                    <Download className="h-4 w-4" />
                                    Start print run
                                  </>
                                }
                                pendingLabel="Checking..."
                              />
                            </TableCell>
                          </TableRow>
                        );
                      })
                    )}
                  </TableBody>
                </Table>
              </div>

              <div className="mt-3 text-sm text-muted-foreground">
                Showing {filteredRows.length} of {rows.length} batches
              </div>
            </>
          ) : (
            <>
              <div className="mb-4 rounded-2xl border bg-muted/10 px-4 py-3 text-sm text-muted-foreground">
                Each source batch appears once here. Open the workspace to assign more stock, review manufacturer distribution, check print progress, and download audit evidence without split rows in the main list.
              </div>

              <div className="rounded-md border">
                <Table className="table-fixed">
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-[24%]">Batch</TableHead>
                      <TableHead className="w-[16%]">Original range</TableHead>
                      <TableHead className="w-[19%]">Inventory</TableHead>
                      <TableHead className="w-[16%]">Manufacturers</TableHead>
                      <TableHead className="w-[14%]">Print status</TableHead>
                      <TableHead className="w-[11%]">Updated</TableHead>
                      <TableHead className="w-[120px] text-right">Workspace</TableHead>
                    </TableRow>
                  </TableHeader>

                  <TableBody>
                    {loading ? (
                      <TableRow>
                        <TableCell colSpan={7} className="text-muted-foreground">
                          Loading...
                        </TableCell>
                      </TableRow>
                    ) : filteredStableRows.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={7} className="text-muted-foreground">
                          No source batches found.
                        </TableCell>
                      </TableRow>
                    ) : (
                      filteredStableRows.map((row) => {
                        const topManufacturer = row.manufacturerSummary[0] || null;

                        return (
                          <TableRow
                            key={row.sourceBatchId}
                            className="cursor-pointer hover:bg-muted/20"
                            onClick={() => onOpenWorkspace(row)}
                          >
                            <TableCell>
                              <div className="space-y-2 pr-4">
                                <div>
                                  <div className="font-medium break-words">{row.sourceBatchName}</div>
                                </div>
                                <div className="text-xs text-muted-foreground">
                                  {row.licensee?.name ? `${row.licensee.name} (${row.licensee.prefix})` : "Brand owner view"}
                                </div>
                                <div className="flex flex-wrap gap-2">
                                  <Badge variant="secondary">Source batch</Badge>
                                  <Badge variant="outline">{row.originalTotalCodes.toLocaleString()} total</Badge>
                                </div>
                              </div>
                            </TableCell>

                            <TableCell className="font-mono text-[11px] leading-5">
                              <div className="break-all">{row.sourceOriginalRangeStart}</div>
                              <div className="break-all">{row.sourceOriginalRangeEnd}</div>
                            </TableCell>

                            <TableCell>
                              <div className="space-y-2 pr-4">
                                <Badge variant={row.remainingUnassignedCodes > 0 ? "default" : "secondary"}>
                                  {row.remainingUnassignedCodes.toLocaleString()} unassigned remaining
                                </Badge>
                                <div className="flex flex-wrap gap-2 text-xs">
                                  <Badge variant={row.assignedCodes > 0 ? "secondary" : "outline"}>
                                    {row.assignedCodes.toLocaleString()} assigned
                                  </Badge>
                                  <Badge variant={row.pendingPrintableCodes > 0 ? "secondary" : "outline"}>
                                    {row.pendingPrintableCodes.toLocaleString()} ready to print
                                  </Badge>
                                </div>
                                <div className="text-[11px] text-muted-foreground font-mono break-all">
                                  {row.remainingRangeStart && row.remainingRangeEnd
                                    ? `${row.remainingRangeStart} -> ${row.remainingRangeEnd}`
                                    : "No unassigned range remains."}
                                </div>
                              </div>
                            </TableCell>

                            <TableCell>
                              {topManufacturer ? (
                                <div className="space-y-2">
                                  <div className="font-medium">{topManufacturer.manufacturerName}</div>
                                  <div className="text-xs text-muted-foreground">
                                    {row.manufacturerCount > 1
                                      ? `+${row.manufacturerCount - 1} more manufacturer accounts`
                                      : `${topManufacturer.allocatedCodes.toLocaleString()} assigned`}
                                  </div>
                                </div>
                              ) : (
                                <span className="text-muted-foreground">Not assigned yet</span>
                              )}
                            </TableCell>

                            <TableCell>
                              <div className="space-y-2">
                                <Badge variant={row.printedCodes > 0 ? "secondary" : "outline"}>
                                  {row.printedCodes.toLocaleString()} printed
                                </Badge>
                                <div className="text-xs text-muted-foreground">
                                  Ready {row.pendingPrintableCodes.toLocaleString()} · Scanned {row.redeemedCodes.toLocaleString()}
                                </div>
                              </div>
                            </TableCell>

                            <TableCell className="text-muted-foreground">
                              {row.sourceUpdatedAt ? format(new Date(row.sourceUpdatedAt), "MMM d, yyyy") : "-"}
                            </TableCell>

                            <TableCell className="text-right">
                              <ActionButton
                                data-testid="batch-workspace-open"
                                size="sm"
                                variant="outline"
                                state={createUiActionState("enabled")}
                                onClick={(event) => {
                                  event.stopPropagation();
                                  onOpenWorkspace(row);
                                }}
                                idleLabel="Review batch"
                                showReasonBelow={false}
                              />
                            </TableCell>
                          </TableRow>
                        );
                      })
                    )}
                  </TableBody>
                </Table>
              </div>

              <div className="mt-3 text-sm text-muted-foreground">
                Showing {filteredStableRows.length} of {stableRows.length} batches
              </div>
            </>
          )}
        </div>
      </OperationalTableShell>
    </DataTablePagePattern>
  );
}
