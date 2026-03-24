import React from "react";
import { format } from "date-fns";
import { Activity, Download, PencilLine, Trash2, UserCog, Boxes, Factory, Printer, ShieldCheck } from "lucide-react";

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
    const range = d.startCode && d.endCode ? ` (${d.startCode} -> ${d.endCode})` : "";
    return `Commissioned ${qty ?? "-"} codes${range}.`;
  }
  if (eventType === "ASSIGNED") {
    return `Assigned ${d.quantity ?? "-"} codes to manufacturer ${d.manufacturerId || "-"}.`;
  }
  if (eventType === "PRINTED") {
    return `Printed ${d.printedCodes ?? d.codes ?? "-"} codes.`;
  }
  if (eventType === "REDEEMED") {
    return `Redeemed on scan${d.scanCount != null ? ` (scan #${d.scanCount})` : ""}.`;
  }
  if (eventType === "BLOCKED") {
    return `Blocked${d.reason ? `: ${d.reason}` : ""}${d.blockedCodes ? ` (${d.blockedCodes} codes)` : ""}.`;
  }
  if (d.context === "ASSIGN_MANUFACTURER_QUANTITY_CHILD") {
    return `Allocated ${d.quantity ?? "-"} to manufacturer ${d.manufacturerId || "-"} (${d.startCode || "?"} -> ${d.endCode || "?"})`;
  }
  return log?.sourceAction || log?.action || "Activity";
};

const historyActor = (log: TraceEventRow) => {
  if (log?.user?.name) return `${log.user.name} (${log.user.email || log.user.id || "id"})`;
  if (log?.manufacturer?.name) return `${log.manufacturer.name} (${log.manufacturer.email || log.manufacturer.id || "id"})`;
  if (log?.user?.email) return log.user.email;
  if (log?.userId) return log.userId;
  return "System";
};

const statusTone = (value: number) => (value > 0 ? "default" : "secondary");

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
      Original allocation: {allocation.batchRangeStart}{" -> "}{allocation.batchRangeEnd}
    </div>
    {(allocation.currentRangeStart || allocation.currentRangeEnd) && (
      <div className="mt-1 text-xs text-muted-foreground font-mono break-all">
        Current printable range: {allocation.currentRangeStart || "-"}{" -> "}{allocation.currentRangeEnd || "-"}
      </div>
    )}
  </div>
);

export function LicenseeBatchWorkspaceDialog({
  open,
  onOpenChange,
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
}: LicenseeBatchWorkspaceDialogProps) {
  const remaining = Number(workspace?.remainingUnassignedCodes || 0);
  const assignQuantityValue = Number(assignQuantity || 0);
  const sourceBatch = workspace?.sourceBatchRow || null;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent data-testid="batch-workspace-dialog" className="flex h-[90vh] max-h-[90vh] flex-col overflow-hidden p-0 sm:max-w-[980px]">
        {!workspace ? null : (
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
                  <div className="text-xs font-medium uppercase tracking-[0.2em] text-muted-foreground">Source range</div>
                  <div className="mt-2 font-mono text-xs break-all">
                    {workspace.sourceOriginalRangeStart}{" -> "}{workspace.sourceOriginalRangeEnd}
                  </div>
                  <div className="mt-3 text-xs text-muted-foreground">
                    Updated {workspace.sourceUpdatedAt ? format(new Date(workspace.sourceUpdatedAt), "PPp") : "-"}
                  </div>
                </div>
              </div>
            </DialogHeader>

            <Tabs defaultValue="overview" className="flex min-h-0 flex-1 flex-col">
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
                            ? `${workspace.remainingRangeStart} -> ${workspace.remainingRangeEnd}`
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
                          If manufacturers have already received allocations, the backend will block deletion and preserve traceability.
                        </div>
                      </div>
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
                                {log.eventType ? <Badge className={eventBadgeClass(log.eventType)}>{log.eventType}</Badge> : null}
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
  );
}

function RefreshButtonLabel({ loading }: { loading: boolean }) {
  return <>{loading ? "Refreshing..." : "Refresh history"}</>;
}
