import React from "react";
import { AlertTriangle, Ban, CheckCircle2, Copy, RefreshCw, ScanEye, Search, ShieldAlert } from "lucide-react";

import { BatchAllocationMapDialog } from "@/components/batches/BatchAllocationMapDialog";
import { PremiumSectionAccordion } from "@/components/premium/PremiumSectionAccordion";
import { PremiumTableSkeleton } from "@/components/premium/PremiumLoadingBlocks";
import { TrackingInsightsPanel, type TrackingTotals, type TrackingTrendPoint } from "@/components/premium/TrackingInsightsPanel";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  decisionOutcomeTone,
  decisionRiskTone,
  decisionTrustTone,
  titleCaseDecisionValue,
} from "@/lib/verification-decision";
import { friendlyReferenceLabel } from "@/lib/friendly-reference";
import {
  describeScanContext,
  formatBatchCreatedDate,
  formatLocation,
  formatScanTimestamp,
  statusTone,
  toCount,
  type BatchSummaryRow,
  type ScanLogRow,
  type TrackingEventSummary,
  type TrackingFilterState,
} from "@/features/tracking/types";

type TrackingWorkspaceProps = {
  role?: string | null;
  loading: boolean;
  error: string | null;
  friendlyError: string;
  blockedLogCount: number;
  firstScanCount: number;
  eventSummary: TrackingEventSummary;
  analyticsTotals: TrackingTotals;
  analyticsTrend: TrackingTrendPoint[];
  scopeMeta: {
    mode: "inventory" | "activity";
    title: string;
    description: string;
    quantities: { distinctCodes: number; scanEvents: number; matchedBatches: number };
  } | null;
  filters: TrackingFilterState;
  onFiltersChange: React.Dispatch<React.SetStateAction<TrackingFilterState>>;
  onLoad: (options?: { silent?: boolean; override?: Partial<TrackingFilterState> }) => Promise<void> | void;
  isSuperAdmin: boolean;
  scopedLicenseeId?: string;
  licensees: any[];
  summary: BatchSummaryRow[];
  logs: ScanLogRow[];
  batchNameById: Map<string, string>;
  onOpenAllocationMap: (batchId: string) => Promise<void> | void;
  onCopyBatchId: (batchId: string) => Promise<void> | void;
  allocationMapOpen: boolean;
  allocationMapLoading: boolean;
  allocationMap: any | null;
  onAllocationMapOpenChange: (open: boolean) => void;
};

export function TrackingWorkspace({
  role,
  loading,
  error,
  friendlyError,
  blockedLogCount,
  firstScanCount,
  eventSummary,
  analyticsTotals,
  analyticsTrend,
  scopeMeta,
  filters,
  onFiltersChange,
  onLoad,
  isSuperAdmin,
  scopedLicenseeId,
  licensees,
  summary,
  logs,
  batchNameById,
  onOpenAllocationMap,
  onCopyBatchId,
  allocationMapOpen,
  allocationMapLoading,
  allocationMap,
  onAllocationMapOpenChange,
}: TrackingWorkspaceProps) {
  return (
    <>
      <div className="space-y-6">
        <div
          className="flex flex-col gap-3 rounded-2xl border border-mscqr-border bg-mscqr-surface p-4 shadow-sm sm:flex-row sm:items-center sm:justify-between"
        >
          <div className="flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-[#8d9db668] bg-white/70">
              <ScanEye className="h-5 w-5 text-[#667292]" />
            </div>
            <div>
              <h1 className="text-3xl font-bold tracking-tight text-mscqr-primary">Scans</h1>
              <p className="text-sm text-slate-600">
                {role === "manufacturer"
                  ? "Track customer scans for the garment batches assigned to you."
                  : "Monitor genuine scans, repeat scans, and items that need attention."}
              </p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Badge className="border-red-200 bg-red-50 text-red-700">{blockedLogCount} blocked scans</Badge>
            <Badge className="border-emerald-200 bg-emerald-50 text-emerald-700">{firstScanCount} first scans</Badge>
            <Badge className="border-amber-200 bg-amber-50 text-amber-700">{eventSummary.externalEvents} repeat or outside scans</Badge>
            <Badge className="border-sky-200 bg-sky-50 text-sky-700">{eventSummary.trustedOwnerEvents} known customer scans</Badge>
            <Button variant="outline" onClick={() => onLoad()} disabled={loading}>
              <RefreshCw className="mr-2 h-4 w-4" />
              Refresh
            </Button>
          </div>
        </div>

        {error ? (
          <div className="rounded-xl border border-red-300 bg-red-50 px-4 py-3 text-sm text-red-700">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4" />
              {friendlyError}
            </div>
            <details className="mt-2 text-xs text-red-700/80">
              <summary className="cursor-pointer">Technical details</summary>
              <p className="mt-1 break-all">{error}</p>
            </details>
          </div>
        ) : null}

        <TrackingInsightsPanel totals={analyticsTotals} trend={analyticsTrend} loading={loading && !logs.length && !summary.length} />

        {scopeMeta ? (
          <div className="grid gap-3 md:grid-cols-6">
            <div className="rounded-xl border bg-white p-4 shadow-sm">
              <p className="text-sm font-medium text-slate-500">View</p>
              <p className="mt-1 text-lg font-semibold text-slate-900">{scopeMeta.title}</p>
              <p className="mt-1 text-xs text-slate-600">{scopeMeta.description}</p>
            </div>
            <div className="rounded-xl border bg-white p-4 shadow-sm">
              <p className="text-sm font-medium text-slate-500">QR labels scanned</p>
              <p className="mt-1 text-2xl font-semibold text-slate-900">{scopeMeta.quantities.distinctCodes.toLocaleString()}</p>
            </div>
            <div className="rounded-xl border bg-white p-4 shadow-sm">
              <p className="text-sm font-medium text-slate-500">Total scans</p>
              <p className="mt-1 text-2xl font-semibold text-slate-900">{scopeMeta.quantities.scanEvents.toLocaleString()}</p>
            </div>
            <div className="rounded-xl border bg-white p-4 shadow-sm">
              <p className="text-sm font-medium text-slate-500">Matched batches</p>
              <p className="mt-1 text-2xl font-semibold text-slate-900">{scopeMeta.quantities.matchedBatches.toLocaleString()}</p>
            </div>
            <div className="rounded-xl border bg-white p-4 shadow-sm">
              <p className="text-sm font-medium text-slate-500">Scans with location</p>
              <p className="mt-1 text-2xl font-semibold text-slate-900">{eventSummary.namedLocationEvents.toLocaleString()}</p>
            </div>
            <div className="rounded-xl border bg-white p-4 shadow-sm">
              <p className="text-sm font-medium text-slate-500">Known customers</p>
              <p className="mt-1 text-2xl font-semibold text-slate-900">{eventSummary.knownDeviceEvents.toLocaleString()}</p>
            </div>
          </div>
        ) : null}

        <PremiumSectionAccordion
          defaultOpen={[]}
          items={[
            {
              value: "tracking-filters",
              title: "Advanced filters",
              subtitle: "Optional filters for QR label, batch, date, and scan behavior",
              badge: <Badge className="border-[#8d9db664] bg-[#bccad630] text-[#4f5b75]">Live scope</Badge>,
              content: (
                <div className="space-y-3">
                  <div className="flex flex-wrap gap-2">
                    <Button onClick={() => onLoad()} disabled={loading} className="bg-[#667292] text-white hover:bg-[#596380]">
                      Apply filters
                    </Button>
                    <Button
                      variant="outline"
                      disabled={loading}
                      onClick={() => {
                        const reset: TrackingFilterState = {
                          code: "",
                          batchQuery: "",
                          status: "all",
                          firstScan: "all",
                          fromDate: "",
                          toDate: "",
                          licenseeId: "all",
                          outcome: "all",
                          riskBand: "all",
                          replacementStatus: "all",
                          customerTrustReviewState: "all",
                        };
                        onFiltersChange(reset);
                        onLoad({ override: reset });
                      }}
                    >
                      Clear
                    </Button>
                  </div>

                  <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                    {isSuperAdmin ? (
                      <Select value={filters.licenseeId} onValueChange={(value) => onFiltersChange((prev) => ({ ...prev, licenseeId: value }))}>
                        <SelectTrigger>
                          <SelectValue placeholder="Brand" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="all">All brands</SelectItem>
                          {licensees.map((licensee) => (
                            <SelectItem key={licensee.id} value={licensee.id}>
                              {licensee.name}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    ) : null}

                    <div className="relative">
                      <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
                      <Input
                        placeholder="Search QR label"
                        value={filters.code}
                        onChange={(event) => onFiltersChange((prev) => ({ ...prev, code: event.target.value }))}
                        className="pl-9"
                      />
                    </div>

                    <Input
                      placeholder="Batch name"
                      value={filters.batchQuery}
                      onChange={(event) => onFiltersChange((prev) => ({ ...prev, batchQuery: event.target.value }))}
                    />

                    <Select value={filters.status} onValueChange={(value) => onFiltersChange((prev) => ({ ...prev, status: value }))}>
                      <SelectTrigger>
                        <SelectValue placeholder="Status" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All statuses</SelectItem>
                        <SelectItem value="DORMANT">Dormant</SelectItem>
                        <SelectItem value="ACTIVE">Active</SelectItem>
                        <SelectItem value="ALLOCATED">Allocated</SelectItem>
                        <SelectItem value="ACTIVATED">Activated</SelectItem>
                        <SelectItem value="PRINTED">Printed</SelectItem>
                        <SelectItem value="REDEEMED">Redeemed</SelectItem>
                        <SelectItem value="SCANNED">Scanned</SelectItem>
                        <SelectItem value="BLOCKED">Blocked</SelectItem>
                      </SelectContent>
                    </Select>

                    <Select value={filters.firstScan} onValueChange={(value) => onFiltersChange((prev) => ({ ...prev, firstScan: value }))}>
                      <SelectTrigger>
                        <SelectValue placeholder="First scan" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All scans</SelectItem>
                        <SelectItem value="yes">First scans only</SelectItem>
                        <SelectItem value="no">Repeat scans only</SelectItem>
                      </SelectContent>
                    </Select>

                    <Select value={filters.outcome} onValueChange={(value) => onFiltersChange((prev) => ({ ...prev, outcome: value }))}>
                      <SelectTrigger>
                        <SelectValue placeholder="Scan result" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All outcomes</SelectItem>
                        <SelectItem value="AUTHENTIC">Authentic</SelectItem>
                        <SelectItem value="SUSPICIOUS_DUPLICATE">Unusual repeat scan</SelectItem>
                        <SelectItem value="BLOCKED">Blocked</SelectItem>
                        <SelectItem value="NOT_READY">Not ready</SelectItem>
                      </SelectContent>
                    </Select>

                    <Select value={filters.riskBand} onValueChange={(value) => onFiltersChange((prev) => ({ ...prev, riskBand: value }))}>
                      <SelectTrigger>
                        <SelectValue placeholder="Scan risk" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All scan risks</SelectItem>
                        <SelectItem value="LOW">Low</SelectItem>
                        <SelectItem value="ELEVATED">Elevated</SelectItem>
                        <SelectItem value="HIGH">High</SelectItem>
                        <SelectItem value="CRITICAL">Critical</SelectItem>
                      </SelectContent>
                    </Select>

                    <Select
                      value={filters.replacementStatus}
                      onValueChange={(value) => onFiltersChange((prev) => ({ ...prev, replacementStatus: value }))}
                    >
                      <SelectTrigger>
                        <SelectValue placeholder="Replacement state" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All replacement states</SelectItem>
                        <SelectItem value="NONE">Primary label</SelectItem>
                        <SelectItem value="ACTIVE_REPLACEMENT">Active replacement</SelectItem>
                        <SelectItem value="REPLACED_LABEL">Superseded label</SelectItem>
                      </SelectContent>
                    </Select>

                    <Select
                      value={filters.customerTrustReviewState}
                      onValueChange={(value) => onFiltersChange((prev) => ({ ...prev, customerTrustReviewState: value }))}
                    >
                      <SelectTrigger>
                        <SelectValue placeholder="Trust review" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All trust review states</SelectItem>
                        <SelectItem value="UNREVIEWED">Unreviewed</SelectItem>
                        <SelectItem value="VERIFIED">Verified</SelectItem>
                        <SelectItem value="DISPUTED">Disputed</SelectItem>
                        <SelectItem value="REVOKED">Revoked</SelectItem>
                      </SelectContent>
                    </Select>

                    <div className="space-y-1">
                      <Label className="text-xs font-medium text-slate-600">From date</Label>
                      <Input type="date" value={filters.fromDate} onChange={(event) => onFiltersChange((prev) => ({ ...prev, fromDate: event.target.value }))} />
                    </div>
                    <div className="space-y-1">
                      <Label className="text-xs font-medium text-slate-600">To date</Label>
                      <Input type="date" value={filters.toDate} onChange={(event) => onFiltersChange((prev) => ({ ...prev, toDate: event.target.value }))} />
                    </div>
                  </div>
                </div>
              ),
            },
          ]}
        />

        <PremiumSectionAccordion
          defaultOpen={["batch-summary", "scan-logs"]}
          items={[
            {
              value: "batch-summary",
              title: "Batch summary",
              subtitle: "Scan and QR label status by garment batch",
              badge: <Badge className="border-[#8d9db664] bg-[#bccad630] text-[#4f5b75]">{summary.length} batches</Badge>,
              content:
                loading && !summary.length ? (
                  <PremiumTableSkeleton rows={6} />
                ) : (
                  <div className="overflow-hidden rounded-lg border">
                    <Table>
                      <TableHeader>
                        <TableRow className="bg-slate-50">
                          <TableHead>Batch</TableHead>
                          <TableHead>Support reference</TableHead>
                          <TableHead>QR labels</TableHead>
                          <TableHead>Scanned labels</TableHead>
                          <TableHead>Labels in batch</TableHead>
                          <TableHead>Events</TableHead>
                          <TableHead>Latest verifier state</TableHead>
                          <TableHead>Dormant</TableHead>
                          <TableHead>Allocated</TableHead>
                          <TableHead>Printed</TableHead>
                          <TableHead>Redeemed</TableHead>
                          <TableHead>Blocked</TableHead>
                          <TableHead>Created</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {summary.length === 0 ? (
                          <TableRow>
                              <TableCell colSpan={13} className="text-slate-500">
                                No batches found for current filters.
                              </TableCell>
                            </TableRow>
                        ) : (
                          summary.map((batch) => {
                            const counts = batch.counts || {};
                            const dormant = toCount(counts, "DORMANT") + toCount(counts, "ACTIVE");
                            const allocated = toCount(counts, "ALLOCATED") + toCount(counts, "ACTIVATED");
                            const redeemed = toCount(counts, "REDEEMED") + toCount(counts, "SCANNED");
                            const blocked = toCount(counts, "BLOCKED");

                            return (
                              <TableRow key={batch.id}>
                                <TableCell className="font-medium text-slate-900">{batch.name}</TableCell>
                                <TableCell className="font-mono text-xs text-slate-600">
                                  <div className="flex flex-wrap items-center gap-2">
                                    <span>{friendlyReferenceLabel(batch.id, "Batch")}</span>
                                    <Button type="button" variant="outline" size="sm" className="h-9 gap-2 whitespace-nowrap px-3 text-xs font-medium" onClick={() => onCopyBatchId(batch.id)}>
                                      <Copy className="h-3.5 w-3.5" />
                                      Copy support reference
                                    </Button>
                                  </div>
                                  <Button type="button" variant="link" className="h-auto px-0 text-xs" onClick={() => onOpenAllocationMap(batch.id)}>
                                    Open allocation map
                                  </Button>
                                </TableCell>
                                <TableCell className="text-sm text-slate-600">
                                  <div>{Number(batch.batchInventoryTotal || batch.totalCodes || 0).toLocaleString()} QR labels</div>
                                  <details className="mt-1 text-xs">
                                    <summary className="cursor-pointer">Technical details</summary>
                                    <div className="mt-1 break-all font-mono">{batch.startCode}</div>
                                    <div className="break-all font-mono">{batch.endCode}</div>
                                  </details>
                                </TableCell>
                                <TableCell>{Number(batch.scopeCodeCount || 0).toLocaleString()}</TableCell>
                                <TableCell>{Number(batch.batchInventoryTotal || batch.totalCodes || 0).toLocaleString()}</TableCell>
                                <TableCell>{Number(batch.scanEventCount || 0).toLocaleString()}</TableCell>
                                <TableCell className="space-y-1">
                                  {batch.latestDecision ? (
                                    <>
                                      <Badge className={decisionOutcomeTone(batch.latestDecision.outcome)}>
                                        {titleCaseDecisionValue(batch.latestDecision.outcome)}
                                      </Badge>
                                      <div className="flex flex-wrap gap-1">
                                        <Badge className={decisionRiskTone(batch.latestDecision.riskBand)}>
                                          {titleCaseDecisionValue(batch.latestDecision.riskBand)}
                                        </Badge>
                                        <Badge className={decisionTrustTone(batch.latestDecision.customerTrustReviewState)}>
                                          {titleCaseDecisionValue(batch.latestDecision.customerTrustReviewState)}
                                        </Badge>
                                      </div>
                                    </>
                                  ) : (
                                      <span className="text-xs text-slate-500">No scan result yet</span>
                                  )}
                                </TableCell>
                                <TableCell>
                                  <Badge className={statusTone("DORMANT")}>{dormant}</Badge>
                                </TableCell>
                                <TableCell>
                                  <Badge className={statusTone("ALLOCATED")}>{allocated}</Badge>
                                </TableCell>
                                <TableCell>
                                  <Badge className={statusTone("PRINTED")}>{toCount(counts, "PRINTED")}</Badge>
                                </TableCell>
                                <TableCell>
                                  <Badge className={statusTone("REDEEMED")}>{redeemed}</Badge>
                                </TableCell>
                                <TableCell>
                                  <Badge className={statusTone("BLOCKED")}>{blocked}</Badge>
                                </TableCell>
                                <TableCell className="text-slate-500">{formatBatchCreatedDate(batch.createdAt)}</TableCell>
                              </TableRow>
                            );
                          })
                        )}
                      </TableBody>
                    </Table>
                  </div>
                ),
            },
            {
              value: "scan-logs",
              title: "Recent scans",
              subtitle: "Customer scans and items that may need attention",
              badge: <Badge className="border-[#8d9db664] bg-[#bccad630] text-[#4f5b75]">{logs.length} entries</Badge>,
              content:
                loading && !logs.length ? (
                  <PremiumTableSkeleton rows={8} />
                ) : (
                  <>
                    <div className="overflow-hidden rounded-lg border">
                      <Table>
                        <TableHeader>
                          <TableRow className="bg-slate-50">
                            <TableHead>QR label</TableHead>
                            <TableHead>Batch</TableHead>
                            <TableHead>Status</TableHead>
                            <TableHead>Scan #</TableHead>
                            <TableHead>Context</TableHead>
                            <TableHead>Scan result</TableHead>
                            <TableHead>Location</TableHead>
                            <TableHead>Support details</TableHead>
                            <TableHead>Scanned At</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {logs.length === 0 ? (
                            <TableRow>
                              <TableCell colSpan={9} className="text-slate-500">
                                No scan logs found.
                              </TableCell>
                            </TableRow>
                          ) : (
                            logs.map((log) => {
                              const status = log.qrCode?.status || log.status || "—";
                              const tone = statusTone(status);
                              const isBlocked = String(status).toUpperCase() === "BLOCKED";
                              return (
                                <TableRow key={log.id} className={isBlocked ? "bg-red-50/40" : undefined}>
                                  <TableCell className="font-mono text-xs">
                                    <div className="font-semibold text-slate-900">{log.code}</div>
                                    {log.licensee?.name ? <div className="text-slate-500">{log.licensee.name}</div> : null}
                                  </TableCell>
                                  <TableCell className="text-sm text-slate-700">
                                    {log.batchId ? batchNameById.get(log.batchId) || log.batchId : "—"}
                                  </TableCell>
                                  <TableCell>
                                    <Badge className={tone}>
                                      {isBlocked ? <Ban className="mr-1 h-3 w-3" /> : <CheckCircle2 className="mr-1 h-3 w-3" />}
                                      {status}
                                    </Badge>
                                  </TableCell>
                                  <TableCell>
                                    <div className="font-medium text-slate-900">{log.scanCount ?? 0}</div>
                                    {log.isFirstScan ? (
                                      <Badge className="mt-1 border-emerald-200 bg-emerald-50 text-emerald-700">First scan</Badge>
                                    ) : (
                                      <Badge className="mt-1 border-amber-200 bg-amber-50 text-amber-700">
                                        <AlertTriangle className="mr-1 h-3 w-3" />
                                        Repeat
                                      </Badge>
                                    )}
                                  </TableCell>
                                  <TableCell className="text-xs text-slate-700">
                                    <Badge className={log.isTrustedOwnerContext ? "border-sky-200 bg-sky-50 text-sky-700" : "border-amber-200 bg-amber-50 text-amber-700"}>
                                      {log.isTrustedOwnerContext ? "Trusted owner" : "External"}
                                    </Badge>
                                    <div className="mt-1 text-[11px] text-slate-500">{describeScanContext(log)}</div>
                                  </TableCell>
                                  <TableCell className="space-y-1 text-xs">
                                    {log.latestDecision ? (
                                      <>
                                        <Badge className={decisionOutcomeTone(log.latestDecision.outcome)}>
                                          {titleCaseDecisionValue(log.latestDecision.outcome)}
                                        </Badge>
                                        <div className="flex flex-wrap gap-1">
                                          <Badge className={decisionRiskTone(log.latestDecision.riskBand)}>
                                            {titleCaseDecisionValue(log.latestDecision.riskBand)}
                                          </Badge>
                                          <Badge className={decisionTrustTone(log.latestDecision.customerTrustReviewState)}>
                                            {titleCaseDecisionValue(log.latestDecision.customerTrustReviewState)}
                                          </Badge>
                                        </div>
                                      </>
                                    ) : (
                                      <span className="text-slate-500">No scan result yet</span>
                                    )}
                                  </TableCell>
                                  <TableCell className="text-xs text-slate-700">{formatLocation(log)}</TableCell>
                                  <TableCell className="max-w-[240px] text-xs text-slate-600">
                                    <details>
                                      <summary className="cursor-pointer">Technical details</summary>
                                      <div className="mt-1">{log.deviceLabel || "Browser device"}</div>
                                      <div className="mt-1 break-all">
                                        {log.userAgent ? "Browser details captured" : "Browser details unavailable"}
                                      </div>
                                      <div className="mt-1 break-all">{log.ipAddress || "Network address unavailable"}</div>
                                    </details>
                                  </TableCell>
                                  <TableCell className="text-xs text-slate-600">{formatScanTimestamp(log.scannedAt)}</TableCell>
                                </TableRow>
                              );
                            })
                          )}
                        </TableBody>
                      </Table>
                    </div>

                    <div className="mt-3 text-sm text-slate-500">
                      Scope: {isSuperAdmin ? (scopedLicenseeId ? "Selected brand" : "All brands") : "Your assigned workspace only"}
                    </div>
                  </>
                ),
            },
          ]}
        />
      </div>

      <BatchAllocationMapDialog
        open={allocationMapOpen}
        onOpenChange={onAllocationMapOpenChange}
        loading={allocationMapLoading}
        payload={allocationMap}
      />
    </>
  );
}
