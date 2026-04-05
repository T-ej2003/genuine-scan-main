import { useEffect, useState } from "react";
import { saveAs } from "file-saver";

import type { AllocationMapPayload } from "@/components/batches/BatchAllocationMapDialog";
import apiClient from "@/lib/api-client";
import type { StableBatchOverviewRow } from "@/lib/batch-workspace";

import type { AuditLogRow, BatchRow, TraceEventRow, TraceEventType } from "./types";

type ToastLike = (options: {
  title?: string;
  description?: string;
  variant?: "default" | "destructive";
}) => unknown;

type UseBatchWorkspaceControllerParams = {
  rows: BatchRow[];
  stableRows: StableBatchOverviewRow[];
  toast: ToastLike;
  onWorkspaceBatchChange?: (batch: BatchRow | null) => void;
  onWorkspaceDraftReset?: () => void;
};

const inferTraceEventTypeFromAudit = (log: AuditLogRow): TraceEventType | undefined => {
  const action = String(log.action || "").trim().toUpperCase();
  const context = String(log.details?.context || "").trim().toUpperCase();

  if (action === "ALLOCATED" || context.includes("ASSIGN_MANUFACTURER")) return "ASSIGNED";
  if (action.includes("PRINT")) return "PRINTED";
  if (action.includes("REDEEM") || action.includes("SCAN")) return "REDEEMED";
  if (action.includes("BLOCK")) return "BLOCKED";
  if (action.includes("COMMISSION")) return "COMMISSIONED";
  return undefined;
};

const normalizeAuditLogToTraceEvent = (log: AuditLogRow): TraceEventRow => ({
  id: String(log.id || `${log.createdAt}:${log.action || "AUDIT"}`).trim(),
  eventType: inferTraceEventTypeFromAudit(log),
  action: log.action,
  sourceAction: log.action || null,
  createdAt: String(log.createdAt || new Date().toISOString()),
  details: log.details || {},
  user: log.user || null,
  userId: log.userId || log.user?.id || null,
});

export function useBatchWorkspaceController({
  rows,
  stableRows,
  toast,
  onWorkspaceBatchChange,
  onWorkspaceDraftReset,
}: UseBatchWorkspaceControllerParams) {
  const [allocationMapOpen, setAllocationMapOpen] = useState(false);
  const [allocationMapLoading, setAllocationMapLoading] = useState(false);
  const [allocationMap, setAllocationMap] = useState<AllocationMapPayload | null>(null);
  const [workspaceOpen, setWorkspaceOpen] = useState(false);
  const [workspaceBatch, setWorkspaceBatch] = useState<StableBatchOverviewRow | null>(null);
  const [workspaceHistoryLogs, setWorkspaceHistoryLogs] = useState<TraceEventRow[]>([]);
  const [workspaceHistoryLoading, setWorkspaceHistoryLoading] = useState(false);
  const [workspaceHistoryLastUpdatedAt, setWorkspaceHistoryLastUpdatedAt] = useState<Date | null>(null);
  const [exportingBatchId, setExportingBatchId] = useState<string | null>(null);

  const fetchWorkspaceHistory = async (workspace: StableBatchOverviewRow, options?: { silent?: boolean }) => {
    if (!options?.silent) {
      setWorkspaceHistoryLoading(true);
    }

    try {
      const batchIds = Array.from(
        new Set(
          [workspace.sourceBatchRow?.id || workspace.sourceBatchId, ...workspace.allocations.map((allocation) => allocation.batchId)]
            .map((value) => String(value || "").trim())
            .filter(Boolean)
        )
      );

      const [traceResponses, auditResponses] = await Promise.all([
        Promise.all(batchIds.map((batchId) => apiClient.getTraceTimeline({ batchId, limit: 60 }))),
        Promise.all(batchIds.map((batchId) => apiClient.getAuditLogs({ entityType: "Batch", entityId: batchId, limit: 60 }))),
      ]);

      const merged = new Map<string, TraceEventRow>();

      for (const response of traceResponses) {
        if (!response.success) continue;
        const payload = response.data as
          | TraceEventRow[]
          | { events?: TraceEventRow[]; logs?: TraceEventRow[] }
          | undefined;
        const list = Array.isArray(payload)
          ? payload
          : Array.isArray(payload?.events)
            ? payload.events
            : Array.isArray(payload?.logs)
              ? payload.logs
              : [];

        for (const item of list) {
          const key = String(item.id || `${item.createdAt}:${item.action || item.sourceAction || item.eventType || "event"}`).trim();
          if (!merged.has(key)) {
            merged.set(key, item);
          }
        }
      }

      for (const response of auditResponses) {
        if (!response.success) continue;
        const payload = response.data as AuditLogRow[] | { logs?: AuditLogRow[]; data?: AuditLogRow[] } | undefined;
        const list = Array.isArray(payload)
          ? payload
          : Array.isArray(payload?.logs)
            ? payload.logs
            : Array.isArray(payload?.data)
              ? payload.data
              : [];

        for (const item of list) {
          const normalized = normalizeAuditLogToTraceEvent(item);
          const key = String(
            normalized.id ||
              `${normalized.createdAt}:${normalized.action || normalized.sourceAction || normalized.eventType || "audit"}`
          ).trim();

          if (!merged.has(key)) {
            merged.set(key, normalized);
          }
        }
      }

      setWorkspaceHistoryLogs(
        Array.from(merged.values()).sort(
          (left, right) => new Date(right.createdAt).getTime() - new Date(left.createdAt).getTime()
        )
      );
      setWorkspaceHistoryLastUpdatedAt(new Date());
    } finally {
      setWorkspaceHistoryLoading(false);
    }
  };

  const openWorkspace = async (workspace: StableBatchOverviewRow) => {
    setWorkspaceBatch(workspace);
    setWorkspaceOpen(true);
    onWorkspaceBatchChange?.(workspace.sourceBatchRow || null);
    onWorkspaceDraftReset?.();
    await fetchWorkspaceHistory(workspace);
  };

  const closeWorkspace = () => {
    setWorkspaceOpen(false);
    setWorkspaceBatch(null);
    setWorkspaceHistoryLogs([]);
    setWorkspaceHistoryLastUpdatedAt(null);
    onWorkspaceBatchChange?.(null);
    onWorkspaceDraftReset?.();
  };

  const openAllocationMap = async (batch: BatchRow) => {
    setAllocationMapOpen(true);
    setAllocationMapLoading(true);
    setAllocationMap(null);

    try {
      const response = await apiClient.getBatchAllocationMap(batch.id);
      if (!response.success || !response.data) {
        toast({
          title: "Allocation map unavailable",
          description: response.error || "Could not load allocation details for this batch.",
          variant: "destructive",
        });
        setAllocationMapOpen(false);
        return;
      }

      setAllocationMap(response.data as AllocationMapPayload);
    } finally {
      setAllocationMapLoading(false);
    }
  };

  const closeAllocationMap = () => {
    setAllocationMapOpen(false);
    setAllocationMap(null);
    setAllocationMapLoading(false);
  };

  const openBatchContextFromAllocationMap = async (batchId: string) => {
    const targetBatchId = String(batchId || "").trim();
    const mapSnapshot = (allocationMap || {}) as AllocationMapPayload;
    const sourceBatchIdFromMap = String(mapSnapshot.sourceBatchId || mapSnapshot.sourceBatch?.id || "").trim();

    closeAllocationMap();
    if (!targetBatchId && !sourceBatchIdFromMap) return;

    const currentWorkspaceMatches =
      workspaceBatch &&
      (workspaceBatch.sourceBatchId === targetBatchId ||
        workspaceBatch.sourceBatchRow?.id === targetBatchId ||
        workspaceBatch.allocations.some((allocation) => allocation.batchId === targetBatchId));
    if (currentWorkspaceMatches) return;

    const matchWorkspaceByBatchId = (candidateId: string) =>
      stableRows.find(
        (row) =>
          row.sourceBatchId === candidateId ||
          row.sourceBatchRow?.id === candidateId ||
          row.allocations.some((allocation) => allocation.batchId === candidateId)
      ) || null;

    const matchedWorkspace =
      (targetBatchId ? matchWorkspaceByBatchId(targetBatchId) : null) ||
      (sourceBatchIdFromMap ? matchWorkspaceByBatchId(sourceBatchIdFromMap) : null);

    if (matchedWorkspace) {
      await openWorkspace(matchedWorkspace);
      return;
    }

    const fallbackRow =
      (targetBatchId ? rows.find((row) => row.id === targetBatchId) : undefined) ||
      (sourceBatchIdFromMap ? rows.find((row) => row.id === sourceBatchIdFromMap) : undefined);

    if (fallbackRow) {
      onWorkspaceBatchChange?.(fallbackRow);
    }
  };

  useEffect(() => {
    if (!workspaceOpen || !workspaceBatch) return;
    const timer = window.setInterval(() => {
      void fetchWorkspaceHistory(workspaceBatch, { silent: true });
    }, 8_000);

    return () => window.clearInterval(timer);
  }, [workspaceBatch, workspaceOpen]);

  useEffect(() => {
    if (!workspaceOpen || !workspaceBatch) return;
    const refreshed = stableRows.find((row) => row.sourceBatchId === workspaceBatch.sourceBatchId) || null;
    if (!refreshed) {
      closeWorkspace();
      return;
    }

    setWorkspaceBatch(refreshed);
    onWorkspaceBatchChange?.(refreshed.sourceBatchRow || null);
    void fetchWorkspaceHistory(refreshed, { silent: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [stableRows, workspaceBatch, workspaceOpen]);

  const downloadAuditPackage = async (batch: BatchRow) => {
    if (exportingBatchId) return;
    setExportingBatchId(batch.id);
    try {
      const blob = await apiClient.exportBatchAuditPackage(batch.id);
      saveAs(blob, `batch-${batch.id}-audit-package.zip`);
      toast({
        title: "Audit package downloaded",
        description: "The package includes the manifest, event chain, and signatures.",
      });
    } catch (error) {
      toast({
        title: "Audit package failed",
        description: error instanceof Error ? error.message : "Could not download the package.",
        variant: "destructive",
      });
    } finally {
      setExportingBatchId(null);
    }
  };

  return {
    allocationMapOpen,
    allocationMapLoading,
    allocationMap,
    workspaceOpen,
    workspaceBatch,
    workspaceHistoryLogs,
    workspaceHistoryLoading,
    workspaceHistoryLastUpdatedAt,
    exportingBatchId,
    setWorkspaceOpen,
    setAllocationMapOpen,
    openWorkspace,
    closeWorkspace,
    fetchWorkspaceHistory,
    openAllocationMap,
    closeAllocationMap,
    openBatchContextFromAllocationMap,
    downloadAuditPackage,
  };
}

export type BatchWorkspaceController = ReturnType<typeof useBatchWorkspaceController>;
