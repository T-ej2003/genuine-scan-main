import { useEffect, useMemo, useRef, useState } from "react";
import { saveAs } from "file-saver";

import type { AllocationMapPayload } from "@/components/batches/BatchAllocationMapDialog";
import apiClient from "@/lib/api-client";
import { buildStableBatchOverviewRows, type StableBatchOverviewRow } from "@/lib/batch-workspace";

import { useBatchAllocationMap } from "./hooks";
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
  isManufacturer: boolean;
  currentLicenseeScope?: string;
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

const HISTORY_PAGE_SIZE = 200;
const HISTORY_BATCH_SIZE = 100;
const HISTORY_BATCH_CONCURRENCY = 2;

const readHistoryPages = async <T,>(
  fetchPage: (cursor?: string) => Promise<{ success: boolean; data?: unknown; error?: string }>,
  rowsFromPayload: (payload: unknown) => T[]
): Promise<T[]> => {
  const rows: T[] = [];
  const seenCursors = new Set<string>();
  let cursor: string | undefined;
  while (true) {
    const response = await fetchPage(cursor);
    if (!response.success) throw new Error(response.error || "Audit history could not be loaded");
    const page = rowsFromPayload(response.data);
    rows.push(...page);
    const nextCursor = (response.data as { nextCursor?: string | null } | undefined)?.nextCursor || undefined;
    if (!nextCursor) return rows;
    if (seenCursors.has(nextCursor)) throw new Error("Audit history pagination did not advance");
    seenCursors.add(nextCursor);
    cursor = nextCursor;
  }
};

const traceRows = (payload: unknown): TraceEventRow[] => {
  if (Array.isArray(payload)) return payload as TraceEventRow[];
  const data = payload as { events?: TraceEventRow[]; logs?: TraceEventRow[] } | undefined;
  return data?.events || data?.logs || [];
};

const auditRows = (payload: unknown): AuditLogRow[] => {
  if (Array.isArray(payload)) return payload as AuditLogRow[];
  const data = payload as { logs?: AuditLogRow[]; data?: AuditLogRow[] } | undefined;
  return data?.logs || data?.data || [];
};

export function useBatchWorkspaceController({
  rows,
  stableRows,
  toast,
  isManufacturer,
  currentLicenseeScope,
  onWorkspaceBatchChange,
  onWorkspaceDraftReset,
}: UseBatchWorkspaceControllerParams) {
  const [allocationMapOpen, setAllocationMapOpen] = useState(false);
  const [allocationMapLoading, setAllocationMapLoading] = useState(false);
  const [allocationMap, setAllocationMap] = useState<AllocationMapPayload | null>(null);
  const [workspaceOpen, setWorkspaceOpen] = useState(false);
  const [workspaceBatch, setWorkspaceBatch] = useState<StableBatchOverviewRow | null>(null);
  const lastPageRows = useRef(stableRows);
  const workspaceTenant = workspaceBatch?.licensee?.id || workspaceBatch?.sourceBatchRow?.licenseeId;
  const scopeMatches = isManufacturer || currentLicenseeScope === undefined || currentLicenseeScope === workspaceTenant;
  const workspaceMapQuery = useBatchAllocationMap(
    workspaceBatch?.focusBatchId,
    workspaceOpen && !isManufacturer && scopeMatches,
    workspaceTenant
  );
  const completeWorkspace = useMemo(() => {
    const map = workspaceMapQuery.data;
    if (!map?.sourceBatch) return null;
    return buildStableBatchOverviewRows([map.sourceBatch, ...map.allocations] as BatchRow[])[0] || null;
  }, [workspaceMapQuery.data]);
  const [workspaceHistoryLogs, setWorkspaceHistoryLogs] = useState<TraceEventRow[]>([]);
  const [workspaceHistoryLoading, setWorkspaceHistoryLoading] = useState(false);
  const [workspaceHistoryError, setWorkspaceHistoryError] = useState<string | null>(null);
  const [workspaceHistoryLastUpdatedAt, setWorkspaceHistoryLastUpdatedAt] = useState<Date | null>(null);
  const historyRequest = useRef(0);
  const openWorkspaceSource = useRef<string | null>(null);
  const [exportingBatchId, setExportingBatchId] = useState<string | null>(null);

  useEffect(() => () => { historyRequest.current += 1; }, []);

  const fetchWorkspaceHistory = async (workspace: StableBatchOverviewRow, options?: { silent?: boolean }) => {
    const selected = !isManufacturer && completeWorkspace?.sourceBatchId === workspace.sourceBatchId
      ? completeWorkspace : isManufacturer ? workspace : null;
    if (!selected || !scopeMatches || openWorkspaceSource.current !== selected.sourceBatchId) return;
    const request = ++historyRequest.current;
    if (!options?.silent) {
      setWorkspaceHistoryLoading(true);
    }
    setWorkspaceHistoryError(null);

    try {
      const batchIds = Array.from(
        new Set(
          [selected.sourceBatchRow?.id || selected.sourceBatchId, ...selected.allocations.map((allocation) => allocation.batchId)]
            .map((value) => String(value || "").trim())
            .filter(Boolean)
        )
      );
      const licenseeId = selected.licensee?.id || selected.sourceBatchRow?.licenseeId;
      const merged = new Map<string, TraceEventRow>();
      const chunks = Array.from({ length: Math.ceil(batchIds.length / HISTORY_BATCH_SIZE) }, (_, index) =>
        batchIds.slice(index * HISTORY_BATCH_SIZE, (index + 1) * HISTORY_BATCH_SIZE));
      for (let index = 0; index < chunks.length; index += HISTORY_BATCH_CONCURRENCY) {
        const group = await Promise.all(chunks.slice(index, index + HISTORY_BATCH_CONCURRENCY).map(async (ids) =>
          Promise.all([
            readHistoryPages<TraceEventRow>((cursor) => apiClient.getTraceTimeline({ batchIds: ids, limit: HISTORY_PAGE_SIZE, cursor,
              licenseeId, purpose: "batch-workspace-history-review" }), traceRows),
            readHistoryPages<AuditLogRow>((cursor) => apiClient.getAuditLogs({ entityType: "Batch", entityIds: ids,
              limit: HISTORY_PAGE_SIZE, cursor, licenseeId, purpose: "batch-workspace-history-review" }), auditRows),
          ])
        ));
        if (request !== historyRequest.current) return;
        for (const [traces, audits] of group) {
          for (const item of traces) merged.set(String(item.id), item);
          for (const item of audits) {
            const normalized = normalizeAuditLogToTraceEvent(item);
            if (!merged.has(normalized.id)) merged.set(normalized.id, normalized);
          }
        }
      }

      setWorkspaceHistoryLogs(
        Array.from(merged.values()).sort(
          (left, right) => new Date(right.createdAt).getTime() - new Date(left.createdAt).getTime() || right.id.localeCompare(left.id)
        )
      );
      setWorkspaceHistoryLastUpdatedAt(new Date());
    } catch (error) {
      if (request === historyRequest.current) setWorkspaceHistoryError(error instanceof Error ? error.message : "Audit history could not be loaded");
    } finally {
      if (request === historyRequest.current) setWorkspaceHistoryLoading(false);
    }
  };

  const openWorkspace = async (workspace: StableBatchOverviewRow) => {
    historyRequest.current += 1;
    openWorkspaceSource.current = workspace.sourceBatchId;
    setWorkspaceBatch(workspace);
    setWorkspaceOpen(true);
    setWorkspaceHistoryLogs([]);
    setWorkspaceHistoryLastUpdatedAt(null);
    setWorkspaceHistoryError(null);
    onWorkspaceBatchChange?.(isManufacturer ? workspace.sourceBatchRow || null : null);
    onWorkspaceDraftReset?.();
    if (isManufacturer) await fetchWorkspaceHistory(workspace);
  };

  const closeWorkspace = () => {
    historyRequest.current += 1;
    openWorkspaceSource.current = null;
    setWorkspaceOpen(false);
    setWorkspaceBatch(null);
    setWorkspaceHistoryLogs([]);
    setWorkspaceHistoryLastUpdatedAt(null);
    setWorkspaceHistoryLoading(false);
    setWorkspaceHistoryError(null);
    onWorkspaceBatchChange?.(null);
    onWorkspaceDraftReset?.();
  };

  const openAllocationMap = async (batch: BatchRow) => {
    setAllocationMapOpen(true);
    setAllocationMapLoading(true);
    setAllocationMap(null);

    try {
      if (workspaceMapQuery.data && workspaceBatch?.sourceBatchId === (batch.rootBatchId || batch.parentBatchId || batch.id)) {
        setAllocationMap(workspaceMapQuery.data as AllocationMapPayload);
        return;
      }
      const response = await apiClient.getBatchAllocationMap(batch.id, batch.licenseeId);
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
    if (!workspaceOpen || isManufacturer || !scopeMatches || !completeWorkspace) return;
    onWorkspaceBatchChange?.(completeWorkspace.sourceBatchRow || null);
    void fetchWorkspaceHistory(completeWorkspace);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [completeWorkspace, isManufacturer, scopeMatches, workspaceOpen]);

  useEffect(() => {
    if (workspaceOpen && !isManufacturer && !scopeMatches) closeWorkspace();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentLicenseeScope, scopeMatches]);

  useEffect(() => {
    const currentWorkspace = isManufacturer ? workspaceBatch : completeWorkspace;
    if (!workspaceOpen || !currentWorkspace) return;
    const timer = window.setInterval(() => {
      void fetchWorkspaceHistory(currentWorkspace, { silent: true });
    }, 60_000);

    return () => window.clearInterval(timer);
  }, [completeWorkspace, isManufacturer, workspaceBatch, workspaceOpen]);

  useEffect(() => {
    if (lastPageRows.current === stableRows) return;
    lastPageRows.current = stableRows;
    if (!workspaceOpen || !workspaceBatch) return;
    const refreshed = stableRows.find((row) => row.sourceBatchId === workspaceBatch.sourceBatchId) || null;
    if (!refreshed) {
      if (!isManufacturer) {
        void workspaceMapQuery.refetch();
        return;
      }
      closeWorkspace();
      return;
    }

    if (isManufacturer) {
      setWorkspaceBatch(refreshed);
      onWorkspaceBatchChange?.(refreshed.sourceBatchRow || null);
      void fetchWorkspaceHistory(refreshed, { silent: true });
    } else {
      void workspaceMapQuery.refetch();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [stableRows, workspaceOpen]);

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
    workspaceBatch: isManufacturer ? workspaceBatch : scopeMatches ? completeWorkspace : null,
    workspaceLoading: !isManufacturer && workspaceOpen && workspaceMapQuery.isPending,
    workspaceError: !isManufacturer && workspaceOpen ? workspaceMapQuery.error?.message || null : null,
    workspaceHistoryLogs,
    workspaceHistoryLoading,
    workspaceHistoryError,
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
