import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { useBatchWorkspaceController } from "@/features/batches/useBatchWorkspaceController";
import { buildStableBatchOverviewRows } from "@/lib/batch-workspace";
import apiClient from "@/lib/api-client";
import type { BatchRow } from "@/features/batches/types";

vi.mock("@/lib/api-client", () => ({
  default: {
    getBatchAllocationMap: vi.fn(),
    getTraceTimeline: vi.fn(async () => ({ success: true, data: [] })),
    getAuditLogs: vi.fn(async () => ({ success: true, data: [] })),
  },
}));

describe("batch workspace allocation map", () => {
  afterEach(() => { window.dispatchEvent(new Event("auth:logout")); vi.restoreAllMocks(); vi.clearAllMocks(); });
  it("uses the complete tenant-scoped map when a child is beyond the current page", async () => {
    const source: BatchRow = {
      id: "source", name: "Source", licenseeId: "tenant", batchKind: "RECEIVED_PARENT",
      startCode: "L0011", endCode: "L0150", totalCodes: 140, unassignedRemainingCodes: 140,
      printedAt: null, createdAt: "2026-03-01T00:00:00Z",
    };
    const child: BatchRow = {
      id: "child", name: "Factory allocation", licenseeId: "tenant", manufacturerId: "factory",
      batchKind: "MANUFACTURER_CHILD", parentBatchId: "source", rootBatchId: "source",
      startCode: "L0001", endCode: "L0010", totalCodes: 10, printableCodes: 10,
      printedAt: null, createdAt: "2026-03-02T00:00:00Z",
    };
    vi.mocked(apiClient.getBatchAllocationMap).mockResolvedValue({
      success: true,
      data: {
        sourceBatchId: "source", focusBatchId: "source", sourceBatch: source, selectedBatch: source,
        allocations: [child],
        totals: { totalDistributedCodes: 10, sourceRemainingCodes: 140, pendingPrintableCodes: 10, printedCodes: 0 },
      },
    } as Awaited<ReturnType<typeof apiClient.getBatchAllocationMap>>);
    const page = buildStableBatchOverviewRows([source]);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const { result, rerender } = renderHook(({ scope }) => useBatchWorkspaceController({
      rows: [source], stableRows: page, isManufacturer: false, currentLicenseeScope: scope, toast: vi.fn(),
    }), { initialProps: { scope: "tenant" }, wrapper: ({ children }) => <QueryClientProvider client={client}>{children}</QueryClientProvider> });

    await act(async () => { await result.current.openWorkspace(page[0]); });
    await waitFor(() => expect(result.current.workspaceBatch?.originalTotalCodes).toBe(150));
    expect(result.current.workspaceBatch?.remainingUnassignedCodes).toBe(140);
    expect(result.current.workspaceBatch?.assignedCodes).toBe(10);
    expect(apiClient.getBatchAllocationMap).toHaveBeenCalledWith("source", "tenant");
    rerender({ scope: "tenant-two" });
    await waitFor(() => expect(result.current.workspaceOpen).toBe(false));
    expect(result.current.workspaceBatch).toBeNull();
  });

  it("includes off-page child history on open, refresh, and allocation-map changes", async () => {
    const source: BatchRow = { id: "source", name: "Source", licenseeId: "tenant", batchKind: "RECEIVED_PARENT",
      startCode: "L0001", endCode: "L0150", totalCodes: 150, printedAt: null, createdAt: "2026-03-01T00:00:00Z" };
    const children = Array.from({ length: 101 }, (_, index): BatchRow => ({
      id: `child-${index}`, name: `Child ${index}`, licenseeId: "tenant", manufacturerId: "factory",
      batchKind: "MANUFACTURER_CHILD", parentBatchId: "source", rootBatchId: "source",
      startCode: `L${index}`, endCode: `L${index}`, totalCodes: 1, printedAt: null,
      createdAt: "2026-03-02T00:00:00Z",
    }));
    let mappedChildren = children;
    vi.mocked(apiClient.getBatchAllocationMap).mockImplementation(async () => ({ success: true, data: {
      sourceBatchId: "source", focusBatchId: "source", sourceBatch: source, selectedBatch: source,
      allocations: mappedChildren, totals: { totalDistributedCodes: mappedChildren.length,
        sourceRemainingCodes: 150 - mappedChildren.length, pendingPrintableCodes: mappedChildren.length, printedCodes: 0 },
    } }) as Awaited<ReturnType<typeof apiClient.getBatchAllocationMap>>);
    vi.mocked(apiClient.getTraceTimeline).mockImplementation(async (options) => ({ success: true, data: { events: [
      ...(options?.batchIds?.includes("source") ? [{ id: "source-event", createdAt: "2026-03-01T00:00:00Z", eventType: "COMMISSIONED" }] : []),
      ...(options?.batchIds?.includes("child-100") ? [{ id: "off-page-event", createdAt: "2026-03-03T00:00:00Z", eventType: "ASSIGNED" }] : []),
      ...(options?.batchIds?.includes("child-101") ? [{ id: "new-event", createdAt: "2026-03-04T00:00:00Z", eventType: "ASSIGNED" }] : []),
    ] },
    }) as Awaited<ReturnType<typeof apiClient.getTraceTimeline>>);
    vi.mocked(apiClient.getAuditLogs).mockResolvedValue({ success: true, data: { logs: [] } } as Awaited<ReturnType<typeof apiClient.getAuditLogs>>);
    let refresh!: () => void;
    vi.spyOn(window, "setInterval").mockImplementation((callback, delay) => {
      if (delay === 600_000) refresh = callback as () => void;
      return 1;
    });
    const page = buildStableBatchOverviewRows([source]);
    let currentPage = page;
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const { result, rerender } = renderHook(() => useBatchWorkspaceController({ rows: [source], stableRows: currentPage,
      isManufacturer: false, toast: vi.fn() }),
    { wrapper: ({ children }) => <QueryClientProvider client={client}>{children}</QueryClientProvider> });
    await act(async () => { await result.current.openWorkspace(page[0]); });
    await waitFor(() => expect(apiClient.getBatchAllocationMap).toHaveBeenCalled());
    await waitFor(() => expect(result.current.workspaceBatch?.assignedCodes).toBe(101));
    await waitFor(() => expect(result.current.workspaceHistoryLoading).toBe(false));
    expect(result.current.workspaceHistoryError).toBeNull();
    await waitFor(() => expect(result.current.workspaceHistoryLogs.map((row) => row.id)).toContain("off-page-event"));
    expect(result.current.workspaceBatch?.assignedCodes).toBe(101);
    expect(result.current.workspaceHistoryLogs.map((row) => row.id)).toEqual(["off-page-event", "source-event"]);
    expect(apiClient.getTraceTimeline).toHaveBeenCalledWith(expect.objectContaining({ batchIds: expect.arrayContaining(["child-100"]), licenseeId: "tenant" }));
    currentPage = buildStableBatchOverviewRows([{ ...source, id: "different-source" }]);
    rerender();
    expect(result.current.workspaceOpen).toBe(true);
    expect(result.current.workspaceBatch?.sourceBatchId).toBe("source");
    await act(async () => { refresh(); });
    await waitFor(() => expect(result.current.workspaceHistoryLoading).toBe(false));
    expect(result.current.workspaceHistoryLogs.map((row) => row.id)).toEqual(["off-page-event", "source-event"]);

    const staleRefresh = refresh;
    mappedChildren = [...children, { ...children[0], id: "child-101" }];
    await act(async () => { await client.invalidateQueries({ queryKey: ["batches", "allocation-map"] }); });
    rerender();
    await waitFor(() => expect(result.current.workspaceBatch?.assignedCodes).toBe(102));
    await waitFor(() => expect(apiClient.getTraceTimeline).toHaveBeenCalledWith(expect.objectContaining({ batchIds: expect.arrayContaining(["child-101"]) })));
    await waitFor(() => expect(result.current.workspaceHistoryLogs.map((row) => row.id)).toContain("new-event"));
    await act(async () => { staleRefresh(); });
    expect(result.current.workspaceBatch?.assignedCodes).toBe(102);
    expect(result.current.workspaceHistoryLogs.map((row) => row.id)).toEqual(["new-event", "off-page-event", "source-event"]);
    act(() => result.current.closeWorkspace());
    expect(result.current.workspaceHistoryLogs).toEqual([]);
    const readCountAfterClose = vi.mocked(apiClient.getTraceTimeline).mock.calls.length;
    await act(async () => { staleRefresh(); });
    expect(apiClient.getTraceTimeline).toHaveBeenCalledTimes(readCountAfterClose);
  });

  it("follows history cursors and ignores a response after closing", async () => {
    const source: BatchRow = { id: "source", name: "Source", licenseeId: "tenant", batchKind: "RECEIVED_PARENT",
      startCode: "L0001", endCode: "L0201", totalCodes: 201, printedAt: null, createdAt: "2026-03-01T00:00:00Z" };
    vi.mocked(apiClient.getBatchAllocationMap).mockResolvedValue({ success: true, data: {
      sourceBatchId: "source", focusBatchId: "source", sourceBatch: source, selectedBatch: source,
      allocations: [], totals: { totalDistributedCodes: 0, sourceRemainingCodes: 201, pendingPrintableCodes: 0, printedCodes: 0 },
    } } as Awaited<ReturnType<typeof apiClient.getBatchAllocationMap>>);
    vi.mocked(apiClient.getAuditLogs).mockResolvedValue({ success: true, data: { logs: [] } } as Awaited<ReturnType<typeof apiClient.getAuditLogs>>);
    vi.mocked(apiClient.getTraceTimeline).mockImplementation(async (options) => ({ success: true, data: options?.cursor
      ? { events: [{ id: "last-event", createdAt: "2026-03-02T00:00:00Z" }] }
      : { events: Array.from({ length: 200 }, (_, index) => ({ id: `event-${index}`, createdAt: "2026-03-01T00:00:00Z" })), nextCursor: "page-2" },
    }) as Awaited<ReturnType<typeof apiClient.getTraceTimeline>>);
    const page = buildStableBatchOverviewRows([source]);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const { result } = renderHook(() => useBatchWorkspaceController({ rows: [source], stableRows: page,
      isManufacturer: false, toast: vi.fn() }),
    { wrapper: ({ children }) => <QueryClientProvider client={client}>{children}</QueryClientProvider> });
    await act(async () => { await result.current.openWorkspace(page[0]); });
    await waitFor(() => expect(result.current.workspaceHistoryLogs).toHaveLength(201));
    expect(result.current.workspaceHistoryLogs[0].id).toBe("last-event");
    expect(apiClient.getTraceTimeline).toHaveBeenCalledWith(expect.objectContaining({ cursor: "page-2" }));

    let finish!: (value: Awaited<ReturnType<typeof apiClient.getTraceTimeline>>) => void;
    vi.mocked(apiClient.getTraceTimeline).mockImplementation(() => new Promise((resolve) => { finish = resolve; }));
    act(() => { void result.current.fetchWorkspaceHistory(result.current.workspaceBatch!); });
    await waitFor(() => expect(finish).toBeDefined());
    act(() => result.current.closeWorkspace());
    await act(async () => { finish({ success: true, data: { events: [{ id: "late-event", createdAt: "2026-03-03T00:00:00Z" }], nextCursor: "page-2" } }); });
    expect(result.current.workspaceHistoryLogs).toEqual([]);
    expect(apiClient.getTraceTimeline).toHaveBeenCalledTimes(3);
  });

  it("bounds reads across 301 batch IDs and keeps complete history after a rate limit", async () => {
    const source: BatchRow = { id: "source", name: "Source", licenseeId: "tenant", batchKind: "RECEIVED_PARENT",
      startCode: "L0001", endCode: "L0301", totalCodes: 301, printedAt: null, createdAt: "2026-03-01T00:00:00Z" };
    const children = Array.from({ length: 301 }, (_, index): BatchRow => ({ ...source, id: `child-${index}`,
      manufacturerId: "factory", batchKind: "MANUFACTURER_CHILD", parentBatchId: "source", rootBatchId: "source", totalCodes: 1 }));
    vi.mocked(apiClient.getBatchAllocationMap).mockResolvedValue({ success: true, data: {
      sourceBatchId: "source", focusBatchId: "source", sourceBatch: source, selectedBatch: source,
      allocations: children, totals: { totalDistributedCodes: 301, sourceRemainingCodes: 0, pendingPrintableCodes: 301, printedCodes: 0 },
    } } as Awaited<ReturnType<typeof apiClient.getBatchAllocationMap>>);
    vi.mocked(apiClient.getTraceTimeline).mockImplementation(async (options) => ({ success: true, data: { total: 1, events:
      options?.batchIds?.includes("child-300") ? [{ id: "last-child", createdAt: "2026-03-03T00:00:00Z" }] : [] },
    }) as Awaited<ReturnType<typeof apiClient.getTraceTimeline>>);
    vi.mocked(apiClient.getAuditLogs).mockResolvedValue({ success: true, data: { total: 0, logs: [] } } as Awaited<ReturnType<typeof apiClient.getAuditLogs>>);
    const page = buildStableBatchOverviewRows([source]);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const { result } = renderHook(() => useBatchWorkspaceController({ rows: [source], stableRows: page,
      isManufacturer: false, toast: vi.fn() }),
    { wrapper: ({ children }) => <QueryClientProvider client={client}>{children}</QueryClientProvider> });
    await act(async () => { await result.current.openWorkspace(page[0]); });
    await waitFor(() => expect(result.current.workspaceHistoryLogs.map((row) => row.id)).toContain("last-child"));
    expect(result.current.workspaceBatch?.allocations).toHaveLength(301);
    expect(apiClient.getAuditLogs).toHaveBeenCalledTimes(4);
    for (let index = 0; index < 4; index++) {
      await act(async () => { await result.current.fetchWorkspaceHistory(result.current.workspaceBatch!); });
    }
    expect(apiClient.getAuditLogs).toHaveBeenCalledTimes(20);
    await act(async () => { await result.current.fetchWorkspaceHistory(result.current.workspaceBatch!); });
    expect(result.current.workspaceHistoryError).toMatch(/incomplete.*budget/i);
    expect(result.current.workspaceHistoryLogs.map((row) => row.id)).toContain("last-child");
    expect(apiClient.getAuditLogs).toHaveBeenCalledTimes(20);
    const now = Date.now();
    vi.spyOn(Date, "now").mockReturnValue(now + 600_001);
    await act(async () => { await result.current.fetchWorkspaceHistory(result.current.workspaceBatch!); });
    expect(result.current.workspaceHistoryError).toBeNull();
    expect(result.current.workspaceHistoryLogs.map((row) => row.id)).toContain("last-child");
  });

  it("reuses unchanged cursor pages and retains history after HTTP 429", async () => {
    const source: BatchRow = { id: "source", name: "Source", licenseeId: "tenant", batchKind: "RECEIVED_PARENT",
      startCode: "L0001", endCode: "L0001", totalCodes: 1, printedAt: null, createdAt: "2026-03-01T00:00:00Z" };
    vi.mocked(apiClient.getBatchAllocationMap).mockResolvedValue({ success: true, data: {
      sourceBatchId: "source", focusBatchId: "source", sourceBatch: source, selectedBatch: source,
      allocations: [], totals: { totalDistributedCodes: 0, sourceRemainingCodes: 1, pendingPrintableCodes: 0, printedCodes: 0 },
    } } as Awaited<ReturnType<typeof apiClient.getBatchAllocationMap>>);
    vi.mocked(apiClient.getTraceTimeline).mockResolvedValue({ success: true, data: { total: 0, events: [] } } as Awaited<ReturnType<typeof apiClient.getTraceTimeline>>);
    let rateLimited = false;
    vi.mocked(apiClient.getAuditLogs).mockImplementation(async (options) => {
      if (rateLimited) return { success: false, status: 429, error: "Too many audit reads" } as Awaited<ReturnType<typeof apiClient.getAuditLogs>>;
      const pageIndex = Number(options?.cursor || 0);
      const logs = Array.from({ length: pageIndex === 3 ? 1 : 200 }, (_, index) => ({
        id: `audit-${pageIndex * 200 + index}`, createdAt: "2026-03-01T00:00:00Z", action: "ALLOCATED",
      }));
      return { success: true, data: { total: 601, logs, nextCursor: pageIndex < 3 ? String(pageIndex + 1) : null } } as Awaited<ReturnType<typeof apiClient.getAuditLogs>>;
    });
    const page = buildStableBatchOverviewRows([source]);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const { result } = renderHook(() => useBatchWorkspaceController({ rows: [source], stableRows: page,
      isManufacturer: false, toast: vi.fn() }),
    { wrapper: ({ children }) => <QueryClientProvider client={client}>{children}</QueryClientProvider> });
    await act(async () => { await result.current.openWorkspace(page[0]); });
    await waitFor(() => expect(result.current.workspaceHistoryLogs).toHaveLength(601));
    expect(apiClient.getAuditLogs).toHaveBeenCalledTimes(4);
    await act(async () => { await result.current.fetchWorkspaceHistory(result.current.workspaceBatch!); });
    expect(apiClient.getAuditLogs).toHaveBeenCalledTimes(5);
    rateLimited = true;
    await act(async () => { await result.current.fetchWorkspaceHistory(result.current.workspaceBatch!); });
    expect(result.current.workspaceHistoryLogs).toHaveLength(601);
    expect(result.current.workspaceHistoryError).toMatch(/Too many audit reads/);
    rateLimited = false;
    await act(async () => { await result.current.fetchWorkspaceHistory(result.current.workspaceBatch!); });
    expect(result.current.workspaceHistoryError).toBeNull();
    expect(result.current.workspaceHistoryLogs).toHaveLength(601);
    vi.mocked(apiClient.getAuditLogs).mockRejectedValueOnce(new Error("Network unavailable"));
    await act(async () => { await result.current.fetchWorkspaceHistory(result.current.workspaceBatch!); });
    expect(result.current.workspaceHistoryError).toBe("Network unavailable");
    expect(result.current.workspaceHistoryLogs).toHaveLength(601);
  });
});
