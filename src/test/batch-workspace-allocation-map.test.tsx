import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

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
    const { result } = renderHook(() => useBatchWorkspaceController({
      rows: [source], stableRows: page, isManufacturer: false, toast: vi.fn(),
    }), { wrapper: ({ children }) => <QueryClientProvider client={client}>{children}</QueryClientProvider> });

    await act(async () => { await result.current.openWorkspace(page[0]); });
    await waitFor(() => expect(result.current.workspaceBatch?.originalTotalCodes).toBe(150));
    expect(result.current.workspaceBatch?.remainingUnassignedCodes).toBe(140);
    expect(result.current.workspaceBatch?.assignedCodes).toBe(10);
    expect(apiClient.getBatchAllocationMap).toHaveBeenCalledWith("source", "tenant");
  });
});
