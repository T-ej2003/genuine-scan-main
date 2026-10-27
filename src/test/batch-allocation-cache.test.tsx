import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";

import apiClient from "@/lib/api-client";
import { controlledDashboardGet, clearDashboardReadCache, getDashboardRequestControlState } from "@/lib/api/internal-client-dashboard-request-control";
import { useDashboardStats } from "@/features/dashboard/hooks";
import { useBatchOperationsController } from "@/features/batches/useBatchOperationsController";
import { queryKeys } from "@/lib/query-keys";

vi.mock("@/lib/api-client", () => ({ default: {
  getDashboardStats: vi.fn(), getQRStats: vi.fn(), getBatches: vi.fn(), getManufacturers: vi.fn(), assignBatchManufacturer: vi.fn(),
} }));

afterEach(() => { cleanup(); clearDashboardReadCache(); vi.clearAllMocks(); });

const source = { id: "source", name: "Source", licenseeId: "tenant-one", batchKind: "RECEIVED_PARENT" as const,
  startCode: "L0001", endCode: "L0150", totalCodes: 150, unassignedRemainingCodes: 150,
  printedAt: null, createdAt: "2026-03-01T00:00:00Z" };

it("refreshes both dashboard cache layers and batch caches only after committed allocation", async () => {
  let available = 150;
  const dashboardRead = vi.fn(async () => ({ success: true, data: { totalQRCodes: 150, available }, status: 200 }));
  const qrRead = vi.fn(async () => ({ success: true, data: { dormant: available, allocated: 150 - available }, status: 200 }));
  vi.mocked(apiClient.getDashboardStats).mockImplementation((scope) =>
    controlledDashboardGet(`dashboard:stats:?licenseeId=${scope}`, dashboardRead) as ReturnType<typeof apiClient.getDashboardStats>);
  vi.mocked(apiClient.getQRStats).mockImplementation((scope) =>
    controlledDashboardGet(`qr:stats:?licenseeId=${scope}`, qrRead) as ReturnType<typeof apiClient.getQRStats>);
  vi.mocked(apiClient.getBatches).mockImplementation(async () => ({ success: true, data: [{ ...source, unassignedRemainingCodes: available }], meta: { total: 1, limit: 100, offset: 0 } }));
  vi.mocked(apiClient.getManufacturers).mockResolvedValue({ success: true, data: [{ id: "factory", name: "Factory", email: "factory@example.test", isActive: true }] });
  vi.mocked(apiClient.assignBatchManufacturer).mockImplementation(async () => {
    available = 140;
    return { success: true, data: { allocated: 10, startCode: "L0001", endCode: "L0010", sourceRemainingCodes: 140 } };
  });

  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: React.ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
  const dashboard = renderHook(() => useDashboardStats("tenant-one"), { wrapper });
  const operations = renderHook(() => useBatchOperationsController({ role: "licensee_admin", userLicenseeId: "tenant-one",
    searchParams: new URLSearchParams(), canAssignManufacturer: true, canDelete: false, toast: vi.fn(),
    progress: { start: vi.fn(), close: vi.fn(), complete: vi.fn().mockResolvedValue(undefined) },
  }), { wrapper });
  await waitFor(() => expect(dashboard.result.current.data?.qrStats.dormant).toBe(150));
  await waitFor(() => expect(operations.result.current.rows).toHaveLength(1));
  client.setQueryData([...queryKeys.batches.allocationMap("source"), "tenant-one"], { stale: true });
  await act(async () => {
    operations.result.current.setAssignBatch(source);
    operations.result.current.setAssignManufacturerId("factory");
    operations.result.current.setAssignQuantity("10");
  });
  await act(async () => { await operations.result.current.submitAssign(); });
  await waitFor(() => expect(dashboard.result.current.data?.qrStats.dormant).toBe(140));
  expect(dashboardRead).toHaveBeenCalledTimes(2);
  expect(qrRead).toHaveBeenCalledTimes(2);
  expect(operations.result.current.rows[0]?.unassignedRemainingCodes).toBe(140);
  expect(client.getQueryState([...queryKeys.batches.allocationMap("source"), "tenant-one"])?.isInvalidated).toBe(true);
  expect(getDashboardRequestControlState().filter((entry) => entry.key.startsWith("dashboard:stats:") || entry.key.startsWith("qr:stats:")).every((entry) => entry.hasLastGood)).toBe(true);
  dashboard.unmount();
  operations.unmount();
});

it("keeps cached totals when allocation fails", async () => {
  vi.mocked(apiClient.getBatches).mockResolvedValue({ success: true, data: [source], meta: { total: 1, limit: 100, offset: 0 } });
  vi.mocked(apiClient.getManufacturers).mockResolvedValue({ success: true, data: [{ id: "factory", name: "Factory", email: "factory@example.test", isActive: true }] });
  vi.mocked(apiClient.assignBatchManufacturer).mockResolvedValue({ success: false, status: 409, error: "Conflict" });
  const cached = vi.fn(async () => ({ success: true, data: { dormant: 150 }, status: 200 }));
  await controlledDashboardGet("qr:stats:?licenseeId=tenant-one", cached);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const { result } = renderHook(() => useBatchOperationsController({ role: "licensee_admin", userLicenseeId: "tenant-one",
    searchParams: new URLSearchParams(), canAssignManufacturer: true, canDelete: false, toast: vi.fn(),
    progress: { start: vi.fn(), close: vi.fn(), complete: vi.fn().mockResolvedValue(undefined) },
  }), { wrapper: ({ children }) => <QueryClientProvider client={client}>{children}</QueryClientProvider> });
  await waitFor(() => expect(result.current.rows).toHaveLength(1));
  await act(async () => { result.current.setAssignBatch(source); result.current.setAssignManufacturerId("factory"); result.current.setAssignQuantity("10"); });
  await act(async () => { await result.current.submitAssign(); });
  await controlledDashboardGet("qr:stats:?licenseeId=tenant-one", cached);
  expect(cached).toHaveBeenCalledTimes(1);
});
