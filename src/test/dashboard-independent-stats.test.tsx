import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";

import apiClient from "@/lib/api-client";
import { useDashboardStats } from "@/features/dashboard/hooks";
import { setRequestCoordinatorScope } from "@/lib/api/request-coordinator";

vi.mock("@/lib/api-client", () => ({ default: { getDashboardStats: vi.fn(), getQRStats: vi.fn() } }));
afterEach(() => { cleanup(); vi.resetAllMocks(); });

it("does not reuse dashboard results after the authenticated scope changes", async () => {
  let total = 1;
  vi.mocked(apiClient.getDashboardStats).mockImplementation(async () => ({ success: true, data: {
    totalQRCodes: total++, activeLicensees: 1, manufacturers: 1, totalBatches: 1,
  } }));
  vi.mocked(apiClient.getQRStats).mockResolvedValue({ success: true, data: {
    total: 1, dormant: 1, allocated: 0, printed: 0, scanned: 0,
  } });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: React.ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
  setRequestCoordinatorScope({ id: "tenant-a" });
  const { result, rerender } = renderHook(() => useDashboardStats(), { wrapper });
  await waitFor(() => expect(result.current.data?.summary?.totalQRCodes).toBe(1));
  setRequestCoordinatorScope({ id: "tenant-b" });
  rerender();
  expect(result.current.data?.summary?.totalQRCodes).not.toBe(1);
  await waitFor(() => expect(result.current.data?.summary?.totalQRCodes).toBe(2));
  client.clear();
  setRequestCoordinatorScope(null);
});

it.each([
  [true, true],
  [true, false],
  [false, true],
  [false, false],
])("keeps independent dashboard resources when summary=%s and QR=%s", async (summaryOk, qrOk) => {
  vi.mocked(apiClient.getDashboardStats).mockResolvedValue(summaryOk
    ? { success: true, data: { totalQRCodes: 12, activeLicensees: 1, manufacturers: 1, totalBatches: 1 } }
    : { success: false, status: 500, error: "unavailable" });
  vi.mocked(apiClient.getQRStats).mockResolvedValue(qrOk
    ? { success: true, data: { total: 12, dormant: 12, allocated: 0, printed: 0, scanned: 0 } }
    : { success: false, status: 500, error: "unavailable" });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: React.ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
  const { result } = renderHook(() => useDashboardStats("tenant-one"), { wrapper });
  await waitFor(() => expect(result.current.data).toBeDefined());
  expect(Boolean(result.current.data?.summary)).toBe(summaryOk);
  expect(Boolean(result.current.data?.qrStats)).toBe(qrOk);
  expect(Boolean(result.current.data?.summaryError)).toBe(!summaryOk);
  expect(Boolean(result.current.data?.qrStatsError)).toBe(!qrOk);
  expect(result.current.error).toBeNull();
  client.clear();
});
