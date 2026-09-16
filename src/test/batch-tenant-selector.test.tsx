import React from "react";
import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import apiClient from "@/lib/api-client";
import { useBatchOperationsController } from "@/features/batches/useBatchOperationsController";

vi.mock("@/lib/api-client", () => ({ default: { getBatches: vi.fn(), getManufacturers: vi.fn() } }));
afterEach(() => { cleanup(); vi.clearAllMocks(); });

it("clears platform loading and paging state while discarding a late response from the previous brand", async () => {
  const row = (tenant: string) => ({ id: tenant, name: "Fixture batch", licenseeId: tenant,
    startCode: "1", endCode: "1", totalCodes: 1, printedAt: null, createdAt: "2026-01-01T00:00:00Z" });
  let finishOld!: (response: Awaited<ReturnType<typeof apiClient.getBatches>>) => void;
  let finishCurrent!: (response: Awaited<ReturnType<typeof apiClient.getBatches>>) => void;
  vi.mocked(apiClient.getBatches).mockImplementation(async (options) => {
    if (options?.licenseeId === "tenant-old") return new Promise((resolve) => { finishOld = resolve; });
    return new Promise((resolve) => { finishCurrent = resolve; });
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: React.ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
  const params = { role: "super_admin", searchParams: new URLSearchParams(), canAssignManufacturer: false, canDelete: false,
    toast: vi.fn(), progress: { start: vi.fn(), close: vi.fn(), complete: vi.fn().mockResolvedValue(undefined) } };
  const { result, rerender } = renderHook(({ scope }) => useBatchOperationsController({ ...params, selectedLicenseeId: scope }), {
    wrapper, initialProps: { scope: "" },
  });
  await waitFor(() => expect(result.current.error).toContain("Select a brand"));
  expect(result.current.loading).toBe(false);
  expect(result.current.batchOffset).toBe(0);
  expect(result.current.batchTotal).toBe(0);
  expect(apiClient.getBatches).not.toHaveBeenCalled();
  rerender({ scope: "tenant-old" });
  await waitFor(() => expect(finishOld).toBeDefined());
  expect(result.current.loading).toBe(true);
  rerender({ scope: "" });
  await waitFor(() => expect(result.current.error).toContain("Select a brand"));
  expect(result.current.rows).toEqual([]);
  expect(result.current.loading).toBe(false);
  expect(result.current.batchOffset).toBe(0);
  expect(result.current.batchTotal).toBe(0);
  expect(apiClient.getBatches).toHaveBeenCalledTimes(1);
  await act(async () => { finishOld({ success: true, data: [row("tenant-old")], meta: { total: 1, limit: 100, offset: 0 } }); });
  expect(result.current.rows).toEqual([]);
  expect(result.current.error).toContain("Select a brand");
  expect(result.current.loading).toBe(false);
  expect(apiClient.getBatches).toHaveBeenCalledTimes(1);
  rerender({ scope: "tenant-current" });
  await waitFor(() => expect(finishCurrent).toBeDefined());
  expect(result.current.loading).toBe(true);
  await act(async () => { finishCurrent({ success: true, data: [row("tenant-current")], meta: { total: 1, limit: 100, offset: 0 } }); });
  await waitFor(() => expect(result.current.rows[0]?.id).toBe("tenant-current"));
  expect(result.current.loading).toBe(false);
  expect(apiClient.getBatches).toHaveBeenLastCalledWith({ licenseeId: "tenant-current", limit: 100, offset: 0 });
});

it("keeps no-scope state when a previous brand request rejects and preserves licensee-admin loading", async () => {
  let rejectOld!: (error: Error) => void;
  vi.mocked(apiClient.getBatches).mockImplementation(async (options) => {
    if (options?.licenseeId === "tenant-old") return new Promise((_resolve, reject) => { rejectOld = reject; });
    return { success: true, data: [], meta: { total: 0, limit: 100, offset: 0 } };
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: React.ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
  const base = { searchParams: new URLSearchParams(), canAssignManufacturer: false, canDelete: false,
    toast: vi.fn(), progress: { start: vi.fn(), close: vi.fn(), complete: vi.fn().mockResolvedValue(undefined) } };
  const { result, rerender, unmount } = renderHook(({ scope }) => useBatchOperationsController({ ...base, role: "super_admin", selectedLicenseeId: scope }), {
    wrapper, initialProps: { scope: "tenant-old" },
  });
  await waitFor(() => expect(rejectOld).toBeDefined());
  rerender({ scope: "" });
  await waitFor(() => expect(result.current.loading).toBe(false));
  await act(async () => { rejectOld(new Error("late failure")); });
  expect(result.current.rows).toEqual([]);
  expect(result.current.error).toContain("Select a brand");
  expect(result.current.loading).toBe(false);
  unmount();

  const licenseeAdmin = renderHook(() => useBatchOperationsController({ ...base, role: "licensee_admin", userLicenseeId: "tenant-own" }), { wrapper });
  await waitFor(() => expect(apiClient.getBatches).toHaveBeenCalledWith({ licenseeId: "tenant-own", limit: 100, offset: 0 }));
  await waitFor(() => expect(licenseeAdmin.result.current.loading).toBe(false));
});
