import React from "react";
import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import apiClient from "@/lib/api-client";
import { useBatchOperationsController } from "@/features/batches/useBatchOperationsController";

vi.mock("@/lib/api-client", () => ({ default: { getBatches: vi.fn(), getManufacturers: vi.fn() } }));
afterEach(() => { cleanup(); vi.clearAllMocks(); });

it("requires explicit platform scope and discards a late response from the previous tenant", async () => {
  const row = (tenant: string) => ({ id: tenant, name: "Fixture batch", licenseeId: tenant,
    startCode: "1", endCode: "1", totalCodes: 1, printedAt: null, createdAt: "2026-01-01T00:00:00Z" });
  let finishOld!: (response: Awaited<ReturnType<typeof apiClient.getBatches>>) => void;
  vi.mocked(apiClient.getBatches).mockImplementation(async (options) => {
    if (options?.licenseeId === "tenant-old") return new Promise((resolve) => { finishOld = resolve; });
    return { success: true, data: [row("tenant-current")], meta: { total: 1, limit: 100, offset: 0 } };
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: React.ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
  const params = { role: "super_admin", searchParams: new URLSearchParams(), canAssignManufacturer: false, canDelete: false,
    toast: vi.fn(), progress: { start: vi.fn(), close: vi.fn(), complete: vi.fn().mockResolvedValue(undefined) } };
  const { result, rerender } = renderHook(({ scope }) => useBatchOperationsController({ ...params, selectedLicenseeId: scope }), {
    wrapper, initialProps: { scope: "" },
  });
  await waitFor(() => expect(result.current.error).toContain("Select a brand"));
  expect(apiClient.getBatches).not.toHaveBeenCalled();
  rerender({ scope: "tenant-old" });
  await waitFor(() => expect(finishOld).toBeDefined());
  rerender({ scope: "tenant-current" });
  await waitFor(() => expect(result.current.rows[0]?.id).toBe("tenant-current"));
  await act(async () => { finishOld({ success: true, data: [row("tenant-old")], meta: { total: 1, limit: 100, offset: 0 } }); });
  expect(result.current.rows[0]?.id).toBe("tenant-current");
  expect(apiClient.getBatches).toHaveBeenLastCalledWith({ licenseeId: "tenant-current", limit: 100, offset: 0 });
});
