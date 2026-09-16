import React from "react";
import { cleanup, renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import apiClient from "@/lib/api-client";
import { useBatches } from "@/features/batches/hooks";

vi.mock("@/lib/api-client", () => ({ default: { getBatches: vi.fn() } }));
afterEach(() => { cleanup(); vi.clearAllMocks(); });

it("retrieves the 101st batch without discarding count or sharing a tenant/page cache", async () => {
  vi.mocked(apiClient.getBatches).mockImplementation(async (options) => {
    const offset = options?.offset || 0;
    return { success: true, data: Array.from({ length: offset === 0 ? 100 : 1 }, (_, index) => ({
      id: `${options?.licenseeId}-${offset + index}`, name: "Fixture batch", licenseeId: options?.licenseeId || "",
      startCode: "0001", endCode: "0001", totalCodes: 1, printedAt: null, createdAt: "2026-01-01T00:00:00Z",
    })), meta: { total: 101, limit: 100, offset } };
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: React.ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
  const { result, rerender } = renderHook(({ tenant, offset }) => useBatches(tenant, true, offset), {
    wrapper, initialProps: { tenant: "tenant-one", offset: 0 },
  });
  await waitFor(() => expect(result.current.data?.rows).toHaveLength(100));
  expect(result.current.data?.meta).toEqual({ total: 101, limit: 100, offset: 0 });
  rerender({ tenant: "tenant-one", offset: 100 });
  await waitFor(() => expect(result.current.data?.rows[0]?.id).toBe("tenant-one-100"));
  expect(result.current.data?.rows).toHaveLength(1);
  rerender({ tenant: "tenant-two", offset: 0 });
  await waitFor(() => expect(result.current.data?.rows[0]?.id).toBe("tenant-two-0"));
  expect(apiClient.getBatches).toHaveBeenCalledTimes(3);
});
