import React from "react";
import { cleanup, renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";
import apiClient from "@/lib/api-client";
import { useDashboardAuditLogs } from "@/features/dashboard/hooks";

vi.mock("@/lib/api-client", () => ({ default: { getAuditLogs: vi.fn() } }));
vi.mock("@/lib/active-print-session", () => ({ useActivePrintSessionSuppression: () => false }));
afterEach(() => { cleanup(); vi.clearAllMocks(); });

const wrapper = () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return ({ children }: { children: React.ReactNode }) =>
    <QueryClientProvider client={client}>{children}</QueryClientProvider>;
};

describe("dashboard audit tenant contract", () => {
  it("does not issue an unscoped request, even on explicit refetch", async () => {
    const { result } = renderHook(() => useDashboardAuditLogs(true), { wrapper: wrapper() });
    const response = await result.current.refetch();
    expect(response.error?.message).toContain("Select a brand");
    expect(apiClient.getAuditLogs).not.toHaveBeenCalled();
  });

  it("binds purpose and tenant and isolates cache entries when scope changes", async () => {
    vi.mocked(apiClient.getAuditLogs).mockResolvedValue({ success: true, data: [] });
    const { result, rerender } = renderHook(({ tenant }) => useDashboardAuditLogs(true, 5, tenant), {
      wrapper: wrapper(), initialProps: { tenant: "tenant-one" },
    });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(apiClient.getAuditLogs).toHaveBeenLastCalledWith({ limit: 5, licenseeId: "tenant-one", purpose: "dashboard-activity-review" });
    rerender({ tenant: "tenant-two" });
    await waitFor(() => expect(apiClient.getAuditLogs).toHaveBeenLastCalledWith({ limit: 5, licenseeId: "tenant-two", purpose: "dashboard-activity-review" }));
  });
});
