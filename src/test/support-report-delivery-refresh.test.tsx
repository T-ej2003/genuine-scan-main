import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { useSupportIssueReports } from "@/features/support/hooks";
import apiClient from "@/lib/api-client";

vi.mock("@/lib/api-client", () => ({ default: { getSupportIssueReports: vi.fn() } }));

describe("support response delivery refresh", () => {
  afterEach(() => vi.restoreAllMocks());

  it.each(["SENT", "FAILED"])("refreshes pending delivery and stops polling at %s", async (status) => {
    vi.mocked(apiClient.getSupportIssueReports).mockReset();
    const report = { id: "report-1", title: "Printer issue", status: "RESPONDED", createdAt: "2026-03-01T00:00:00Z" };
    vi.mocked(apiClient.getSupportIssueReports)
      .mockResolvedValueOnce({ success: true, data: { reports: [{ ...report, emailDeliveryStatus: "PENDING" }], total: 1 } } as Awaited<ReturnType<typeof apiClient.getSupportIssueReports>>)
      .mockResolvedValueOnce({ success: true, data: { reports: [{ ...report, emailDeliveryStatus: status }], total: 1 } } as Awaited<ReturnType<typeof apiClient.getSupportIssueReports>>);

    const realSetInterval = window.setInterval.bind(window);
    const interval = vi.spyOn(window, "setInterval");
    const clear = vi.spyOn(window, "clearInterval");
    let refresh: (() => void) | undefined;
    let refreshTimer: number | undefined;
    interval.mockImplementation((callback, delay) => {
      const id = realSetInterval(callback, delay);
      if (delay === 60_000) { refresh = callback as () => void; refreshTimer = id; }
      return id;
    });

    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const { result, unmount } = renderHook(() => useSupportIssueReports(), {
      wrapper: ({ children }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>,
    });
    await waitFor(() => expect(result.current.data?.reports[0].emailDeliveryStatus).toBe("PENDING"));
    await waitFor(() => expect(refresh).toBeDefined());
    await act(async () => { refresh?.(); });
    await waitFor(() => expect(result.current.data?.reports[0].emailDeliveryStatus).toBe(status));
    expect(clear).toHaveBeenCalledWith(refreshTimer);
    expect(apiClient.getSupportIssueReports).toHaveBeenCalledTimes(2);
    unmount();
  });
});
