import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { useSupportIssueReports } from "@/features/support/hooks";
import apiClient from "@/lib/api-client";
import { setRequestCoordinatorScope } from "@/lib/api/request-coordinator";

vi.mock("@/lib/api-client", () => ({ default: { getSupportIssueReports: vi.fn() } }));

describe("support response delivery refresh", () => {
  afterEach(() => { setRequestCoordinatorScope(null); vi.restoreAllMocks(); });

  it.each([
    ["SENT", false], ["UNKNOWN", false], ["DRY_RUN", false], ["SENT", true],
  ])("refreshes pending delivery and stops polling at %s after interruption=%s", async (status, interrupted) => {
    vi.mocked(apiClient.getSupportIssueReports).mockReset();
    const report = { id: "report-1", title: "Printer issue", status: "RESPONDED", createdAt: "2026-03-01T00:00:00Z", respondedAt: new Date().toISOString() };
    const reportsRead = vi.mocked(apiClient.getSupportIssueReports).mockResolvedValueOnce({ success: true, data: {
      reports: [{ ...report, emailDeliveryStatus: "PENDING" }], total: 1,
    } } as Awaited<ReturnType<typeof apiClient.getSupportIssueReports>>);
    if (interrupted) reportsRead.mockRejectedValueOnce(new Error("Network unavailable"));
    reportsRead.mockResolvedValueOnce({ success: true, data: {
      reports: [{ ...report, emailDeliveryStatus: status }], total: 1,
    } } as Awaited<ReturnType<typeof apiClient.getSupportIssueReports>>);

    const realSetInterval = window.setInterval.bind(window);
    const interval = vi.spyOn(window, "setInterval");
    const clear = vi.spyOn(window, "clearInterval");
    let refresh: (() => void) | undefined;
    let refreshTimer: number | undefined;
    interval.mockImplementation((callback, delay) => {
      const id = realSetInterval(callback, delay);
      if (delay === 120_000) { refresh = callback as () => void; refreshTimer = id; }
      return id;
    });

    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const { result, unmount } = renderHook(() => useSupportIssueReports(), {
      wrapper: ({ children }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>,
    });
    await waitFor(() => expect(result.current.data?.reports[0].emailDeliveryStatus).toBe("PENDING"));
    await waitFor(() => expect(refresh).toBeDefined());
    await act(async () => { refresh?.(); });
    if (interrupted) {
      await waitFor(() => expect(reportsRead).toHaveBeenCalledTimes(2));
      await waitFor(() => expect(result.current.isFetching).toBe(false));
      expect(result.current.data?.reports[0].emailDeliveryStatus).toBe("PENDING");
      await act(async () => { refresh?.(); });
    }
    await waitFor(() => expect(result.current.data?.reports[0].emailDeliveryStatus).toBe(status));
    expect(clear).toHaveBeenCalledWith(refreshTimer);
    expect(apiClient.getSupportIssueReports).toHaveBeenCalledTimes(interrupted ? 3 : 2);
    unmount();
  });

  it("keeps refreshing a failed delivery until a worker retry records SENT", async () => {
    const report = { id: "report-1", title: "Printer issue", status: "RESPONDED", createdAt: "2026-03-01T00:00:00Z", respondedAt: new Date().toISOString() };
    vi.mocked(apiClient.getSupportIssueReports).mockReset();
    for (const emailDeliveryStatus of ["PENDING", "FAILED", "SENT"]) {
      vi.mocked(apiClient.getSupportIssueReports).mockResolvedValueOnce({ success: true, data: {
        reports: [{ ...report, emailDeliveryStatus }], total: 1,
      } } as Awaited<ReturnType<typeof apiClient.getSupportIssueReports>>);
    }
    const realSetInterval = window.setInterval.bind(window);
    const realClearInterval = window.clearInterval.bind(window);
    const activeRefreshes = new Map<number, () => void>();
    let refresh: (() => void) | undefined;
    vi.spyOn(window, "setInterval").mockImplementation((callback, delay) => {
      const id = realSetInterval(callback, delay);
      if (delay === 120_000) activeRefreshes.set(id, callback as () => void);
      return id;
    });
    vi.spyOn(window, "clearInterval").mockImplementation((id) => {
      if (id !== undefined) activeRefreshes.delete(id);
      return realClearInterval(id);
    });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const { result, unmount } = renderHook(() => useSupportIssueReports(), {
      wrapper: ({ children }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>,
    });
    await waitFor(() => expect(result.current.data?.reports[0].emailDeliveryStatus).toBe("PENDING"));
    await waitFor(() => expect(activeRefreshes.size).toBeGreaterThan(0));
    refresh = [...activeRefreshes.values()][0];
    await act(async () => { refresh?.(); });
    await waitFor(() => expect(result.current.data?.reports[0].emailDeliveryStatus).toBe("FAILED"));
    await waitFor(() => expect(activeRefreshes.size).toBeGreaterThan(0));
    refresh = [...activeRefreshes.values()][0];
    await act(async () => { refresh?.(); });
    await waitFor(() => expect(result.current.data?.reports[0].emailDeliveryStatus).toBe("SENT"));
    await waitFor(() => expect(activeRefreshes.size).toBe(0));
    expect(apiClient.getSupportIssueReports).toHaveBeenCalledTimes(3);
    unmount();
  });

  it.each([[31, true], [121, false]])("bounds FAILED delivery polling at age %i minutes", async (ageMinutes, shouldPoll) => {
    vi.mocked(apiClient.getSupportIssueReports).mockReset().mockResolvedValue({ success: true, data: { reports: [{
      id: "report-2", title: "Old issue", status: "RESPONDED", createdAt: "2026-03-01T00:00:00Z",
      respondedAt: new Date(Date.now() - ageMinutes * 60_000).toISOString(), emailDeliveryStatus: "FAILED",
    }], total: 1 } } as Awaited<ReturnType<typeof apiClient.getSupportIssueReports>>);
    const interval = vi.spyOn(window, "setInterval");
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const { result, unmount } = renderHook(() => useSupportIssueReports(), {
      wrapper: ({ children }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>,
    });
    await waitFor(() => expect(result.current.data?.reports[0].emailDeliveryStatus).toBe("FAILED"));
    if (shouldPoll) await waitFor(() => expect(interval.mock.calls.some(([, delay]) => delay === 120_000)).toBe(true));
    else expect(interval.mock.calls.some(([, delay]) => delay === 120_000)).toBe(false);
    unmount();
  });

  it("does not reuse one actor's report cache after authentication scope changes", async () => {
    const report = { title: "Printer issue", status: "RESPONDED", createdAt: "2026-03-01T00:00:00Z" };
    vi.mocked(apiClient.getSupportIssueReports).mockReset()
      .mockResolvedValueOnce({ success: true, data: { reports: [{ ...report, id: "actor-a-report", emailDeliveryStatus: "SENT" }], total: 1 } } as Awaited<ReturnType<typeof apiClient.getSupportIssueReports>>)
      .mockResolvedValueOnce({ success: true, data: { reports: [{ ...report, id: "actor-b-report", emailDeliveryStatus: "SENT" }], total: 1 } } as Awaited<ReturnType<typeof apiClient.getSupportIssueReports>>);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 60_000 } } });
    setRequestCoordinatorScope({ id: "actor-a", role: "super_admin" });
    const { result, rerender, unmount } = renderHook(() => useSupportIssueReports(), {
      wrapper: ({ children }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>,
    });
    await waitFor(() => expect(result.current.data?.reports[0].id).toBe("actor-a-report"));
    setRequestCoordinatorScope({ id: "actor-b", role: "super_admin" });
    rerender();
    expect(result.current.data?.reports[0]?.id).not.toBe("actor-a-report");
    await waitFor(() => expect(result.current.data?.reports[0].id).toBe("actor-b-report"));
    expect(apiClient.getSupportIssueReports).toHaveBeenCalledTimes(2);
    unmount();
  });
});
