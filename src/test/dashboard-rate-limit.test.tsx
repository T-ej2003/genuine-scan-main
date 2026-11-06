import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";

import Dashboard from "@/pages/Dashboard";
import apiClient from "@/lib/api-client";
import { renderWithQueryClient } from "@/test/render-with-query-client";

vi.mock("@/contexts/AuthContext", () => ({
  useAuth: () => ({
    user: {
      id: "licensee-admin-1",
      role: "licensee_admin",
      licenseeId: "lic-1",
      name: "Brand Admin",
      email: "admin@example.com",
    },
  }),
}));

vi.mock("@/components/layout/DashboardLayout", () => ({
  DashboardLayout: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

vi.mock("@/components/dashboard/RecentActivityCard", () => ({
  RecentActivityCard: ({ logs, emptyMessage }: { logs: Array<{ id: string }>; emptyMessage?: string }) =>
    <div data-testid="recent-log-ids">{logs.length ? logs.map(log => log.id).join(",") : emptyMessage}</div>,
}));

vi.mock("@/lib/mutation-events", () => ({
  onMutationEvent: () => () => undefined,
}));

vi.mock("@/lib/api-client", () => ({
  default: {
    getDashboardStats: vi.fn(),
    getQRStats: vi.fn(),
    getAuditLogs: vi.fn(),
    streamDashboardEvents: vi.fn(() => () => undefined),
  },
}));

describe("Dashboard rate-limit partial state", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(apiClient.getDashboardStats).mockResolvedValue({
      success: true,
      data: {
        totalQRCodes: 100,
        activeLicensees: 1,
        manufacturers: 2,
        totalBatches: 3,
      },
    } as Awaited<ReturnType<typeof apiClient.getDashboardStats>>);
    vi.mocked(apiClient.getQRStats).mockResolvedValue({
      success: true,
      data: {
        dormant: 20,
        allocated: 30,
        printed: 40,
        scanned: 10,
      },
    } as Awaited<ReturnType<typeof apiClient.getQRStats>>);
    vi.mocked(apiClient.getAuditLogs).mockResolvedValue({
      success: false,
      status: 429,
      code: "RATE_LIMITED",
      retryAfterSec: 60,
      error: "Activity is refreshing too often. Please try again in a moment.",
    } as Awaited<ReturnType<typeof apiClient.getAuditLogs>>);
  });

  it("keeps KPI data visible and shows friendly recent activity copy when audit reads are rate-limited", async () => {
    renderWithQueryClient(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>
    );

    expect(await screen.findByText("Unassigned QR labels")).toBeInTheDocument();
    expect(screen.getByText("30 assigned to manufacturers")).toBeInTheDocument();
    const kpiCards = screen.getAllByTestId("dashboard-kpi-card");

    expect(kpiCards).toHaveLength(4);
    for (const card of kpiCards) {
      expect(card).toHaveClass("h-full");
      expect(card).toHaveClass("w-full");
      expect(card).toHaveClass("min-h-[15.5rem]");
    }
    expect(screen.queryByText("Updated just now")).not.toBeInTheDocument();
    expect(screen.queryByText("Refreshes automatically")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /refresh/i })).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText(/Recent activity is temporarily unavailable/i)).toBeInTheDocument();
    });

    expect(screen.queryByText(/429/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Too many audit read requests/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Operations overview unavailable/i)).not.toBeInTheDocument();
  });

  it("decreases unassigned inventory when labels move from DORMANT to ALLOCATED", async () => {
    renderWithQueryClient(<MemoryRouter><Dashboard /></MemoryRouter>);
    const card = (await screen.findByText("Unassigned QR labels")).closest('[data-testid="dashboard-kpi-card"]');
    expect(card).not.toBeNull();
    expect(within(card as HTMLElement).getByText("20")).toBeInTheDocument();

    vi.mocked(apiClient.getQRStats).mockResolvedValue({
      success: true,
      data: { dormant: 10, allocated: 40, printed: 40, scanned: 10 },
    } as Awaited<ReturnType<typeof apiClient.getQRStats>>);
    fireEvent.click(screen.getByRole("button", { name: /refresh/i }));

    await waitFor(() => expect(within(card as HTMLElement).getByText("10")).toBeInTheDocument());
    expect(screen.getByText("40 assigned to manufacturers")).toBeInTheDocument();
  });

  it("preserves loaded same-scope audit history on the first stream delta", async () => {
    let onEvent: ((envelope: unknown) => void) | undefined;
    vi.mocked(apiClient.streamDashboardEvents).mockImplementation((callback) => {
      onEvent = callback as (envelope: unknown) => void;
      return () => undefined;
    });
    vi.mocked(apiClient.getAuditLogs).mockResolvedValue({
      success: true,
      data: { logs: [{ id: "loaded-row", createdAt: "2026-11-06T00:00:00.000Z" }] },
    } as Awaited<ReturnType<typeof apiClient.getAuditLogs>>);
    renderWithQueryClient(<MemoryRouter><Dashboard /></MemoryRouter>);
    await waitFor(() => expect(screen.getByTestId("recent-log-ids")).toHaveTextContent("loaded-row"));
    expect(onEvent).toBeDefined();
    act(() => onEvent?.({ type: "audit.delta", payload: { log: { id: "new-row" } } }));
    expect(screen.getByTestId("recent-log-ids")).toHaveTextContent("new-row,loaded-row");
  });
});
