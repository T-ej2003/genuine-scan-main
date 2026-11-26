import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";

import Dashboard from "@/pages/Dashboard";
import apiClient from "@/lib/api-client";
import { renderWithQueryClient } from "@/test/render-with-query-client";
import { setRequestCoordinatorScope } from "@/lib/api/request-coordinator";

const mockNavigate = vi.fn();

vi.mock("react-router", async () => {
  const actual = await vi.importActual<typeof import("react-router")>("react-router");
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

vi.mock("@/contexts/AuthContext", () => ({
  useAuth: () => ({
    user: {
      id: "manufacturer-1",
      role: "manufacturer",
      rawRole: "MANUFACTURER_ADMIN",
      licenseeId: "lic-1",
      name: "Factory User",
      email: "factory@example.com",
      linkedLicensees: [
        { id: "lic-1", name: "Acme Brands", prefix: "ACM", orgId: "org-1", isPrimary: true },
        { id: "lic-2", name: "Bravo Health", prefix: "BRV", orgId: "org-1", isPrimary: false },
      ],
    },
  }),
}));

vi.mock("@/components/layout/DashboardLayout", () => ({
  DashboardLayout: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
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

class MockEventSource {
  url: string;
  onerror: ((this: EventSource, ev: Event) => unknown) | null = null;
  onopen: ((this: EventSource, ev: Event) => unknown) | null = null;

  constructor(url: string) {
    this.url = url;
  }

  addEventListener() {}
  close() {}
}

describe("Dashboard manufacturer multi-licensee scope", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockNavigate.mockReset();

    Object.defineProperty(globalThis, "EventSource", {
      configurable: true,
      writable: true,
      value: MockEventSource,
    });

    vi.mocked(apiClient.getDashboardStats).mockResolvedValue({
      success: true,
      data: {
        totalQRCodes: 80,
        activeLicensees: 2,
        manufacturers: 1,
        totalBatches: 12,
        qrStats: {
          total: 80,
          byStatus: { ALLOCATED: 73, PRINTED: 6, BLOCKED: 1 },
          scansToday: 3,
        },
      },
    } as Awaited<ReturnType<typeof apiClient.getDashboardStats>>);

    vi.mocked(apiClient.getAuditLogs).mockResolvedValue({
      success: true,
      data: { logs: [] },
    } as Awaited<ReturnType<typeof apiClient.getAuditLogs>>);
  });

  it("loads unscoped manufacturer stats and shows linked licensees", async () => {
    renderWithQueryClient(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(vi.mocked(apiClient.getDashboardStats)).toHaveBeenCalledWith(undefined);
      expect(vi.mocked(apiClient.getQRStats)).not.toHaveBeenCalled();
    });

    await waitFor(() => expect(vi.mocked(apiClient.getAuditLogs)).toHaveBeenCalledWith({
      limit: 5, licenseeId: "lic-1", purpose: "dashboard-personal-activity",
    }));
    expect(apiClient.getAuditLogs).toHaveBeenCalledTimes(1);
    expect(await screen.findByText("Linked brands")).toBeInTheDocument();
    expect(vi.mocked(apiClient.getDashboardStats)).toHaveBeenCalledTimes(1);
    expect(vi.mocked(apiClient.getQRStats)).not.toHaveBeenCalled();
    expect(screen.getByText("Brand workspaces you can print for")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Allocated QR labels/ })).toHaveTextContent("80");
    expect(screen.getByRole("button", { name: "All (80)" })).toBeInTheDocument();
    expect(screen.queryByText("Unassigned QR labels")).not.toBeInTheDocument();
    expect(screen.queryByText(/waiting for allocation/)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Allocated QR labels/ }));
    expect(mockNavigate).toHaveBeenCalledWith("/batches");
    fireEvent.click(screen.getByRole("button", { name: /Labels printed.*View print history/ }));
    expect(mockNavigate).toHaveBeenCalledWith("/audit-history");
    const scansCard = screen.getByText("Scans today").closest('[data-testid="dashboard-kpi-card"]');
    expect(scansCard).toHaveTextContent("3");
    expect(scansCard).toHaveTextContent("Customer scans recorded today");

    fireEvent.click(screen.getByText("Open scope details"));

    expect(await screen.findByText("Manufacturer workspace details")).toBeInTheDocument();
    expect(screen.getByText("Acme Brands")).toBeInTheDocument();
    expect(screen.getByText("Bravo Health")).toBeInTheDocument();
  });

  it("waits for the initial overview before opening the live stream or loading activity", async () => {
    type StatsResponse = Awaited<ReturnType<typeof apiClient.getDashboardStats>>;
    let resolveStats!: (value: StatsResponse) => void;
    vi.mocked(apiClient.getDashboardStats).mockReturnValueOnce(new Promise((resolve) => { resolveStats = resolve; }));
    renderWithQueryClient(<MemoryRouter><Dashboard /></MemoryRouter>);
    await waitFor(() => expect(apiClient.getDashboardStats).toHaveBeenCalled());
    expect(apiClient.streamDashboardEvents).not.toHaveBeenCalled();
    expect(apiClient.getAuditLogs).not.toHaveBeenCalled();
    resolveStats({ success: true, data: { totalQRCodes: 0, qrStats: { total: 0 } } });
    await waitFor(() => expect(apiClient.streamDashboardEvents).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(apiClient.getAuditLogs).toHaveBeenCalledTimes(1));
  });

  it("reconnects dashboard events after the authenticated request scope changes", async () => {
    const stop = vi.fn();
    vi.mocked(apiClient.streamDashboardEvents).mockReturnValue(stop);
    renderWithQueryClient(<MemoryRouter><Dashboard /></MemoryRouter>);
    await waitFor(() => expect(apiClient.streamDashboardEvents).toHaveBeenCalledTimes(1));

    act(() => setRequestCoordinatorScope({ id: "another-manufacturer" }));
    await waitFor(() => expect(apiClient.streamDashboardEvents).toHaveBeenCalledTimes(2));
    expect(stop).toHaveBeenCalled();
    act(() => setRequestCoordinatorScope(null));
  });

  it("uses the same allocation total on live snapshots and manual refresh, including zero", async () => {
    let onEvent: Parameters<typeof apiClient.streamDashboardEvents>[0] | undefined;
    vi.mocked(apiClient.streamDashboardEvents).mockImplementation((callback) => {
      onEvent = callback;
      return () => undefined;
    });
    renderWithQueryClient(<MemoryRouter><Dashboard /></MemoryRouter>);
    const card = () => screen.getByRole("button", { name: /Allocated QR labels/ });
    await waitFor(() => expect(card()).toHaveTextContent("80"));
    act(() => onEvent?.({ type: "snapshot", payload: {
      summary: { totalQRCodes: 79 },
      qrStats: { total: 79, allocated: 73, printed: 6 },
    } }));
    await waitFor(() => expect(card()).toHaveTextContent("79"));
    expect(screen.getByRole("button", { name: "All (79)" })).toBeInTheDocument();

    vi.mocked(apiClient.getDashboardStats).mockResolvedValue({
      success: true, data: { totalQRCodes: 0, qrStats: { total: 0 } },
    });
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    expect(await screen.findByRole("button", { name: "All (0)" })).toBeInTheDocument();
    expect(card()).toHaveTextContent("0");
    expect(card()).not.toHaveTextContent("Unavailable");
  });

  it("distinguishes a failed activity read from an empty feed", async () => {
    vi.mocked(apiClient.getAuditLogs).mockImplementation(async ({ licenseeId } = {}) => {
      if (licenseeId === "lic-1") throw new Error("Audit read unavailable");
      return { success: true, data: { logs: [] } };
    });
    renderWithQueryClient(<MemoryRouter><Dashboard /></MemoryRouter>);
    expect(await screen.findByText("Recent activity is temporarily unavailable.")).toBeInTheDocument();
    expect(screen.queryByText(/No recent activity yet/)).not.toBeInTheDocument();
  });

  it("shows a failure when the request controller returns a cached empty feed after a 503", async () => {
    vi.mocked(apiClient.getAuditLogs).mockResolvedValue({
      success: true, degraded: true, data: { logs: [] },
    });
    renderWithQueryClient(<MemoryRouter><Dashboard /></MemoryRouter>);
    expect(await screen.findByText("Recent activity is temporarily unavailable.")).toBeInTheDocument();
    expect(screen.queryByText(/No recent activity yet/)).not.toBeInTheDocument();
  });

  it("re-reads personal activity on a live activity signal", async () => {
    let onEvent: Parameters<typeof apiClient.streamDashboardEvents>[0] | undefined;
    vi.mocked(apiClient.streamDashboardEvents).mockImplementation((callback) => {
      onEvent = callback;
      return () => undefined;
    });
    renderWithQueryClient(<MemoryRouter><Dashboard /></MemoryRouter>);
    expect(await screen.findByText(/No recent activity yet/)).toBeInTheDocument();
    act(() => onEvent?.({ type: "audit.delta", payload: {
      log: { id: "cross-actor", action: "CREATE_BATCH", createdAt: new Date().toISOString() },
    } }));
    expect(screen.queryByText("Batch created")).not.toBeInTheDocument();
    vi.mocked(apiClient.getAuditLogs).mockResolvedValue({
      success: true,
      data: { logs: [{ id: "print", action: "CONFIRM_PRINT", createdAt: new Date().toISOString() }] },
    });
    act(() => onEvent?.({ type: "summary.refresh", payload: { reason: "personal_activity" } }));
    expect(await screen.findByText("Print confirmed")).toBeInTheDocument();
    expect(apiClient.getDashboardStats).toHaveBeenCalledTimes(1);
  });
});
