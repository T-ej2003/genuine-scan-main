import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

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

    expect(await screen.findByText("QR labels available")).toBeInTheDocument();
    expect(screen.getByText("20 not used yet • 30 assigned")).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText(/Recent activity is temporarily unavailable/i)).toBeInTheDocument();
    });

    expect(screen.queryByText(/429/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Too many audit read requests/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Operations overview unavailable/i)).not.toBeInTheDocument();
  });
});
