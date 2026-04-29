import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import Dashboard from "@/pages/Dashboard";
import apiClient from "@/lib/api-client";
import { renderWithQueryClient } from "@/test/render-with-query-client";

const mockNavigate = vi.fn();

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
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
  DashboardLayout: ({ children }: any) => <div>{children}</div>,
}));

vi.mock("@/lib/mutation-events", () => ({
  onMutationEvent: () => () => undefined,
}));

vi.mock("@/lib/api-client", () => ({
  default: {
    getDashboardStats: vi.fn(),
    getQRStats: vi.fn(),
    getAuditLogs: vi.fn(),
  },
}));

class MockEventSource {
  url: string;
  onerror: ((this: EventSource, ev: Event) => any) | null = null;
  onopen: ((this: EventSource, ev: Event) => any) | null = null;

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
        totalQRCodes: 2400,
        activeLicensees: 2,
        manufacturers: 1,
        totalBatches: 12,
      },
    } as any);

    vi.mocked(apiClient.getQRStats).mockResolvedValue({
      success: true,
      data: {
        byStatus: {
          DORMANT: 20,
          ACTIVE: 100,
          ALLOCATED: 700,
          ACTIVATED: 200,
          PRINTED: 600,
          REDEEMED: 80,
          BLOCKED: 4,
        },
      },
    } as any);

    vi.mocked(apiClient.getAuditLogs).mockResolvedValue({
      success: true,
      data: { logs: [] },
    } as any);
  });

  it("loads unscoped manufacturer stats and shows linked licensees", async () => {
    renderWithQueryClient(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(vi.mocked(apiClient.getDashboardStats)).toHaveBeenCalledWith(undefined);
      expect(vi.mocked(apiClient.getQRStats)).toHaveBeenCalledWith(undefined);
    });

    expect(vi.mocked(apiClient.getAuditLogs)).not.toHaveBeenCalled();
    expect(await screen.findByText("Linked brands")).toBeInTheDocument();
    expect(screen.getByText("Brand workspaces you can print for")).toBeInTheDocument();
    expect(screen.getByText("120 not used yet • 900 assigned")).toBeInTheDocument();

    fireEvent.click(screen.getByText("Open scope details"));

    expect(await screen.findByText("Manufacturer workspace details")).toBeInTheDocument();
    expect(screen.getByText("Acme Brands")).toBeInTheDocument();
    expect(screen.getByText("Bravo Health")).toBeInTheDocument();
  });
});
