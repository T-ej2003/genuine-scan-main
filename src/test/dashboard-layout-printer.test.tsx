import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import { DashboardLayout } from "@/components/layout/DashboardLayout";
import apiClient from "@/lib/api-client";

const storage = new Map<string, string>();

vi.mock("@/contexts/AuthContext", () => ({
  useAuth: () => ({
    user: { id: "manufacturer-1", role: "manufacturer", name: "Factory User", email: "factory@example.com" },
    logout: vi.fn(),
  }),
}));

vi.mock("@/hooks/use-toast", () => ({
  useToast: () => ({
    toast: vi.fn(),
  }),
}));

vi.mock("@/help/contextual-help", () => ({
  getContextualHelpRoute: () => "/help/support",
}));

vi.mock("@/components/support/SupportIssueLauncher", () => ({
  SupportIssueLauncher: () => <div data-testid="support-launcher" />,
}));

vi.mock("@/lib/support-diagnostics", () => ({
  buildSupportDiagnosticsPayload: () => ({}),
  captureSupportScreenshot: vi.fn().mockResolvedValue(null),
}));

vi.mock("@/lib/api-client", () => ({
  default: {
    getNotifications: vi.fn(),
    streamNotifications: vi.fn(),
    getLocalPrintAgentStatus: vi.fn(),
    reportPrinterHeartbeat: vi.fn(),
    getPrinterConnectionStatus: vi.fn(),
    streamPrinterConnectionStatus: vi.fn(),
  },
}));

describe("DashboardLayout printer connection dialog", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    storage.clear();
    Object.defineProperty(window, "localStorage", {
      configurable: true,
      value: {
        getItem: (key: string) => storage.get(key) ?? null,
        setItem: (key: string, value: string) => {
          storage.set(key, String(value));
        },
        removeItem: (key: string) => {
          storage.delete(key);
        },
        clear: () => {
          storage.clear();
        },
      },
    });

    vi.mocked(apiClient.getNotifications).mockResolvedValue({
      success: true,
      data: { notifications: [], unread: 0 },
    } as any);
    vi.mocked(apiClient.streamNotifications).mockImplementation(() => () => undefined);
    vi.mocked(apiClient.streamPrinterConnectionStatus).mockImplementation(() => () => undefined);
    vi.mocked(apiClient.getLocalPrintAgentStatus).mockResolvedValue({
      success: false,
      error: "Local print agent is unavailable",
    } as any);
    vi.mocked(apiClient.reportPrinterHeartbeat).mockResolvedValue({ success: true } as any);
    vi.mocked(apiClient.getPrinterConnectionStatus).mockResolvedValue({
      success: true,
      data: {
        connected: false,
        trusted: false,
        compatibilityMode: false,
        compatibilityReason: null,
        eligibleForPrinting: false,
        connectionClass: "BLOCKED",
        stale: true,
        requiredForPrinting: true,
        trustStatus: "UNREGISTERED",
        trustReason: "No trusted printer registration",
        lastHeartbeatAt: null,
        ageSeconds: null,
        registrationId: null,
        agentId: null,
        deviceFingerprint: null,
        mtlsFingerprint: null,
        printerName: null,
        printerId: null,
        selectedPrinterId: null,
        selectedPrinterName: null,
        deviceName: null,
        agentVersion: null,
        capabilitySummary: null,
        printers: [],
        calibrationProfile: null,
        error: "Local print agent is unavailable",
      },
    } as any);
  });

  it("opens the printer dialog even when the local agent is unreachable", async () => {
    storage.set("manufacturer-printer-onboarding:v1:manufacturer-1", "dismissed");

    render(
      <MemoryRouter>
        <DashboardLayout>
          <div>Dashboard content</div>
        </DashboardLayout>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(vi.mocked(apiClient.getLocalPrintAgentStatus)).toHaveBeenCalled();
    });

    fireEvent.click(screen.getByRole("button", { name: /connector offline/i }));

    await waitFor(() => {
      expect(screen.getByText("Printing Status")).toBeInTheDocument();
    });

    expect(screen.getByText(/switch between connected printers when needed/i)).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Refresh status" }).length).toBeGreaterThan(0);
  });

  it("shows first-run workstation printer onboarding for manufacturers", async () => {
    render(
      <MemoryRouter>
        <DashboardLayout>
          <div>Dashboard content</div>
        </DashboardLayout>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(vi.mocked(apiClient.getLocalPrintAgentStatus)).toHaveBeenCalled();
    });

    expect(screen.getByText("Set up printing on this workstation")).toBeInTheDocument();
    expect(screen.getByText(/The browser cannot install printers, drivers, or native apps by itself/i)).toBeInTheDocument();
    expect(screen.getByText(/If the OS can see the printer, MSCQR will detect it and it will appear automatically/i)).toBeInTheDocument();
    expect(screen.getByText(/Install the MSCQR Workstation Connector on that same device/i)).toBeInTheDocument();
  });
});
