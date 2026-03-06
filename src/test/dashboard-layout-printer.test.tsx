import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import { DashboardLayout } from "@/components/layout/DashboardLayout";
import apiClient from "@/lib/api-client";

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

    fireEvent.click(screen.getByRole("button", { name: /agent offline/i }));

    await waitFor(() => {
      expect(screen.getByText("Printer Connection Center")).toBeInTheDocument();
    });

    expect(screen.getByText(/The browser could not reach the workstation print agent/i)).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Try again (Refresh)" }).length).toBeGreaterThan(0);
  });
});
