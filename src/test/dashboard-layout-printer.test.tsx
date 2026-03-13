import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import { DashboardLayout } from "@/components/layout/DashboardLayout";
import apiClient from "@/lib/api-client";

const localStorageState = new Map<string, string>();
const sessionStorageState = new Map<string, string>();

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
    listRegisteredPrinters: vi.fn(),
    getLocalPrintAgentStatus: vi.fn(),
    reportPrinterHeartbeat: vi.fn(),
    getPrinterConnectionStatus: vi.fn(),
    streamPrinterConnectionStatus: vi.fn(),
  },
}));

describe("DashboardLayout printer connection dialog", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorageState.clear();
    sessionStorageState.clear();
    Object.defineProperty(window, "localStorage", {
      configurable: true,
      value: {
        getItem: (key: string) => localStorageState.get(key) ?? null,
        setItem: (key: string, value: string) => {
          localStorageState.set(key, String(value));
        },
        removeItem: (key: string) => {
          localStorageState.delete(key);
        },
        clear: () => {
          localStorageState.clear();
        },
      },
    });
    Object.defineProperty(window, "sessionStorage", {
      configurable: true,
      value: {
        getItem: (key: string) => sessionStorageState.get(key) ?? null,
        setItem: (key: string, value: string) => {
          sessionStorageState.set(key, String(value));
        },
        removeItem: (key: string) => {
          sessionStorageState.delete(key);
        },
        clear: () => {
          sessionStorageState.clear();
        },
      },
    });

    vi.mocked(apiClient.getNotifications).mockResolvedValue({
      success: true,
      data: { notifications: [], unread: 0 },
    } as any);
    vi.mocked(apiClient.streamNotifications).mockImplementation(() => () => undefined);
    vi.mocked(apiClient.streamPrinterConnectionStatus).mockImplementation(() => () => undefined);
    vi.mocked(apiClient.listRegisteredPrinters).mockResolvedValue({
      success: true,
      data: [],
    } as any);
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
    localStorageState.set("manufacturer-printer-onboarding:v1:manufacturer-1", "dismissed");

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

    expect(screen.getByText(/review live printer readiness/i)).toBeInTheDocument();
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
    expect(screen.getByRole("button", { name: /install connector/i })).toBeInTheDocument();
    expect(screen.getByText(/download the Mac or Windows installer for that same device/i)).toBeInTheDocument();
  });

  it("keeps managed network routes visible instead of pushing connector install when a saved route is ready", async () => {
    localStorageState.set("manufacturer-printer-onboarding:v1:manufacturer-1", "dismissed");
    vi.mocked(apiClient.listRegisteredPrinters).mockResolvedValue({
      success: true,
      data: [
        {
          id: "printer-managed-1",
          name: "Factory LAN Printer",
          connectionType: "NETWORK_DIRECT",
          commandLanguage: "ZPL",
          isActive: true,
          isDefault: true,
          registryStatus: {
            state: "READY",
            summary: "Ready",
            detail: "Raw TCP validation succeeded.",
          },
        },
      ],
    } as any);

    render(
      <MemoryRouter>
        <DashboardLayout>
          <div>Dashboard content</div>
        </DashboardLayout>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(vi.mocked(apiClient.listRegisteredPrinters)).toHaveBeenCalled();
    });

    expect(screen.queryByText("Set up printing on this workstation")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /printer ready/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /printer setup/i })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /install connector/i })).not.toBeInTheDocument();
  });

  it("only auto-opens the ready printer dialog once per manufacturer browser session", async () => {
    localStorageState.set("manufacturer-printer-onboarding:v1:manufacturer-1", "dismissed");
    vi.mocked(apiClient.getPrinterConnectionStatus).mockResolvedValue({
      success: true,
      data: {
        connected: true,
        trusted: true,
        compatibilityMode: false,
        compatibilityReason: null,
        eligibleForPrinting: true,
        connectionClass: "TRUSTED",
        stale: false,
        requiredForPrinting: true,
        trustStatus: "TRUSTED",
        trustReason: "Trusted printer ready",
        lastHeartbeatAt: "2026-03-13T19:23:36.000Z",
        ageSeconds: 0,
        registrationId: "printer-managed-1",
        agentId: "agent-1",
        deviceFingerprint: "device-fingerprint",
        mtlsFingerprint: "mtls-fingerprint",
        printerName: "Canon TS4100i series 2",
        printerId: "printer-1",
        selectedPrinterId: "printer-1",
        selectedPrinterName: "Canon TS4100i series 2",
        deviceName: "Factory Mac",
        agentVersion: "2026.3.13",
        capabilitySummary: null,
        printers: [
          {
            printerId: "printer-1",
            printerName: "Canon TS4100i series 2",
            model: "TS4100i",
            connection: "ipps",
            online: true,
            isDefault: true,
            protocols: ["ipp"],
            languages: ["pdf"],
            mediaSizes: ["A4"],
            dpi: 300,
          },
        ],
        calibrationProfile: null,
        error: null,
      },
    } as any);

    const firstMount = render(
      <MemoryRouter>
        <DashboardLayout>
          <div>Dashboard content</div>
        </DashboardLayout>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText("Printing Status")).toBeInTheDocument();
    });

    expect(sessionStorageState.get("manufacturer-printer-dialog-opened:v1:manufacturer-1")).toBe("shown");

    firstMount.unmount();

    render(
      <MemoryRouter>
        <DashboardLayout>
          <div>Dashboard content</div>
        </DashboardLayout>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(vi.mocked(apiClient.getPrinterConnectionStatus)).toHaveBeenCalledTimes(2);
    });

    expect(screen.getByRole("button", { name: /printer ready/i })).toBeInTheDocument();
    expect(screen.queryByText("Printing Status")).not.toBeInTheDocument();
  });
});
