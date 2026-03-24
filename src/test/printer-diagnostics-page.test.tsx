import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import PrinterSetupAdvancedPage from "@/features/printing/PrinterSetupAdvancedPage";
import apiClient from "@/lib/api-client";

vi.mock("@/contexts/AuthContext", () => ({
  useAuth: () => ({
    user: { id: "manufacturer-1", role: "manufacturer", name: "Factory User", email: "factory@example.com" },
  }),
}));

vi.mock("@/hooks/use-toast", () => ({
  useToast: () => ({
    toast: vi.fn(),
  }),
}));

vi.mock("@/help/contextual-help", () => ({
  getContextualHelpRoute: () => "/help/manufacturer",
}));

vi.mock("@/components/layout/DashboardLayout", () => ({
  DashboardLayout: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

vi.mock("@/lib/api-client", () => ({
  default: {
    getLocalPrintAgentStatus: vi.fn(),
    reportPrinterHeartbeat: vi.fn(),
    getPrinterConnectionStatus: vi.fn(),
    listRegisteredPrinters: vi.fn(),
    testRegisteredPrinter: vi.fn(),
    deleteRegisteredPrinter: vi.fn(),
    createNetworkPrinter: vi.fn(),
    updateNetworkPrinter: vi.fn(),
    selectLocalPrinter: vi.fn(),
  },
}));

describe("PrinterDiagnostics managed printer controls", () => {
  beforeEach(() => {
    vi.clearAllMocks();

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
        eligibleForPrinting: false,
        connectionClass: "BLOCKED",
        stale: true,
        trustStatus: "UNREGISTERED",
        trustReason: "No trusted printer registration",
        lastHeartbeatAt: null,
        ageSeconds: null,
        printers: [],
        error: "Local print agent is unavailable",
      },
    } as any);
    vi.mocked(apiClient.listRegisteredPrinters).mockResolvedValue({
      success: true,
      data: [
        {
          id: "network-direct-1",
          name: "Line 1 Zebra",
          vendor: "Zebra",
          model: "ZT411",
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
    vi.mocked(apiClient.testRegisteredPrinter).mockResolvedValue({
      success: true,
      data: {
        registryStatus: {
          state: "READY",
          summary: "Ready",
          detail: "Validation succeeded.",
        },
      },
    } as any);
  });

  it("opens the network route dialog from the saved network route card", async () => {
    render(
      <MemoryRouter>
        <PrinterSetupAdvancedPage />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(vi.mocked(apiClient.listRegisteredPrinters)).toHaveBeenCalled();
    });

    fireEvent.click(screen.getByRole("button", { name: /saved network route/i }));

    await waitFor(() => {
      expect(screen.getByText("Network printer routes")).toBeInTheDocument();
    });

    expect(screen.getAllByText("Line 1 Zebra").length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: "Check" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Edit" })).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /remove/i }).length).toBeGreaterThan(0);
  });

  it("lets the network-direct compatibility controls open the create flow", async () => {
    render(
      <MemoryRouter>
        <PrinterSetupAdvancedPage />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(vi.mocked(apiClient.listRegisteredPrinters)).toHaveBeenCalled();
    });

    fireEvent.click(screen.getByRole("button", { name: /register factory printer/i }));

    await waitFor(() => {
      expect(screen.getByText("Create factory label printer")).toBeInTheDocument();
    });

    expect(screen.getByRole("button", { name: /save setup/i })).toBeInTheDocument();
    expect(screen.getByText(/Save a raw TCP endpoint for ZPL, TSPL, EPL, or CPCL dispatch/i)).toBeInTheDocument();
  });

  it("can prefill the network route form from an auto-detected raw TCP printer", async () => {
    vi.mocked(apiClient.getLocalPrintAgentStatus).mockResolvedValue({
      success: true,
      data: {
        connected: true,
        selectedPrinterId: "detected-zebra",
        selectedPrinterName: "Dock Zebra",
        printers: [
          {
            printerId: "detected-zebra",
            printerName: "Dock Zebra",
            model: "ZDesigner ZD421-203dpi ZPL",
            connection: "network",
            online: true,
            isDefault: true,
            protocols: ["raw-9100"],
            languages: ["ZPL"],
            deviceUri: "socket://192.168.1.55:9100",
          },
        ],
      },
    } as any);

    render(
      <MemoryRouter>
        <PrinterSetupAdvancedPage />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(vi.mocked(apiClient.getLocalPrintAgentStatus)).toHaveBeenCalled();
    });

    fireEvent.click(screen.getByRole("button", { name: /saved network route/i }));

    await waitFor(() => {
      expect(screen.getByText("Auto-detected connected printers")).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: /use detected route/i }));

    await waitFor(() => {
      expect(screen.getByText("Create factory label printer")).toBeInTheDocument();
    });

    expect(screen.getByDisplayValue("192.168.1.55")).toBeInTheDocument();
    expect(screen.getByDisplayValue("9100")).toBeInTheDocument();
  });

  it("opens the managed printer dialog from the route query", async () => {
    render(
      <MemoryRouter initialEntries={["/printer-setup/advanced?managedProfiles=open"]}>
        <PrinterSetupAdvancedPage />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(vi.mocked(apiClient.listRegisteredPrinters)).toHaveBeenCalled();
    });

    await waitFor(() => {
      expect(screen.getByText("Network printer routes")).toBeInTheDocument();
    });

    expect(screen.getAllByText("Line 1 Zebra").length).toBeGreaterThan(0);
  });
});
