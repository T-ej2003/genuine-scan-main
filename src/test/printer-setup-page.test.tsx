import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import PrinterSetupPage from "@/pages/PrinterSetup";
import apiClient from "@/lib/api-client";
import { renderWithQueryClient } from "@/test/render-with-query-client";
import { useManufacturerPrinterRuntime } from "@/features/printing/hooks";

const toastMock = vi.hoisted(() => vi.fn());

vi.mock("@/components/layout/DashboardLayout", () => ({
  DashboardLayout: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

vi.mock("@/hooks/use-toast", () => ({
  useToast: () => ({
    toast: toastMock,
  }),
}));

vi.mock("@/features/printing/hooks", () => ({
  useManufacturerPrinterRuntime: vi.fn(),
}));

vi.mock("@/lib/api-client", () => ({
  default: {
    getLocalPrintAgentStatus: vi.fn(),
    getLatestConnectorRelease: vi.fn(),
    createNetworkPrinter: vi.fn(),
    discoverRegisteredPrinter: vi.fn(),
    testPrinterLabel: vi.fn(),
    selectLocalPrinter: vi.fn(),
  },
}));

describe("PrinterSetupPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();

    vi.mocked(useManufacturerPrinterRuntime).mockReturnValue({
      data: {
        registeredPrinters: [],
        remoteStatus: {
          connected: true,
          eligibleForPrinting: true,
          agentVersion: "2026.3.12",
        },
      },
      refetch: vi.fn().mockResolvedValue(undefined),
    } as any);

    vi.mocked(apiClient.getLatestConnectorRelease).mockResolvedValue({
      success: true,
      data: {
        latestVersion: "2026.3.12",
        release: {
          platforms: {
            windows: { version: "2026.3.12" },
          },
        },
      },
    } as any);

    vi.mocked(apiClient.getLocalPrintAgentStatus).mockResolvedValue({
      success: true,
      data: {
        printers: [
          {
            printerId: "printer-1",
            printerName: "Canon TS4100i series 2",
            model: "TS4100i",
            connection: "ipps",
            online: true,
            isDefault: true,
            protocols: ["IPP"],
            languages: ["PDF"],
            mediaSizes: ["A4"],
          },
        ],
      },
    } as any);
    vi.mocked(apiClient.selectLocalPrinter).mockResolvedValue({ success: true, data: {} } as any);
  });

  it("lets the user finish the missing printer address without the form resetting", async () => {
    renderWithQueryClient(
      <MemoryRouter>
        <PrinterSetupPage />
      </MemoryRouter>
    );

    const hostInput = await screen.findByRole("textbox", { name: /^printer address$/i });
    fireEvent.change(hostInput, { target: { value: "192.168.1.44" } });

    await waitFor(() => {
      expect(screen.getByRole("textbox", { name: /^printer address$/i })).toHaveValue("192.168.1.44");
    });

    expect(screen.getByRole("button", { name: /save printer and print test label/i })).toBeEnabled();
  });

  it("shows inline help for manual printer fields", async () => {
    renderWithQueryClient(
      <MemoryRouter>
        <PrinterSetupPage />
      </MemoryRouter>
    );

    const helpButton = await screen.findByRole("button", { name: /how to find host/i });
    fireEvent.click(helpButton);

    expect(
      await screen.findByText(/this is the printer's real network address/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/replace it with the real printer ip or host name/i),
    ).toBeInTheDocument();
  });

  it("shows connector update and USB Zebra alternative for a stale WiFi queue", async () => {
    vi.mocked(useManufacturerPrinterRuntime).mockReturnValue({
      data: {
        registeredPrinters: [],
        remoteStatus: {
          connected: false,
          eligibleForPrinting: false,
          connectorUpdateRequired: true,
          agentVersion: "2026.5.23",
          buildVersion: "2026.5.23",
        },
      },
      refetch: vi.fn().mockResolvedValue(undefined),
    } as any);
    vi.mocked(apiClient.getLatestConnectorRelease).mockResolvedValue({
      success: true,
      data: {
        latestVersion: "2026.6.13",
        release: { platforms: { windows: { version: "2026.6.13" } } },
      },
    } as any);
    vi.mocked(apiClient.getLocalPrintAgentStatus).mockResolvedValue({
      success: true,
      data: {
        printers: [
          {
            printerId: "MSCQR Zebra ZT410 WiFi",
            printerName: "MSCQR Zebra ZT410 WiFi",
            model: "ZDesigner ZT410-300dpi ZPL",
            connection: "network",
            online: false,
            isDefault: true,
            languages: ["ZPL"],
            windowsPortName: "MSCQR-ZT410-WIFI-9100",
            windowsPortHost: "10.45.144.9",
            windowsPortNumber: 9100,
            queueStatus: "Error",
            queueHasErrors: true,
            stuckJobCount: 1,
          },
          {
            printerId: "ZDesigner ZT410-300dpi ZPL",
            printerName: "ZDesigner ZT410-300dpi ZPL",
            model: "ZDesigner ZT410-300dpi ZPL",
            connection: "usb",
            online: true,
            portName: "USB001",
            languages: ["ZPL"],
            usbAvailable: true,
          },
        ],
      },
    } as any);

    renderWithQueryClient(
      <MemoryRouter>
        <PrinterSetupPage />
      </MemoryRouter>
    );

    expect(await screen.findByText("Connector update required")).toBeInTheDocument();
    expect(screen.getByText(/Detected: 2026.5.23/i)).toBeInTheDocument();
    expect(await screen.findByText("Network Zebra queue is broken")).toBeInTheDocument();
    expect(screen.getByText(/10.45.144.9:9100/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Use USB Zebra" }));
    await waitFor(() => {
      expect(apiClient.selectLocalPrinter).toHaveBeenCalledWith("ZDesigner ZT410-300dpi ZPL");
    });
  });

  it("shows a queued setup test label as pending connector confirmation", async () => {
    vi.mocked(useManufacturerPrinterRuntime).mockReturnValue({
      data: {
        registeredPrinters: [
          {
            id: "printer-profile-zebra",
            name: "ZDesigner ZT410-300dpi ZPL",
            deliveryMode: "DIRECT",
            commandLanguage: "ZPL",
            isDefault: true,
            registryStatus: { state: "READY", summary: "Ready", detail: "Printer route saved." },
          },
        ],
        remoteStatus: {
          connected: true,
          eligibleForPrinting: true,
          agentVersion: "2026.6.16",
        },
      },
      refetch: vi.fn().mockResolvedValue(undefined),
    } as any);
    vi.mocked(apiClient.testPrinterLabel).mockResolvedValue({
      success: true,
      data: {
        outcome: "queued",
        message: "Live setup test label queued. Keep MSCQR Connector 2026.6.16 running until it prints and confirms.",
      },
    } as any);

    renderWithQueryClient(
      <MemoryRouter>
        <PrinterSetupPage />
      </MemoryRouter>
    );

    fireEvent.click(await screen.findByRole("button", { name: /print live test label/i }));

    await waitFor(() => {
      expect(apiClient.testPrinterLabel).toHaveBeenCalledWith("printer-profile-zebra");
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({
          title: "Live test label queued",
          description: expect.stringMatching(/prints and confirms/i),
          variant: "default",
        })
      );
    });
  });
});
