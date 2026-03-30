import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import PrinterSetupPage from "@/pages/PrinterSetup";
import apiClient from "@/lib/api-client";
import { renderWithQueryClient } from "@/test/render-with-query-client";
import { useManufacturerPrinterRuntime } from "@/features/printing/hooks";

vi.mock("@/components/layout/DashboardLayout", () => ({
  DashboardLayout: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

vi.mock("@/hooks/use-toast", () => ({
  useToast: () => ({
    toast: vi.fn(),
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
  });

  it("lets the user finish the missing printer address without the form resetting", async () => {
    renderWithQueryClient(
      <MemoryRouter>
        <PrinterSetupPage />
      </MemoryRouter>
    );

    const hostInput = await screen.findByRole("textbox", { name: /^host$/i });
    fireEvent.change(hostInput, { target: { value: "192.168.1.44" } });

    await waitFor(() => {
      expect(screen.getByRole("textbox", { name: /^host$/i })).toHaveValue("192.168.1.44");
    });

    expect(screen.getByRole("button", { name: /save and print live test label/i })).toBeEnabled();
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
});
