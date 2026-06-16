import React from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import apiClient from "@/lib/api-client";
import { clearActivePrintSession, updateActivePrintSession } from "@/lib/active-print-session";
import { useDashboardStats } from "@/features/dashboard/hooks";
import { useDashboardNotifications, useOperationalAttentionQueue } from "@/features/layout/hooks";
import { useManufacturerPrinterRuntime } from "@/features/printing/hooks";

vi.mock("@/lib/api-client", () => ({
  default: {
    getDashboardStats: vi.fn(),
    getQRStats: vi.fn(),
    getNotifications: vi.fn(),
    getOperationalAttentionQueue: vi.fn(),
    getPrinterConnectionStatus: vi.fn(),
    getLocalPrintAgentStatus: vi.fn(),
    listRegisteredPrinters: vi.fn(),
  },
}));

const renderWithClient = (ui: React.ReactElement) => {
  const client = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
    },
  });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
};

function AutoReadProbe() {
  useDashboardStats();
  useDashboardNotifications(true);
  useOperationalAttentionQueue(true);
  useManufacturerPrinterRuntime(true, true);
  return <div>probe ready</div>;
}

describe("active print session read suppression", () => {
  afterEach(() => {
    clearActivePrintSession();
    vi.clearAllMocks();
  });

  it("does not auto-fetch nonessential protected reads during an active print modal", () => {
    updateActivePrintSession({
      active: true,
      jobId: "job-live",
      modalOpen: true,
      terminal: false,
    });

    renderWithClient(<AutoReadProbe />);

    expect(screen.getByText("probe ready")).toBeInTheDocument();
    expect(apiClient.getDashboardStats).not.toHaveBeenCalled();
    expect(apiClient.getQRStats).not.toHaveBeenCalled();
    expect(apiClient.getNotifications).not.toHaveBeenCalled();
    expect(apiClient.getOperationalAttentionQueue).not.toHaveBeenCalled();
    expect(apiClient.getPrinterConnectionStatus).not.toHaveBeenCalled();
    expect(apiClient.getLocalPrintAgentStatus).not.toHaveBeenCalled();
    expect(apiClient.listRegisteredPrinters).not.toHaveBeenCalled();
  });
});
