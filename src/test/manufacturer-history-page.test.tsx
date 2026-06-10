import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import AuditLogs from "@/pages/AuditLogs";
import apiClient from "@/lib/api-client";

vi.mock("@/contexts/AuthContext", () => ({
  useAuth: () => ({
    user: {
      id: "manufacturer-user-1",
      role: "manufacturer",
      licenseeId: "lic-1",
      name: "Factory Operator",
      email: "factory@example.com",
    },
  }),
}));

vi.mock("@/components/layout/DashboardLayout", () => ({
  DashboardLayout: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

vi.mock("@/hooks/use-toast", () => ({
  useToast: () => ({ toast: vi.fn() }),
}));

vi.mock("@/lib/mutation-events", () => ({
  onMutationEvent: () => () => undefined,
}));

vi.mock("@/lib/api-client", () => ({
  default: {
    getAuditLogs: vi.fn(),
    listPrintJobs: vi.fn(),
    streamAuditLogs: vi.fn(() => () => undefined),
    getFraudReports: vi.fn(),
    getLicensees: vi.fn(),
    respondToFraudReport: vi.fn(),
  },
}));

const renderHistory = () =>
  render(
    <MemoryRouter>
      <AuditLogs />
    </MemoryRouter>
  );

const auditRows = [
  {
    id: "audit-1",
    action: "LOCAL_AGENT_PRINT_ITEM_ACKED",
    entityType: "PrintJob",
    createdAt: "2026-06-08T12:00:00.000Z",
    details: { printerName: "Zebra ZT410", batchName: "Spring Denim" },
    user: { name: "Factory Operator", email: "factory@example.com" },
  },
  {
    id: "audit-2",
    action: "LOCAL_AGENT_PRINT_ITEM_CONFIRMED",
    entityType: "PrintJob",
    createdAt: "2026-06-08T12:02:00.000Z",
    details: { printerName: "Zebra ZT410", batchName: "Spring Denim" },
    user: { name: "Factory Operator", email: "factory@example.com" },
  },
  {
    id: "audit-3",
    action: "INTERNAL_RENDER_TOKEN_ROTATED",
    entityType: "Internal",
    createdAt: "2026-06-08T12:03:00.000Z",
    details: { token: "secret-token", renderUrl: "https://secret.example/render" },
    user: null,
  },
];

const printJobRows = [
  {
    id: "550e8400-e29b-41d4-a716-446655440000",
    jobNumber: "PRINT-42",
    status: "CONFIRMED",
    printMode: "LOCAL_AGENT",
    quantity: 12,
    itemCount: 12,
    confirmedAt: "2026-06-08T12:10:00.000Z",
    batch: { id: "batch-1", name: "Spring Denim" },
    printer: { id: "printer-1", name: "Zebra ZT410", connectionType: "LOCAL_AGENT" },
    session: { confirmedItems: 12, remainingToPrint: 0 },
    createdByUser: { name: "Factory Operator", email: "factory@example.com" },
  },
];

describe("manufacturer History page", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(apiClient.getAuditLogs).mockResolvedValue({ success: true, data: { logs: auditRows } } as any);
    vi.mocked(apiClient.listPrintJobs).mockResolvedValue({ success: true, data: printJobRows } as any);
  });

  it("renders meaningful manufacturer activity and print history without raw internal names", async () => {
    renderHistory();

    expect(await screen.findByText("Print history")).toBeInTheDocument();
    expect(screen.getByText("Spring Denim")).toBeInTheDocument();
    expect(screen.getByText("PRINT-42")).toBeInTheDocument();
    expect(screen.getByText(/12 printed of 12/i)).toBeInTheDocument();
    expect(screen.getByText("Zebra ZT410")).toBeInTheDocument();
    expect(screen.getByText("Completed")).toBeInTheDocument();

    expect(await screen.findByText("Print job received by printer connector")).toBeInTheDocument();
    expect(screen.getByText("Label print confirmed")).toBeInTheDocument();
    expect(screen.getByText("Workspace activity")).toBeInTheDocument();
    expect(screen.queryByText(/Local Agent Print Item Acked/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/LOCAL_AGENT_PRINT_ITEM_ACKED/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/LOCAL_AGENT_PRINT_ITEM_CONFIRMED/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/INTERNAL_RENDER_TOKEN_ROTATED/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/secret-token/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/https:\/\/secret\.example/i)).not.toBeInTheDocument();
  });

  it("shows clean empty states", async () => {
    vi.mocked(apiClient.getAuditLogs).mockResolvedValue({ success: true, data: { logs: [] } } as any);
    vi.mocked(apiClient.listPrintJobs).mockResolvedValue({ success: true, data: [] } as any);

    renderHistory();

    expect(await screen.findByText("No print runs found for current filters.")).toBeInTheDocument();
    expect(screen.getByText("No history found for current filters.")).toBeInTheDocument();
  });

  it("shows safe rate-limit copy without exposing technical details", async () => {
    vi.mocked(apiClient.getAuditLogs).mockResolvedValue({
      success: false,
      status: 429,
      code: "RATE_LIMITED",
      error: "Too many audit read requests: stack trace / token=abc",
    } as any);
    vi.mocked(apiClient.listPrintJobs).mockResolvedValue({
      success: false,
      status: 429,
      code: "RATE_LIMITED",
      error: "raw SQL stack and cookie=abc",
    } as any);

    renderHistory();

    expect(await screen.findByText("Too many refresh attempts. Waiting a few seconds before trying again.")).toBeInTheDocument();
    expect(screen.queryByText(/stack trace/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/token=abc/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/cookie=abc/i)).not.toBeInTheDocument();
  });

  it("keeps Refresh single-flight and disabled while loading", async () => {
    renderHistory();

    await screen.findByText("PRINT-42");
    vi.clearAllMocks();

    let resolveAudit: (value: any) => void = () => {};
    let resolvePrintJobs: (value: any) => void = () => {};
    vi.mocked(apiClient.getAuditLogs).mockReturnValue(new Promise((resolve) => { resolveAudit = resolve; }) as any);
    vi.mocked(apiClient.listPrintJobs).mockReturnValue(new Promise((resolve) => { resolvePrintJobs = resolve; }) as any);

    const refreshButton = screen.getByRole("button", { name: /refresh/i });
    fireEvent.click(refreshButton);
    fireEvent.click(refreshButton);

    expect(refreshButton).toBeDisabled();
    expect(screen.getByRole("button", { name: /refreshing/i })).toBeDisabled();
    expect(apiClient.getAuditLogs).toHaveBeenCalledTimes(1);
    expect(apiClient.listPrintJobs).toHaveBeenCalledTimes(1);

    resolveAudit({ success: true, data: { logs: auditRows } });
    resolvePrintJobs({ success: true, data: printJobRows });

    await waitFor(() => expect(screen.getByRole("button", { name: /refresh/i })).not.toBeDisabled());
  });
});
