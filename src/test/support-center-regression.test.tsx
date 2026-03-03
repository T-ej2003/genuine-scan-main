import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import SupportCenter from "@/pages/SupportCenter";
import apiClient from "@/lib/api-client";

vi.mock("@/contexts/AuthContext", () => ({
  useAuth: () => ({
    user: { id: "admin-1", role: "super_admin", name: "Root", email: "root@example.com" },
  }),
}));

vi.mock("@/components/layout/DashboardLayout", () => ({
  DashboardLayout: ({ children }: any) => <div>{children}</div>,
}));

vi.mock("@/lib/api-client", () => ({
  default: {
    getSupportTickets: vi.fn(),
    getSupportTicket: vi.fn(),
    getUsers: vi.fn(),
    patchSupportTicket: vi.fn(),
    addSupportTicketMessage: vi.fn(),
  },
}));

describe("SupportCenter regression", () => {
  const ticket = {
    id: "ticket-1",
    referenceCode: "SUP-2026-0001",
    status: "OPEN",
    priority: "P2",
    subject: "Customer cannot verify",
    createdAt: "2026-03-01T12:00:00.000Z",
    updatedAt: "2026-03-01T12:00:00.000Z",
    incidentId: "incident-1",
    incident: { id: "incident-1", status: "NEW", severity: "HIGH", qrCodeValue: "TT0000000001" },
    sla: { hasSla: true, dueAt: "2026-03-02T12:00:00.000Z", remainingMinutes: 1440, isBreached: false },
  };

  const detail = {
    ...ticket,
    messages: [],
  };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(apiClient.getSupportTickets).mockResolvedValue({ success: true, data: { tickets: [ticket], total: 1 } } as any);
    vi.mocked(apiClient.getSupportTicket).mockResolvedValue({ success: true, data: detail } as any);
    vi.mocked(apiClient.getUsers).mockResolvedValue({
      success: true,
      data: [{ id: "u1", role: "SUPER_ADMIN", name: "Security Lead", email: "sec@example.com" }],
    } as any);
    vi.mocked(apiClient.patchSupportTicket).mockResolvedValue({ success: true, data: detail } as any);
    vi.mocked(apiClient.addSupportTicketMessage).mockResolvedValue({ success: true, data: { id: "msg-1" } } as any);
  });

  it("loads detail and allows workflow save + message append", async () => {
    render(
      <MemoryRouter>
        <SupportCenter />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(vi.mocked(apiClient.getSupportTickets)).toHaveBeenCalled();
      expect(vi.mocked(apiClient.getSupportTicket)).toHaveBeenCalledWith(ticket.id);
    });

    fireEvent.change(screen.getByPlaceholderText("Add handoff or customer-support note..."), {
      target: { value: "Escalated to L2 for root-cause trace." },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add message" }));

    await waitFor(() => {
      expect(vi.mocked(apiClient.addSupportTicketMessage)).toHaveBeenCalledWith(
        ticket.id,
        expect.objectContaining({
          message: "Escalated to L2 for root-cause trace.",
          isInternal: true,
        })
      );
    });

    fireEvent.click(screen.getByRole("button", { name: "Save workflow update" }));

    await waitFor(() => {
      expect(vi.mocked(apiClient.patchSupportTicket)).toHaveBeenCalledWith(
        ticket.id,
        expect.objectContaining({
          status: "OPEN",
          assignedToUserId: null,
        })
      );
    });
  });
});
