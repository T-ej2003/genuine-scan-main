import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import Incidents from "@/pages/Incidents";
import apiClient from "@/lib/api-client";

vi.mock("@/contexts/AuthContext", () => ({
  useAuth: () => ({
    user: { id: "u1", role: "super_admin", name: "Root", email: "root@example.com" },
  }),
}));

vi.mock("@/components/layout/DashboardLayout", () => ({
  DashboardLayout: ({ children }: any) => <div>{children}</div>,
}));

vi.mock("@/lib/api-client", () => ({
  default: {
    getIncidents: vi.fn(),
    getIncidentById: vi.fn(),
    getUsers: vi.fn(),
    getLicensees: vi.fn(),
    patchIncident: vi.fn(),
    addIncidentNote: vi.fn(),
    sendIncidentEmail: vi.fn(),
    notifyIncidentCustomer: vi.fn(),
    uploadIncidentEvidence: vi.fn(),
    downloadIncidentEvidence: vi.fn(),
  },
}));

describe("Incidents filters", () => {
  const incidentRow = {
    id: "d3d37da2-e7da-41a9-8692-07b121d0264b",
    createdAt: "2026-02-13T13:10:00.000Z",
    qrCodeValue: "TT0000000074",
    incidentType: "OTHER",
    severity: "LOW",
    status: "NEW",
    description: "Suspected issue",
    consentToContact: true,
    customerEmail: "customer@example.com",
    customerPhone: null,
    locationName: "Location unknown",
    assignedToUserId: null,
    assignedToUser: null,
  };

  const incidentDetail = {
    ...incidentRow,
    events: [],
    evidence: [],
    internalNotes: "",
    resolutionSummary: "",
    resolutionOutcome: null,
    tags: [],
  };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(apiClient.getIncidents).mockResolvedValue({
      success: true,
      data: { incidents: [incidentRow] },
    } as any);
    vi.mocked(apiClient.getIncidentById).mockResolvedValue({ success: true, data: incidentDetail } as any);
    vi.mocked(apiClient.getUsers).mockResolvedValue({ success: true, data: [] } as any);
    vi.mocked(apiClient.getLicensees).mockResolvedValue({ success: true, data: [] } as any);
    vi.mocked(apiClient.patchIncident).mockResolvedValue({ success: true, data: { ...incidentDetail, status: "RESOLVED" } } as any);
  });

  it("sends search filter to incidents API", async () => {
    render(<Incidents />);

    await waitFor(() => {
      expect(vi.mocked(apiClient.getIncidents).mock.calls.length).toBeGreaterThan(0);
    });

    fireEvent.change(
      screen.getByPlaceholderText("Search by code / description / contact"),
      { target: { value: "TT0000000068" } }
    );
    fireEvent.click(screen.getByText("Apply"));

    await waitFor(() => {
      expect(vi.mocked(apiClient.getIncidents)).toHaveBeenLastCalledWith(
        expect.objectContaining({
          search: "TT0000000068",
        })
      );
    });
  });

  it("quick status buttons patch incident directly", async () => {
    render(<Incidents />);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Mark resolved" })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole("button", { name: "Mark resolved" }));
    await waitFor(() => {
      expect(vi.mocked(apiClient.patchIncident)).toHaveBeenCalledWith(
        incidentRow.id,
        expect.objectContaining({ status: "RESOLVED" })
      );
    });

    fireEvent.click(screen.getByRole("button", { name: "Reject as spam" }));
    await waitFor(() => {
      expect(vi.mocked(apiClient.patchIncident)).toHaveBeenLastCalledWith(
        incidentRow.id,
        expect.objectContaining({ status: "REJECTED_SPAM" })
      );
    });
  });
});
