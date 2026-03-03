import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import Incidents from "@/pages/Incidents";
import apiClient from "@/lib/api-client";
import { saveAs } from "file-saver";

vi.mock("@/contexts/AuthContext", () => ({
  useAuth: () => ({
    user: { id: "u1", role: "super_admin", name: "Root", email: "root@example.com" },
  }),
}));

vi.mock("@/components/layout/DashboardLayout", () => ({
  DashboardLayout: ({ children }: any) => <div>{children}</div>,
}));

vi.mock("file-saver", () => ({
  saveAs: vi.fn(),
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
    requestIncidentPdfExport: vi.fn(),
  },
}));

describe("Incidents PDF export", () => {
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
    handoff: null,
    supportTicket: null,
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
    vi.mocked(apiClient.requestIncidentPdfExport).mockResolvedValue(new Blob(["pdf-data"], { type: "application/pdf" }));
  });

  it("exports selected incident as PDF", async () => {
    render(<Incidents />);

    await waitFor(() => {
      expect(vi.mocked(apiClient.getIncidentById)).toHaveBeenCalledWith(incidentRow.id);
    });

    fireEvent.click(screen.getByRole("button", { name: "Export PDF" }));

    await waitFor(() => {
      expect(vi.mocked(apiClient.requestIncidentPdfExport)).toHaveBeenCalledWith(incidentRow.id);
      expect(vi.mocked(saveAs)).toHaveBeenCalledWith(expect.any(Blob), `incident-${incidentRow.id}.pdf`);
    });
  });
});
