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
    notifyIncidentCustomer: vi.fn(),
    uploadIncidentEvidence: vi.fn(),
    downloadIncidentEvidence: vi.fn(),
  },
}));

describe("Incidents filters", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(apiClient.getIncidents).mockResolvedValue({
      success: true,
      data: { incidents: [] },
    } as any);
    vi.mocked(apiClient.getIncidentById).mockResolvedValue({ success: false } as any);
    vi.mocked(apiClient.getUsers).mockResolvedValue({ success: true, data: [] } as any);
    vi.mocked(apiClient.getLicensees).mockResolvedValue({ success: true, data: [] } as any);
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
});
