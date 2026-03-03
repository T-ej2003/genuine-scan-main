import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import IR from "@/pages/IR";
import apiClient from "@/lib/api-client";

vi.mock("@/components/layout/DashboardLayout", () => ({
  DashboardLayout: ({ children }: any) => <div>{children}</div>,
}));

vi.mock("@/lib/api-client", () => ({
  default: {
    getLicensees: vi.fn(),
    getIrIncidents: vi.fn(),
    getIrAlerts: vi.fn(),
    getIrPolicies: vi.fn(),
    createIrIncident: vi.fn(),
    patchIrAlert: vi.fn(),
    createIrPolicy: vi.fn(),
    patchIrPolicy: vi.fn(),
  },
}));

describe("IR regression", () => {
  beforeEach(() => {
    vi.clearAllMocks();

    vi.mocked(apiClient.getLicensees).mockResolvedValue({
      success: true,
      data: [{ id: "lic-1", name: "Acme", prefix: "ACM" }],
    } as any);

    vi.mocked(apiClient.getIrIncidents).mockResolvedValue({
      success: true,
      data: {
        incidents: [
          {
            id: "incident-1",
            status: "NEW",
            severity: "HIGH",
            priority: "P2",
            qrCodeValue: "ACM00000001",
            createdAt: "2026-03-01T10:00:00.000Z",
            licensee: { id: "lic-1", name: "Acme", prefix: "ACM" },
            assignedToUser: null,
          },
        ],
        total: 1,
      },
    } as any);

    vi.mocked(apiClient.getIrAlerts).mockResolvedValue({
      success: true,
      data: {
        alerts: [
          {
            id: "alert-1",
            alertType: "POLICY_RULE",
            severity: "HIGH",
            message: "Multi-device spike",
            acknowledgedAt: null,
            createdAt: "2026-03-01T10:10:00.000Z",
            licensee: { id: "lic-1", name: "Acme", prefix: "ACM" },
            qrCode: { code: "ACM00000001" },
          },
        ],
        total: 1,
      },
    } as any);

    vi.mocked(apiClient.getIrPolicies).mockResolvedValue({
      success: true,
      data: {
        rules: [
          {
            id: "rule-1",
            name: "Burst scan threshold",
            ruleType: "BURST_SCANS",
            threshold: 6,
            windowMinutes: 10,
            severity: "HIGH",
            isActive: true,
            autoCreateIncident: true,
            updatedAt: "2026-03-01T10:10:00.000Z",
            licensee: null,
          },
        ],
        total: 1,
      },
    } as any);

    vi.mocked(apiClient.createIrIncident).mockResolvedValue({
      success: true,
      data: { id: "incident-2" },
    } as any);

    vi.mocked(apiClient.patchIrAlert).mockResolvedValue({
      success: true,
      data: { id: "alert-1", acknowledgedAt: "2026-03-01T10:30:00.000Z" },
    } as any);
  });

  it("covers incident creation flow", async () => {
    render(
      <MemoryRouter>
        <IR />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(vi.mocked(apiClient.getIrIncidents)).toHaveBeenCalled();
    });

    expect(vi.mocked(apiClient.getIrAlerts)).toHaveBeenCalledTimes(0);
    expect(vi.mocked(apiClient.getIrPolicies)).toHaveBeenCalledTimes(0);
    fireEvent.click(screen.getByRole("button", { name: "New incident" }));

    fireEvent.change(screen.getByPlaceholderText("A0000000001"), {
      target: { value: "acm00000077" },
    });
    fireEvent.change(screen.getByPlaceholderText("What happened and why this needs investigation."), {
      target: { value: "Repeated scans from multiple locations within five minutes." },
    });

    fireEvent.click(screen.getByRole("button", { name: "Create incident" }));

    await waitFor(() => {
      expect(vi.mocked(apiClient.createIrIncident)).toHaveBeenCalledWith(
        expect.objectContaining({
          qrCodeValue: "ACM00000077",
          description: "Repeated scans from multiple locations within five minutes.",
        })
      );
    });
  });
});
