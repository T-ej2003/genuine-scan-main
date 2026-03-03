import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import Governance from "@/pages/Governance";
import apiClient from "@/lib/api-client";
import { saveAs } from "file-saver";

vi.mock("@/contexts/AuthContext", () => ({
  useAuth: () => ({
    user: { id: "lic-admin-1", role: "licensee_admin", licenseeId: "lic-1", name: "Ops", email: "ops@example.com" },
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
    getGovernanceFeatureFlags: vi.fn(),
    getEvidenceRetentionPolicy: vi.fn(),
    upsertGovernanceFeatureFlag: vi.fn(),
    patchEvidenceRetentionPolicy: vi.fn(),
    runEvidenceRetentionJob: vi.fn(),
    getComplianceReport: vi.fn(),
    getRouteTransitionSummary: vi.fn(),
    exportIncidentEvidenceBundle: vi.fn(),
    runCompliancePack: vi.fn(),
    getCompliancePackJobs: vi.fn(),
    downloadCompliancePackJob: vi.fn(),
  },
}));

describe("Governance regression", () => {
  beforeEach(() => {
    vi.clearAllMocks();

    vi.mocked(apiClient.getGovernanceFeatureFlags).mockResolvedValue({
      success: true,
      data: {
        flags: [
          { id: "flag-1", key: "verify_show_timeline_card", enabled: true },
          { id: "flag-2", key: "verify_show_risk_cards", enabled: true },
        ],
      },
    } as any);

    vi.mocked(apiClient.getEvidenceRetentionPolicy).mockResolvedValue({
      success: true,
      data: {
        id: "policy-1",
        retentionDays: 180,
        purgeEnabled: false,
        exportBeforePurge: true,
        legalHoldTags: ["legal_hold"],
      },
    } as any);

    vi.mocked(apiClient.runCompliancePack).mockResolvedValue({
      success: true,
      data: {
        job: { id: "job-1", status: "COMPLETED" },
      },
    } as any);

    vi.mocked(apiClient.getCompliancePackJobs).mockResolvedValue({
      success: true,
      data: {
        jobs: [
          {
            id: "job-1",
            status: "COMPLETED",
            startedAt: "2026-03-01T11:00:00.000Z",
            triggerType: "MANUAL",
          },
        ],
      },
    } as any);

    vi.mocked(apiClient.downloadCompliancePackJob).mockResolvedValue(
      new Blob(["zip-data"], { type: "application/zip" })
    );
  });

  it("generates and downloads signed compliance pack", async () => {
    render(<Governance />);

    await waitFor(() => {
      expect(vi.mocked(apiClient.getGovernanceFeatureFlags)).toHaveBeenCalledWith("lic-1");
      expect(vi.mocked(apiClient.getEvidenceRetentionPolicy)).toHaveBeenCalledWith("lic-1");
    });

    fireEvent.click(screen.getByRole("button", { name: "Generate signed pack" }));

    await waitFor(() => {
      expect(vi.mocked(apiClient.runCompliancePack)).toHaveBeenCalledWith({ licenseeId: "lic-1" });
      expect(vi.mocked(apiClient.getCompliancePackJobs)).toHaveBeenCalled();
    });

    fireEvent.click(screen.getByRole("button", { name: "Download" }));

    await waitFor(() => {
      expect(vi.mocked(apiClient.downloadCompliancePackJob)).toHaveBeenCalledWith("job-1");
      expect(vi.mocked(saveAs)).toHaveBeenCalledWith(expect.any(Blob), "compliance-pack-job-1.zip");
    });
  });
});
