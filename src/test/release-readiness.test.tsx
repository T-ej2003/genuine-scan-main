import React from "react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import ReleaseReadiness from "@/pages/ReleaseReadiness";
import apiClient from "@/lib/api-client";

vi.mock("@/contexts/AuthContext", () => ({
  useAuth: () => ({
    user: { id: "super-1", role: "super_admin", name: "Platform", email: "super@example.com" },
  }),
}));

vi.mock("@/components/layout/DashboardLayout", () => ({
  DashboardLayout: ({ children }: { children: ReactNode }) => <div>{children}</div>,
}));

vi.mock("@/lib/api-client", () => ({
  default: {
    getInternalReleaseMetadata: vi.fn(),
    getComplianceReport: vi.fn(),
    getCompliancePackJobs: vi.fn(),
    getRouteTransitionSummary: vi.fn(),
    getRateLimitAnalytics: vi.fn(),
    getRateLimitAlerts: vi.fn(),
  },
}));

describe("Release readiness page", () => {
  beforeEach(() => {
    vi.clearAllMocks();

    vi.mocked(apiClient.getInternalReleaseMetadata).mockResolvedValue({
      success: true,
      data: {
        name: "mscqr-backend",
        version: "1.0.0",
        gitSha: "abcdef1234567890",
        environment: "production",
        release: "2026.04.24",
        signing: {
          mode: "kms",
          provider: "aws-kms",
          keyVersion: "v3",
          keyRef: "alias/mscqr-signing",
        },
      },
    });

    vi.mocked(apiClient.getComplianceReport).mockResolvedValue({
      success: true,
      data: {
        generatedAt: "2026-04-24T12:00:00.000Z",
        scope: { licenseeId: null },
        metrics: {
          incidents: { resolved: 4, total: 5, slaBreachedOpen: 1 },
          auditEvents: 91,
          failedLogins: 3,
        },
        compliance: {
          securityAccess: {
            passwordHandling: "Passwords are handled with secure controls.",
            roleBasedAccess: ["SUPER_ADMIN", "LICENSEE_ADMIN"],
          },
        },
        controlSummary: {
          EFFECTIVE: 12,
          MONITOR: 2,
          ATTENTION: 1,
        },
      },
    });

    vi.mocked(apiClient.getCompliancePackJobs).mockResolvedValue({
      success: true,
      data: {
        jobs: [
          {
            id: "job-1",
            status: "COMPLETED",
            startedAt: "2026-04-24T11:30:00.000Z",
            triggerType: "MANUAL",
          },
        ],
      },
    });

    vi.mocked(apiClient.getRouteTransitionSummary).mockResolvedValue({
      success: true,
      data: {
        verifyFunnel: { dropped: 2, avgTransitionMs: 315 },
      },
    });

    vi.mocked(apiClient.getRateLimitAnalytics).mockResolvedValue({
      success: true,
      data: {
        topLimitedRoutes: [{ route: "GET /internal/release", family: "internal.release", count: 4 }],
        exportAbusePatterns: [{ family: "audit.export", count: 3, uniqueOffenders: 2, uniqueTenants: 1 }],
      },
    });

    vi.mocked(apiClient.getRateLimitAlerts).mockResolvedValue({
      success: true,
      data: {
        alerts: [{ severity: "high", family: "governance.read", reason: "threshold exceeded", count: 12 }],
      },
    });
  });

  it("renders release identity, evidence, and guardrail posture for super admins", async () => {
    render(
      <MemoryRouter>
        <ReleaseReadiness />
      </MemoryRouter>
    );

    expect(await screen.findByText("Release readiness")).toBeInTheDocument();

    await waitFor(() => {
      expect(vi.mocked(apiClient.getInternalReleaseMetadata)).toHaveBeenCalled();
      expect(vi.mocked(apiClient.getComplianceReport)).toHaveBeenCalled();
      expect(vi.mocked(apiClient.getRateLimitAlerts)).toHaveBeenCalledWith({ windowMs: 60 * 60 * 1000 });
    });

    expect(screen.getByText("abcdef1234567890")).toBeInTheDocument();
    expect(screen.getByText(/aws-kms · kms/i)).toBeInTheDocument();
    expect(screen.getByText(/1 active guardrail alert/i)).toBeInTheDocument();
    expect(screen.getByText("Release metadata route")).toBeInTheDocument();
    expect(screen.getByText(/Passwords are handled with secure controls/i)).toBeInTheDocument();
  });
});
