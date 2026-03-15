import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import QRTracking from "@/pages/QRTracking";
import apiClient from "@/lib/api-client";

vi.mock("@/contexts/AuthContext", () => ({
  useAuth: () => ({
    user: { id: "manufacturer-1", role: "manufacturer", name: "Factory User", email: "factory@example.com" },
  }),
}));

vi.mock("@/components/layout/DashboardLayout", () => ({
  DashboardLayout: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

vi.mock("@/lib/mutation-events", () => ({
  onMutationEvent: () => () => {},
}));

vi.mock("@/components/premium/TrackingInsightsPanel", () => ({
  TrackingInsightsPanel: ({ totals }: { totals: { scanEvents?: number } }) => (
    <div data-testid="tracking-insights">scan-events:{totals.scanEvents ?? 0}</div>
  ),
}));

vi.mock("@/components/premium/PremiumLoadingBlocks", () => ({
  PremiumTableSkeleton: () => <div>loading</div>,
}));

vi.mock("@/components/premium/PremiumSectionAccordion", () => ({
  PremiumSectionAccordion: ({ items }: { items: Array<{ value: string; content: React.ReactNode }> }) => (
    <div>{items.map((item) => <div key={item.value}>{item.content}</div>)}</div>
  ),
}));

vi.mock("@/components/batches/BatchAllocationMapDialog", () => ({
  BatchAllocationMapDialog: () => null,
}));

vi.mock("@/lib/api-client", () => ({
  default: {
    getQrTrackingAnalytics: vi.fn(),
    getBatchAllocationMap: vi.fn(),
  },
}));

describe("QRTracking", () => {
  beforeEach(() => {
    vi.clearAllMocks();

    vi.mocked(apiClient.getQrTrackingAnalytics).mockResolvedValue({
      success: true,
      data: {
        scope: {
          mode: "inventory",
          title: "Inventory scope",
          description: "Inventory totals plus scan visibility.",
          quantities: {
            distinctCodes: 5,
            scanEvents: 7,
            matchedBatches: 1,
          },
        },
        totals: {
          total: 82,
          dormant: 13,
          allocated: 17,
          printed: 19,
          redeemed: 23,
          blocked: 29,
          created: 1,
        },
        eventSummary: {
          totalScanEvents: 7,
          firstScanEvents: 2,
          repeatScanEvents: 5,
          blockedEvents: 1,
          trustedOwnerEvents: 3,
          externalEvents: 4,
          namedLocationEvents: 2,
          knownDeviceEvents: 6,
        },
        trend: [
          {
            label: "Mar 14",
            total: 82,
            dormant: 13,
            allocated: 17,
            printed: 19,
            redeemed: 23,
            blocked: 29,
            scanEvents: 7,
          },
        ],
        batches: [
          {
            id: "batch-1",
            name: "Batch 1",
            licenseeId: "lic-1",
            startCode: "AADS00000020001",
            endCode: "AADS00000020100",
            totalCodes: 100,
            batchInventoryTotal: 100,
            scopeCodeCount: 82,
            scanEventCount: 7,
            createdAt: "2026-03-14T10:00:00.000Z",
            counts: { DORMANT: 8, ACTIVE: 5, ALLOCATED: 11, ACTIVATED: 6, PRINTED: 19, REDEEMED: 21, SCANNED: 2, BLOCKED: 29 },
          },
        ],
        logs: [
          {
            id: "log-1",
            code: "AADS00000020037",
            status: "REDEEMED",
            scanCount: 5,
            scannedAt: "2026-03-14T11:52:32.000Z",
            batchId: "batch-1",
            device: "android-device",
            deviceLabel: "Chrome on Android",
            userAgent: "Chrome on Android",
            ipAddress: "5.71.218.224",
            latitude: 12.3456,
            longitude: 78.9012,
            accuracy: 42,
            isTrustedOwnerContext: false,
            ownershipMatchMethod: null,
            licensee: { id: "lic-1", name: "facttest", prefix: "AADS" },
            qrCode: { id: "qr-1", code: "AADS00000020037", status: "REDEEMED" },
          },
          {
            id: "log-2",
            code: "AADS00000020037",
            status: "REDEEMED",
            scanCount: 6,
            scannedAt: "2026-03-14T12:02:00.000Z",
            batchId: "batch-1",
            device: "claimed-device",
            deviceLabel: "Claimed Android",
            userAgent: "Chrome on Android",
            ipAddress: "5.71.218.224",
            locationName: "London, United Kingdom",
            isTrustedOwnerContext: true,
            ownershipMatchMethod: "device_token",
            licensee: { id: "lic-1", name: "facttest", prefix: "AADS" },
            qrCode: { id: "qr-1", code: "AADS00000020037", status: "REDEEMED" },
          },
        ],
        pagination: { total: 2, limit: 200, offset: 0 },
      },
    } as any);
  });

  it("shows scan event totals and scan context details instead of zeroed inventory-only tracking", async () => {
    render(
      <MemoryRouter>
        <QRTracking />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(vi.mocked(apiClient.getQrTrackingAnalytics)).toHaveBeenCalled();
    });

    expect(await screen.findByText("4 external scans")).toBeInTheDocument();
    expect(screen.getByText("3 owner-linked scans")).toBeInTheDocument();
    expect(screen.getByText("Named locations")).toBeInTheDocument();
    expect(screen.getByText("Known devices")).toBeInTheDocument();
    expect(screen.getByTestId("tracking-insights")).toHaveTextContent("scan-events:7");
    expect(screen.getByText("GPS 12.346, 78.901 (~42m)")).toBeInTheDocument();
    expect(screen.getByText("Trusted claimed device")).toBeInTheDocument();
    expect(screen.getByText("External / anonymous context")).toBeInTheDocument();
    expect(screen.getByText("Chrome on Android")).toBeInTheDocument();
    expect(screen.getAllByText("User agent captured").length).toBeGreaterThan(0);
    const batchRow = screen.getAllByText("Batch 1")[0]?.closest("tr");
    expect(batchRow).toHaveTextContent("13");
    expect(batchRow).toHaveTextContent("17");
    expect(batchRow).toHaveTextContent("19");
    expect(batchRow).toHaveTextContent("23");
    expect(batchRow).toHaveTextContent("29");
  });
});
