import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";

import QRTracking from "@/pages/QRTracking";
import QRRequests from "@/pages/QRRequests";
import apiClient from "@/lib/api-client";
import { createLicenseeQrApi } from "@/lib/api/internal-client-licensee-qr";
import { clearRequestCoordinator, setRequestCoordinatorScope } from "@/lib/api/request-coordinator";

const auth = vi.hoisted(() => ({
  user: { id: "manufacturer-1", role: "manufacturer", name: "Factory User", email: "factory@example.invalid", licenseeId: "lic-1" },
}));
vi.mock("@/contexts/AuthContext", () => ({ useAuth: () => auth }));

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
    getQrAllocationRequests: vi.fn(),
    getLicensees: vi.fn().mockResolvedValue({ success: true, data: [] }),
  },
}));

describe("QRTracking", () => {
  it("preserves owner context/count and renders absent fields as unavailable", async () => {
    const result = await apiClient.getQrTrackingAnalytics({} as any);
    vi.mocked(apiClient.getQrTrackingAnalytics).mockResolvedValue({ ...result, data: { ...(result.data as Record<string, unknown>),
      logs: [
        { id: "trusted", code: "TRUSTED", scannedAt: "2026-10-01T00:00:00Z", isTrustedOwnerContext: true, scanCount: 7 },
        { id: "external", code: "EXTERNAL", scannedAt: "2026-10-01T00:00:00Z", isTrustedOwnerContext: false, scanCount: 2 },
        { id: "unknown", code: "UNKNOWN", scannedAt: "2026-10-01T00:00:00Z" },
      ],
    }} as any);
    render(<MemoryRouter><QRTracking /></MemoryRouter>);
    const trusted = (await screen.findByText("TRUSTED")).closest("tr")!;
    const external = screen.getByText("EXTERNAL").closest("tr")!;
    const unknown = screen.getByText("UNKNOWN").closest("tr")!;
    expect(trusted).toHaveTextContent("Trusted owner"); expect(trusted).toHaveTextContent("7");
    expect(external).toHaveTextContent("External"); expect(external).toHaveTextContent("2");
    expect(unknown).toHaveTextContent("Unavailable"); expect(unknown).toHaveTextContent("Context unavailable");
    expect(unknown).not.toHaveTextContent("External"); expect(unknown).not.toHaveTextContent("Repeat");
  });

  beforeEach(() => {
    vi.clearAllMocks();
    auth.user.role = "manufacturer";
    auth.user.licenseeId = "lic-1";
    clearRequestCoordinator();
    setRequestCoordinatorScope(auth.user as any);

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

  it("hides allocation attribution and an open decision dialog when the authenticated actor changes", async () => {
    auth.user.role = "super_admin";
    setRequestCoordinatorScope(auth.user as any);
    let finishB!: (value: any) => void;
    vi.mocked(apiClient.getQrAllocationRequests)
      .mockResolvedValueOnce({ success: true, data: [{ id: "request-A", quantity: 10, batchName: "PRIVATE-BATCH-A", status: "PENDING", createdAt: "2026-10-02T10:00:00Z", requestedByUser: { id: "maker", name: "PRIVATE-ACTOR-A", email: "fixture@example.invalid" } }] } as any)
      .mockImplementationOnce(() => new Promise(resolve => { finishB = resolve; }));
    const view = render(<MemoryRouter><QRRequests /></MemoryRouter>);
    expect(await screen.findByText(/PRIVATE-BATCH-A/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Approve" }));
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    await act(async () => { auth.user.licenseeId = "lic-2"; setRequestCoordinatorScope(auth.user as any); });
    view.rerender(<MemoryRouter><QRRequests /></MemoryRouter>);
    expect(screen.queryByText(/PRIVATE-BATCH-A/)).not.toBeInTheDocument();
    expect(screen.queryByText("PRIVATE-ACTOR-A")).not.toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    await waitFor(() => expect(finishB).toBeDefined());
    await act(async () => finishB({ success: false, status: 403 }));
    expect(screen.queryByText(/PRIVATE-BATCH-A/)).not.toBeInTheDocument();
  });

  it("never paints a result while the React actor projection lags the authoritative HTTP scope", async () => {
    const view = render(<MemoryRouter><QRTracking /></MemoryRouter>);
    expect((await screen.findAllByText("AADS00000020037")).length).toBeGreaterThan(0);
    const calls = vi.mocked(apiClient.getQrTrackingAnalytics).mock.calls.length;
    await act(async () => setRequestCoordinatorScope({ ...auth.user, licenseeId: "lic-2" } as any));
    view.rerender(<MemoryRouter><QRTracking /></MemoryRouter>);
    expect(screen.queryAllByText("AADS00000020037")).toHaveLength(0);
    expect(apiClient.getQrTrackingAnalytics).toHaveBeenCalledTimes(calls);
  });

  it.each(["manufacturer", "licensee_admin"])("hides cached %s A immediately while B fails, then safely remounts", async role => {
    const baseline: any = await apiClient.getQrTrackingAnalytics();
    const result = (code: string) => ({ ...baseline, data: { ...baseline.data, batches: [], logs: [{ id: code, code, status: "PRINTED", scannedAt: "2026-10-02T10:00:00Z", qrCode: { displayCode: code } }] } });
    const core = { request: vi.fn().mockResolvedValueOnce(result("CACHED-A")) };
    const real = createLicenseeQrApi(core as any);
    vi.mocked(apiClient.getQrTrackingAnalytics).mockImplementation(real.getQrTrackingAnalytics);
    auth.user.role = role;
    setRequestCoordinatorScope(auth.user as any);
    let view = render(<React.StrictMode><MemoryRouter><QRTracking /></MemoryRouter></React.StrictMode>);
    expect(await screen.findByText("CACHED-A")).toBeInTheDocument();
    let failB!: (value: any) => void;
    core.request.mockImplementationOnce(() => new Promise(resolve => { failB = resolve; }));
    await act(async () => { auth.user.licenseeId = "lic-2"; setRequestCoordinatorScope(auth.user as any); });
    view.rerender(<React.StrictMode><MemoryRouter><QRTracking /></MemoryRouter></React.StrictMode>);
    expect(screen.queryByText("CACHED-A")).not.toBeInTheDocument();
    await waitFor(() => expect(failB).toBeDefined());
    await act(async () => failB({ success: false, status: 500, error: "B unavailable" }));
    expect(screen.queryByText("CACHED-A")).not.toBeInTheDocument();
    view.unmount();
    core.request.mockResolvedValueOnce(result("CURRENT-B"));
    view = render(<MemoryRouter><QRTracking /></MemoryRouter>);
    expect(await screen.findByText("CURRENT-B")).toBeInTheDocument();
    expect(screen.queryByText("CACHED-A")).not.toBeInTheDocument();
    expect(core.request.mock.calls.every(call => !String(call[0]).includes("licenseeId="))).toBe(true);
    auth.user.role = "manufacturer";
  });

  it("suppresses both delayed previous generations during rapid A→B→A switching", async () => {
    const baseline: any = await apiClient.getQrTrackingAnalytics();
    const result = (code: string) => ({ ...baseline, data: { ...baseline.data, batches: [], logs: [{ id: code, code, status: "PRINTED", scannedAt: "2026-10-02T10:00:00Z", qrCode: { displayCode: code } }] } });
    const pending: Array<(value: any) => void> = [];
    const core = { request: vi.fn(() => new Promise(resolve => pending.push(resolve))) };
    vi.mocked(apiClient.getQrTrackingAnalytics).mockImplementation(createLicenseeQrApi(core as any).getQrTrackingAnalytics);
    const view = render(<MemoryRouter><QRTracking /></MemoryRouter>);
    await waitFor(() => expect(pending).toHaveLength(1));
    await act(async () => { auth.user.licenseeId = "lic-2"; setRequestCoordinatorScope(auth.user as any); });
    view.rerender(<MemoryRouter><QRTracking /></MemoryRouter>);
    await waitFor(() => expect(pending).toHaveLength(2));
    await act(async () => { auth.user.licenseeId = "lic-1"; setRequestCoordinatorScope(auth.user as any); });
    view.rerender(<MemoryRouter><QRTracking /></MemoryRouter>);
    await waitFor(() => expect(pending).toHaveLength(3));
    await act(async () => pending[2](result("LATEST-A")));
    expect(await screen.findByText("LATEST-A")).toBeInTheDocument();
    await act(async () => { pending[1](result("LATE-B")); pending[0](result("OLD-A")); });
    expect(screen.queryByText("LATE-B")).not.toBeInTheDocument();
    expect(screen.queryByText("OLD-A")).not.toBeInTheDocument();
    expect(screen.getByText("LATEST-A")).toBeInTheDocument();
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
    expect(vi.mocked(apiClient.getQrTrackingAnalytics).mock.calls[0][0]?.licenseeId).toBeUndefined();

    expect(await screen.findByText("4 repeat or outside scans")).toBeInTheDocument();
    expect(screen.getByText("3 known customer scans")).toBeInTheDocument();
    expect(screen.getByText("Scans with location")).toBeInTheDocument();
    expect(screen.getByText("Known customers")).toBeInTheDocument();
    expect(screen.getByTestId("tracking-insights")).toHaveTextContent("scan-events:7");
    expect(screen.getByText("GPS 12.346, 78.901 (~42m)")).toBeInTheDocument();
    expect(screen.getByText("Trusted claimed device")).toBeInTheDocument();
    expect(screen.getByText("External / anonymous context")).toBeInTheDocument();
    expect(screen.queryByText("Chrome on Android")).not.toBeInTheDocument();
    expect(screen.queryByText("Browser details captured")).not.toBeInTheDocument();
    const batchRow = screen.getAllByText("Batch 1")[0]?.closest("tr");
    expect(batchRow).toHaveTextContent("13");
    expect(batchRow).toHaveTextContent("17");
    expect(batchRow).toHaveTextContent("19");
    expect(batchRow).toHaveTextContent("23");
    expect(batchRow).toHaveTextContent("29");
  });

  it("renders sanitized events and ignores an older response after switching the selected tenant", async () => {
    const baseline: any = await apiClient.getQrTrackingAnalytics();
    const response = (code: string) => ({ ...baseline, data: { ...baseline.data, batches: [], logs: [
      { id: code, code, status: "BLOCKED", scannedAt: "2026-10-02T10:00:00Z", isFirstScan: false,
        qrCode: { id: code, displayCode: code }, latestDecision: { outcome: "BLOCKED", riskBand: "HIGH", replacementStatus: "NONE", customerTrustReviewState: "DISPUTED" } },
    ] } });
    vi.clearAllMocks();
    let resolveFirst!: (value: any) => void;
    vi.mocked(apiClient.getQrTrackingAnalytics)
      .mockImplementationOnce(() => new Promise(resolve => { resolveFirst = resolve; }))
      .mockResolvedValueOnce(response("SELECTED-B"));
    const view = render(<MemoryRouter><QRTracking /></MemoryRouter>);
    await waitFor(() => expect(resolveFirst).toBeDefined());
    auth.user.licenseeId = "lic-2";
    setRequestCoordinatorScope(auth.user as any);
    view.rerender(<MemoryRouter><QRTracking /></MemoryRouter>);
    expect(await screen.findByText("SELECTED-B")).toBeInTheDocument();
    expect(screen.getByText("Context unavailable")).toBeInTheDocument();
    expect(screen.getByText("Disputed")).toBeInTheDocument();
    await act(async () => resolveFirst(response("STALE-A")));
    expect(screen.queryByText("STALE-A")).not.toBeInTheDocument();
    expect(screen.getByText("SELECTED-B")).toBeInTheDocument();
  });
});
