import React from "react";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import App from "@/App";
import apiClient from "@/lib/api-client";
import { queryClient } from "@/lib/query-client";

const manufacturerUser = {
  id: "manufacturer-1",
  email: "factory@example.com",
  name: "Factory User",
  role: "MANUFACTURER",
  licenseeId: "licensee-1",
  orgId: "org-1",
  auth: { sessionStage: "ACTIVE" },
};

const localAgentStatus = {
  connected: true,
  printerName: null,
  printerId: null,
  selectedPrinterId: null,
  selectedPrinterName: null,
  deviceName: null,
  agentVersion: "2026.6.26",
  protocolVersion: null,
  buildVersion: "2026.6.26",
  transportDiagnosticsVersion: null,
  capabilities: null,
  error: null,
  agentId: "agent-1",
  deviceFingerprint: "device-1",
  publicKeyPem: null,
  clientCertFingerprint: null,
  heartbeatNonce: null,
  heartbeatIssuedAt: null,
  heartbeatSignature: null,
  compatibilityMode: false,
  websocket: null,
  capabilitySummary: null,
  printers: [],
  calibrationProfile: null,
};

vi.mock("@/lib/api-client", () => ({
  default: {
    getToken: vi.fn(() => null),
    setToken: vi.fn(),
    logout: vi.fn(),
    logoutSession: vi.fn().mockResolvedValue({ success: true }),
    refreshSession: vi.fn(),
    getCurrentUser: vi.fn(),
    getBatches: vi.fn(),
    getPrinterConnectionStatus: vi.fn(),
    getLocalPrintAgentStatus: vi.fn(),
    listRegisteredPrinters: vi.fn(),
  },
}));

vi.mock("@/components/auth/StepUpRecoveryDialog", () => ({
  default: () => null,
}));

vi.mock("@/components/help/HelpAssistantWidget", () => ({
  default: () => null,
}));

vi.mock("@/components/trust/CookieConsentBanner", () => ({
  CookieConsentBanner: () => null,
}));

vi.mock("@/components/RouteMetricsTracker", () => ({
  default: () => null,
}));

vi.mock("@/components/RouteScrollReset", () => ({
  RouteScrollReset: () => null,
}));

vi.mock("@/components/seo/SeoController", () => ({
  SeoController: () => null,
}));

vi.mock("@/pages/Dashboard", async () => {
  const React = await vi.importActual<typeof import("react")>("react");
  const { useNavigate } = await vi.importActual<typeof import("react-router")>("react-router");
  const { useLocation } = await vi.importActual<typeof import("react-router")>("react-router");
  const { useAuth } = await vi.importActual<typeof import("@/contexts/AuthContext")>("@/contexts/AuthContext");
  return { default: function DashboardProbe() {
    const navigate = useNavigate();
    const location = useLocation();
    const auth = useAuth();
    return React.createElement("div", { "data-testid": "protected-dashboard-probe", "data-path": location.pathname },
      React.createElement("button", { onClick: () => navigate("/batches") }, "Open batches"),
      React.createElement("button", { onClick: () => navigate("/batches?view=latest") }, "Open latest batches"),
      React.createElement("button", { onClick: () => void auth.refresh() }, "Check session"),
      React.createElement("button", { onClick: () => auth.logout() }, "Log out"));
  } };
});

vi.mock("@/pages/Batches", async () => {
  const React = await vi.importActual<typeof import("react")>("react");
  const { useLocation, useNavigate } = await vi.importActual<typeof import("react-router")>("react-router");
  const { useAuth } = await vi.importActual<typeof import("@/contexts/AuthContext")>("@/contexts/AuthContext");
  const { useBatches } = await vi.importActual<typeof import("@/features/batches/hooks")>("@/features/batches/hooks");
  const { useManufacturerPrinterRuntime } =
    await vi.importActual<typeof import("@/features/printing/hooks")>("@/features/printing/hooks");

  return {
    default: function ProtectedBatchesProbe() {
      const auth = useAuth();
      const location = useLocation();
      const navigate = useNavigate();
      useBatches(new URLSearchParams(location.search).get("licenseeId") || undefined, true);
      useManufacturerPrinterRuntime(true, true);
      return React.createElement("div", { "data-testid": "protected-batches-probe", "data-licensee": auth.user?.licenseeId,
        "data-search": location.search }, "Protected batches",
        React.createElement("button", { onClick: () => navigate("/batches?licenseeId=B") }, "Switch licensee"));
    },
  };
});

const renderAt = (path: string) => {
  window.history.pushState({}, "", path);
  return render(<App />);
};

describe("auth bootstrap after reload", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    queryClient.clear();
    vi.mocked(apiClient.getToken).mockReturnValue(null);
    vi.mocked(apiClient.getCurrentUser).mockResolvedValue({
      success: false,
      status: 401,
      error: "No token provided",
    } as Awaited<ReturnType<typeof apiClient.getCurrentUser>>);
    vi.mocked(apiClient.getBatches).mockResolvedValue({ success: true, data: [] } as Awaited<
      ReturnType<typeof apiClient.getBatches>
    >);
    vi.mocked(apiClient.getPrinterConnectionStatus).mockResolvedValue({
      success: false,
      status: 401,
      error: "No token provided",
    } as Awaited<ReturnType<typeof apiClient.getPrinterConnectionStatus>>);
    vi.mocked(apiClient.getLocalPrintAgentStatus).mockResolvedValue({ success: true, data: localAgentStatus } as Awaited<
      ReturnType<typeof apiClient.getLocalPrintAgentStatus>
    >);
    vi.mocked(apiClient.listRegisteredPrinters).mockResolvedValue({ success: true, data: [] } as Awaited<
      ReturnType<typeof apiClient.listRegisteredPrinters>
    >);
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    queryClient.clear();
    window.history.pushState({}, "", "/");
  });

  it("restores a refresh-cookie session before protected batch and printer queries fire", async () => {
    let resolveRefresh: (value: Awaited<ReturnType<typeof apiClient.refreshSession>>) => void = () => undefined;
    vi.mocked(apiClient.refreshSession).mockReturnValue(
      new Promise((resolve) => {
        resolveRefresh = resolve;
      }) as ReturnType<typeof apiClient.refreshSession>
    );

    renderAt("/batches");

    await waitFor(() => expect(apiClient.refreshSession).toHaveBeenCalledTimes(1));
    expect(apiClient.getBatches).not.toHaveBeenCalled();
    expect(apiClient.getPrinterConnectionStatus).not.toHaveBeenCalled();

    await act(async () => {
      resolveRefresh({
        success: true,
        data: {
          user: manufacturerUser,
          auth: { sessionStage: "ACTIVE" },
        },
      });
    });

    expect(await screen.findByTestId("protected-batches-probe")).toBeInTheDocument();
    await waitFor(() => expect(apiClient.getBatches).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(apiClient.getPrinterConnectionStatus).toHaveBeenCalledTimes(1));
  });

  it("validates a known cookie session without rotating it on ordinary navigation", async () => {
    let now = 100_000;
    vi.spyOn(Date, "now").mockImplementation(() => now);
    let resolveMe: (value: Awaited<ReturnType<typeof apiClient.getCurrentUser>>) => void = () => undefined;
    vi.mocked(apiClient.refreshSession).mockResolvedValue({ success: true, data: { user: manufacturerUser } } as any);
    vi.mocked(apiClient.getCurrentUser).mockImplementation(() => new Promise(resolve => { resolveMe = resolve; }) as ReturnType<typeof apiClient.getCurrentUser>);

    renderAt("/dashboard");
    await screen.findByTestId("protected-dashboard-probe");
    now += 61_000;
    fireEvent.click(screen.getByRole("button", { name: "Open batches" }));

    await waitFor(() => expect(apiClient.getCurrentUser).toHaveBeenCalledTimes(1));
    expect(apiClient.refreshSession).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId("protected-dashboard-probe")).toBeInTheDocument();
    expect(apiClient.getBatches).not.toHaveBeenCalled();

    await act(async () => resolveMe({ success: true, data: { user: manufacturerUser } } as any));
    expect(await screen.findByTestId("protected-batches-probe")).toBeInTheDocument();
    expect(apiClient.refreshSession).toHaveBeenCalledTimes(1);
  });

  it("does not rotate a known session when the validation read is throttled", async () => {
    let now = 100_000;
    vi.spyOn(Date, "now").mockImplementation(() => now);
    vi.mocked(apiClient.refreshSession).mockResolvedValue({ success: true, data: { user: manufacturerUser } } as any);
    vi.mocked(apiClient.getCurrentUser).mockResolvedValue({ success: false, status: 429, retryAfterSec: 755 } as any);

    renderAt("/dashboard");
    await screen.findByTestId("protected-dashboard-probe");
    now += 61_000;
    fireEvent.click(screen.getByRole("button", { name: "Open batches" }));
    await waitFor(() => expect(apiClient.getCurrentUser).toHaveBeenCalledOnce());
    expect(apiClient.refreshSession).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId("protected-dashboard-probe")).toBeInTheDocument();
    expect(apiClient.getBatches).not.toHaveBeenCalled();
  });

  it("holds the old route and destination queries until navigation validation settles", async () => {
    let now = 100_000;
    vi.spyOn(Date, "now").mockImplementation(() => now);
    let resolveRefresh: (value: Awaited<ReturnType<typeof apiClient.refreshSession>>) => void = () => undefined;
    vi.mocked(apiClient.refreshSession)
      .mockResolvedValueOnce({ success: true, data: { user: manufacturerUser } } as any)
      .mockImplementationOnce(() => new Promise(resolve => { resolveRefresh = resolve; }) as ReturnType<typeof apiClient.refreshSession>);
    renderAt("/dashboard");
    await screen.findByTestId("protected-dashboard-probe");
    now += 61_000;
    fireEvent.click(screen.getByRole("button", { name: "Open batches" }));
    await waitFor(() => expect(apiClient.refreshSession).toHaveBeenCalledTimes(2));
    expect(screen.getByTestId("protected-dashboard-probe")).toBeInTheDocument();
    expect(screen.getByTestId("protected-dashboard-probe")).toHaveAttribute("data-path", "/dashboard");
    expect(screen.queryByTestId("protected-batches-probe")).not.toBeInTheDocument();
    expect(apiClient.getBatches).not.toHaveBeenCalled();
    expect(apiClient.getPrinterConnectionStatus).not.toHaveBeenCalled();
    await act(async () => resolveRefresh({ success: true, data: { user: manufacturerUser } } as any));
    expect(await screen.findByTestId("protected-batches-probe")).toBeInTheDocument();
    await waitFor(() => expect(apiClient.getBatches).toHaveBeenCalledOnce());
    await waitFor(() => expect(apiClient.getPrinterConnectionStatus).toHaveBeenCalledOnce());
  });

  it("holds destination queries when a manual refresh is already pending before the navigation interval", async () => {
    let now = 100_000;
    vi.spyOn(Date, "now").mockImplementation(() => now);
    let resolveRefresh: (value: Awaited<ReturnType<typeof apiClient.refreshSession>>) => void = () => undefined;
    vi.mocked(apiClient.refreshSession)
      .mockResolvedValueOnce({ success: true, data: { user: manufacturerUser } } as any)
      .mockImplementationOnce(() => new Promise(resolve => { resolveRefresh = resolve; }) as ReturnType<typeof apiClient.refreshSession>);
    renderAt("/dashboard");
    await screen.findByTestId("protected-dashboard-probe");
    now += 10_000;
    fireEvent.click(screen.getByRole("button", { name: "Check session" }));
    await waitFor(() => expect(apiClient.refreshSession).toHaveBeenCalledTimes(2));
    fireEvent.click(screen.getByRole("button", { name: "Open batches" }));
    expect(screen.getByTestId("protected-dashboard-probe")).toHaveAttribute("data-path", "/dashboard");
    expect(apiClient.getBatches).not.toHaveBeenCalled();
    await act(async () => resolveRefresh({ success: true, data: { user: manufacturerUser } } as any));
    expect(await screen.findByTestId("protected-batches-probe")).toBeInTheDocument();
    await waitFor(() => expect(apiClient.getBatches).toHaveBeenCalledOnce());
  });

  it("holds same-path licensee queries until navigation validation settles", async () => {
    let now = 100_000;
    vi.spyOn(Date, "now").mockImplementation(() => now);
    let resolveRefresh: (value: Awaited<ReturnType<typeof apiClient.refreshSession>>) => void = () => undefined;
    vi.mocked(apiClient.refreshSession)
      .mockResolvedValueOnce({ success: true, data: { user: manufacturerUser } } as any)
      .mockImplementationOnce(() => new Promise(resolve => { resolveRefresh = resolve; }) as ReturnType<typeof apiClient.refreshSession>);
    renderAt("/batches?licenseeId=A");
    await screen.findByTestId("protected-batches-probe");
    await waitFor(() => expect(apiClient.getBatches).toHaveBeenCalledOnce());
    now += 61_000;
    fireEvent.click(screen.getByRole("button", { name: "Switch licensee" }));
    await waitFor(() => expect(apiClient.refreshSession).toHaveBeenCalledTimes(2));
    expect(screen.getByTestId("protected-batches-probe")).toHaveAttribute("data-search", "?licenseeId=A");
    expect(apiClient.getBatches).toHaveBeenCalledTimes(1);
    await act(async () => resolveRefresh({ success: true, data: { user: manufacturerUser } } as any));
    await waitFor(() => expect(screen.getByTestId("protected-batches-probe")).toHaveAttribute("data-search", "?licenseeId=B"));
    await waitFor(() => expect(apiClient.getBatches).toHaveBeenCalledTimes(2));
    expect(apiClient.getBatches).toHaveBeenLastCalledWith({ licenseeId: "B", limit: 100, offset: 0 });
  });

  it("uses the latest route and refreshed tenant after rapid navigation", async () => {
    let now = 100_000;
    vi.spyOn(Date, "now").mockImplementation(() => now);
    let resolveRefresh: (value: Awaited<ReturnType<typeof apiClient.refreshSession>>) => void = () => undefined;
    vi.mocked(apiClient.refreshSession)
      .mockResolvedValueOnce({ success: true, data: { user: manufacturerUser } } as any)
      .mockImplementationOnce(() => new Promise(resolve => { resolveRefresh = resolve; }) as ReturnType<typeof apiClient.refreshSession>);
    renderAt("/dashboard");
    await screen.findByTestId("protected-dashboard-probe");
    now += 61_000;
    fireEvent.click(screen.getByRole("button", { name: "Open batches" }));
    fireEvent.click(screen.getByRole("button", { name: "Open latest batches" }));
    expect(apiClient.getBatches).not.toHaveBeenCalled();
    await waitFor(() => expect(apiClient.refreshSession).toHaveBeenCalledTimes(2));
    await act(async () => resolveRefresh({ success: true, data: { user: { ...manufacturerUser, licenseeId: "licensee-2" } } } as any));
    expect(await screen.findByTestId("protected-batches-probe")).toHaveAttribute("data-licensee", "licensee-2");
    expect(window.location.search).toBe("?view=latest");
    await waitFor(() => expect(apiClient.getBatches).toHaveBeenCalledOnce());
  });

  it("does not mount the destination after logout during pending validation", async () => {
    let now = 100_000;
    vi.spyOn(Date, "now").mockImplementation(() => now);
    let resolveRefresh: (value: Awaited<ReturnType<typeof apiClient.refreshSession>>) => void = () => undefined;
    vi.mocked(apiClient.refreshSession)
      .mockResolvedValueOnce({ success: true, data: { user: manufacturerUser } } as any)
      .mockImplementationOnce(() => new Promise(resolve => { resolveRefresh = resolve; }) as ReturnType<typeof apiClient.refreshSession>);
    renderAt("/dashboard");
    await screen.findByTestId("protected-dashboard-probe");
    now += 61_000;
    fireEvent.click(screen.getByRole("button", { name: "Open batches" }));
    await waitFor(() => expect(apiClient.refreshSession).toHaveBeenCalledTimes(2));
    fireEvent.click(screen.getByRole("button", { name: "Log out" }));
    await act(async () => resolveRefresh({ success: true, data: { user: manufacturerUser } } as any));
    await waitFor(() => expect(window.location.pathname).toBe("/login"));
    expect(apiClient.getBatches).not.toHaveBeenCalled();
  });

  it("does not mount destination queries after a terminal navigation refresh rejection", async () => {
    let now = 100_000;
    vi.spyOn(Date, "now").mockImplementation(() => now);
    vi.mocked(apiClient.refreshSession)
      .mockResolvedValueOnce({ success: true, data: { user: manufacturerUser } } as any)
      .mockResolvedValue({ success: false, status: 401 } as any);
    renderAt("/dashboard");
    await screen.findByTestId("protected-dashboard-probe");
    now += 61_000;
    fireEvent.click(screen.getByRole("button", { name: "Open batches" }));
    await waitFor(() => expect(window.location.pathname).toBe("/login"));
    expect(apiClient.getBatches).not.toHaveBeenCalled();
  });

  it.each([
    ["rate limit", { success: false, status: 429, retryAfterSec: 755 }],
    ["network failure", { success: false, status: 0 }],
  ])("keeps the old route while %s prevents navigation validation", async (_, failure) => {
    let now = 100_000;
    vi.spyOn(Date, "now").mockImplementation(() => now);
    vi.mocked(apiClient.refreshSession)
      .mockResolvedValueOnce({ success: true, data: { user: manufacturerUser } } as any)
      .mockResolvedValueOnce(failure as any);
    renderAt("/dashboard");
    await screen.findByTestId("protected-dashboard-probe");
    now += 61_000;
    fireEvent.click(screen.getByRole("button", { name: "Open batches" }));
    await waitFor(() => expect(apiClient.getCurrentUser).toHaveBeenCalledOnce());
    expect(screen.getByTestId("protected-dashboard-probe")).toBeInTheDocument();
    expect(screen.queryByTestId("protected-batches-probe")).not.toBeInTheDocument();
    expect(apiClient.getBatches).not.toHaveBeenCalled();
  });

  it("does not release destination queries during an existing refresh cooldown", async () => {
    let now = 100_000;
    vi.spyOn(Date, "now").mockImplementation(() => now);
    vi.mocked(apiClient.refreshSession)
      .mockResolvedValueOnce({ success: true, data: { user: manufacturerUser } } as any)
      .mockResolvedValue({ success: false, status: 429, retryAfterSec: 755 } as any);
    renderAt("/dashboard");
    await screen.findByTestId("protected-dashboard-probe");
    now += 61_000;
    fireEvent.click(screen.getByRole("button", { name: "Check session" }));
    await waitFor(() => expect(apiClient.getCurrentUser).toHaveBeenCalledOnce());
    await act(async () => { await new Promise((resolve) => setTimeout(resolve, 0)); });
    fireEvent.click(screen.getByRole("button", { name: "Open batches" }));
    await act(async () => { await Promise.resolve(); });
    expect(screen.getByTestId("protected-dashboard-probe")).toBeInTheDocument();
    expect(apiClient.getBatches).not.toHaveBeenCalled();
    expect(apiClient.refreshSession).toHaveBeenCalledTimes(2);
  });

  it("redirects cleanly when restore fails and does not run protected queries", async () => {
    vi.mocked(apiClient.refreshSession).mockResolvedValue({
      success: false,
      status: 401,
      error: "Session expired. Please sign in again.",
    } as Awaited<ReturnType<typeof apiClient.refreshSession>>);

    renderAt("/batches");

    await waitFor(() => expect(apiClient.refreshSession).toHaveBeenCalledTimes(1));

    expect(apiClient.getBatches).not.toHaveBeenCalled();
    expect(apiClient.getPrinterConnectionStatus).not.toHaveBeenCalled();
    expect(screen.queryByTestId("protected-batches-probe")).not.toBeInTheDocument();
    expect(screen.queryByText(/no token provided/i)).not.toBeInTheDocument();
  });

  it("restores a valid access-cookie session after refresh is throttled", async () => {
    vi.mocked(apiClient.refreshSession).mockResolvedValue({
      success: false, status: 429, retryAfterSec: 45, error: "Rate limited",
    } as Awaited<ReturnType<typeof apiClient.refreshSession>>);
    vi.mocked(apiClient.getCurrentUser).mockResolvedValue({
      success: true, data: { user: manufacturerUser, auth: { sessionStage: "ACTIVE" } },
    } as Awaited<ReturnType<typeof apiClient.getCurrentUser>>);

    renderAt("/batches");

    await waitFor(() => expect(apiClient.refreshSession).toHaveBeenCalledOnce());
    await waitFor(() => expect(apiClient.getCurrentUser).toHaveBeenCalledOnce());
    expect(await screen.findByTestId("protected-batches-probe")).toBeInTheDocument();
    expect(apiClient.getBatches).toHaveBeenCalledTimes(1);
  });

  it("keeps protected queries pending and retries after both restore paths fail transiently", async () => {
    vi.useFakeTimers();
    vi.mocked(apiClient.refreshSession)
      .mockResolvedValueOnce({ success: false, status: 429, retryAfterSec: 45 } as any)
      .mockResolvedValueOnce({ success: true, data: { user: manufacturerUser, auth: { sessionStage: "ACTIVE" } } } as any);
    vi.mocked(apiClient.getCurrentUser).mockResolvedValueOnce({ success: false, status: 503 } as any);
    try {
      await act(async () => { renderAt("/batches"); await Promise.resolve(); });
      expect(apiClient.refreshSession).toHaveBeenCalledOnce();
      expect(apiClient.getCurrentUser).toHaveBeenCalledOnce();
      expect(apiClient.getBatches).not.toHaveBeenCalled();
      expect(screen.queryByTestId("protected-batches-probe")).not.toBeInTheDocument();
      await act(async () => { await vi.advanceTimersByTimeAsync(44_000); });
      expect(apiClient.refreshSession).toHaveBeenCalledOnce();
      await act(async () => { await vi.advanceTimersByTimeAsync(1_000); });
      expect(apiClient.refreshSession).toHaveBeenCalledTimes(2);
      expect(screen.getByTestId("protected-batches-probe")).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });

  it("treats refresh-token revocation as terminal even if current-user lookup would be transient", async () => {
    vi.mocked(apiClient.refreshSession).mockResolvedValue({ success: false, status: 401 } as any);
    vi.mocked(apiClient.getCurrentUser).mockResolvedValue({ success: false, status: 503 } as any);
    renderAt("/batches");
    await waitFor(() => expect(apiClient.refreshSession).toHaveBeenCalledOnce());
    expect(apiClient.getCurrentUser).not.toHaveBeenCalled();
    expect(apiClient.getBatches).not.toHaveBeenCalled();
    expect(screen.queryByTestId("protected-batches-probe")).not.toBeInTheDocument();
  });

  it("ends bootstrap on an explicit manufacturer scope denial", async () => {
    vi.mocked(apiClient.refreshSession).mockResolvedValue({ success: false, status: 403, code: "AUTH_SCOPE_UNAVAILABLE" } as any);
    renderAt("/batches");
    await waitFor(() => expect(apiClient.refreshSession).toHaveBeenCalledOnce());
    expect(apiClient.getCurrentUser).not.toHaveBeenCalled();
    expect(apiClient.getBatches).not.toHaveBeenCalled();
    expect(screen.queryByTestId("protected-batches-probe")).not.toBeInTheDocument();
  });

  it("redirects an anonymous CSRF 403 plus current-user 401 to login", async () => {
    vi.mocked(apiClient.refreshSession).mockResolvedValue({ success: false, status: 403, code: "CSRF_DENIED" } as any);
    renderAt("/dashboard");
    await waitFor(() => expect(apiClient.getCurrentUser).toHaveBeenCalledOnce());
    await waitFor(() => expect(window.location.pathname).toBe("/login"));
  });

  it("keeps a throttled refresh plus expired access cookie pending", async () => {
    vi.mocked(apiClient.refreshSession).mockResolvedValue({ success: false, status: 429, retryAfterSec: 45 } as any);
    renderAt("/dashboard");
    await waitFor(() => expect(apiClient.getCurrentUser).toHaveBeenCalledOnce());
    expect(window.location.pathname).toBe("/dashboard");
    expect(screen.queryByTestId("protected-batches-probe")).not.toBeInTheDocument();
  });
});
