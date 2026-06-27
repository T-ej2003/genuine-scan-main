import React from "react";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
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

vi.mock("@/pages/Batches", async () => {
  const React = await vi.importActual<typeof import("react")>("react");
  const { useBatches } = await vi.importActual<typeof import("@/features/batches/hooks")>("@/features/batches/hooks");
  const { useManufacturerPrinterRuntime } =
    await vi.importActual<typeof import("@/features/printing/hooks")>("@/features/printing/hooks");

  return {
    default: function ProtectedBatchesProbe() {
      useBatches(undefined, true);
      useManufacturerPrinterRuntime(true, true);
      return React.createElement("div", { "data-testid": "protected-batches-probe" }, "Protected batches");
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
});
