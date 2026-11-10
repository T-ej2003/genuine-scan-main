import React from "react";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter, useNavigate } from "react-router";

import { AuthProvider, useAuth } from "@/contexts/AuthContext";
import apiClient from "@/lib/api-client";

let scope = "initial";
let ready = true;
vi.mock("@/lib/api/request-coordinator", () => ({
  clearRequestCoordinator: vi.fn(),
  getRequestCoordinatorScope: () => `${scope}:${ready}`,
  isRequestCoordinatorScopeReady: () => ready,
  isRequestCoordinatorUserCurrent: (user: { id: string }) => ready && scope === user.id,
  setRequestCoordinatorScope: (user: { id: string } | null) => { scope = user?.id || "null"; ready = true; },
}));
vi.mock("@/lib/api-client", () => ({ default: {
  getToken: vi.fn(() => null), setToken: vi.fn(), logout: vi.fn(),
  refreshSession: vi.fn(), getCurrentUser: vi.fn(),
} }));

const user = { id: "actor", email: "actor@example.com", role: "MANUFACTURER", auth: { sessionStage: "ACTIVE" } };
function Probe() {
  const auth = useAuth();
  return <div>{auth.user?.id || "signed-out"}<button onClick={() => void auth.refresh()}>Refresh session</button></div>;
}
function NavigationProbe() {
  const auth = useAuth();
  const navigate = useNavigate();
  return <div><span data-testid="auth-loading">{auth.isLoading ? "loading" : "ready"}</span>
    <span data-testid="navigation-pending">{String(auth.navigationValidationPending)}</span>
    <span>{auth.user?.id || "signed-out"}</span>
    <button onClick={() => navigate("/batches")}>Open batches</button></div>;
}
const mount = () => render(<MemoryRouter initialEntries={["/dashboard"]}><AuthProvider><Probe /></AuthProvider></MemoryRouter>);

describe("auth scope refresh", () => {
  beforeEach(() => {
    vi.mocked(apiClient.getCurrentUser).mockResolvedValue({ success: false, status: 401 } as any);
  });
  afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); vi.clearAllMocks(); scope = "initial"; ready = true; });

  it("hydrates a successful current-user response after the client updates coordinator scope", async () => {
    vi.mocked(apiClient.refreshSession).mockResolvedValue({ success: true, data: { user } } as any);
    vi.mocked(apiClient.getCurrentUser).mockImplementation(async () => {
      scope = "actor"; ready = true;
      return { success: true, data: { user } } as any;
    });
    mount();
    await screen.findByText("actor");
    scope = "peer"; ready = false;
    await act(async () => { window.dispatchEvent(new Event("auth:scope-refresh")); });
    await waitFor(() => expect(apiClient.getCurrentUser).toHaveBeenCalledOnce());
    expect(screen.getByText("actor")).toBeInTheDocument();
    expect(ready).toBe(true);
  });

  it("keeps an authenticated route visible while a background session check is pending", async () => {
    let now = 100_000;
    vi.spyOn(Date, "now").mockImplementation(() => now);
    let resolveRefresh: (value: any) => void = () => {};
    vi.mocked(apiClient.refreshSession)
      .mockResolvedValueOnce({ success: true, data: { user } } as any)
      .mockImplementationOnce(() => new Promise(resolve => { resolveRefresh = resolve; }));
    render(<MemoryRouter initialEntries={["/dashboard"]}><AuthProvider><NavigationProbe /></AuthProvider></MemoryRouter>);
    await screen.findByText("actor");
    expect(screen.getByTestId("auth-loading")).toHaveTextContent("ready");
    now += 61_000;
    fireEvent.click(screen.getByRole("button", { name: "Open batches" }));
    expect(screen.getByTestId("auth-loading")).toHaveTextContent("ready");
    await act(async () => { resolveRefresh({ success: true, data: { user } }); });
  });

  it("gates navigation while a cross-tab scope validation is pending", async () => {
    let now = 100_000;
    vi.spyOn(Date, "now").mockImplementation(() => now);
    let resolveMe: (value: any) => void = () => {};
    vi.mocked(apiClient.refreshSession).mockResolvedValue({ success: true, data: { user } } as any);
    vi.mocked(apiClient.getCurrentUser).mockImplementation(() => new Promise(resolve => { resolveMe = resolve; }));
    render(<MemoryRouter initialEntries={["/dashboard"]}><AuthProvider><NavigationProbe /></AuthProvider></MemoryRouter>);
    await screen.findByText("actor");
    scope = "peer"; ready = false;
    await act(async () => { window.dispatchEvent(new Event("auth:scope-refresh")); });
    await waitFor(() => expect(apiClient.getCurrentUser).toHaveBeenCalledOnce());
    now += 1_000;
    fireEvent.click(screen.getByRole("button", { name: "Open batches" }));
    expect(screen.getByTestId("navigation-pending")).toHaveTextContent("true");
    await act(async () => { scope = "actor"; ready = true; resolveMe({ success: true, data: { user } }); });
    expect(screen.getByTestId("navigation-pending")).toHaveTextContent("false");
  });

  it("still clears the authenticated view after a terminal background refresh rejection", async () => {
    let now = 100_000;
    vi.spyOn(Date, "now").mockImplementation(() => now);
    vi.mocked(apiClient.refreshSession)
      .mockResolvedValueOnce({ success: true, data: { user } } as any)
      .mockResolvedValueOnce({ success: false, status: 401 } as any);
    render(<MemoryRouter initialEntries={["/dashboard"]}><AuthProvider><NavigationProbe /></AuthProvider></MemoryRouter>);
    await screen.findByText("actor");
    now += 61_000;
    fireEvent.click(screen.getByRole("button", { name: "Open batches" }));
    await screen.findByText("signed-out");
    expect(screen.getByTestId("auth-loading")).toHaveTextContent("ready");
  });

  it("clears refresh cooldown after a successful access-cookie fallback", async () => {
    vi.mocked(apiClient.refreshSession)
      .mockResolvedValueOnce({ success: false, status: 429, retryAfterSec: 267 } as any)
      .mockResolvedValueOnce({ success: true, data: { user } } as any);
    vi.mocked(apiClient.getCurrentUser).mockResolvedValue({ success: true, data: { user } } as any);
    mount();
    await screen.findByText("actor");
    expect(apiClient.refreshSession).toHaveBeenCalledOnce();
    await act(async () => { await Promise.resolve(); });
    fireEvent.click(screen.getByRole("button", { name: "Refresh session" }));
    await waitFor(() => expect(apiClient.getCurrentUser).toHaveBeenCalledTimes(2));
    expect(apiClient.refreshSession).toHaveBeenCalledOnce();
  });

  it("retries a transient scope refresh after Retry-After", async () => {
    vi.mocked(apiClient.refreshSession).mockResolvedValue({ success: true, data: { user } } as any);
    vi.mocked(apiClient.getCurrentUser)
      .mockResolvedValueOnce({ success: false, status: 429, retryAfterSec: 267 } as any)
      .mockImplementationOnce(async () => { scope = "actor"; ready = true; return { success: true, data: { user } } as any; });
    mount();
    await screen.findByText("actor");
    scope = "peer"; ready = false;
    vi.useFakeTimers();
    await act(async () => { window.dispatchEvent(new Event("auth:scope-refresh")); await Promise.resolve(); });
    expect(ready).toBe(false);
    await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
    expect(apiClient.getCurrentUser).toHaveBeenCalledOnce();
    await act(async () => { await vi.advanceTimersByTimeAsync(207_000); });
    expect(apiClient.getCurrentUser).toHaveBeenCalledTimes(2);
    expect(ready).toBe(true);
    expect(screen.getByText("actor")).toBeInTheDocument();
  });
});
