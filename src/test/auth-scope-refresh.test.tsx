import React from "react";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router";

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
  return <div>{auth.user?.id || "signed-out"}</div>;
}
const mount = () => render(<MemoryRouter initialEntries={["/dashboard"]}><AuthProvider><Probe /></AuthProvider></MemoryRouter>);

describe("auth scope refresh", () => {
  afterEach(() => { cleanup(); vi.useRealTimers(); vi.clearAllMocks(); scope = "initial"; ready = true; });

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
