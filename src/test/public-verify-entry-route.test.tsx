import React from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";

import App from "@/App";
import apiClient from "@/lib/api-client";

vi.mock("@/lib/api-client", () => ({
  default: {
    getCurrentUser: vi.fn(),
    logout: vi.fn(),
    logoutSession: vi.fn().mockResolvedValue({ success: true }),
    captureRouteTransition: vi.fn().mockResolvedValue({ success: true }),
    stepUpWithAdminMfa: vi.fn(),
    stepUpWithPassword: vi.fn(),
    beginAdminWebAuthnChallenge: vi.fn(),
    completeAdminWebAuthnChallenge: vi.fn(),
  },
}));

const renderAt = (path: string) => {
  window.history.pushState({}, "", path);
  return render(<App />);
};

describe("public verify entry route", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(apiClient.getCurrentUser).mockResolvedValue({
      success: false,
      error: "Unauthorized",
    } as Awaited<ReturnType<typeof apiClient.getCurrentUser>>);
  });

  afterEach(() => {
    cleanup();
    window.history.pushState({}, "", "/");
  });

  it("renders /verify for logged-out visitors even when the current-user request returns 401", async () => {
    renderAt("/verify");

    expect(await screen.findByRole("heading", { name: /verify a garment/i })).toBeInTheDocument();
    expect(screen.getByLabelText(/qr label code/i)).toBeInTheDocument();
    expect(window.location.pathname).toBe("/verify");
    expect(apiClient.getCurrentUser).not.toHaveBeenCalled();
  });

  it("canonicalizes /verify/ to /verify without blanking the public entry page", async () => {
    renderAt("/verify/");

    await waitFor(() => expect(window.location.pathname).toBe("/verify"));
    expect(await screen.findByRole("heading", { name: /verify a garment/i })).toBeInTheDocument();
    expect(apiClient.getCurrentUser).not.toHaveBeenCalled();
  });

  it("does not request the operator session on the anonymous public homepage", async () => {
    renderAt("/");

    expect((await screen.findAllByRole("link", { name: /verify product/i })).length).toBeGreaterThan(0);
    expect(apiClient.getCurrentUser).not.toHaveBeenCalled();
  });

  it("still requests the operator session before protected route decisions", async () => {
    renderAt("/dashboard");

    await waitFor(() => expect(apiClient.getCurrentUser).toHaveBeenCalledTimes(1));
  });
});
