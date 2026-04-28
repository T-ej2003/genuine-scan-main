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
    } as any);
  });

  afterEach(() => {
    cleanup();
    window.history.pushState({}, "", "/");
  });

  it("renders /verify for logged-out visitors even when the current-user request returns 401", async () => {
    renderAt("/verify");

    expect(
      await screen.findByRole("heading", { name: /check a product without losing the evidence trail/i }),
    ).toBeInTheDocument();
    expect(screen.getByLabelText(/label code/i)).toBeInTheDocument();
    expect(window.location.pathname).toBe("/verify");
  });

  it("canonicalizes /verify/ to /verify without blanking the public entry page", async () => {
    renderAt("/verify/");

    await waitFor(() => expect(window.location.pathname).toBe("/verify"));
    expect(
      await screen.findByRole("heading", { name: /check a product without losing the evidence trail/i }),
    ).toBeInTheDocument();
  });
});
