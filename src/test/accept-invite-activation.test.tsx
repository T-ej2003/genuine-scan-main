import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import AcceptInvite from "@/pages/AcceptInvite";

const { navigate, hydrate, preview, accept, verify, resend } = vi.hoisted(() => ({
  navigate: vi.fn(), hydrate: vi.fn(), preview: vi.fn(), accept: vi.fn(), verify: vi.fn(), resend: vi.fn(),
}));
vi.mock("react-router", async () => ({
  ...(await vi.importActual<typeof import("react-router")>("react-router")),
  useNavigate: () => navigate,
}));
vi.mock("@/contexts/AuthContext", () => ({ useAuth: () => ({ completeMfaSession: hydrate }) }));
vi.mock("@/lib/api-client", () => ({ default: {
  getInvitePreview: preview, acceptInvite: accept, verifyInviteActivation: verify, resendInviteActivation: resend,
} }));

describe("invite activation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    preview.mockResolvedValue({ success: true, data: {
      email: "invited@example.invalid", role: "LICENSEE_ADMIN", expiresAt: "2026-09-25T00:00:00Z",
      licenseeName: null, requiresConnector: false, challengeId: null, challengeCreatedAt: null,
    } });
    accept.mockResolvedValue({ success: true, data: { challengeId: "opaque-challenge", delivered: true } });
    verify.mockResolvedValue({ success: true, data: { user: { id: "user-1" }, auth: { sessionStage: "ACTIVE", authAssurance: "PASSWORD" } } });
  });

  it("does not navigate until OTP establishes frontend authentication state", async () => {
    render(<MemoryRouter initialEntries={["/accept-invite?token=opaque-invite"]}><AcceptInvite /></MemoryRouter>);
    await screen.findByText(/invited@example.invalid/);
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "Good-password-23!" } });
    fireEvent.change(screen.getByLabelText("Confirm password"), { target: { value: "Good-password-23!" } });
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    await waitFor(() => expect(accept).toHaveBeenCalledWith({
      token: "opaque-invite", password: "Good-password-23!", confirmPassword: "Good-password-23!", name: undefined,
    }));
    expect(navigate).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText("Verification code"), { target: { value: "000123" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify & Continue" }));
    await waitFor(() => expect(verify).toHaveBeenCalledWith("opaque-challenge", "000123"));
    await waitFor(() => expect(hydrate).toHaveBeenCalledWith({
      user: { id: "user-1" }, auth: { sessionStage: "ACTIVE", authAssurance: "PASSWORD" },
    }));
    expect(navigate).toHaveBeenCalledWith("/dashboard", { replace: true });
  });

  it("resumes a pending challenge without another password submission", async () => {
    preview.mockResolvedValue({ success: true, data: {
      email: "invited@example.invalid", role: "LICENSEE_ADMIN", expiresAt: "2026-09-25T00:00:00Z",
      licenseeName: null, requiresConnector: false, challengeId: "pending-challenge", challengeCreatedAt: "2026-09-23T00:00:00Z",
    } });
    resend.mockResolvedValue({ success: true, data: { challengeId: "replacement-challenge", delivered: true } });
    render(<MemoryRouter initialEntries={["/accept-invite?token=opaque-invite"]}><AcceptInvite /></MemoryRouter>);
    await screen.findByLabelText("Verification code");
    expect(accept).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Resend code" }));
    await waitFor(() => expect(resend).toHaveBeenCalledWith("pending-challenge"));
  });

  it("leaves a consumed OTP screen for normal login when activation committed without a session", async () => {
    verify.mockResolvedValue({ success: true, data: { activated: true, loginRequired: true } });
    render(<MemoryRouter initialEntries={["/accept-invite?token=opaque-invite"]}><AcceptInvite /></MemoryRouter>);
    await screen.findByText(/invited@example.invalid/);
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "Good-password-23!" } });
    fireEvent.change(screen.getByLabelText("Confirm password"), { target: { value: "Good-password-23!" } });
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    await screen.findByLabelText("Verification code");
    fireEvent.change(screen.getByLabelText("Verification code"), { target: { value: "000123" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify & Continue" }));
    await waitFor(() => expect(navigate).toHaveBeenCalledWith("/login", { replace: true }));
    expect(hydrate).not.toHaveBeenCalled();
  });
});
