import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import Login from "@/pages/Login";

const {
  navigateMock,
  completeMfaSessionMock,
  logoutMock,
  beginChallengeMock,
  completeChallengeMock,
  pendingAuthMock,
} = vi.hoisted(() => ({
  navigateMock: vi.fn(),
  completeMfaSessionMock: vi.fn(),
  logoutMock: vi.fn(),
  beginChallengeMock: vi.fn(),
  completeChallengeMock: vi.fn(),
  pendingAuthMock: {
    user: { email: "admin@example.com" },
    auth: {
      mfaEnrolled: true,
      availableMfaMethods: ["TOTP"],
      preferredMfaMethod: "TOTP",
    },
  },
}));

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return {
    ...actual,
    useNavigate: () => navigateMock,
  };
});

vi.mock("@/contexts/AuthContext", () => ({
  useAuth: () => ({
    login: vi.fn(),
    logout: logoutMock,
    completeMfaSession: completeMfaSessionMock,
    pendingAuth: pendingAuthMock,
  }),
}));

vi.mock("@/lib/api-client", () => ({
  default: {
    beginAdminMfaChallenge: beginChallengeMock,
    completeAdminMfaChallenge: completeChallengeMock,
  },
}));

describe("Login MFA challenge regression", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    beginChallengeMock.mockResolvedValue({
      success: true,
      data: {
        ticket: "ticket-1",
        expiresAt: "2026-04-10T10:00:00.000Z",
      },
    });
    completeChallengeMock.mockResolvedValue({
      success: true,
      data: {
        user: { id: "admin-1" },
        auth: { sessionStage: "ACTIVE" },
      },
    });
  });

  it("submits backup code separately in challenge mode", async () => {
    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(beginChallengeMock).toHaveBeenCalled();
    });

    await waitFor(() => {
      const backupButtons = screen.getAllByRole("button", { name: "Backup code" });
      expect(backupButtons[backupButtons.length - 1]).not.toBeDisabled();
    });

    await act(async () => {
      const backupButtons = screen.getAllByRole("button", { name: "Backup code" });
      fireEvent.click(backupButtons[backupButtons.length - 1]);
    });

    await waitFor(() => {
      expect(screen.getByLabelText("Backup code")).toBeInTheDocument();
    });

    await act(async () => {
      fireEvent.change(screen.getByLabelText("Backup code"), { target: { value: "abcde-12345" } });
      fireEvent.click(screen.getByRole("button", { name: "Open secure session" }));
    });

    await waitFor(() => {
      expect(completeChallengeMock).toHaveBeenCalledWith("ticket-1", "ABCDE-12345");
    });
    await waitFor(() => {
      expect(completeMfaSessionMock).toHaveBeenCalled();
      expect(navigateMock).toHaveBeenCalledWith("/dashboard");
    });
  });
});
