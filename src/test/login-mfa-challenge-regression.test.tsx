import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";

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

vi.mock("react-router", async () => {
  const actual = await vi.importActual<typeof import("react-router")>("react-router");
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
      expect(completeChallengeMock).toHaveBeenCalledWith("ticket-1", "ABCDE-12345", "backup_code");
    });
    await waitFor(() => {
      expect(completeMfaSessionMock).toHaveBeenCalled();
      expect(navigateMock).toHaveBeenCalledWith("/dashboard");
    });
  });

  it("prevents duplicate authenticator submissions while verification is in flight", async () => {
    let resolveComplete: (value: unknown) => void = () => undefined;
    completeChallengeMock.mockReturnValue(
      new Promise((resolve) => {
        resolveComplete = resolve;
      })
    );

    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );

    await waitFor(() => expect(beginChallengeMock).toHaveBeenCalled());

    fireEvent.change(screen.getByLabelText("Authenticator code"), { target: { value: "123456" } });
    const submit = screen.getByRole("button", { name: "Open secure session" });
    fireEvent.click(submit);
    fireEvent.click(submit);

    expect(completeChallengeMock).toHaveBeenCalledTimes(1);
    expect(completeChallengeMock).toHaveBeenCalledWith("ticket-1", "123456", "totp");

    resolveComplete({
      success: true,
      data: { user: { id: "admin-1" }, auth: { sessionStage: "ACTIVE" } },
    });

    await waitFor(() => expect(navigateMock).toHaveBeenCalledWith("/dashboard"));
  });

  it("single-flights MFA challenge begin under StrictMode double effects", async () => {
    let resolveBegin: (value: unknown) => void = () => undefined;
    beginChallengeMock.mockReturnValue(
      new Promise((resolve) => {
        resolveBegin = resolve;
      })
    );

    render(
      <React.StrictMode>
        <MemoryRouter>
          <Login />
        </MemoryRouter>
      </React.StrictMode>
    );

    await waitFor(() => expect(beginChallengeMock).toHaveBeenCalledTimes(1));

    resolveBegin({
      success: true,
      data: {
        ticket: "ticket-1",
        expiresAt: "2026-04-10T10:00:00.000Z",
      },
    });

    await waitFor(() => expect(screen.getByLabelText("Authenticator code")).toBeInTheDocument());
  });

  it("shows invalid-code copy for 400 without expiring the current challenge", async () => {
    completeChallengeMock.mockResolvedValue({
      success: false,
      status: 400,
      error: "Invalid authentication code.",
    });

    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );

    await waitFor(() => expect(beginChallengeMock).toHaveBeenCalled());

    fireEvent.change(screen.getByLabelText("Authenticator code"), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Open secure session" }));

    expect(await screen.findByText("The security code could not be verified. Check the code and try again.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Open secure session" })).not.toBeDisabled();
  });

  it("shows Retry-After copy for 429 without starting a new challenge loop", async () => {
    completeChallengeMock.mockResolvedValue({
      success: false,
      status: 429,
      retryAfterSec: 60,
      error: "Too many attempts.",
    });

    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );

    await waitFor(() => expect(beginChallengeMock).toHaveBeenCalledTimes(1));

    fireEvent.change(screen.getByLabelText("Authenticator code"), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Open secure session" }));

    expect(await screen.findByText("Too many attempts. Please wait 60 seconds.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Open secure session" })).not.toBeDisabled();
    expect(beginChallengeMock).toHaveBeenCalledTimes(1);
  });

  it("shows expired-session copy for 410 and stops stale challenge retries", async () => {
    completeChallengeMock.mockResolvedValue({
      success: false,
      status: 410,
      error: "This MFA challenge expired. Start again.",
    });

    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );

    await waitFor(() => expect(beginChallengeMock).toHaveBeenCalledTimes(1));

    fireEvent.change(screen.getByLabelText("Authenticator code"), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Open secure session" }));

    expect(await screen.findByText("This verification session expired. Start sign-in again.")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole("button", { name: "Open secure session" })).toBeDisabled());
    expect(beginChallengeMock).toHaveBeenCalledTimes(1);
  });
});
