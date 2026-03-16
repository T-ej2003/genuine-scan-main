import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import Login from "@/pages/Login";
import apiClient from "@/lib/api-client";

const navigateMock = vi.fn();
const loginMock = vi.fn();
const completeMfaLoginMock = vi.fn();

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return {
    ...actual,
    useNavigate: () => navigateMock,
  };
});

vi.mock("@/contexts/AuthContext", () => ({
  useAuth: () => ({
    login: loginMock,
    completeMfaLogin: completeMfaLoginMock,
  }),
}));

vi.mock("@/lib/api-client", () => ({
  default: {
    beginMfaBootstrapSetup: vi.fn(),
    confirmMfaBootstrapSetup: vi.fn(),
  },
}));

describe("Login required MFA setup", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    loginMock.mockResolvedValue({
      success: false,
      mfaSetupRequired: true,
      mfaSetupToken: "bootstrap-ticket",
      email: "admin@example.com",
      role: "PLATFORM_SUPER_ADMIN",
    });
    vi.mocked(apiClient.beginMfaBootstrapSetup).mockResolvedValue({
      success: true,
      data: {
        secret: "ABCDEF123456",
        otpauthUri: "otpauth://totp/MSCQR:admin@example.com?secret=ABCDEF123456",
        backupCodes: ["AAAAA-BBBBB", "CCCCC-DDDDD"],
      },
    } as any);
  });

  it("switches into MFA enrollment when a privileged login is not yet enrolled", async () => {
    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>
    );

    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "admin@example.com" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "password123" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));

    await waitFor(() => {
      expect(loginMock).toHaveBeenCalledWith("admin@example.com", "password123");
    });

    await waitFor(() => {
      expect(vi.mocked(apiClient.beginMfaBootstrapSetup)).toHaveBeenCalledWith("bootstrap-ticket");
    });

    expect(await screen.findByText("Set up multi-factor authentication")).toBeInTheDocument();
    expect(screen.getByText(/must enroll in MFA before portal access is granted/i)).toBeInTheDocument();
    expect(screen.getByText("AAAAA-BBBBB")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Enable MFA and continue" })).toBeInTheDocument();
    expect(navigateMock).not.toHaveBeenCalled();
  });
});
