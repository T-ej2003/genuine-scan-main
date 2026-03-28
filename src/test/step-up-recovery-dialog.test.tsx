import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";

import StepUpRecoveryDialog from "@/components/auth/StepUpRecoveryDialog";

const {
  refreshMock,
  toastMock,
  stepUpWithPasswordMock,
  stepUpWithAdminMfaMock,
  authState,
} = vi.hoisted(() => ({
  refreshMock: vi.fn(),
  toastMock: vi.fn(),
  stepUpWithPasswordMock: vi.fn(),
  stepUpWithAdminMfaMock: vi.fn(),
  authState: {
    user: { role: "manufacturer" as const },
  },
}));

const authStateTyped = authState as {
  user: { role: "manufacturer" | "super_admin" },
};

vi.mock("@/contexts/AuthContext", () => ({
  useAuth: () => ({
    user: authStateTyped.user,
    refresh: refreshMock,
  }),
}));

vi.mock("@/hooks/use-toast", () => ({
  useToast: () => ({
    toast: toastMock,
  }),
}));

vi.mock("@/lib/api-client", () => ({
  default: {
    stepUpWithPassword: stepUpWithPasswordMock,
    stepUpWithAdminMfa: stepUpWithAdminMfaMock,
  },
}));

describe("StepUpRecoveryDialog", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    authStateTyped.user = { role: "manufacturer" };
    stepUpWithPasswordMock.mockResolvedValue({ success: true });
    stepUpWithAdminMfaMock.mockResolvedValue({ success: true });
  });

  it("handles password reauthentication from a global step-up event", async () => {
    render(<StepUpRecoveryDialog />);

    await act(async () => {
      window.dispatchEvent(
        new CustomEvent("auth:step-up-required", {
          detail: {
            stepUpMethod: "PASSWORD_REAUTH",
            message: "Confirm your password to continue.",
          },
        })
      );
    });

    expect(await screen.findByText("Confirm Your Password")).toBeInTheDocument();

    await act(async () => {
      fireEvent.change(screen.getByLabelText("Current password"), { target: { value: "password123" } });
      fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    });

    await waitFor(() => {
      expect(stepUpWithPasswordMock).toHaveBeenCalledWith("password123");
    });
    await waitFor(() => {
      expect(refreshMock).toHaveBeenCalled();
    });
  });

  it("handles admin MFA reauthentication from a global step-up event", async () => {
    authStateTyped.user = { role: "super_admin" };

    render(<StepUpRecoveryDialog />);

    await act(async () => {
      window.dispatchEvent(
        new CustomEvent("auth:step-up-required", {
          detail: {
            stepUpMethod: "ADMIN_MFA",
            message: "Confirm your authenticator code to continue.",
          },
        })
      );
    });

    expect(await screen.findByText("Confirm Admin Verification")).toBeInTheDocument();

    await act(async () => {
      fireEvent.change(screen.getByLabelText("Authenticator or backup code"), { target: { value: "123456" } });
      fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    });

    await waitFor(() => {
      expect(stepUpWithAdminMfaMock).toHaveBeenCalledWith("123456");
    });
  });
});
