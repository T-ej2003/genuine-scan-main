import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import Manufacturers from "@/pages/Manufacturers";
import apiClient from "@/lib/api-client";

const toast = vi.fn();
const mockNavigate = vi.fn();

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual<typeof import("react-router-dom")>("react-router-dom");
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

vi.mock("@/contexts/AuthContext", () => ({
  useAuth: () => ({
    user: {
      id: "licensee-admin-1",
      role: "licensee_admin",
      licenseeId: "lic-1",
      name: "Licensee Ops",
      email: "ops@example.com",
    },
  }),
}));

vi.mock("@/components/layout/DashboardLayout", () => ({
  DashboardLayout: ({ children }: any) => <div>{children}</div>,
}));

vi.mock("@/hooks/use-toast", () => ({
  useToast: () => ({
    toast,
  }),
}));

vi.mock("@/lib/mutation-events", () => ({
  onMutationEvent: () => () => undefined,
}));

vi.mock("@/lib/api-client", () => ({
  default: {
    getManufacturers: vi.fn(),
    getBatches: vi.fn(),
    getUsers: vi.fn(),
    inviteUser: vi.fn(),
    deactivateManufacturer: vi.fn(),
    restoreManufacturer: vi.fn(),
    hardDeleteManufacturer: vi.fn(),
  },
}));

describe("Manufacturers licensee linking flow", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockNavigate.mockReset();
    toast.mockReset();

    vi.mocked(apiClient.getManufacturers).mockResolvedValue({ success: true, data: [] } as any);
    vi.mocked(apiClient.getBatches).mockResolvedValue({ success: true, data: [] } as any);
    vi.mocked(apiClient.getUsers).mockResolvedValue({ success: true, data: [] } as any);
    vi.mocked(apiClient.inviteUser).mockResolvedValue({
      success: true,
      data: { linkAction: "LINKED_EXISTING" },
    } as any);
  });

  it("links an existing manufacturer into the current licensee scope", async () => {
    render(
      <MemoryRouter>
        <Manufacturers />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(vi.mocked(apiClient.getManufacturers)).toHaveBeenCalledWith(
        expect.objectContaining({
          licenseeId: "lic-1",
          includeInactive: true,
        })
      );
    });

    fireEvent.click(screen.getByRole("button", { name: "Add Manufacturer" }));
    fireEvent.change(screen.getByPlaceholderText("Factory A"), { target: { value: "Factory A" } });
    fireEvent.change(screen.getByPlaceholderText("factory@example.com"), { target: { value: "factory@example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Send invite" }));

    await waitFor(() => {
      expect(vi.mocked(apiClient.inviteUser)).toHaveBeenCalledWith(
        expect.objectContaining({
          email: "factory@example.com",
          name: "Factory A",
          role: "MANUFACTURER",
          licenseeId: "lic-1",
          allowExistingInvitedUser: true,
        })
      );
    });

    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({
        title: "Manufacturer linked",
      })
    );
  });
});
