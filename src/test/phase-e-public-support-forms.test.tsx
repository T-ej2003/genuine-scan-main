import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import { RequestAccessPage } from "@/pages/PublicMarketing";
import SupportHelp from "@/pages/help/Support";
import apiClient from "@/lib/api-client";

vi.mock("@/contexts/AuthContext", () => ({
  useAuth: () => ({
    isAuthenticated: false,
    user: null,
  }),
}));

vi.mock("@/lib/api-client", () => ({
  default: {
    submitRequestAccess: vi.fn(),
    submitPublicSupportIssue: vi.fn(),
  },
}));

describe("Phase E public support forms", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(apiClient.submitRequestAccess).mockResolvedValue({
      success: true,
      data: {
        referenceCode: "RA-260604-ABC123",
        status: "NEW",
        emailDeliveryStatus: "DRY_RUN",
        acknowledgementEmailDeliveryStatus: "DRY_RUN",
        message: "Request received. MSCQR will review your access request.",
      },
    } as any);
    vi.mocked(apiClient.submitPublicSupportIssue).mockResolvedValue({
      success: true,
      data: {
        referenceCode: "SUP-260604-XYZ789",
        status: "OPEN",
        emailDeliveryStatus: "DRY_RUN",
        acknowledgementEmailDeliveryStatus: "DRY_RUN",
        message: "Support request received. Keep this reference for follow-up.",
      },
    } as any);
  });

  it("submits request access to the backend and shows a reference", async () => {
    render(
      <MemoryRouter>
        <RequestAccessPage />
      </MemoryRouter>
    );

    fireEvent.change(screen.getByLabelText("Full name"), { target: { value: "Asha Patel" } });
    fireEvent.change(screen.getByLabelText("Work email"), { target: { value: "asha@brand.example" } });
    fireEvent.change(screen.getByLabelText("Company / brand name"), { target: { value: "Phase E Brand" } });
    fireEvent.change(screen.getByLabelText("Role"), { target: { value: "Operations lead" } });
    fireEvent.change(screen.getByLabelText("Monthly garment volume"), { target: { value: "25,000 garments" } });
    fireEvent.change(screen.getByLabelText("Country"), { target: { value: "United Kingdom" } });
    fireEvent.change(screen.getByLabelText("Message"), {
      target: { value: "We need QR-labelled garment authentication for production batches." },
    });

    fireEvent.click(screen.getByRole("button", { name: "Submit request" }));

    await waitFor(() => {
      expect(apiClient.submitRequestAccess).toHaveBeenCalledWith(
        expect.objectContaining({
          fullName: "Asha Patel",
          workEmail: "asha@brand.example",
          companyName: "Phase E Brand",
          website: "",
        })
      );
    });
    expect(await screen.findByText(/RA-260604-ABC123/)).toBeInTheDocument();
  });

  it("submits public support and shows a tracking reference", async () => {
    render(
      <MemoryRouter>
        <SupportHelp />
      </MemoryRouter>
    );

    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Customer Reporter" } });
    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "customer@example.test" } });
    fireEvent.change(screen.getByLabelText("Subject"), {
      target: { value: "Scan result does not match garment" },
    });
    fireEvent.change(screen.getByLabelText("Verification code or QR token"), {
      target: { value: "MSCQR-PHASE-E" },
    });
    fireEvent.change(screen.getByLabelText("What happened?"), {
      target: { value: "The verification page result looks different from the garment label I scanned." },
    });

    fireEvent.click(screen.getByRole("button", { name: "Send support request" }));

    await waitFor(() => {
      expect(apiClient.submitPublicSupportIssue).toHaveBeenCalledWith(
        expect.objectContaining({
          email: "customer@example.test",
          issueType: "verification_result",
          verificationCode: "MSCQR-PHASE-E",
          website: "",
        })
      );
    });
    expect(await screen.findByText(/SUP-260604-XYZ789/)).toBeInTheDocument();
  });
});
