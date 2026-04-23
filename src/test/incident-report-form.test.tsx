import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { fireEvent, render, screen } from "@testing-library/react";

import Verify from "@/pages/Verify";
import apiClient from "@/lib/api-client";

vi.mock("@/lib/api-client", () => ({
  default: {
    verifyQRCode: vi.fn(),
    scanToken: vi.fn(),
    startVerificationSession: vi.fn(),
    getVerificationSession: vi.fn(),
    getCustomerAuthProviders: vi.fn(),
    getCustomerAuthSession: vi.fn(),
    getCustomerPasskeyCredentials: vi.fn(),
    submitProductFeedback: vi.fn(),
    reportFraud: vi.fn(),
    captureRouteTransition: vi.fn(() => Promise.resolve({ success: true })),
    trackSupportTicket: vi.fn(),
  },
}));

describe("Incident report form", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(apiClient.getCustomerAuthProviders).mockResolvedValue({
      success: true,
      data: { items: [] },
    } as any);
    vi.mocked(apiClient.getCustomerAuthSession).mockResolvedValue({
      success: true,
      data: { customer: null, auth: { cookieBacked: true, authenticated: false } },
    } as any);
    vi.mocked(apiClient.getCustomerPasskeyCredentials).mockResolvedValue({
      success: true,
      data: { items: [] },
    } as any);
    Object.defineProperty(globalThis.navigator, "geolocation", {
      configurable: true,
      value: {
        getCurrentPosition: (success: (pos: any) => void) =>
          success({ coords: { latitude: 10, longitude: 20, accuracy: 25 } }),
      },
    });
  });

  it("keeps concern reporting unavailable until sign-in completes", async () => {
    vi.mocked(apiClient.getVerificationSession).mockResolvedValue({
      success: true,
      data: {
        sessionId: "session-1",
        decisionId: "decision-1",
        code: "TT0000000068",
        maskedCode: "TT00-0068",
        brandName: "MSCQR",
        entryMethod: "MANUAL_CODE",
        authState: "PENDING",
        intakeCompleted: false,
        revealed: false,
        startedAt: "2026-04-05T12:00:00.000Z",
        proofTier: "SIGNED_LABEL",
        proofSource: "SIGNED_LABEL",
        labelState: "PRINTED",
        printTrustState: "PRINT_CONFIRMED",
        verificationLocked: true,
      },
    } as any);

    render(
      <React.StrictMode>
        <MemoryRouter initialEntries={["/verify/TT0000000068?session=session-1"]}>
          <Routes>
            <Route path="/verify/:code" element={<Verify />} />
          </Routes>
        </MemoryRouter>
      </React.StrictMode>
    );

    expect(await screen.findByText("Verify who is checking this product")).toBeTruthy();
    expect(screen.queryByText("Reveal and report a concern")).toBeNull();
    expect(vi.mocked(apiClient.reportFraud)).toHaveBeenCalledTimes(0);
  });
});
