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
    submitIncidentReport: vi.fn(),
    submitFraudReport: vi.fn(),
    submitProductFeedback: vi.fn(),
    reportFraud: vi.fn(),
  },
}));

describe("Incident report form", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    Object.defineProperty(global.navigator, "geolocation", {
      configurable: true,
      value: {
        getCurrentPosition: (success: (pos: any) => void) =>
          success({ coords: { latitude: 10, longitude: 20, accuracy: 25 } }),
      },
    });
  });

  it("prevents submit when description is too short", async () => {
    vi.mocked(apiClient.verifyQRCode).mockResolvedValue({
      success: true,
      data: {
        isAuthentic: false,
        code: "TT0000000068",
        status: "REDEEMED",
        message: "Already verified.",
      },
    } as any);

    render(
      <React.StrictMode>
        <MemoryRouter initialEntries={["/verify/TT0000000068"]}>
          <Routes>
            <Route path="/verify/:code" element={<Verify />} />
          </Routes>
        </MemoryRouter>
      </React.StrictMode>
    );

    expect(await screen.findByText("Report suspected counterfeit")).toBeTruthy();
    fireEvent.click(screen.getByText("Report suspected counterfeit"));
    fireEvent.click(screen.getByText("Submit report"));
    expect(vi.mocked(apiClient.submitFraudReport)).toHaveBeenCalledTimes(0);
  });
});
