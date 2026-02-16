import React from "react";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { render, screen } from "@testing-library/react";
import Verify from "@/pages/Verify";
import apiClient from "@/lib/api-client";

vi.mock("@/lib/api-client", () => ({
  default: {
    verifyQRCode: vi.fn(),
    scanToken: vi.fn(),
    reportFraud: vi.fn(),
    submitIncidentReport: vi.fn(),
    submitProductFeedback: vi.fn(),
    captureRouteTransition: vi.fn(() => Promise.resolve({ success: true })),
  },
}));

describe("Verify page", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    Object.defineProperty(global.navigator, "geolocation", {
      configurable: true,
      value: {
        getCurrentPosition: (success: (pos: any) => void) => {
          success({ coords: { latitude: 10, longitude: 20, accuracy: 25 } });
        },
      },
    });
  });

  it("renders blocked state in StrictMode without falling back to unavailable", async () => {
    vi.mocked(apiClient.verifyQRCode).mockResolvedValue({
      success: true,
      data: {
        isAuthentic: false,
        code: "AADS0000006007",
        status: "BLOCKED",
        message: "This QR code has been blocked due to fraud or recall.",
        licensee: { id: "1", name: "sad", prefix: "AADS" },
        batch: {
          id: "b1",
          name: "test1",
          printedAt: "2026-02-12T22:35:38.530Z",
          manufacturer: { id: "m1", name: "facttest" },
        },
      },
    } as any);

    render(
      <React.StrictMode>
        <MemoryRouter initialEntries={["/verify/AADS0000006007"]}>
          <Routes>
            <Route path="/verify/:code" element={<Verify />} />
          </Routes>
        </MemoryRouter>
      </React.StrictMode>
    );

    expect(await screen.findByText("Blocked by Security")).toBeTruthy();
    expect(screen.queryByText("Verification Unavailable")).toBeNull();
    expect(vi.mocked(apiClient.verifyQRCode)).toHaveBeenCalledTimes(1);
  });
});
