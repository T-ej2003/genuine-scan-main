import React from "react";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { render, screen, waitFor } from "@testing-library/react";
import Verify from "@/pages/Verify";
import apiClient from "@/lib/api-client";

vi.mock("@/lib/api-client", () => ({
  default: {
    verifyQRCode: vi.fn(),
    scanToken: vi.fn(),
    reportFraud: vi.fn(),
    submitFraudReport: vi.fn(),
    submitProductFeedback: vi.fn(),
    requestVerifyEmailOtp: vi.fn(),
    verifyEmailOtp: vi.fn(),
    claimVerifiedProduct: vi.fn(),
    linkDeviceClaimToUser: vi.fn(),
    createOwnershipTransfer: vi.fn(),
    cancelOwnershipTransfer: vi.fn(),
    acceptOwnershipTransfer: vi.fn(),
    captureRouteTransition: vi.fn(() => Promise.resolve({ success: true })),
  },
}));

const CODE = "AADS0000006007";
const CUSTOMER_TOKEN_KEY = "authenticqr_verify_customer_token";
const TRANSFER_TOKEN_KEY = `authenticqr_verify_transfer_token:${CODE}`;
const localStorageStore = new Map<string, string>();

Object.defineProperty(window, "localStorage", {
  configurable: true,
  value: {
    getItem: (key: string) => localStorageStore.get(key) ?? null,
    setItem: (key: string, value: string) => {
      localStorageStore.set(key, value);
    },
    removeItem: (key: string) => {
      localStorageStore.delete(key);
    },
    clear: () => {
      localStorageStore.clear();
    },
  },
});

const renderVerifyPage = (path = `/verify/${CODE}`) =>
  render(
    <React.StrictMode>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/verify/:code" element={<Verify />} />
        </Routes>
      </MemoryRouter>
    </React.StrictMode>
  );

const buildVerifyResponse = (overrides: Record<string, unknown> = {}) => ({
  success: true,
  data: {
    isAuthentic: true,
    code: CODE,
    status: "ACTIVE",
    message: "Verified.",
    classification: "FIRST_SCAN",
    licensee: { id: "1", name: "sad", prefix: "AADS" },
    batch: {
      id: "b1",
      name: "test1",
      printedAt: "2026-02-12T22:35:38.530Z",
      manufacturer: { id: "m1", name: "facttest" },
    },
    ownershipStatus: {
      isClaimed: false,
      claimedAt: null,
      isOwnedByRequester: false,
      isClaimedByAnother: false,
      canClaim: true,
      matchMethod: null,
    },
    ownershipTransfer: {
      state: "none",
      active: false,
      canCreate: false,
      canCancel: false,
      canAccept: false,
    },
    verifyUxPolicy: {
      allowOwnershipClaim: true,
      allowFraudReport: true,
    },
    ...overrides,
  },
});

describe("Verify page", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    window.localStorage.clear();
    Object.defineProperty(global.navigator, "geolocation", {
      configurable: true,
      value: {
        getCurrentPosition: (success: (pos: GeolocationPosition) => void) => {
          success({
            coords: {
              latitude: 10,
              longitude: 20,
              accuracy: 25,
              altitude: null,
              altitudeAccuracy: null,
              heading: null,
              speed: null,
            },
            timestamp: Date.now(),
          } as GeolocationPosition);
        },
      },
    });
  });

  it("renders blocked state in StrictMode without falling back to unavailable", async () => {
    vi.mocked(apiClient.verifyQRCode).mockResolvedValue({
      success: true,
      data: {
        isAuthentic: false,
        code: CODE,
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
    } as unknown as Awaited<ReturnType<typeof apiClient.verifyQRCode>>);

    renderVerifyPage();

    expect(await screen.findByText("Blocked by Security")).toBeTruthy();
    expect(screen.queryByText("Verification Unavailable")).toBeNull();
    expect(vi.mocked(apiClient.verifyQRCode)).toHaveBeenCalledTimes(1);
  });

  it("explains that an owner must sign in before starting a resale transfer", async () => {
    vi.mocked(apiClient.verifyQRCode).mockResolvedValue(
      buildVerifyResponse({
        ownershipStatus: {
          isClaimed: true,
          claimedAt: "2026-03-11T10:40:14.000Z",
          isOwnedByRequester: true,
          isClaimedByAnother: false,
          canClaim: false,
          matchMethod: "device_token",
        },
      }) as unknown as Awaited<ReturnType<typeof apiClient.verifyQRCode>>
    );

    renderVerifyPage();

    expect(await screen.findByText("Sign in below to start a secure resale transfer.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign in to continue" })).toBeInTheDocument();
  });

  it("reuses a saved transfer token so the owner can recover the transfer link after refresh", async () => {
    window.localStorage.setItem(CUSTOMER_TOKEN_KEY, "cust-session-token");
    window.localStorage.setItem(TRANSFER_TOKEN_KEY, "saved-transfer-token");
    vi.mocked(apiClient.verifyQRCode).mockResolvedValue(
      buildVerifyResponse({
        ownershipStatus: {
          isClaimed: true,
          claimedAt: "2026-03-11T10:40:14.000Z",
          isOwnedByRequester: true,
          isClaimedByAnother: false,
          canClaim: false,
          matchMethod: "user",
        },
        ownershipTransfer: {
          state: "pending_owner_action",
          active: true,
          canCreate: false,
          canCancel: true,
          canAccept: false,
          initiatedByYou: true,
          initiatedAt: "2026-03-11T11:00:00.000Z",
          expiresAt: "2026-03-14T11:00:00.000Z",
          acceptUrl: `https://mscqr.com/verify/${CODE}?transfer=saved-transfer-token`,
        },
      }) as unknown as Awaited<ReturnType<typeof apiClient.verifyQRCode>>
    );

    renderVerifyPage();

    await waitFor(() => {
      expect(vi.mocked(apiClient.verifyQRCode)).toHaveBeenCalledWith(
        CODE,
        expect.objectContaining({
          customerToken: "cust-session-token",
          transferToken: "saved-transfer-token",
        })
      );
    });

    expect(await screen.findByRole("button", { name: "Copy transfer link" })).toBeInTheDocument();
  });
});
