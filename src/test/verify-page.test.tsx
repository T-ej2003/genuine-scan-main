import React from "react";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
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
    beginCustomerPasskeyRegistration: vi.fn(),
    finishCustomerPasskeyRegistration: vi.fn(),
    beginCustomerPasskeyAssertion: vi.fn(),
    finishCustomerPasskeyAssertion: vi.fn(),
    getCustomerPasskeyCredentials: vi.fn(),
    deleteCustomerPasskeyCredential: vi.fn(),
    claimVerifiedProduct: vi.fn(),
    linkDeviceClaimToUser: vi.fn(),
    createOwnershipTransfer: vi.fn(),
    cancelOwnershipTransfer: vi.fn(),
    acceptOwnershipTransfer: vi.fn(),
    captureRouteTransition: vi.fn(() => Promise.resolve({ success: true })),
  },
}));

const CODE = "AADS0000006007";
const CUSTOMER_TOKEN_KEY = "mscqr_verify_customer_token";
const TRANSFER_TOKEN_KEY = `mscqr_verify_transfer_token:${CODE}`;
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
        <LocationProbe />
        <Routes>
          <Route path="/verify/:code" element={<Verify />} />
          <Route path="/scan" element={<Verify />} />
        </Routes>
      </MemoryRouter>
    </React.StrictMode>
  );

function LocationProbe() {
  const location = useLocation();
  return <div data-testid="location-probe">{`${location.pathname}${location.search}`}</div>;
}

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
    Object.defineProperty(globalThis.navigator, "geolocation", {
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

  it("explains that an owner must sign in before starting a transfer", async () => {
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

    expect(await screen.findByText("Sign in below to start a secure ownership transfer.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign in to continue" })).toBeInTheDocument();
  });

  it("keeps trusted repeat activity out of the suspicious duplicate state", async () => {
    vi.mocked(apiClient.verifyQRCode).mockResolvedValue(
      buildVerifyResponse({
        classification: undefined,
        isFirstScan: false,
        status: "SCANNED",
        activitySummary: {
          state: "trusted_repeat",
          summary: "9 recent scans matched the same owner or trusted device in the last 24 hours.",
          trustedOwnerScanCount24h: 9,
          trustedOwnerScanCount10m: 6,
          untrustedScanCount24h: 0,
          untrustedScanCount10m: 0,
          distinctTrustedActorCount24h: 1,
          distinctUntrustedDeviceCount24h: 0,
          currentActorTrustedOwnerContext: true,
        },
        scanSignals: {
          distinctDeviceCount24h: 4,
          recentScanCount10m: 6,
          distinctCountryCount24h: 1,
          currentActorTrustedOwnerContext: true,
          trustedOwnerScanCount24h: 9,
          trustedOwnerScanCount10m: 6,
          untrustedScanCount24h: 0,
          untrustedScanCount10m: 0,
          distinctTrustedActorCount24h: 1,
          distinctUntrustedDeviceCount24h: 0,
          distinctUntrustedCountryCount24h: 0,
        },
      }) as unknown as Awaited<ReturnType<typeof apiClient.verifyQRCode>>
    );

    renderVerifyPage();

    expect(await screen.findByText("Verified Again")).toBeInTheDocument();
    expect(screen.queryByText("Suspicious Duplicate")).toBeNull();
    expect(screen.getByText("Trusted repeat activity (24h)")).toBeInTheDocument();
    expect(screen.getAllByText("9 recent scans matched the same owner or trusted device in the last 24 hours.").length).toBeGreaterThan(0);
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

    expect(await screen.findByRole("button", { name: "Copy handover link" })).toBeInTheDocument();
  });

  it("hydrates stored customer auth before the first scan request so refresh does not double-hit the public endpoint", async () => {
    window.localStorage.setItem(CUSTOMER_TOKEN_KEY, "cust-session-token");
    vi.mocked(apiClient.scanToken).mockResolvedValue(
      buildVerifyResponse({
        code: CODE,
      }) as unknown as Awaited<ReturnType<typeof apiClient.scanToken>>
    );

    renderVerifyPage("/scan?t=signed-scan-token");

    await waitFor(() => {
      expect(vi.mocked(apiClient.scanToken)).toHaveBeenCalledTimes(1);
    });

    expect(vi.mocked(apiClient.scanToken)).toHaveBeenCalledWith(
      "signed-scan-token",
      expect.objectContaining({
        customerToken: "cust-session-token",
      })
    );
    expect(await screen.findByText("Verified Authentic")).toBeInTheDocument();
  });

  it("keeps the signed token on the canonical verify URL after a successful signed scan", async () => {
    vi.mocked(apiClient.scanToken).mockResolvedValue(
      buildVerifyResponse({
        code: CODE,
        proofSource: "SIGNED_LABEL",
      }) as unknown as Awaited<ReturnType<typeof apiClient.scanToken>>
    );

    renderVerifyPage("/scan?t=signed-scan-token");

    await waitFor(() => {
      expect(screen.getByTestId("location-probe")).toHaveTextContent(`/verify/${CODE}?t=signed-scan-token`);
    });
  });

  it("shows proof tier and requester trust from the unified verification decision contract", async () => {
    vi.mocked(apiClient.verifyQRCode).mockResolvedValue(
      buildVerifyResponse({
        decisionId: "dec_123",
        decisionVersion: 1,
        proofSource: "SIGNED_LABEL",
        proofTier: "SIGNED_LABEL",
        customerTrustLevel: "ACCOUNT_TRUSTED",
        printTrustState: "PRINT_CONFIRMED",
        reasonCodes: ["FIRST_SCAN", "SIGNED_LABEL"],
      }) as unknown as Awaited<ReturnType<typeof apiClient.verifyQRCode>>
    );

    renderVerifyPage();

    expect(await screen.findByText("Proof tier: signed label")).toBeInTheDocument();
    expect(screen.getByText("Requester trust: signed-in account")).toBeInTheDocument();
    expect(screen.getByText("Decision Trace")).toBeInTheDocument();
  });

  it("shows passkey requester trust when the session was step-up verified", async () => {
    vi.mocked(apiClient.verifyQRCode).mockResolvedValue(
      buildVerifyResponse({
        customerTrustLevel: "PASSKEY_VERIFIED",
      }) as unknown as Awaited<ReturnType<typeof apiClient.verifyQRCode>>
    );

    renderVerifyPage();

    expect(await screen.findByText("Requester trust: passkey verified")).toBeInTheDocument();
  });
});
