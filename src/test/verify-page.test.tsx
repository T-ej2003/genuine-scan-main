import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import Verify from "@/pages/Verify";
import apiClient from "@/lib/api-client";

vi.mock("@/lib/api-client", () => ({
  default: {
    verifyQRCode: vi.fn(),
    scanToken: vi.fn(),
    startVerificationSession: vi.fn(),
    getVerificationSession: vi.fn(),
    getCustomerAuthProviders: vi.fn(),
    exchangeCustomerOAuth: vi.fn(),
    submitVerificationIntake: vi.fn(),
    revealVerificationSession: vi.fn(),
    requestVerifyEmailOtp: vi.fn(),
    verifyEmailOtp: vi.fn(),
    reportFraud: vi.fn(),
    beginCustomerPasskeyRegistration: vi.fn(),
    finishCustomerPasskeyRegistration: vi.fn(),
    beginCustomerPasskeyAssertion: vi.fn(),
    finishCustomerPasskeyAssertion: vi.fn(),
    getCustomerPasskeyCredentials: vi.fn(),
    deleteCustomerPasskeyCredential: vi.fn(),
    claimVerifiedProduct: vi.fn(),
    acceptOwnershipTransfer: vi.fn(),
    captureRouteTransition: vi.fn(() => Promise.resolve({ success: true })),
  },
}));

const CODE = "AADS0000006007";
const SESSION_ID = "session-1";
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

const buildVerifyPayload = (overrides: Record<string, unknown> = {}) => ({
  isAuthentic: true,
  decisionId: "decision-1",
  decisionVersion: 1,
  code: CODE,
  status: "PRINTED",
  labelState: "PRINTED",
  printTrustState: "PRINT_CONFIRMED",
  message: "MSCQR confirmed this issued label is active.",
  proofSource: "SIGNED_LABEL",
  proofTier: "SIGNED_LABEL",
  publicOutcome: "SIGNED_LABEL_ACTIVE",
  riskDisposition: "CLEAR",
  messageKey: "signed_label_active",
  nextActionKey: "review_details",
  latestDecisionOutcome: "AUTHENTIC",
  classification: "FIRST_SCAN",
  reasonCodes: ["FIRST_SCAN", "SIGNED_LABEL"],
  customerTrustLevel: "ANONYMOUS",
  replacementStatus: "NONE",
  licensee: { id: "lic-1", name: "MSCQR Demo", brandName: "MSCQR", prefix: "MSC", supportEmail: "support@mscqr.com" },
  batch: { id: "batch-1", name: "Batch 1", printedAt: "2026-04-05T11:00:00.000Z" },
  ownershipStatus: {
    isClaimed: false,
    claimedAt: null,
    isOwnedByRequester: false,
    isClaimedByAnother: false,
    canClaim: true,
    matchMethod: null,
  },
  reasons: ["First successful customer verification recorded."],
  ...overrides,
});

const buildSession = (overrides: Record<string, unknown> = {}) => ({
  sessionId: SESSION_ID,
  decisionId: "decision-1",
  code: CODE,
  maskedCode: "AADS-6007",
  brandName: "MSCQR",
  entryMethod: "SIGNED_SCAN",
  authState: "PENDING",
  intakeCompleted: false,
  revealed: false,
  startedAt: "2026-04-05T12:00:00.000Z",
  proofTier: "SIGNED_LABEL",
  proofSource: "SIGNED_LABEL",
  labelState: "PRINTED",
  printTrustState: "PRINT_CONFIRMED",
  verificationLocked: true,
  ...overrides,
});

describe("Verify page", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    window.localStorage.clear();
    window.sessionStorage.clear();
    vi.mocked(apiClient.getCustomerAuthProviders).mockResolvedValue({
      success: true,
      data: { items: [] },
    } as any);
    vi.mocked(apiClient.getCustomerPasskeyCredentials).mockResolvedValue({
      success: true,
      data: { items: [] },
    } as any);
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

  it("creates a secure verification session and navigates to the canonical signed URL", async () => {
    vi.mocked(apiClient.scanToken).mockResolvedValue({
      success: true,
      data: buildVerifyPayload(),
    } as any);
    vi.mocked(apiClient.startVerificationSession).mockResolvedValue({
      success: true,
      data: buildSession({ sessionProofToken: "session-proof-1", proofBindingRequired: true }),
    } as any);
    vi.mocked(apiClient.getVerificationSession).mockResolvedValue({
      success: true,
      data: buildSession(),
    } as any);

    renderVerifyPage("/scan?t=signed-token");

    await waitFor(() => {
      expect(vi.mocked(apiClient.scanToken)).toHaveBeenCalledWith(
        "signed-token",
        expect.objectContaining({ device: expect.any(String) })
      );
    });

    await waitFor(() => {
      expect(vi.mocked(apiClient.startVerificationSession)).toHaveBeenCalledWith("decision-1", "SIGNED_SCAN", undefined);
    });

    await waitFor(() => {
      expect(vi.mocked(apiClient.getVerificationSession)).toHaveBeenCalledWith(SESSION_ID, undefined, "session-proof-1");
    });

    await waitFor(() => {
      expect(screen.getByTestId("location-probe")).toHaveTextContent(`/verify/${CODE}?session=${SESSION_ID}&t=signed-token`);
    });
  });

  it("holds the result behind identity when the session is not yet revealed", async () => {
    vi.mocked(apiClient.getVerificationSession).mockResolvedValue({
      success: true,
      data: buildSession(),
    } as any);

    renderVerifyPage(`/verify/${CODE}?session=${SESSION_ID}`);

    expect(await screen.findByText("Verify who is checking this product")).toBeInTheDocument();
    expect(screen.queryByText("What MSCQR checked")).toBeNull();
  });

  it("renders configured customer social providers from the backend", async () => {
    vi.mocked(apiClient.getVerificationSession).mockResolvedValue({
      success: true,
      data: buildSession(),
    } as any);
    vi.mocked(apiClient.getCustomerAuthProviders).mockResolvedValue({
      success: true,
      data: { items: [{ id: "google", label: "Google" }] },
    } as any);

    renderVerifyPage(`/verify/${CODE}?session=${SESSION_ID}`);

    const providerLink = await screen.findByRole("link", { name: "Continue with Google" });
    expect(providerLink).toHaveAttribute("href", expect.stringContaining("/verify/auth/oauth/google/start?"));
  });

  it("email OTP sign-in advances the user into the purchase questionnaire", async () => {
    vi.mocked(apiClient.getVerificationSession).mockResolvedValue({
      success: true,
      data: buildSession(),
    } as any);
    vi.mocked(apiClient.requestVerifyEmailOtp).mockResolvedValue({
      success: true,
      data: {
        challengeToken: "otp-challenge",
        expiresAt: "2026-04-05T12:10:00.000Z",
        maskedEmail: "ab***@example.com",
      },
    } as any);
    vi.mocked(apiClient.verifyEmailOtp).mockResolvedValue({
      success: true,
      data: {
        token: "customer-token",
        customer: {
          userId: "cust-1",
          email: "abhi@example.com",
          maskedEmail: "ab***@example.com",
        },
      },
    } as any);
    vi.mocked(apiClient.getCustomerPasskeyCredentials).mockResolvedValue({
      success: true,
      data: { items: [] },
    } as any);

    renderVerifyPage(`/verify/${CODE}?session=${SESSION_ID}`);

    fireEvent.change(await screen.findByLabelText("Email"), { target: { value: "abhi@example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Send code" }));

    await screen.findByText("Code sent to ab***@example.com.");

    fireEvent.change(screen.getByLabelText("6-digit code"), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify and continue" }));

    expect(await screen.findByText("Tell MSCQR how you obtained the product")).toBeInTheDocument();
  });

  it("reveals the locked result from the server-side session payload", async () => {
    vi.mocked(apiClient.getVerificationSession).mockResolvedValue({
      success: true,
      data: buildSession({
        authState: "VERIFIED",
        intakeCompleted: true,
        revealed: true,
        verification: buildVerifyPayload({
          customerTrustLevel: "ACCOUNT_TRUSTED",
          reasonCodes: ["FIRST_SCAN", "SIGNED_LABEL", "ACCOUNT_TRUSTED"],
        }),
        intake: {
          purchaseChannel: "online",
          sourceCategory: "marketplace",
          platformName: "Amazon",
          sellerName: "Example Seller",
          listingUrl: "https://example.com/listing",
          orderReference: "ORDER-123",
          packagingState: "sealed",
          packagingConcern: "none",
          scanReason: "routine_check",
          ownershipIntent: "verify_only",
          notes: "",
        },
      }),
    } as any);
    window.localStorage.setItem("mscqr_verify_customer_token", "customer-token");

    renderVerifyPage(`/verify/${CODE}?session=${SESSION_ID}`);

    expect(await screen.findByText("What MSCQR checked")).toBeInTheDocument();
    expect(screen.getByText("Signed label check")).toBeInTheDocument();
    expect(screen.getByText("Requester context")).toBeInTheDocument();
  });

  it("reports a concern with session and decision ids after reveal", async () => {
    vi.mocked(apiClient.getVerificationSession).mockResolvedValue({
      success: true,
      data: buildSession({
        authState: "VERIFIED",
        intakeCompleted: true,
        revealed: true,
        verification: buildVerifyPayload(),
        intake: {
          purchaseChannel: "offline",
          sourceCategory: "retail_store",
          storeName: "MSCQR Store",
          purchaseCity: "London",
          purchaseCountry: "UK",
          packagingState: "sealed",
          packagingConcern: "minor",
          scanReason: "packaging_concern",
          ownershipIntent: "report_concern",
          notes: "Packaging looked slightly off.",
        },
      }),
    } as any);
    vi.mocked(apiClient.reportFraud).mockResolvedValue({
      success: true,
      data: { supportTicketRef: "SUP-1001" },
    } as any);
    window.localStorage.setItem("mscqr_verify_customer_token", "customer-token");
    window.localStorage.setItem("mscqr_verify_customer_email", "abhi@example.com");

    renderVerifyPage(`/verify/${CODE}?session=${SESSION_ID}`);

    fireEvent.click(await screen.findByRole("button", { name: "Report concern" }));

    await waitFor(() => {
      expect(vi.mocked(apiClient.reportFraud)).toHaveBeenCalledWith(
        expect.objectContaining({
          code: CODE,
          sessionId: SESSION_ID,
          decisionId: "decision-1",
        })
      );
    });
  });

  it("lets a signed-in customer complete a replay review check and refresh the session", async () => {
    vi.mocked(apiClient.getVerificationSession)
      .mockResolvedValueOnce({
        success: true,
        data: buildSession({
          authState: "VERIFIED",
          challengeRequired: true,
          revealed: false,
          intakeCompleted: false,
        }),
      } as any)
      .mockResolvedValueOnce({
        success: true,
        data: buildSession({
          sessionId: "session-updated",
          authState: "VERIFIED",
          challengeCompleted: true,
          challengeCompletedBy: "CUSTOMER_IDENTITY",
          revealed: false,
          intakeCompleted: false,
        }),
      } as any);
    vi.mocked(apiClient.verifyQRCode).mockResolvedValue({
      success: true,
      data: buildVerifyPayload({
        classification: "SUSPICIOUS_DUPLICATE",
        publicOutcome: "REVIEW_REQUIRED",
        riskDisposition: "REVIEW_REQUIRED",
        challenge: {
          required: false,
          completed: true,
          completedBy: "CUSTOMER_IDENTITY",
        },
      }),
    } as any);
    vi.mocked(apiClient.startVerificationSession).mockResolvedValue({
      success: true,
      data: buildSession({
        sessionId: "session-updated",
        authState: "VERIFIED",
        challengeCompleted: true,
        challengeCompletedBy: "CUSTOMER_IDENTITY",
        sessionProofToken: "session-proof-updated",
        proofBindingRequired: true,
      }),
    } as any);
    window.localStorage.setItem("mscqr_verify_customer_token", "customer-token");
    window.localStorage.setItem("mscqr_verify_customer_email", "abhi@example.com");

    renderVerifyPage(`/verify/${CODE}?session=${SESSION_ID}`);

    expect(await screen.findByText("Additional review check required")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Re-check with verified identity" }));

    await waitFor(() => {
      expect(vi.mocked(apiClient.verifyQRCode)).toHaveBeenCalledWith(
        CODE,
        expect.objectContaining({
          customerToken: "customer-token",
          device: expect.any(String),
        })
      );
    });

    await waitFor(() => {
      expect(vi.mocked(apiClient.startVerificationSession)).toHaveBeenCalledWith("decision-1", "MANUAL_CODE", "customer-token");
    });

    await waitFor(() => {
      expect(screen.getByText(/completed the additional review check/i)).toBeInTheDocument();
    });

    await waitFor(() => {
      expect(screen.getByTestId("location-probe")).toHaveTextContent(`/verify/${CODE}?session=session-updated`);
    });
  });
});
