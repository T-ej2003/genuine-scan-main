import React from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter, Route, Routes, useLocation } from "react-router";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";

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
    logoutCustomerVerifySession: vi.fn().mockResolvedValue({ success: true, data: { cleared: true } }),
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
  sessionStartToken: "session-start-1",
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
  licensee: {
    id: "lic-1",
    name: "MSCQR Demo",
    brandName: "MSCQR",
    prefix: "MSC",
    website: "https://brand.example/verify",
    supportEmail: "support@mscqr.com",
    supportPhone: "+44 20 0000 0000",
  },
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
    } as never);
    vi.mocked(apiClient.getCustomerAuthSession).mockResolvedValue({
      success: true,
      data: { customer: null, auth: { cookieBacked: true, authenticated: false } },
    } as never);
    vi.mocked(apiClient.getCustomerPasskeyCredentials).mockResolvedValue({
      success: true,
      data: { items: [] },
    } as never);
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
      data: buildVerifyPayload({ decisionId: undefined, sessionStartToken: "session-start-1" }),
    } as never);
    vi.mocked(apiClient.startVerificationSession).mockResolvedValue({
      success: true,
      data: buildSession({ sessionProofToken: "session-proof-1", proofBindingRequired: true }),
    } as never);
    vi.mocked(apiClient.getVerificationSession).mockResolvedValue({
      success: true,
      data: buildSession(),
    } as never);

    renderVerifyPage("/scan?t=signed-token");

    await waitFor(() => {
      expect(vi.mocked(apiClient.scanToken)).toHaveBeenCalledWith(
        "signed-token",
        expect.objectContaining({ device: expect.any(String) })
      );
    });

    await waitFor(() => {
      expect(vi.mocked(apiClient.startVerificationSession)).toHaveBeenCalledWith("session-start-1", "SIGNED_SCAN");
    });

    await waitFor(() => {
      expect(vi.mocked(apiClient.getVerificationSession)).toHaveBeenCalledWith(SESSION_ID, "session-proof-1");
    });

    await waitFor(() => {
      expect(screen.getByTestId("location-probe")).toHaveTextContent(`/verify/${CODE}?session=${SESSION_ID}`);
    });
    expect(screen.getByTestId("location-probe")).not.toHaveTextContent("signed-token");
  });

  it("shows a calm quick-check state when the session is not yet revealed", async () => {
    vi.mocked(apiClient.getVerificationSession).mockResolvedValue({
      success: true,
      data: buildSession(),
    } as never);

    renderVerifyPage(`/verify/${CODE}?session=${SESSION_ID}`);

    expect(await screen.findByText("We need one quick check before showing the full result.")).toBeInTheDocument();
    expect(screen.queryByText("Result details")).toBeNull();
  });

  it("renders configured customer social providers from the backend", async () => {
    vi.mocked(apiClient.getVerificationSession).mockResolvedValue({
      success: true,
      data: buildSession(),
    } as never);
    vi.mocked(apiClient.getCustomerAuthProviders).mockResolvedValue({
      success: true,
      data: { items: [{ id: "google", label: "Google" }] },
    } as never);

    renderVerifyPage(`/verify/${CODE}?session=${SESSION_ID}`);

    const providerLink = await screen.findByRole("link", { name: "Continue with Google" });
    expect(providerLink).toHaveAttribute("href", expect.stringContaining("/verify/auth/oauth/google/start?"));
  });

  it("email sign-in advances the user into optional scan review questions", async () => {
    vi.mocked(apiClient.getVerificationSession).mockResolvedValue({
      success: true,
      data: buildSession(),
    } as never);
    vi.mocked(apiClient.requestVerifyEmailOtp).mockResolvedValue({
      success: true,
      data: {
        challengeToken: "otp-challenge",
        expiresAt: "2026-04-05T12:10:00.000Z",
        maskedEmail: "ab***@example.com",
      },
    } as never);
    vi.mocked(apiClient.verifyEmailOtp).mockResolvedValue({
      success: true,
      data: {
        customer: {
          userId: "cust-1",
          email: "abhi@example.com",
          maskedEmail: "ab***@example.com",
        },
        auth: {
          cookieBacked: true,
          authenticated: true,
          authStrength: "EMAIL_OTP",
        },
      },
    } as never);
    vi.mocked(apiClient.getCustomerPasskeyCredentials).mockResolvedValue({
      success: true,
      data: { items: [] },
    } as never);

    renderVerifyPage(`/verify/${CODE}?session=${SESSION_ID}`);

    fireEvent.change(await screen.findByLabelText("Email"), { target: { value: "abhi@example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Send code" }));

    await screen.findByText("Code sent. Check your email.");
    expect(screen.getByText("Sent to ab***@example.com.")).toBeInTheDocument();
    expect(vi.mocked(apiClient.requestVerifyEmailOtp)).toHaveBeenCalledWith("abhi@example.com");

    fireEvent.change(screen.getByLabelText("6-digit code"), { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify and continue" }));

    expect(await screen.findByText("Help the brand review this scan")).toBeInTheDocument();
    expect(localStorageStore.has("mscqr_verify_customer_email")).toBe(false);
    expect(localStorageStore.has("authenticqr_verify_customer_email")).toBe(false);
  });

  it("shows a public-safe inline email error when the OTP request fails", async () => {
    vi.mocked(apiClient.getVerificationSession).mockResolvedValue({
      success: true,
      data: buildSession(),
    } as never);
    vi.mocked(apiClient.requestVerifyEmailOtp).mockResolvedValue({
      success: false,
      error: "SIGN_IN_AUTH_FAILED",
    } as never);

    renderVerifyPage(`/verify/${CODE}?session=${SESSION_ID}`);

    fireEvent.change(await screen.findByLabelText("Email"), { target: { value: "abhi@example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Send code" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "We could not send the code right now. Please try again or report a concern."
    );
    expect(document.body).not.toHaveTextContent("SIGN_IN_AUTH_FAILED");
  });

  it("lets customers skip optional intake questions and still reveal the locked result", async () => {
    vi.mocked(apiClient.getVerificationSession).mockResolvedValue({
      success: true,
      data: buildSession({
        authState: "VERIFIED",
        intakeCompleted: false,
        revealed: false,
      }),
    } as never);
    vi.mocked(apiClient.submitVerificationIntake).mockResolvedValue({
      success: true,
      data: { sessionId: SESSION_ID },
    } as never);
    vi.mocked(apiClient.revealVerificationSession).mockResolvedValue({
      success: true,
      data: buildSession({
        authState: "VERIFIED",
        intakeCompleted: true,
        revealed: true,
        verification: buildVerifyPayload({
          publicOutcome: "SIGNED_LABEL_ACTIVE",
          riskDisposition: "CLEAR",
        }),
      }),
    } as never);
    renderVerifyPage(`/verify/${CODE}?session=${SESSION_ID}`);

    expect(await screen.findByText("Help the brand review this scan")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Skip optional questions" }));

    await waitFor(() => {
      expect(vi.mocked(apiClient.submitVerificationIntake)).toHaveBeenCalledWith(
        SESSION_ID,
        expect.objectContaining({
          purchaseChannel: "unknown",
          sourceCategory: "unknown",
          packagingState: "unsure",
          packagingConcern: "unsure",
          scanReason: "routine_check",
          ownershipIntent: "verify_only",
        }),
        undefined
      );
    });

    expect(await screen.findByText("This garment matches a registered brand record.")).toBeInTheDocument();
    expect(screen.getByText("Verification summary")).toBeInTheDocument();
    expect(screen.queryByText("Technical details for support")).toBeNull();
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
    } as never);
    renderVerifyPage(`/verify/${CODE}?session=${SESSION_ID}`);

    expect(await screen.findByText("This garment matches a registered brand record.")).toBeInTheDocument();
    expect(screen.getByText("Verification passed")).toBeInTheDocument();
    const brandDetails = screen.getByRole("region", { name: "Brand details" });
    expect(within(brandDetails).getByText("Brand")).toBeInTheDocument();
    expect(within(brandDetails).getByText("MSCQR")).toBeInTheDocument();
    expect(within(brandDetails).getByText("Label code")).toBeInTheDocument();
    expect(within(brandDetails).getByText("AADS-6007")).toBeInTheDocument();
    const websiteLink = within(brandDetails).getByRole("link", { name: /brand\.example\/verify/i });
    expect(websiteLink).toHaveAttribute("href", "https://brand.example/verify");
    expect(websiteLink).toHaveAttribute("target", "_blank");
    expect(websiteLink).toHaveAttribute("rel", "noreferrer");
    expect(within(brandDetails).getByRole("link", { name: "support@mscqr.com" })).toHaveAttribute(
      "href",
      "mailto:support@mscqr.com"
    );
    expect(within(brandDetails).getByRole("link", { name: "+44 20 0000 0000" })).toHaveAttribute(
      "href",
      "tel:+442000000000"
    );
    expect(screen.getByText("Verification summary")).toBeInTheDocument();
    expect(screen.getByText("Save verification")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Report a concern" })).toBeInTheDocument();
    expect(screen.getByText("Email")).toBeInTheDocument();
    expect(screen.queryByText("Technical details for support")).toBeNull();
    expect(screen.queryByText("Decision reference")).toBeNull();
    expect(screen.queryByText("Session reference")).toBeNull();
    expect(screen.queryByText("Support notes")).toBeNull();
    expect(document.body).not.toHaveTextContent(/decisionId|classification|riskScore|proofSource|proofTier|decision-1/i);
  });

  it("omits missing brand contact rows without placeholder text", async () => {
    vi.mocked(apiClient.getVerificationSession).mockResolvedValue({
      success: true,
      data: buildSession({
        authState: "VERIFIED",
        intakeCompleted: true,
        revealed: true,
        verification: buildVerifyPayload({
          licensee: {
            name: "Minimal Public Brand",
            brandName: "Minimal Public Brand",
          },
        }),
      }),
    } as never);

    renderVerifyPage(`/verify/${CODE}?session=${SESSION_ID}`);

    const brandDetails = await screen.findByRole("region", { name: "Brand details" });
    expect(within(brandDetails).getByText("Brand")).toBeInTheDocument();
    expect(within(brandDetails).getByText("Minimal Public Brand")).toBeInTheDocument();
    expect(within(brandDetails).getByText("Label code")).toBeInTheDocument();
    expect(within(brandDetails).queryByText("Website")).toBeNull();
    expect(within(brandDetails).queryByText("Support email")).toBeNull();
    expect(within(brandDetails).queryByText("Support phone")).toBeNull();
    expect(document.body).not.toHaveTextContent("Not available");
  });

  it("does not render raw backend verification labels on the public result", async () => {
    vi.mocked(apiClient.getVerificationSession).mockResolvedValue({
      success: true,
      data: buildSession({
        authState: "VERIFIED",
        intakeCompleted: true,
        revealed: true,
        verification: buildVerifyPayload({
          proofTier: "MANUAL_REGISTRY_LOOKUP",
          proofSource: "MANUAL_CODE_LOOKUP",
          riskDisposition: "CLEAR",
          publicOutcome: "MANUAL_RECORD_FOUND",
          classification: "FIRST_SCAN",
          licensee: {
            id: "lic-1",
            name: "A very long brand name that should wrap without breaking the public verification layout",
            brandName: "A very long brand name that should wrap without breaking the public verification layout",
            prefix: "MSC",
            supportEmail: "support@example.com",
            supportPhone: "+44 20 0000 0000",
            website: "brand.example",
          },
        }),
      }),
    } as never);

    renderVerifyPage(`/verify/${CODE}?session=${SESSION_ID}`);

    expect(await screen.findByText("This garment matches a registered brand record.")).toBeInTheDocument();
    const brandDetails = screen.getByRole("region", { name: "Brand details" });
    expect(within(brandDetails).getByRole("link", { name: "support@example.com" })).toBeInTheDocument();
    expect(within(brandDetails).getByRole("link", { name: "+44 20 0000 0000" })).toBeInTheDocument();
    expect(within(brandDetails).getByRole("link", { name: /brand\.example/i })).toBeInTheDocument();
    expect(document.body).not.toHaveTextContent("Manual Registry Lookup");
    expect(document.body).not.toHaveTextContent("Manual Code Lookup");
    expect(document.body).not.toHaveTextContent("MANUAL_REGISTRY_LOOKUP");
    expect(document.body).not.toHaveTextContent("MANUAL_CODE_LOOKUP");
    expect(document.body).not.toHaveTextContent("Decision reference");
    expect(document.body).not.toHaveTextContent("Session reference");
    expect(document.body).not.toHaveTextContent("Support notes");
    expect(document.body).not.toHaveTextContent(/decisionId|classification|riskScore|proofSource|proofTier|decision-1/i);
  });

  it("opens and submits a concern with public session context after reveal", async () => {
    vi.mocked(apiClient.getCustomerAuthSession).mockResolvedValue({
      success: true,
      data: {
        customer: { userId: "cust-1", email: "abhi@example.com", maskedEmail: "ab***@example.com" },
        auth: { cookieBacked: true, authenticated: true, authStrength: "EMAIL_OTP" },
      },
    } as never);
    vi.mocked(apiClient.getVerificationSession).mockResolvedValue({
      success: true,
      data: buildSession({
        decisionId: undefined,
        sessionProofToken: "session-proof-1",
        authState: "VERIFIED",
        intakeCompleted: true,
        revealed: true,
        verification: buildVerifyPayload({ decisionId: undefined }),
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
    } as never);
    vi.mocked(apiClient.reportFraud).mockResolvedValue({
      success: true,
      data: { supportTicketRef: "SUP-1001" },
    } as never);

    renderVerifyPage(`/verify/${CODE}?session=${SESSION_ID}`);

    fireEvent.click(await screen.findByRole("button", { name: "Report a concern" }));
    expect(await screen.findByRole("heading", { name: "Report a concern" })).toBeInTheDocument();
    expect(screen.getByLabelText("What do you want to report?")).toBeInTheDocument();
    fireEvent.click(await screen.findByRole("button", { name: "Submit concern" }));

    await waitFor(() => {
      expect(vi.mocked(apiClient.reportFraud)).toHaveBeenCalledWith(
        expect.objectContaining({
          sessionId: SESSION_ID,
        }),
        "session-proof-1"
      );
    });
    const payload = vi.mocked(apiClient.reportFraud).mock.calls[0]?.[0] as Record<string, unknown>;
    expect(payload).not.toHaveProperty("decisionId");
    expect(payload).not.toHaveProperty("code");
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
      } as never)
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
      } as never);
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
    } as never);
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
    } as never);
    renderVerifyPage(`/verify/${CODE}?session=${SESSION_ID}`);

    expect(await screen.findByText("Complete one quick check")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Complete quick check" }));

    await waitFor(() => {
      expect(vi.mocked(apiClient.verifyQRCode)).toHaveBeenCalledWith(
        CODE,
        expect.objectContaining({ device: expect.any(String) })
      );
    });

    await waitFor(() => {
      expect(vi.mocked(apiClient.startVerificationSession)).toHaveBeenCalledWith("session-start-1", "MANUAL_CODE");
    });

    await waitFor(() => {
      expect(screen.getByText(/Additional review check completed/i)).toBeInTheDocument();
    });

    await waitFor(() => {
      expect(screen.getByTestId("location-probe")).toHaveTextContent(`/verify/${CODE}?session=session-updated`);
    });
  });

  it("clears legacy persisted customer email keys instead of reusing them", async () => {
    localStorageStore.set("mscqr_verify_customer_email", "abhi@example.com");
    localStorageStore.set("authenticqr_verify_customer_email", "legacy@example.com");
    vi.mocked(apiClient.getVerificationSession).mockResolvedValue({
      success: true,
      data: buildSession(),
    } as never);

    renderVerifyPage(`/verify/${CODE}?session=${SESSION_ID}`);

    await screen.findByText("We need one quick check before showing the full result.");

    expect(localStorageStore.has("mscqr_verify_customer_email")).toBe(false);
    expect(localStorageStore.has("authenticqr_verify_customer_email")).toBe(false);
  });
});
