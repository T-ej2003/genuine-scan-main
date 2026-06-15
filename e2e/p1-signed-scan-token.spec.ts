import { expect, test, type Page, type Route } from "@playwright/test";
import { verifyScenarioBody } from "./helpers/p0-trust-mocks";

const json = (route: Route, body: unknown, status = 200) =>
  route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });

type VerifyMockResponse = { success: true; data: Record<string, unknown> };

const scenarioData = (kind: "valid" | "invalid" | "suspicious") =>
  (verifyScenarioBody("SIGNED-P1", kind) as VerifyMockResponse).data;

const publicScenarioData = (kind: "valid" | "invalid" | "suspicious") => {
  const data = { ...scenarioData(kind) };
  delete data.decisionId;
  delete data.sessionStartToken;
  return data;
};

const signedPayload = (kind: "valid" | "expired" | "tampered" | "revoked" | "missing" | "suspicious") => {
  if (kind === "valid") {
    return {
      success: true,
      data: {
        ...publicScenarioData("valid"),
        proofSource: "SIGNED_LABEL",
        publicOutcome: "SIGNED_LABEL_ACTIVE",
        classification: "FIRST_SCAN",
      },
    };
  }
  if (kind === "suspicious") {
    return {
      success: true,
      data: {
        ...publicScenarioData("suspicious"),
        proofSource: "SIGNED_LABEL",
        publicOutcome: "REVIEW_REQUIRED",
        challenge: { required: true, methods: ["SIGN_IN"] },
        warningMessage: "This signed QR was scanned from a different context unusually quickly.",
      },
    };
  }
  if (kind === "missing") {
    return { success: true, data: { ...publicScenarioData("invalid"), proofSource: "SIGNED_LABEL" } };
  }
  return {
    success: true,
    data: {
      isAuthentic: false,
      code: "SIGNED-P1",
      proofSource: "SIGNED_LABEL",
      publicOutcome: "BLOCKED",
      classification: "BLOCKED_BY_SECURITY",
      scanOutcome: kind === "expired" ? "EXPIRED" : kind === "revoked" ? "TOKEN_MISMATCH" : "INVALID_SIGNATURE",
      message:
        kind === "expired"
          ? "QR token expired."
          : kind === "revoked"
            ? "QR token revoked or mismatched."
            : "Invalid or tampered QR token.",
      warningMessage: "We could not verify the cryptographic label.",
      verifyUxPolicy: { allowFraudReport: true },
    },
  };
};

async function installSignedScanMocks(page: Page) {
  await page.addInitScript(() => {
    window.localStorage.setItem(
      "mscqr_cookie_consent_state:v1",
      JSON.stringify({ version: 1, updatedAt: "2026-06-01T00:00:00.000Z", categories: { functional: true } }),
    );
  });

  await page.route("**/api/**", async (route: Route) => {
    const url = new URL(route.request().url());
    if (!url.pathname.startsWith("/api/")) return route.continue();
    const path = url.pathname.replace(/^\/api/, "");
    if (path === "/verify/auth/providers") return json(route, { success: true, data: { items: [] } });
    if (path === "/verify/auth/session") return json(route, { success: true, data: null });
    if (path === "/telemetry/route-transition" || path === "/telemetry/csp-report") return json(route, { success: true });
    if (path === "/scan") {
      const token = url.searchParams.get("t") || "";
      if (!token) return json(route, { success: false, error: "Invalid QR code format" }, 400);
      if (token.includes("expired")) return json(route, signedPayload("expired"));
      if (token.includes("tampered")) return json(route, signedPayload("tampered"));
      if (token.includes("revoked")) return json(route, signedPayload("revoked"));
      if (token.includes("missing")) return json(route, signedPayload("missing"), 404);
      if (token.includes("suspicious")) return json(route, signedPayload("suspicious"));
      return json(route, signedPayload("valid"));
    }
    return json(route, { success: true, data: {} });
  });
}

test.describe("P1 signed /scan?t= QR result states", () => {
  test.beforeEach(async ({ page }) => {
    await installSignedScanMocks(page);
  });

  test("renders a valid signed scan result without admin data", async ({ page }) => {
    await page.goto("/scan?t=valid-signed-p1-token");
    await expect(page.getByText(/Verification passed|registered brand record/i).first()).toBeVisible();
    await expect(page.getByRole("link", { name: /Verify another garment/i }).first()).toBeVisible();
    await expect(page.getByRole("button", { name: /Save verification/i })).toBeVisible();
    await expect(page.getByRole("button", { name: /Report a concern/i })).toBeVisible();
    await expect(page.locator("body")).not.toContainText(/Technical details for support|Decision reference|Session reference|Support notes/i);
    await expect(page.locator("body")).not.toContainText(/tokenHash|licenseeId|manufacturerId|admin-only|Bearer|JWT|stack trace/i);
  });

  test("renders expired, tampered, revoked, and missing token states safely", async ({ page }) => {
    for (const token of ["expired-p1-token", "tampered-p1-token", "revoked-p1-token"]) {
      await page.goto(`/scan?t=${token}`);
      await expect(page.locator("body")).toContainText(/could not|blocked|expired|revoked|not find|verify/i);
      await expect(page.getByRole("button", { name: /Report a concern/i })).toBeVisible();
      await expect(page.locator("body")).not.toContainText(/\{.*error.*\}|tokenHash|Prisma|localhost|undefined|null/i);
    }

    await page.goto("/scan?t=missing-p1-token");
    await expect(page.locator("body")).toContainText(/could not|not found|match this QR label|enter code again/i);
    await expect(page.locator("body")).not.toContainText(/HTTP 400|HTTP 404|Cannot GET/i);
    await expect(page.getByRole("link", { name: /Enter code again/i })).toBeVisible();
    await expect(page.locator("body")).not.toContainText(/Technical details for support|Decision reference|Session reference|Support notes/i);
    await expect(page.locator("body")).not.toContainText(/\{.*error.*\}|tokenHash|Prisma|localhost|undefined|null/i);
  });

  test("renders suspicious duplicate signed scan on mobile", async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto("/scan?t=suspicious-p1-token");
    await expect(page.getByText(/review needed|brand review|suspicious/i).first()).toBeVisible();
    await expect(page.getByRole("button", { name: /Report a concern/i })).toBeVisible();
    await expect(page.getByRole("button", { name: /Save verification/i })).toBeVisible();
    await expect(page.locator("body")).not.toContainText(/Technical details for support|Decision reference|Session reference|Support notes/i);
    await expect(page.locator("body")).not.toContainText(/admin-only|internal id|tokenHash|Bearer/i);
  });
});
