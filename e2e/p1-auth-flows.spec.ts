import { expect, test, type Page, type Route } from "@playwright/test";
import { loginAsSeededRole } from "./fixtures/authenticated";

const activeUser = {
  id: "p1-auth-super-admin",
  email: "p1-admin@mscqr.example",
  name: "P1 Admin",
  role: "SUPER_ADMIN",
  licenseeId: null,
  orgId: "platform-org",
  isActive: true,
  auth: {
    sessionStage: "ACTIVE",
    authAssurance: "ADMIN_MFA",
    mfaRequired: true,
    mfaEnrolled: true,
    mfaVerifiedAt: "2026-06-01T00:00:00.000Z",
    sessionId: "p1-active-session",
    sessionExpiresAt: "2026-06-01T08:00:00.000Z",
  },
};

const pendingMfaUser = {
  ...activeUser,
  id: "p1-auth-mfa-user",
  email: "p1-mfa@mscqr.example",
  auth: {
    ...activeUser.auth,
    sessionStage: "MFA_BOOTSTRAP",
    authAssurance: "PASSWORD",
  },
};

const json = (route: Route, body: unknown, status = 200) =>
  route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });

async function installP1AuthMocks(page: Page) {
  let authenticated = false;
  await page.route("**/api/**", async (route) => {
    const url = new URL(route.request().url());
    if (!url.pathname.startsWith("/api/")) return route.continue();
    const path = url.pathname.replace(/^\/api/, "");
    const body = route.request().postDataJSON?.() || {};

    if (path === "/auth/me") {
      return authenticated
        ? json(route, { success: true, data: activeUser })
        : json(route, { success: false, error: "Invalid or expired token" }, 401);
    }
    if (path === "/auth/login") {
      if (body.email === "p1-mfa@mscqr.example") {
        return json(route, {
          success: true,
          data: {
            user: pendingMfaUser,
            auth: pendingMfaUser.auth,
          },
        });
      }
      if (body.email === "p1-admin@mscqr.example" && body.password === "CorrectHorseBattery1!") {
        authenticated = true;
        return json(route, { success: true, data: { user: activeUser, auth: activeUser.auth } });
      }
      return json(route, { success: false, error: "Invalid email or password" }, 401);
    }
    if (path === "/auth/mfa/challenge/begin") {
      return json(route, { success: true, data: { ticket: "p1-mfa-ticket", expiresAt: "2026-06-01T00:10:00.000Z" } });
    }
    if (path === "/auth/mfa/challenge/complete") {
      if (body.code === "123456") {
        authenticated = true;
        return json(route, { success: true, data: { user: activeUser, auth: activeUser.auth } });
      }
      return json(route, { success: false, error: "Invalid MFA code" }, 401);
    }
    if (path === "/auth/invite-preview") {
      return json(route, {
        success: true,
        data: {
          email: "invitee@brand.example",
          role: "MANUFACTURER",
          expiresAt: "2026-06-02T00:00:00.000Z",
          licenseeName: "P1 Brand",
          requiresConnector: true,
        },
      });
    }
    if (path === "/auth/accept-invite") {
      authenticated = true;
      return json(route, { success: true, data: { user: activeUser, auth: activeUser.auth } });
    }
    if (path === "/auth/forgot-password") return json(route, { success: true, data: { queued: true } });
    if (path === "/auth/reset-password") return json(route, { success: false, error: "Reset token is invalid or expired" }, 400);
    if (path === "/auth/logout") {
      authenticated = false;
      return json(route, { success: true, data: { cleared: true } });
    }
    if (path.startsWith("/dashboard") || path.startsWith("/notifications") || path.startsWith("/internal/release")) {
      return json(route, { success: true, data: {} });
    }
    if (path === "/events/dashboard" || path === "/events/notifications" || path === "/audit/stream") return route.abort();
    return json(route, { success: true, data: [] });
  });
}

test.describe("P1 auth flow automation", () => {
  test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => {
      window.localStorage.setItem(
        "mscqr_cookie_consent_state:v1",
        JSON.stringify({ version: 1, updatedAt: "2026-06-01T00:00:00.000Z", categories: { functional: true } }),
      );
    });
    await installP1AuthMocks(page);
  });

  test("login success, logout, and expired session redirect are safe", async ({ page }) => {
    await page.goto("/login");
    await page.getByLabel("Email").fill("p1-admin@mscqr.example");
    await page.getByLabel("Password", { exact: true }).fill("CorrectHorseBattery1!");
    await page.getByRole("button", { name: /^sign in$/i }).click();
    await expect(page).toHaveURL(/\/dashboard/);
    await expect(page.locator("main")).toBeVisible();

    await page.getByRole("button", { name: /P1 Admin/i }).click();
    await page.getByRole("menuitem", { name: /Log out/i }).click();
    await page.goto("/dashboard");
    await expect(page).toHaveURL(/\/login/);
    await expect(page.locator("body")).not.toContainText(/token|stack trace|undefined|null/i);
  });

  test("invalid login and MFA failure show safe messages", async ({ page }) => {
    await page.goto("/login");
    await page.getByLabel("Email").fill("p1-admin@mscqr.example");
    await page.getByLabel("Password", { exact: true }).fill("wrong-password");
    await page.getByRole("button", { name: /^sign in$/i }).click();
    await expect(page.getByText(/incorrect password/i)).toBeVisible();

    await page.getByLabel("Email").fill("p1-mfa@mscqr.example");
    await page.getByLabel("Password", { exact: true }).fill("CorrectHorseBattery1!");
    await page.getByRole("button", { name: /^sign in$/i }).click();
    await expect(page.getByText(/authenticator|security code/i).first()).toBeVisible();
    await page.getByLabel(/authenticator code|security code/i).fill("000000");
    await page.getByRole("button", { name: /open secure session|verify|continue|confirm/i }).click();
    await expect(page.getByText(/invalid MFA code|could not be verified|check the code/i)).toBeVisible();
  });

  test("invite acceptance and password reset screens handle safe states", async ({ page }) => {
    await page.goto("/accept-invite?token=p1-invite-token");
    await expect(page.getByText("invitee@brand.example")).toBeVisible();
    await page.getByLabel("Password", { exact: true }).fill("CorrectHorseBattery1!");
    await page.getByLabel("Confirm password", { exact: true }).fill("CorrectHorseBattery1!");
    await page.getByRole("button", { name: /activate account/i }).click();
    await expect(page).toHaveURL(/\/dashboard/);
    await page.getByRole("button", { name: /P1 Admin/i }).click();
    await page.getByRole("menuitem", { name: /Log out/i }).click();
    await expect(page).toHaveURL(/\/login/);

    await page.goto("/forgot-password");
    await page.getByLabel("Email").fill("unknown@brand.example");
    await page.getByRole("button", { name: /send reset link/i }).click();
    await expect(page.getByText(/request received/i)).toBeVisible();

    await page.goto("/reset-password?token=expired-p1-token");
    await page.getByLabel("New password").fill("CorrectHorseBattery1!");
    await page.getByLabel("Confirm password").fill("CorrectHorseBattery1!");
    await page.getByRole("button", { name: /update password/i }).click();
    await expect(page.getByText(/invalid or expired/i)).toBeVisible();
  });
});

test.describe("P1 seeded real auth smoke", () => {
  test.skip(
    String(process.env.E2E_REAL_AUTH || "").toLowerCase() !== "true",
    "Set E2E_REAL_AUTH=true with seeded backend credentials to run real login coverage.",
  );

  test("seeded roles can log in through the real auth UI", async ({ page }) => {
    await loginAsSeededRole(page, "superAdmin");
    await expect(page).toHaveURL(/\/dashboard/);
  });
});
