import { expect, test } from "@playwright/test";

import { installP0TrustMocks, type FrontendRole } from "./helpers/p0-trust-mocks";

const protectedRoutes = [
  { path: "/dashboard", label: "Overview", roles: ["super_admin", "licensee_admin", "manufacturer"] },
  { path: "/licensees", label: "Brands", roles: ["super_admin"] },
  { path: "/code-requests", label: "QR Requests", roles: ["super_admin", "licensee_admin"] },
  { path: "/batches", label: "Batches", roles: ["super_admin", "licensee_admin", "manufacturer"] },
  { path: "/scan-activity", label: "Scans", roles: ["super_admin", "licensee_admin", "manufacturer"] },
  { path: "/manufacturers", label: "Manufacturers", roles: ["super_admin", "licensee_admin"] },
  { path: "/audit-history", label: "History", roles: ["super_admin", "licensee_admin", "manufacturer"] },
  { path: "/incident-response", label: "Issues", roles: ["super_admin"] },
  { path: "/support", label: "Support", roles: ["super_admin"] },
  { path: "/release-readiness", label: "Release Readiness", roles: ["super_admin"] },
  { path: "/governance", label: "Governance", roles: ["super_admin"] },
  { path: "/settings", label: "Settings", roles: ["super_admin", "licensee_admin", "manufacturer"] },
  { path: "/account", label: "Account", roles: ["super_admin", "licensee_admin", "manufacturer"] },
  { path: "/printer-setup", label: "Printing", roles: ["manufacturer"] },
] as const;

const navExpectations: Record<FrontendRole, { visible: RegExp[]; hidden: RegExp[] }> = {
  super_admin: {
    visible: [/Overview/, /Brands/, /QR Requests/, /Batches/, /Manufacturers/, /Scans/, /History/, /Issues/, /Support/, /Release Readiness/],
    hidden: [/Printing/],
  },
  licensee_admin: {
    visible: [/Overview/, /QR Requests/, /Batches/, /Manufacturers/, /Scans/, /History/],
    hidden: [/Brands/, /Issues/, /Support/, /Release Readiness/, /Printing/],
  },
  manufacturer: {
    visible: [/Overview/, /Batches/, /Scans/, /History/, /Printing/],
    hidden: [/Brands/, /QR Requests/, /Manufacturers/, /Issues/, /Support/, /Release Readiness/],
  },
};

const publicRoutes = ["/", "/trust", "/platform", "/solutions/brands", "/verify", "/help/customer"];
const roles: FrontendRole[] = ["super_admin", "licensee_admin", "manufacturer"];

test.describe("P0 frontend access control", () => {
  for (const path of publicRoutes) {
    test(`anonymous user can open public route ${path} without auth bootstrap`, async ({ page }) => {
      let authMeCalls = 0;
      await page.route("**/api/auth/me", (route) => {
        authMeCalls += 1;
        return route.fulfill({ status: 401, json: { success: false, error: "No token provided" } });
      });
      await page.route("**/api/telemetry/route-transition", (route) => route.fulfill({ json: { success: true } }));

      await page.goto(path);
      await expect(page.locator("body")).not.toContainText(/Invalid or expired token|Insufficient permissions/i);
      expect(authMeCalls).toBe(0);
    });
  }

  for (const routeInfo of protectedRoutes) {
    test(`anonymous user is safely redirected from ${routeInfo.path}`, async ({ page }) => {
      await installP0TrustMocks(page, { authenticated: false });

      await page.goto(routeInfo.path);

      await expect(page).toHaveURL(/\/login$/);
      await expect(page.locator("body")).not.toContainText(new RegExp(`${routeInfo.label}.*P0`, "i"));
      await expect(page.locator("body")).not.toContainText(/Acme Brand|Acme Factory|Feature flags|Compliance pack/i);
    });
  }

  for (const role of roles) {
    test(`${role} sees only role-allowed sidebar entries`, async ({ page }) => {
      await installP0TrustMocks(page, { role });
      await page.goto("/dashboard");

      const nav = page.getByRole("navigation", { name: "Authenticated MSCQR navigation" });
      await expect(nav).toBeVisible();
      await expect(
        page.getByText(role === "super_admin" ? "Platform Admin" : role === "licensee_admin" ? "Brand Admin" : "Manufacturer Admin", {
          exact: true,
        }).first(),
      ).toBeVisible();

      for (const label of navExpectations[role].visible) {
        await expect(nav.getByRole("link", { name: label })).toBeVisible();
      }
      for (const label of navExpectations[role].hidden) {
        await expect(nav.getByRole("link", { name: label })).toHaveCount(0);
      }
    });

    for (const routeInfo of protectedRoutes) {
      const allowed = routeInfo.roles.includes(role);
      test(`${role} ${allowed ? "can access" : "is blocked from"} direct URL ${routeInfo.path}`, async ({ page }) => {
        await installP0TrustMocks(page, { role });

        await page.goto(routeInfo.path);

        if (allowed) {
          await expect(page).not.toHaveURL(/\/login$/);
          if (routeInfo.path !== "/dashboard") {
            await expect(page).toHaveURL(new RegExp(`${routeInfo.path.replace("/", "\\/")}(?:$|[?#])`));
          }
          await expect(page.locator("body")).toContainText(routeInfo.label);
          return;
        }

        await expect(page).toHaveURL(/\/dashboard$/);
        await expect(page.locator("body")).not.toContainText(new RegExp(`${routeInfo.label}.*P0`, "i"));
      });
    }
  }

  test("invalid or expired session redirects to login without protected content flash", async ({ page }) => {
    await installP0TrustMocks(page, { authenticated: false });

    await page.goto("/governance");

    await expect(page).toHaveURL(/\/login$/);
    await expect(page.locator("body")).not.toContainText(/Feature flags|Compliance report|Evidence retention/i);
  });

  test("logout clears frontend access and protected route bootstrap returns to login", async ({ page }) => {
    await installP0TrustMocks(page, { role: "super_admin" });

    await page.goto("/dashboard");
    await expect(page.getByText("Alex Admin").first()).toBeVisible();
    await page.getByRole("button", { name: /Alex Admin/ }).click();
    await page.getByRole("menuitem", { name: /Log out/ }).click();

    await expect(page).toHaveURL(/\/login$/);
    await page.goto("/dashboard");
    await expect(page).toHaveURL(/\/login$/);
  });
});
