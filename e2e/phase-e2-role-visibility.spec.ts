import { expect, test } from "@playwright/test";
import { installP0TrustMocks, type FrontendRole } from "./helpers/p0-trust-mocks";

const platformOnlyLinks = [
  { href: "/support", label: "Support" },
  { href: "/incident-response", label: "Issues" },
  { href: "/release-readiness", label: "Release Readiness" },
  { href: "/licensees", label: "Brands" },
];

const protectedMarkers = /Phase E2 Request Access|request-access-secret@example\.test|phase-e2-request-access-internal-note/i;

test.describe("Phase E2 role visibility", () => {
  test("super admin sees platform support, incident, release, and admin surfaces", async ({ page }) => {
    await installP0TrustMocks(page, { role: "super_admin" });

    await page.goto("/dashboard");
    for (const link of platformOnlyLinks) {
      await expect(page.locator(`a[href="${link.href}"]`).first(), `${link.label} nav link`).toBeVisible();
    }

    await page.goto("/support");
    await expect(page).toHaveURL(/\/support$/);
    await expect(page.locator("body")).toContainText(/Phase E2 Request Access|Support/i);
    await expect(page.getByTestId("support-ticket-save")).toHaveCount(0);
  });

  for (const role of ["licensee_admin", "manufacturer"] as FrontendRole[]) {
    test(`${role} cannot see or navigate directly to platform-only queues`, async ({ page }) => {
      await installP0TrustMocks(page, { role });

      await page.goto("/dashboard");
      for (const link of platformOnlyLinks) {
        await expect(page.locator(`a[href="${link.href}"]`), `${role} ${link.label} nav link`).toHaveCount(0);
      }

      await page.goto("/support");
      await expect(page).toHaveURL(/\/dashboard$/);
      await expect(page.locator("body")).not.toContainText(protectedMarkers);
      await expect(page.getByTestId("support-ticket-save")).toHaveCount(0);

      await page.goto("/incident-response");
      await expect(page).toHaveURL(/\/dashboard$/);
      await expect(page.locator("body")).not.toContainText(/Incident Response|customer email|internal note/i);
    });
  }
});
