import { expect, test, type Page } from "@playwright/test";

import { installP0TrustMocks } from "./helpers/p0-trust-mocks";

const launchViewports = [
  { width: 320, height: 720 },
  { width: 375, height: 812 },
  { width: 768, height: 1024 },
  { width: 1024, height: 768 },
  { width: 1280, height: 800 },
  { width: 1440, height: 900 },
];

const expectNoHorizontalOverflow = async (page: Page) => {
  const overflow = await page.evaluate(() => {
    const root = document.documentElement;
    return root.scrollWidth - root.clientWidth;
  });

  expect(overflow).toBeLessThanOrEqual(1);
};

const collectBrowserErrors = (page: Page) => {
  const errors: string[] = [];

  page.on("console", (message) => {
    const text = message.text();

    // The P0 dashboard mocks intentionally abort SSE/local polling requests; Chromium reports those as resource errors.
    if (message.type() === "error" && !text.includes("Failed to load resource: net::ERR_FAILED")) errors.push(text);
  });
  page.on("pageerror", (error) => errors.push(error.message));

  return errors;
};

test.describe("Phase C launch polish", () => {
  test("public header removes crowded CTAs while preserving hero actions across breakpoints", async ({ page }) => {
    const browserErrors = collectBrowserErrors(page);

    await page.route("**/api/telemetry/route-transition", (route) => route.fulfill({ json: { success: true } }));

    for (const viewport of launchViewports) {
      await page.setViewportSize(viewport);
      await page.goto("/");

      const header = page.getByRole("banner");
      const main = page.getByRole("main");

      await expect(header.getByRole("link", { name: "Request Access" })).toHaveCount(0);
      await expect(header.getByRole("link", { name: /verify product/i })).toHaveCount(0);
      await expect(header.getByRole("link", { name: /sign in/i })).toBeVisible();
      await expect(main.getByRole("link", { name: "Request Access" })).toBeVisible();
      await expect(main.getByRole("link", { name: /verify a product/i })).toBeVisible();

      if (viewport.width < 1024) {
        await expect(header.getByRole("button", { name: /open public navigation menu/i })).toBeVisible();
      }

      await expectNoHorizontalOverflow(page);
    }

    expect(browserErrors).toEqual([]);
  });

  test("dashboard overview KPI cards stay aligned and overflow-free across breakpoints", async ({ page }) => {
    const browserErrors = collectBrowserErrors(page);

    await installP0TrustMocks(page, { role: "super_admin" });

    for (const viewport of launchViewports) {
      await page.setViewportSize(viewport);
      await page.goto("/dashboard");

      await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
      const cards = page.getByTestId("dashboard-kpi-card");
      await expect(cards).toHaveCount(4);

      const boxes = await cards.evaluateAll((elements) =>
        elements.map((element) => {
          const rect = element.getBoundingClientRect();
          return { width: rect.width, height: rect.height };
        }),
      );
      const heights = boxes.map((box) => box.height);
      const widths = boxes.map((box) => box.width);

      expect(Math.max(...heights) - Math.min(...heights)).toBeLessThanOrEqual(16);
      expect(Math.min(...widths)).toBeGreaterThan(0);
      await expectNoHorizontalOverflow(page);
    }

    expect(browserErrors).toEqual([]);
  });
});
