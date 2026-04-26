import { expect, test as base, type Browser, type Page } from "@playwright/test";

export type SeededRole = "superAdmin" | "licenseeAdmin" | "manufacturer";

type RoleCredentials = {
  email: string;
  password: string;
  displayName: string;
};

type AuthenticatedFixtures = {
  loginAsSeededRole: (role: SeededRole, pageOverride?: Page) => Promise<void>;
  superAdminPage: Page;
  licenseeAdminPage: Page;
  manufacturerPage: Page;
};

const seededCredentials: Record<SeededRole, RoleCredentials> = {
  superAdmin: {
    email: String(process.env.E2E_SUPERADMIN_EMAIL || "admin@mscqr.com").trim(),
    password: process.env.E2E_SUPERADMIN_PASSWORD?.trim() ?? "",
    displayName: "Super Admin",
  },
  licenseeAdmin: {
    email: String(process.env.E2E_LICENSEE_ADMIN_EMAIL || "admin@acme.com").trim(),
    password: process.env.E2E_LICENSEE_ADMIN_PASSWORD?.trim() ?? "",
    displayName: "Licensee Admin",
  },
  manufacturer: {
    email: String(process.env.E2E_MANUFACTURER_EMAIL || "factory1@acme.com").trim(),
    password: process.env.E2E_MANUFACTURER_PASSWORD?.trim() ?? "",
    displayName: "Manufacturer",
  },
};

const goto = async (page: Page, path: string) => {
  await page.goto(path, { waitUntil: "domcontentloaded" });
  await page.waitForLoadState("networkidle").catch(() => undefined);
};

export const loginAsSeededRole = async (page: Page, role: SeededRole) => {
  const credentials = seededCredentials[role];
  if (!credentials.email || !credentials.password) {
    throw new Error(`Missing seeded credentials for ${credentials.displayName}.`);
  }

  await goto(page, "/login");
  await page.locator("#email").fill(credentials.email);
  await page.locator("#password").fill(credentials.password);
  await page.getByRole("button", { name: /^sign in$/i }).click();
  await page.waitForFunction(
    () => !["/login", "/forgot-password", "/reset-password", "/accept-invite"].includes(window.location.pathname),
    undefined,
    { timeout: 60_000 },
  );
  await expect(page.locator("main")).toBeVisible({ timeout: 20_000 });
};

const makeAuthenticatedPage = async (browser: Browser, role: SeededRole, providePage: (page: Page) => Promise<void>) => {
  const page = await browser.newPage();
  try {
    await loginAsSeededRole(page, role);
    await providePage(page);
  } finally {
    await page.close();
  }
};

export const test = base.extend<AuthenticatedFixtures>({
  loginAsSeededRole: async ({ page }, provide) => {
    await provide((role, pageOverride) => loginAsSeededRole(pageOverride || page, role));
  },
  superAdminPage: async ({ browser }, provide) => {
    await makeAuthenticatedPage(browser, "superAdmin", provide);
  },
  licenseeAdminPage: async ({ browser }, provide) => {
    await makeAuthenticatedPage(browser, "licenseeAdmin", provide);
  },
  manufacturerPage: async ({ browser }, provide) => {
    await makeAuthenticatedPage(browser, "manufacturer", provide);
  },
});

export { expect };
