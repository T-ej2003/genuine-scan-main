import { expect, test, type Page } from "@playwright/test";

type Role = "LICENSEE_ADMIN" | "MANUFACTURER";

const consentState = {
  version: 1,
  updatedAt: "2026-04-24T12:00:00.000Z",
  categories: { functional: true, analytics: false, marketing: false },
};

const userFor = (role: Role) => ({
  id: `${role.toLowerCase()}-visual-user`,
  email: role === "MANUFACTURER" ? "factory1@acme.com" : "admin@acme.com",
  name: role === "MANUFACTURER" ? "Acme Factory 1" : "Acme Admin",
  role: role === "MANUFACTURER" ? "manufacturer" : "licensee_admin",
  licenseeId: "licensee-acme",
  orgId: "licensee-acme",
  licensee: { id: "licensee-acme", name: "Acme Corporation", prefix: "ACM", brandName: "Acme Corporation" },
  linkedLicensees:
    role === "MANUFACTURER"
      ? [{ id: "licensee-acme", name: "Acme Corporation", prefix: "ACM", brandName: "Acme Corporation", isPrimary: true }]
      : [],
  createdAt: "2026-04-24T12:00:00.000Z",
  isActive: true,
  auth: {
    sessionStage: "ACTIVE",
    authAssurance: "ADMIN_MFA",
    mfaRequired: true,
    mfaEnrolled: true,
    mfaVerifiedAt: "2026-04-24T12:00:00.000Z",
    sessionId: "session-visual-123456",
    sessionExpiresAt: "2026-04-24T18:00:00.000Z",
  },
});

const batchRows = [
  {
    id: "batch-source-1",
    name: "Spring Retail Run",
    batchKind: "RECEIVED_PARENT",
    licenseeId: "licensee-acme",
    licensee: { id: "licensee-acme", name: "Acme Corporation", prefix: "ACM" },
    totalCodes: 150000,
    startCode: "ACM-000001",
    endCode: "ACM-150000",
    remainingStartCode: "ACM-120001",
    remainingEndCode: "ACM-150000",
    unassignedRemainingCodes: 30000,
    printedCodes: 84000,
    printableCodes: 36000,
    redeemedCodes: 22000,
    blockedCodes: 18,
    printedAt: null,
    createdAt: "2026-04-20T09:00:00.000Z",
    updatedAt: "2026-04-24T12:00:00.000Z",
  },
  {
    id: "batch-child-1",
    name: "Factory A Allocation",
    batchKind: "MANUFACTURER_CHILD",
    licenseeId: "licensee-acme",
    manufacturerId: "manufacturer-1",
    manufacturer: { id: "manufacturer-1", name: "Acme Factory 1", email: "factory1@acme.com" },
    totalCodes: 45000,
    startCode: "ACM-000001",
    endCode: "ACM-045000",
    remainingStartCode: "ACM-030001",
    remainingEndCode: "ACM-045000",
    printableCodes: 15000,
    printedCodes: 30000,
    redeemedCodes: 9200,
    blockedCodes: 4,
    printedAt: null,
    createdAt: "2026-04-21T09:00:00.000Z",
  },
];

async function mockClientApis(page: Page, role: Role = "LICENSEE_ADMIN") {
  await page.addInitScript((state) => {
    window.localStorage.setItem("mscqr_cookie_consent_state:v1", JSON.stringify(state));
    document.cookie = "aq_vid=client-visual-device; Max-Age=31536000; Path=/; SameSite=Lax";
    window.sessionStorage.setItem("manufacturer-printer-dialog-opened:v1:manufacturer-visual-user", "shown");
    window.localStorage.setItem("manufacturer-printer-onboarding:v1:manufacturer-visual-user:client-visual-device", "dismissed");
  }, consentState);

  await page.route("**/api/auth/me", (route) => route.fulfill({ json: { success: true, data: userFor(role) } }));
  await page.route("**/api/notifications**", (route) => route.fulfill({ json: { success: true, data: { items: [], unreadCount: 0 } } }));
  await page.route("**/api/dashboard/attention-queue", (route) => route.fulfill({ json: { success: true, data: [] } }));
  await page.route("**/api/dashboard/stats**", (route) =>
    route.fulfill({
      json: {
        success: true,
        data: { totalBatches: 2, totalCodes: 150000, printedCodes: 84000, scanEvents: 1280, scansToday: 120, activeLicensees: 1 },
      },
    }),
  );
  await page.route("**/api/qr/stats**", (route) =>
    route.fulfill({
      json: {
        success: true,
        data: { total: 150000, dormant: 30000, allocated: 36000, printed: 84000, redeemed: 22000, blocked: 18 },
      },
    }),
  );
  await page.route("**/api/telemetry/route-transition", (route) => route.fulfill({ json: { success: true } }));
  await page.route("**/api/events/**", (route) => route.abort());
  await page.route("**/api/audit/stream", (route) =>
    route.fulfill({ status: 200, contentType: "text/event-stream", body: "" }),
  );
  await page.route("**/api/trace/timeline**", (route) =>
    route.fulfill({
      json: {
        success: true,
        data: [
          {
            id: "trace-1",
            eventType: "COMMISSIONED",
            createdAt: "2026-04-24T12:00:00.000Z",
            details: { batchName: "Spring Retail Run" },
          },
        ],
      },
    }),
  );
  await page.route("**/api/auth/mfa/status", (route) =>
    route.fulfill({ json: { success: true, data: { required: true, enabled: true, backupCodesRemaining: 6, preferredMethod: "TOTP" } } }),
  );
  await page.route("**/api/auth/sessions", (route) =>
    route.fulfill({
      json: {
        success: true,
        data: {
          items: [
            {
              id: "session-visual-123456",
              current: true,
              createdAt: "2026-04-24T09:00:00.000Z",
              lastUsedAt: "2026-04-24T12:00:00.000Z",
              expiresAt: "2026-04-24T18:00:00.000Z",
              mfaVerifiedAt: "2026-04-24T12:00:00.000Z",
              security: {
                riskScore: 12,
                riskLevel: "LOW",
                riskReasons: [],
                internalIpReputation: "trusted",
                possibleImpossibleTravel: false,
              },
            },
          ],
          summary: {
            highestRiskScore: 12,
            highestRiskLevel: "LOW",
            highRiskSessionCount: 0,
            elevatedRiskSessionCount: 0,
            distinctIpHashes24h: 1,
            possibleImpossibleTravel: false,
            internalIpReputation: "trusted",
          },
        },
      },
    }),
  );
  await page.route("**/api/qr/batches**", (route) => route.fulfill({ json: { success: true, data: batchRows } }));
  await page.route("**/api/manufacturers**", (route) =>
    route.fulfill({
      json: {
        success: true,
        data: [{ id: "manufacturer-1", name: "Acme Factory 1", email: "factory1@acme.com", isActive: true, location: "Cape Town" }],
      },
    }),
  );
  await page.route("**/api/users**", (route) =>
    route.fulfill({
      json: {
        success: true,
        data: [{ id: "manufacturer-1", name: "Acme Factory 1", email: "factory1@acme.com", role: "MANUFACTURER", isActive: true }],
      },
    }),
  );
  await page.route("**/api/qr/requests**", (route) =>
    route.fulfill({
      json: {
        success: true,
        data: [
          {
            id: "request-1",
            licenseeId: "licensee-acme",
            status: "PENDING",
            quantity: 25000,
            batchName: "May Production",
            note: "Retail launch labels",
            createdAt: "2026-04-24T10:00:00.000Z",
            requestedByUser: { id: "admin-1", name: "Acme Admin", email: "admin@acme.com" },
            licensee: { id: "licensee-acme", name: "Acme Corporation", prefix: "ACM" },
          },
        ],
      },
    }),
  );
  await page.route("**/api/admin/qr/analytics**", (route) =>
    route.fulfill({
      json: {
        success: true,
        data: {
          totals: { total: 150000, dormant: 30000, allocated: 36000, printed: 84000, redeemed: 22000, blocked: 18, created: 2 },
          trend: [
            { label: "Apr 22", total: 150000, scanEvents: 400, dormant: 30000, allocated: 36000, printed: 84000, redeemed: 8000, blocked: 4 },
            { label: "Apr 23", total: 150000, scanEvents: 920, dormant: 30000, allocated: 36000, printed: 84000, redeemed: 16000, blocked: 9 },
            { label: "Apr 24", total: 150000, scanEvents: 1280, dormant: 30000, allocated: 36000, printed: 84000, redeemed: 22000, blocked: 18 },
          ],
          batches: [
            {
              id: "batch-source-1",
              name: "Spring Retail Run",
              totalCodes: 150000,
              batchInventoryTotal: 150000,
              scopeCodeCount: 22000,
              scanEventCount: 1280,
              counts: { DORMANT: 30000, ALLOCATED: 36000, PRINTED: 84000, REDEEMED: 22000, BLOCKED: 18 },
              createdAt: "2026-04-20T09:00:00.000Z",
            },
          ],
          logs: [
            {
              id: "scan-1",
              code: "ACM-040012",
              batchId: "batch-source-1",
              status: "REDEEMED",
              scanCount: 1,
              isFirstScan: true,
              isTrustedOwnerContext: true,
              locationLabel: "Cape Town",
              scannedAt: "2026-04-24T12:00:00.000Z",
            },
          ],
          scope: {
            mode: "activity",
            title: "Current brand",
            description: "Activity scoped to Acme Corporation.",
            quantities: { distinctCodes: 22000, scanEvents: 1280, matchedBatches: 1 },
          },
          eventSummary: {
            totalScanEvents: 1280,
            firstScanEvents: 1100,
            repeatScanEvents: 180,
            blockedEvents: 18,
            trustedOwnerEvents: 900,
            externalEvents: 180,
            namedLocationEvents: 760,
            knownDeviceEvents: 640,
          },
        },
      },
    }),
  );
  await page.route("**/api/audit/logs**", (route) =>
    route.fulfill({
      json: {
        success: true,
        data: [
          {
            id: "audit-1",
            action: "AUTH_MFA_ENROLLED",
            entityType: "User",
            entityId: "admin-1",
            createdAt: "2026-04-24T12:00:00.000Z",
            user: { id: "admin-1", name: "Acme Admin", email: "admin@acme.com" },
            details: { email: "admin@acme.com" },
          },
          {
            id: "audit-2",
            action: "RESEND_LICENSEE_ADMIN_INVITE",
            entityType: "Invite",
            entityId: "invite-1",
            createdAt: "2026-04-24T11:00:00.000Z",
            user: { id: "admin-1", name: "Acme Admin", email: "admin@acme.com" },
            details: { email: "newadmin@acme.com", brandName: "Acme Corporation" },
          },
        ],
      },
    }),
  );
  await page.route("**/api/manufacturer/printers**", (route) =>
    route.fulfill({ json: { success: true, data: [{ id: "printer-1", name: "MSCQR Visual Printer", connectionType: "LOCAL_AGENT", isActive: true }] } }),
  );
  await page.route("**/api/manufacturer/print-jobs**", (route) => route.fulfill({ json: { success: true, data: [] } }));
  await page.route("**/api/manufacturer/printer-agent/events", (route) =>
    route.fulfill({ json: { success: true, data: { events: [] } } }),
  );
  await page.route("**/api/manufacturer/printer-agent/heartbeat", (route) =>
    route.fulfill({ json: { success: true, data: { connected: true } } }),
  );
  await page.route("**/api/manufacturer/printer-agent/status", (route) =>
    route.fulfill({ json: { success: true, data: { connected: true, eligibleForPrinting: true, trustStatus: "TRUSTED" } } }),
  );
  await page.route("http://127.0.0.1:17866/**", (route) =>
    route.fulfill({ json: { success: true, connected: true, printers: [] } }),
  );
}

test.describe("client-facing visual regression", () => {
  test.use({ colorScheme: "light" });

  test("MFA setup onboarding is light and readable", async ({ page }) => {
    await page.route("**/api/auth/me", (route) => route.fulfill({ json: { success: false } }));
    await page.route("**/api/auth/login", (route) =>
      route.fulfill({
        json: {
          success: true,
          data: {
            user: userFor("LICENSEE_ADMIN"),
            auth: { sessionStage: "MFA_BOOTSTRAP", authAssurance: "PASSWORD", mfaRequired: true, mfaEnrolled: false },
          },
        },
      }),
    );
    await page.route("**/api/auth/mfa/setup/begin", (route) =>
      route.fulfill({
        json: {
          success: true,
          data: {
            secret: "MASKEDVISUALSECRET",
            otpauthUri: "otpauth://totp/MSCQR:admin@acme.com?secret=MASKEDVISUALSECRET&issuer=MSCQR",
            backupCodes: ["ABCD-1001", "ABCD-1002", "ABCD-1003", "ABCD-1004", "ABCD-1005", "ABCD-1006"],
          },
        },
      }),
    );
    await page.goto("/login");
    await page.getByLabel("Email").fill("admin@acme.com");
    await page.getByRole("textbox", { name: "Password" }).fill("Password123!");
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page.getByRole("heading", { name: "Set up admin MFA" })).toBeVisible();
    await expect(page).toHaveScreenshot("client-mfa-setup-light.png", {
      animations: "disabled",
      mask: [page.getByAltText("Authenticator setup QR code"), page.locator('[value="MASKEDVISUALSECRET"]')],
    });
  });

  test("brand admin polished pages", async ({ page }) => {
    await mockClientApis(page, "LICENSEE_ADMIN");
    for (const [path, heading, screenshot] of [
      ["/dashboard", "Overview", "client-overview.png"],
      ["/batches", "Batches", "client-batches.png"],
      ["/audit-history", "History", "client-history.png"],
      ["/account", "Account & Security", "client-account.png"],
      ["/manufacturers", "Manufacturers", "client-manufacturers.png"],
      ["/code-requests", "QR Requests", "client-qr-requests.png"],
    ] as const) {
      await page.goto(path);
      await expect(page.locator("h1", { hasText: heading }).first()).toBeVisible();
      await expect(page).toHaveScreenshot(screenshot, { animations: "disabled" });
    }
  });

  test("scans analytics page is polished", async ({ page }) => {
    await mockClientApis(page, "LICENSEE_ADMIN");
    await page.goto("/dashboard");
    await expect(page.locator("h1", { hasText: "Overview" }).first()).toBeVisible();
    await page.goto("/scan-activity");
    await expect(page).toHaveURL(/\/scan-activity/);
    await expect(page.locator("h1", { hasText: "Scans" }).first()).toBeVisible();
    await expect(page).toHaveScreenshot("client-scans.png", { animations: "disabled" });
  });

  test("batch detail modal", async ({ page }) => {
    await mockClientApis(page, "LICENSEE_ADMIN");
    await page.goto("/batches");
    await page.getByTestId("batch-workspace-open").first().click();
    await expect(page.getByTestId("batch-workspace-dialog")).toBeVisible();
    await expect(page).toHaveScreenshot("client-batch-detail-modal.png", { animations: "disabled" });
  });

  test("manufacturer batches page", async ({ page }) => {
    await mockClientApis(page, "MANUFACTURER");
    await page.goto("/batches");
    await expect(page.getByRole("heading", { name: "Batches" })).toBeVisible();
    await expect(page).toHaveScreenshot("client-manufacturer-batches.png", { animations: "disabled" });
  });
});
