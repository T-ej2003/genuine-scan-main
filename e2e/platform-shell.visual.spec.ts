import { expect, test, type Page } from "@playwright/test";

type MockRole = "SUPER_ADMIN" | "LICENSEE_ADMIN" | "MANUFACTURER";

const roleProfiles: Record<MockRole, { name: string; email: string; licenseeId?: string; orgId?: string }> = {
  SUPER_ADMIN: { name: "Super Admin", email: "admin@mscqr.com" },
  LICENSEE_ADMIN: { name: "Acme Admin", email: "admin@acme.com", licenseeId: "licensee-acme", orgId: "licensee-acme" },
  MANUFACTURER: { name: "Acme Factory 1", email: "factory1@acme.com", licenseeId: "licensee-acme", orgId: "licensee-acme" },
};

const visualConsentState = {
  version: 1,
  updatedAt: "2026-04-24T12:00:00.000Z",
  categories: {
    functional: true,
    analytics: false,
    marketing: false,
  },
};

const authPayloadForRole = (role: MockRole) => {
  const profile = roleProfiles[role];
  return {
    success: true,
    data: {
      id: `${role.toLowerCase()}-visual-user`,
      email: profile.email,
      name: profile.name,
      role,
      licenseeId: profile.licenseeId || null,
      orgId: profile.orgId || null,
      licensee: profile.licenseeId
        ? { id: profile.licenseeId, name: "Acme Corporation", prefix: "A", brandName: "Acme Corporation" }
        : null,
      linkedLicensees:
        role === "MANUFACTURER"
          ? [{ id: "licensee-acme", name: "Acme Corporation", prefix: "A", brandName: "Acme Corporation", isPrimary: true }]
          : [],
      createdAt: "2026-04-24T12:00:00.000Z",
      isActive: true,
      auth: {
        sessionStage: "ACTIVE",
        authAssurance: "PASSWORD",
        mfaRequired: false,
        mfaEnrolled: false,
        authenticatedAt: "2026-04-24T12:00:00.000Z",
      },
    },
  };
};

const mockPlatformApis = async (page: Page, role: MockRole) => {
  await page.addInitScript((consentState) => {
    window.localStorage.setItem("mscqr_cookie_consent_state:v1", JSON.stringify(consentState));
  }, visualConsentState);

  if (role === "MANUFACTURER") {
    await page.addInitScript(() => {
      window.sessionStorage.setItem("manufacturer-printer-dialog-opened:v1:manufacturer-visual-user", "shown");
      window.localStorage.setItem("manufacturer-printer-onboarding:v1:manufacturer-visual-user", "dismissed");
    });
  }

  await page.route("**/api/auth/me", (route) => route.fulfill({ json: authPayloadForRole(role) }));
  await page.route("**/api/telemetry/route-transition", (route) => route.fulfill({ json: { success: true } }));
  await page.route("**/api/dashboard/stats**", (route) =>
    route.fulfill({
      json: {
        success: true,
        data: { totalQRCodes: 1240, activeLicensees: role === "SUPER_ADMIN" ? 2 : 1, manufacturers: 3, totalBatches: 18 },
      },
    }),
  );
  await page.route("**/api/qr/stats**", (route) =>
    route.fulfill({
      json: {
        success: true,
        data: {
          dormant: 320,
          allocated: 410,
          printed: 390,
          scanned: 120,
          byStatus: { DORMANT: 320, ALLOCATED: 410, PRINTED: 390, SCANNED: 120 },
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
            id: "audit-visual-1",
            action: "PRINT_CONFIRMED",
            entityType: "PrintJob",
            entityId: "PJ-2049",
            createdAt: "2026-04-24T12:04:00.000Z",
          },
        ],
      },
    }),
  );
  await page.route("**/api/notifications**", (route) =>
    route.fulfill({
      json: {
        success: true,
        data: {
          notifications: [
            {
              id: "note-visual-1",
              title: "Duplicate review signal",
              body: "A repeated public scan needs operator review.",
              type: "duplicate_review",
              data: { targetRoute: "/scan-activity" },
              readAt: null,
              createdAt: "2026-04-24T12:02:00.000Z",
            },
          ],
          unread: 1,
          total: 1,
        },
      },
    }),
  );
  await page.route("**/api/dashboard/attention-queue", (route) =>
    route.fulfill({
      json: {
        success: true,
        data: {
          generatedAt: "2026-04-24T12:05:00.000Z",
          summary: {
            unreadNotifications: 1,
            reviewSignals: role === "MANUFACTURER" ? 1 : 3,
            printOperations: 2,
            supportEscalations: role === "SUPER_ADMIN" ? 1 : 0,
            auditEvents24h: 14,
          },
          items: [
            {
              id: "policy-visual-1",
              type: "policy_alert",
              title: "3 unacknowledged policy alerts",
              body: "Velocity spike requires review before further customer-facing verification.",
              tone: "review",
              route: role === "SUPER_ADMIN" ? "/incident-response" : "/scan-activity",
              count: 3,
              createdAt: "2026-04-24T12:01:00.000Z",
            },
            {
              id: "print-visual-1",
              type: "print_job",
              title: "2 active print operations",
              body: "PJ-2049 is PRINTER_ACKNOWLEDGED.",
              tone: "print",
              route: "/batches",
              count: 2,
              createdAt: "2026-04-24T12:00:00.000Z",
            },
          ],
        },
      },
    }),
  );
  await page.route("**/api/events/**", (route) => route.abort());
  await page.route("http://127.0.0.1:17866/status", (route) =>
    route.fulfill({
      json: {
        connected: role === "MANUFACTURER",
        printerName: role === "MANUFACTURER" ? "MSCQR Visual Printer" : null,
        printerId: role === "MANUFACTURER" ? "visual-printer" : null,
        selectedPrinterId: role === "MANUFACTURER" ? "visual-printer" : null,
        selectedPrinterName: role === "MANUFACTURER" ? "MSCQR Visual Printer" : null,
        agentId: "visual-agent",
        deviceName: "visual-workstation",
        agentVersion: "visual",
        printers:
          role === "MANUFACTURER"
            ? [{ printerId: "visual-printer", printerName: "MSCQR Visual Printer", isDefault: true }]
            : [],
      },
    }),
  );
  await page.route("http://127.0.0.1:17866/backend/config", (route) => route.fulfill({ json: { success: true } }));
  await page.route("**/api/printer-agent/local/claim", (route) => route.fulfill({ json: { success: true, data: null } }));
  await page.route("**/api/manufacturer/printer-agent/events", (route) => route.abort());
  await page.route("**/api/manufacturer/printer-agent/heartbeat", (route) =>
    route.fulfill({
      json: {
        success: true,
        data: {
          connected: role === "MANUFACTURER",
          trusted: role === "MANUFACTURER",
          compatibilityMode: false,
          degraded: false,
          eligibleForPrinting: role === "MANUFACTURER",
          connectionClass: role === "MANUFACTURER" ? "TRUSTED" : "BLOCKED",
          stale: false,
          requiredForPrinting: true,
          trustStatus: role === "MANUFACTURER" ? "TRUSTED" : "UNREGISTERED",
          trustReason: role === "MANUFACTURER" ? "Visual fixture printer trusted" : "No visual printer",
          lastHeartbeatAt: "2026-04-24T12:05:00.000Z",
          ageSeconds: 0,
          printerName: role === "MANUFACTURER" ? "MSCQR Visual Printer" : null,
          printerId: role === "MANUFACTURER" ? "visual-printer" : null,
          selectedPrinterId: role === "MANUFACTURER" ? "visual-printer" : null,
          selectedPrinterName: role === "MANUFACTURER" ? "MSCQR Visual Printer" : null,
          deviceName: "visual-workstation",
          printers:
            role === "MANUFACTURER"
              ? [{ printerId: "visual-printer", printerName: "MSCQR Visual Printer", isDefault: true }]
              : [],
        },
      },
    }),
  );
  await page.route("**/api/manufacturer/printers**", (route) =>
    route.fulfill({
      json: {
        success: true,
        data:
          role === "MANUFACTURER"
            ? [
                {
                  id: "visual-managed-printer",
                  name: "MSCQR Visual Printer",
                  manufacturerId: "manufacturer-visual-user",
                  connectionType: "LOCAL_AGENT",
                  isActive: true,
                },
              ]
            : [],
      },
    }),
  );
  await page.route("**/api/manufacturer/printer-agent/status", (route) =>
    route.fulfill({
      json: {
        success: true,
        data: {
          connected: role === "MANUFACTURER",
          eligibleForPrinting: role === "MANUFACTURER",
          trustStatus: role === "MANUFACTURER" ? "TRUSTED" : "PENDING",
        },
      },
    }),
  );
};

test.describe("platform shell visual regression", () => {
  test.use({ colorScheme: "light" });

  test("platform admin workspace shell", async ({ page }) => {
    await mockPlatformApis(page, "SUPER_ADMIN");
    await page.goto("/dashboard");
    await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
    await expect(page).toHaveScreenshot("platform-shell-super-admin-dashboard.png", {
      animations: "disabled",
      maxDiffPixelRatio: 0.08,
    });
  });

  test("brand admin workspace shell", async ({ page }) => {
    await mockPlatformApis(page, "LICENSEE_ADMIN");
    await page.goto("/dashboard");
    await expect(page.getByText("Acme Corporation", { exact: true }).first()).toBeVisible();
    await expect(page).toHaveScreenshot("platform-shell-licensee-dashboard.png", {
      animations: "disabled",
      maxDiffPixelRatio: 0.08,
    });
  });

  test("manufacturer mobile shell with activity sheet", async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await mockPlatformApis(page, "MANUFACTURER");
    await page.goto("/dashboard");
    await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
    await expect(page.getByRole("dialog").filter({ hasText: "Printing Status" })).toBeHidden();

    const activityButton = page.getByLabel("Open workspace activity");
    await activityButton.click({ trial: true });
    await activityButton.click();
    await expect(page.getByRole("dialog").getByText("Workspace activity").first()).toBeVisible();
    await expect(page).toHaveScreenshot("platform-shell-manufacturer-mobile-intelligence.png", {
      animations: "disabled",
      maxDiffPixelRatio: 0.08,
    });
  });
});
