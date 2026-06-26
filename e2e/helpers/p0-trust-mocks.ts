import type { Page, Route } from "@playwright/test";

export type FrontendRole = "super_admin" | "licensee_admin" | "manufacturer";

type TrustMockOptions = {
  role?: FrontendRole;
  authenticated?: boolean;
};

const consentState = {
  version: 1,
  updatedAt: "2026-06-01T00:00:00.000Z",
  categories: { functional: true, analytics: false, marketing: false },
};

const roleUser = (role: FrontendRole) => {
  const rawRole =
    role === "super_admin"
      ? "SUPER_ADMIN"
      : role === "licensee_admin"
        ? "LICENSEE_ADMIN"
        : "MANUFACTURER";

  const name =
    role === "super_admin"
      ? "Alex Admin"
      : role === "licensee_admin"
        ? "Avery Brand"
        : "Morgan Factory";

  return {
    id: `${role}-p0-user`,
    email:
      role === "super_admin"
        ? "admin@mscqr.com"
        : role === "licensee_admin"
          ? "admin@acme.example"
          : "factory@acme.example",
    name,
    role: rawRole,
    licenseeId: role === "super_admin" ? null : "licensee-acme",
    orgId: role === "super_admin" ? "platform-org" : "org-acme",
    licensee:
      role === "super_admin"
        ? null
        : { id: "licensee-acme", name: "Acme Brand", prefix: "ACM", brandName: "Acme Brand" },
    linkedLicensees:
      role === "manufacturer"
        ? [{ id: "licensee-acme", name: "Acme Brand", prefix: "ACM", brandName: "Acme Brand", isPrimary: true }]
        : [],
    createdAt: "2026-06-01T00:00:00.000Z",
    isActive: true,
    auth: {
      sessionStage: "ACTIVE",
      authAssurance: "ADMIN_MFA",
      mfaRequired: true,
      mfaEnrolled: true,
      mfaVerifiedAt: "2026-06-01T00:00:00.000Z",
      sessionId: `${role}-session`,
      sessionExpiresAt: "2026-06-01T08:00:00.000Z",
    },
  };
};

const authSessionPayload = (role: FrontendRole) => {
  const user = roleUser(role);
  return {
    user,
    auth: user.auth,
    accessToken: `p0-${role}-access-token`,
  };
};

const batchRows = [
  {
    id: "batch-p0-source",
    name: "P0 Retail Run",
    licenseeId: "licensee-acme",
    licensee: { id: "licensee-acme", name: "Acme Brand", prefix: "ACM" },
    manufacturerId: "manufacturer-p0-user",
    manufacturer: { id: "manufacturer-p0-user", name: "Acme Factory", email: "factory@acme.example" },
    totalCodes: 5000,
    startCode: "ACM-P0-0001",
    endCode: "ACM-P0-5000",
    printableCodes: 3000,
    printedCodes: 1500,
    redeemedCodes: 42,
    blockedCodes: 1,
    createdAt: "2026-06-01T00:00:00.000Z",
  },
];

const emptyPage = { items: [], total: 0, page: 1, pageSize: 25 };

const json = (route: Route, data: unknown, status = 200) =>
  route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(data),
  });

const apiPath = (route: Route) => {
  const url = new URL(route.request().url());
  return url.pathname.replace(/^\/api/, "") || "/";
};

const apiRoutePatterns = [
  "**/api/**",
  "http://127.0.0.1:4000/**",
  "http://localhost:4000/**",
  /.*\/(?:auth|dashboard|notifications|qr|licensees|manufacturers|users|admin|audit|trace|analytics|policy|support|ir|incidents|governance|internal|security|manufacturer|public|telemetry|events|verify)(?:\/.*)?$/,
] as const;

const dashboardStats = {
  totalBatches: 1,
  totalCodes: 5000,
  printedCodes: 1500,
  scanEvents: 42,
  scansToday: 6,
  activeLicensees: 1,
};

const qrStats = {
  total: 5000,
  dormant: 3000,
  allocated: 500,
  printed: 1500,
  redeemed: 42,
  blocked: 1,
};

const routePayload = (path: string) => {
  if (path === "/dashboard/stats") return { success: true, data: dashboardStats };
  if (path === "/dashboard/attention-queue") return { success: true, data: [] };
  if (path.startsWith("/notifications")) return { success: true, data: { items: [], unreadCount: 0, total: 0 } };
  if (path === "/qr/stats") return { success: true, data: qrStats };
  if (path.startsWith("/qr/batches")) return { success: true, data: batchRows };
  if (path.startsWith("/qr/requests")) {
    return {
      success: true,
      data: [
        {
          id: "qr-request-p0",
          status: "PENDING",
          quantity: 1000,
          batchName: "P0 Request",
          licenseeId: "licensee-acme",
          createdAt: "2026-06-01T00:00:00.000Z",
          licensee: { id: "licensee-acme", name: "Acme Brand", prefix: "ACM" },
        },
      ],
    };
  }
  if (path.startsWith("/licensees")) {
    return { success: true, data: [{ id: "licensee-acme", name: "Acme Brand", prefix: "ACM", isActive: true }] };
  }
  if (path.startsWith("/manufacturers") || path.startsWith("/users")) {
    return {
      success: true,
      data: [{ id: "manufacturer-p0-user", name: "Acme Factory", email: "factory@acme.example", isActive: true }],
    };
  }
  if (path.startsWith("/admin/qr/analytics")) return { success: true, data: { totals: qrStats, trend: [], batches: batchRows } };
  if (path.startsWith("/admin/qr/scan-logs")) return { success: true, data: emptyPage };
  if (path.startsWith("/admin/qr/batch-summary")) return { success: true, data: [] };
  if (path.startsWith("/audit/logs") || path.startsWith("/audit/fraud-reports")) return { success: true, data: emptyPage };
  if (path.startsWith("/trace/timeline")) return { success: true, data: [] };
  if (path.startsWith("/analytics/")) return { success: true, data: { rows: [], totals: {} } };
  if (path.startsWith("/policy/")) return { success: true, data: { items: [], config: {} } };
  if (path.startsWith("/support/request-access")) {
    return {
      success: true,
      data: {
        records: [
          {
            id: "request-access-phase-e2",
            referenceCode: "REQ-E2",
            fullName: "Phase E2 Request Access",
            workEmail: "request-access-secret@example.test",
            companyName: "Protected Platform Queue",
            roleTitle: "Operations",
            country: "Test",
            monthlyGarmentVolume: "1000",
            status: "NEW",
            internalNote: "phase-e2-request-access-internal-note",
            createdAt: "2026-06-01T00:00:00.000Z",
          },
        ],
        total: 1,
        limit: 50,
        offset: 0,
      },
    };
  }
  if (path.startsWith("/support/tickets") || path.startsWith("/support/reports")) return { success: true, data: emptyPage };
  if (path.startsWith("/ir/incidents") || path.startsWith("/incidents")) return { success: true, data: emptyPage };
  if (path.startsWith("/ir/policies") || path.startsWith("/ir/alerts")) return { success: true, data: emptyPage };
  if (path.startsWith("/governance/feature-flags")) return { success: true, data: [] };
  if (path.startsWith("/governance/evidence-retention")) return { success: true, data: { days: 365, enabled: true } };
  if (path.startsWith("/governance/compliance/report")) return { success: true, data: { generatedAt: "2026-06-01T00:00:00.000Z" } };
  if (path.startsWith("/governance/compliance/pack/jobs")) return { success: true, data: emptyPage };
  if (path.startsWith("/governance/approvals")) return { success: true, data: emptyPage };
  if (path.startsWith("/internal/release")) return { success: true, data: { version: "p0-test" } };
  if (path.startsWith("/security/abuse/rate-limits")) return { success: true, data: { items: [] } };
  if (path.startsWith("/auth/mfa/status")) return { success: true, data: { required: true, enabled: true, backupCodesRemaining: 6 } };
  if (path.startsWith("/auth/sessions")) return { success: true, data: { items: [], summary: null } };
  if (path.startsWith("/manufacturer/printer-agent/status")) return { success: true, data: { connected: false, mode: "not_configured" } };
  if (path.startsWith("/manufacturer/printers") || path.startsWith("/manufacturer/print-jobs")) return { success: true, data: [] };
  if (path.startsWith("/public/connector/releases/latest")) return { success: true, data: { version: "1.0.0", assets: [] } };
  return { success: true, data: {} };
};

export async function installP0TrustMocks(page: Page, options: TrustMockOptions = {}) {
  let authenticated = options.authenticated ?? true;
  const role = options.role || "super_admin";

  if (process.env.P0_DEBUG_MOCKS === "1") {
    page.on("request", (request) => {
      const url = request.url();
      if (url.includes("/api/") || url.includes("/auth/") || url.includes("/dashboard")) {
        console.log(`[p0-mock:request] ${request.resourceType()} ${url}`);
      }
    });
    page.on("requestfailed", (request) => console.log(`[p0-mock:failed] ${request.url()} ${request.failure()?.errorText}`));
    page.on("pageerror", (error) => console.log(`[p0-mock:pageerror] ${error.message}`));
  }

  await page.addInitScript((state) => {
    window.localStorage.setItem("mscqr_cookie_consent_state:v1", JSON.stringify(state));
    document.cookie = "aq_vid=p0-device; Max-Age=31536000; Path=/; SameSite=Lax";
    window.sessionStorage.setItem("manufacturer-printer-dialog-opened:v1:manufacturer-p0-user", "shown");
    window.localStorage.setItem("manufacturer-printer-onboarding:v1:manufacturer-p0-user:p0-device", "dismissed");
  }, consentState);

  const handleRoute = async (route: Route) => {
    if (!["fetch", "xhr", "eventsource"].includes(route.request().resourceType())) return route.fallback();
    const path = apiPath(route);
    if (path === "/events/dashboard" || path === "/events/notifications") return route.abort();
    if (path === "/audit/stream") return route.fulfill({ status: 200, contentType: "text/event-stream", body: "" });
    if (path === "/telemetry/route-transition" || path === "/telemetry/csp-report") return json(route, { success: true });
    if (path === "/auth/refresh") {
      return authenticated
        ? json(route, { success: true, data: authSessionPayload(role) })
        : json(route, { success: false, error: "Invalid or expired token" }, 401);
    }
    if (path === "/auth/me") {
      return authenticated
        ? json(route, { success: true, data: roleUser(role) })
        : json(route, { success: false, error: "Invalid or expired token" }, 401);
    }
    if (path === "/auth/logout") {
      authenticated = false;
      return json(route, { success: true, data: { cleared: true } });
    }
    return json(route, routePayload(path));
  };

  for (const pattern of apiRoutePatterns) {
    await page.route(pattern, handleRoute);
  }

  return {
    expireSession: () => {
      authenticated = false;
    },
  };
}

export type VerifyScenario = {
  code: string;
  status?: number;
  body?: unknown;
};

const baseVerifyPayload = (code: string) => ({
  code,
  isAuthentic: true,
  status: "REDEEMED",
  publicOutcome: "VERIFIED",
  classification: "FIRST_SCAN",
  isFirstScan: true,
  scanCount: 1,
  licensee: {
    name: "Acme Brand",
    brandName: "Acme Brand",
    website: "https://brand.example",
    supportEmail: "support@brand.example",
  },
  batch: {
    name: "Retail Collection",
    manufacturer: {
      name: "Acme Factory",
      website: "https://factory.example",
    },
  },
  ownershipStatus: { canClaim: false },
  verifyUxPolicy: { allowFraudReport: true },
});

export const verifyScenarioBody = (code: string, kind: "valid" | "invalid" | "blocked" | "pending" | "suspicious") => {
  const payload = baseVerifyPayload(code);
  if (kind === "invalid") {
    return { success: true, data: { ...payload, isAuthentic: false, publicOutcome: "NOT_FOUND", classification: "NOT_FOUND", licensee: null, batch: null } };
  }
  if (kind === "blocked") {
    return { success: true, data: { ...payload, isAuthentic: false, isBlocked: true, publicOutcome: "BLOCKED", status: "BLOCKED", classification: "BLOCKED_BY_SECURITY" } };
  }
  if (kind === "pending") {
    return { success: true, data: { ...payload, isAuthentic: false, isReady: false, publicOutcome: "NOT_READY", status: "DORMANT", classification: "NOT_READY_FOR_CUSTOMER_USE" } };
  }
  if (kind === "suspicious") {
    return {
      success: true,
      data: {
        ...payload,
        isAuthentic: false,
        publicOutcome: "REVIEW_REQUIRED",
        classification: "SUSPICIOUS_DUPLICATE",
        scanCount: 7,
        totalScans: 7,
        warningMessage: "This label has unusual repeat scan activity.",
      },
    };
  }
  return { success: true, data: payload };
};

export async function installP0VerifyMocks(page: Page, scenarios: VerifyScenario[]) {
  await page.addInitScript((state) => {
    window.localStorage.setItem("mscqr_cookie_consent_state:v1", JSON.stringify(state));
  }, consentState);

  const byCode = new Map(scenarios.map((scenario) => [scenario.code.toUpperCase(), scenario]));

  const handleRoute = async (route: Route) => {
    if (!["fetch", "xhr", "eventsource"].includes(route.request().resourceType())) return route.fallback();
    const path = apiPath(route);
    if (path === "/verify/auth/providers") return json(route, { success: true, data: { items: [] } });
    if (path === "/verify/auth/session") return json(route, { success: true, data: null });
    if (path === "/telemetry/route-transition" || path === "/telemetry/csp-report") return json(route, { success: true });

    const match = path.match(/^\/verify\/([^/]+)$/);
    if (match) {
      const code = decodeURIComponent(match[1]).toUpperCase();
      const scenario = byCode.get(code);
      if (!scenario) return json(route, { success: false, error: "QR label not found" }, 404);
      return json(route, scenario.body ?? verifyScenarioBody(scenario.code, "valid"), scenario.status || 200);
    }

    return json(route, { success: true, data: {} });
  };

  for (const pattern of apiRoutePatterns) {
    await page.route(pattern, handleRoute);
  }
}
