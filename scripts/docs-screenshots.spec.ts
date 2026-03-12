import { test, expect, type Locator, type Page } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";

type Callout = {
  locator: Locator;
  text: string;
};

type OverlaySpec = {
  title: string;
  callouts?: Callout[];
};

const OUT_DIR = path.join(process.cwd(), "public", "docs");

const BASE_URL = process.env.DOCS_BASE_URL || "http://localhost:8080";
const OPERATIONS_BASE_URL = process.env.DOCS_OPERATIONS_BASE_URL || BASE_URL;
const MANUFACTURER_BASE_URL = process.env.DOCS_MANUFACTURER_BASE_URL || BASE_URL;

const SUPERADMIN_EMAIL = process.env.DOCS_SUPERADMIN_EMAIL || "administration@mscqr.com";
const SUPERADMIN_LOGIN_EMAIL = process.env.DOCS_SUPERADMIN_LOGIN_EMAIL || SUPERADMIN_EMAIL;
const SUPERADMIN_PASSWORD = process.env.DOCS_SUPERADMIN_PASSWORD || "admin123";
const SUPERADMIN_ACCESS_TOKEN = String(process.env.DOCS_SUPERADMIN_ACCESS_TOKEN || "").trim();

const LICENSEE_ADMIN_EMAIL = process.env.DOCS_LICENSEE_ADMIN_EMAIL || "admin@acme.com";
const LICENSEE_ADMIN_PASSWORD = process.env.DOCS_LICENSEE_ADMIN_PASSWORD || "licensee123";

const MANUFACTURER_EMAIL = process.env.DOCS_MANUFACTURER_EMAIL || "factory1@acme.com";
const MANUFACTURER_PASSWORD = process.env.DOCS_MANUFACTURER_PASSWORD || "manufacturer123";

const DOCS_CODE = process.env.DOCS_QR_CODE || "A0000000051";
const DOCS_DUPLICATE_CODE = process.env.DOCS_DUPLICATE_QR_CODE || DOCS_CODE;
const DOCS_BATCH_NAME =
  process.env.DOCS_BATCH_NAME ||
  `Docs Batch ${new Date().toISOString().slice(0, 16).replace(/[:T]/g, "-")}`;
const RESUME_STAGE = String(process.env.DOCS_RESUME_FROM || "setup").trim().toLowerCase();
const STAGE_ORDER = {
  setup: 0,
  manufacturer: 1,
  customer: 2,
  ir: 3,
} as const;

const activeResumeStage = (RESUME_STAGE in STAGE_ORDER ? RESUME_STAGE : "setup") as keyof typeof STAGE_ORDER;
const shouldRunStage = (stage: keyof typeof STAGE_ORDER) => STAGE_ORDER[activeResumeStage] <= STAGE_ORDER[stage];

const disableMotion = async (page: Page) => {
  await page.addStyleTag({
    content: `
      *, *::before, *::after {
        animation-duration: 0s !important;
        animation-delay: 0s !important;
        transition-duration: 0s !important;
        scroll-behavior: auto !important;
      }
    `,
  });
};

const goto = async (page: Page, url: string) => {
  await page.goto(url, { waitUntil: "domcontentloaded" });
  await page.waitForTimeout(250);
};

const login = async (page: Page, baseUrl: string, email: string, password: string) => {
  await goto(page, `${baseUrl}/login`);
  await page.locator("#email").fill(email);
  await page.locator("#password").fill(password);
  await page.getByRole("button", { name: /^sign in$/i }).click();
  // Remote DB + first-load bundles can be slow; wait for any authenticated app route.
  await page.waitForFunction(
    () => {
      const publicAuthRoutes = new Set([
        "/login",
        "/forgot-password",
        "/reset-password",
        "/accept-invite",
      ]);
      return !publicAuthRoutes.has(window.location.pathname);
    },
    undefined,
    { timeout: 60_000 },
  );
  await expect(page.locator("main")).toBeVisible({ timeout: 15_000 });
};

const authenticateSuperAdmin = async (page: Page, baseUrl: string) => {
  if (!SUPERADMIN_ACCESS_TOKEN) {
    await login(page, baseUrl, SUPERADMIN_LOGIN_EMAIL, SUPERADMIN_PASSWORD);
    return;
  }

  const host = new URL(baseUrl).hostname;
  await page.context().setExtraHTTPHeaders({
    Authorization: `Bearer ${SUPERADMIN_ACCESS_TOKEN}`,
  });
  await page.context().addCookies([
    {
      name: "aq_access",
      value: SUPERADMIN_ACCESS_TOKEN,
      domain: host,
      path: "/",
      httpOnly: true,
      secure: false,
      sameSite: "Lax",
    },
    {
      name: "aq_csrf",
      value: "docs-csrf",
      domain: host,
      path: "/",
      httpOnly: false,
      secure: false,
      sameSite: "Lax",
    },
  ]);
};

const clearOverlay = async (page: Page) => {
  await page.evaluate(() => {
    const root = document.getElementById("__aq_doc_overlay");
    if (root) root.remove();
  });
};

const applyOverlay = async (page: Page, spec: OverlaySpec) => {
  const callouts = spec.callouts || [];
  const resolved = [];

  for (const c of callouts) {
    await expect(c.locator).toBeVisible({ timeout: 15_000 });
    const box = await c.locator.boundingBox();
    if (!box) continue;
    resolved.push({
      x: box.x,
      y: box.y,
      w: box.width,
      h: box.height,
      text: c.text,
    });
  }

  await page.evaluate(
    ({ resolvedCallouts }) => {
      const prev = document.getElementById("__aq_doc_overlay");
      if (prev) prev.remove();

      const root = document.createElement("div");
      root.id = "__aq_doc_overlay";
      root.style.position = "fixed";
      root.style.inset = "0";
      root.style.zIndex = "2147483647";
      root.style.pointerEvents = "none";
      root.style.fontFamily =
        'ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, "Helvetica Neue", Arial, "Noto Sans", "Liberation Sans", sans-serif';
      document.body.appendChild(root);

      const clamp = (v: number, min: number, max: number) => Math.max(min, Math.min(max, v));
      const makeDiv = () => document.createElement("div");
      const placed: Array<{ left: number; top: number; right: number; bottom: number }> = [];
      const overlaps = (a: { left: number; top: number; right: number; bottom: number }, b: { left: number; top: number; right: number; bottom: number }) =>
        !(a.right <= b.left || a.left >= b.right || a.bottom <= b.top || a.top >= b.bottom);

      for (const c of resolvedCallouts as any[]) {
        const inset = 4;
        const highlight = makeDiv();
        highlight.style.position = "fixed";
        highlight.style.left = `${c.x - inset}px`;
        highlight.style.top = `${c.y - inset}px`;
        highlight.style.width = `${c.w + inset * 2}px`;
        highlight.style.height = `${c.h + inset * 2}px`;
        highlight.style.borderRadius = "14px";
        highlight.style.background = "rgba(34, 211, 238, 0.08)";
        highlight.style.border = "2px solid rgba(34, 211, 238, 0.92)";
        highlight.style.boxShadow =
          "0 0 0 1px rgba(15, 23, 42, 0.14), 0 10px 24px rgba(34, 211, 238, 0.2)";
        root.appendChild(highlight);

        const label = makeDiv();
        label.textContent = c.text;
        label.style.position = "fixed";
        label.style.maxWidth = "220px";
        label.style.padding = "5px 9px";
        label.style.borderRadius = "10px";
        label.style.background = "rgba(15, 23, 42, 0.9)";
        label.style.border = "1px solid rgba(34, 211, 238, 0.9)";
        label.style.color = "rgba(241, 245, 249, 0.98)";
        label.style.fontSize = "11px";
        label.style.lineHeight = "1.3";
        label.style.fontWeight = "600";
        label.style.boxShadow = "0 10px 24px rgba(15, 23, 42, 0.28)";
        root.appendChild(label);

        const placeInside = c.w >= 180 && c.h >= 64;
        let left = clamp(c.x + 10, 12, window.innerWidth - 232);
        let top = placeInside ? c.y + 10 : c.y - 34;
        label.style.left = `${left}px`;
        label.style.top = `${top}px`;

        let rect = label.getBoundingClientRect();
        if (!placeInside && rect.top < 12) {
          top = c.y + c.h + 10;
          label.style.top = `${top}px`;
          rect = label.getBoundingClientRect();
        }

        for (let tries = 0; tries < 6; tries++) {
          const box = { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom };
          if (!placed.some((p) => overlaps(box, p))) {
            placed.push(box);
            break;
          }

          top = clamp(top + rect.height + 8, 12, window.innerHeight - rect.height - 12);
          label.style.top = `${top}px`;
          rect = label.getBoundingClientRect();
        }
      }
    },
    { resolvedCallouts: resolved }
  );
};

const screenshot = async (page: Page, filename: string, overlay?: OverlaySpec) => {
  await clearOverlay(page);
  if (overlay) await applyOverlay(page, overlay);
  await page.waitForTimeout(150);
  await page.screenshot({ path: path.join(OUT_DIR, filename) });
  await clearOverlay(page);
};

const openLicenseeBatchWorkspace = async (page: Page, batchName: string) => {
  const namedRow = page.locator("tr", { hasText: batchName }).first();
  const row =
    (await namedRow.count()) > 0
      ? namedRow
      : page
          .locator("tr")
          .filter({ has: page.getByRole("button", { name: /^open$/i }) })
          .first();
  await expect(row).toBeVisible({ timeout: 20_000 });
  await row.getByRole("button", { name: /^open$/i }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByRole("tab", { name: /^overview$/i })).toBeVisible({ timeout: 15_000 });
  return dialog;
};

test.describe.configure({ mode: "serial" });
test.setTimeout(20 * 60_000);

test("capture help screenshots", async ({ browser }) => {
  fs.mkdirSync(OUT_DIR, { recursive: true });

  if (shouldRunStage("setup")) {
    // Public: login + onboarding screens (no submission required)
    {
      const ctx = await browser.newContext({ viewport: { width: 1300, height: 780 } });
      const page = await ctx.newPage();
      await disableMotion(page);

      await goto(page, `${OPERATIONS_BASE_URL}/login`);
      await page.locator("#email").fill(SUPERADMIN_EMAIL);
      await page.locator("#password").fill("********");
      await screenshot(page, "access-super-admin-login.png", {
        title: "Documentation Capture - Super Admin Access",
        callouts: [
          { locator: page.locator("#email"), text: "Enter your email address" },
          { locator: page.locator("#password"), text: "Enter your password" },
          { locator: page.getByRole("button", { name: /^sign in$/i }), text: "Sign in with provided credentials" },
        ],
      });

      await goto(page, `${OPERATIONS_BASE_URL}/accept-invite?token=docs-token`);
      await page.locator("#password").fill("********");
      await page.locator("#confirm").fill("********");
      await screenshot(page, "password-accept-invite.png", {
        title: "Documentation Capture - Accept Invite",
        callouts: [
          { locator: page.locator("#password"), text: "Set your new password" },
          { locator: page.getByRole("button", { name: /activate account/i }), text: "Activate to finish onboarding" },
        ],
      });

      await goto(page, `${OPERATIONS_BASE_URL}/forgot-password`);
      await page.locator("#email").fill(SUPERADMIN_EMAIL);
      await screenshot(page, "password-forgot-password.png", {
        title: "Documentation Capture - Forgot Password",
        callouts: [
          { locator: page.locator("#email"), text: "Enter your account email" },
          { locator: page.getByRole("button", { name: /send reset link/i }), text: "Request a reset link" },
        ],
      });

      await goto(page, `${OPERATIONS_BASE_URL}/reset-password?token=docs-token`);
      await page.locator("#password").fill("********");
      await page.locator("#confirm").fill("********");
      await screenshot(page, "password-reset-password.png", {
        title: "Documentation Capture - Reset Password",
        callouts: [
          { locator: page.locator("#password"), text: "Enter your new password" },
          { locator: page.getByRole("button", { name: /update password/i }), text: "Update password" },
        ],
      });

      await ctx.close();
    }

    // Licensee admin: request inventory, open assign dialog, create manufacturer modal
    const licenseeCtx = await browser.newContext({ viewport: { width: 1500, height: 820 } });
    const licenseePage = await licenseeCtx.newPage();
    await disableMotion(licenseePage);
    await login(licenseePage, OPERATIONS_BASE_URL, LICENSEE_ADMIN_EMAIL, LICENSEE_ADMIN_PASSWORD);

    await goto(licenseePage, `${OPERATIONS_BASE_URL}/qr-requests`);
    const qtyInput = licenseePage.locator('input[type="number"]').first();
    const batchNameInput = licenseePage.getByPlaceholder("Example: March Retail Rollout");
    const noteInput = licenseePage.locator("input").nth(2);
    await qtyInput.fill("250");
    await batchNameInput.fill(DOCS_BATCH_NAME);
    await noteInput.fill("Docs capture request");
    await screenshot(licenseePage, "licensee-request-qr-inventory.png", {
      title: "Documentation Capture - Licensee/Admin - Request QR Inventory",
      callouts: [
        { locator: qtyInput, text: "Enter the quantity you need" },
        { locator: batchNameInput, text: "Add a request reference to help the approver identify this request" },
        { locator: licenseePage.getByRole("button", { name: /submit request/i }), text: "Submit quantity request" },
      ],
    });
    await licenseePage.getByRole("button", { name: /submit request/i }).click();
    await licenseePage.waitForTimeout(800);

    await goto(licenseePage, `${OPERATIONS_BASE_URL}/manufacturers`);
    await licenseePage.getByRole("button", { name: /add manufacturer/i }).click();
    const manufacturerDialog = licenseePage.getByRole("dialog");
    await screenshot(licenseePage, "licensee-create-manufacturer.png", {
      title: "Documentation Capture - Licensee/Admin - Create Manufacturer",
      callouts: [
        { locator: manufacturerDialog.getByPlaceholder("Factory A"), text: "Enter the manufacturer name" },
        { locator: manufacturerDialog.getByPlaceholder("factory@example.com"), text: "Manufacturer login email" },
        { locator: manufacturerDialog.getByText(/invite link only/i).first(), text: "User onboarding is handled through a one-time invite link" },
      ],
    });
    // Close dialog
    await licenseePage.getByRole("button", { name: /^cancel$/i }).click();

    // Super admin: approve the pending request + capture licensee creation modal + IR dashboard
    const superCtx = await browser.newContext({ viewport: { width: 1500, height: 820 } });
    const superPage = await superCtx.newPage();
    await disableMotion(superPage);
    await authenticateSuperAdmin(superPage, OPERATIONS_BASE_URL);

    await goto(superPage, `${OPERATIONS_BASE_URL}/licensees`);
    await superPage.getByRole("button", { name: /add licensee/i }).click();
    await screenshot(superPage, "superadmin-create-licensee.png", {
      title: "Documentation Capture - Super Admin - Create Licensee",
      callouts: [
        {
          locator: superPage.getByRole("dialog").getByRole("heading", { name: /create new licensee/i }),
          text: "Create a new licensee (tenant)",
        },
        {
          locator: superPage.getByRole("dialog").getByPlaceholder("Acme Corp"),
          text: "Enter the organization name",
        },
      ],
    });
    // Close dialog (X button)
    await superPage.keyboard.press("Escape");

    await goto(superPage, `${OPERATIONS_BASE_URL}/qr-requests`);
    const pendingRow = superPage.locator("tr", { hasText: DOCS_BATCH_NAME }).first();
    await expect(pendingRow).toBeVisible({ timeout: 15_000 });
    await pendingRow.getByRole("button", { name: /^approve$/i }).click();
    await screenshot(superPage, "superadmin-approve-qr-request.png", {
      title: "Documentation Capture - Super Admin - QR Request Approval",
      callouts: [
        { locator: superPage.getByRole("dialog").getByRole("button", { name: /^approve$/i }), text: "Approve and allocate the request" },
        { locator: superPage.getByRole("dialog"), text: "Review request details" },
      ],
    });
    await superPage.getByRole("dialog").getByRole("button", { name: /^approve$/i }).click();
    await superPage.waitForTimeout(900);

    await goto(superPage, `${OPERATIONS_BASE_URL}/ir`);
    await screenshot(superPage, "ir-dashboard.png", {
      title: "Documentation Capture - IR Center",
      callouts: [
        { locator: superPage.getByRole("tab", { name: /incidents/i }), text: "Incidents queue" },
        { locator: superPage.getByRole("tab", { name: /alerts/i }), text: "Policy alerts" },
        { locator: superPage.getByRole("tab", { name: /policies/i }), text: "Policy rules" },
      ],
    });

    // Policy create modal
    await superPage.getByRole("tab", { name: /policies/i }).click();
    await superPage.getByRole("button", { name: /new policy/i }).click();
    await screenshot(superPage, "ir-policy-create.png", {
      title: "Documentation Capture - Policy Alerts - Create Rule",
      callouts: [
        { locator: superPage.getByRole("dialog"), text: "Create policy rule" },
        { locator: superPage.getByRole("dialog").getByText(/rule type/i), text: "Choose a rule type and thresholds" },
      ],
    });
    await superPage.keyboard.press("Escape");

    await superCtx.close();

    // Licensee admin: capture Assign Manufacturer dialog after approval creates a received batch
    await goto(licenseePage, `${OPERATIONS_BASE_URL}/batches`);
    const assignDialog = await openLicenseeBatchWorkspace(licenseePage, DOCS_BATCH_NAME);
    await assignDialog.getByRole("tab", { name: /^operations$/i }).click();
    await expect(assignDialog.getByRole("button", { name: /allocate quantity/i })).toBeVisible({ timeout: 15_000 });
    await screenshot(licenseePage, "licensee-assign-batch.png", {
      title: "Documentation Capture - Licensee/Admin - Source Batch Workspace",
      callouts: [
        { locator: assignDialog.getByRole("tab", { name: /^operations$/i }), text: "Open Operations to manage source-batch actions" },
        { locator: assignDialog.getByRole("combobox").first(), text: "Choose the manufacturer receiving the allocation" },
        { locator: assignDialog.getByPlaceholder("Enter quantity").first(), text: "Enter quantity" },
        { locator: assignDialog.getByRole("button", { name: /allocate quantity/i }), text: "Create the manufacturer allocation from the source batch" },
      ],
    });
    const manufacturerTrigger = assignDialog.getByRole("combobox").first();
    await manufacturerTrigger.click();
    // Radix Select portals options outside the dialog subtree.
    const manufacturerOption = licenseePage.getByRole("option", { name: new RegExp(MANUFACTURER_EMAIL, "i") });
    if (await manufacturerOption.count()) {
      await manufacturerOption.first().click();
    } else {
      await expect(licenseePage.getByRole("option").first()).toBeVisible({ timeout: 15_000 });
      await licenseePage.getByRole("option").first().click();
    }
    await assignDialog.getByPlaceholder("Enter quantity").fill("2");
    await assignDialog.getByRole("button", { name: /allocate quantity/i }).click();
    await licenseePage.waitForTimeout(1200);
    await licenseePage.keyboard.press("Escape");

    await licenseeCtx.close();
  }

  if (shouldRunStage("manufacturer")) {
    // Manufacturer printing screenshots are source-controlled illustrations.
    // Generate them with `npm run docs:printing:images` so the manuals stay stable
    // even when live test data or printer setup differs across environments.
  }

  if (shouldRunStage("customer")) {
    // Customer (public): verify outcomes + report
    const startCtx = await browser.newContext({ viewport: { width: 900, height: 700 } });
    const startPage = await startCtx.newPage();
    await disableMotion(startPage);

    await goto(startPage, `${OPERATIONS_BASE_URL}/verify`);
    await startPage.getByPlaceholder(/e\.g\.\s*A0000000001/i).fill("A0000000001");
    await screenshot(startPage, "customer-verify-start.png", {
      title: "Customer - Start Verification",
      callouts: [
        { locator: startPage.getByPlaceholder(/e\.g\.\s*A0000000001/i).first(), text: "Enter the code" },
        { locator: startPage.getByRole("button", { name: /^verify$/i }).first(), text: "Select Verify" },
        { locator: startPage.getByRole("button", { name: /use mobile camera capture/i }).first(), text: "Use your camera" },
      ],
    });
    await startCtx.close();

    const customerCtx = await browser.newContext({ viewport: { width: 1200, height: 800 } });
    const customerPage = await customerCtx.newPage();
    await disableMotion(customerPage);

    // First scan
    await goto(customerPage, `${OPERATIONS_BASE_URL}/verify/${encodeURIComponent(DOCS_CODE)}`);
    await customerPage.waitForTimeout(900);
    await screenshot(customerPage, "customer-first-verification.png", {
      title: "Customer - Verified Authentic",
      callouts: [
        { locator: customerPage.getByRole("heading", { name: /verified authentic/i }).first(), text: "Status banner" },
        { locator: customerPage.getByText(/scan summary/i).first(), text: "Scan summary" },
      ],
    });

    // Second scan: verified again
    await goto(customerPage, `${OPERATIONS_BASE_URL}/verify/${encodeURIComponent(DOCS_CODE)}`);
    await customerPage.waitForTimeout(800);
    await screenshot(customerPage, "customer-verified-again.png", {
      title: "Customer - Verified Again",
      callouts: [
        { locator: customerPage.getByRole("heading", { name: /verified again/i }).first(), text: "Repeat check" },
        { locator: customerPage.getByText(/scan summary/i).first(), text: "Earlier scans" },
      ],
    });

    const duplicateCtx = await browser.newContext({ viewport: { width: 1200, height: 800 } });
    const duplicatePage = await duplicateCtx.newPage();
    await disableMotion(duplicatePage);

    const duplicateHeading = duplicatePage.getByRole("heading", { name: /suspicious duplicate|possible duplicate/i }).first();
    await goto(duplicatePage, `${OPERATIONS_BASE_URL}/verify/${encodeURIComponent(DOCS_DUPLICATE_CODE)}`);
    await duplicatePage.waitForTimeout(1200);
    await expect(duplicateHeading).toBeVisible({ timeout: 15_000 });
    await screenshot(duplicatePage, "customer-possible-duplicate.png", {
      title: "Customer - Possible Duplicate",
      callouts: [
        { locator: duplicateHeading, text: "Warning" },
        { locator: duplicatePage.getByText(/duplicate risk signals detected/i).first(), text: "Why it was flagged" },
      ],
    });

    // Report dialog
    await duplicatePage.getByRole("button", { name: /open incident drawer|report suspected counterfeit/i }).first().click();
    await duplicatePage.getByPlaceholder("Describe what looked suspicious.").fill("Docs capture: possible duplicate label observed.");
    await screenshot(duplicatePage, "customer-report-dialog.png", {
      title: "Customer - Report a Suspicious Product",
      callouts: [
        { locator: duplicatePage.getByPlaceholder("Describe what looked suspicious."), text: "Describe the issue" },
        { locator: duplicatePage.getByRole("button", { name: /submit report/i }), text: "Submit report" },
      ],
    });

    // Submit report to ensure an incident exists for IR detail screenshots (best-effort).
    await duplicatePage.getByRole("button", { name: /submit report/i }).click();
    await duplicatePage.waitForTimeout(1200);

    await duplicateCtx.close();
    await customerCtx.close();
  }

  if (shouldRunStage("ir")) {
    // IR incident detail screenshots (open latest incident)
    const irCtx = await browser.newContext({ viewport: { width: 1500, height: 820 } });
    const irPage = await irCtx.newPage();
    await disableMotion(irPage);
    await authenticateSuperAdmin(irPage, OPERATIONS_BASE_URL);
    await goto(irPage, `${OPERATIONS_BASE_URL}/ir`);
    await irPage.getByPlaceholder(/search qr/i).fill(DOCS_CODE);
    await irPage.keyboard.press("Enter");
    await irPage.waitForTimeout(1200);

    const firstIncidentRow = irPage.locator("tbody tr").first();
    await expect(firstIncidentRow).toBeVisible({ timeout: 15_000 });
    await firstIncidentRow.click();
    await irPage.waitForURL("**/ir/incidents/**", { timeout: 15_000 });

    // Open an action dialog
    await irPage.getByRole("button", { name: /^flag qr$/i }).click();
    await screenshot(irPage, "ir-incident-actions.png", {
      title: "Documentation Capture - Incident Actions",
      callouts: [
        { locator: irPage.getByRole("dialog"), text: "Containment action requires a reason" },
        { locator: irPage.getByRole("button", { name: /^confirm$/i }), text: "Apply action (reversible)" },
      ],
    });
    await irPage.keyboard.press("Escape");

    // Communications compose section
    const subjectInput = irPage.locator("label", { hasText: "Subject" }).locator("..").locator("input");
    const messageTextarea = irPage.locator("label", { hasText: "Message" }).locator("..").locator("textarea");
    await subjectInput.fill("Investigation update");
    await messageTextarea.fill("Docs capture message to demonstrate incident communications.");
    await screenshot(irPage, "ir-communication-compose.png", {
      title: "Documentation Capture - Incident Communications",
      callouts: [
        { locator: irPage.getByText(/communications/i).first(), text: "Email is logged in the timeline" },
        { locator: irPage.getByRole("button", { name: /send email/i }), text: "Send email" },
      ],
    });

    await irCtx.close();
  }
});
