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
    ({ title, resolvedCallouts }) => {
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

      // Soft frame around viewport
      const frame = document.createElement("div");
      frame.style.position = "fixed";
      frame.style.inset = "10px";
      frame.style.borderRadius = "16px";
      frame.style.border = "1px solid rgba(148, 163, 184, 0.55)";
      frame.style.boxShadow = "0 0 0 1px rgba(15, 23, 42, 0.08) inset";
      root.appendChild(frame);

      // Title pill
      const pill = document.createElement("div");
      pill.textContent = title;
      pill.style.position = "fixed";
      pill.style.left = "14px";
      pill.style.top = "12px";
      pill.style.padding = "6px 12px";
      pill.style.borderRadius = "999px";
      pill.style.background = "rgba(15, 23, 42, 0.86)";
      pill.style.border = "1px solid rgba(148, 163, 184, 0.35)";
      pill.style.color = "rgba(226, 232, 240, 0.95)";
      pill.style.fontSize = "12px";
      pill.style.fontWeight = "600";
      pill.style.letterSpacing = "0.01em";
      pill.style.boxShadow = "0 10px 30px rgba(2, 6, 23, 0.35)";
      root.appendChild(pill);

      const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      svg.setAttribute("width", String(window.innerWidth));
      svg.setAttribute("height", String(window.innerHeight));
      svg.style.position = "fixed";
      svg.style.inset = "0";
      svg.style.pointerEvents = "none";
      root.appendChild(svg);

      const defs = document.createElementNS("http://www.w3.org/2000/svg", "defs");
      const marker = document.createElementNS("http://www.w3.org/2000/svg", "marker");
      marker.setAttribute("id", "aqArrowHead");
      marker.setAttribute("markerWidth", "10");
      marker.setAttribute("markerHeight", "10");
      marker.setAttribute("refX", "9");
      marker.setAttribute("refY", "3");
      marker.setAttribute("orient", "auto");
      const arrowPath = document.createElementNS("http://www.w3.org/2000/svg", "path");
      arrowPath.setAttribute("d", "M0,0 L10,3 L0,6 Z");
      arrowPath.setAttribute("fill", "#22d3ee");
      marker.appendChild(arrowPath);
      defs.appendChild(marker);
      svg.appendChild(defs);

      const clamp = (v: number, min: number, max: number) => Math.max(min, Math.min(max, v));

      const makeDiv = () => document.createElement("div");

      for (const c of resolvedCallouts as any[]) {
        const highlight = makeDiv();
        highlight.style.position = "fixed";
        highlight.style.left = `${c.x}px`;
        highlight.style.top = `${c.y}px`;
        highlight.style.width = `${c.w}px`;
        highlight.style.height = `${c.h}px`;
        highlight.style.borderRadius = "12px";
        highlight.style.border = "3px solid rgba(34, 211, 238, 0.95)";
        highlight.style.boxShadow =
          "0 0 0 2px rgba(15, 23, 42, 0.15), 0 0 22px rgba(34, 211, 238, 0.35)";
        root.appendChild(highlight);

        const bubble = makeDiv();
        bubble.textContent = c.text;
        bubble.style.position = "fixed";
        bubble.style.maxWidth = "260px";
        bubble.style.padding = "6px 10px";
        bubble.style.borderRadius = "12px";
        bubble.style.background = "rgba(2, 6, 23, 0.88)";
        bubble.style.border = "1px solid rgba(34, 211, 238, 0.85)";
        bubble.style.color = "rgba(226, 232, 240, 0.96)";
        bubble.style.fontSize = "12px";
        bubble.style.fontWeight = "600";
        bubble.style.boxShadow = "0 12px 28px rgba(2, 6, 23, 0.4)";

        const bubbleW = 260;
        const targetX = clamp(c.x, 12, window.innerWidth - bubbleW - 12);
        let bubbleY = c.y - 48;
        if (bubbleY < 12) bubbleY = c.y + c.h + 16;
        bubble.style.left = `${targetX}px`;
        bubble.style.top = `${bubbleY}px`;
        root.appendChild(bubble);

        const b = bubble.getBoundingClientRect();
        const startX = b.left + b.width / 2;
        const startY = bubbleY < c.y ? b.bottom : b.top;
        const endX = c.x + c.w / 2;
        const endY = c.y + c.h / 2;
        const midY = (startY + endY) / 2;
        const ctrlX = startX;
        const ctrlY = midY;

        const pathEl = document.createElementNS("http://www.w3.org/2000/svg", "path");
        pathEl.setAttribute("d", `M ${startX} ${startY} Q ${ctrlX} ${ctrlY} ${endX} ${endY}`);
        pathEl.setAttribute("fill", "none");
        pathEl.setAttribute("stroke", "#22d3ee");
        pathEl.setAttribute("stroke-width", "3");
        pathEl.setAttribute("stroke-linecap", "round");
        pathEl.setAttribute("stroke-linejoin", "round");
        pathEl.setAttribute("marker-end", "url(#aqArrowHead)");
        svg.appendChild(pathEl);
      }
    },
    { title: spec.title, resolvedCallouts: resolved }
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

const selectFirstEnabledPrintJobButton = async (page: Page) => {
  const buttons = page.getByRole("button", { name: /create print job/i });
  await expect(buttons.first()).toBeVisible({ timeout: 20_000 });
  const count = await buttons.count();

  for (let i = 0; i < Math.min(count, 12); i++) {
    const candidate = buttons.nth(i);
    if (await candidate.isDisabled()) continue;
    await candidate.click();
    return;
  }

  throw new Error("Could not find an enabled Create Print Job button.");
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
    // Manufacturer: create print job + direct dispatch + capture status
    const manuCtx = await browser.newContext({ viewport: { width: 1500, height: 820 } });
    const manuPage = await manuCtx.newPage();
    await disableMotion(manuPage);
    await login(manuPage, MANUFACTURER_BASE_URL, MANUFACTURER_EMAIL, MANUFACTURER_PASSWORD);

    await goto(manuPage, `${MANUFACTURER_BASE_URL}/printer-diagnostics`);
    const sameHostMockButton = manuPage.getByRole("button", { name: /use same-host mock printer/i }).first();
    await expect(sameHostMockButton).toBeVisible({ timeout: 20_000 });
    await sameHostMockButton.click();
    await expect(manuPage.getByText(/mock zebra printer/i).first()).toBeVisible({ timeout: 20_000 });
    await manuPage.waitForTimeout(1200);
    await screenshot(manuPage, "manufacturer-printer-diagnostics.png", {
      title: "Documentation Capture - Manufacturer - Printer Diagnostics",
      callouts: [
        { locator: manuPage.getByRole("heading", { name: /printer diagnostics/i }), text: "Validate printer readiness before opening the print dialog" },
        { locator: manuPage.getByText(/mock zebra printer/i).first(), text: "Registered network-direct printer profile" },
        { locator: sameHostMockButton, text: "Quick setup for same-host mock printer testing" },
      ],
    });

    await goto(manuPage, `${MANUFACTURER_BASE_URL}/batches`);
    await selectFirstEnabledPrintJobButton(manuPage);
    const printDialog = manuPage.getByRole("dialog");
    const qtyToPrintInput = printDialog.getByPlaceholder("Enter quantity").first();
    const printerProfileTrigger = printDialog.getByRole("combobox").first();
    await qtyToPrintInput.fill("1");
    if (!/mock zebra printer/i.test((await printerProfileTrigger.innerText()).trim())) {
      await printerProfileTrigger.click();
      await manuPage.getByRole("option", { name: /mock zebra printer/i }).first().click();
    }
    await screenshot(manuPage, "manufacturer-create-print-job.png", {
      title: "Documentation Capture - Manufacturer - Create Print Job",
      callouts: [
        { locator: qtyToPrintInput, text: "Select quantity to print" },
        { locator: printerProfileTrigger, text: "Use the validated registered printer profile" },
        { locator: printDialog.getByRole("button", { name: /create print job & start dispatch/i }), text: "Start controlled direct-print dispatch" },
      ],
    });
    await printDialog.getByRole("button", { name: /create print job & start dispatch/i }).click();
    await expect(printDialog.getByText(/recent print jobs/i)).toBeVisible({ timeout: 20_000 });
    await screenshot(manuPage, "manufacturer-print-status.png", {
      title: "Documentation Capture - Manufacturer - Print Confirmation",
      callouts: [
        { locator: printDialog.getByText(/active print job/i).first(), text: "Current job stays visible in the batch dialog" },
        { locator: printDialog.getByText(/recent print jobs/i).first(), text: "Recent jobs confirm status and printed counts" },
      ],
    });

    await manuCtx.close();
  }

  if (shouldRunStage("customer")) {
    // Customer (public): verify outcomes + report
    const customerCtx = await browser.newContext({ viewport: { width: 1200, height: 800 } });
    const customerPage = await customerCtx.newPage();
    await disableMotion(customerPage);

    // First scan
    await goto(customerPage, `${OPERATIONS_BASE_URL}/verify/${encodeURIComponent(DOCS_CODE)}`);
    await customerPage.waitForTimeout(900);
    await screenshot(customerPage, "customer-first-verification.png", {
      title: "Documentation Capture - Customer - First Verification",
      callouts: [
        { locator: customerPage.getByText(/verified authentic/i).first(), text: "First scan confirms authenticity" },
      ],
    });

    // Second scan: verified again
    await goto(customerPage, `${OPERATIONS_BASE_URL}/verify/${encodeURIComponent(DOCS_CODE)}`);
    await customerPage.waitForTimeout(800);
    await screenshot(customerPage, "customer-verified-again.png", {
      title: "Documentation Capture - Customer - Legit Repeat Verification",
      callouts: [
        { locator: customerPage.getByText(/verified again/i).first(), text: "Same buyer can verify again safely" },
      ],
    });

    // Switch to a fresh browser context so later scans simulate a different device.
    const duplicateCtx = await browser.newContext({ viewport: { width: 1200, height: 800 } });
    const duplicatePage = await duplicateCtx.newPage();
    await disableMotion(duplicatePage);

    await goto(duplicatePage, `${OPERATIONS_BASE_URL}/verify/${encodeURIComponent(DOCS_CODE)}`);
    await duplicatePage.waitForTimeout(600);
    await goto(duplicatePage, `${OPERATIONS_BASE_URL}/verify/${encodeURIComponent(DOCS_CODE)}`);
    await duplicatePage.waitForTimeout(900);
    await screenshot(duplicatePage, "customer-possible-duplicate.png", {
      title: "Documentation Capture - Customer - Possible Duplicate",
      callouts: [
        { locator: duplicatePage.getByText(/suspicious duplicate/i).first(), text: "Unusual scan patterns may indicate copying" },
        { locator: duplicatePage.getByText(/risk explanation/i).first(), text: "Reasons and summary help you decide" },
      ],
    });

    // Report dialog
    await duplicatePage.getByRole("button", { name: /open incident drawer|report suspected counterfeit/i }).first().click();
    await duplicatePage.getByPlaceholder("Describe what looked suspicious.").fill("Docs capture: possible duplicate label observed.");
    await screenshot(duplicatePage, "customer-report-dialog.png", {
      title: "Documentation Capture - Customer - Fraud Report",
      callouts: [
        { locator: duplicatePage.getByRole("dialog"), text: "Structured report with metadata" },
        { locator: duplicatePage.getByRole("button", { name: /submit report/i }), text: "Submit to incident response" },
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
