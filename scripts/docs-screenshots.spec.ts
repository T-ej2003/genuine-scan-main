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

const SUPERADMIN_EMAIL = process.env.DOCS_SUPERADMIN_EMAIL || "admin@authenticqr.com";
const SUPERADMIN_PASSWORD = process.env.DOCS_SUPERADMIN_PASSWORD || "admin123";

const LICENSEE_ADMIN_EMAIL = process.env.DOCS_LICENSEE_ADMIN_EMAIL || "admin@acme.com";
const LICENSEE_ADMIN_PASSWORD = process.env.DOCS_LICENSEE_ADMIN_PASSWORD || "licensee123";

const MANUFACTURER_EMAIL = process.env.DOCS_MANUFACTURER_EMAIL || "factory1@acme.com";
const MANUFACTURER_PASSWORD = process.env.DOCS_MANUFACTURER_PASSWORD || "manufacturer123";

const DOCS_CODE = process.env.DOCS_QR_CODE || "A0000000051";

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

const login = async (page: Page, email: string, password: string) => {
  await goto(page, `${BASE_URL}/login`);
  await page.locator("#email").fill(email);
  await page.locator("#password").fill(password);
  await page.getByRole("button", { name: /^sign in$/i }).click();
  // Remote DB + first-load bundles can be slow; keep this generous for docs capture stability.
  await page.waitForURL("**/dashboard", { timeout: 60_000 });
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

const openAssignManufacturerDialog = async (page: Page) => {
  // Try a few rows until we find one with Assign manufacturer enabled
  const actionButtons = page.getByRole("button", { name: /^actions$/i });
  await expect(actionButtons.first()).toBeVisible({ timeout: 20_000 });
  const count = await actionButtons.count();

  for (let i = 0; i < Math.min(count, 8); i++) {
    await actionButtons.nth(i).click();
    const item = page.getByRole("menuitem", { name: /assign manufacturer/i });
    const disabled = await item.getAttribute("data-disabled");
    if (!disabled) {
      await item.click();
      return;
    }
    // close menu by clicking elsewhere
    await page.mouse.click(20, 20);
  }

  throw new Error("Could not find an unassigned batch to open Assign Manufacturer dialog.");
};

test.describe.configure({ mode: "serial" });
test.setTimeout(20 * 60_000);

test("capture help screenshots", async ({ browser }) => {
  fs.mkdirSync(OUT_DIR, { recursive: true });

  // Public: login + onboarding screens (no submission required)
  {
    const ctx = await browser.newContext({ viewport: { width: 1300, height: 780 } });
    const page = await ctx.newPage();
    await disableMotion(page);

    await goto(page, `${BASE_URL}/login`);
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

    await goto(page, `${BASE_URL}/accept-invite?token=docs-token`);
    await page.locator("#password").fill("********");
    await page.locator("#confirm").fill("********");
    await screenshot(page, "password-accept-invite.png", {
      title: "Documentation Capture - Accept Invite",
      callouts: [
        { locator: page.locator("#password"), text: "Set your new password" },
        { locator: page.getByRole("button", { name: /activate account/i }), text: "Activate to finish onboarding" },
      ],
    });

    await goto(page, `${BASE_URL}/forgot-password`);
    await page.locator("#email").fill(SUPERADMIN_EMAIL);
    await screenshot(page, "password-forgot-password.png", {
      title: "Documentation Capture - Forgot Password",
      callouts: [
        { locator: page.locator("#email"), text: "Enter your account email" },
        { locator: page.getByRole("button", { name: /send reset link/i }), text: "Request a reset link" },
      ],
    });

    await goto(page, `${BASE_URL}/reset-password?token=docs-token`);
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
  await login(licenseePage, LICENSEE_ADMIN_EMAIL, LICENSEE_ADMIN_PASSWORD);

  await goto(licenseePage, `${BASE_URL}/qr-requests`);
  const qtyInput = licenseePage.locator('input[type="number"]').first();
  await qtyInput.fill("250");
  const noteInput = licenseePage.getByRole("textbox").first();
  await noteInput.fill("Docs capture request");
  await screenshot(licenseePage, "licensee-request-qr-inventory.png", {
    title: "Documentation Capture - Licensee/Admin - Request QR Inventory",
    callouts: [
      { locator: qtyInput, text: "Enter the quantity you need" },
      { locator: licenseePage.getByRole("button", { name: /submit request/i }), text: "Submit quantity request" },
    ],
  });
  await licenseePage.getByRole("button", { name: /submit request/i }).click();
  await licenseePage.waitForTimeout(800);

  await goto(licenseePage, `${BASE_URL}/manufacturers`);
  await licenseePage.getByRole("button", { name: /add manufacturer/i }).click();
  const manufacturerDialog = licenseePage.getByRole("dialog");
  await screenshot(licenseePage, "licensee-create-manufacturer.png", {
    title: "Documentation Capture - Licensee/Admin - Create Manufacturer",
    callouts: [
      { locator: manufacturerDialog.getByPlaceholder("factory@example.com"), text: "Manufacturer login email" },
      { locator: manufacturerDialog.getByRole("combobox").first(), text: "Invite link is recommended" },
    ],
  });
  // Close dialog
  await licenseePage.getByRole("button", { name: /^cancel$/i }).click();

  // Super admin: approve the pending request + capture licensee creation modal + IR dashboard
  const superCtx = await browser.newContext({ viewport: { width: 1500, height: 820 } });
  const superPage = await superCtx.newPage();
  await disableMotion(superPage);
  await login(superPage, SUPERADMIN_EMAIL, SUPERADMIN_PASSWORD);

  await goto(superPage, `${BASE_URL}/licensees`);
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

  await goto(superPage, `${BASE_URL}/qr-requests`);
  const pendingRow = superPage.locator("tr", { hasText: "Docs capture request" }).first();
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

  await goto(superPage, `${BASE_URL}/ir`);
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
  await goto(licenseePage, `${BASE_URL}/batches`);

  // Best-effort: ensure at least one unassigned batch exists so the Assign Manufacturer flow is available.
  // Some environments may have all existing batches already assigned.
  try {
    await licenseePage.request.post(`${BASE_URL}/api/qr/batches`, {
      data: {
        name: `Docs Received ${new Date().toISOString().slice(0, 10)}`,
        quantity: 10,
      },
    });
  } catch {
    // ignore
  }
  await goto(licenseePage, `${BASE_URL}/batches`);

  await openAssignManufacturerDialog(licenseePage);
  const assignDialog = licenseePage.getByRole("dialog");
  await screenshot(licenseePage, "licensee-assign-batch.png", {
    title: "Documentation Capture - Licensee/Admin - Assign Batch",
    callouts: [
      { locator: assignDialog.getByText("Select manufacturer").first(), text: "Select manufacturer" },
      { locator: assignDialog.getByPlaceholder("Enter quantity").first(), text: "Enter quantity" },
    ],
  });
  await licenseePage.keyboard.press("Escape");

  await licenseeCtx.close();

  // Manufacturer: create print job + download pack + capture status
  const manuCtx = await browser.newContext({ viewport: { width: 1500, height: 820 } });
  const manuPage = await manuCtx.newPage();
  await disableMotion(manuPage);
  await login(manuPage, MANUFACTURER_EMAIL, MANUFACTURER_PASSWORD);

  await goto(manuPage, `${BASE_URL}/batches`);
  const createBtn = manuPage.getByRole("button", { name: /create print job/i }).first();
  await expect(createBtn).toBeVisible({ timeout: 15_000 });
  await createBtn.click();
  const printDialog = manuPage.getByRole("dialog");
  const qtyToPrintInput = printDialog.getByPlaceholder("Enter quantity").first();
  await qtyToPrintInput.fill("1");
  await screenshot(manuPage, "manufacturer-create-print-job.png", {
    title: "Documentation Capture - Manufacturer - Create Print Job",
    callouts: [
      { locator: qtyToPrintInput, text: "Select quantity to print" },
      { locator: manuPage.getByRole("button", { name: /^create print job$/i }), text: "Generate tokens" },
    ],
  });
  await manuPage.getByRole("button", { name: /^create print job$/i }).click();
  await manuPage.waitForTimeout(900);

  await screenshot(manuPage, "manufacturer-download-print-pack.png", {
    title: "Documentation Capture - Manufacturer - Download Print Pack",
    callouts: [
      { locator: manuPage.getByRole("button", { name: /download zip/i }), text: "Download secure print ZIP" },
    ],
  });

  const [download] = await Promise.all([
    manuPage.waitForEvent("download", { timeout: 25_000 }),
    manuPage.getByRole("button", { name: /download zip/i }).click(),
  ]);
  const tmpZipPath = path.join(OUT_DIR, "__tmp_print_pack.zip");
  await download.saveAs(tmpZipPath);
  try {
    fs.unlinkSync(tmpZipPath);
  } catch {
    // ignore
  }

  // Capture printed status from fresh list view.
  // We intentionally navigate directly instead of relying on modal-close clicks,
  // because dialog animations/state changes can be flaky across environments.
  await goto(manuPage, `${BASE_URL}/batches`);

  const printedStatusCell = manuPage.locator("tbody tr").first().locator("td").nth(7);
  await screenshot(manuPage, "manufacturer-print-status.png", {
    title: "Documentation Capture - Manufacturer - Print Confirmation",
    callouts: [
      { locator: printedStatusCell, text: "Status updates after print workflow" },
    ],
  });

  await manuCtx.close();

  // Customer (public): verify outcomes + report
  const customerCtx = await browser.newContext({ viewport: { width: 1200, height: 800 } });
  const customerPage = await customerCtx.newPage();
  await disableMotion(customerPage);

  // First scan
  await goto(customerPage, `${BASE_URL}/verify/${encodeURIComponent(DOCS_CODE)}`);
  await customerPage.waitForTimeout(900);
  await screenshot(customerPage, "customer-first-verification.png", {
    title: "Documentation Capture - Customer - First Verification",
    callouts: [
      { locator: customerPage.getByText(/verified authentic/i).first(), text: "First scan confirms authenticity" },
    ],
  });

  // Second scan: verified again
  await goto(customerPage, `${BASE_URL}/verify/${encodeURIComponent(DOCS_CODE)}`);
  await customerPage.waitForTimeout(800);
  await screenshot(customerPage, "customer-verified-again.png", {
    title: "Documentation Capture - Customer - Legit Repeat Verification",
    callouts: [
      { locator: customerPage.getByText(/verified again/i).first(), text: "Same buyer can verify again safely" },
    ],
  });

  // Third scan (still verified again), then 4th scan (possible duplicate based on high count)
  await goto(customerPage, `${BASE_URL}/verify/${encodeURIComponent(DOCS_CODE)}`);
  await customerPage.waitForTimeout(600);
  await goto(customerPage, `${BASE_URL}/verify/${encodeURIComponent(DOCS_CODE)}`);
  await customerPage.waitForTimeout(900);
  await screenshot(customerPage, "customer-possible-duplicate.png", {
    title: "Documentation Capture - Customer - Possible Duplicate",
    callouts: [
      { locator: customerPage.getByText(/possible duplicate/i).first(), text: "Unusual scan patterns may indicate copying" },
      { locator: customerPage.getByText(/why this was flagged/i).first(), text: "Reasons and summary help you decide" },
    ],
  });

  // Report dialog
  await customerPage.getByRole("button", { name: /report suspected counterfeit/i }).first().click();
  await customerPage.getByPlaceholder("Describe what looked suspicious.").fill("Docs capture: possible duplicate label observed.");
  await screenshot(customerPage, "customer-report-dialog.png", {
    title: "Documentation Capture - Customer - Fraud Report",
    callouts: [
      { locator: customerPage.getByRole("dialog"), text: "Structured report with metadata" },
      { locator: customerPage.getByRole("button", { name: /submit report/i }), text: "Submit to incident response" },
    ],
  });

  // Submit report to ensure an incident exists for IR detail screenshots (best-effort).
  await customerPage.getByRole("button", { name: /submit report/i }).click();
  await customerPage.waitForTimeout(1200);

  await customerCtx.close();

  // IR incident detail screenshots (open latest incident)
  const irCtx = await browser.newContext({ viewport: { width: 1500, height: 820 } });
  const irPage = await irCtx.newPage();
  await disableMotion(irPage);
  await login(irPage, SUPERADMIN_EMAIL, SUPERADMIN_PASSWORD);
  await goto(irPage, `${BASE_URL}/ir`);
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
});
