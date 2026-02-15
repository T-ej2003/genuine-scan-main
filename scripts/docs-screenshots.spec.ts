import fs from "fs/promises";
import path from "path";
import { createHash } from "crypto";
import { execFileSync } from "child_process";
import { test, expect, type Browser, type BrowserContext, type Locator, type Page } from "@playwright/test";

const BASE_URL = process.env.DOCS_BASE_URL || "http://localhost:8080";
const API_URL = process.env.DOCS_API_URL || `${BASE_URL}/api`;
const OUT_DIR = path.resolve(process.cwd(), "public/docs");
const BACKEND_ENV_PATH = path.resolve(process.cwd(), "backend/.env");

const viewport = { width: 1460, height: 980 };

const creds = {
  superAdmin: {
    email: process.env.DOCS_SUPERADMIN_EMAIL || "admin@authenticqr.com",
    password: process.env.DOCS_SUPERADMIN_PASSWORD || "admin123",
  },
  licensee: {
    email: process.env.DOCS_LICENSEE_EMAIL || "admin@acme.com",
    password: process.env.DOCS_LICENSEE_PASSWORD || "licensee123",
  },
  manufacturer: {
    email: process.env.DOCS_MANUFACTURER_EMAIL || "factory1@acme.com",
    password: process.env.DOCS_MANUFACTURER_PASSWORD || "manufacturer123",
  },
};

const customerEmail = process.env.DOCS_CUSTOMER_EMAIL || "docs-customer@example.com";
const customerName = process.env.DOCS_CUSTOMER_NAME || "Docs Customer";

type CaptureOptions = {
  title: string;
  focusSelector?: string;
  focusLabel?: string;
  waitMs?: number;
};

type BackendSettings = {
  databaseUrl: string;
  otpSalt: string;
};

const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const escapeRegExp = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

test.setTimeout(15 * 60_000);

const shotPath = (fileName: string) => path.join(OUT_DIR, fileName);

const parseEnvFile = async (filePath: string) => {
  const out: Record<string, string> = {};
  const raw = await fs.readFile(filePath, "utf8");
  for (const line of raw.split(/\r?\n/)) {
    if (!line || line.trim().startsWith("#")) continue;
    const idx = line.indexOf("=");
    if (idx <= 0) continue;
    const key = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    out[key] = value.replace(/^['\"]|['\"]$/g, "");
  }
  return out;
};

const loadBackendSettings = async (): Promise<BackendSettings | null> => {
  try {
    const parsed = await parseEnvFile(BACKEND_ENV_PATH);
    const databaseUrl = String(process.env.DOCS_DATABASE_URL || parsed.DATABASE_URL || "").trim();
    const otpSalt = String(
      process.env.DOCS_OTP_SALT || parsed.CUSTOMER_OTP_SALT || parsed.SESSION_SECRET || parsed.JWT_SECRET || ""
    ).trim();
    if (!databaseUrl || !otpSalt) return null;
    return { databaseUrl, otpSalt };
  } catch {
    return null;
  }
};

const runPsqlSingle = (databaseUrl: string, sql: string) => {
  try {
    const raw = execFileSync("psql", [databaseUrl, "-Atc", sql], { encoding: "utf8" });
    return String(raw || "").trim();
  } catch {
    return "";
  }
};

const deriveOtpCode = (email: string, codeHash: string, otpSalt: string) => {
  const normalizedEmail = String(email || "").trim().toLowerCase();
  const target = String(codeHash || "").trim().toLowerCase();
  if (!normalizedEmail || !target || !otpSalt) return null;

  for (let i = 0; i < 1_000_000; i += 1) {
    const otp = String(i).padStart(6, "0");
    const digest = createHash("sha256")
      .update(`${otpSalt}:${normalizedEmail}:${otp}`)
      .digest("hex");
    if (digest === target) return otp;
  }
  return null;
};

const apiJson = async (url: string, init?: RequestInit) => {
  const res = await fetch(url, {
    ...init,
    headers: {
      "content-type": "application/json",
      ...(init?.headers || {}),
    },
  });
  return (await res.json().catch(() => ({}))) as any;
};

const apiLogin = async (email: string, password: string) => {
  const payload = await apiJson(`${API_URL}/auth/login`, {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
  if (!payload?.success || !payload?.data?.token) {
    throw new Error(`API login failed for ${email}: ${payload?.error || "unknown error"}`);
  }
  return String(payload.data.token);
};

const ensurePendingRequest = async () => {
  const token = await apiLogin(creds.licensee.email, creds.licensee.password);
  const list = await apiJson(`${API_URL}/qr/requests?status=PENDING`, {
    headers: { authorization: `Bearer ${token}` },
  });
  const pending = Array.isArray(list?.data) ? list.data.length : 0;
  if (pending > 0) return;

  await apiJson(`${API_URL}/qr/requests`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}` },
    body: JSON.stringify({ quantity: 250, note: "Docs capture request" }),
  });
};

const approveOnePendingRequest = async () => {
  const superToken = await apiLogin(creds.superAdmin.email, creds.superAdmin.password);
  const list = await apiJson(`${API_URL}/qr/requests?status=PENDING`, {
    headers: { authorization: `Bearer ${superToken}` },
  });
  const rows = Array.isArray(list?.data) ? list.data : [];
  const target = rows[0];
  if (!target?.id) return;

  await apiJson(`${API_URL}/qr/requests/${target.id}/approve`, {
    method: "POST",
    headers: { authorization: `Bearer ${superToken}` },
    body: JSON.stringify({ decisionNote: "Approved for docs capture" }),
  });
};

const addFrameOverlay = async (page: Page, title: string) => {
  await page.evaluate((inputTitle) => {
    document.querySelectorAll("[data-doc-overlay='1']").forEach((el) => el.remove());

    const style = document.createElement("style");
    style.setAttribute("data-doc-overlay", "1");
    style.textContent = `
      .doc-capture-frame {
        position: fixed;
        inset: 10px;
        border-radius: 16px;
        border: 2px solid rgba(15, 23, 42, 0.35);
        box-shadow: inset 0 0 0 1px rgba(148, 163, 184, 0.3);
        pointer-events: none;
        z-index: 2147483646;
      }
      .doc-capture-chip {
        position: fixed;
        top: 20px;
        left: 20px;
        max-width: 66vw;
        border-radius: 999px;
        background: rgba(15, 23, 42, 0.92);
        color: #f8fafc;
        padding: 8px 14px;
        font: 600 13px/1.2 ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
        letter-spacing: 0.01em;
        pointer-events: none;
        z-index: 2147483647;
      }
      .doc-focus-box {
        position: fixed;
        border: 3px solid #22d3ee;
        border-radius: 12px;
        box-shadow: 0 0 0 2px rgba(15, 23, 42, 0.24), 0 12px 28px rgba(8, 47, 73, 0.28);
        pointer-events: none;
        z-index: 2147483647;
      }
	      .doc-focus-label {
	        position: fixed;
	        border-radius: 10px;
	        background: rgba(8, 47, 73, 0.95);
	        color: #e0f2fe;
	        padding: 6px 10px;
	        font: 600 12px/1.2 ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
	        pointer-events: none;
	        z-index: 2147483647;
	      }
	      .doc-focus-arrow {
	        position: fixed;
	        inset: 0;
	        pointer-events: none;
	        z-index: 2147483646;
	      }
	    `;

    const frame = document.createElement("div");
    frame.className = "doc-capture-frame";
    frame.setAttribute("data-doc-overlay", "1");

    const chip = document.createElement("div");
    chip.className = "doc-capture-chip";
    chip.setAttribute("data-doc-overlay", "1");
    chip.textContent = `Documentation Capture • ${inputTitle}`;

    document.body.appendChild(style);
    document.body.appendChild(frame);
    document.body.appendChild(chip);
  }, title);
};

const addFocusOverlay = async (page: Page, selector: string, label: string) => {
  const locator = page.locator(selector).first();
  const visible = await locator.isVisible().catch(() => false);
  if (!visible) return false;

  const box = await locator.boundingBox();
  if (!box) return false;

  await page.evaluate(
    ({ rect, text }) => {
      const clamp = (value: number, min: number, max: number) => Math.max(min, Math.min(max, value));

      const boxEl = document.createElement("div");
      boxEl.className = "doc-focus-box";
      boxEl.setAttribute("data-doc-overlay", "1");
      boxEl.style.left = `${Math.max(8, rect.x - 4)}px`;
      boxEl.style.top = `${Math.max(8, rect.y - 4)}px`;
      boxEl.style.width = `${Math.max(24, rect.width + 8)}px`;
      boxEl.style.height = `${Math.max(24, rect.height + 8)}px`;

      const labelEl = document.createElement("div");
      labelEl.className = "doc-focus-label";
      labelEl.setAttribute("data-doc-overlay", "1");
      labelEl.textContent = text;
      // Prefer above the target, but flip below if near the top of viewport.
      const nextTop = rect.y - 44 < 14 ? rect.y + rect.height + 14 : rect.y - 44;
      labelEl.style.left = `${clamp(rect.x, 12, window.innerWidth - 260)}px`;
      labelEl.style.top = `${clamp(nextTop, 14, window.innerHeight - 44)}px`;

      document.body.appendChild(boxEl);
      document.body.appendChild(labelEl);

      // Arrow overlay: draw a clean SVG arrow from label to target.
      const svgNS = "http://www.w3.org/2000/svg";
      const svg = document.createElementNS(svgNS, "svg");
      svg.setAttribute("data-doc-overlay", "1");
      svg.setAttribute("class", "doc-focus-arrow");
      svg.setAttribute("width", "100%");
      svg.setAttribute("height", "100%");
      svg.setAttribute("viewBox", `0 0 ${window.innerWidth} ${window.innerHeight}`);

      const defs = document.createElementNS(svgNS, "defs");
      const marker = document.createElementNS(svgNS, "marker");
      marker.setAttribute("id", "doc-arrowhead");
      marker.setAttribute("markerWidth", "10");
      marker.setAttribute("markerHeight", "10");
      marker.setAttribute("refX", "9");
      marker.setAttribute("refY", "5");
      marker.setAttribute("orient", "auto");
      marker.setAttribute("markerUnits", "userSpaceOnUse");
      const markerPath = document.createElementNS(svgNS, "path");
      markerPath.setAttribute("d", "M 0 0 L 10 5 L 0 10 z");
      markerPath.setAttribute("fill", "#22d3ee");
      marker.appendChild(markerPath);
      defs.appendChild(marker);
      svg.appendChild(defs);

      const labelRect = labelEl.getBoundingClientRect();
      const startX = clamp(labelRect.left + Math.min(22, labelRect.width / 2), 8, window.innerWidth - 8);
      const startY = clamp(labelRect.bottom + 6, 8, window.innerHeight - 8);

      const endX = clamp(rect.x + rect.width / 2, 8, window.innerWidth - 8);
      const endY = clamp(rect.y - 2, 8, window.innerHeight - 8);

      const ctrlX = (startX + endX) / 2;
      const ctrlY = clamp(Math.min(startY, endY) - 70, 8, window.innerHeight - 8);

      const arrowPath = document.createElementNS(svgNS, "path");
      arrowPath.setAttribute("d", `M ${startX} ${startY} Q ${ctrlX} ${ctrlY} ${endX} ${endY}`);
      arrowPath.setAttribute("fill", "none");
      arrowPath.setAttribute("stroke", "#22d3ee");
      arrowPath.setAttribute("stroke-width", "3");
      arrowPath.setAttribute("stroke-linecap", "round");
      arrowPath.setAttribute("stroke-linejoin", "round");
      arrowPath.setAttribute("marker-end", "url(#doc-arrowhead)");
      arrowPath.setAttribute("style", "filter: drop-shadow(0 3px 6px rgba(8, 47, 73, 0.35));");

      svg.appendChild(arrowPath);
      document.body.appendChild(svg);
    },
    { rect: box, text: label }
  );

  return true;
};

const clearOverlays = async (page: Page) => {
  await page.evaluate(() => {
    document.querySelectorAll("[data-doc-overlay='1']").forEach((el) => el.remove());
  });
};

const capture = async (page: Page, fileName: string, options: CaptureOptions) => {
  await pause(options.waitMs ?? 450);
  await addFrameOverlay(page, options.title);
  if (options.focusSelector) {
    await addFocusOverlay(page, options.focusSelector, options.focusLabel || "Focus");
  }

  await page.screenshot({
    path: shotPath(fileName),
    fullPage: false,
    animations: "disabled",
  });

  await clearOverlays(page);
};

const newContext = async (browser: Browser) => browser.newContext({ viewport });

const loginUi = async (page: Page, email: string, password: string) => {
  await page.goto(`${BASE_URL}/login`, { waitUntil: "domcontentloaded" });
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page).toHaveURL(/\/dashboard/, { timeout: 20_000 });
};

const tryClick = async (page: Page, selector: string) => {
  const el = page.locator(selector).first();
  const visible = await el.isVisible().catch(() => false);
  const enabled = visible ? await el.isEnabled().catch(() => false) : false;
  if (!visible || !enabled) return false;
  await el.click();
  return true;
};

const openFirstActionsAndPick = async (page: Page, itemName: RegExp) => {
  const buttons = page.getByRole("button", { name: /actions/i });
  const count = await buttons.count().catch(() => 0);
  if (!count) return false;

  for (let i = 0; i < count; i += 1) {
    const button = buttons.nth(i);
    const visible = await button.isVisible().catch(() => false);
    const enabled = visible ? await button.isEnabled().catch(() => false) : false;
    if (!visible || !enabled) continue;

    await button.click();

    const menuItem = page.getByRole("menuitem", { name: itemName }).first();
    const itemVisible = await menuItem.isVisible().catch(() => false);
    const itemEnabled = itemVisible ? await menuItem.isEnabled().catch(() => false) : false;
    if (!itemVisible || !itemEnabled) {
      await page.keyboard.press("Escape").catch(() => undefined);
      continue;
    }

    await menuItem.click();
    return true;
  }

  return false;
};

const clickFirstEnabled = async (locator: Locator) => {
  const count = await locator.count().catch(() => 0);
  if (!count) return false;
  for (let i = 0; i < count; i += 1) {
    const el = locator.nth(i);
    const visible = await el.isVisible().catch(() => false);
    const enabled = visible ? await el.isEnabled().catch(() => false) : false;
    if (!visible || !enabled) continue;
    await el.click();
    return true;
  }
  return false;
};

const waitForDialog = async (page: Page, timeoutMs = 15_000) => {
  const dialog = page.locator("[role='dialog']").first();
  await dialog.waitFor({ state: "visible", timeout: timeoutMs }).catch(() => undefined);
  return dialog;
};

const waitForVerifySettled = async (page: Page) => {
  await Promise.race([
    page
      .locator("text=SCAN HISTORY SUMMARY")
      .first()
      .waitFor({ state: "visible", timeout: 30_000 }),
    page
      .locator("text=Verification service unavailable")
      .first()
      .waitFor({ state: "visible", timeout: 30_000 }),
    page
      .locator("text=Invalid QR")
      .first()
      .waitFor({ state: "visible", timeout: 30_000 }),
  ]).catch(() => undefined);

  await pause(450);
};

const getFreshCustomerCode = (settings: BackendSettings | null) => {
  const manual = String(process.env.DOCS_CUSTOMER_TEST_CODE || "").trim();
  if (manual) return manual;
  if (!settings) return "TT0000000105";

  const first = runPsqlSingle(
    settings.databaseUrl,
    `select q."code"
     from "QRCode" q
     left join "ProductOwnership" o on o."qrCodeId" = q."id"
     where o."id" is null
       and q."status" in ('PRINTED','REDEEMED')
       and coalesce(q."scanCount",0)=0
     order by q."createdAt" desc
     limit 1;`
  );
  if (first) return first;

  const fallback = runPsqlSingle(
    settings.databaseUrl,
    `select q."code"
     from "QRCode" q
     left join "ProductOwnership" o on o."qrCodeId" = q."id"
     where o."id" is null
       and q."status" in ('PRINTED','REDEEMED')
     order by coalesce(q."scanCount",0) asc, q."createdAt" desc
     limit 1;`
  );
  return fallback || "TT0000000105";
};

const resolveOtpFromDb = (settings: BackendSettings | null, email: string) => {
  if (!settings) return null;
  const escapedEmail = email.replace(/'/g, "''");
  const codeHash = runPsqlSingle(
    settings.databaseUrl,
    `select "codeHash" from "CustomerOtpCode" where email='${escapedEmail}' and "consumedAt" is null order by "createdAt" desc limit 1;`
  );
  if (!codeHash) return null;
  return deriveOtpCode(email, codeHash, settings.otpSalt);
};

test.beforeAll(async () => {
  await fs.mkdir(OUT_DIR, { recursive: true });
  await ensurePendingRequest();
});

test("capture documentation screenshots with framed callouts", async ({ browser }) => {
  const settings = await loadBackendSettings();

  // ------------------ SUPER ADMIN + INTRO ------------------
  const superCtx = await newContext(browser);
  const superPage = await superCtx.newPage();

  await superPage.goto(`${BASE_URL}/login`, { waitUntil: "domcontentloaded" });
  await superPage.getByLabel("Email").fill(creds.superAdmin.email);
  await superPage.getByLabel("Password").fill(creds.superAdmin.password);
  await capture(superPage, "access-super-admin-login.png", {
    title: "Super Admin Access",
    focusSelector: "button:has-text('Sign in')",
    focusLabel: "Sign in with provided credentials",
  });

  await superPage.getByRole("button", { name: /sign in/i }).click();
  await expect(superPage).toHaveURL(/\/dashboard/, { timeout: 20_000 });

  await superPage.goto(`${BASE_URL}/licensees`, { waitUntil: "domcontentloaded" });
  await superPage.getByRole("button", { name: /add licensee/i }).first().waitFor({ state: "visible", timeout: 20_000 });
  await tryClick(superPage, "button:has-text('Add Licensee')");
  await waitForDialog(superPage);
  await capture(superPage, "access-licensee-admin-created-user.png", {
    title: "Licensee/Admin Access",
    focusSelector: "[role='dialog']",
    focusLabel: "Admin creates licensee and first admin user",
  });
  await capture(superPage, "superadmin-create-licensee-form.png", {
    title: "Super Admin • Create Licensee",
    focusSelector: "[role='dialog']",
    focusLabel: "Complete details and create",
  });
  await superPage.keyboard.press("Escape");

  await openFirstActionsAndPick(superPage, /allocate qr range/i);
  await superPage.locator("text=Allocate QR Range").first().waitFor({ state: "visible", timeout: 12_000 }).catch(() => undefined);
  await capture(superPage, "superadmin-allocate-qr-range.png", {
    title: "Super Admin • Allocate QR Range",
    focusSelector: "[role='dialog']",
    focusLabel: "Allocate by quantity or range",
  });
  await superPage.keyboard.press("Escape");

  await superPage.goto(`${BASE_URL}/qr-requests`, { waitUntil: "domcontentloaded" });
  // Filter to pending so the screenshot is deterministic.
  await superPage.locator("select").first().selectOption("PENDING").catch(() => undefined);
  await superPage.locator("text=Loading...").first().waitFor({ state: "detached", timeout: 20_000 }).catch(() => undefined);
  const rowApprove = superPage.getByRole("button", { name: /^Approve$/i }).first();
  await rowApprove.waitFor({ state: "visible", timeout: 20_000 }).catch(() => undefined);
  await rowApprove.click().catch(() => undefined);
  await waitForDialog(superPage);
  await capture(superPage, "superadmin-approve-qr-request.png", {
    title: "Super Admin • QR Request Approval",
    focusSelector: "[role='dialog']",
    focusLabel: "Review and approve pending request",
  });
  await superPage.keyboard.press("Escape");

  await approveOnePendingRequest();

  await superPage.goto(`${BASE_URL}/incidents`, { waitUntil: "domcontentloaded" });
  await capture(superPage, "superadmin-incident-list.png", {
    title: "Super Admin • Incidents",
    focusSelector: "text=Incidents",
    focusLabel: "Review reported risks",
  });

  await superPage.goto(`${BASE_URL}/qr-tracking`, { waitUntil: "domcontentloaded" });
  await capture(superPage, "superadmin-policy-alerts.png", {
    title: "Super Admin • Policy / Tracking Alerts",
    focusSelector: "text=QR Tracking",
    focusLabel: "Monitor risk patterns and alerts",
  });

  await superPage.goto(`${BASE_URL}/account`, { waitUntil: "domcontentloaded" });
  await capture(superPage, "password-superadmin-account-security.png", {
    title: "Super Admin • Password Settings",
    focusSelector: "text=Security",
    focusLabel: "Change password from Account settings",
  });

  await superCtx.close();

  // ------------------ LICENSEE ADMIN ------------------
  const licenseeCtx = await newContext(browser);
  const licenseePage = await licenseeCtx.newPage();

  await loginUi(licenseePage, creds.licensee.email, creds.licensee.password);

  await licenseePage.goto(`${BASE_URL}/manufacturers`, { waitUntil: "domcontentloaded" });
  await licenseePage.getByRole("button", { name: /add manufacturer/i }).first().waitFor({ state: "visible", timeout: 20_000 });
  await tryClick(licenseePage, "button:has-text('Add Manufacturer')");
  await waitForDialog(licenseePage);
  await capture(licenseePage, "access-manufacturer-create-form.png", {
    title: "Manufacturer Access Setup",
    focusSelector: "[role='dialog']",
    focusLabel: "Admin creates factory user credentials",
  });
  await capture(licenseePage, "licensee-create-manufacturer.png", {
    title: "Licensee/Admin • Create Manufacturer",
    focusSelector: "[role='dialog']",
    focusLabel: "Fill profile and login details",
  });
  await licenseePage.keyboard.press("Escape");

  await licenseePage.goto(`${BASE_URL}/qr-requests`, { waitUntil: "domcontentloaded" });
  await capture(licenseePage, "licensee-qr-request-submit.png", {
    title: "Licensee/Admin • Request QR Inventory",
    focusSelector: "button:has-text('Submit Request')",
    focusLabel: "Submit quantity request",
  });

  await licenseePage.goto(`${BASE_URL}/batches`, { waitUntil: "domcontentloaded" });
  await openFirstActionsAndPick(licenseePage, /assign manufacturer/i);
  await licenseePage.locator("text=Assign Manufacturer").first().waitFor({ state: "visible", timeout: 12_000 }).catch(() => undefined);

  const assignDialog = licenseePage.locator("[role='dialog']").first();
  // Best-effort: prefill fields so the docs look like a real workflow.
  const mfgTrigger = assignDialog.locator("text=Select manufacturer").first();
  if (await mfgTrigger.isVisible().catch(() => false)) {
    await mfgTrigger.click().catch(() => undefined);
    const optionByEmail = licenseePage
      .getByRole("option", { name: new RegExp(escapeRegExp(creds.manufacturer.email), "i") })
      .first();
    await optionByEmail.click().catch(() => undefined);
  }
  const qty = assignDialog.locator("input[placeholder='Enter quantity']").first();
  if (await qty.isVisible().catch(() => false)) {
    await qty.fill("50").catch(() => undefined);
  }

  await capture(licenseePage, "licensee-assign-batch-manufacturer.png", {
    title: "Licensee/Admin • Assign Batch",
    focusSelector: "[role='dialog']",
    focusLabel: "Assign quantity to a manufacturer",
  });
  const saveAssign = assignDialog.getByRole("button", { name: /^Save$/i }).first();
  const canSaveAssign =
    (await saveAssign.isVisible().catch(() => false)) && (await saveAssign.isEnabled().catch(() => false));
  if (canSaveAssign) {
    await saveAssign.click().catch(() => undefined);
    await pause(1400);
    if (await assignDialog.isVisible().catch(() => false)) {
      await licenseePage.keyboard.press("Escape").catch(() => undefined);
    }
  } else {
    await licenseePage.keyboard.press("Escape");
  }

  await licenseePage.goto(`${BASE_URL}/incidents`, { waitUntil: "domcontentloaded" });
  await capture(licenseePage, "licensee-incidents-overview.png", {
    title: "Licensee/Admin • Incident Overview",
    focusSelector: "text=Incidents",
    focusLabel: "Track and triage customer reports",
  });

  await licenseePage.goto(`${BASE_URL}/qr-tracking`, { waitUntil: "domcontentloaded" });
  await capture(licenseePage, "licensee-qr-tracking-filtered.png", {
    title: "Licensee/Admin • QR Tracking",
    focusSelector: "text=QR Tracking",
    focusLabel: "Use filters for scan investigation",
  });

  await licenseePage.goto(`${BASE_URL}/account`, { waitUntil: "domcontentloaded" });
  await capture(licenseePage, "password-licensee-change-password.png", {
    title: "Licensee/Admin • Password Settings",
    focusSelector: "text=Security",
    focusLabel: "Update account password",
  });

  await licenseeCtx.close();

  // ------------------ MANUFACTURER ------------------
  const manufacturerCtx = await newContext(browser);
  const manufacturerPage = await manufacturerCtx.newPage();

  await loginUi(manufacturerPage, creds.manufacturer.email, creds.manufacturer.password);

  await manufacturerPage.goto(`${BASE_URL}/batches`, { waitUntil: "domcontentloaded" });
  await capture(manufacturerPage, "manufacturer-batches-list.png", {
    title: "Manufacturer • Assigned Batches",
    focusSelector: "text=Batches",
    focusLabel: "Open assigned production batches",
  });

  await manufacturerPage
    .getByRole("button", { name: /create print job/i })
    .first()
    .waitFor({ state: "visible", timeout: 20_000 });
  await clickFirstEnabled(manufacturerPage.getByRole("button", { name: /create print job/i }));
  const printDialog = await waitForDialog(manufacturerPage);
  await manufacturerPage
    .locator("text=Create Print Job")
    .first()
    .waitFor({ state: "visible", timeout: 12_000 })
    .catch(() => undefined);

  const qtyInput = printDialog.locator("input[type='number']").first();
  if (await qtyInput.isVisible().catch(() => false)) {
    await qtyInput.fill("1").catch(() => undefined);
  }

  await capture(manufacturerPage, "manufacturer-create-print-job.png", {
    title: "Manufacturer • Create Print Job",
    focusSelector: "[role='dialog']",
    focusLabel: "Set quantity and generate tokens",
  });

  const createBtn = printDialog.getByRole("button", { name: /^Create Print Job$/i }).first();
  const canCreatePrintJob =
    (await createBtn.isVisible().catch(() => false)) && (await createBtn.isEnabled().catch(() => false));
  if (canCreatePrintJob) {
    await createBtn.click().catch(() => undefined);
    const downloadInDialog = printDialog.locator("button:has-text('Download ZIP')").first();
    await expect(downloadInDialog).toBeEnabled({ timeout: 20_000 }).catch(() => undefined);
  }

  await capture(manufacturerPage, "manufacturer-download-print-pack.png", {
    title: "Manufacturer • Download Print Pack",
    focusSelector: "button:has-text('Download ZIP')",
    focusLabel: "Download secure print ZIP",
    waitMs: 850,
  });

  const downloadBtn = printDialog.locator("button:has-text('Download ZIP')").first();
  const canDownload =
    (await downloadBtn.isVisible().catch(() => false)) && (await downloadBtn.isEnabled().catch(() => false));
  if (canDownload) {
    const downloadPromise = manufacturerPage.waitForEvent("download", { timeout: 12_000 }).catch(() => null);
    await downloadBtn.click().catch(() => undefined);
    await downloadPromise;
  }

  await pause(900);
  await manufacturerPage.keyboard.press("Escape").catch(() => undefined);
  await manufacturerPage.goto(`${BASE_URL}/batches`, { waitUntil: "domcontentloaded" });
  await manufacturerPage.locator("text=Printed").first().waitFor({ state: "visible", timeout: 12_000 }).catch(() => undefined);
  const printedVisible = await manufacturerPage.locator("text=Printed").first().isVisible().catch(() => false);
  await capture(manufacturerPage, "manufacturer-print-confirmed-status.png", {
    title: "Manufacturer • Print Confirmation",
    focusSelector: printedVisible ? "text=Printed" : "text=Not printed",
    focusLabel: printedVisible ? "Status updates after download" : "Printing status is shown here",
  });

  await manufacturerPage.goto(`${BASE_URL}/account`, { waitUntil: "domcontentloaded" });
  await capture(manufacturerPage, "password-manufacturer-account-security.png", {
    title: "Manufacturer • Password Settings",
    focusSelector: "text=Security",
    focusLabel: "Change password in account settings",
  });

  await manufacturerCtx.close();

  // ------------------ CUSTOMER ------------------
  const verifyCode = getFreshCustomerCode(settings);

  const customerCtx = await newContext(browser);
  const customerPage = await customerCtx.newPage();

  await customerPage.goto(`${BASE_URL}/verify/${encodeURIComponent(verifyCode)}`, {
    waitUntil: "domcontentloaded",
  });
  await waitForVerifySettled(customerPage);
  await customerPage.locator("text=Verified Again").first().waitFor({ state: "visible", timeout: 12_000 }).catch(() => undefined);

  await capture(customerPage, "access-customer-verify-entry.png", {
    title: "Customer Access • Public Verification",
    focusSelector: "text=Verified Authentic",
    focusLabel: "Verification works without dashboard login",
  });

  await capture(customerPage, "customer-verify-first-scan.png", {
    title: "Customer • First Verification",
    focusSelector: "text=Verified Authentic",
    focusLabel: "First scan confirms authenticity",
  });

  await customerPage.goto(`${BASE_URL}/verify/${encodeURIComponent(verifyCode)}`, {
    waitUntil: "domcontentloaded",
  });
  await waitForVerifySettled(customerPage);

  await capture(customerPage, "customer-verify-again-scan.png", {
    title: "Customer • Legit Repeat Verification",
    focusSelector: "text=Verified Again",
    focusLabel: "Same customer can verify again safely",
  });

  await capture(customerPage, "customer-signin-otp.png", {
    title: "Customer • Optional OTP Sign-in",
    focusSelector: "input[placeholder='you@example.com']",
    focusLabel: "Sign in to claim ownership",
  });

  await customerPage.locator("input[placeholder='you@example.com']").first().fill(customerEmail);
  await customerPage.locator("input[placeholder='Your name']").first().fill(customerName);

  await capture(customerPage, "password-customer-otp-request.png", {
    title: "Customer • Request OTP",
    focusSelector: "button:has-text('Continue with email OTP')",
    focusLabel: "Request one-time sign-in code",
  });

  await customerPage.getByRole("button", { name: /continue with email otp/i }).first().click();
  await pause(1200);

  await capture(customerPage, "password-customer-otp-verify.png", {
    title: "Customer • Verify OTP",
    focusSelector: "input[placeholder='Enter OTP']",
    focusLabel: "Enter OTP and verify",
  });

  const otpCode = resolveOtpFromDb(settings, customerEmail);
  if (otpCode) {
    await customerPage.locator("input[placeholder='Enter OTP']").first().fill(otpCode);
    await customerPage.getByRole("button", { name: /^Verify$/i }).first().click();
    await pause(1200);
  }

  // Signing in triggers a background refresh of the verification state.
  await waitForVerifySettled(customerPage);
  await customerPage.locator("text=Ownership protection").first().scrollIntoViewIfNeeded().catch(() => undefined);
  await pause(450);

  const claimBtn = customerPage.getByRole("button", { name: /claim this product/i }).first();
  const claimedByYou = customerPage.locator("text=Claimed by you").first();
  const claimedByOther = customerPage.locator("text=already claimed by another account").first();
  const claimFocusSelector = (await claimBtn.isVisible().catch(() => false))
    ? "button:has-text('Claim this product')"
    : (await claimedByYou.isVisible().catch(() => false))
    ? "text=Claimed by you"
    : (await claimedByOther.isVisible().catch(() => false))
    ? "text=already claimed by another account"
    : "text=Ownership protection";

  await capture(customerPage, "customer-claim-product.png", {
    title: "Customer • Claim Product",
    focusSelector: claimFocusSelector,
    focusLabel: "Claim ownership for stronger protection",
  });

  await customerCtx.close();

  const duplicateCtx = await newContext(browser);
  const duplicatePage = await duplicateCtx.newPage();

  await duplicatePage.goto(`${BASE_URL}/verify/${encodeURIComponent(verifyCode)}`, {
    waitUntil: "domcontentloaded",
  });
  await waitForVerifySettled(duplicatePage);
  await duplicatePage
    .locator("text=Possible Duplicate")
    .first()
    .waitFor({ state: "visible", timeout: 12_000 })
    .catch(() => undefined);

  await capture(duplicatePage, "customer-possible-duplicate.png", {
    title: "Customer • Possible Duplicate",
    focusSelector: "text=Possible Duplicate",
    focusLabel: "Different identity/device triggers warning",
  });

  const reportBtn = duplicatePage.getByRole("button", { name: /report suspected counterfeit/i }).first();
  if (await reportBtn.isVisible().catch(() => false)) {
    await reportBtn.click();
    await pause(400);
  }

  await capture(duplicatePage, "customer-report-counterfeit-form.png", {
    title: "Customer • Fraud Report",
    focusSelector: "[role='dialog']",
    focusLabel: "Structured report with metadata",
  });

  await duplicateCtx.close();

  // ------------------ HELP PAGE OVERVIEW (extra) ------------------
  const helpCtx = await newContext(browser);
  const helpPage = await helpCtx.newPage();

  await helpPage.goto(`${BASE_URL}/help`, { waitUntil: "domcontentloaded" });
  await capture(helpPage, "help-home.png", {
    title: "Help Center",
    focusSelector: "text=Help & Documentation",
    focusLabel: "Role-based help landing page",
  });

  await helpPage.goto(`${BASE_URL}/help/getting-access`, { waitUntil: "domcontentloaded" });
  await capture(helpPage, "help-getting-access.png", {
    title: "Help • Getting Access",
    focusSelector: "text=Getting Access",
    focusLabel: "Role-specific onboarding",
  });

  await helpPage.goto(`${BASE_URL}/help/setting-password`, { waitUntil: "domcontentloaded" });
  await capture(helpPage, "help-setting-password.png", {
    title: "Help • Setting Password",
    focusSelector: "text=Setting Your Password",
    focusLabel: "Password and reset guidance",
  });

  await helpPage.goto(`${BASE_URL}/help/super-admin`, { waitUntil: "domcontentloaded" });
  await capture(helpPage, "help-super-admin.png", {
    title: "Help • Super Admin",
    focusSelector: "text=Super Admin",
    focusLabel: "Super admin responsibilities",
  });

  await helpPage.goto(`${BASE_URL}/help/licensee-admin`, { waitUntil: "domcontentloaded" });
  await capture(helpPage, "help-licensee-admin.png", {
    title: "Help • Licensee/Admin",
    focusSelector: "text=Licensee/Admin",
    focusLabel: "Licensee operations",
  });

  await helpPage.goto(`${BASE_URL}/help/manufacturer`, { waitUntil: "domcontentloaded" });
  await capture(helpPage, "help-manufacturer.png", {
    title: "Help • Manufacturer",
    focusSelector: "text=Manufacturer",
    focusLabel: "Factory print workflow",
  });

  await helpPage.goto(`${BASE_URL}/help/customer`, { waitUntil: "domcontentloaded" });
  await capture(helpPage, "help-customer.png", {
    title: "Help • Customer",
    focusSelector: "text=Customer",
    focusLabel: "Verification and fraud reporting",
  });

  await helpCtx.close();
});
