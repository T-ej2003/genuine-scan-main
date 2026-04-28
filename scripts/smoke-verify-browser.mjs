import { chromium } from "@playwright/test";

const trimTrailingSlash = (value) => String(value || "").trim().replace(/\/+$/, "");

const baseUrl = trimTrailingSlash(process.env.VERIFY_BROWSER_SMOKE_BASE_URL || "https://www.mscqr.com");
const verifyUrl = `${baseUrl}/verify`;
const verifySlashUrl = `${baseUrl}/verify/`;
const expectedHeading = /verify a product|product verification/i;
const allowedGuestFailures = [/\/api\/auth\/me(?:\?|$)/];

const failures = [];

const isAllowedGuestFailure = (url) => allowedGuestFailures.some((pattern) => pattern.test(url));

const assert = (condition, message) => {
  if (!condition) failures.push(message);
};

const run = async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });

  const pageErrors = [];
  const consoleErrors = [];
  const failedRequests = [];

  page.on("pageerror", (error) => pageErrors.push(error.message));
  page.on("console", (message) => {
    if (message.type() === "error") consoleErrors.push(message.text());
  });
  page.on("requestfailed", (request) => {
    const url = request.url();
    if (!isAllowedGuestFailure(url)) {
      failedRequests.push(`${url}: ${request.failure()?.errorText || "request failed"}`);
    }
  });

  const response = await page.goto(verifyUrl, { waitUntil: "networkidle" });
  assert(response?.ok(), `/verify must return a successful document response; got HTTP ${response?.status() ?? "unknown"}.`);
  await page.getByRole("heading", { name: expectedHeading }).waitFor({ timeout: 10_000 });

  const bodyText = (await page.locator("body").innerText()).trim();
  const robots = (await page.locator('meta[name="robots"]').getAttribute("content")) || "";
  const canonical = (await page.locator('link[rel="canonical"]').getAttribute("href")) || "";

  assert(bodyText.length > 200, "/verify rendered too little text and may be visually blank.");
  assert(!/noindex/i.test(robots), `/verify must not render a noindex robots directive; got "${robots}".`);
  assert(canonical === verifyUrl, `/verify canonical must be ${verifyUrl}; got "${canonical || "missing"}".`);

  const slashResponse = await page.goto(verifySlashUrl, { waitUntil: "networkidle" });
  assert(slashResponse?.ok(), `/verify/ must return a successful SPA document response; got HTTP ${slashResponse?.status() ?? "unknown"}.`);
  await page.waitForURL(verifyUrl, { timeout: 10_000 });
  await page.getByRole("heading", { name: expectedHeading }).waitFor({ timeout: 10_000 });

  assert(page.url() === verifyUrl, `/verify/ must canonicalize in-browser to ${verifyUrl}; got ${page.url()}.`);
  assert(pageErrors.length === 0, `Browser page errors were raised: ${pageErrors.join(" | ")}`);
  assert(failedRequests.length === 0, `Unexpected failed browser requests: ${failedRequests.join(" | ")}`);

  const unexpectedConsoleErrors = consoleErrors.filter(
    (message) => !message.includes("/api/auth/me") && !/Failed to load resource: the server responded with a status of 401/i.test(message),
  );
  assert(unexpectedConsoleErrors.length === 0, `Unexpected console errors: ${unexpectedConsoleErrors.join(" | ")}`);

  await browser.close();

  if (failures.length > 0) {
    console.error("Verify browser smoke failed:");
    for (const failure of failures) console.error(`- ${failure}`);
    process.exit(1);
  }

  console.log(`Verify browser smoke passed for ${verifyUrl}.`);
};

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
