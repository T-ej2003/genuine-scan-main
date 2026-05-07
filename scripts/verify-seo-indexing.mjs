import { readFileSync } from "node:fs";
import path from "node:path";

const repoRoot = process.cwd();
const SITE_ORIGIN = "https://www.mscqr.com";

const files = {
  index: path.join(repoRoot, "index.html"),
  sitemap: path.join(repoRoot, "public", "sitemap.xml"),
  robots: path.join(repoRoot, "public", "robots.txt"),
  seo: path.join(repoRoot, "src", "components", "seo", "SeoController.tsx"),
  app: path.join(repoRoot, "src", "App.tsx"),
};

const failures = [];

const read = (file, label) => {
  try {
    return readFileSync(file, "utf8");
  } catch (error) {
    failures.push(`${label} is missing or unreadable: ${error instanceof Error ? error.message : String(error)}`);
    return "";
  }
};

const sitemap = read(files.sitemap, "public/sitemap.xml");
const robots = read(files.robots, "public/robots.txt");
const seo = read(files.seo, "src/components/seo/SeoController.tsx");
const app = read(files.app, "src/App.tsx");
const indexHtml = read(files.index, "index.html");

const sitemapUrls = Array.from(sitemap.matchAll(/<loc>([^<]+)<\/loc>/g), (match) => match[1].trim());
const sitemapPaths = sitemapUrls.map((value) => {
  try {
    return new URL(value).pathname;
  } catch {
    failures.push(`Invalid sitemap URL: ${value}`);
    return "";
  }
});

const requiredSitemapUrls = [
  `${SITE_ORIGIN}/`,
  `${SITE_ORIGIN}/about`,
  `${SITE_ORIGIN}/contact`,
  `${SITE_ORIGIN}/privacy`,
  `${SITE_ORIGIN}/terms`,
  `${SITE_ORIGIN}/request-access`,
];

const forbiddenSitemapPathPrefixes = [
  "/login",
  "/accept-invite",
  "/verify-email",
  "/forgot-password",
  "/reset-password",
  "/dashboard",
  "/licensees",
  "/code-requests",
  "/batches",
  "/printer-setup",
  "/scan-activity",
  "/manufacturers",
  "/audit-history",
  "/incident-response",
  "/support",
  "/release-readiness",
  "/governance",
  "/settings",
  "/account",
  "/api",
  "/scan",
  "/qr-codes",
  "/qr-requests",
  "/product-batches",
  "/qr-tracking",
  "/audit-logs",
  "/ir",
  "/incidents",
];

const forbiddenExactSitemapPaths = new Set(["/verify/"]);

for (const url of requiredSitemapUrls) {
  if (!sitemapUrls.includes(url)) failures.push(`Sitemap must include ${url}.`);
}

for (const currentPath of sitemapPaths) {
  if (!currentPath) continue;
  if (forbiddenExactSitemapPaths.has(currentPath)) {
    failures.push(`Sitemap must not include ${currentPath}.`);
  }
  if (currentPath.startsWith("/verify/")) {
    failures.push(`Sitemap must not include verification result URL ${currentPath}.`);
  }
  for (const prefix of forbiddenSitemapPathPrefixes) {
    if (currentPath === prefix || currentPath.startsWith(`${prefix}/`)) {
      failures.push(`Sitemap must not include private/noindex URL ${currentPath}.`);
    }
  }
}

const robotsDisallowRules = Array.from(robots.matchAll(/^\s*Disallow:\s*(\S*)\s*$/gim), (match) => match[1].trim()).filter(Boolean);
const robotsAllowRules = Array.from(robots.matchAll(/^\s*Allow:\s*(\S*)\s*$/gim), (match) => match[1].trim()).filter(Boolean);

const isRobotsBlocked = (urlPath) => {
  let best = { type: "allow", length: -1 };
  for (const rule of robotsAllowRules) {
    if (urlPath.startsWith(rule) && rule.length > best.length) best = { type: "allow", length: rule.length };
  }
  for (const rule of robotsDisallowRules) {
    if (urlPath.startsWith(rule) && rule.length > best.length) best = { type: "disallow", length: rule.length };
  }
  return best.type === "disallow";
};

const crawlablePublicPaths = ["/", "/about", "/contact", "/privacy", "/terms", "/request-access", "/verify", "/platform", "/trust"];
for (const publicPath of crawlablePublicPaths) {
  if (isRobotsBlocked(publicPath)) {
    failures.push(`robots.txt must not block public indexable path ${publicPath}.`);
  }
}

const assertIndexContains = (needle, message) => {
  if (!indexHtml.includes(needle)) failures.push(message);
};

assertIndexContains(
  "<title>MSCQR | Garment Authentication QR Platform</title>",
  "Homepage index.html must use the production MSCQR garment authentication title.",
);
assertIndexContains(
  'content="MSCQR helps brands and manufacturers verify garment authenticity using secure QR labels, scan reviews, and customer support workflows."',
  "Homepage index.html must use the production MSCQR meta description.",
);
assertIndexContains(
  '<link rel="canonical" href="https://www.mscqr.com/"',
  "Homepage index.html must declare the canonical https://www.mscqr.com/ URL.",
);
assertIndexContains(
  '<meta property="og:title" content="MSCQR | Garment Authentication QR Platform"',
  "Homepage index.html must declare the production Open Graph title.",
);
assertIndexContains(
  '<meta name="twitter:card" content="summary_large_image"',
  "Homepage index.html must declare a summary_large_image Twitter card.",
);
assertIndexContains('"@type": "Organization"', "Homepage index.html must include Organization JSON-LD.");
assertIndexContains('"@type": "WebSite"', "Homepage index.html must include WebSite JSON-LD.");
assertIndexContains('"name": "MSCQR"', "Homepage JSON-LD must identify MSCQR by name.");
assertIndexContains('"url": "https://www.mscqr.com"', "Homepage JSON-LD must identify the canonical MSCQR URL.");

const requiredRobotsDisallows = [
  "/api",
  "/login",
  "/accept-invite",
  "/verify-email",
  "/forgot-password",
  "/reset-password",
  "/dashboard",
  "/licensees",
  "/code-requests",
  "/batches",
  "/printer-setup",
  "/scan-activity",
  "/manufacturers",
  "/audit-history",
  "/incident-response",
  "/support",
  "/release-readiness",
  "/governance",
  "/settings",
  "/account",
  "/scan",
  "/qr-codes",
  "/qr-requests",
  "/product-batches",
  "/qr-tracking",
  "/audit-logs",
  "/ir",
  "/incidents",
];

const requiredRobotsAllows = ["/verify", "/verify/"];

for (const allow of requiredRobotsAllows) {
  if (!robotsAllowRules.includes(allow)) failures.push(`robots.txt must include Allow: ${allow}.`);
}

for (const disallow of requiredRobotsDisallows) {
  if (!robotsDisallowRules.includes(disallow)) failures.push(`robots.txt must include Disallow: ${disallow}.`);
}

if (robotsDisallowRules.some((rule) => rule === "/verify" || rule === "/verify/")) {
  failures.push(
    "robots.txt must not disallow /verify or /verify/. Verification result URLs are excluded by sitemap and rendered noindex so /verify remains unambiguously crawlable.",
  );
}

const assertSeoContains = (needle, message) => {
  if (!seo.includes(needle)) failures.push(message);
};

assertSeoContains('"/verify"', "SeoController must define /verify as public metadata.");
assertSeoContains('"/about"', "SeoController must define /about as public metadata.");
assertSeoContains('"/contact"', "SeoController must define /contact as public metadata.");
assertSeoContains("INDEX_ROBOTS", "SeoController must keep an explicit index/follow directive for public pages.");
assertSeoContains('path.startsWith("/verify/")', "SeoController must noindex /verify/:code and deeper result paths.");
assertSeoContains('path === "/scan"', "SeoController must noindex /scan.");
assertSeoContains("NOINDEX_ROBOTS", "SeoController must define a noindex,nofollow directive.");

const noindexRequiredPaths = [
  "/login",
  "/accept-invite",
  "/verify-email",
  "/forgot-password",
  "/reset-password",
  "/dashboard",
  "/licensees",
  "/code-requests",
  "/batches",
  "/printer-setup",
  "/scan-activity",
  "/manufacturers",
  "/audit-history",
  "/incident-response",
  "/support",
  "/release-readiness",
  "/governance",
  "/settings",
  "/account",
  "/qr-codes",
  "/qr-requests",
  "/product-batches",
  "/qr-tracking",
  "/audit-logs",
  "/ir",
  "/incidents",
];

for (const noindexPath of noindexRequiredPaths) {
  assertSeoContains(`"${noindexPath}"`, `SeoController must include ${noindexPath} in noindex route metadata.`);
}

const verifyResultBlock = seo.slice(seo.indexOf('path.startsWith("/verify/")'), seo.indexOf('if (path === "/scan")'));
if (!verifyResultBlock.includes("robots: NOINDEX_ROBOTS")) {
  failures.push("SeoController must assign noindex,nofollow to /verify/:code result paths.");
}
if (verifyResultBlock.includes('path: "/verify"')) {
  failures.push("Verification result pages must not canonicalize to the indexable /verify entry page.");
}

const scanBlock = seo.slice(seo.indexOf('if (path === "/scan")'), seo.indexOf("if (\n    AUTH_NOINDEX_PATHS"));
if (!scanBlock.includes("robots: NOINDEX_ROBOTS")) {
  failures.push("SeoController must assign noindex,nofollow to /scan.");
}
if (scanBlock.includes('path: "/verify"')) {
  failures.push("/scan must not canonicalize to the indexable /verify entry page.");
}

if (!app.includes('location.pathname === "/verify/"') || !app.includes('pathname: "/verify"')) {
  failures.push(
    "App must canonicalize the exact /verify/ browser path to /verify without using an ambiguous trailing-slash route.",
  );
}

if (app.includes('path="/verify/"')) {
  failures.push("App must not use a path=\"/verify/\" redirect route because React Router can also match /verify.");
}

if (!app.includes('path="/verify" element={<VerifyLanding />}')) {
  failures.push("App must render the public VerifyLanding component at /verify.");
}

if (!app.includes('path="/about" element={<AboutPage />}')) {
  failures.push("App must render the public AboutPage component at /about.");
}

if (!app.includes('path="/contact" element={<ContactPage />}')) {
  failures.push("App must render the public ContactPage component at /contact.");
}

if (app.indexOf('path="/verify"') > app.indexOf('path="/verify/:code"')) {
  failures.push("App must keep the /verify entry route declared before /verify/:code for readability and auditability.");
}

if (failures.length > 0) {
  console.error("SEO indexing guardrail failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log("SEO indexing guardrail passed.");
