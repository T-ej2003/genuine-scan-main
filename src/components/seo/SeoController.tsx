import { useEffect } from "react";
import { useLocation } from "react-router-dom";

const SITE_NAME = "MSCQR";
const SITE_ORIGIN = "https://www.mscqr.com";
const DEFAULT_OG_IMAGE = `${SITE_ORIGIN}/brand/mscqr-og.png`;
const DEFAULT_TITLE = "MSCQR | Manufacturer-Led Product Authentication Infrastructure";
const DEFAULT_DESCRIPTION =
  "MSCQR helps manufacturers govern QR issuance, controlled printing, public verification, anomaly review, support escalation, and audit evidence for high-trust products.";
const HOME_DESCRIPTION =
  "MSCQR helps manufacturers govern QR issuance, controlled printing, public verification, duplicate/anomaly review, support escalation, and audit evidence.";

type SeoMetadata = {
  title: string;
  description: string;
  path?: string;
  robots?: string;
  ogTitle?: string;
  ogDescription?: string;
  structuredData?: unknown[];
};

const INDEX_ROBOTS = "index,follow,max-image-preview:large";
const NOINDEX_ROBOTS = "noindex,nofollow";

const HOME_STRUCTURED_DATA = [
  {
    "@context": "https://schema.org",
    "@type": "Organization",
    name: SITE_NAME,
    url: SITE_ORIGIN,
    logo: `${SITE_ORIGIN}/brand/mscqr-mark-512.png`,
    image: DEFAULT_OG_IMAGE,
  },
  {
    "@context": "https://schema.org",
    "@type": "WebSite",
    name: SITE_NAME,
    url: `${SITE_ORIGIN}/`,
  },
  {
    "@context": "https://schema.org",
    "@type": "SoftwareApplication",
    name: SITE_NAME,
    applicationCategory: "BusinessApplication",
    operatingSystem: "Web",
    url: SITE_ORIGIN,
    image: DEFAULT_OG_IMAGE,
    description:
      "Manufacturer-led product authentication infrastructure for governed QR issuance, controlled printing, public verification, anomaly review, support escalation, and audit evidence.",
  },
] as const;

const PUBLIC_SEO: Record<string, SeoMetadata> = {
  "/": {
    title: DEFAULT_TITLE,
    description: HOME_DESCRIPTION,
    path: "/",
    structuredData: [...HOME_STRUCTURED_DATA],
  },
  "/trust": {
    title: "Trust & Security | MSCQR",
    description:
      "Review MSCQR's trust posture for governed product authentication, controlled QR workflows, audit evidence, and production-grade operational controls.",
    path: "/trust",
  },
  "/privacy": {
    title: "Privacy Policy | MSCQR",
    description:
      "Read MSCQR's privacy policy for product authentication, verification, and manufacturer-led platform workflows.",
    path: "/privacy",
  },
  "/terms": {
    title: "Terms of Service | MSCQR",
    description: "Read the terms governing use of MSCQR's manufacturer-led product authentication infrastructure.",
    path: "/terms",
  },
  "/cookies": {
    title: "Cookie Policy | MSCQR",
    description: "Read how MSCQR uses cookies and related technologies across its product authentication platform.",
    path: "/cookies",
  },
  "/connector-download": {
    title: "Printer Connector Download | MSCQR",
    description:
      "Download MSCQR's printer connector for controlled QR printing workflows where authorized by your organization.",
    path: "/connector-download",
  },
  "/verify": {
    title: "Verify a Product | MSCQR",
    description: "Use MSCQR to verify a product code or QR code through a manufacturer-led product authentication workflow.",
    path: "/verify",
  },
  "/help": {
    title: "MSCQR Help Center",
    description:
      "Find help for MSCQR product verification, manufacturer workflows, controlled printing, and support escalation.",
    path: "/help",
  },
  "/platform": {
    title: "Platform | MSCQR Product Authentication Infrastructure",
    description:
      "Explore MSCQR's governed QR issuance, controlled printing, public verification, anomaly review, support escalation, and audit evidence workflows.",
    path: "/platform",
  },
  "/solutions/manufacturers": {
    title: "For Manufacturers | MSCQR",
    description:
      "MSCQR helps manufacturers control QR issuance, printing, verification, duplicate review, and audit evidence across high-trust product workflows.",
    path: "/solutions/manufacturers",
  },
  "/solutions/licensees": {
    title: "For Licensees | MSCQR",
    description:
      "MSCQR supports licensee and operator workflows for controlled product verification, scan review, support escalation, and manufacturer-governed QR operations.",
    path: "/solutions/licensees",
  },
  "/industries": {
    title: "Industries | MSCQR",
    description:
      "MSCQR supports high-trust product authentication workflows for industrial components, spare parts, regulated supply chains, electronics, cosmetics, certificates, and more.",
    path: "/industries",
  },
  "/industries/industrial-components": {
    title: "Industrial Component Authentication | MSCQR",
    description:
      "MSCQR supports governed QR verification and audit evidence workflows for industrial components and high-trust spare parts.",
    path: "/industries/industrial-components",
  },
  "/industries/spare-parts": {
    title: "Spare Parts Authentication | MSCQR",
    description:
      "MSCQR helps manufacturers and operators verify spare parts with controlled QR issuance, scan review, and audit evidence workflows.",
    path: "/industries/spare-parts",
  },
  "/industries/regulated-supply-chains": {
    title: "Regulated Supply Chain Product Authentication | MSCQR",
    description:
      "MSCQR supports controlled labeling, product verification, anomaly review, and audit evidence workflows for regulated supply chain environments.",
    path: "/industries/regulated-supply-chains",
  },
  "/request-access": {
    title: "Request Access | MSCQR",
    description:
      "Contact MSCQR to discuss manufacturer-led product authentication, governed QR issuance, controlled printing, and verification workflows.",
    path: "/request-access",
  },
  "/blog": {
    title: "MSCQR Insights",
    description:
      "Practical notes on product authentication, QR verification, controlled printing, audit evidence, and manufacturer-led anti-counterfeit operations.",
    path: "/blog",
  },
};

const AUTH_NOINDEX_PATHS = new Set([
  "/login",
  "/accept-invite",
  "/verify-email",
  "/forgot-password",
  "/reset-password",
]);

const PRIVATE_NOINDEX_PATHS = new Set([
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
]);

const normalizePathname = (pathname: string) => {
  if (pathname.length > 1 && pathname.endsWith("/")) return pathname.slice(0, -1);
  return pathname || "/";
};

const buildUrl = (path = "/") => `${SITE_ORIGIN}${path === "/" ? "/" : path}`;

const isIncidentDetailPath = (pathname: string) =>
  pathname.startsWith("/incident-response/incidents/") || pathname.startsWith("/ir/incidents/");

const getSeoMetadata = (pathname: string): SeoMetadata => {
  const path = normalizePathname(pathname);
  const publicMeta = PUBLIC_SEO[path];
  if (publicMeta) return { robots: INDEX_ROBOTS, ...publicMeta };

  if (path.startsWith("/verify/")) {
    return {
      title: "Product Verification | MSCQR",
      description: "MSCQR product verification result pages are kept out of search indexes to protect scan context.",
      path,
      robots: NOINDEX_ROBOTS,
    };
  }

  if (path === "/scan") {
    return {
      title: "Scan a Product | MSCQR",
      description: "MSCQR scanner flows are kept out of search indexes to protect verification context.",
      path,
      robots: NOINDEX_ROBOTS,
    };
  }

  if (
    AUTH_NOINDEX_PATHS.has(path) ||
    PRIVATE_NOINDEX_PATHS.has(path) ||
    isIncidentDetailPath(path) ||
    path.startsWith("/help/")
  ) {
    return {
      title: `${SITE_NAME} Platform`,
      description: DEFAULT_DESCRIPTION,
      path,
      robots: NOINDEX_ROBOTS,
    };
  }

  return {
    title: "Page Not Found | MSCQR",
    description: "MSCQR could not find the requested page.",
    path,
    robots: NOINDEX_ROBOTS,
  };
};

const upsertMeta = (attribute: "name" | "property", key: string, content: string) => {
  const selector = `meta[${attribute}="${key}"]`;
  const existing = Array.from(document.head.querySelectorAll<HTMLMetaElement>(selector));
  const element = existing[0] || document.createElement("meta");

  if (!existing[0]) {
    element.setAttribute(attribute, key);
    document.head.appendChild(element);
  }

  for (const duplicate of existing.slice(1)) duplicate.remove();
  element.setAttribute("content", content);
};

const upsertCanonical = (href: string) => {
  const existing = Array.from(document.head.querySelectorAll<HTMLLinkElement>('link[rel="canonical"]'));
  const element = existing[0] || document.createElement("link");

  if (!existing[0]) {
    element.setAttribute("rel", "canonical");
    document.head.appendChild(element);
  }

  for (const duplicate of existing.slice(1)) duplicate.remove();
  element.setAttribute("href", href);
};

const upsertStructuredData = (items: unknown[] | undefined) => {
  const scriptId = "mscqr-route-structured-data";
  const existing = document.getElementById(scriptId);

  if (!items?.length) {
    existing?.remove();
    return;
  }

  const element = existing || document.createElement("script");
  element.setAttribute("id", scriptId);
  element.setAttribute("type", "application/ld+json");
  element.textContent = JSON.stringify(items, null, 2);

  if (!existing) document.head.appendChild(element);
};

export function SeoController() {
  const location = useLocation();

  useEffect(() => {
    const metadata = getSeoMetadata(location.pathname);
    const canonicalUrl = buildUrl(metadata.path);
    const ogTitle = metadata.ogTitle || metadata.title;
    const ogDescription = metadata.ogDescription || metadata.description;

    document.title = metadata.title;
    upsertCanonical(canonicalUrl);
    upsertMeta("name", "description", metadata.description);
    upsertMeta("name", "robots", metadata.robots || INDEX_ROBOTS);
    upsertMeta("name", "author", SITE_NAME);
    upsertMeta("name", "application-name", SITE_NAME);
    upsertMeta("property", "og:site_name", SITE_NAME);
    upsertMeta("property", "og:title", ogTitle);
    upsertMeta("property", "og:description", ogDescription);
    upsertMeta("property", "og:type", "website");
    upsertMeta("property", "og:url", canonicalUrl);
    upsertMeta("property", "og:image", DEFAULT_OG_IMAGE);
    upsertMeta("property", "og:image:secure_url", DEFAULT_OG_IMAGE);
    upsertMeta("property", "og:image:type", "image/png");
    upsertMeta("property", "og:image:width", "1200");
    upsertMeta("property", "og:image:height", "630");
    upsertMeta("property", "og:image:alt", "MSCQR product authentication infrastructure preview");
    upsertMeta("name", "twitter:card", "summary_large_image");
    upsertMeta("name", "twitter:title", ogTitle);
    upsertMeta("name", "twitter:description", ogDescription);
    upsertMeta("name", "twitter:image", DEFAULT_OG_IMAGE);
    upsertMeta("name", "twitter:image:alt", "MSCQR product authentication infrastructure preview");
    upsertStructuredData(metadata.structuredData);
  }, [location.pathname]);

  return null;
}
