import { useEffect } from "react";
import { useLocation } from "react-router-dom";

const SITE_NAME = "MSCQR";
const SITE_ORIGIN = "https://www.mscqr.com";
const DEFAULT_OG_IMAGE = `${SITE_ORIGIN}/brand/mscqr-og.png`;
const DEFAULT_TITLE = "MSCQR | Garment Authentication for Brands and Manufacturers";
const DEFAULT_DESCRIPTION =
  "MSCQR helps brands and manufacturers create QR labels for garments, support customer verification, and review suspicious scan patterns.";
const HOME_DESCRIPTION =
  "Make every garment verifiable. MSCQR helps brands and manufacturers let customers scan garments and trust what they buy.";

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
      "Garment authentication software for brands and manufacturers using QR labels, customer verification, and suspicious scan review.",
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
    title: "Trust & Security for Garment Verification | MSCQR",
    description:
      "Learn how MSCQR helps brands review garment label status, print confirmation, scan history, and suspicious repeat scan patterns.",
    path: "/trust",
  },
  "/privacy": {
    title: "Privacy Policy | MSCQR",
    description:
      "Read MSCQR's privacy policy for garment verification, customer scans, and brand or manufacturer workflows.",
    path: "/privacy",
  },
  "/terms": {
    title: "Terms of Service | MSCQR",
    description: "Read the terms governing use of MSCQR's garment authentication platform.",
    path: "/terms",
  },
  "/cookies": {
    title: "Cookie Policy | MSCQR",
    description: "Read how MSCQR uses cookies and related technologies across garment verification workflows.",
    path: "/cookies",
  },
  "/connector-download": {
    title: "Printer Connector for Garment QR Labels | MSCQR",
    description:
      "Download MSCQR's printer connector for supported garment QR label printing workflows.",
    path: "/connector-download",
  },
  "/verify": {
    title: "Verify a Garment QR Label | MSCQR",
    description:
      "Use MSCQR to verify a garment QR label and see whether the item can be confirmed.",
    path: "/verify",
  },
  "/help": {
    title: "MSCQR Help Center",
    description:
      "Find help for MSCQR garment verification, brand workflows, manufacturing label workflows, and customer scans.",
    path: "/help",
  },
  "/platform": {
    title: "Garment Authentication Workspace | MSCQR",
    description:
      "Explore MSCQR for QR labels, print confirmation, customer scans, and suspicious scan review.",
    path: "/platform",
  },
  "/solutions/brands": {
    title: "QR Label Verification for Clothing Brands | MSCQR",
    description:
      "MSCQR helps clothing brands issue garment QR labels, let customers verify garments, and review suspicious scan patterns.",
    path: "/solutions/brands",
  },
  "/solutions/garment-manufacturers": {
    title: "QR Label Workflows for Garment Manufacturers | MSCQR",
    description:
      "MSCQR helps garment manufacturers receive QR labels, print or attach tags, confirm completion, and support brand verification workflows.",
    path: "/solutions/garment-manufacturers",
  },
  "/solutions/apparel-authenticity": {
    title: "Apparel Authenticity and Suspicious Scan Detection | MSCQR",
    description:
      "MSCQR is built for garment and clothing verification with QR labels, customer scans, and suspicious repeat scan review.",
    path: "/solutions/apparel-authenticity",
  },
  "/how-scanning-works": {
    title: "How Garment QR Scanning Works | MSCQR",
    description:
      "See how customers scan garment QR labels, view verification results, check brand information, and optionally report concerns.",
    path: "/how-scanning-works",
  },
  "/solutions/manufacturers": {
    title: "QR Label Workflows for Garment Manufacturers | MSCQR",
    description:
      "MSCQR helps garment manufacturers receive QR labels, print or attach tags, confirm completion, and support brand verification workflows.",
    path: "/solutions/manufacturers",
  },
  "/solutions/licensees": {
    title: "QR Label Verification for Clothing Brands | MSCQR",
    description:
      "MSCQR helps clothing brands issue garment QR labels, let customers verify garments, and review suspicious scan patterns.",
    path: "/solutions/licensees",
  },
  "/industries": {
    title: "Apparel Authenticity and Suspicious Scan Detection | MSCQR",
    description:
      "MSCQR is built for garment and clothing verification with QR labels, customer scans, and suspicious repeat scan review.",
    path: "/industries",
  },
  "/industries/industrial-components": {
    title: "Apparel Authenticity and Suspicious Scan Detection | MSCQR",
    description:
      "MSCQR is built for garment and clothing verification with QR labels, customer scans, and suspicious repeat scan review.",
    path: "/industries/industrial-components",
  },
  "/industries/spare-parts": {
    title: "Apparel Authenticity and Suspicious Scan Detection | MSCQR",
    description:
      "MSCQR is built for garment and clothing verification with QR labels, customer scans, and suspicious repeat scan review.",
    path: "/industries/spare-parts",
  },
  "/industries/regulated-supply-chains": {
    title: "Apparel Authenticity and Suspicious Scan Detection | MSCQR",
    description:
      "MSCQR is built for garment and clothing verification with QR labels, customer scans, and suspicious repeat scan review.",
    path: "/industries/regulated-supply-chains",
  },
  "/request-access": {
    title: "Request Access to MSCQR Garment Authentication",
    description:
      "Request access to MSCQR for garment QR labels, customer verification, print confirmation, and suspicious scan review.",
    path: "/request-access",
  },
  "/blog": {
    title: "MSCQR Insights | Garment Authentication Notes",
    description:
      "Practical notes for clothing brands and garment manufacturers using QR labels, customer verification, and suspicious scan review.",
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
      title: "Garment Verification | MSCQR",
      description: "MSCQR garment verification result pages are kept out of search indexes to protect scan context.",
      path,
      robots: NOINDEX_ROBOTS,
    };
  }

  if (path === "/scan") {
    return {
      title: "Scan a Garment | MSCQR",
      description: "MSCQR scanner flows are kept out of search indexes to protect garment verification context.",
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
    upsertMeta("property", "og:image:alt", "MSCQR garment authentication preview");
    upsertMeta("name", "twitter:card", "summary_large_image");
    upsertMeta("name", "twitter:title", ogTitle);
    upsertMeta("name", "twitter:description", ogDescription);
    upsertMeta("name", "twitter:image", DEFAULT_OG_IMAGE);
    upsertMeta("name", "twitter:image:alt", "MSCQR garment authentication preview");
    upsertStructuredData(metadata.structuredData);
  }, [location.pathname]);

  return null;
}
