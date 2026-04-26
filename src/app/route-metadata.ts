import {
  Building2,
  CircleHelp,
  Factory,
  FileText,
  LayoutDashboard,
  ScanEye,
  Settings,
  Shield,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

import type { UserRole } from "@/types";

export const APP_PATHS = {
  dashboard: "/dashboard",
  licensees: "/licensees",
  codeRequests: "/code-requests",
  batches: "/batches",
  scanActivity: "/scan-activity",
  manufacturers: "/manufacturers",
  auditHistory: "/audit-history",
  incidentResponse: "/incident-response",
  incidentDetailPrefix: "/incident-response/incidents",
  support: "/support",
  governance: "/governance",
  releaseReadiness: "/release-readiness",
  settings: "/settings",
  account: "/account",
  connectorDownload: "/connector-download",
  printerSetup: "/printer-setup",
  verify: "/verify",
} as const;

type HelpRouteResolver = string | ((role?: UserRole | null) => string);

export type AppRouteMeta = {
  key: string;
  href: string;
  title: string;
  section: string;
  roles?: UserRole[];
  icon?: LucideIcon;
  nav: boolean;
  matchMode?: "exact" | "prefix";
  aliases?: string[];
  navLabel?: string;
  roleLabels?: Partial<Record<UserRole, string>>;
  helpRoute?: HelpRouteResolver;
};

const ALL_ADMIN_ROLES: UserRole[] = ["super_admin", "licensee_admin", "manufacturer"];

const ROUTES: AppRouteMeta[] = [
  {
    key: "incident-detail",
    href: APP_PATHS.incidentDetailPrefix,
    title: "Incident details",
    section: "Incident Response",
    roles: ["super_admin"],
    nav: false,
    matchMode: "prefix",
    aliases: ["/ir/incidents"],
    helpRoute: "/help/incident-actions",
  },
  {
    key: "incident-response",
    href: APP_PATHS.incidentResponse,
    title: "Incident Response",
    section: "Review",
    roles: ["super_admin"],
    icon: Shield,
    nav: true,
    matchMode: "prefix",
    aliases: ["/ir", "/incidents"],
    helpRoute: "/help/incident-response",
  },
  {
    key: "dashboard",
    href: APP_PATHS.dashboard,
    title: "Dashboard",
    section: "Command",
    roles: ALL_ADMIN_ROLES,
    icon: LayoutDashboard,
    nav: true,
    matchMode: "prefix",
    navLabel: "Overview",
    helpRoute: (role) => {
      if (role === "manufacturer") return "/help/manufacturer";
      if (role === "licensee_admin") return "/help/licensee-admin";
      return "/help/super-admin";
    },
  },
  {
    key: "licensees",
    href: APP_PATHS.licensees,
    title: "Licensees",
    section: "Governance",
    roles: ["super_admin"],
    icon: Building2,
    nav: true,
    matchMode: "prefix",
    helpRoute: "/help/super-admin",
  },
  {
    key: "code-requests",
    href: APP_PATHS.codeRequests,
    title: "Code Requests",
    section: "Lifecycle",
    roles: ["super_admin", "licensee_admin"],
    icon: FileText,
    nav: true,
    matchMode: "prefix",
    navLabel: "Code Requests",
    aliases: ["/qr-requests"],
    helpRoute: (role) => (role === "super_admin" ? "/help/super-admin" : "/help/licensee-admin"),
  },
  {
    key: "batches",
    href: APP_PATHS.batches,
    title: "Batches",
    section: "Lifecycle",
    roles: ALL_ADMIN_ROLES,
    icon: FileText,
    nav: true,
    matchMode: "prefix",
    roleLabels: { manufacturer: "My Batches" },
    helpRoute: (role) => {
      if (role === "manufacturer") return "/help/manufacturer";
      if (role === "licensee_admin") return "/help/licensee-admin";
      return "/help/super-admin";
    },
  },
  {
    key: "manufacturers",
    href: APP_PATHS.manufacturers,
    title: "Manufacturers",
    section: "Governance",
    roles: ["super_admin", "licensee_admin"],
    icon: Factory,
    nav: true,
    matchMode: "prefix",
    helpRoute: (role) => (role === "super_admin" ? "/help/super-admin" : "/help/licensee-admin"),
  },
  {
    key: "scan-activity",
    href: APP_PATHS.scanActivity,
    title: "Scan Activity",
    section: "Review",
    roles: ALL_ADMIN_ROLES,
    icon: ScanEye,
    nav: true,
    matchMode: "prefix",
    aliases: ["/qr-tracking", "/qr-codes"],
    navLabel: "Verification Activity",
    helpRoute: (role) => {
      if (role === "manufacturer") return "/help/manufacturer";
      if (role === "licensee_admin") return "/help/licensee-admin";
      return "/help/super-admin";
    },
  },
  {
    key: "support",
    href: APP_PATHS.support,
    title: "Support",
    section: "Review",
    roles: ["super_admin"],
    icon: CircleHelp,
    nav: true,
    matchMode: "prefix",
    helpRoute: "/help/support",
  },
  {
    key: "release-readiness",
    href: APP_PATHS.releaseReadiness,
    title: "Release Readiness",
    section: "Governance",
    roles: ["super_admin"],
    icon: Shield,
    nav: true,
    matchMode: "prefix",
    helpRoute: "/help/governance",
  },
  {
    key: "governance",
    href: APP_PATHS.governance,
    title: "Governance",
    section: "Governance",
    roles: ["super_admin"],
    icon: Shield,
    nav: false,
    matchMode: "prefix",
    helpRoute: "/help/governance",
  },
  {
    key: "audit-history",
    href: APP_PATHS.auditHistory,
    title: "Audit History",
    section: "Evidence",
    roles: ALL_ADMIN_ROLES,
    icon: FileText,
    nav: true,
    matchMode: "prefix",
    aliases: ["/audit-logs"],
    navLabel: "Audit Evidence",
    helpRoute: "/help/auth-overview",
  },
  {
    key: "settings",
    href: APP_PATHS.settings,
    title: "Settings",
    section: "Settings",
    roles: ALL_ADMIN_ROLES,
    icon: Settings,
    nav: true,
    matchMode: "prefix",
    helpRoute: "/help/setting-password",
  },
  {
    key: "account",
    href: APP_PATHS.account,
    title: "Account",
    section: "Settings",
    roles: ALL_ADMIN_ROLES,
    icon: Settings,
    nav: false,
    matchMode: "prefix",
    helpRoute: "/help/setting-password",
  },
  {
    key: "printer-setup",
    href: APP_PATHS.printerSetup,
    title: "Printer Setup",
    section: "Settings",
    roles: ["manufacturer"],
    nav: false,
    matchMode: "prefix",
    helpRoute: "/help/manufacturer",
  },
  {
    key: "connector-download",
    href: APP_PATHS.connectorDownload,
    title: "Install Connector",
    section: "Settings",
    nav: false,
    matchMode: "prefix",
    helpRoute: "/help/manufacturer",
  },
  {
    key: "verify",
    href: APP_PATHS.verify,
    title: "Verify Product",
    section: "Public",
    nav: false,
    matchMode: "prefix",
    aliases: ["/scan"],
    helpRoute: "/help/customer",
  },
];

const matchesPath = (pathname: string, href: string, matchMode: "exact" | "prefix" = "exact") => {
  if (pathname === href) return true;
  if (matchMode === "prefix") return pathname.startsWith(`${href}/`);
  return false;
};

export const getAppRouteMeta = (pathname: string) =>
  ROUTES.find((route) => {
    if (matchesPath(pathname, route.href, route.matchMode)) return true;
    return (route.aliases || []).some((alias) => matchesPath(pathname, alias, route.matchMode));
  }) || null;

export const getAppRouteLabel = (pathname: string, role?: UserRole | null) => {
  const route = getAppRouteMeta(pathname);
  if (!route) return null;
  return (role && route.roleLabels?.[role]) || route.navLabel || route.title;
};

export const isAppRouteActive = (pathname: string, href: string) => {
  const current = getAppRouteMeta(pathname);
  const target = ROUTES.find((route) => route.href === href);
  if (!current || !target) return false;
  return current.key === target.key;
};

export const getNavItemsForRole = (role?: UserRole | null) => {
  if (!role) return [];
  return ROUTES.filter((route) => route.nav && route.roles?.includes(role)).map((route) => ({
    ...route,
    icon: route.icon!,
    label: route.roleLabels?.[role] || route.navLabel || route.title,
  }));
};

export const getRoleDisplayLabel = (role?: UserRole | null) => {
  if (role === "super_admin") return "Super Admin";
  if (role === "licensee_admin") return "Licensee Admin";
  if (role === "manufacturer") return "Manufacturer Admin";
  return "User";
};

export const getAppHelpRoute = (pathname: string, role?: UserRole | null) => {
  const route = getAppRouteMeta(pathname);
  if (!route?.helpRoute) return null;
  return typeof route.helpRoute === "function" ? route.helpRoute(role) : route.helpRoute;
};

export const getAppBreadcrumbs = (pathname: string, role?: UserRole | null) => {
  const route = getAppRouteMeta(pathname);
  if (!route) return [];

  return [
    { label: route.section, href: route.href },
    { label: (role && route.roleLabels?.[role]) || route.title },
  ];
};
