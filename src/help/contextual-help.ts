import type { UserRole } from "@/types";

export type PageGuidance = {
  title: string;
  summary: string;
  firstAction: string;
  note?: string;
};

const isPath = (pathname: string, exact: string) => pathname === exact;
const starts = (pathname: string, prefix: string) => pathname.startsWith(prefix);

export const getRoleHelpHome = (role?: UserRole | null) => {
  if (role === "super_admin") return "/help/super-admin";
  if (role === "licensee_admin") return "/help/licensee-admin";
  if (role === "manufacturer") return "/help/manufacturer";
  return "/help/customer";
};

export const getContextualHelpRoute = (pathname: string, role?: UserRole | null) => {
  if (starts(pathname, "/ir/incidents/")) return "/help/incident-actions";
  if (starts(pathname, "/ir")) return "/help/incident-response";
  if (starts(pathname, "/incidents")) return role === "super_admin" ? "/help/incidents" : "/help/licensee-admin";
  if (starts(pathname, "/licensees")) return "/help/super-admin";
  if (starts(pathname, "/qr-codes")) return "/help/super-admin";
  if (starts(pathname, "/printer-diagnostics")) return "/help/manufacturer";
  if (starts(pathname, "/qr-requests")) return role === "super_admin" ? "/help/super-admin" : "/help/licensee-admin";
  if (starts(pathname, "/batches")) {
    if (role === "manufacturer") return "/help/manufacturer";
    if (role === "super_admin") return "/help/super-admin";
    return "/help/licensee-admin";
  }
  if (starts(pathname, "/manufacturers")) return role === "super_admin" ? "/help/super-admin" : "/help/licensee-admin";
  if (starts(pathname, "/qr-tracking")) {
    if (role === "super_admin") return "/help/super-admin";
    if (role === "manufacturer") return "/help/manufacturer";
    return "/help/licensee-admin";
  }
  if (starts(pathname, "/support")) return role === "super_admin" ? "/help/support" : "/help/communications";
  if (starts(pathname, "/governance")) return role === "super_admin" ? "/help/governance" : "/help/licensee-admin";
  if (starts(pathname, "/audit-logs")) return "/help/auth-overview";
  if (starts(pathname, "/account")) return "/help/setting-password";
  if (starts(pathname, "/verify") || starts(pathname, "/scan")) return "/help/customer";
  if (starts(pathname, "/help")) return getRoleHelpHome(role);
  return getRoleHelpHome(role);
};

export const getPageGuidance = (pathname: string, role?: UserRole | null): PageGuidance | null => {
  if (isPath(pathname, "/dashboard")) {
    return {
      title: "Understand your dashboard",
      summary: "This page gives a quick health view of your work area, pending tasks, and alerts.",
      firstAction: "Start with cards marked pending or blocked, then open their linked page.",
      note: "All numbers are scoped to your role permissions.",
    };
  }

  if (starts(pathname, "/qr-requests")) {
    return {
      title: "Manage QR inventory requests",
      summary: "Use this page to submit, review, and track QR quantity requests.",
      firstAction: role === "super_admin" ? "Review pending requests first." : "Create a new request with required quantity.",
      note: "Always add clear notes so approvals are easier.",
    };
  }

  if (starts(pathname, "/batches")) {
    return {
      title: "Work with batches",
      summary: "Batches group QR codes for controlled print and tracking operations.",
      firstAction:
        role === "manufacturer"
          ? "Open an assigned batch and start print job creation."
          : "Open a source batch workspace to allocate quantity, review manufacturer distribution, and inspect audit history.",
      note: role === "manufacturer" ? "Only assigned stock can move to next lifecycle step." : "The main list shows one stable source row per original batch.",
    };
  }

  if (starts(pathname, "/manufacturers")) {
    return {
      title: "Manage manufacturer accounts",
      summary: "Create, activate, and maintain factory user accounts for print execution.",
      firstAction: "Check account status, then use View details or Pending/Printed chips to jump into that manufacturer's work.",
      note: "Deactivate unused factory users for better security.",
    };
  }

  if (starts(pathname, "/qr-tracking")) {
    return {
      title: "Review scan activity",
      summary: "Track scan history, repeated scans, and blocked events to detect potential issues.",
      firstAction: "Filter by status and recent date range to focus on anomalies.",
      note: "Location shown here is coarse context only.",
    };
  }

  if (starts(pathname, "/ir") || starts(pathname, "/incidents")) {
    return {
      title: "Handle incidents step-by-step",
      summary: "Triage cases, apply containment, add evidence, and close with documented outcomes.",
      firstAction: "Open NEW or HIGH severity items first.",
      note: "Every major action is logged for audit traceability.",
    };
  }

  if (starts(pathname, "/support")) {
    return {
      title: "Run support workflow",
      summary: "Track ticket queue, SLA timers, and messages linked to incident lifecycles.",
      firstAction: "Prioritize breached or high-priority tickets first.",
      note: "Support workflow is Super Admin only.",
    };
  }

  if (starts(pathname, "/governance")) {
    return {
      title: "Manage governance controls",
      summary: "Configure tenant feature flags, retention lifecycle, compliance reporting, and telemetry review.",
      firstAction: "Confirm tenant scope before applying policy changes.",
      note: "Always run retention preview before apply mode.",
    };
  }

  if (starts(pathname, "/audit-logs")) {
    return {
      title: "Audit history",
      summary: "Use this page to verify who did what and when across key workflows.",
      firstAction: "Use filters to narrow by action type and date.",
      note: "Audit data supports investigations and compliance checks.",
    };
  }

  if (starts(pathname, "/licensees")) {
    return {
      title: "Manage tenant organizations",
      summary: "Create and maintain licensee organizations and their access boundaries.",
      firstAction: "Review existing licensees before creating a new one.",
      note: "Ensure support contact fields are complete for customer workflows.",
    };
  }

  if (starts(pathname, "/qr-codes")) {
    return {
      title: "Review QR inventory",
      summary: "Inspect code status and lifecycle readiness across allocations and prints.",
      firstAction: "Use status filters to identify dormant, blocked, or active stock.",
      note: "Avoid deleting records unless operational policy requires it.",
    };
  }

  if (starts(pathname, "/printer-diagnostics")) {
    return {
      title: "Diagnose printer issues",
      summary: "Separate workstation connector problems, operating-system printer visibility, and saved printer readiness.",
      firstAction: "Start with the top status card, then inspect workstation connector reachability and discovered printers.",
      note: "Use workstation printing for printers installed on the computer, factory label printer profiles for controlled LAN devices, and office / AirPrint profiles for IPP printers.",
    };
  }

  if (starts(pathname, "/account")) {
    return {
      title: "Keep your account secure",
      summary: "Update your profile and password to maintain secure access.",
      firstAction: "Use a strong unique password and rotate it regularly.",
      note: "If sign-in fails, use the password reset flow from the login page.",
    };
  }

  return null;
};
