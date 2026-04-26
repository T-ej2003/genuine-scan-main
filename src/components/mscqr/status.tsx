import { AlertTriangle, Ban, CheckCircle2, CircleDashed, FileCheck2, PackageCheck, ShieldCheck } from "lucide-react";
import type { LucideIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

export type MscqrStatusTone =
  | "neutral"
  | "verified"
  | "issued"
  | "printPending"
  | "printConfirmed"
  | "review"
  | "duplicate"
  | "blocked"
  | "replaced"
  | "expired"
  | "degraded"
  | "support"
  | "audit";

const toneClasses: Record<MscqrStatusTone, string> = {
  neutral: "border-mscqr-border bg-mscqr-surface-muted/70 text-mscqr-secondary",
  verified: "border-mscqr-verified/30 bg-mscqr-verified/12 text-mscqr-verified",
  issued: "border-mscqr-issued/30 bg-mscqr-issued/12 text-mscqr-issued",
  printPending: "border-mscqr-pending/35 bg-mscqr-pending/12 text-mscqr-pending",
  printConfirmed: "border-mscqr-confirmed/35 bg-mscqr-confirmed/12 text-mscqr-confirmed",
  review: "border-mscqr-review/35 bg-mscqr-review/12 text-mscqr-review",
  duplicate: "border-mscqr-duplicate/35 bg-mscqr-duplicate/12 text-mscqr-duplicate",
  blocked: "border-mscqr-blocked/35 bg-mscqr-blocked/12 text-mscqr-blocked",
  replaced: "border-mscqr-replaced/35 bg-mscqr-replaced/12 text-mscqr-replaced",
  expired: "border-mscqr-expired/35 bg-mscqr-expired/12 text-mscqr-expired",
  degraded: "border-mscqr-degraded/35 bg-mscqr-degraded/12 text-mscqr-degraded",
  support: "border-mscqr-support/35 bg-mscqr-support/12 text-mscqr-support",
  audit: "border-mscqr-audit/35 bg-mscqr-audit/12 text-mscqr-audit",
};

const verificationToneByValue: Record<string, MscqrStatusTone> = {
  FIRST_SCAN: "verified",
  LEGIT_REPEAT: "verified",
  SUSPICIOUS_DUPLICATE: "review",
  BLOCKED_BY_SECURITY: "blocked",
  NOT_READY_FOR_CUSTOMER_USE: "printPending",
  NOT_FOUND: "neutral",
  SIGNED_LABEL_ACTIVE: "verified",
  MANUAL_RECORD_FOUND: "issued",
  LIMITED_PROVENANCE: "degraded",
  REVIEW_REQUIRED: "review",
  BLOCKED: "blocked",
  NOT_READY: "printPending",
  INTEGRITY_ERROR: "blocked",
  PRINTER_SETUP_ONLY: "printPending",
};

const printToneByValue: Record<string, MscqrStatusTone> = {
  PENDING: "printPending",
  SENT: "issued",
  PRINT_CONFIRMED: "printConfirmed",
  CONFIRMED: "printConfirmed",
  FAILED: "review",
  CANCELLED: "expired",
};

const toneIcons: Record<MscqrStatusTone, LucideIcon> = {
  neutral: CircleDashed,
  verified: ShieldCheck,
  issued: FileCheck2,
  printPending: CircleDashed,
  printConfirmed: PackageCheck,
  review: AlertTriangle,
  duplicate: AlertTriangle,
  blocked: Ban,
  replaced: FileCheck2,
  expired: CircleDashed,
  degraded: AlertTriangle,
  support: AlertTriangle,
  audit: CheckCircle2,
};

type StatusBadgeProps = {
  children: React.ReactNode;
  tone?: MscqrStatusTone;
  className?: string;
  pulse?: boolean;
};

export function StatusBadge({ children, tone = "neutral", className, pulse = false }: StatusBadgeProps) {
  const Icon = toneIcons[tone];

  return (
    <Badge
      className={cn(
        "inline-flex items-center gap-1.5 border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.14em] hover:bg-current/10",
        toneClasses[tone],
        className,
      )}
    >
      <span className="relative flex size-2">
        {pulse ? <span className="absolute inline-flex size-full animate-ping rounded-full bg-current opacity-30 motion-reduce:animate-none" /> : null}
        <span className="relative inline-flex size-2 rounded-full bg-current" />
      </span>
      <Icon className="size-3.5" />
      {children}
    </Badge>
  );
}

export function VerificationStateBadge({
  value,
  label,
  className,
}: {
  value?: string | null;
  label?: string;
  className?: string;
}) {
  const normalized = String(value || "").trim().toUpperCase();
  const tone = verificationToneByValue[normalized] || "neutral";
  const fallbackLabel = normalized ? normalized.replace(/_/g, " ").toLowerCase() : "Unknown";

  return (
    <StatusBadge tone={tone} pulse={tone === "review" || tone === "blocked"} className={className}>
      {label || fallbackLabel}
    </StatusBadge>
  );
}

export function PrintStateIndicator({
  value,
  label,
  className,
}: {
  value?: string | null;
  label?: string;
  className?: string;
}) {
  const normalized = String(value || "").trim().toUpperCase();
  const tone = printToneByValue[normalized] || (normalized.includes("CONFIRMED") ? "printConfirmed" : "neutral");

  return (
    <StatusBadge tone={tone} className={className}>
      {label || normalized.replace(/_/g, " ").toLowerCase() || "Print state unknown"}
    </StatusBadge>
  );
}

export type RiskLevel = "low" | "watch" | "elevated" | "high" | "blocked";

const riskClasses: Record<RiskLevel, string> = {
  low: "border-mscqr-risk-low/30 bg-mscqr-risk-low/12 text-mscqr-risk-low",
  watch: "border-mscqr-risk-watch/35 bg-mscqr-risk-watch/12 text-mscqr-risk-watch",
  elevated: "border-mscqr-risk-elevated/35 bg-mscqr-risk-elevated/12 text-mscqr-risk-elevated",
  high: "border-mscqr-risk-high/35 bg-mscqr-risk-high/12 text-mscqr-risk-high",
  blocked: "border-mscqr-risk-blocked/35 bg-mscqr-risk-blocked/12 text-mscqr-risk-blocked",
};

export function RiskSignal({
  level = "low",
  label,
  detail,
  className,
}: {
  level?: RiskLevel;
  label?: string;
  detail?: string;
  className?: string;
}) {
  return (
    <div className={cn("rounded-2xl border p-4", riskClasses[level], className)}>
      <div className="flex items-center justify-between gap-3">
        <p className="text-xs font-semibold uppercase tracking-[0.2em]">Risk signal</p>
        <span className="size-2.5 rounded-full bg-current shadow-[0_0_18px_currentColor]" />
      </div>
      <p className="mt-3 text-sm font-semibold text-mscqr-primary">{label || level}</p>
      {detail ? <p className="mt-2 text-sm leading-6 text-mscqr-secondary">{detail}</p> : null}
    </div>
  );
}
