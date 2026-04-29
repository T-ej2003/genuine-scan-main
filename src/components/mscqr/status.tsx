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
  neutral: "border-slate-200 bg-slate-50 text-slate-700 dark:border-slate-700 dark:bg-slate-900/45 dark:text-slate-200",
  verified: "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-700/60 dark:bg-emerald-950/35 dark:text-emerald-200",
  issued: "border-blue-200 bg-blue-50 text-blue-700 dark:border-blue-700/60 dark:bg-blue-950/35 dark:text-blue-200",
  printPending: "border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-700/60 dark:bg-amber-950/35 dark:text-amber-200",
  printConfirmed: "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-700/60 dark:bg-emerald-950/35 dark:text-emerald-200",
  review: "border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-700/60 dark:bg-amber-950/35 dark:text-amber-200",
  duplicate: "border-orange-200 bg-orange-50 text-orange-800 dark:border-orange-700/60 dark:bg-orange-950/35 dark:text-orange-200",
  blocked: "border-red-200 bg-red-50 text-red-700 dark:border-red-700/60 dark:bg-red-950/35 dark:text-red-200",
  replaced: "border-moonlight-300 bg-moonlight-100 text-moonlight-900 dark:border-moonlight-400/60 dark:bg-moonlight-900/35 dark:text-moonlight-200",
  expired: "border-slate-200 bg-slate-50 text-slate-700 dark:border-slate-700 dark:bg-slate-900/45 dark:text-slate-200",
  degraded: "border-orange-200 bg-orange-50 text-orange-800 dark:border-orange-700/60 dark:bg-orange-950/35 dark:text-orange-200",
  support: "border-blue-200 bg-blue-50 text-blue-700 dark:border-blue-700/60 dark:bg-blue-950/35 dark:text-blue-200",
  audit: "border-moonlight-300 bg-moonlight-100 text-moonlight-900 dark:border-moonlight-400/60 dark:bg-moonlight-900/35 dark:text-moonlight-200",
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
        "inline-flex items-center gap-1.5 border px-2.5 py-1 text-xs font-medium leading-none tracking-normal hover:bg-current/10",
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
  low: "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-700/60 dark:bg-emerald-950/35 dark:text-emerald-200",
  watch: "border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-700/60 dark:bg-amber-950/35 dark:text-amber-200",
  elevated: "border-orange-200 bg-orange-50 text-orange-800 dark:border-orange-700/60 dark:bg-orange-950/35 dark:text-orange-200",
  high: "border-red-200 bg-red-50 text-red-700 dark:border-red-700/60 dark:bg-red-950/35 dark:text-red-200",
  blocked: "border-red-300 bg-red-50 text-red-800 dark:border-red-700/70 dark:bg-red-950/45 dark:text-red-200",
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
        <p className="text-sm font-medium">Scan risk</p>
        <span aria-hidden="true" className="size-2.5 rounded-full bg-current" />
      </div>
      <p className="mt-3 text-sm font-semibold text-foreground">{label || level}</p>
      {detail ? <p className="mt-2 text-sm leading-6 text-muted-foreground">{detail}</p> : null}
    </div>
  );
}
