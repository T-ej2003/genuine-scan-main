import React, { useMemo } from "react";
import { cn } from "@/lib/utils";
import { PREMIUM_PALETTE } from "@/components/premium/palette";

type VerificationClassification =
  | "FIRST_SCAN"
  | "LEGIT_REPEAT"
  | "SUSPICIOUS_DUPLICATE"
  | "BLOCKED_BY_SECURITY"
  | "NOT_READY_FOR_CUSTOMER_USE";

type ConfidenceSignalInput = {
  classification: VerificationClassification;
  totalScans?: number;
  distinctDeviceCount24h?: number | null;
  recentScanCount10m?: number | null;
  distinctCountryCount24h?: number | null;
  warningMessage?: string | null;
};

const clamp = (value: number, min: number, max: number) => Math.min(max, Math.max(min, value));

export const deriveVerificationConfidence = (input: ConfidenceSignalInput) => {
  const byClass: Record<VerificationClassification, number> = {
    FIRST_SCAN: 95,
    LEGIT_REPEAT: 88,
    SUSPICIOUS_DUPLICATE: 42,
    BLOCKED_BY_SECURITY: 8,
    NOT_READY_FOR_CUSTOMER_USE: 26,
  };

  let score = byClass[input.classification];

  if (input.classification === "LEGIT_REPEAT") {
    score -= Math.min(4, Math.max(0, (input.totalScans || 0) - 1));
  }

  score -= Math.min(16, Number(input.distinctDeviceCount24h || 0) * 3);
  score -= Math.min(18, Number(input.recentScanCount10m || 0) * 2);
  score -= Math.min(16, Number(input.distinctCountryCount24h || 0) * 8);
  if (input.warningMessage) score -= 8;

  return clamp(Math.round(score), 3, 99);
};

const toTier = (score: number) => {
  if (score >= 85) return { label: "High trust", color: "#4c9f87", bg: "rgba(76,159,135,0.14)" };
  if (score >= 60) return { label: "Moderate trust", color: PREMIUM_PALETTE.anchor, bg: "rgba(102,114,146,0.16)" };
  if (score >= 35) return { label: "Elevated risk", color: "#b47b45", bg: "rgba(241,227,221,0.62)" };
  return { label: "Critical risk", color: "#8f2d56", bg: "rgba(241,227,221,0.82)" };
};

type VerificationConfidenceMeterProps = {
  classification: VerificationClassification;
  totalScans?: number;
  distinctDeviceCount24h?: number | null;
  recentScanCount10m?: number | null;
  distinctCountryCount24h?: number | null;
  warningMessage?: string | null;
  className?: string;
};

export function VerificationConfidenceMeter(props: VerificationConfidenceMeterProps) {
  const score = useMemo(
    () =>
      deriveVerificationConfidence({
        classification: props.classification,
        totalScans: props.totalScans,
        distinctDeviceCount24h: props.distinctDeviceCount24h,
        recentScanCount10m: props.recentScanCount10m,
        distinctCountryCount24h: props.distinctCountryCount24h,
        warningMessage: props.warningMessage,
      }),
    [
      props.classification,
      props.totalScans,
      props.distinctDeviceCount24h,
      props.recentScanCount10m,
      props.distinctCountryCount24h,
      props.warningMessage,
    ]
  );

  const tier = toTier(score);
  const progress = clamp(score, 0, 100);

  return (
    <div
      className={cn("rounded-2xl border p-3 shadow-sm premium-pop-in", props.className)}
      style={{ borderColor: `${PREMIUM_PALETTE.steel}7a`, background: "rgba(255,255,255,0.9)" }}
    >
      <div className="flex items-center gap-3">
        <div className="relative h-20 w-20 shrink-0">
          <div
            className="absolute inset-0 rounded-full"
            style={{
              background: `conic-gradient(${tier.color} ${progress * 3.6}deg, rgba(188,202,214,0.35) ${progress * 3.6}deg)`,
            }}
            aria-hidden="true"
          />
          <div className="absolute inset-[7px] rounded-full border border-white/90 bg-white/95" aria-hidden="true" />
          <div className="absolute inset-0 flex items-center justify-center">
            <span className="text-lg font-semibold" style={{ color: tier.color }}>
              {score}
            </span>
          </div>
        </div>

        <div className="min-w-0">
          <p className="text-[11px] uppercase tracking-[0.14em] text-slate-500">Confidence</p>
          <p
            className="mt-1 inline-flex rounded-full px-2.5 py-1 text-xs font-semibold"
            style={{ color: tier.color, backgroundColor: tier.bg }}
          >
            {tier.label}
          </p>
        </div>
      </div>
    </div>
  );
}
