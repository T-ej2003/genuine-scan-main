import React from "react";
import { cn } from "@/lib/utils";
import { PREMIUM_PALETTE } from "@/components/premium/palette";

type PremiumScanLoaderProps = {
  className?: string;
  srLabel?: string;
  compact?: boolean;
};

export function PremiumScanLoader({ className, srLabel = "Verifying secure QR scan", compact = false }: PremiumScanLoaderProps) {
  const boxSize = compact ? "h-28 w-28" : "h-40 w-40";
  const gridCells = compact ? 25 : 49;
  const gridClass = compact ? "grid-cols-5" : "grid-cols-7";

  return (
    <div className={cn("relative inline-flex items-center justify-center", className)} role="status" aria-live="polite">
      <span className="sr-only">{srLabel}</span>

      <div
        className={cn(
          "relative overflow-hidden rounded-[2rem] border shadow-[0_24px_44px_rgba(102,114,146,0.24)]",
          "bg-[radial-gradient(circle_at_20%_20%,rgba(241,227,221,0.7),rgba(255,255,255,0.95)_46%,rgba(188,202,214,0.52)_100%)]",
          boxSize
        )}
        style={{ borderColor: `${PREMIUM_PALETTE.steel}88` }}
        aria-hidden="true"
      >
        <div className="absolute inset-2 rounded-[1.4rem] border border-white/65 premium-grid-bg" />

        <div className={cn("absolute inset-4 grid gap-1.5", gridClass)}>
          {Array.from({ length: gridCells }).map((_, idx) => (
            <span
              key={idx}
              className="rounded-[5px] bg-[#8d9db6]/45 motion-reduce:opacity-50"
              style={{
                animation: "premium-pop-in 680ms ease-out both",
                animationDelay: `${(idx % 8) * 48}ms`,
              }}
            />
          ))}
        </div>

        <div
          className="absolute inset-x-3 top-1 h-16 rounded-full blur-md motion-reduce:hidden"
          style={{
            background: `linear-gradient(180deg, ${PREMIUM_PALETTE.anchor}dd 0%, ${PREMIUM_PALETTE.steel}88 50%, transparent 100%)`,
            animation: "premium-scan-beam 1.75s cubic-bezier(0.4, 0, 0.2, 1) infinite",
          }}
        />

        <div
          className="absolute inset-3 rounded-[1.5rem] border border-[#667292]/35 motion-reduce:hidden"
          style={{ animation: "premium-ring-pulse 2.6s ease-out infinite" }}
        />
      </div>

      <div
        className="pointer-events-none absolute h-[120%] w-[120%] rounded-full border border-[#8d9db6]/30"
        style={{ animation: "premium-ring-pulse 2.6s ease-out infinite 180ms" }}
        aria-hidden="true"
      />
    </div>
  );
}
