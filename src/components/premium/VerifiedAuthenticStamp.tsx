import React from "react";
import { ShieldCheck } from "lucide-react";
import { cn } from "@/lib/utils";
import { PREMIUM_PALETTE } from "@/components/premium/palette";

type VerifiedAuthenticStampProps = {
  className?: string;
};

export function VerifiedAuthenticStamp({ className }: VerifiedAuthenticStampProps) {
  return (
    <div className={cn("inline-flex premium-verified-seal", className)} role="img" aria-label="Verified authentic seal">
      <div
        className="relative inline-flex items-center gap-2 rounded-full border px-3 py-1.5 shadow-[0_10px_24px_rgba(33,90,72,0.22)]"
        style={{
          borderColor: "#63a993",
          background: `linear-gradient(140deg, rgba(99,169,147,0.2), ${PREMIUM_PALETTE.warm})`,
        }}
      >
        <ShieldCheck className="h-4 w-4 text-[#2e7d66]" />
        <span className="text-[11px] font-semibold uppercase tracking-[0.14em] text-[#285f51]">Authentic</span>
      </div>
    </div>
  );
}
