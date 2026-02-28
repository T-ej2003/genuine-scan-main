import React from "react";
import { cn } from "@/lib/utils";

type BlockProps = {
  className?: string;
};

export function PremiumSkeletonBlock({ className }: BlockProps) {
  return (
    <div
      aria-hidden="true"
      className={cn("premium-shimmer rounded-xl bg-[#bccad6]/45", className)}
    />
  );
}

export function PremiumTableSkeleton({ rows = 6 }: { rows?: number }) {
  return (
    <div className="space-y-2">
      <PremiumSkeletonBlock className="h-10 w-full rounded-2xl" />
      {Array.from({ length: rows }).map((_, idx) => (
        <PremiumSkeletonBlock key={idx} className="h-12 w-full rounded-xl" />
      ))}
    </div>
  );
}

export function PremiumChartSkeleton() {
  return (
    <div className="rounded-2xl border border-[#8d9db64f] bg-white/90 p-4">
      <PremiumSkeletonBlock className="h-5 w-48" />
      <PremiumSkeletonBlock className="mt-3 h-56 w-full rounded-2xl" />
      <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
        {Array.from({ length: 4 }).map((_, idx) => (
          <PremiumSkeletonBlock key={idx} className="h-12 rounded-xl" />
        ))}
      </div>
    </div>
  );
}
