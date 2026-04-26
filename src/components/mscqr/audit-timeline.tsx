import { motion, useReducedMotion } from "framer-motion";

import { cn } from "@/lib/utils";

export type AuditTimelineItem = {
  label: string;
  value?: string;
  meta?: string;
  tone?: "neutral" | "verified" | "review" | "blocked" | "audit";
};

const dotClasses: Record<NonNullable<AuditTimelineItem["tone"]>, string> = {
  neutral: "bg-mscqr-muted",
  verified: "bg-mscqr-verified",
  review: "bg-mscqr-review",
  blocked: "bg-mscqr-blocked",
  audit: "bg-mscqr-audit",
};

export function AuditTimeline({
  items,
  className,
}: {
  items: readonly AuditTimelineItem[];
  className?: string;
}) {
  const reducedMotion = useReducedMotion();
  const canObserveViewport = typeof window !== "undefined" && "IntersectionObserver" in window;

  return (
    <div className={cn("flex flex-col gap-3", className)}>
      {items.map((item, index) => {
        const tone = item.tone || "audit";

        return (
          <motion.div
            key={`${item.label}-${index}`}
            initial={reducedMotion ? false : { opacity: 0, x: -8 }}
            animate={reducedMotion || !canObserveViewport ? { opacity: 1, x: 0 } : undefined}
            whileInView={!reducedMotion && canObserveViewport ? { opacity: 1, x: 0 } : undefined}
            viewport={!reducedMotion && canObserveViewport ? { once: true, margin: "-80px" } : undefined}
            transition={{ duration: 0.24, delay: reducedMotion || !canObserveViewport ? 0 : index * 0.045 }}
            className="grid grid-cols-[24px_1fr] gap-3"
          >
            <div className="flex flex-col items-center">
              <div className={cn("mt-1 size-2 rounded-full shadow-[0_0_18px_currentColor]", dotClasses[tone])} />
              {index < items.length - 1 ? <div className="mt-1 h-full min-h-6 w-px bg-mscqr-border" /> : null}
            </div>
            <div className="min-w-0 pb-1">
              <p className="text-sm font-medium text-mscqr-primary">{item.label}</p>
              {item.value ? <p className="mt-1 truncate font-mono text-xs text-mscqr-muted">{item.value}</p> : null}
              {item.meta ? <p className="mt-1 text-xs leading-5 text-mscqr-secondary">{item.meta}</p> : null}
            </div>
          </motion.div>
        );
      })}
    </div>
  );
}
