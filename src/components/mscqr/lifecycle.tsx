import { CheckCircle2, CircleDashed } from "lucide-react";
import { motion, useReducedMotion } from "framer-motion";

import { cn } from "@/lib/utils";

export type LifecycleStepState = "complete" | "current" | "pending" | "review" | "blocked";

export type LifecycleStep = {
  label: string;
  title: string;
  body?: string;
  state?: LifecycleStepState;
};

const stateClasses: Record<LifecycleStepState, string> = {
  complete: "border-mscqr-confirmed/35 bg-mscqr-confirmed/12 text-mscqr-confirmed",
  current: "border-mscqr-accent/45 bg-mscqr-accent/14 text-mscqr-accent",
  pending: "border-mscqr-border bg-mscqr-surface-muted/55 text-mscqr-muted",
  review: "border-mscqr-review/45 bg-mscqr-review/12 text-mscqr-review",
  blocked: "border-mscqr-blocked/45 bg-mscqr-blocked/12 text-mscqr-blocked",
};

export function LabelLifecycleRail({
  steps,
  className,
  compact = false,
}: {
  steps: readonly LifecycleStep[];
  className?: string;
  compact?: boolean;
}) {
  const reducedMotion = useReducedMotion();
  const canObserveViewport = typeof window !== "undefined" && "IntersectionObserver" in window;

  return (
    <div className={cn("relative", className)}>
      <div className="absolute left-4 top-4 h-[calc(100%-2rem)] w-px bg-mscqr-border lg:left-0 lg:right-0 lg:top-5 lg:h-px lg:w-full" />
      <div className={cn("grid gap-5", compact ? "lg:grid-cols-5" : "lg:grid-cols-6")}>
        {steps.map((step, index) => {
          const state = step.state || "pending";
          const Icon = state === "complete" ? CheckCircle2 : CircleDashed;

          return (
            <motion.article
              key={`${step.label}-${index}`}
              initial={reducedMotion ? false : { opacity: 0, y: 8 }}
              animate={reducedMotion || !canObserveViewport ? { opacity: 1, y: 0 } : undefined}
              whileInView={!reducedMotion && canObserveViewport ? { opacity: 1, y: 0 } : undefined}
              viewport={!reducedMotion && canObserveViewport ? { once: true, margin: "-80px" } : undefined}
              transition={{ duration: 0.25, delay: reducedMotion || !canObserveViewport ? 0 : index * 0.045 }}
              className="relative pl-12 lg:pl-0 lg:pt-12"
            >
              <div
                className={cn(
                  "absolute left-0 top-0 flex size-9 items-center justify-center rounded-full border bg-mscqr-background text-xs font-semibold lg:top-0",
                  stateClasses[state],
                )}
              >
                {state === "current" && !reducedMotion ? (
                  <span className="absolute inline-flex size-full animate-ping rounded-full bg-current opacity-20" />
                ) : null}
                <Icon className="relative size-4" />
              </div>
              <p className="font-mono text-xs uppercase tracking-[0.2em] text-mscqr-accent/80">{step.label}</p>
              <h3 className="mt-2 text-sm font-semibold leading-6 text-mscqr-primary">{step.title}</h3>
              {step.body ? <p className="mt-2 text-sm leading-6 text-mscqr-secondary">{step.body}</p> : null}
            </motion.article>
          );
        })}
      </div>
    </div>
  );
}
