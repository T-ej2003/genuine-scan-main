import { AlertTriangle, CircleDashed, Loader2 } from "lucide-react";
import type { LucideIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

type StateAction = {
  label: string;
  onClick?: () => void;
  href?: string;
};

type FeedbackStateProps = {
  title: string;
  description: string;
  icon?: LucideIcon;
  action?: StateAction;
  className?: string;
  tone?: "neutral" | "error" | "loading";
};

export function EmptyState({ icon = CircleDashed, ...props }: Omit<FeedbackStateProps, "tone">) {
  return <FeedbackState icon={icon} tone="neutral" {...props} />;
}

export function ErrorState({ icon = AlertTriangle, ...props }: Omit<FeedbackStateProps, "tone">) {
  return <FeedbackState icon={icon} tone="error" {...props} />;
}

export function LoadingState({
  title = "Loading MSCQR state",
  description = "Checking the governed registry and current workspace context.",
  className,
}: Partial<Pick<FeedbackStateProps, "title" | "description" | "className">>) {
  return (
    <FeedbackState
      title={title}
      description={description}
      icon={Loader2}
      tone="loading"
      className={className}
    />
  );
}

function FeedbackState({ title, description, icon: Icon = CircleDashed, action, className, tone = "neutral" }: FeedbackStateProps) {
  return (
    <div
      className={cn(
        "rounded-[1.75rem] border bg-mscqr-surface/80 p-6 text-mscqr-primary",
        tone === "error" ? "border-mscqr-blocked/30" : "border-mscqr-border",
        className,
      )}
    >
      <div
        className={cn(
          "flex size-11 items-center justify-center rounded-2xl border",
          tone === "error"
            ? "border-mscqr-blocked/30 bg-mscqr-blocked/10 text-mscqr-blocked"
            : "border-mscqr-accent/25 bg-mscqr-accent/10 text-mscqr-accent",
        )}
      >
        <Icon className={cn("size-5", tone === "loading" && "animate-spin motion-reduce:animate-none")} />
      </div>
      <h3 className="mt-5 text-lg font-semibold">{title}</h3>
      <p className="mt-2 max-w-xl text-sm leading-7 text-mscqr-secondary">{description}</p>
      {action ? (
        <div className="mt-5">
          {action.href ? (
            <Button asChild variant="outline">
              <a href={action.href}>{action.label}</a>
            </Button>
          ) : (
            <Button variant="outline" onClick={action.onClick}>
              {action.label}
            </Button>
          )}
        </div>
      ) : null}
    </div>
  );
}
