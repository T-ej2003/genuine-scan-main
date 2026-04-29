import type { ReactNode } from "react";

import { MotionPage, MotionPanel } from "@/components/mscqr/motion";
import { cn } from "@/lib/utils";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";

type PagePatternProps = {
  title: string;
  description?: string;
  eyebrow?: string;
  actions?: ReactNode;
  filters?: ReactNode;
  children: ReactNode;
  className?: string;
  contentClassName?: string;
};

type WorkflowModalPatternProps = {
  title: string;
  description?: string;
  children: ReactNode;
  footer?: ReactNode;
  className?: string;
};

export function DashboardPagePattern({
  title,
  description,
  eyebrow,
  actions,
  filters,
  children,
  className,
  contentClassName,
}: PagePatternProps) {
  return (
    <MotionPage className={cn("mx-auto w-full max-w-7xl space-y-6", className)}>
      <header className="overflow-hidden rounded-2xl border border-mscqr-border bg-mscqr-surface px-5 py-5 shadow-sm sm:px-7 sm:py-6">
        <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
          <div className="space-y-3">
            {eyebrow ? (
              <div className="inline-flex rounded-full border border-mscqr-accent/20 bg-mscqr-accent-soft px-3 py-1 text-sm font-medium text-mscqr-accent">
                {eyebrow}
              </div>
            ) : null}
            <div className="space-y-2">
              <h1 className="text-3xl font-semibold tracking-normal text-mscqr-primary sm:text-[2.1rem]">{title}</h1>
              {description ? <p className="max-w-3xl text-sm leading-6 text-mscqr-secondary">{description}</p> : null}
            </div>
          </div>
          {actions ? <div className="flex flex-wrap gap-2 lg:justify-end">{actions}</div> : null}
        </div>
      </header>
      {filters ? (
        <MotionPanel className="rounded-2xl border border-mscqr-border bg-mscqr-surface p-4 shadow-sm">
          {filters}
        </MotionPanel>
      ) : null}
      <div className={cn("space-y-6", contentClassName)}>{children}</div>
    </MotionPage>
  );
}

export function DataTablePagePattern(props: PagePatternProps) {
  return <DashboardPagePattern {...props} />;
}

export function DetailPagePattern(props: PagePatternProps) {
  return <DashboardPagePattern {...props} />;
}

export function SettingsPagePattern(props: PagePatternProps) {
  return <DashboardPagePattern {...props} />;
}

export function WorkflowModalPattern({
  title,
  description,
  children,
  footer,
  className,
}: WorkflowModalPatternProps) {
  return (
    <section className={cn("space-y-4", className)}>
      <header className="space-y-1">
        <h2 className="text-lg font-semibold">{title}</h2>
        {description ? <p className="text-sm text-muted-foreground">{description}</p> : null}
      </header>
      <div className="space-y-4">{children}</div>
      {footer ? <footer className="flex justify-end gap-2 pt-2">{footer}</footer> : null}
    </section>
  );
}

export function PageSection({
  title,
  description,
  action,
  children,
  className,
}: {
  title: string;
  description?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <MotionPanel className={cn("rounded-2xl border border-mscqr-border bg-mscqr-surface p-6 shadow-sm", className)}>
      <div className="flex flex-col gap-3 border-b border-mscqr-border pb-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="space-y-1">
          <h2 className="text-lg font-semibold text-mscqr-primary">{title}</h2>
          {description ? <p className="max-w-3xl text-sm leading-6 text-mscqr-secondary">{description}</p> : null}
        </div>
        {action ? <div className="flex shrink-0 flex-wrap gap-2">{action}</div> : null}
      </div>
      <div className="pt-4">{children}</div>
    </MotionPanel>
  );
}

export function PageEmptyState({
  title,
  description,
  actionLabel,
  onAction,
  className,
}: {
  title: string;
  description: string;
  actionLabel?: string;
  onAction?: () => void;
  className?: string;
}) {
  return (
    <div className={cn("rounded-2xl border border-dashed border-mscqr-border bg-mscqr-surface-muted/35 px-6 py-10 text-center", className)}>
      <div className="mx-auto max-w-xl space-y-3">
        <h3 className="text-lg font-semibold text-mscqr-primary">{title}</h3>
        <p className="text-sm leading-6 text-mscqr-secondary">{description}</p>
        {actionLabel && onAction ? (
          <div className="pt-1">
            <Button onClick={onAction}>{actionLabel}</Button>
          </div>
        ) : null}
      </div>
    </div>
  );
}

export function PageInlineNotice({
  title,
  description,
  variant = "default",
  className,
}: {
  title: string;
  description: string;
  variant?: "default" | "destructive";
  className?: string;
}) {
  return (
    <Alert variant={variant} className={className}>
      <AlertTitle>{title}</AlertTitle>
      <AlertDescription>{description}</AlertDescription>
    </Alert>
  );
}
