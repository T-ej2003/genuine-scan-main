import type { ReactNode } from "react";

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
    <section className={cn("mx-auto w-full max-w-7xl space-y-6", className)}>
      <header className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div className="space-y-2">
          {eyebrow ? <div className="text-xs font-semibold uppercase tracking-[0.16em] text-muted-foreground">{eyebrow}</div> : null}
          <h1 className="text-3xl font-bold tracking-tight">{title}</h1>
          {description ? <p className="max-w-3xl text-sm text-muted-foreground">{description}</p> : null}
        </div>
        {actions ? <div className="flex flex-wrap gap-2">{actions}</div> : null}
      </header>
      {filters ? (
        <div className="rounded-2xl border bg-card p-4 shadow-sm">
          {filters}
        </div>
      ) : null}
      <div className={cn("space-y-6", contentClassName)}>{children}</div>
    </section>
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
    <section className={cn("rounded-2xl border bg-card p-6 shadow-sm", className)}>
      <div className="flex flex-col gap-3 border-b pb-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="space-y-1">
          <h2 className="text-lg font-semibold text-foreground">{title}</h2>
          {description ? <p className="max-w-3xl text-sm text-muted-foreground">{description}</p> : null}
        </div>
        {action ? <div className="flex shrink-0 flex-wrap gap-2">{action}</div> : null}
      </div>
      <div className="pt-4">{children}</div>
    </section>
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
    <div className={cn("rounded-2xl border border-dashed bg-muted/20 px-6 py-10 text-center", className)}>
      <div className="mx-auto max-w-xl space-y-3">
        <h3 className="text-lg font-semibold text-foreground">{title}</h3>
        <p className="text-sm text-muted-foreground">{description}</p>
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
