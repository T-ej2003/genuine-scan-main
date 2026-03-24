import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

type PagePatternProps = {
  title: string;
  description?: string;
  actions?: ReactNode;
  filters?: ReactNode;
  children: ReactNode;
  className?: string;
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
  actions,
  filters,
  children,
  className,
}: PagePatternProps) {
  return (
    <section className={cn("space-y-6", className)}>
      <header className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div className="space-y-2">
          <h1 className="text-3xl font-bold tracking-tight">{title}</h1>
          {description ? <p className="max-w-3xl text-sm text-muted-foreground">{description}</p> : null}
        </div>
        {actions ? <div className="flex flex-wrap gap-2">{actions}</div> : null}
      </header>
      {filters ? (
        <div className="rounded-xl border bg-card p-4 shadow-sm">
          {filters}
        </div>
      ) : null}
      <div className="space-y-6">{children}</div>
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
