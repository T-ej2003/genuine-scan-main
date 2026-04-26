import type { ReactNode } from "react";

import { MotionPanel } from "@/components/mscqr/motion";
import { cn } from "@/lib/utils";

type OperationalTableShellProps = {
  title?: string;
  description?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  contentClassName?: string;
};

export function OperationalTableShell({
  title,
  description,
  actions,
  children,
  className,
  contentClassName,
}: OperationalTableShellProps) {
  return (
    <MotionPanel className={cn("overflow-hidden rounded-[1.6rem] border border-mscqr-border bg-mscqr-surface/95 shadow-[0_24px_56px_-48px_rgba(15,23,42,0.65)]", className)}>
      {(title || description || actions) ? (
        <div className="flex flex-col gap-3 border-b border-mscqr-border bg-mscqr-surface-elevated/70 px-4 py-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            {title ? <h2 className="text-base font-semibold text-mscqr-primary">{title}</h2> : null}
            {description ? <p className="mt-1 text-sm leading-6 text-mscqr-secondary">{description}</p> : null}
          </div>
          {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
        </div>
      ) : null}
      <div className={cn("overflow-x-auto", contentClassName)}>{children}</div>
    </MotionPanel>
  );
}
