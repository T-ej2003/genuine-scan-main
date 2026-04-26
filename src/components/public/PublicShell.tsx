import { type ReactNode } from "react";

import { MotionPage } from "@/components/mscqr/motion";
import { LegalFooter } from "@/components/trust/LegalFooter";
import { PublicHeader } from "@/components/public/PublicHeader";
import { cn } from "@/lib/utils";

type PublicShellProps = {
  children: ReactNode;
  footer?: boolean;
  header?: boolean;
  className?: string;
};

export function PublicShell({ children, footer = true, header = true, className }: PublicShellProps) {
  return (
    <div className={cn("dark min-h-screen overflow-x-hidden bg-mscqr-background text-mscqr-primary", className)}>
      {header ? <PublicHeader /> : null}
      <MotionPage>{children}</MotionPage>
      {footer ? <LegalFooter tone="dark" className="bg-mscqr-background" /> : null}
    </div>
  );
}
