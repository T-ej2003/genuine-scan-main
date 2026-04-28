import { Link } from "react-router-dom";
import { LockKeyhole, ScanLine } from "lucide-react";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const publicNavItems = [
  { href: "/platform", label: "Platform" },
  { href: "/solutions/manufacturers", label: "Manufacturers" },
  { href: "/industries", label: "Industries" },
  { href: "/trust", label: "Trust" },
  { href: "/help/support", label: "Support" },
  { href: "/blog", label: "Insights" },
] as const;

type PublicHeaderProps = {
  className?: string;
};

export function PublicHeader({ className }: PublicHeaderProps) {
  return (
    <header
      className={cn(
        "sticky top-0 z-50 border-b border-white/10 bg-[#070b10]/88 text-slate-100 backdrop-blur-2xl",
        className,
      )}
    >
      <div className="mx-auto flex w-full max-w-7xl flex-col gap-4 px-4 py-4 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex items-center justify-between gap-4">
          <Link
            to="/"
            className="group flex min-w-0 items-center gap-3 rounded-2xl focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70 focus-visible:ring-offset-2 focus-visible:ring-offset-[#070b10]"
            aria-label="MSCQR home"
          >
            <span className="relative flex size-11 shrink-0 items-center justify-center overflow-hidden rounded-2xl border border-cyan-200/20 bg-[#0c151e] shadow-[0_0_34px_rgba(34,211,238,0.12)]">
              <img src="/brand/mscqr-mark.svg" alt="" className="size-7" aria-hidden="true" />
              <span className="absolute inset-x-2 bottom-1 h-px bg-cyan-200/40 transition-transform duration-300 group-hover:translate-x-1" />
            </span>
            <span className="min-w-0">
              <span className="block text-sm font-semibold tracking-[0.2em] text-white">MSCQR</span>
              <span className="block truncate text-xs text-slate-400">Product authentication infrastructure</span>
            </span>
          </Link>

          <div className="flex shrink-0 items-center gap-2 lg:hidden">
            <Button asChild size="sm" className="bg-none bg-cyan-200 text-slate-950 hover:bg-cyan-100">
              <Link to="/verify" aria-label="Verify a product">
                <ScanLine data-icon="inline-start" />
                Verify
              </Link>
            </Button>
            <Button
              asChild
              size="sm"
              variant="outline"
              className="border-white/10 bg-white/[0.04] text-slate-100 hover:bg-white/[0.08]"
            >
              <Link to="/login" aria-label="Platform access">
                <LockKeyhole data-icon="inline-start" />
                Access
              </Link>
            </Button>
          </div>
        </div>

        <nav className="flex items-center gap-1 overflow-x-auto pb-1 lg:justify-center lg:overflow-visible lg:pb-0">
          {publicNavItems.map((item) => (
            <Link
              key={item.href}
              to={item.href}
              className="shrink-0 rounded-full px-3 py-2 text-sm text-slate-400 transition-colors duration-200 hover:bg-white/[0.06] hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300/70 focus-visible:ring-offset-2 focus-visible:ring-offset-[#070b10]"
            >
              {item.label}
            </Link>
          ))}
        </nav>

        <div className="hidden items-center gap-2 lg:flex">
          <Button asChild className="bg-none bg-cyan-200 text-slate-950 hover:bg-cyan-100">
            <Link to="/verify">
              <ScanLine data-icon="inline-start" />
              Verify
            </Link>
          </Button>
          <Button
            asChild
            variant="outline"
            className="border-white/10 bg-white/[0.04] text-slate-100 hover:bg-white/[0.08]"
          >
            <Link to="/login">
              <LockKeyhole data-icon="inline-start" />
              Platform access
            </Link>
          </Button>
        </div>
      </div>
    </header>
  );
}
