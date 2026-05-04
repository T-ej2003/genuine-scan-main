import { Link } from "react-router-dom";
import { LockKeyhole, ScanLine } from "lucide-react";

import { BrandLockup } from "@/components/brand/BrandLockup";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const publicNavItems = [
  { href: "/", label: "Home" },
  { href: "/solutions/brands", label: "For Brands" },
  { href: "/solutions/garment-manufacturers", label: "For Manufacturers" },
  { href: "/how-scanning-works", label: "How Scanning Works" },
  { href: "/trust", label: "Trust & Security" },
  { href: "/request-access", label: "Request Access" },
  { href: "/verify", label: "Verify Product" },
] as const;

type PublicHeaderProps = {
  className?: string;
};

export function PublicHeader({ className }: PublicHeaderProps) {
  return (
    <header className={cn("sticky top-0 z-50 border-b border-border/80 bg-white/92 backdrop-blur-xl", className)}>
      <div className="mx-auto flex w-full max-w-7xl flex-col gap-4 px-4 py-4 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex items-center justify-between gap-4">
          <BrandLockup
            to="/"
            className="group flex min-w-0 items-center gap-3 rounded-2xl focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/70 focus-visible:ring-offset-2"
            markClassName="size-11"
            textClassName="text-sm tracking-normal text-foreground"
            ariaLabel="MSCQR home"
          />

          <div className="flex shrink-0 items-center gap-2 lg:hidden">
            <Button asChild size="sm">
              <Link to="/request-access">Request Access</Link>
            </Button>
            <Button asChild size="sm" variant="outline">
              <Link to="/verify" aria-label="Verify Product">
                <ScanLine data-icon="inline-start" />
                Verify
              </Link>
            </Button>
          </div>
        </div>

        <nav className="flex items-center gap-1 overflow-x-auto pb-1 lg:justify-center lg:overflow-visible lg:pb-0">
          {publicNavItems.map((item) => (
            <Link
              key={item.href}
              to={item.href}
              className="shrink-0 rounded-full px-3 py-2 text-sm font-medium text-muted-foreground transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/70 focus-visible:ring-offset-2"
            >
              {item.label}
            </Link>
          ))}
        </nav>

        <div className="hidden items-center gap-2 lg:flex">
          <Button asChild>
            <Link to="/request-access">Request Access</Link>
          </Button>
          <Button asChild variant="outline">
            <Link to="/verify">
              <ScanLine data-icon="inline-start" />
              Verify Product
            </Link>
          </Button>
          <Button asChild variant="ghost" size="icon" aria-label="Sign in">
            <Link to="/login">
              <LockKeyhole />
            </Link>
          </Button>
        </div>
      </div>
    </header>
  );
}
