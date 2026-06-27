import { Link } from "react-router-dom";
import { LockKeyhole, Menu } from "lucide-react";

import { BrandLockup } from "@/components/brand/BrandLockup";
import { MscqrLogo } from "@/components/brand/MscqrLogo";
import { Button } from "@/components/ui/button";
import { Sheet, SheetClose, SheetContent, SheetDescription, SheetHeader, SheetTitle, SheetTrigger } from "@/components/ui/sheet";
import { cn } from "@/lib/utils";

const publicNavItems = [
  { href: "/", label: "Home" },
  { href: "/about", label: "About" },
  { href: "/solutions/brands", label: "For Brands" },
  { href: "/solutions/garment-manufacturers", label: "For Manufacturers" },
  { href: "/how-scanning-works", label: "How Scanning Works" },
  { href: "/trust", label: "Trust & Security" },
  { href: "/contact", label: "Contact" },
] as const;

type PublicHeaderProps = {
  className?: string;
};

export function PublicHeader({ className }: PublicHeaderProps) {
  return (
    <header className={cn("sticky top-0 z-50 border-b border-border/80 bg-white/92 backdrop-blur-xl", className)}>
      <div className="mx-auto flex w-full max-w-7xl items-center justify-between gap-4 px-4 py-4 sm:px-6 lg:gap-6">
        <BrandLockup
          to="/"
          className="group flex min-w-0 max-w-[190px] shrink-0 items-center gap-3 rounded-2xl focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/70 focus-visible:ring-offset-2"
          markClassName="size-11"
          wordmarkClassName="h-4 max-w-[5.5rem]"
          ariaLabel="MSCQR home"
        />

        <nav className="hidden min-w-0 flex-1 items-center justify-center gap-1 lg:flex" aria-label="Public MSCQR navigation">
          {publicNavItems.map((item) => (
            <Link
              key={item.href}
              to={item.href}
              className="shrink-0 rounded-full px-3 py-2 text-center text-sm font-medium whitespace-nowrap text-muted-foreground transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/70 focus-visible:ring-offset-2 xl:px-3.5"
            >
              {item.label}
            </Link>
          ))}
        </nav>

        <div className="flex shrink-0 items-center justify-end gap-2">
          <Button asChild variant="ghost" size="icon" aria-label="Sign in">
            <Link to="/login">
              <LockKeyhole />
            </Link>
          </Button>

          <Sheet>
            <SheetTrigger asChild>
              <Button variant="outline" size="icon" className="lg:hidden" aria-label="Open public navigation menu">
                <Menu />
              </Button>
            </SheetTrigger>
            <SheetContent side="right" className="w-[min(22rem,calc(100vw-2rem))]">
              <SheetHeader>
                <SheetTitle>
                  <MscqrLogo variant="wordmark" alt="MSCQR" className="h-5 w-auto" />
                </SheetTitle>
                <SheetDescription>Public navigation</SheetDescription>
              </SheetHeader>
              <nav className="mt-8 grid gap-2" aria-label="Mobile public MSCQR navigation">
                {publicNavItems.map((item) => (
                  <SheetClose asChild key={item.href}>
                    <Link
                      to={item.href}
                      className="rounded-2xl px-4 py-3 text-base font-medium text-foreground transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/70 focus-visible:ring-offset-2"
                    >
                      {item.label}
                    </Link>
                  </SheetClose>
                ))}
              </nav>
              <div className="mt-8 border-t border-border pt-5">
                <SheetClose asChild>
                  <Link
                    to="/login"
                    className="inline-flex items-center gap-2 rounded-full px-3 py-2 text-sm font-medium text-muted-foreground transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/70 focus-visible:ring-offset-2"
                  >
                    <LockKeyhole className="size-4" />
                    Sign in
                  </Link>
                </SheetClose>
              </div>
            </SheetContent>
          </Sheet>
        </div>
      </div>
    </header>
  );
}
