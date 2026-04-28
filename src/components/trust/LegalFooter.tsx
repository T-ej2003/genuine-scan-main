import { Link } from "react-router-dom";

import { cn } from "@/lib/utils";

type LegalFooterProps = {
  tone?: "light" | "dark";
  className?: string;
};

const footerLinks = [
  { href: "/platform", label: "Platform" },
  { href: "/solutions/manufacturers", label: "Manufacturers" },
  { href: "/industries", label: "Industries" },
  { href: "/verify", label: "Verify" },
  { href: "/help", label: "Help" },
  { href: "/blog", label: "Insights" },
  { href: "/privacy", label: "Privacy" },
  { href: "/terms", label: "Terms" },
  { href: "/cookies", label: "Cookies" },
  { href: "/trust", label: "Trust" },
  { href: "/request-access", label: "Request access" },
] as const;

export function LegalFooter({ tone = "light", className }: LegalFooterProps) {
  const isDark = tone === "dark";

  return (
    <footer
      className={cn(
        "border-t",
        isDark ? "border-white/10 bg-[#071019] text-slate-400" : "border-slate-200 bg-white text-slate-600",
        className,
      )}
    >
      <div className="mx-auto flex w-full max-w-7xl flex-col gap-4 px-4 py-6 text-sm md:flex-row md:items-center md:justify-between">
        <div className="max-w-2xl leading-6">
          MSCQR uses cookies and similar technologies for secure sign-in, verification continuity, support diagnostics,
          and product operation. Legal and policy wording should be reviewed by MSCQR administration before commercial use.
        </div>

        <div className="flex flex-wrap items-center gap-4">
          {footerLinks.map((item) => (
            <Link
              key={item.href}
              to={item.href}
              className={cn(
                "transition-colors hover:underline hover:underline-offset-4",
                isDark ? "hover:text-slate-200" : "text-slate-700 hover:text-slate-950",
              )}
            >
              {item.label}
            </Link>
          ))}
        </div>
      </div>
    </footer>
  );
}
