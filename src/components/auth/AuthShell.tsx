import { ReactNode } from "react";
import { Link } from "react-router-dom";
import { BadgeCheck, Fingerprint, ShieldCheck, Sparkles } from "lucide-react";

import { BrandLockup } from "@/components/brand/BrandLockup";
import { MscqrLogo } from "@/components/brand/MscqrLogo";
import { MotionPanel } from "@/components/mscqr/motion";
import { StatusBadge } from "@/components/mscqr/status";
import { cn } from "@/lib/utils";

type AuthShellProps = {
  title: string;
  description: string;
  sideTitle: string;
  sideDescription: string;
  children: ReactNode;
  variant?: "dark" | "light";
};

const trustItems = [
  {
    icon: ShieldCheck,
    label: "Protected operator access",
    detail: "Role-aware controls for manufacturers, licensees, and platform operators.",
  },
  {
    icon: Fingerprint,
    label: "Governed label operations",
    detail: "Access to issuance, controlled print, verification activity, and review workflows.",
  },
  {
    icon: BadgeCheck,
    label: "Audit-aware workspace",
    detail: "Sensitive actions remain connected to platform evidence and account context.",
  },
];

export function AuthShell({ title, description, sideTitle, sideDescription, children, variant = "dark" }: AuthShellProps) {
  const light = variant === "light";
  return (
    <div
      className={cn(
        "relative min-h-screen overflow-hidden text-mscqr-primary",
        light
          ? "bg-[linear-gradient(180deg,#f8fafc,#ffffff)]"
          : "dark bg-[radial-gradient(circle_at_15%_8%,rgba(34,211,238,0.14),transparent_30%),radial-gradient(circle_at_90%_18%,rgba(251,191,36,0.08),transparent_24%),linear-gradient(180deg,hsl(var(--mscqr-background)),hsl(var(--mscqr-background-soft)))]"
      )}
    >
      <div className={cn("pointer-events-none absolute inset-0", light ? "opacity-25" : "")}>
        <div className="absolute inset-0 mscqr-public-grid opacity-60" />
        <div className={cn("absolute inset-0", light ? "bg-[radial-gradient(circle_at_top,rgba(14,165,233,0.08),transparent_38%)]" : "bg-[radial-gradient(circle_at_top,rgba(255,255,255,0.06),transparent_40%)]")} />
      </div>

      <div className="relative mx-auto flex min-h-screen w-full max-w-7xl items-center p-4 sm:p-6 lg:p-10">
        <div className="grid w-full gap-6 lg:grid-cols-[1.1fr_0.9fr]">
          <MotionPanel className={cn("hidden lg:flex flex-col justify-between rounded-3xl border p-8 backdrop-blur-xl", light ? "border-slate-200 bg-white shadow-xl" : "border-white/10 bg-mscqr-surface/78 shadow-[0_30px_90px_rgba(0,0,0,0.32)]")}>
            <div className="space-y-8">
                <BrandLockup
	                  className="gap-3"
	                  markClassName={cn("h-12 w-12", light ? "border-slate-200 bg-slate-50" : "border-cyan-200/20 bg-cyan-200/10")}
	                  iconClassName="h-7 w-7"
	                  wordmarkClassName={cn("h-6 max-w-[8.5rem]", light ? "" : "invert")}
	                />

              <div className="space-y-3">
                <div className={cn("inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs", light ? "border-sky-200 bg-sky-50 text-sky-700" : "border-amber-200/20 bg-amber-200/10 text-amber-100")}>
                  <Sparkles className="h-3.5 w-3.5" />
                  Operator workspace
                </div>
                <h1 className={cn("text-4xl font-semibold leading-tight", light ? "text-slate-950" : "text-white")}>{sideTitle}</h1>
                <p className={cn("max-w-xl text-sm leading-6", light ? "text-slate-600" : "text-slate-300")}>{sideDescription}</p>
              </div>

              <div className="grid gap-3">
                {trustItems.map((item) => (
                  <div
                    key={item.label}
                    className={cn("rounded-2xl border p-4 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]", light ? "border-slate-200 bg-slate-50" : "border-white/10 bg-[#05080c]/55")}
                  >
                    <div className="flex items-start gap-3">
                      <div className={cn("mt-0.5 rounded-xl p-2 ring-1", light ? "bg-white ring-slate-200" : "bg-white/5 ring-white/10")}>
                        <item.icon className={cn("h-4 w-4", light ? "text-sky-700" : "text-cyan-200")} />
                      </div>
                      <div className="space-y-1">
                        <div className={cn("text-sm font-medium", light ? "text-slate-950" : "text-white")}>{item.label}</div>
                        <div className={cn("text-xs leading-5", light ? "text-slate-600" : "text-slate-400")}>{item.detail}</div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className={cn("mt-6 flex items-center justify-between rounded-2xl border px-4 py-3 text-xs", light ? "border-slate-200 bg-slate-50 text-slate-600" : "border-white/10 bg-white/5 text-slate-300")}>
	              <MscqrLogo variant="wordmark" decorative className={cn("h-4 w-auto", light ? "" : "invert")} />
              <StatusBadge tone="verified">Safeguards active</StatusBadge>
            </div>
          </MotionPanel>

          <section className="flex items-center">
            <MotionPanel className={cn("w-full rounded-3xl border p-2 shadow-2xl backdrop-blur-xl", light ? "border-slate-200 bg-white" : "border-white/10 bg-white/[0.04]")}>
              <div className={cn("rounded-[1.25rem] border text-mscqr-primary", light ? "border-slate-200 bg-white shadow-xl" : "border-white/10 bg-mscqr-surface/92 shadow-[0_24px_80px_rgba(5,15,30,0.35)]")}>
                <div className={cn("border-b px-6 py-6 sm:px-8", light ? "border-slate-200" : "border-white/10")}>
                  <BrandLockup
	                    className="gap-3 lg:hidden"
	                    markClassName="h-8 w-8 rounded-none border-0 bg-transparent"
	                    iconClassName="h-8 w-8"
	                    wordmarkClassName={cn("h-4 max-w-[6.5rem]", light ? "" : "invert")}
	                  />
                  <div className="mt-4 flex flex-col gap-4 lg:mt-0 sm:flex-row sm:items-start sm:justify-between">
                    <div>
                      <h2 className={cn("text-2xl font-semibold tracking-tight", light ? "text-slate-950" : "text-white")}>{title}</h2>
                      <p className={cn("mt-1 text-sm leading-6", light ? "text-slate-600" : "text-slate-400")}>{description}</p>
                    </div>
                    <Link
                      to="/verify"
                      className={cn(
                        "inline-flex shrink-0 items-center justify-center rounded-xl border px-3 py-2 text-sm font-medium transition focus-visible:outline-none focus-visible:ring-2",
                        light
                          ? "border-slate-300 bg-white text-slate-900 hover:bg-slate-50 focus-visible:ring-sky-500"
                          : "border-cyan-200/20 bg-cyan-200/10 text-cyan-100 hover:bg-cyan-200/15 focus-visible:ring-cyan-200/70"
                      )}
                    >
                      Verify a product
                    </Link>
                  </div>
                </div>
                <div className="px-6 py-6 sm:px-8">{children}</div>
              </div>
            </MotionPanel>
          </section>
        </div>
      </div>
    </div>
  );
}
