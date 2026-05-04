import { ReactNode } from "react";
import { Link } from "react-router-dom";
import { BadgeCheck, Fingerprint, ShieldCheck, Sparkles } from "lucide-react";

import { MotionPanel } from "@/components/mscqr/motion";
import { StatusBadge } from "@/components/mscqr/status";

type AuthShellProps = {
  title: string;
  description: string;
  sideTitle: string;
  sideDescription: string;
  children: ReactNode;
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

export function AuthShell({ title, description, sideTitle, sideDescription, children }: AuthShellProps) {
  return (
    <div className="dark relative min-h-screen overflow-hidden bg-[radial-gradient(circle_at_15%_8%,rgba(34,211,238,0.14),transparent_30%),radial-gradient(circle_at_90%_18%,rgba(251,191,36,0.08),transparent_24%),linear-gradient(180deg,hsl(var(--mscqr-background)),hsl(var(--mscqr-background-soft)))] text-mscqr-primary">
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute inset-0 mscqr-public-grid opacity-60" />
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(255,255,255,0.06),transparent_40%)]" />
      </div>

      <div className="relative mx-auto flex min-h-screen w-full max-w-7xl items-center p-4 sm:p-6 lg:p-10">
        <div className="grid w-full gap-6 lg:grid-cols-[1.1fr_0.9fr]">
          <MotionPanel className="hidden lg:flex flex-col justify-between rounded-3xl border border-white/10 bg-mscqr-surface/78 p-8 shadow-[0_30px_90px_rgba(0,0,0,0.32)] backdrop-blur-xl">
            <div className="space-y-8">
              <div className="flex items-center gap-3">
                <div className="flex h-12 w-12 items-center justify-center rounded-2xl border border-cyan-200/20 bg-cyan-200/10">
                  <img src="/brand/mscqr-mark.svg" alt="MSCQR logo" className="h-7 w-7" />
                </div>
                <div>
                  <div className="text-xl font-semibold tracking-tight text-white">MSCQR</div>
                </div>
              </div>

              <div className="space-y-3">
                <div className="inline-flex items-center gap-2 rounded-full border border-amber-200/20 bg-amber-200/10 px-3 py-1 text-xs text-amber-100">
                  <Sparkles className="h-3.5 w-3.5" />
                  Operator workspace
                </div>
                <h1 className="text-4xl font-semibold leading-tight text-white">{sideTitle}</h1>
                <p className="max-w-xl text-sm leading-6 text-slate-300">{sideDescription}</p>
              </div>

              <div className="grid gap-3">
                {trustItems.map((item) => (
                  <div
                    key={item.label}
                    className="rounded-2xl border border-white/10 bg-[#05080c]/55 p-4 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]"
                  >
                    <div className="flex items-start gap-3">
                      <div className="mt-0.5 rounded-xl bg-white/5 p-2 ring-1 ring-white/10">
                        <item.icon className="h-4 w-4 text-cyan-200" />
                      </div>
                      <div className="space-y-1">
                        <div className="text-sm font-medium text-white">{item.label}</div>
                        <div className="text-xs leading-5 text-slate-400">{item.detail}</div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="mt-6 flex items-center justify-between rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-xs text-slate-300">
              <span className="font-semibold text-white">MSCQR</span>
              <StatusBadge tone="verified">Safeguards active</StatusBadge>
            </div>
          </MotionPanel>

          <section className="flex items-center">
            <MotionPanel className="w-full rounded-3xl border border-white/10 bg-white/[0.04] p-2 shadow-2xl backdrop-blur-xl">
              <div className="rounded-[1.25rem] border border-white/10 bg-mscqr-surface/92 text-mscqr-primary shadow-[0_24px_80px_rgba(5,15,30,0.35)]">
                <div className="border-b border-white/10 px-6 py-6 sm:px-8">
                  <div className="flex items-center gap-3 lg:hidden">
                    <img src="/brand/mscqr-mark.svg" alt="MSCQR logo" className="h-8 w-8" />
                    <div>
                      <div className="text-base font-semibold text-white">MSCQR</div>
                    </div>
                  </div>
                  <div className="mt-4 flex flex-col gap-4 lg:mt-0 sm:flex-row sm:items-start sm:justify-between">
                    <div>
                      <h2 className="text-2xl font-semibold tracking-tight text-white">{title}</h2>
                      <p className="mt-1 text-sm leading-6 text-slate-400">{description}</p>
                    </div>
                    <Link
                      to="/verify"
                      className="inline-flex shrink-0 items-center justify-center rounded-xl border border-cyan-200/20 bg-cyan-200/10 px-3 py-2 text-sm font-medium text-cyan-100 transition hover:bg-cyan-200/15 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-200/70"
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
