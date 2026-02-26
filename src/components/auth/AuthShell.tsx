import { ReactNode } from "react";
import { BadgeCheck, Fingerprint, ShieldCheck, Sparkles } from "lucide-react";
import { ThemeModeButton } from "@/components/theme/ThemeModeButton";

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
    label: "Protected admin access",
    detail: "Role-aware controls and audit visibility built in.",
  },
  {
    icon: Fingerprint,
    label: "Verified operations",
    detail: "Secure workflows for QR allocation, tracking, and approvals.",
  },
  {
    icon: BadgeCheck,
    label: "Production-ready flow",
    detail: "Enterprise login, password reset, and tenant-safe experiences.",
  },
];

export function AuthShell({ title, description, sideTitle, sideDescription, children }: AuthShellProps) {
  return (
    <div className="relative min-h-screen overflow-hidden bg-[radial-gradient(circle_at_top,hsl(var(--primary)/0.08),transparent_45%),linear-gradient(180deg,hsl(var(--background)),hsl(var(--background)))] text-foreground dark:bg-[radial-gradient(circle_at_top,rgba(16,185,129,0.18),transparent_45%),linear-gradient(180deg,#07101d,#0a1321)]">
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute -left-24 top-[-8rem] h-72 w-72 rounded-full bg-emerald-400/15 blur-3xl dark:bg-emerald-400/20" />
        <div className="absolute right-[-6rem] top-24 h-80 w-80 rounded-full bg-amber-400/12 blur-3xl dark:bg-amber-400/15" />
        <div className="absolute bottom-[-8rem] left-1/3 h-80 w-80 rounded-full bg-cyan-400/8 blur-3xl dark:bg-cyan-400/10" />
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(15,23,42,0.06),transparent_40%)] dark:bg-[radial-gradient(circle_at_top,rgba(255,255,255,0.08),transparent_40%)]" />
      </div>

      <div className="absolute right-4 top-4 z-20 sm:right-6 sm:top-6 lg:right-10 lg:top-8">
        <ThemeModeButton compact />
      </div>

      <div className="relative mx-auto flex min-h-screen w-full max-w-7xl items-center p-4 sm:p-6 lg:p-10">
        <div className="grid w-full gap-6 lg:grid-cols-[1.1fr_0.9fr]">
          <section className="hidden lg:flex flex-col justify-between rounded-3xl border border-white/45 bg-white/65 p-8 shadow-[0_30px_70px_-50px_rgba(15,23,42,0.35)] backdrop-blur-xl dark:border-white/10 dark:bg-white/5 dark:shadow-none">
            <div className="space-y-8">
              <div className="flex items-center gap-3">
                <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-emerald-400/15 ring-1 ring-emerald-300/30">
                  <img src="/brand/authenticqr-mark.svg" alt="AuthenticQR logo" className="h-7 w-7" />
                </div>
                <div>
                  <div className="text-xl font-semibold tracking-tight text-slate-900 dark:text-white">AuthenticQR</div>
                  <div className="text-xs uppercase tracking-[0.22em] text-slate-500 dark:text-slate-400">Secure QR Operations</div>
                </div>
              </div>

              <div className="space-y-3">
                <div className="inline-flex items-center gap-2 rounded-full border border-amber-200/40 bg-amber-100/70 px-3 py-1 text-xs text-amber-900 dark:border-amber-200/20 dark:bg-amber-200/10 dark:text-amber-100">
                  <Sparkles className="h-3.5 w-3.5" />
                  Premium Admin Access
                </div>
                <h1 className="text-4xl font-semibold leading-tight text-slate-950 dark:text-white">{sideTitle}</h1>
                <p className="max-w-xl text-sm leading-6 text-slate-600 dark:text-slate-300">{sideDescription}</p>
              </div>

              <div className="grid gap-3">
                {trustItems.map((item) => (
                  <div
                    key={item.label}
                    className="rounded-2xl border border-white/50 bg-white/70 p-4 shadow-[inset_0_1px_0_rgba(255,255,255,0.4),0_14px_24px_-22px_rgba(15,23,42,0.3)] dark:border-white/10 dark:bg-slate-950/30 dark:shadow-[inset_0_1px_0_rgba(255,255,255,0.05)]"
                  >
                    <div className="flex items-start gap-3">
                      <div className="mt-0.5 rounded-xl bg-white/80 p-2 ring-1 ring-slate-200/80 dark:bg-white/5 dark:ring-white/10">
                        <item.icon className="h-4 w-4 text-emerald-600 dark:text-emerald-200" />
                      </div>
                      <div className="space-y-1">
                        <div className="text-sm font-medium text-slate-900 dark:text-white">{item.label}</div>
                        <div className="text-xs leading-5 text-slate-500 dark:text-slate-400">{item.detail}</div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="mt-6 flex items-center justify-between rounded-2xl border border-white/50 bg-white/60 px-4 py-3 text-xs text-slate-600 dark:border-white/10 dark:bg-white/5 dark:text-slate-300">
              <span>MSCQR secure access console</span>
              <span className="rounded-full bg-emerald-400/10 px-2 py-1 text-emerald-700 ring-1 ring-emerald-300/30 dark:text-emerald-200 dark:ring-emerald-300/20">
                Active safeguards
              </span>
            </div>
          </section>

          <section className="flex items-center">
            <div className="w-full rounded-3xl border border-white/55 bg-white/55 p-2 shadow-2xl backdrop-blur-xl dark:border-white/10 dark:bg-white/[0.04]">
              <div className="rounded-[1.25rem] border border-slate-200/70 bg-white text-slate-900 shadow-[0_24px_80px_rgba(5,15,30,0.16)] dark:border-white/10 dark:bg-slate-950/78 dark:text-slate-100 dark:shadow-[0_24px_80px_rgba(5,15,30,0.35)]">
                <div className="border-b border-slate-100 px-6 py-6 dark:border-white/10 sm:px-8">
                  <div className="flex items-center gap-3 lg:hidden">
                    <img src="/brand/authenticqr-mark.svg" alt="AuthenticQR logo" className="h-8 w-8" />
                    <div>
                      <div className="text-base font-semibold text-slate-900 dark:text-white">AuthenticQR</div>
                      <div className="text-xs text-slate-500 dark:text-slate-400">Secure QR Operations</div>
                    </div>
                  </div>
                  <div className="mt-4 lg:mt-0">
                    <h2 className="text-2xl font-semibold tracking-tight text-slate-900 dark:text-white">{title}</h2>
                    <p className="mt-1 text-sm leading-6 text-slate-500 dark:text-slate-400">{description}</p>
                  </div>
                </div>
                <div className="px-6 py-6 sm:px-8">{children}</div>
              </div>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
