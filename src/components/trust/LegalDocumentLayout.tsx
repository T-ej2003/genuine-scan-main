import type { ComponentType, ReactNode } from "react";
import { Link } from "react-router-dom";
import { ArrowRight, CalendarDays, FileText, ShieldCheck, Tag } from "lucide-react";

import { LegalFooter } from "@/components/trust/LegalFooter";
import { PublicHeader } from "@/components/public/PublicHeader";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

type LegalIcon = ComponentType<{ className?: string }>;

export type LegalSection = {
  id: string;
  title: string;
  children: ReactNode;
};

type LegalLink = {
  to: string;
  label: string;
  icon?: LegalIcon;
};

type LegalAction = {
  label: string;
  onClick: () => void;
  icon?: LegalIcon;
};

type LegalDocumentLayoutProps = {
  title: string;
  tagline: string;
  summary: string;
  updatedAt: string;
  version?: string;
  sections: LegalSection[];
  primaryAction?: LegalAction;
  relatedLinks?: LegalLink[];
  children?: ReactNode;
};

export function LegalCallout({
  title,
  children,
  icon: Icon = ShieldCheck,
  tone = "lavender",
}: {
  title: string;
  children: ReactNode;
  icon?: LegalIcon;
  tone?: "lavender" | "amber" | "green";
}) {
  const toneClass = {
    lavender: "border-moonlight-200 bg-moonlight-50 text-moonlight-900",
    amber: "border-amber-200 bg-amber-50 text-amber-950",
    green: "border-emerald-200 bg-emerald-50 text-emerald-950",
  }[tone];

  return (
    <aside className={cn("my-6 rounded-lg border p-5", toneClass)}>
      <div className="flex gap-4">
        <span className="mt-0.5 flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-white/80 shadow-sm">
          <Icon className="h-5 w-5" />
        </span>
        <div className="min-w-0">
          <h3 className="text-base font-semibold tracking-tight">{title}</h3>
          <div className="mt-2 text-sm leading-7 text-slate-700">{children}</div>
        </div>
      </div>
    </aside>
  );
}

export function LegalDocumentLayout({
  title,
  tagline,
  summary,
  updatedAt,
  version,
  sections,
  primaryAction,
  relatedLinks = [],
  children,
}: LegalDocumentLayoutProps) {
  return (
    <div className="min-h-screen bg-[hsl(var(--mscqr-background))] text-slate-900">
      <PublicHeader />

      <main>
        <section className="border-b border-slate-200 bg-white">
          <div className="mx-auto grid w-full max-w-7xl gap-10 px-4 py-12 md:py-16 lg:grid-cols-[minmax(0,1fr)_360px] lg:items-center">
            <div className="max-w-3xl">
              <div className="inline-flex items-center gap-2 rounded-lg border border-moonlight-200 bg-moonlight-50 px-3 py-1.5 text-xs font-semibold uppercase tracking-[0.16em] text-moonlight-800">
                <ShieldCheck className="h-3.5 w-3.5" />
                Legal
              </div>
              <h1 className="mt-5 text-4xl font-semibold tracking-tight text-slate-950 md:text-6xl">{title}</h1>
              <p className="mt-4 text-xl font-medium text-primary">{tagline}</p>
              <p className="mt-4 max-w-2xl text-base leading-7 text-slate-600 md:text-lg md:leading-8">{summary}</p>

              <div className="mt-7 flex flex-wrap items-center gap-4 text-sm text-slate-600">
                <span className="inline-flex items-center gap-2">
                  <CalendarDays className="h-4 w-4 text-slate-400" />
                  Last updated: {updatedAt}
                </span>
                {version ? (
                  <span className="inline-flex items-center gap-2">
                    <Tag className="h-4 w-4 text-slate-400" />
                    Version {version}
                  </span>
                ) : null}
              </div>

              <div className="mt-8 flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center">
                {primaryAction ? (
                  <Button type="button" onClick={primaryAction.onClick} className="w-full sm:w-auto">
                    {primaryAction.icon ? <primaryAction.icon /> : null}
                    {primaryAction.label}
                    <ArrowRight />
                  </Button>
                ) : null}
                {relatedLinks.map((item) => {
                  const Icon = item.icon ?? FileText;
                  return (
                    <Button key={item.to} asChild variant="outline" className="w-full bg-white sm:w-auto">
                      <Link to={item.to}>
                        <Icon />
                        {item.label}
                      </Link>
                    </Button>
                  );
                })}
              </div>
            </div>

            <div className="hidden rounded-lg border border-moonlight-200 bg-moonlight-50/70 p-8 shadow-sm lg:block">
              <div className="mx-auto flex h-44 w-44 items-center justify-center rounded-lg border border-moonlight-200 bg-white">
                <ShieldCheck className="h-20 w-20 text-primary" />
              </div>
              <p className="mt-6 text-center text-sm leading-6 text-slate-600">
                Clear public notices for privacy, cookies, responsible product verification, and user rights.
              </p>
            </div>
          </div>
        </section>

        <section className="mx-auto grid w-full max-w-7xl gap-8 px-4 py-10 lg:grid-cols-[260px_minmax(0,1fr)] lg:py-12">
          <aside className="lg:sticky lg:top-28 lg:self-start">
            <details className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm lg:hidden">
              <summary className="cursor-pointer text-sm font-semibold text-slate-950">On this page</summary>
              <nav aria-label={`${title} sections`} className="mt-4 grid gap-1">
                {sections.map((section, index) => (
                  <a key={section.id} href={`#${section.id}`} className="rounded-md px-3 py-2 text-sm text-slate-600 hover:bg-moonlight-50 hover:text-slate-950">
                    {index + 1}. {section.title}
                  </a>
                ))}
              </nav>
            </details>

            <nav aria-label={`${title} sections`} className="hidden rounded-lg border border-slate-200 bg-white p-4 shadow-sm lg:block">
              <p className="px-3 text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">On this page</p>
              <div className="mt-3 grid gap-1">
                {sections.map((section, index) => (
                  <a key={section.id} href={`#${section.id}`} className="rounded-md px-3 py-2 text-sm leading-5 text-slate-600 transition-colors hover:bg-moonlight-50 hover:text-slate-950">
                    {index + 1}. {section.title}
                  </a>
                ))}
              </div>
            </nav>
          </aside>

          <div className="min-w-0">
            <div className="space-y-5">
              {sections.map((section, index) => (
                <section key={section.id} id={section.id} className="scroll-mt-28 rounded-lg border border-slate-200 bg-white p-6 shadow-sm md:p-8">
                  <h2 className="text-2xl font-semibold tracking-tight text-slate-950">
                    {index + 1}. {section.title}
                  </h2>
                  <div className="mt-5 space-y-4 overflow-x-auto text-base leading-7 text-slate-700 [&_a]:font-medium [&_a]:text-primary [&_a]:underline [&_a]:underline-offset-4 [&_code]:rounded [&_code]:bg-slate-100 [&_code]:px-1.5 [&_code]:py-0.5 [&_code]:text-sm [&_li]:pl-1 [&_table]:min-w-[720px] [&_table]:border-collapse [&_table]:text-sm [&_td]:border-t [&_td]:border-slate-200 [&_td]:p-3 [&_td]:align-top [&_th]:border-b [&_th]:border-slate-300 [&_th]:p-3 [&_th]:text-left [&_thead]:text-slate-950 [&_ul]:list-disc [&_ul]:space-y-2 [&_ul]:pl-5">
                    {section.children}
                  </div>
                </section>
              ))}
            </div>
            {children ? <div className="mt-6">{children}</div> : null}
          </div>
        </section>
      </main>

      <LegalFooter />
    </div>
  );
}
