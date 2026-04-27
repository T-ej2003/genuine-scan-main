import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { ShieldCheck } from "lucide-react";

import { LegalFooter } from "@/components/trust/LegalFooter";

type LegalDocumentLayoutProps = {
  title: string;
  summary: string;
  updatedAt: string;
  children: ReactNode;
};

export function LegalDocumentLayout({ title, summary, updatedAt, children }: LegalDocumentLayoutProps) {
  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <header className="border-b border-slate-200 bg-white/90 backdrop-blur">
        <div className="mx-auto flex w-full max-w-5xl items-center justify-between gap-4 px-4 py-4">
          <Link to="/" className="flex items-center gap-3">
            <span className="inline-flex h-10 w-10 items-center justify-center rounded-2xl bg-slate-950 text-white">
              <ShieldCheck className="h-5 w-5" />
            </span>
            <div>
              <div className="text-sm font-semibold tracking-[0.18em] text-slate-950">MSCQR</div>
              <div className="text-xs text-slate-500">Legal and privacy surface</div>
            </div>
          </Link>
          <div className="text-xs uppercase tracking-[0.18em] text-slate-500">MSCQR policy</div>
        </div>
      </header>

      <main className="mx-auto w-full max-w-5xl px-4 py-10">
        <div className="space-y-4">
          <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Last updated {updatedAt}</p>
          <h1 className="text-4xl font-semibold tracking-tight text-slate-950">{title}</h1>
          <p className="max-w-3xl text-base leading-7 text-slate-600">{summary}</p>
        </div>

        <div className="prose prose-slate mt-8 max-w-none prose-p:leading-7 prose-li:leading-7">{children}</div>
      </main>

      <LegalFooter />
    </div>
  );
}
