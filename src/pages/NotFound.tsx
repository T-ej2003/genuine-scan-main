import React from "react";
import { Link, useLocation } from "react-router-dom";
import { ArrowRight, LifeBuoy, ScanLine, ShieldCheck } from "lucide-react";

import { Button } from "@/components/ui/button";
import { LegalFooter } from "@/components/trust/LegalFooter";

export default function NotFound() {
  const location = useLocation();

  return (
    <div className="min-h-screen bg-slate-50">
      <div className="mx-auto flex min-h-[calc(100vh-88px)] w-full max-w-5xl items-center px-6 py-12">
        <div className="grid gap-10 md:grid-cols-[1.1fr_0.9fr] md:items-center">
          <div className="space-y-6">
            <div className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1 text-xs uppercase tracking-[0.18em] text-slate-500">
              <ShieldCheck className="h-3.5 w-3.5 text-emerald-600" />
              MSCQR route recovery
            </div>
            <div className="space-y-3">
              <p className="text-sm uppercase tracking-[0.2em] text-slate-500">404</p>
              <h1 className="text-4xl font-semibold tracking-tight text-slate-950 md:text-5xl">
                That page is not available.
              </h1>
              <p className="max-w-2xl text-base leading-7 text-slate-600">
                MSCQR could not find <span className="font-medium text-slate-900">{location.pathname}</span>. Use one of
                the trusted entry points below to continue.
              </p>
            </div>

            <div className="flex flex-wrap gap-3">
              <Button asChild>
                <Link to="/verify">
                  <ScanLine className="h-4 w-4" />
                  Verify a product
                </Link>
              </Button>
              <Button asChild variant="outline">
                <Link to="/trust">
                  Open Trust Center
                  <ArrowRight className="h-4 w-4" />
                </Link>
              </Button>
              <Button asChild variant="outline">
                <Link to="/help/support">
                  <LifeBuoy className="h-4 w-4" />
                  Get help
                </Link>
              </Button>
            </div>
          </div>

          <div className="rounded-[2rem] border border-slate-200 bg-white p-6 shadow-[0_20px_50px_rgba(15,23,42,0.08)]">
            <div className="text-sm font-semibold uppercase tracking-[0.18em] text-slate-500">Trusted paths</div>
            <div className="mt-4 space-y-4 text-sm leading-7 text-slate-600">
              <p>Use verification pages for customer checks, the trust center for proof guidance, and the help hub for role-specific support.</p>
              <p>Legal, privacy, cookie, and preference information is available from the footer below.</p>
            </div>
          </div>
        </div>
      </div>
      <LegalFooter />
    </div>
  );
}
