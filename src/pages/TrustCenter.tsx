import { Link } from "react-router-dom";
import { ArrowRight, LifeBuoy, LockKeyhole, ScanLine, ShieldCheck, ShieldAlert, Waypoints } from "lucide-react";

import { MotionPanel } from "@/components/mscqr/motion";
import { StatusBadge } from "@/components/mscqr/status";
import { PublicShell } from "@/components/public/PublicShell";
import { Button } from "@/components/ui/button";

const CONTACT_EMAIL = "administration@mscqr.com";

const proofTiers = [
  {
    title: "Signed label verification",
    body: "The strongest MSCQR proof tier. The live result is tied to a server-issued label signature and checked against lifecycle state.",
  },
  {
    title: "Manual registry lookup",
    body: "Useful when a code must be entered by hand. It confirms registry and lifecycle state, but it does not prove the physical label binding.",
  },
  {
    title: "Degraded handling",
    body: "If critical integrity storage is unavailable, MSCQR either queues audit evidence safely or fails closed instead of pretending verification is complete.",
  },
] as const;

const lifecycleStages = [
  "Issued into the governed QR registry",
  "Authorized for controlled print",
  "Confirmed by print lifecycle evidence before customer readiness",
  "Verified with repeat and duplicate classification against live state",
  "Reissued or blocked through explicit operator actions when needed",
] as const;

const operatorPillars = [
  {
    title: "Unified public verification",
    body: "Signed scans, manual code lookup, and replacement handling converge on one backend decision path.",
  },
  {
    title: "Replay-aware evidence",
    body: "Repeat scans are judged against authoritative lifecycle, ownership, and recent activity instead of a loose counter alone.",
  },
  {
    title: "Controlled replacement chains",
    body: "Authorized reissues create explicit replacement records so superseded labels can be handled truthfully.",
  },
] as const;

export default function TrustCenter() {
  return (
    <PublicShell>
      <main>
        <section className="border-b border-white/8">
          <div className="mx-auto grid min-h-[calc(100svh-1px)] w-full max-w-7xl gap-12 px-4 py-16 md:grid-cols-[1.05fr_0.95fr] md:items-end md:py-20">
            <MotionPanel className="max-w-3xl">
              <StatusBadge tone="audit">MSCQR Trust Center</StatusBadge>
              <div className="mt-8 text-sm uppercase tracking-[0.28em] text-slate-400">Governed QR verification</div>
              <h1 className="mt-4 max-w-3xl text-balance text-5xl font-semibold leading-[1.02] text-white md:text-7xl">
                Server-validated label verification with clear proof tiers and controlled print trust.
              </h1>
              <p className="mt-6 max-w-2xl text-base leading-7 text-slate-300 md:text-lg">
                MSCQR is designed to make public verification, print lifecycle control, and operator evidence tell the
                same story. This page explains exactly what the platform proves, what it does not prove, and how
                suspicious or degraded states are handled.
              </p>
              <div className="mt-8 flex flex-wrap gap-3">
                <Button asChild size="lg" className="bg-none bg-cyan-200 text-slate-950 hover:bg-cyan-100">
                  <Link to="/verify">
                    <ScanLine data-icon="inline-start" />
                    Verify a product
                  </Link>
                </Button>
                <Button asChild size="lg" variant="outline" className="border-white/12 bg-white/5 text-slate-100 hover:bg-white/10">
                  <Link to="/login">
                    <LockKeyhole data-icon="inline-start" />
                    Platform access
                  </Link>
                </Button>
              </div>
            </MotionPanel>

            <MotionPanel className="grid gap-4 md:pb-4">
              <div className="rounded-[1.8rem] border border-white/10 bg-white/[0.05] p-6 shadow-[0_34px_90px_rgba(0,0,0,0.35)]">
                <p className="text-xs uppercase tracking-[0.22em] text-slate-400">Proof posture</p>
                <div className="mt-4 space-y-4">
                  <TrustMetric label="Primary verifier" value="Signed label first" />
                  <TrustMetric label="Lifecycle gate" value="Print confirmed before customer-ready" />
                  <TrustMetric label="Fraud review" value="Decision, evidence, and audit trail recorded together" />
                </div>
              </div>
              <div className="rounded-[1.8rem] border border-white/10 bg-[#0d1825] p-6">
                <p className="text-xs uppercase tracking-[0.22em] text-slate-400">Important limit</p>
                <p className="mt-3 text-sm leading-7 text-slate-300">
                  MSCQR does not pretend that a printed QR code is impossible to photograph or copy. The platform is
                  designed to make label state, scan history, duplicate behavior, and operational evidence visible and
                  reviewable.
                </p>
              </div>
            </MotionPanel>
          </div>
        </section>

        <section className="border-b border-white/8">
          <div className="mx-auto w-full max-w-7xl px-4 py-20">
            <div className="max-w-3xl">
              <div className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.03] px-3 py-1 text-[11px] uppercase tracking-[0.22em] text-slate-400">
                <ShieldAlert className="h-3.5 w-3.5 text-cyan-200" />
                Proof tiers
              </div>
              <h2 className="mt-5 text-balance text-3xl font-semibold text-white md:text-4xl">
                Every public result now declares what kind of proof was actually used.
              </h2>
            </div>
            <div className="mt-12 grid gap-8 md:grid-cols-3">
              {proofTiers.map((item) => (
                <div key={item.title} className="border-t border-white/10 pt-5">
                  <h3 className="text-xl font-semibold text-white">{item.title}</h3>
                  <p className="mt-3 text-sm leading-7 text-slate-300">{item.body}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="border-b border-white/8 bg-white/[0.02]">
          <div className="mx-auto grid w-full max-w-7xl gap-10 px-4 py-20 md:grid-cols-[0.44fr_0.56fr]">
            <div>
              <div className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.03] px-3 py-1 text-[11px] uppercase tracking-[0.22em] text-slate-400">
                <Waypoints className="h-3.5 w-3.5 text-cyan-200" />
                Lifecycle trust
              </div>
              <h2 className="mt-5 text-balance text-3xl font-semibold text-white md:text-4xl">
                Customer-facing verification only becomes available after the governed print path says the label is ready.
              </h2>
            </div>
            <div className="space-y-5">
              {lifecycleStages.map((item, index) => (
                <div key={item} className="grid gap-4 border-t border-white/10 pt-4 md:grid-cols-[72px_1fr]">
                  <div className="text-sm font-medium tracking-[0.22em] text-slate-500">0{index + 1}</div>
                  <p className="text-sm leading-7 text-slate-300">{item}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="border-b border-white/8">
          <div className="mx-auto w-full max-w-7xl px-4 py-20">
            <div className="max-w-3xl">
              <div className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.03] px-3 py-1 text-[11px] uppercase tracking-[0.22em] text-slate-400">
                <ShieldCheck className="h-3.5 w-3.5 text-cyan-200" />
                Operations and governance
              </div>
              <h2 className="mt-5 text-balance text-3xl font-semibold text-white md:text-4xl">
                Field verification is connected to the same operator controls that manage reissue, containment, and fraud review.
              </h2>
            </div>
            <div className="mt-12 grid gap-8 md:grid-cols-3">
              {operatorPillars.map((item) => (
                <div key={item.title} className="border-t border-white/10 pt-5">
                  <h3 className="text-xl font-semibold text-white">{item.title}</h3>
                  <p className="mt-3 text-sm leading-7 text-slate-300">{item.body}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section>
          <div className="mx-auto grid w-full max-w-7xl gap-10 px-4 py-20 md:grid-cols-[0.55fr_0.45fr]">
            <div>
              <div className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.03] px-3 py-1 text-[11px] uppercase tracking-[0.22em] text-slate-400">
                <LifeBuoy className="h-3.5 w-3.5 text-cyan-200" />
                Support and reporting
              </div>
              <h2 className="mt-5 text-balance text-3xl font-semibold text-white md:text-4xl">
                Suspicious activity should be escalated with the verification result, purchase context, and any label photos available.
              </h2>
              <p className="mt-4 max-w-2xl text-sm leading-7 text-slate-300">
                Customers can verify or report directly from the public verification flow. Operators can use the managed
                workspace for incident response, governance, and print controls.
              </p>
            </div>
            <div className="space-y-4">
              <TrustLink href="/verify" title="Open verification" body="Scan a signed label or enter a code manually." />
              <TrustLink href="/login" title="Open platform access" body="Managed workspace for print, incidents, governance, and support." />
              <TrustLink
                href={`mailto:${CONTACT_EMAIL}?subject=MSCQR%20Trust%20Center%20Support`}
                title="Contact MSCQR administration"
                body={CONTACT_EMAIL}
                external
              />
            </div>
          </div>
        </section>
      </main>
    </PublicShell>
  );
}

function TrustMetric({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-end justify-between gap-4 border-t border-white/10 pt-4">
      <div className="text-xs uppercase tracking-[0.22em] text-slate-500">{label}</div>
      <div className="text-sm font-semibold text-white">{value}</div>
    </div>
  );
}

function TrustLink({
  href,
  title,
  body,
  external = false,
}: {
  href: string;
  title: string;
  body: string;
  external?: boolean;
}) {
  const content = (
    <div className="flex items-start justify-between gap-4 rounded-[1.4rem] border border-white/10 bg-white/[0.04] p-5 transition-colors duration-300 hover:border-white/20 hover:bg-white/[0.06]">
      <div>
        <p className="text-base font-semibold text-white">{title}</p>
        <p className="mt-2 text-sm leading-7 text-slate-300">{body}</p>
      </div>
      <ArrowRight className="mt-1 h-4 w-4 shrink-0 text-cyan-200" />
    </div>
  );

  if (external) {
    return (
      <a href={href} className="block">
        {content}
      </a>
    );
  }

  return (
    <Link to={href} className="block">
      {content}
    </Link>
  );
}
