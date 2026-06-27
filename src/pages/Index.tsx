import { type ElementType } from "react";
import { Link } from "react-router-dom";
import {
  ArrowRight,
  BadgeCheck,
  ClipboardCheck,
  Factory,
  Fingerprint,
  Headphones,
  History,
  Mail,
  PackageCheck,
  QrCode,
  ScanLine,
  ShieldCheck,
  Store,
  TriangleAlert,
  Users,
} from "lucide-react";

import { PublicShell } from "@/components/public/PublicShell";
import { MscqrLogo } from "@/components/brand/MscqrLogo";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

type Icon = ElementType;

const workflow = [
  {
    title: "Issue signed labels",
    body: "Generate label records for approved batches and bind each customer-facing scan to server-side registry state.",
    icon: QrCode,
  },
  {
    title: "Confirm production",
    body: "Require controlled print or attachment confirmation before a label can present as customer-ready.",
    icon: ClipboardCheck,
  },
  {
    title: "Verify in public",
    body: "Route public scans through one verification decision path with label state, proof source, and scan history.",
    icon: ScanLine,
  },
  {
    title: "Review anomalies",
    body: "Surface suspicious repeat activity, ownership conflicts, and scan patterns for operations teams.",
    icon: TriangleAlert,
  },
] as const;

const securityPillars = [
  {
    title: "Signed label proof",
    body: "Signed QR payloads are checked against stored token state, label lifecycle, and tenant/batch bindings.",
    icon: Fingerprint,
  },
  {
    title: "Print-state integrity",
    body: "Labels stay limited until the print workflow confirms they are ready for customer verification.",
    icon: BadgeCheck,
  },
  {
    title: "Replay-aware decisions",
    body: "Repeat scans are evaluated against first-use state, trusted context, and recent scan behavior.",
    icon: History,
  },
] as const;

const roles = [
  {
    title: "Brands and licensees",
    body: "Allocate labels, monitor scan activity, review investigations, and keep customer support grounded in the label record.",
    icon: Store,
  },
  {
    title: "Manufacturers",
    body: "Receive assigned batches, run controlled print jobs, and confirm label production without exposing raw customer flows.",
    icon: Factory,
  },
  {
    title: "Verification teams",
    body: "Use one operating view for genuine scans, repeat checks, suspicious duplicates, blocked labels, and support context.",
    icon: Users,
  },
] as const;

export default function Index() {
  return (
    <PublicShell>
      <main className="bg-mscqr-background text-foreground">
        <HeroSection />
        <HowItWorksSection />
        <SecuritySection />
        <RolesSection />
        <SupportSection />
      </main>
    </PublicShell>
  );
}

function HeroSection() {
  return (
    <section className="relative isolate overflow-hidden bg-[#162019] text-white">
      <img
        src="/docs/customer-result-verified.png"
        alt=""
        aria-hidden="true"
        className="absolute inset-0 -z-20 h-full w-full object-cover object-[58%_34%] opacity-[0.38]"
      />
      <div className="absolute inset-0 -z-10 bg-[linear-gradient(90deg,rgba(10,18,14,0.94)_0%,rgba(10,18,14,0.82)_42%,rgba(10,18,14,0.46)_100%)]" />

      <div className="mx-auto flex min-h-[78svh] w-full max-w-7xl flex-col justify-center px-4 py-16 sm:py-20 lg:py-24">
        <div className="max-w-3xl animate-fade-in">
          <p className="mb-5 inline-flex items-center gap-2 text-sm font-semibold uppercase tracking-[0.18em] text-emerald-200">
            <ShieldCheck className="size-4" />
            Authentication service platform
          </p>
          <h1 className="max-w-4xl text-4xl font-semibold leading-[1.05] tracking-normal sm:text-6xl lg:text-7xl">
            <MscqrLogo variant="wordmark" alt="MSCQR" className="h-[0.9em] w-auto max-w-full invert" />
          </h1>
          <p className="mt-6 max-w-2xl text-lg leading-8 text-slate-100 sm:text-xl">
            A production authentication platform for QR-labelled products, controlled print workflows, and public
            verification decisions that stay honest about scan history and suspicious repeat use.
          </p>
          <div className="mt-9 flex flex-col gap-3 sm:flex-row">
            <Button asChild size="lg" className="bg-white text-[#162019] hover:bg-emerald-50">
              <Link to="/request-access">
                Request Access
                <ArrowRight data-icon="inline-end" />
              </Link>
            </Button>
            <Button asChild size="lg" variant="outline" className="border-white/60 bg-white/10 text-white hover:bg-white/20">
              <Link to="/verify">
                <ScanLine data-icon="inline-start" />
                Verify a Product
              </Link>
            </Button>
          </div>
        </div>
      </div>
    </section>
  );
}

function HowItWorksSection() {
  return (
    <section className="border-b border-border bg-white">
      <div className="mx-auto w-full max-w-7xl px-4 py-16 lg:py-20">
        <SectionHeader
          eyebrow="How MSCQR Works"
          title="One verification path from label issue to customer result."
          body="MSCQR keeps public verification tied to server-side label state instead of treating every QR scan as a standalone URL visit."
        />
        <div className="mt-10 grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {workflow.map((item, index) => (
            <ProcessItem key={item.title} item={item} index={index} />
          ))}
        </div>
      </div>
    </section>
  );
}

function SecuritySection() {
  return (
    <section className="border-b border-border bg-mscqr-background">
      <div className="mx-auto grid w-full max-w-7xl gap-10 px-4 py-16 lg:grid-cols-[0.44fr_0.56fr] lg:items-start lg:py-20">
        <SectionHeader
          eyebrow="Security Posture"
          title="Trust is based on state, proof, and behavior."
          body="MSCQR does not pretend a printed QR code is impossible to copy. It verifies issued label proof, print readiness, first-use state, and repeat-scan context."
        />
        <div className="grid gap-4">
          {securityPillars.map((item) => (
            <WideItem key={item.title} item={item} />
          ))}
        </div>
      </div>
    </section>
  );
}

function RolesSection() {
  return (
    <section className="border-b border-border bg-white">
      <div className="mx-auto w-full max-w-7xl px-4 py-16 lg:py-20">
        <SectionHeader
          eyebrow="Platform Operations"
          title="Built for the teams that operate product authentication."
          body="The workspace separates customer verification from internal controls, giving each role only the workflows needed to issue, print, review, and support labels."
        />
        <div className="mt-10 grid gap-4 lg:grid-cols-3">
          {roles.map((item) => (
            <RoleItem key={item.title} item={item} />
          ))}
        </div>
      </div>
    </section>
  );
}

function SupportSection() {
  return (
    <section className="bg-[#f5f7f2]">
      <div className="mx-auto grid w-full max-w-7xl gap-8 px-4 py-16 lg:grid-cols-[0.56fr_0.44fr] lg:items-center lg:py-20">
        <div>
          <p className="text-sm font-semibold uppercase tracking-[0.18em] text-mscqr-verified">Support</p>
          <h2 className="mt-3 max-w-3xl text-3xl font-semibold leading-tight text-foreground lg:text-5xl">
            Start with a verification result, then bring in the right team.
          </h2>
          <p className="mt-5 max-w-2xl text-base leading-7 text-muted-foreground">
            Customers can verify a product publicly. Brands and operators can request access, review support context, and
            investigate labels that need attention.
          </p>
        </div>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-1">
          <SupportLink
            icon={PackageCheck}
            title="Public verification"
            body="Check a product label and see the current decision."
            to="/verify"
          />
          <SupportLink
            icon={Headphones}
            title="Support centre"
            body="Find customer guidance and report concerns."
            to="/help/support"
          />
          <SupportLink
            icon={Users}
            title="Platform access"
            body="Speak with MSCQR about onboarding."
            to="/request-access"
          />
          <SupportLink
            icon={Mail}
            title="Contact MSCQR"
            body="Reach the team for commercial or operational questions."
            to="/contact"
          />
        </div>
      </div>
    </section>
  );
}

function SectionHeader({ eyebrow, title, body }: { eyebrow: string; title: string; body: string }) {
  return (
    <div className="max-w-3xl">
      <p className="text-sm font-semibold uppercase tracking-[0.18em] text-primary">{eyebrow}</p>
      <h2 className="mt-3 text-3xl font-semibold leading-tight text-foreground lg:text-5xl">{title}</h2>
      <p className="mt-4 text-base leading-7 text-muted-foreground">{body}</p>
    </div>
  );
}

function ProcessItem({ item, index }: { item: { title: string; body: string; icon: Icon }; index: number }) {
  return (
    <article
      className={cn(
        "animate-fade-in rounded-md border border-border bg-white p-5 shadow-sm",
        index > 0 && "delay-100",
      )}
    >
      <div className="flex items-center justify-between gap-3">
        <div className="flex size-10 items-center justify-center rounded-md bg-mscqr-background text-primary">
          <item.icon className="size-5" />
        </div>
        <span className="text-sm font-semibold text-muted-foreground">{String(index + 1).padStart(2, "0")}</span>
      </div>
      <h3 className="mt-5 text-lg font-semibold text-foreground">{item.title}</h3>
      <p className="mt-3 text-sm leading-7 text-muted-foreground">{item.body}</p>
    </article>
  );
}

function WideItem({ item }: { item: { title: string; body: string; icon: Icon } }) {
  return (
    <article className="grid gap-4 rounded-md border border-border bg-white p-5 shadow-sm sm:grid-cols-[44px_1fr]">
      <div className="flex size-11 items-center justify-center rounded-md bg-emerald-50 text-mscqr-verified">
        <item.icon className="size-5" />
      </div>
      <div>
        <h3 className="text-lg font-semibold text-foreground">{item.title}</h3>
        <p className="mt-2 text-sm leading-7 text-muted-foreground">{item.body}</p>
      </div>
    </article>
  );
}

function RoleItem({ item }: { item: { title: string; body: string; icon: Icon } }) {
  return (
    <article className="rounded-md border border-border bg-white p-6 shadow-sm">
      <div className="flex size-11 items-center justify-center rounded-md bg-[#f5f7f2] text-[#244b37]">
        <item.icon className="size-5" />
      </div>
      <h3 className="mt-5 text-lg font-semibold text-foreground">{item.title}</h3>
      <p className="mt-3 text-sm leading-7 text-muted-foreground">{item.body}</p>
    </article>
  );
}

function SupportLink({
  icon: IconComponent,
  title,
  body,
  to,
}: {
  icon: Icon;
  title: string;
  body: string;
  to: string;
}) {
  return (
    <Link
      to={to}
      className="group grid gap-3 rounded-md border border-border bg-white p-5 shadow-sm transition hover:-translate-y-0.5 hover:border-mscqr-border-strong hover:shadow-md"
    >
      <div className="flex items-center gap-3">
        <div className="flex size-10 items-center justify-center rounded-md bg-mscqr-background text-primary">
          <IconComponent className="size-5" />
        </div>
        <h3 className="text-base font-semibold text-foreground">{title}</h3>
        <ArrowRight className="ml-auto size-4 text-muted-foreground transition group-hover:translate-x-1 group-hover:text-primary" />
      </div>
      <p className="text-sm leading-6 text-muted-foreground">{body}</p>
    </Link>
  );
}
