import { type ElementType, type ReactNode } from "react";
import { Link } from "react-router-dom";
import {
  AlertTriangle,
  ArrowRight,
  BadgeCheck,
  ClipboardCheck,
  Factory,
  PackageCheck,
  QrCode,
  ScanLine,
  Shirt,
  ShieldCheck,
  Store,
  Users,
} from "lucide-react";

import { PublicShell } from "@/components/public/PublicShell";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

type Icon = ElementType;

const scanFlow = [
  {
    title: "Brand creates QR labels",
    body: "Each label is prepared for a garment collection or batch.",
    icon: QrCode,
  },
  {
    title: "Manufacturer attaches the label",
    body: "The factory prints or attaches the label and confirms the work is complete.",
    icon: Factory,
  },
  {
    title: "Customer scans the garment",
    body: "A shopper scans the QR label before or after purchase.",
    icon: ScanLine,
  },
  {
    title: "MSCQR shows the result",
    body: "The customer sees a clear result while the brand can review suspicious repeat scans.",
    icon: ShieldCheck,
  },
] as const;

const problemPoints = [
  "Fake garments damage brand trust and customer confidence.",
  "Customers need a quick way to check whether a garment is genuine.",
  "Brands need visibility when the same QR label is scanned in unusual ways.",
  "QR codes can be copied, so MSCQR looks at label status, print confirmation, scan history, and suspicious repeat activity.",
] as const;

const howItWorks = [
  {
    title: "Issue QR labels",
    body: "Prepare QR labels for garments, batches, collections, or brand-approved manufacturing runs.",
    icon: QrCode,
  },
  {
    title: "Print and attach",
    body: "Give manufacturers a clear process to print, attach, and confirm garment labels.",
    icon: ClipboardCheck,
  },
  {
    title: "Customer scans",
    body: "Show the verification result first, then explain what it means in plain language.",
    icon: ScanLine,
  },
  {
    title: "Review suspicious scans",
    body: "Help teams spot unusual repeat scans and follow up without overwhelming customers.",
    icon: AlertTriangle,
  },
] as const;

const audiences = [
  {
    title: "Clothing brands",
    body: "Give customers a simple authenticity check and protect brand trust after products leave your control.",
    icon: Store,
  },
  {
    title: "Garment manufacturers",
    body: "Receive assigned QR labels, print or attach garment tags, and confirm completion for brand partners.",
    icon: Factory,
  },
  {
    title: "Authenticity teams",
    body: "Review scan activity, suspicious repeat scans, and garment label status from one workspace.",
    icon: BadgeCheck,
  },
  {
    title: "Customers",
    body: "Scan a garment QR label and see a clear result without needing technical knowledge.",
    icon: Users,
  },
] as const;

export default function Index() {
  return (
    <PublicShell>
      <main>
        <HeroSection />
        <ProblemSection />
        <HowItWorksSection />
        <AudienceSection />
        <TrustSection />
        <FinalCTA />
      </main>
    </PublicShell>
  );
}

function HeroSection() {
  return (
    <section className="relative overflow-hidden border-b border-border bg-white">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_12%_12%,rgba(204,204,255,0.42),transparent_32%),linear-gradient(180deg,#ffffff_0%,#fafaff_100%)]" />
      <div className="relative mx-auto grid w-full max-w-7xl gap-12 px-4 py-16 lg:min-h-[calc(100svh-84px)] lg:grid-cols-[0.92fr_1.08fr] lg:items-center lg:py-20">
        <div className="max-w-3xl">
          <h1 className="text-balance text-5xl font-semibold leading-[1.02] tracking-normal text-foreground sm:text-6xl lg:text-7xl">
            Make every garment verifiable.
          </h1>
          <p className="mt-6 max-w-2xl text-lg leading-8 text-muted-foreground">
            Let customers scan your garments and trust what they buy.
          </p>
          <div className="mt-8 flex flex-col gap-3 sm:flex-row sm:flex-wrap">
            <Button asChild size="lg">
              <Link to="/request-access">
                Request Access
                <ArrowRight data-icon="inline-end" />
              </Link>
            </Button>
            <Button asChild size="lg" variant="outline">
              <Link to="/how-scanning-works">
                See how scanning works
                <ArrowRight data-icon="inline-end" />
              </Link>
            </Button>
            <Button asChild size="lg" variant="ghost">
              <Link to="/verify">
                <ScanLine data-icon="inline-start" />
                Verify a Product
              </Link>
            </Button>
          </div>
        </div>

        <div className="rounded-3xl border border-moonlight-300/70 bg-white p-4 shadow-xl shadow-moonlight-900/10 sm:p-6">
          <div className="grid gap-4 sm:grid-cols-2">
            {scanFlow.map((step, index) => (
              <FlowCard key={step.title} step={step} index={index} />
            ))}
          </div>
          <div className="mt-5 rounded-2xl border border-border bg-mscqr-background p-5">
            <div className="grid gap-5 sm:grid-cols-[148px_1fr] sm:items-center">
              <GarmentLabelVisual />
              <div>
                <p className="text-sm font-semibold text-foreground">Customer result preview</p>
                <div className="mt-3 rounded-2xl border border-emerald-200 bg-emerald-50 p-4 text-emerald-800">
                  <div className="flex items-center gap-2 text-sm font-semibold">
                    <ShieldCheck className="size-4" />
                    This garment is genuine
                  </div>
                  <p className="mt-2 text-sm leading-6 text-emerald-700">Verified by MSCQR</p>
                </div>
                <p className="mt-3 text-sm leading-6 text-muted-foreground">
                  If scan behavior looks unusual, the brand can review the activity inside the workspace.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function FlowCard({ step, index }: { step: (typeof scanFlow)[number]; index: number }) {
  return (
    <article className="rounded-2xl border border-border bg-white p-5">
      <div className="flex items-center justify-between gap-3">
        <div className="flex size-11 items-center justify-center rounded-xl bg-accent text-accent-foreground">
          <step.icon className="size-5" />
        </div>
        <span className="text-sm font-semibold text-moonlight-700">{index + 1}</span>
      </div>
      <h2 className="mt-4 text-lg font-semibold text-foreground">{step.title}</h2>
      <p className="mt-2 text-sm leading-6 text-muted-foreground">{step.body}</p>
    </article>
  );
}

function GarmentLabelVisual() {
  return (
    <div className="rounded-2xl border border-border bg-white p-4" aria-label="Garment QR label preview" role="img">
      <div className="flex items-center gap-2 text-sm font-semibold text-moonlight-900">
        <Shirt className="size-4" />
        Garment Tag
      </div>
      <div className="mt-4 grid size-28 grid-cols-7 gap-1 rounded-xl border border-border bg-mscqr-background p-2">
        {Array.from({ length: 49 }, (_, index) => (
          <span
            key={index}
            className={cn(
              "rounded-[3px]",
              [0, 1, 2, 4, 5, 6, 7, 14, 16, 18, 20, 21, 22, 24, 28, 30, 31, 33, 35, 39, 42, 43, 44, 46, 48].includes(index)
                ? "bg-moonlight-900"
                : "bg-white",
            )}
          />
        ))}
      </div>
      <p className="mt-4 text-xs leading-5 text-muted-foreground">Scan to verify authenticity</p>
    </div>
  );
}

function ProblemSection() {
  return (
    <section className="border-b border-border bg-mscqr-background">
      <div className="mx-auto grid w-full max-w-7xl gap-10 px-4 py-16 lg:grid-cols-[0.42fr_0.58fr] lg:py-20">
        <div>
          <h2 className="text-3xl font-semibold leading-tight text-foreground lg:text-5xl">
            Fake garments are a trust problem, not just a label problem.
          </h2>
          <p className="mt-5 text-base leading-7 text-muted-foreground">
            MSCQR gives brands and manufacturers a clearer way to connect QR labels, printing, customer scans, and review
            workflows.
          </p>
        </div>
        <div className="grid gap-4">
          {problemPoints.map((point) => (
            <div key={point} className="grid grid-cols-[32px_1fr] gap-4 rounded-2xl border border-border bg-white p-5">
              <PackageCheck className="mt-1 size-5 text-primary" />
              <p className="text-sm leading-7 text-foreground">{point}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function HowItWorksSection() {
  return (
    <section id="how-scanning-works" className="scroll-mt-28 border-b border-border bg-white">
      <div className="mx-auto w-full max-w-7xl px-4 py-16 lg:py-20">
        <SectionHeader
          title="How MSCQR works"
          body="A simple garment flow for teams and customers: prepare the QR label, attach it to the garment, let the customer scan, and review suspicious activity when needed."
        />
        <div className="mt-10 grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {howItWorks.map((item) => (
            <InfoCard key={item.title} item={item} />
          ))}
        </div>
      </div>
    </section>
  );
}

function AudienceSection() {
  return (
    <section className="border-b border-border bg-mscqr-background">
      <div className="mx-auto w-full max-w-7xl px-4 py-16 lg:py-20">
        <SectionHeader title="Who MSCQR is for" body="Built only for garment verification workflows, from brand owners to public customers scanning clothing QR labels." />
        <div className="mt-10 grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {audiences.map((item) => (
            <InfoCard key={item.title} item={item} />
          ))}
        </div>
      </div>
    </section>
  );
}

function TrustSection() {
  return (
    <section className="border-b border-border bg-white">
      <div className="mx-auto grid w-full max-w-7xl gap-10 px-4 py-16 lg:grid-cols-[0.52fr_0.48fr] lg:items-center lg:py-20">
        <div>
          <h2 className="text-3xl font-semibold leading-tight text-foreground lg:text-5xl">
            Honest garment verification, built around real scan context.
          </h2>
          <p className="mt-5 text-base leading-7 text-muted-foreground">
            MSCQR checks label status, print confirmation, scan history, and unusual repeat activity. It helps teams
            detect misuse without claiming that a printed QR code can never be copied.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <Button asChild>
              <Link to="/trust">
                Trust & Security
                <ArrowRight data-icon="inline-end" />
              </Link>
            </Button>
            <Button asChild variant="outline">
              <Link to="/solutions/apparel-authenticity">Apparel Authenticity</Link>
            </Button>
          </div>
        </div>
        <div className="rounded-3xl border border-moonlight-300 bg-moonlight-100 p-6">
          <div className="grid gap-4">
            {["Label status", "Print confirmation", "Scan history", "Suspicious repeat activity"].map((item) => (
              <div key={item} className="flex items-center gap-3 rounded-2xl border border-moonlight-300/70 bg-white p-4">
                <ShieldCheck className="size-5 text-primary" />
                <span className="text-sm font-semibold text-foreground">{item}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

function FinalCTA() {
  return (
    <section className="bg-mscqr-background">
      <div className="mx-auto w-full max-w-4xl px-4 py-16 text-center lg:py-20">
        <h2 className="text-3xl font-semibold leading-tight text-foreground lg:text-5xl">
          Ready to make your garments verifiable?
        </h2>
        <p className="mx-auto mt-5 max-w-2xl text-base leading-7 text-muted-foreground">
          Request access to discuss how MSCQR can support your brand, manufacturer, or authenticity team.
        </p>
        <div className="mt-8 flex flex-col justify-center gap-3 sm:flex-row">
          <Button asChild size="lg">
            <Link to="/request-access">
              Request Access
              <ArrowRight data-icon="inline-end" />
            </Link>
          </Button>
          <Button asChild size="lg" variant="outline">
            <Link to="/verify">
              <ScanLine data-icon="inline-start" />
              Verify a Product
            </Link>
          </Button>
        </div>
      </div>
    </section>
  );
}

function SectionHeader({ title, body }: { title: string; body: string }) {
  return (
    <div className="max-w-3xl">
      <h2 className="text-3xl font-semibold leading-tight text-foreground lg:text-5xl">{title}</h2>
      <p className="mt-4 text-base leading-7 text-muted-foreground">{body}</p>
    </div>
  );
}

function InfoCard({ item }: { item: { title: string; body: string; icon: Icon } }) {
  return (
    <article className="rounded-2xl border border-border bg-white p-6 shadow-sm">
      <div className="flex size-11 items-center justify-center rounded-xl bg-accent text-accent-foreground">
        <item.icon className="size-5" />
      </div>
      <h3 className="mt-5 text-lg font-semibold text-foreground">{item.title}</h3>
      <p className="mt-3 text-sm leading-7 text-muted-foreground">{item.body}</p>
    </article>
  );
}
