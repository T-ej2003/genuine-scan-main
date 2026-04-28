import { type ElementType, type ReactNode } from "react";
import { Link } from "react-router-dom";
import {
  ArrowRight,
  BadgeCheck,
  ClipboardCheck,
  Factory,
  FileClock,
  Fingerprint,
  Globe2,
  Layers3,
  LifeBuoy,
  PackageCheck,
  QrCode,
  ScanLine,
  ShieldCheck,
  Users,
  Waypoints,
} from "lucide-react";

import { PublicShell } from "@/components/public/PublicShell";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const CONTACT_EMAIL = "administration@mscqr.com";

type Feature = {
  title: string;
  body: string;
  icon: ElementType;
};

type PageShellProps = {
  eyebrow: string;
  title: string;
  intro: string;
  children: ReactNode;
  imageAlt: string;
};

const platformFeatures: Feature[] = [
  {
    title: "Governed QR issuance",
    body: "Create and allocate QR/code inventory through role-aware workflows before labels reach production.",
    icon: QrCode,
  },
  {
    title: "Controlled printing",
    body: "Connect print readiness, printer setup, and confirmation evidence to manufacturer-side operations.",
    icon: Factory,
  },
  {
    title: "Public verification",
    body: "Support QR scans and manual lookup without exposing internal incident, audit, or operator data.",
    icon: ScanLine,
  },
  {
    title: "Review and escalation",
    body: "Classify duplicate behavior, raise support or incident reviews, and preserve evidence for operator follow-up.",
    icon: ShieldCheck,
  },
];

const platformWorkflow = [
  {
    step: "Issue",
    detail: "Create governed code records before label artwork or print files move into production.",
  },
  {
    step: "Assign",
    detail: "Connect labels to manufacturer, licensee, batch, and product context where authorized.",
  },
  {
    step: "Print",
    detail: "Use controlled print readiness and confirmation instead of treating labels as loose exports.",
  },
  {
    step: "Verify",
    detail: "Route QR scans and manual lookup through one public product verification entry point.",
  },
  {
    step: "Review",
    detail: "Keep duplicate, replay, and anomaly behavior visible for authorized operators.",
  },
  {
    step: "Escalate",
    detail: "Move suspicious outcomes into support or incident workflows with relevant context.",
  },
  {
    step: "Evidence",
    detail: "Preserve audit logs and verification decisions for high-trust product operations.",
  },
] as const;

const industryLinks = [
  {
    title: "Industrial components",
    body: "Govern QR verification and audit evidence for components that need controlled production context.",
    href: "/industries/industrial-components",
  },
  {
    title: "Spare parts",
    body: "Help operators verify replacement parts while keeping duplicate and replay activity reviewable.",
    href: "/industries/spare-parts",
  },
  {
    title: "Regulated supply chains",
    body: "Support controlled labeling and product verification workflows where evidence quality matters.",
    href: "/industries/regulated-supply-chains",
  },
];

const insightTopics = [
  "Governed QR issuance",
  "Controlled printing",
  "Product verification workflows",
  "Duplicate and replay review",
  "Audit evidence for product authentication",
  "Manufacturer-led brand protection operations",
] as const;

function PageShell({ eyebrow, title, intro, children, imageAlt }: PageShellProps) {
  return (
    <PublicShell>
      <main>
        <section className="border-b border-white/10">
          <div className="mx-auto grid w-full max-w-7xl gap-10 px-4 py-16 lg:grid-cols-[0.92fr_0.72fr] lg:items-center lg:py-20">
            <div>
              <p className="text-xs font-semibold uppercase text-cyan-200">{eyebrow}</p>
              <h1 className="mt-5 max-w-4xl text-balance text-4xl font-semibold leading-tight text-white sm:text-5xl lg:text-6xl">
                {title}
              </h1>
              <p className="mt-6 max-w-3xl text-base leading-8 text-slate-300">{intro}</p>
              <div className="mt-8 flex flex-col gap-3 sm:flex-row sm:flex-wrap">
                <Button asChild size="lg" className="bg-none bg-cyan-200 text-slate-950 hover:bg-cyan-100">
                  <Link to="/request-access">
                    Request access
                    <ArrowRight data-icon="inline-end" />
                  </Link>
                </Button>
                <Button
                  asChild
                  size="lg"
                  variant="outline"
                  className="border-white/10 bg-white/[0.04] text-slate-100 hover:bg-white/[0.08]"
                >
                  <Link to="/verify">
                    <ScanLine data-icon="inline-start" />
                    Verify a product
                  </Link>
                </Button>
              </div>
            </div>
            <div className="overflow-hidden rounded-lg border border-white/10 bg-white/[0.04]">
              <img
                src="/brand/mscqr-og.png"
                alt={imageAlt}
                className="aspect-[1200/630] h-auto w-full object-cover"
                width="1200"
                height="630"
              />
            </div>
          </div>
        </section>
        {children}
      </main>
    </PublicShell>
  );
}

function FeatureGrid({ items }: { items: Feature[] }) {
  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
      {items.map((item) => (
        <article key={item.title} className="rounded-lg border border-white/10 bg-white/[0.035] p-5">
          <item.icon className="size-5 text-cyan-200" />
          <h2 className="mt-4 text-xl font-semibold text-white">{item.title}</h2>
          <p className="mt-3 text-sm leading-7 text-slate-400">{item.body}</p>
        </article>
      ))}
    </div>
  );
}

function ContentBand({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <section className={cn("border-b border-white/10", className)}>
      <div className="mx-auto w-full max-w-7xl px-4 py-16 lg:py-20">{children}</div>
    </section>
  );
}

function TextBlock({ eyebrow, title, body }: { eyebrow: string; title: string; body: string }) {
  return (
    <div className="max-w-3xl">
      <p className="text-xs font-semibold uppercase text-amber-200">{eyebrow}</p>
      <h2 className="mt-4 text-3xl font-semibold leading-tight text-white lg:text-4xl">{title}</h2>
      <p className="mt-4 text-sm leading-7 text-slate-400">{body}</p>
    </div>
  );
}

export function PlatformPage() {
  return (
    <PageShell
      eyebrow="Platform"
      title="Product authentication infrastructure for governed QR operations."
      intro="MSCQR connects QR/code issuance, controlled printing, public verification, anomaly review, support escalation, and audit evidence into a manufacturer-led operating model."
      imageAlt="MSCQR product authentication dashboard preview"
    >
      <ContentBand>
        <FeatureGrid items={platformFeatures} />
      </ContentBand>
      <ContentBand className="bg-[#05080c]">
        <div className="grid gap-10 lg:grid-cols-[0.34fr_0.66fr] lg:items-start">
          <TextBlock
            eyebrow="Operating model"
            title="From issued code to reviewable verification evidence."
            body="MSCQR is structured around the operational steps manufacturers need to control before and after a product is verified: issue, assign, print, verify, review, escalate, and preserve evidence."
          />
          <div className="grid gap-3 md:grid-cols-2">
            {platformWorkflow.map((item, index) => (
              <article key={item.step} className="rounded-lg border border-white/10 bg-white/[0.035] p-5">
                <p className="font-mono text-xs uppercase tracking-[0.18em] text-slate-500">
                  {String(index + 1).padStart(2, "0")}
                </p>
                <h2 className="mt-3 text-lg font-semibold text-white">{item.step}</h2>
                <p className="mt-3 text-sm leading-7 text-slate-400">{item.detail}</p>
              </article>
            ))}
          </div>
        </div>
      </ContentBand>
      <ContentBand className="bg-[#080d13]">
        <div className="grid gap-8 lg:grid-cols-[0.62fr_0.38fr] lg:items-end">
          <TextBlock
            eyebrow="Operational posture"
            title="Built for global and regional authentication workflows."
            body="MSCQR is positioned for manufacturer-led deployments serving UK, India, Hyderabad/India, and global operating teams without claiming automated multi-region failover or formal certifications that are not yet in place."
          />
          <Button
            asChild
            size="lg"
            variant="outline"
            className="w-fit border-white/10 bg-white/[0.04] text-slate-100 hover:bg-white/[0.08]"
          >
            <Link to="/trust">
              Review trust posture
              <ArrowRight data-icon="inline-end" />
            </Link>
          </Button>
        </div>
      </ContentBand>
    </PageShell>
  );
}

export function ManufacturersPage() {
  return (
    <PageShell
      eyebrow="For manufacturers"
      title="Control QR issuance, printing, verification, and evidence around real production workflows."
      intro="MSCQR helps manufacturers govern product code inventory, print readiness, public verification, duplicate review, support escalation, and audit evidence without turning the public verifier into an internal console."
      imageAlt="MSCQR controlled QR printing workflow preview"
    >
      <ContentBand>
        <FeatureGrid
          items={[
            {
              title: "Manufacturer control",
              body: "Manage issued codes and batch context before labels move into production.",
              icon: Factory,
            },
            {
              title: "Print confirmation",
              body: "Use controlled print workflows and connector support where authorized by your organization.",
              icon: ClipboardCheck,
            },
            {
              title: "Scan review",
              body: "Review duplicate or replay patterns against lifecycle state and operational context.",
              icon: Fingerprint,
            },
            {
              title: "Audit evidence",
              body: "Preserve workflow and verification evidence for high-trust product operations.",
              icon: FileClock,
            },
          ]}
        />
      </ContentBand>
      <ContentBand className="bg-[#080d13]">
        <div className="grid gap-8 lg:grid-cols-[0.58fr_0.42fr] lg:items-start">
          <TextBlock
            eyebrow="Manufacturer-first"
            title="Make public verification depend on controlled production context."
            body="The manufacturer page now points buyers toward the core operating question: who issued the code, who controlled print readiness, what product or batch context exists, and what evidence is available when scan behavior looks unusual."
          />
          <div className="rounded-lg border border-white/10 bg-white/[0.035] p-6">
            <h2 className="text-2xl font-semibold text-white">Useful when teams need</h2>
            <ul className="mt-5 space-y-3 text-sm leading-7 text-slate-400">
              <li>Controlled QR issuance before labels reach a printer.</li>
              <li>Public product verification without exposing internal operations.</li>
              <li>Duplicate and replay review tied to label lifecycle state.</li>
              <li>Audit evidence for support, incident, and governance review.</li>
            </ul>
            <Button asChild size="lg" className="mt-6 bg-none bg-cyan-200 text-slate-950 hover:bg-cyan-100">
              <Link to="/request-access">
                Request manufacturer access
                <ArrowRight data-icon="inline-end" />
              </Link>
            </Button>
          </div>
        </div>
      </ContentBand>
    </PageShell>
  );
}

export function LicenseesPage() {
  return (
    <PageShell
      eyebrow="For licensees and operators"
      title="Operate product verification workflows inside manufacturer-governed boundaries."
      intro="MSCQR supports licensee and enterprise operator workflows for assigned inventory, scan review, support escalation, and controlled QR operations while preserving tenant and role boundaries."
      imageAlt="MSCQR licensee product verification operations preview"
    >
      <ContentBand>
        <FeatureGrid
          items={[
            {
              title: "Assigned operations",
              body: "Work with allocated batches and manufacturer-governed QR inventory.",
              icon: Layers3,
            },
            {
              title: "Review queues",
              body: "Monitor scan activity and route suspicious outcomes into structured review.",
              icon: Waypoints,
            },
            {
              title: "Support escalation",
              body: "Attach relevant verification context to support and investigation workflows.",
              icon: LifeBuoy,
            },
            {
              title: "Role-aware access",
              body: "Keep platform operations separated from public verification experiences.",
              icon: Users,
            },
          ]}
        />
      </ContentBand>
      <ContentBand className="bg-[#080d13]">
        <div className="grid gap-8 lg:grid-cols-[0.52fr_0.48fr]">
          <TextBlock
            eyebrow="Boundaries"
            title="Licensee workflows stay inside manufacturer-governed operations."
            body="Licensees and enterprise operators can help monitor assigned inventory, scan outcomes, and support escalation, while MSCQR keeps sensitive dashboard, audit, incident, and account routes private."
          />
          <div className="rounded-lg border border-white/10 bg-white/[0.035] p-6">
            <h2 className="text-2xl font-semibold text-white">Good secondary audience fit</h2>
            <p className="mt-3 text-sm leading-7 text-slate-400">
              Licensee pages should support buying committees and operator teams without shifting MSCQR away from the
              manufacturer-led product authentication position.
            </p>
            <Button
              asChild
              size="lg"
              variant="outline"
              className="mt-6 border-white/10 bg-white/[0.04] text-slate-100 hover:bg-white/[0.08]"
            >
              <Link to="/solutions/manufacturers">
                Compare manufacturer workflows
                <ArrowRight data-icon="inline-end" />
              </Link>
            </Button>
          </div>
        </div>
      </ContentBand>
    </PageShell>
  );
}

export function IndustriesPage() {
  return (
    <PageShell
      eyebrow="Industries"
      title="Authentication workflows for high-trust products and controlled supply chains."
      intro="MSCQR supports product authentication patterns for industrial components, spare parts, regulated supply chains, electronics, cosmetics, alcohol, certificates, documents, and high-trust product brands."
      imageAlt="MSCQR public product verification screen preview"
    >
      <ContentBand>
        <div className="grid gap-4 md:grid-cols-3">
          {industryLinks.map((item) => (
            <Link key={item.href} to={item.href} className="rounded-lg border border-white/10 bg-white/[0.035] p-5 hover:bg-white/[0.055]">
              <h2 className="text-xl font-semibold text-white">{item.title}</h2>
              <p className="mt-3 text-sm leading-7 text-slate-400">{item.body}</p>
              <span className="mt-5 inline-flex items-center gap-2 text-sm font-medium text-cyan-200">
                Open {item.title.toLowerCase()} page
                <ArrowRight className="size-4" />
              </span>
            </Link>
          ))}
        </div>
      </ContentBand>
      <ContentBand className="bg-[#080d13]">
        <TextBlock
          eyebrow="Search intent"
          title="Built around product categories where verification evidence matters."
          body="MSCQR copy intentionally focuses on controlled product labeling, QR verification for supply chains, duplicate review, and audit evidence rather than broad anti-counterfeit guarantees. Industry pages should help qualified teams find the right operating model without inventing case studies."
        />
      </ContentBand>
    </PageShell>
  );
}

export function IndustrialComponentsPage() {
  return (
    <IndustryDetail
      eyebrow="Industrial component authentication"
      title="Governed QR verification for industrial components and high-trust spare parts."
      body="MSCQR supports component workflows where issued label state, controlled print evidence, scan behavior, and audit history need to remain reviewable for operators."
      icon={PackageCheck}
      focusItems={[
        {
          title: "Component identity",
          body: "Tie QR verification to issued label records and production context instead of loose code lists.",
        },
        {
          title: "Controlled print evidence",
          body: "Make label readiness depend on controlled print confirmation where the workflow requires it.",
        },
        {
          title: "Duplicate review",
          body: "Surface repeated scans for operator review without exposing private investigation data publicly.",
        },
        {
          title: "Audit trail",
          body: "Preserve verification and lifecycle evidence for support and governance review.",
        },
      ]}
    />
  );
}

export function SparePartsPage() {
  return (
    <IndustryDetail
      eyebrow="Spare parts authentication"
      title="Verify spare parts while keeping duplicate and replay behavior visible."
      body="MSCQR helps manufacturers and operators connect controlled QR issuance, public verification, scan review, and audit evidence around replacement-part workflows."
      icon={BadgeCheck}
      focusItems={[
        {
          title: "Replacement context",
          body: "Connect spare-part verification to batch, product, or operator context where available.",
        },
        {
          title: "Manual fallback",
          body: "Keep code lookup available when a damaged label or field environment makes QR scanning difficult.",
        },
        {
          title: "Replay visibility",
          body: "Help operators review repeated scan patterns without promising counterfeit-proof outcomes.",
        },
        {
          title: "Support escalation",
          body: "Give teams a route to handle suspicious verification results with relevant evidence.",
        },
      ]}
    />
  );
}

export function RegulatedSupplyChainsPage() {
  return (
    <IndustryDetail
      eyebrow="Regulated supply chain product authentication"
      title="Controlled labeling and verification workflows for evidence-sensitive environments."
      body="MSCQR supports product verification infrastructure where controlled labeling, anomaly review, support escalation, and audit evidence need a consistent workflow."
      icon={ShieldCheck}
      focusItems={[
        {
          title: "Controlled labeling",
          body: "Govern issuance and print state before product verification is exposed publicly.",
        },
        {
          title: "Policy-led verification",
          body: "Apply consistent public verification outcomes across QR scans and manual lookup.",
        },
        {
          title: "Anomaly review",
          body: "Route duplicate and unusual scan behavior into review workflows for authorized teams.",
        },
        {
          title: "Evidence retention",
          body: "Preserve audit records without claiming formal compliance certifications that are not in place.",
        },
      ]}
    />
  );
}

function IndustryDetail({
  eyebrow,
  title,
  body,
  icon: Icon,
  focusItems = [
    {
      title: "Controlled QR issuance",
      body: "Govern issuance before labels are used in product or document workflows.",
    },
    {
      title: "Print confirmation",
      body: "Connect print state to product verification readiness where controlled printing is required.",
    },
    {
      title: "Duplicate/replay review",
      body: "Keep suspicious scan behavior visible for authorized operators.",
    },
    {
      title: "Audit evidence",
      body: "Preserve reviewable evidence for support and governance workflows.",
    },
  ],
}: {
  eyebrow: string;
  title: string;
  body: string;
  icon: ElementType;
  focusItems?: Array<{ title: string; body: string }>;
}) {
  return (
    <PageShell eyebrow={eyebrow} title={title} intro={body} imageAlt="MSCQR product verification infrastructure preview">
      <ContentBand>
        <div className="grid gap-8 lg:grid-cols-[0.38fr_0.62fr] lg:items-start">
          <div className="rounded-lg border border-white/10 bg-white/[0.035] p-5">
            <Icon className="size-6 text-cyan-200" />
            <h2 className="mt-4 text-2xl font-semibold text-white">Workflow focus</h2>
            <p className="mt-3 text-sm leading-7 text-slate-400">
              Govern issuance before labels are used, confirm print state, support public verification, and preserve the
              review evidence needed by authorized operators.
            </p>
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            {focusItems.map((item) => (
              <div key={item.title} className="rounded-lg border border-white/10 bg-[#080d13] p-5">
                <h2 className="text-lg font-semibold text-white">{item.title}</h2>
                <p className="mt-3 text-sm leading-7 text-slate-400">{item.body}</p>
              </div>
            ))}
          </div>
        </div>
      </ContentBand>
    </PageShell>
  );
}

export function RequestAccessPage() {
  return (
    <PageShell
      eyebrow="Request access"
      title="Discuss manufacturer-led product authentication with MSCQR."
      intro="Use this page to contact MSCQR about governed QR issuance, controlled printing, public verification, duplicate review, support escalation, and audit evidence workflows."
      imageAlt="MSCQR request access and product authentication workflow preview"
    >
      <ContentBand>
        <div className="grid gap-8 lg:grid-cols-[0.54fr_0.46fr]">
          <TextBlock
            eyebrow="Commercial fit"
            title="Best suited to manufacturers and governed operator networks."
            body="MSCQR is a fit for teams that need QR verification infrastructure tied to production, print, support, and audit workflows. UK and India-focused deployments, including Hyderabad/India operations, can be discussed without overclaiming local office or certification status."
          />
          <div className="rounded-lg border border-white/10 bg-white/[0.035] p-6">
            <h2 className="text-2xl font-semibold text-white">Contact</h2>
            <p className="mt-3 text-sm leading-7 text-slate-400">
              Send a brief note about your product category, printing workflow, target regions, and verification risk model.
            </p>
            <Button asChild size="lg" className="mt-6 bg-none bg-cyan-200 text-slate-950 hover:bg-cyan-100">
              <a href={`mailto:${CONTACT_EMAIL}?subject=MSCQR%20request%20access`}>
                Email MSCQR administration
                <ArrowRight data-icon="inline-end" />
              </a>
            </Button>
          </div>
        </div>
      </ContentBand>
    </PageShell>
  );
}

export function BlogPage() {
  return (
    <PageShell
      eyebrow="MSCQR Insights"
      title="Practical notes for manufacturer-led product authentication."
      intro="The insights library is being structured around QR verification workflows, controlled printing, audit evidence, and brand protection operations. Articles will be published only when reviewed and ready."
      imageAlt="MSCQR insights library product authentication preview"
    >
      <ContentBand>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {insightTopics.map((topic) => (
            <article key={topic} className="rounded-lg border border-white/10 bg-white/[0.035] p-5">
              <Globe2 className="size-5 text-amber-200" />
              <h2 className="mt-4 text-xl font-semibold text-white">{topic}</h2>
              <p className="mt-3 text-sm leading-7 text-slate-400">
                Coming soon. This topic is reserved for reviewed operational guidance, not filler articles.
              </p>
            </article>
          ))}
        </div>
      </ContentBand>
    </PageShell>
  );
}
