import { useEffect, useMemo, useState, type ElementType } from "react";
import { Link } from "react-router-dom";
import {
  ArrowRight,
  Factory,
  Headset,
  LockKeyhole,
  Mail,
  QrCode,
  ScanLine,
  ShieldAlert,
  ShieldCheck,
  Users,
  Waypoints,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const CONTACT_EMAIL = "administration@mscqr.com";

const SECTION_LINKS = [
  {
    id: "how-it-works",
    label: "How It Works",
    kicker: "Verification flow",
    summary: "Every public check runs through one verification policy and the same lifecycle rules.",
  },
  {
    id: "security",
    label: "Security",
    kicker: "Fraud controls",
    summary: "Signed labels, print-state checks, replay detection, and audit evidence stay aligned.",
  },
  {
    id: "operations",
    label: "Operations",
    kicker: "Platform roles",
    summary: "Manufacturers, licensees, and platform operators work from one governed issuance model.",
  },
  {
    id: "support",
    label: "Support",
    kicker: "Response path",
    summary: "Customers get clear verification guidance. Operators get direct escalation and contact routes.",
  },
] as const;

const HOW_IT_WORKS = [
  {
    step: "01",
    title: "Issue and print",
    body: "MSCQR issues labels to tracked inventory, then waits for controlled print confirmation before a label is customer-ready.",
  },
  {
    step: "02",
    title: "Verify once, classify every time",
    body: "Public scans and manual checks route into the same backend verification engine so authenticity and duplicate outcomes do not drift.",
  },
  {
    step: "03",
    title: "Escalate with evidence",
    body: "Later scans are evaluated against print state, ownership context, and prior activity instead of loose heuristic-only repeats.",
  },
] as const;

const SECURITY_PILLARS = [
  {
    title: "Label-bound proof",
    detail: "Signed scans validate server-issued token data. Manual code entry stays available, but it is presented as a controlled registry lookup.",
  },
  {
    title: "Replay-aware lifecycle",
    detail: "First-scan outcomes now depend on authoritative issued and print-confirmed state. Not-ready labels do not create fake redemption history.",
  },
  {
    title: "Traceable decisions",
    detail: "Duplicate classification, ownership checks, and public outcomes share one policy surface so fraud review sees the same story customers do.",
  },
] as const;

const ROLE_COLUMNS = [
  {
    icon: Factory,
    title: "Manufacturers",
    items: [
      "Run controlled print jobs instead of browser-driven label generation.",
      "Track reissues and replacements through the print lifecycle.",
      "Keep field labels tied to confirmed production events.",
    ],
  },
  {
    icon: Users,
    title: "Licensees",
    items: [
      "Manage inventory visibility, support flows, and downstream allocation.",
      "Review scan outcomes against batch and ownership context.",
      "Keep reconciliation inside the same governed QR registry.",
    ],
  },
  {
    icon: ShieldAlert,
    title: "Platform operators",
    items: [
      "Monitor blocked labels, suspicious duplicates, and incident review trails.",
      "Apply approval controls to high-risk actions without opening public gaps.",
      "Keep verification behavior consistent across public entry points.",
    ],
  },
] as const;

export default function Index() {
  const [activeSection, setActiveSection] = useState<(typeof SECTION_LINKS)[number]["id"]>("how-it-works");

  const activeSectionMeta = useMemo(
    () => SECTION_LINKS.find((item) => item.id === activeSection) || SECTION_LINKS[0],
    [activeSection]
  );

  useEffect(() => {
    const updateFromHash = () => {
      const currentHash = window.location.hash.replace("#", "").trim();
      if (SECTION_LINKS.some((item) => item.id === currentHash)) {
        setActiveSection(currentHash as (typeof SECTION_LINKS)[number]["id"]);
      }
    };

    updateFromHash();

    const observer = new IntersectionObserver(
      (entries) => {
        const next = entries
          .filter((entry) => entry.isIntersecting)
          .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
        const id = next?.target?.id;
        if (id && SECTION_LINKS.some((item) => item.id === id)) {
          setActiveSection(id as (typeof SECTION_LINKS)[number]["id"]);
        }
      },
      {
        rootMargin: "-28% 0px -48% 0px",
        threshold: [0.24, 0.5, 0.78],
      }
    );

    SECTION_LINKS.forEach((item) => {
      const el = document.getElementById(item.id);
      if (el) observer.observe(el);
    });

    window.addEventListener("hashchange", updateFromHash);

    return () => {
      window.removeEventListener("hashchange", updateFromHash);
      observer.disconnect();
    };
  }, []);

  const focusSection = (id: (typeof SECTION_LINKS)[number]["id"]) => {
    setActiveSection(id);
    const target = document.getElementById(id);
    target?.scrollIntoView?.({ behavior: "smooth", block: "start" });
    window.history.replaceState(null, "", `#${id}`);
  };

  return (
    <div className="min-h-screen overflow-x-hidden bg-[#08111b] text-slate-100">
      <div className="pointer-events-none fixed inset-0 -z-10 bg-[radial-gradient(circle_at_top,_rgba(45,212,191,0.12),_transparent_34%),radial-gradient(circle_at_82%_18%,_rgba(148,163,184,0.16),_transparent_24%),linear-gradient(180deg,_#08111b_0%,_#0c1723_46%,_#08111b_100%)]" />
      <div className="pointer-events-none fixed inset-x-0 top-0 -z-10 h-64 bg-[linear-gradient(180deg,rgba(255,255,255,0.06),transparent)] opacity-60" />

      <header className="sticky top-0 z-50 border-b border-white/8 bg-[#08111b]/78 backdrop-blur-xl">
        <div className="mx-auto flex w-full max-w-7xl items-center justify-between gap-4 px-4 py-4">
          <Link to="/" className="flex items-center gap-3">
            <img
              src="/brand/mscqr-mark.svg"
              alt="MSCQR logo"
              className="h-10 w-10 rounded-2xl border border-white/12 bg-white/5 p-1.5"
            />
            <div>
              <div className="text-sm font-semibold tracking-[0.18em] text-teal-200">MSCQR</div>
              <div className="text-xs text-slate-400">Authentication and traceability platform</div>
            </div>
          </Link>

          <nav className="hidden items-center gap-1.5 md:flex">
            {SECTION_LINKS.map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={() => focusSection(item.id)}
                aria-current={activeSection === item.id ? "true" : undefined}
                className={cn(
                  "rounded-full px-3 py-2 text-sm transition-colors duration-300",
                  activeSection === item.id
                    ? "bg-white/10 text-white"
                    : "text-slate-400 hover:bg-white/6 hover:text-slate-100"
                )}
              >
                {item.label}
              </button>
            ))}
          </nav>

          <div className="flex items-center gap-2">
            <Link to="/verify">
              <Button variant="outline" className="border-white/12 bg-white/5 text-slate-100 hover:bg-white/10">
                Verify
              </Button>
            </Link>
            <Link to="/login">
              <Button className="bg-teal-300 text-slate-950 hover:bg-teal-200">Platform access</Button>
            </Link>
          </div>
        </div>
      </header>

      <main>
        <section className="relative overflow-hidden border-b border-white/8">
          <div className="absolute inset-0 bg-[linear-gradient(135deg,rgba(255,255,255,0.03),transparent_38%,rgba(45,212,191,0.07)_100%)]" />
          <div className="mx-auto grid min-h-[calc(100svh-73px)] w-full max-w-7xl gap-12 px-4 py-16 md:grid-cols-[1.1fr_0.9fr] md:items-center md:py-20">
            <div className="relative z-10 max-w-3xl">
              <div className="inline-flex items-center gap-2 rounded-full border border-white/12 bg-white/6 px-3 py-1 text-[11px] uppercase tracking-[0.22em] text-slate-300">
                <ShieldCheck className="h-3.5 w-3.5 text-teal-200" />
                Trusted product authentication
              </div>

              <div className="mt-8">
                <div className="text-sm uppercase tracking-[0.32em] text-slate-400">MSCQR</div>
                <h1 className="mt-4 max-w-3xl text-balance text-5xl font-semibold leading-[1.02] text-white md:text-7xl">
                  Authenticate products with one governed verification path.
                </h1>
                <p className="mt-6 max-w-2xl text-base leading-7 text-slate-300 md:text-lg">
                  MSCQR links issued labels, controlled print confirmation, public verification, and fraud review into a
                  single production system. Customers get a clear authenticity answer. Operators get lifecycle evidence
                  they can act on.
                </p>
              </div>

              <div className="mt-8 flex flex-wrap items-center gap-3">
                <Link to="/verify">
                  <Button size="lg" className="gap-2 bg-teal-300 text-slate-950 hover:bg-teal-200">
                    <ScanLine className="h-4 w-4" />
                    Verify a product
                  </Button>
                </Link>
                <Link to="/login">
                  <Button
                    size="lg"
                    variant="outline"
                    className="gap-2 border-white/12 bg-white/5 text-slate-100 hover:bg-white/10"
                  >
                    <LockKeyhole className="h-4 w-4" />
                    Platform access
                  </Button>
                </Link>
              </div>

              <div className="mt-8 grid max-w-2xl gap-6 border-t border-white/10 pt-6 text-sm text-slate-300 md:grid-cols-3">
                <Metric label="Public verification" value="Signed scan first" />
                <Metric label="Lifecycle control" value="Print confirmed" />
                <Metric label="Duplicate review" value="Unified classification" />
              </div>
            </div>

            <div className="relative z-10">
              <div className="relative overflow-hidden rounded-[2rem] border border-white/10 bg-white/[0.04] p-6 shadow-[0_40px_120px_rgba(0,0,0,0.35)] transition-transform duration-700 md:p-8">
                <div className="absolute inset-0 bg-[linear-gradient(160deg,rgba(255,255,255,0.06),transparent_42%,rgba(45,212,191,0.08)_100%)]" />
                <div className="relative">
                  <div className="flex items-start justify-between gap-4 border-b border-white/10 pb-5">
                    <div>
                      <div className="text-xs uppercase tracking-[0.24em] text-slate-400">Current focus</div>
                      <div className="mt-2 text-2xl font-semibold text-white">{activeSectionMeta.label}</div>
                      <p className="mt-2 max-w-sm text-sm leading-6 text-slate-300">{activeSectionMeta.summary}</p>
                    </div>
                    <div className="rounded-2xl border border-white/12 bg-[#0b1521] px-3 py-2 text-right">
                      <div className="text-[11px] uppercase tracking-[0.22em] text-slate-500">
                        {activeSectionMeta.kicker}
                      </div>
                      <div className="mt-1 text-sm font-medium text-slate-200">MSCQR surface</div>
                    </div>
                  </div>

                  <div className="mt-6 space-y-4">
                    {SECTION_LINKS.map((item, index) => (
                      <button
                        key={item.id}
                        type="button"
                        onClick={() => focusSection(item.id)}
                        className={cn(
                          "flex w-full items-start justify-between gap-4 rounded-2xl border px-4 py-4 text-left transition-all duration-300",
                          activeSection === item.id
                            ? "border-teal-200/30 bg-teal-300/10 text-white"
                            : "border-white/10 bg-[#0b1521] text-slate-300 hover:border-white/18 hover:bg-white/[0.05]"
                        )}
                      >
                        <div>
                          <div className="text-[11px] uppercase tracking-[0.22em] text-slate-500">
                            0{index + 1}
                          </div>
                          <div className="mt-2 text-base font-semibold">{item.label}</div>
                          <div className="mt-1 text-sm leading-6 text-slate-300">{item.summary}</div>
                        </div>
                        <ArrowRight
                          className={cn(
                            "mt-1 h-4 w-4 shrink-0 transition-transform duration-300",
                            activeSection === item.id && "translate-x-1 text-teal-200"
                          )}
                        />
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section id="how-it-works" className="scroll-mt-24 border-b border-white/8">
          <div className="mx-auto grid w-full max-w-7xl gap-10 px-4 py-20 md:grid-cols-[0.42fr_0.58fr]">
            <div>
              <SectionEyebrow icon={Waypoints}>How MSCQR Works</SectionEyebrow>
              <SectionHeading>
                One verification engine for public scans, manual lookups, and downstream review.
              </SectionHeading>
            </div>
            <div className="space-y-8">
              {HOW_IT_WORKS.map((item) => (
                <div key={item.step} className="grid gap-4 border-t border-white/10 pt-5 md:grid-cols-[84px_1fr]">
                  <div className="text-sm font-medium tracking-[0.22em] text-slate-500">{item.step}</div>
                  <div>
                    <h3 className="text-xl font-semibold text-white">{item.title}</h3>
                    <p className="mt-2 max-w-2xl text-sm leading-7 text-slate-300">{item.body}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section id="security" className="scroll-mt-24 border-b border-white/8 bg-white/[0.02]">
          <div className="mx-auto w-full max-w-7xl px-4 py-20">
            <SectionEyebrow icon={ShieldCheck}>Security and Traceability</SectionEyebrow>
            <SectionHeading className="max-w-3xl">
              The public story stays honest: signed labels get stronger proof, manual lookups stay controlled, and both
              paths use the same lifecycle rules.
            </SectionHeading>

            <div className="mt-12 grid gap-10 md:grid-cols-3">
              {SECURITY_PILLARS.map((pillar) => (
                <div key={pillar.title} className="border-t border-white/10 pt-5">
                  <h3 className="text-xl font-semibold text-white">{pillar.title}</h3>
                  <p className="mt-3 text-sm leading-7 text-slate-300">{pillar.detail}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section id="operations" className="scroll-mt-24 border-b border-white/8">
          <div className="mx-auto w-full max-w-7xl px-4 py-20">
            <SectionEyebrow icon={Factory}>Platform Roles</SectionEyebrow>
            <SectionHeading className="max-w-3xl">
              MSCQR operates as a governed authentication service, not a disconnected QR generator.
            </SectionHeading>

            <div className="mt-12 grid gap-8 lg:grid-cols-[1.1fr_0.9fr]">
              <div className="space-y-8">
                {ROLE_COLUMNS.map((column) => (
                  <RoleColumn key={column.title} icon={column.icon} title={column.title} items={column.items} />
                ))}
              </div>

              <div className="rounded-[1.75rem] border border-white/10 bg-white/[0.04] p-6">
                <div className="text-xs uppercase tracking-[0.22em] text-slate-500">Operational posture</div>
                <div className="mt-4 space-y-6">
                  <div className="border-t border-white/10 pt-4">
                    <div className="text-lg font-semibold text-white">Customer-ready only after print confirmation</div>
                    <p className="mt-2 text-sm leading-7 text-slate-300">
                      Verification does not overclaim authenticity for labels that have not moved through the managed
                      print lifecycle.
                    </p>
                  </div>
                  <div className="border-t border-white/10 pt-4">
                    <div className="text-lg font-semibold text-white">Replay resistance with truthful limits</div>
                    <p className="mt-2 text-sm leading-7 text-slate-300">
                      MSCQR materially reduces weak repeat handling through server state, ownership context, and scan
                      classification. It does not pretend to offer offline-proof clone prevention it does not yet have.
                    </p>
                  </div>
                  <div className="border-t border-white/10 pt-4">
                    <div className="text-lg font-semibold text-white">Field response stays connected to governance</div>
                    <p className="mt-2 text-sm leading-7 text-slate-300">
                      Suspicious duplicates, blocked labels, and replacement labels all feed back into the same managed
                      platform record.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section id="support" className="scroll-mt-24">
          <div className="mx-auto grid w-full max-w-7xl gap-10 px-4 py-20 md:grid-cols-[0.52fr_0.48fr]">
            <div>
              <SectionEyebrow icon={Headset}>Support and Contact</SectionEyebrow>
              <SectionHeading className="max-w-2xl">
                Public verification, operator support, and platform administration stay easy to find.
              </SectionHeading>
              <p className="mt-4 max-w-2xl text-sm leading-7 text-slate-300">
                Consumers can verify a product or report a suspicious result. Operators can access the managed MSCQR
                workspace for print, governance, and incident response.
              </p>
            </div>

            <div className="space-y-4">
              <SupportLink
                href="/verify"
                icon={QrCode}
                title="Verify a product"
                body="Open the public verification flow to scan a signed label or enter a code manually."
                cta="Open verification"
                internal
              />
              <SupportLink
                href="/login"
                icon={LockKeyhole}
                title="Platform access"
                body="Open the authenticated workspace for managed operations, print activity, audit review, and support handling."
                cta="Go to platform"
                internal
              />
              <SupportLink
                href={`mailto:${CONTACT_EMAIL}?subject=MSCQR%20Platform%20Support`}
                icon={Mail}
                title="Contact MSCQR administration"
                body="Reach the platform team for onboarding, operational support, or governance questions."
                cta={CONTACT_EMAIL}
              />
            </div>
          </div>
        </section>
      </main>

      <footer className="border-t border-white/8 bg-[#071019]">
        <div className="mx-auto flex w-full max-w-7xl flex-col gap-4 px-4 py-8 text-sm text-slate-400 md:flex-row md:items-center md:justify-between">
          <div>MSCQR authentication platform for governed product verification and traceability.</div>
          <div className="flex flex-wrap items-center gap-4">
            <Link to="/verify" className="transition-colors hover:text-slate-200">
              Verify
            </Link>
            <Link to="/login" className="transition-colors hover:text-slate-200">
              Platform access
            </Link>
            <a href={`mailto:${CONTACT_EMAIL}`} className="transition-colors hover:text-slate-200">
              {CONTACT_EMAIL}
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-xs uppercase tracking-[0.22em] text-slate-500">{label}</div>
      <div className="mt-2 text-base font-semibold text-white">{value}</div>
    </div>
  );
}

function SectionEyebrow({
  children,
  icon: Icon,
}: {
  children: string;
  icon: ElementType;
}) {
  return (
    <div className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.03] px-3 py-1 text-[11px] uppercase tracking-[0.22em] text-slate-400">
      <Icon className="h-3.5 w-3.5 text-teal-200" />
      {children}
    </div>
  );
}

function SectionHeading({
  children,
  className,
}: {
  children: string;
  className?: string;
}) {
  return <h2 className={cn("mt-5 text-balance text-3xl font-semibold text-white md:text-4xl", className)}>{children}</h2>;
}

function RoleColumn({
  icon: Icon,
  title,
  items,
}: {
  icon: ElementType;
  title: string;
  items: readonly string[];
}) {
  return (
    <div className="border-t border-white/10 pt-5">
      <div className="flex items-center gap-3">
        <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-white/10 bg-white/[0.04]">
          <Icon className="h-5 w-5 text-teal-200" />
        </div>
        <h3 className="text-xl font-semibold text-white">{title}</h3>
      </div>
      <div className="mt-4 space-y-3">
        {items.map((item) => (
          <p key={item} className="text-sm leading-7 text-slate-300">
            {item}
          </p>
        ))}
      </div>
    </div>
  );
}

function SupportLink({
  href,
  icon: Icon,
  title,
  body,
  cta,
  internal = false,
}: {
  href: string;
  icon: ElementType;
  title: string;
  body: string;
  cta: string;
  internal?: boolean;
}) {
  const content = (
    <div className="flex items-start justify-between gap-4 rounded-[1.5rem] border border-white/10 bg-white/[0.04] px-5 py-5 transition-colors duration-300 hover:bg-white/[0.06]">
      <div className="flex gap-4">
        <div className="mt-0.5 flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border border-white/10 bg-[#0b1521]">
          <Icon className="h-5 w-5 text-teal-200" />
        </div>
        <div>
          <div className="text-lg font-semibold text-white">{title}</div>
          <div className="mt-2 max-w-lg text-sm leading-7 text-slate-300">{body}</div>
        </div>
      </div>
      <div className="mt-1 shrink-0 text-sm font-medium text-slate-200">{cta}</div>
    </div>
  );

  if (internal) {
    return <Link to={href}>{content}</Link>;
  }

  return (
    <a href={href} className="block">
      {content}
    </a>
  );
}
