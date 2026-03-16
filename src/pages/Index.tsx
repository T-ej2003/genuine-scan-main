import { useEffect, useMemo, useState, type ElementType, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { ArrowRight, CircleHelp, Headset, Lock, Mail, QrCode, ShieldCheck, ShieldAlert, Smartphone, Users } from "lucide-react";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const CONTACT_EMAIL = "administration@mscqr.com";

const SECTION_LINKS = [
  { id: "scan", label: "Scan", routeLabel: "/verify", helper: "Public verification" },
  { id: "security", label: "Security", routeLabel: "/login", helper: "Authenticated control plane" },
  { id: "support", label: "Support", routeLabel: "/help/support", helper: "Support guidance" },
  { id: "contact", label: "Contact", routeLabel: CONTACT_EMAIL, helper: "Admin contact" },
] as const;

export default function Index() {
  const [activeSection, setActiveSection] = useState<(typeof SECTION_LINKS)[number]["id"]>("scan");
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
        rootMargin: "-30% 0px -45% 0px",
        threshold: [0.2, 0.45, 0.7],
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
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="absolute inset-0 -z-10 bg-[radial-gradient(circle_at_top,_rgba(20,184,166,0.16),_transparent_45%),radial-gradient(circle_at_80%_20%,_rgba(59,130,246,0.16),_transparent_38%),linear-gradient(180deg,_#020617_0%,_#0f172a_40%,_#020617_100%)]" />

      <header className="sticky top-0 z-50 border-b border-white/10 bg-slate-950/80 backdrop-blur">
        <div className="mx-auto flex w-full max-w-7xl items-center justify-between gap-4 px-4 py-3">
          <Link to="/" className="flex items-center gap-3">
            <img src="/brand/mscqr-mark.svg" alt="MSCQR logo" className="h-10 w-10 rounded-xl border border-emerald-300/20 bg-slate-900 p-1" />
            <div>
              <div className="text-sm font-semibold tracking-wide text-emerald-300">MSCQR</div>
              <div className="text-xs text-slate-300">Secure product verification</div>
            </div>
          </Link>

          <nav className="hidden items-center gap-2 md:flex">
            {SECTION_LINKS.map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={() => focusSection(item.id)}
                aria-current={activeSection === item.id ? "true" : undefined}
                className={cn(
                  "rounded-full border px-3 py-2 text-sm transition",
                  activeSection === item.id
                    ? "border-emerald-300/40 bg-emerald-300/10 text-white shadow-[0_0_0_1px_rgba(110,231,183,0.16)_inset]"
                    : "border-transparent text-slate-300 hover:border-white/10 hover:bg-white/5 hover:text-white"
                )}
              >
                {item.label}
              </button>
            ))}
          </nav>

          <div className="flex items-center gap-2">
            <Link to="/verify">
              <Button variant="outline" className="border-white/15 bg-white/5 text-slate-100 hover:bg-white/10">
                Scan
              </Button>
            </Link>
            <Link to="/login">
              <Button className="bg-emerald-400 text-slate-950 hover:bg-emerald-300">Login</Button>
            </Link>
          </div>
        </div>
      </header>

      <main>
        <section className="mx-auto grid w-full max-w-7xl gap-10 px-4 pb-16 pt-16 md:grid-cols-[1.1fr_0.9fr] md:pt-24">
          <div>
            <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-emerald-300/25 bg-emerald-300/10 px-3 py-1 text-xs font-medium text-emerald-200">
              <ShieldCheck className="h-3.5 w-3.5" />
              MSCQR secure verification platform
            </div>

            <div className="mb-5 flex flex-wrap items-center gap-3">
              <div className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.04] px-3 py-1.5 text-xs text-slate-200">
                <span className="h-2 w-2 rounded-full bg-emerald-300 shadow-[0_0_0_6px_rgba(110,231,183,0.12)]" />
                Viewing {activeSectionMeta.label}
              </div>
              <div className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.04] px-3 py-1.5 text-xs text-slate-300">
                Route {activeSectionMeta.routeLabel}
              </div>
              <div className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.04] px-3 py-1.5 text-xs text-slate-300">
                {activeSectionMeta.helper}
              </div>
            </div>

            <h1 className="text-balance text-4xl font-semibold leading-tight text-white md:text-6xl">
              Verify products instantly.
              <span className="block text-emerald-300">Protect your brand at scale.</span>
            </h1>

            <p className="mt-5 max-w-2xl text-base leading-7 text-slate-300 md:text-lg">
              MSCQR runs a public verification route for customers and a role-scoped operations portal for licensees,
              manufacturers, and super admins. QR codes move through issuance, print, scan, and audit workflows with
              traceable platform events and authenticated operational controls.
            </p>

            <div className="mt-8 flex flex-wrap items-center gap-3">
              <Link to="/verify">
                <Button size="lg" className="gap-2 bg-emerald-400 text-slate-950 hover:bg-emerald-300">
                  <QrCode className="h-4 w-4" />
                  Scan / Verify Product
                </Button>
              </Link>
              <Link to="/login">
                <Button size="lg" variant="outline" className="gap-2 border-white/15 bg-white/5 text-slate-100 hover:bg-white/10">
                  Portal Login
                  <ArrowRight className="h-4 w-4" />
                </Button>
              </Link>
              <Link to="/help/support">
                <Button size="lg" variant="ghost" className="gap-2 text-slate-200 hover:bg-white/5 hover:text-white">
                  <CircleHelp className="h-4 w-4" />
                  Public Help & Support
                </Button>
              </Link>
            </div>

            <div className="mt-8 grid gap-3 sm:grid-cols-2">
              <StatPill label="Public verification" value="24/7" />
              <StatPill label="Public route" value="/verify" />
              <StatPill label="Authenticated portal" value="/login" />
              <StatPill label="Support route" value="/help/support" />
              <StatPill label="Transport security" value="HTTPS / TLS" />
            </div>

            <div className="mt-8 grid gap-3 sm:grid-cols-2">
              {SECTION_LINKS.map((item) => (
                <button
                  key={`jump-${item.id}`}
                  type="button"
                  onClick={() => focusSection(item.id)}
                  className={cn(
                    "rounded-2xl border px-4 py-4 text-left transition",
                    activeSection === item.id
                      ? "border-emerald-300/35 bg-emerald-300/10 shadow-[0_16px_36px_-28px_rgba(16,185,129,0.85)]"
                      : "border-white/10 bg-white/[0.03] hover:border-white/20 hover:bg-white/[0.05]"
                  )}
                >
                  <div className="text-xs uppercase tracking-[0.18em] text-slate-400">{item.routeLabel}</div>
                  <div className="mt-2 text-base font-semibold text-white">{item.label}</div>
                  <div className="mt-1 text-sm text-slate-300">{item.helper}</div>
                </button>
              ))}
            </div>
          </div>

          <div className="rounded-3xl border border-white/10 bg-white/5 p-5 shadow-[0_20px_80px_rgba(2,6,23,0.55)] backdrop-blur">
            <div className="rounded-2xl border border-white/10 bg-slate-900/80 p-5">
              <div className="mb-4 rounded-2xl border border-emerald-300/15 bg-emerald-300/8 p-4">
                <div className="text-xs font-semibold uppercase tracking-[0.2em] text-emerald-200">Route focus</div>
                <div className="mt-2 flex items-end justify-between gap-4">
                  <div>
                    <div className="text-xl font-semibold text-white">{activeSectionMeta.label}</div>
                    <div className="mt-1 text-sm text-slate-300">{activeSectionMeta.helper}</div>
                  </div>
                  <div className="rounded-xl border border-white/10 bg-white/[0.04] px-3 py-2 text-right">
                    <div className="text-[11px] uppercase tracking-[0.16em] text-slate-400">Route</div>
                    <div className="mt-1 text-sm font-semibold text-white">{activeSectionMeta.routeLabel}</div>
                  </div>
                </div>
              </div>

              <h2 className="text-sm font-semibold uppercase tracking-[0.18em] text-emerald-300">Quick Actions</h2>
              <div className="mt-4 grid gap-3">
                <ActionCard
                  icon={QrCode}
                  title="Scan a code"
                  description="Open the public verifier to check authenticity or report suspicious activity."
                  href="/verify"
                  cta="Open Scanner"
                  internal
                />
                <ActionCard
                  icon={Lock}
                  title="Login to dashboard"
                  description="Sign in for role-scoped QR operations, governance, audit logs, incident handling, notifications, and support workflows."
                  href="/login"
                  cta="Open Login"
                  internal
                />
                <ActionCard
                  icon={Headset}
                  title="Support and documentation"
                  description="Open the public support page for setup guidance, reporting paths, and response expectations."
                  href="/help/support"
                  cta="Open Support"
                  internal
                />
                <ActionCard
                  icon={Mail}
                  title="Contact MSCQR team"
                  description="For onboarding or platform administration queries, contact the MSCQR admin team."
                  href={`mailto:${CONTACT_EMAIL}?subject=MSCQR%20Inquiry`}
                  cta={CONTACT_EMAIL}
                />
              </div>
            </div>
          </div>
        </section>

        <section
          id="scan"
          className={cn(
            "border-y border-white/5 bg-white/[0.02] transition-colors duration-300",
            activeSection === "scan" && "bg-white/[0.04]"
          )}
        >
          <div className="mx-auto w-full max-w-7xl px-4 py-14">
            <div className="grid gap-5 md:grid-cols-3">
              <FeatureCard
                icon={Smartphone}
                title="Customer scan flow"
                description="Customers use the public verifier to check a code, receive an authenticity result, and escalate suspicious activity when needed."
              />
              <FeatureCard
                icon={Users}
                title="Role-scoped operations"
                description="The authenticated portal separates super admin, licensee, manufacturer, governance, and support workflows."
              />
              <FeatureCard
                icon={ShieldAlert}
                title="Traceable lifecycle control"
                description="Operational events, audit logs, and support handling stay attached to the QR lifecycle so disputes and failures can be reviewed."
              />
            </div>
          </div>
        </section>

        <section
          id="security"
          className={cn("mx-auto w-full max-w-7xl px-4 py-16 transition-all duration-300", activeSection === "security" && "scale-[1.001]")}
        >
          <div className="grid gap-8 lg:grid-cols-[1.1fr_0.9fr]">
            <div>
              <h2 className="text-3xl font-semibold text-white md:text-4xl">Authentication and control posture</h2>
              <p className="mt-4 max-w-2xl leading-7 text-slate-300">
                MSCQR is the platform for public verification and authenticated back-office operations.
                Security still depends on production deployment and operating procedures, but the application ships with
                role-aware access control, auditable workflows, notification trails, and tenant-separated operational
                paths.
              </p>
              <ul className="mt-6 space-y-3 text-sm text-slate-200">
                <SecurityBullet>Public verification is separated from the authenticated operations portal.</SecurityBullet>
                <SecurityBullet>Role-scoped access is used for super admin, licensee, manufacturer, and response workflows.</SecurityBullet>
                <SecurityBullet>Privileged actions use authenticated API requests, CSRF checks, validation, and audit logging.</SecurityBullet>
                <SecurityBullet>Required MFA for super admins, licensee admins, and manufacturer users protects the authenticated platform.</SecurityBullet>
                <SecurityBullet>Transport security is designed for HTTPS/TLS deployment behind the production reverse proxy.</SecurityBullet>
                <SecurityBullet>Control wording is aligned for ISO 27001 and SOC 2 style evidence collection; certification claims depend on formal external audit and current operating evidence.</SecurityBullet>
              </ul>
            </div>

            <div className="rounded-3xl border border-white/10 bg-white/5 p-6">
              <div className="rounded-2xl border border-emerald-300/15 bg-slate-900/70 p-5">
                <h3 className="text-lg font-semibold text-white">Current operating profile</h3>
                <div className="mt-4 space-y-3">
                  <div className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
                    <div className="text-xs uppercase tracking-[0.16em] text-slate-400">Public access</div>
                    <p className="mt-2 text-sm leading-6 text-slate-200">
                      Customers verify products through <span className="font-semibold text-white">/verify</span> and can
                      move into suspicious-activity reporting from that flow.
                    </p>
                  </div>
                  <div className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
                    <div className="text-xs uppercase tracking-[0.16em] text-slate-400">Authenticated operations</div>
                    <p className="mt-2 text-sm leading-6 text-slate-200">
                      Internal users sign in through <span className="font-semibold text-white">/login</span> for QR
                      lifecycle management, printing, audit review, incidents, governance, and support response.
                    </p>
                  </div>
                  <div className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
                    <div className="text-xs uppercase tracking-[0.16em] text-slate-400">Support and evidence</div>
                    <p className="mt-2 text-sm leading-6 text-slate-200">
                      Incoming support reports, workflow updates, notifications, and audit events are retained as part of
                      the operational evidence trail.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section
          id="support"
          className={cn(
            "border-y border-white/5 bg-slate-900/40 transition-colors duration-300",
            activeSection === "support" && "bg-slate-900/55"
          )}
        >
          <div className="mx-auto w-full max-w-7xl px-4 py-16">
            <div className="grid gap-6 md:grid-cols-2">
              <Panel
                title="Support"
                description="Need help with scanning, verification, user access, printer readiness, or platform usage? Start with the public support page, then sign in for tenant-specific workflows."
                actions={
                  <>
                    <Link to="/help/support">
                      <Button variant="outline" className="border-white/15 bg-white/5 text-slate-100 hover:bg-white/10">
                        Open Support Page
                      </Button>
                    </Link>
                    <Link to="/help">
                      <Button className="bg-emerald-400 text-slate-950 hover:bg-emerald-300">Support Guide</Button>
                    </Link>
                  </>
                }
              />

              <Panel
                title="Contact"
                description="For onboarding, admin coordination, or platform inquiries, contact the MSCQR administration team. Include your organization name and issue summary for faster routing."
                actions={
                  <>
                    <a href={`mailto:${CONTACT_EMAIL}?subject=MSCQR%20Support%20Request`}>
                      <Button className="bg-white text-slate-950 hover:bg-slate-200">{CONTACT_EMAIL}</Button>
                    </a>
                    <Link to="/login">
                      <Button variant="outline" className="border-white/15 bg-white/5 text-slate-100 hover:bg-white/10">
                        Portal Login
                      </Button>
                    </Link>
                  </>
                }
              />
            </div>
          </div>
        </section>
      </main>

      <footer
        id="contact"
        className={cn(
          "border-t border-white/10 bg-slate-950/90 transition-colors duration-300",
          activeSection === "contact" && "bg-slate-900"
        )}
      >
        <div className="mx-auto flex w-full max-w-7xl flex-col gap-4 px-4 py-8 md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-3">
            <img src="/brand/mscqr-mark.svg" alt="MSCQR logo" className="h-9 w-9 rounded-lg border border-white/10 bg-slate-900 p-1" />
            <div>
              <div className="text-sm font-semibold text-white">MSCQR</div>
              <div className="text-xs text-slate-400">Secure QR verification and product trust</div>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3 text-sm text-slate-300">
            <Link to="/verify" className="hover:text-white">Scan</Link>
            <Link to="/login" className="hover:text-white">Login</Link>
            <Link to="/help/support" className="hover:text-white">Support</Link>
            <a href={`mailto:${CONTACT_EMAIL}`} className="hover:text-white">{CONTACT_EMAIL}</a>
          </div>

          <p className="text-xs text-slate-500">© 2026 MSCQR. All rights reserved.</p>
        </div>
      </footer>
    </div>
  );
}

function ActionCard({
  icon: Icon,
  title,
  description,
  href,
  cta,
  internal = false,
}: {
  icon: ElementType;
  title: string;
  description: string;
  href: string;
  cta: string;
  internal?: boolean;
}) {
  const content = (
    <div className="rounded-xl border border-white/10 bg-white/[0.03] p-4 transition hover:border-emerald-300/30 hover:bg-white/[0.05]">
      <div className="flex items-start gap-3">
        <div className="mt-0.5 rounded-lg border border-emerald-300/20 bg-emerald-300/10 p-2 text-emerald-200">
          <Icon className="h-4 w-4" />
        </div>
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-white">{title}</h3>
          <p className="mt-1 text-xs leading-5 text-slate-300">{description}</p>
          <div className="mt-2 text-xs font-medium text-emerald-300">{cta}</div>
        </div>
      </div>
    </div>
  );

  if (internal) return <Link to={href}>{content}</Link>;

  return (
    <a href={href} target="_blank" rel="noopener noreferrer">
      {content}
    </a>
  );
}

function FeatureCard({ icon: Icon, title, description }: { icon: ElementType; title: string; description: string }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-slate-900/60 p-5">
      <div className="mb-4 inline-flex rounded-lg border border-emerald-300/20 bg-emerald-300/10 p-2 text-emerald-200">
        <Icon className="h-4 w-4" />
      </div>
      <h3 className="text-base font-semibold text-white">{title}</h3>
      <p className="mt-2 text-sm leading-6 text-slate-300">{description}</p>
    </div>
  );
}

function Panel({ title, description, actions }: { title: string; description: string; actions: ReactNode }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-white/[0.03] p-6">
      <h3 className="text-xl font-semibold text-white">{title}</h3>
      <p className="mt-2 text-sm leading-6 text-slate-300">{description}</p>
      <div className="mt-4 flex flex-wrap gap-3">{actions}</div>
    </div>
  );
}

function StatPill({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-white/10 bg-white/[0.03] px-4 py-3">
      <div className="text-xs uppercase tracking-[0.14em] text-slate-400">{label}</div>
      <div className="mt-1 text-sm font-semibold text-white">{value}</div>
    </div>
  );
}

function SecurityBullet({ children }: { children: ReactNode }) {
  return (
    <li className="flex items-start gap-2">
      <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-emerald-300" />
      <span>{children}</span>
    </li>
  );
}
