import type { ElementType, ReactNode } from "react";
import { Link } from "react-router-dom";
import { ArrowRight, CircleHelp, Headset, Lock, Mail, QrCode, ShieldCheck, ShieldAlert, Smartphone, Users } from "lucide-react";

import { Button } from "@/components/ui/button";

const CONTACT_EMAIL = "administration@mscqr.com";

export default function Index() {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="absolute inset-0 -z-10 bg-[radial-gradient(circle_at_top,_rgba(20,184,166,0.16),_transparent_45%),radial-gradient(circle_at_80%_20%,_rgba(59,130,246,0.16),_transparent_38%),linear-gradient(180deg,_#020617_0%,_#0f172a_40%,_#020617_100%)]" />

      <header className="sticky top-0 z-50 border-b border-white/10 bg-slate-950/80 backdrop-blur">
        <div className="mx-auto flex w-full max-w-7xl items-center justify-between gap-4 px-4 py-3">
          <Link to="/" className="flex items-center gap-3">
            <img src="/brand/authenticqr-mark.svg" alt="MSCQR logo" className="h-10 w-10 rounded-xl border border-emerald-300/20 bg-slate-900 p-1" />
            <div>
              <div className="text-sm font-semibold tracking-wide text-emerald-300">MSCQR</div>
              <div className="text-xs text-slate-300">Secure product verification</div>
            </div>
          </Link>

          <nav className="hidden items-center gap-6 text-sm text-slate-300 md:flex">
            <a href="#scan" className="hover:text-white">Scan</a>
            <a href="#security" className="hover:text-white">Security</a>
            <a href="#support" className="hover:text-white">Support</a>
            <a href="#contact" className="hover:text-white">Contact</a>
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
              MSCQR powered by AuthenticQR platform
            </div>

            <h1 className="text-balance text-4xl font-semibold leading-tight text-white md:text-6xl">
              Verify products instantly.
              <span className="block text-emerald-300">Protect your brand at scale.</span>
            </h1>

            <p className="mt-5 max-w-2xl text-base leading-7 text-slate-300 md:text-lg">
              MSCQR helps manufacturers, licensees, and customers verify genuine products through secure QR scans,
              controlled code lifecycle management, and traceable audit events.
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
              <StatPill label="Verification route" value="/verify" />
              <StatPill label="Help documentation" value="/help" />
              <StatPill label="Secure TLS" value="HTTPS" />
            </div>
          </div>

          <div className="rounded-3xl border border-white/10 bg-white/5 p-5 shadow-[0_20px_80px_rgba(2,6,23,0.55)] backdrop-blur">
            <div className="rounded-2xl border border-white/10 bg-slate-900/80 p-5">
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
                  description="Sign in for QR operations, governance, audit logs, incidents, and support workflows."
                  href="/login"
                  cta="Open Login"
                  internal
                />
                <ActionCard
                  icon={Headset}
                  title="Support and documentation"
                  description="Read setup, usage, and response guidance from the support/help section."
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

        <section id="scan" className="border-y border-white/5 bg-white/[0.02]">
          <div className="mx-auto w-full max-w-7xl px-4 py-14">
            <div className="grid gap-5 md:grid-cols-3">
              <FeatureCard
                icon={Smartphone}
                title="Customer scan flow"
                description="Customers can scan a printed QR code and receive an authenticity result with guidance and reporting actions."
              />
              <FeatureCard
                icon={Users}
                title="Role-based operations"
                description="Separate workflows for super admins, licensee admins, manufacturers, and incident response teams."
              />
              <FeatureCard
                icon={ShieldAlert}
                title="Fraud signal awareness"
                description="Repeat-scan and suspicious behavior signals help identify potential cloning or misuse patterns."
              />
            </div>
          </div>
        </section>

        <section id="security" className="mx-auto w-full max-w-7xl px-4 py-16">
          <div className="grid gap-8 lg:grid-cols-[1.1fr_0.9fr]">
            <div>
              <h2 className="text-3xl font-semibold text-white md:text-4xl">How secure is MSCQR?</h2>
              <p className="mt-4 max-w-2xl leading-7 text-slate-300">
                MSCQR uses the AuthenticQR platform to combine secure QR verification with operational controls. Security
                depends on production configuration, but the app includes controls for protected scan workflows, audit
                trails, incident handling, and tenant-separated operations.
              </p>
              <ul className="mt-6 space-y-3 text-sm text-slate-200">
                <SecurityBullet>HTTPS/TLS deployment support with reverse proxy configuration for secure traffic.</SecurityBullet>
                <SecurityBullet>Multi-tenant role controls to separate admin, manufacturer, and response operations.</SecurityBullet>
                <SecurityBullet>Incident reporting and response flows to track suspicious scans and follow-up actions.</SecurityBullet>
                <SecurityBullet>Audit logs and governance workflows for traceability and operational accountability.</SecurityBullet>
                <SecurityBullet>Backend protections such as rate limiting and validation (server configuration dependent).</SecurityBullet>
              </ul>
            </div>

            <div className="rounded-3xl border border-white/10 bg-white/5 p-6">
              <div className="rounded-2xl border border-emerald-300/15 bg-slate-900/70 p-5">
                <h3 className="text-lg font-semibold text-white">Transport Security Trust Seal</h3>
                <p className="mt-2 text-sm leading-6 text-slate-300">
                  MSCQR highlights transport security trust signaling with the Sectigo secure site seal on the public homepage.
                  Use HTTPS access to ensure the secure connection indicator is visible in the browser.
                </p>
                <div className="mt-5 rounded-xl border border-white/10 bg-white p-4">
                  <a
                    href="https://www.sectigo.com/"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center justify-center"
                    aria-label="Sectigo secure site seal"
                  >
                    <img
                      src="https://www.sectigo.com/images/seals/sectigo_trust_seal_md_2x.png"
                      alt="Sectigo Secure Site Seal"
                      className="h-auto max-w-full"
                      loading="lazy"
                    />
                  </a>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section id="support" className="border-y border-white/5 bg-slate-900/40">
          <div className="mx-auto w-full max-w-7xl px-4 py-16">
            <div className="grid gap-6 md:grid-cols-2">
              <Panel
                title="Support"
                description="Need help with scanning, verification, user access, or platform usage? Start with the public help documentation, then sign in for role-specific operations."
                actions={
                  <>
                    <Link to="/help">
                      <Button variant="outline" className="border-white/15 bg-white/5 text-slate-100 hover:bg-white/10">
                        Open Help Hub
                      </Button>
                    </Link>
                    <Link to="/help/support">
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

      <footer id="contact" className="border-t border-white/10 bg-slate-950/90">
        <div className="mx-auto flex w-full max-w-7xl flex-col gap-4 px-4 py-8 md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-3">
            <img src="/brand/authenticqr-mark.svg" alt="MSCQR logo" className="h-9 w-9 rounded-lg border border-white/10 bg-slate-900 p-1" />
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

          <p className="text-xs text-slate-500">© 2026 MSCQR. Built on AuthenticQR.</p>
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
