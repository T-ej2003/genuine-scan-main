import { type ElementType, type ReactNode } from "react";
import { Link } from "react-router-dom";
import {
  AlertTriangle,
  ArrowRight,
  ClipboardCheck,
  Factory,
  FileCheck2,
  Fingerprint,
  Layers3,
  PackageCheck,
  QrCode,
  ScanLine,
  ShieldCheck,
  Split,
  TerminalSquare,
  Users,
  Waypoints,
} from "lucide-react";

import { AuditTimeline } from "@/components/mscqr/audit-timeline";
import { LabelLifecycleRail } from "@/components/mscqr/lifecycle";
import { MotionPanel } from "@/components/mscqr/motion";
import { StatusBadge } from "@/components/mscqr/status";
import { PublicShell } from "@/components/public/PublicShell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

type Icon = ElementType;
const lifecycleSteps = [
  {
    label: "Issue",
    title: "Label records are created before print",
    body: "Codes start as governed registry entries, not loose files passed around for uncontrolled use.",
    state: "complete",
  },
  {
    label: "Assign",
    title: "Batches connect labels to manufacturer context",
    body: "Issued labels can be allocated to product batches and operational ownership before they reach the line.",
    state: "complete",
  },
  {
    label: "Print confirm",
    title: "Readiness depends on controlled print state",
    body: "A public verification result is stronger when the backend knows whether a label was actually printed.",
    state: "complete",
  },
  {
    label: "Verify",
    title: "Public scans and manual lookup share policy",
    body: "QR scans and entered codes route through one verification surface so outcomes stay consistent.",
    state: "current",
  },
  {
    label: "Classify",
    title: "Duplicate behavior is reviewable",
    body: "Repeat scans are not hand-waved. They are classified against lifecycle state, prior activity, and route.",
    state: "review",
  },
  {
    label: "Audit",
    title: "Evidence remains available for review",
    body: "Operators can preserve scan decisions, label state, and workflow history in auditable records.",
    state: "pending",
  },
] as const;
const capabilityGroups = [
  {
    title: "Registry control",
    capabilities: ["Controlled issuance", "Manufacturer batch assignment", "Role-based platform access"],
  },
  {
    title: "Print governance",
    capabilities: ["Print confirmation", "Replacement/reissue visibility", "Operator-ready label state"],
  },
  {
    title: "Verification response",
    capabilities: ["Public QR verification", "Manual code lookup", "Scan route classification"],
  },
  {
    title: "Review and evidence",
    capabilities: ["Duplicate/replay classification", "Incident/support escalation", "Audit logs and exportable evidence"],
  },
] as const;
const roleOperations = [
  {
    icon: Factory,
    audience: "Manufacturers",
    summary: "Control product authentication around real production batches and label workflows.",
    items: ["Govern QR/code issuance", "Control print readiness", "Connect verification to production batches"],
  },
  {
    icon: Users,
    audience: "Licensees and enterprise operators",
    summary: "Monitor inventory and support outcomes without losing tenant boundaries.",
    items: ["Allocate and monitor inventory", "Review scan outcomes", "Handle support and reconciliation"],
  },
  {
    icon: ShieldCheck,
    audience: "Platform operators",
    summary: "Govern risky actions and preserve evidence for review.",
    items: ["Review anomalies", "Maintain audit trails", "Escalate suspicious verification behavior"],
  },
  {
    icon: QrCode,
    audience: "Consumers",
    summary: "Get a clear product check without seeing operational complexity.",
    items: ["Scan or enter a code", "Receive a verification response", "Report suspicious outcomes"],
  },
] as const;

const publicVerificationSteps = [
  "Scan the label QR",
  "Enter the code manually if needed",
  "Receive a verification response",
  "Escalate suspicious results",
] as const;
const auditEvents = [
  { label: "Label issued", value: "MSCQR-7F42-91C8", tone: "audit" },
  { label: "Assigned to batch", value: "B-2049 / manufacturer scope", tone: "audit" },
  { label: "Print confirmed", value: "Controlled print event", tone: "verified" },
  { label: "Public scan received", value: "Signed QR route", tone: "audit" },
  { label: "Response generated", value: "First verification / low duplicate risk", tone: "verified" },
] as const;

const qrCells = [
  0, 1, 2, 5, 6, 7, 9, 13, 15, 16, 17, 19, 21, 25, 27, 28, 29, 32, 35, 36, 38, 40, 43, 45, 46, 48, 49, 54, 56, 57,
  58, 60, 64, 66, 69, 70, 72, 73, 74, 77, 79, 80,
] as const;
const qrCellSet = new Set<number>(qrCells);

export default function Index() {
  return (
    <PublicShell>
      <main>
        <HeroSection />
        <LifecycleRail />
        <ProblemSection />
        <CapabilityMatrix />
        <RoleOperations />
        <TrustModel />
        <PublicVerificationCTA />
        <FinalCTA />
      </main>
    </PublicShell>
  );
}

function HeroSection() {
  return (
    <section className="relative isolate overflow-hidden border-b border-white/10">
      <BackgroundGrid />
      <div className="mx-auto grid min-h-[calc(100svh-145px)] w-full max-w-7xl gap-12 px-4 py-16 lg:min-h-[calc(100svh-81px)] lg:grid-cols-[0.95fr_1.05fr] lg:items-center lg:py-20">
        <div className="relative z-10 max-w-3xl">
          <SectionEyebrow icon={Fingerprint}>Product authentication for manufacturers</SectionEyebrow>
          <h1 className="mt-7 text-balance text-5xl font-semibold leading-[0.98] tracking-[-0.055em] text-white sm:text-6xl lg:text-7xl">
            Manufacturer-Led Product Authentication Infrastructure
          </h1>
          <p className="mt-6 max-w-2xl text-base leading-8 text-slate-300 sm:text-lg">
            MSCQR helps manufacturers govern QR/code issuance, controlled product labeling, public verification,
            duplicate and anomaly review, support escalation, and audit evidence across high-trust product workflows.
          </p>

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
              <Link to="/solutions/manufacturers">
                Explore manufacturer workflows
                <ArrowRight data-icon="inline-end" />
              </Link>
            </Button>
            <Button
              asChild
              size="lg"
              variant="ghost"
              className="bg-transparent text-slate-300 hover:bg-white/[0.06] hover:text-white"
            >
              <Link to="/platform">
                Review platform controls
                <ArrowRight data-icon="inline-end" />
              </Link>
            </Button>
          </div>

          <div className="mt-10 grid max-w-3xl gap-3 sm:grid-cols-3">
            <Signal label="Issuance" value="Governed QR/code records" />
            <Signal label="Printing" value="Controlled label readiness" />
            <Signal label="Review" value="Duplicate and anomaly evidence" />
          </div>
        </div>

        <MotionPanel>
          <HeroVerificationPanel />
        </MotionPanel>
      </div>
    </section>
  );
}

function BackgroundGrid() {
  return (
    <div className="pointer-events-none absolute inset-0 -z-10">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_18%_8%,rgba(34,211,238,0.15),transparent_30%),radial-gradient(circle_at_82%_18%,rgba(251,191,36,0.08),transparent_22%),linear-gradient(180deg,#070b10_0%,#0b1219_52%,#070b10_100%)]" />
      <div className="absolute inset-0 opacity-[0.16] [background-image:linear-gradient(rgba(148,163,184,0.32)_1px,transparent_1px),linear-gradient(90deg,rgba(148,163,184,0.32)_1px,transparent_1px)] [background-size:56px_56px]" />
      <div className="absolute inset-x-0 top-0 h-40 bg-[linear-gradient(180deg,rgba(255,255,255,0.08),transparent)]" />
    </div>
  );
}

function HeroVerificationPanel() {
  return (
    <div className="relative z-10">
      <div className="absolute -inset-4 rounded-[2rem] bg-cyan-300/10 blur-3xl" />
      <div className="relative overflow-hidden rounded-[2rem] border border-white/12 bg-[#0a1118]/94 shadow-[0_42px_140px_rgba(0,0,0,0.48)]">
        <div className="border-b border-white/10 bg-white/[0.035] px-5 py-4 sm:px-6">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <p className="text-xs uppercase tracking-[0.28em] text-slate-500">Verification object</p>
              <h2 className="mt-1 text-xl font-semibold text-white">MSCQR-7F42-91C8</h2>
            </div>
            <div className="flex flex-wrap gap-2">
              <Badge className="border-cyan-200/20 bg-cyan-200/10 text-cyan-100 hover:bg-cyan-200/10">
                Signed QR route
              </Badge>
              <StatusBadge tone="printConfirmed">Print confirmed</StatusBadge>
            </div>
          </div>
        </div>

        <div className="grid gap-0 lg:grid-cols-[0.85fr_1.15fr]">
          <div className="border-b border-white/10 p-5 sm:p-6 lg:border-b-0 lg:border-r">
            <div className="rounded-[1.4rem] border border-white/10 bg-[#05080c] p-4">
              <div className="flex items-center justify-between gap-3">
                <span className="font-mono text-xs text-slate-500">LABEL PREVIEW</span>
                <span className="rounded-full border border-emerald-200/20 bg-emerald-300/10 px-2 py-1 text-xs text-emerald-100">
                  active registry record
                </span>
              </div>
              <div className="mt-5 grid grid-cols-[132px_1fr] gap-4">
                <QrMotif />
                <div className="flex min-w-0 flex-col justify-between gap-4">
                  <div>
                    <p className="text-xs uppercase tracking-[0.22em] text-slate-500">Batch</p>
                    <p className="mt-1 font-mono text-lg text-white">B-2049</p>
                  </div>
                  <div>
                    <p className="text-xs uppercase tracking-[0.22em] text-slate-500">Product state</p>
                    <p className="mt-1 text-sm font-medium text-cyan-100">Print confirmed</p>
                  </div>
                  <div className="h-px bg-white/10" />
                  <p className="font-mono text-[11px] leading-5 text-slate-500">Reference ID: MSCQR-B2049</p>
                </div>
              </div>
            </div>

            <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-1">
              <StatusTile label="Public result" value="Authenticity check passed" tone="success" />
              <StatusTile label="Duplicate risk" value="Low / watch rules active" tone="watch" />
            </div>
          </div>

          <div className="p-5 sm:p-6">
            <div className="rounded-[1.4rem] border border-white/10 bg-white/[0.025] p-4">
              <div className="flex items-center justify-between gap-4">
                <div>
                  <p className="text-xs uppercase tracking-[0.24em] text-slate-500">State machine</p>
                  <p className="mt-1 text-sm text-slate-300">Label lifecycle before the response is generated.</p>
                </div>
                <span className="relative flex size-3">
                  <span className="absolute inline-flex size-full animate-ping rounded-full bg-cyan-300 opacity-30 motion-reduce:animate-none" />
                  <span className="relative inline-flex size-3 rounded-full bg-cyan-200" />
                </span>
              </div>

              <div className="mt-5 grid grid-cols-5 gap-2">
                {["Issued", "Assigned", "Printed", "Scanned", "Response"].map((item, index) => (
                  <div key={item} className="relative">
                    {index < 4 ? <div className="absolute left-1/2 top-4 h-px w-full bg-cyan-200/18" /> : null}
                    <div className="relative flex flex-col items-center gap-2">
                      <div
                        className={cn(
                          "flex size-8 items-center justify-center rounded-full border text-xs font-semibold",
                          index < 4
                            ? "border-cyan-200/30 bg-cyan-200/10 text-cyan-100"
                            : "border-emerald-200/30 bg-emerald-200/10 text-emerald-100",
                        )}
                      >
                        {index + 1}
                      </div>
                      <p className="text-center text-[10px] font-medium uppercase tracking-[0.12em] text-slate-400">
                        {item}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="mt-4 rounded-[1.4rem] border border-white/10 bg-[#05080c] p-4">
              <div className="flex items-center justify-between gap-3">
                <p className="text-xs uppercase tracking-[0.24em] text-slate-500">Audit trail</p>
                <p className="font-mono text-xs text-slate-500">latest event: first public verification</p>
              </div>
              <AuditTimeline items={auditEvents} className="mt-4" />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function QrMotif() {
  return (
    <div
      className="grid size-[132px] shrink-0 grid-cols-9 gap-1 rounded-2xl border border-white/10 bg-white/[0.03] p-3"
      aria-label="QR-inspired label geometry"
      role="img"
    >
      {Array.from({ length: 81 }, (_, index) => (
        <span
          key={index}
          className={cn(
            "rounded-[3px]",
            qrCellSet.has(index)
              ? index % 7 === 0
                ? "bg-cyan-200"
                : "bg-slate-200"
              : "bg-white/[0.035]",
          )}
        />
      ))}
    </div>
  );
}

function Signal({ label, value }: { label: string; value: string }) {
  return (
    <div className="border-l border-white/12 bg-white/[0.025] px-4 py-3">
      <p className="text-xs uppercase tracking-[0.2em] text-slate-500">{label}</p>
      <p className="mt-2 text-sm font-medium text-slate-100">{value}</p>
    </div>
  );
}

function StatusTile({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone: "success" | "watch";
}) {
  return (
    <div className="rounded-[1.25rem] border border-white/10 bg-white/[0.025] p-4">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-xs uppercase tracking-[0.2em] text-slate-500">{label}</p>
          <p className="mt-2 text-sm font-semibold text-white">{value}</p>
        </div>
        <span
          className={cn(
            "mt-1 size-2.5 rounded-full",
            tone === "success" ? "bg-emerald-300 shadow-[0_0_18px_rgba(110,231,183,0.45)]" : "bg-amber-300",
          )}
        />
      </div>
    </div>
  );
}

function LifecycleRail() {
  return (
    <section id="how-it-works" className="scroll-mt-28 border-b border-white/10 bg-[#080d13]">
      <div className="mx-auto w-full max-w-7xl px-4 py-20 lg:py-28">
        <div className="grid gap-10 lg:grid-cols-[0.38fr_0.62fr]">
          <div>
            <SectionEyebrow icon={Waypoints}>Verification lifecycle</SectionEyebrow>
            <SectionHeading>A QR label is only useful when the backend knows its state.</SectionHeading>
            <p className="mt-5 max-w-xl text-sm leading-7 text-slate-400">
              MSCQR treats a label as an operational record moving through issuance, assignment, print readiness,
              verification, duplicate classification, and audit review.
            </p>
          </div>

          <LabelLifecycleRail steps={lifecycleSteps} />
        </div>
      </div>
    </section>
  );
}

function ProblemSection() {
  const points = [
    "Uncontrolled printing creates weak trust before the product ever reaches a customer.",
    "First scans and duplicate scans need consistent handling across QR and manual lookup routes.",
    "Support teams need evidence, not screenshots detached from the label lifecycle.",
    "Manufacturers need visibility into state, ownership, scan behavior, and escalation history.",
  ] as const;

  return (
    <section className="border-b border-white/10">
      <div className="mx-auto grid w-full max-w-7xl gap-10 px-4 py-20 lg:grid-cols-[0.9fr_1.1fr] lg:py-28">
        <div>
          <SectionEyebrow icon={AlertTriangle}>Operational problem</SectionEyebrow>
          <h2 className="mt-6 text-balance text-4xl font-semibold leading-tight tracking-[-0.04em] text-white lg:text-6xl">
            QR codes are easy to copy. Verification systems are hard to govern.
          </h2>
        </div>

        <div className="rounded-[2rem] border border-white/10 bg-white/[0.035] p-6 lg:p-8">
          <p className="text-lg leading-8 text-slate-300">
            The printed mark is only the customer-facing surface. The trust work happens behind it: issuance policy,
            print confirmation, scan classification, duplicate review, and an audit path operators can defend.
          </p>
          <div className="mt-8 flex flex-col gap-4">
            {points.map((point) => (
              <div key={point} className="grid grid-cols-[28px_1fr] gap-4 border-t border-white/10 pt-4">
                <Split className="mt-1 size-4 text-amber-200" />
                <p className="text-sm leading-7 text-slate-300">{point}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

function CapabilityMatrix() {
  return (
    <section className="border-b border-white/10 bg-[#090f15]">
      <div className="mx-auto w-full max-w-7xl px-4 py-20 lg:py-28">
        <div className="grid gap-10 lg:grid-cols-[0.44fr_0.56fr] lg:items-end">
          <div>
            <SectionEyebrow icon={Layers3}>Platform capabilities</SectionEyebrow>
            <SectionHeading>Authentication operations need a registry, not a pile of generated codes.</SectionHeading>
          </div>
          <p className="max-w-2xl text-sm leading-7 text-slate-400 lg:justify-self-end">
            MSCQR organizes the lifecycle into concrete controls that manufacturers, licensees, and platform operators
            can use without turning public verification into an operator console.
          </p>
        </div>

        <div className="mt-12 overflow-hidden rounded-[2rem] border border-white/10 bg-[#05080c]">
          {capabilityGroups.map((group, index) => (
            <div
              key={group.title}
              className={cn("grid gap-0 lg:grid-cols-[0.32fr_0.68fr]", index > 0 && "border-t border-white/10")}
            >
              <div className="border-b border-white/10 bg-white/[0.035] p-5 lg:border-b-0 lg:border-r lg:p-6">
                <p className="font-mono text-xs uppercase tracking-[0.22em] text-slate-500">0{index + 1}</p>
                <h3 className="mt-3 text-xl font-semibold text-white">{group.title}</h3>
              </div>
              <div className="grid gap-px bg-white/10 sm:grid-cols-3">
                {group.capabilities.map((capability) => (
                  <div key={capability} className="bg-[#080d13] p-5">
                    <ClipboardCheck className="size-4 text-cyan-200" />
                    <p className="mt-4 text-sm font-medium leading-6 text-slate-100">{capability}</p>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>

      </div>
    </section>
  );
}

function RoleOperations() {
  return (
    <section id="operations" className="scroll-mt-28 border-b border-white/10">
      <div className="mx-auto w-full max-w-7xl px-4 py-20 lg:py-28">
        <div className="max-w-3xl">
          <SectionEyebrow icon={Factory}>Role-based operations</SectionEyebrow>
          <SectionHeading>Built for manufacturer control with room for licensees, operators, and consumers.</SectionHeading>
          <p className="mt-5 text-sm leading-7 text-slate-400">
            MSCQR is positioned for careful UK, India, and global product authentication rollouts where evidence quality
            matters more than generic QR campaign volume.
          </p>
        </div>

        <div className="mt-12 grid gap-5 lg:grid-cols-4">
          {roleOperations.map((role, index) => (
            <article
              key={role.audience}
              className={cn(
                "rounded-[1.75rem] border border-white/10 bg-white/[0.03] p-6",
                index === 0 && "lg:col-span-2 lg:row-span-2 lg:p-8",
              )}
            >
              <div className="flex items-start justify-between gap-4">
                <div className="flex size-11 items-center justify-center rounded-2xl border border-white/10 bg-[#0a1118]">
                  <role.icon className="size-5 text-cyan-200" />
                </div>
                {index === 0 ? (
                  <Badge className="border-cyan-200/20 bg-cyan-200/10 text-cyan-100 hover:bg-cyan-200/10">
                    Primary audience
                  </Badge>
                ) : null}
              </div>
              <h3 className={cn("mt-6 font-semibold text-white", index === 0 ? "text-3xl" : "text-xl")}>
                {role.audience}
              </h3>
              <p className="mt-3 text-sm leading-7 text-slate-400">{role.summary}</p>
              <div className="mt-6 flex flex-col gap-3">
                {role.items.map((item) => (
                  <div key={item} className="flex items-start gap-3 text-sm leading-6 text-slate-300">
                    <span className="mt-2 size-1.5 shrink-0 rounded-full bg-cyan-200/80" />
                    <span>{item}</span>
                  </div>
                ))}
              </div>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}

function TrustModel() {
  return (
    <section id="security" className="scroll-mt-28 border-b border-white/10 bg-[#080d13]">
      <div className="mx-auto grid w-full max-w-7xl gap-10 px-4 py-20 lg:grid-cols-[0.9fr_1.1fr] lg:py-28">
        <div>
          <SectionEyebrow icon={ShieldCheck}>Honest trust model</SectionEyebrow>
          <SectionHeading>MSCQR improves authentication by making label state and scan behavior reviewable.</SectionHeading>
          <p className="mt-5 max-w-xl text-sm leading-7 text-slate-400">
            The platform combines issued label records, controlled print state, public verification, duplicate review,
            and audit evidence. The claim is operational visibility, not magic ink.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <Button asChild className="bg-none bg-cyan-200 text-slate-950 hover:bg-cyan-100">
              <Link to="/trust">
                Open Trust Center
                <ArrowRight data-icon="inline-end" />
              </Link>
            </Button>
            <Button
              asChild
              variant="outline"
              className="border-white/10 bg-white/[0.04] text-slate-100 hover:bg-white/[0.08]"
            >
              <Link to="/request-access">
                Request access
                <ArrowRight data-icon="inline-end" />
              </Link>
            </Button>
          </div>
        </div>

        <div className="rounded-[2rem] border border-amber-200/15 bg-[linear-gradient(135deg,rgba(251,191,36,0.08),rgba(255,255,255,0.025)_42%,rgba(34,211,238,0.05))] p-6 lg:p-8">
          <TerminalSquare className="size-6 text-amber-200" />
          <blockquote className="mt-6 text-balance text-2xl font-semibold leading-10 tracking-[-0.025em] text-white">
            MSCQR does not pretend that a printed QR code is impossible to photograph or copy.
          </blockquote>
          <p className="mt-5 text-sm leading-7 text-slate-300">
            The platform is designed to make label state, scan history, duplicate behavior, and operational evidence
            visible and reviewable. That honesty is part of the security posture: teams can see what happened, classify
            risk, and support customers from evidence rather than guesswork.
          </p>

          <div className="mt-8 grid gap-3 sm:grid-cols-3">
            <TrustPillar icon={FileCheck2} title="Issued record" />
            <TrustPillar icon={PackageCheck} title="Print state" />
            <TrustPillar icon={AlertTriangle} title="Duplicate review" />
          </div>
        </div>
      </div>
    </section>
  );
}

function TrustPillar({ icon: Icon, title }: { icon: Icon; title: string }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-[#05080c]/70 p-4">
      <Icon className="size-4 text-cyan-200" />
      <p className="mt-3 text-sm font-medium text-slate-100">{title}</p>
    </div>
  );
}

function PublicVerificationCTA() {
  return (
    <section className="border-b border-white/10">
      <div className="mx-auto w-full max-w-7xl px-4 py-20 lg:py-28">
        <div className="overflow-hidden rounded-[2rem] border border-cyan-200/15 bg-[#05080c]">
          <div className="grid lg:grid-cols-[0.92fr_1.08fr]">
            <div className="p-6 lg:p-10">
              <SectionEyebrow icon={ScanLine}>Public verification front door</SectionEyebrow>
              <h2 className="mt-6 text-balance text-4xl font-semibold leading-tight tracking-[-0.04em] text-white lg:text-5xl">
                Checking a product should be simple. Governing that check should not be.
              </h2>
              <p className="mt-5 max-w-xl text-sm leading-7 text-slate-400">
                Consumers get a direct path to scan or enter a code. MSCQR keeps the operational policy, duplicate
                handling, and escalation evidence behind that result.
              </p>
              <Button asChild size="lg" className="mt-8 bg-none bg-cyan-200 text-slate-950 hover:bg-cyan-100">
                <Link to="/verify">
                  <ScanLine data-icon="inline-start" />
                  Verify a product
                </Link>
              </Button>
            </div>

            <div className="border-t border-white/10 bg-white/[0.025] p-6 lg:border-l lg:border-t-0 lg:p-10">
              <div className="grid gap-4 sm:grid-cols-2">
                {publicVerificationSteps.map((step, index) => (
                  <div key={step} className="rounded-[1.5rem] border border-white/10 bg-[#080d13] p-5">
                    <p className="font-mono text-xs uppercase tracking-[0.22em] text-slate-500">0{index + 1}</p>
                    <p className="mt-4 text-lg font-semibold text-white">{step}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function FinalCTA() {
  return (
    <section className="relative isolate overflow-hidden">
      <div className="pointer-events-none absolute inset-0 -z-10 bg-[radial-gradient(circle_at_50%_0%,rgba(34,211,238,0.14),transparent_28%)]" />
      <div className="mx-auto w-full max-w-5xl px-4 py-20 text-center lg:py-28">
        <p className="font-mono text-xs uppercase tracking-[0.28em] text-cyan-200/80">MSCQR public surface</p>
        <h2 className="mt-5 text-balance text-4xl font-semibold leading-tight tracking-[-0.04em] text-white lg:text-6xl">
          Start with a product check. Build toward governed authentication operations.
        </h2>
        <p className="mx-auto mt-5 max-w-2xl text-sm leading-7 text-slate-400">
          Give consumers a clear verification entry point while giving manufacturers and operators the lifecycle
          evidence needed to manage issued labels responsibly.
        </p>
        <div className="mt-8 flex flex-col justify-center gap-3 sm:flex-row">
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
          <Button
            asChild
            size="lg"
            variant="ghost"
            className="bg-transparent text-slate-300 hover:bg-white/[0.06] hover:text-white"
          >
            <Link to="/solutions/manufacturers">Explore manufacturer workflows</Link>
          </Button>
        </div>
      </div>
    </section>
  );
}

function SectionEyebrow({ children, icon: Icon }: { children: ReactNode; icon: Icon }) {
  return (
    <div className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.035] px-3 py-1 text-[11px] font-medium uppercase tracking-[0.22em] text-slate-400">
      <Icon className="size-3.5 text-cyan-200" />
      {children}
    </div>
  );
}

function SectionHeading({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <h2 className={cn("mt-5 text-balance text-3xl font-semibold leading-tight tracking-[-0.035em] text-white lg:text-5xl", className)}>
      {children}
    </h2>
  );
}
