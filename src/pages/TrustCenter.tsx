import { Link } from "react-router-dom";
import { AlertTriangle, ArrowRight, ClipboardCheck, History, QrCode, ScanLine, ShieldCheck } from "lucide-react";

import { PublicShell } from "@/components/public/PublicShell";
import { Button } from "@/components/ui/button";

const trustChecks = [
  {
    title: "Label status",
    body: "MSCQR checks whether a garment QR label is known and whether it is ready for customer verification.",
    icon: QrCode,
  },
  {
    title: "Print confirmation",
    body: "When supported by the workflow, MSCQR can use print completion as part of the verification context.",
    icon: ClipboardCheck,
  },
  {
    title: "Scan history",
    body: "The platform can compare a scan with previous activity for the same garment label.",
    icon: History,
  },
  {
    title: "Suspicious repeat activity",
    body: "Unusual repeat scans can be surfaced for brand review instead of hidden from the team.",
    icon: AlertTriangle,
  },
] as const;

export default function TrustCenter() {
  return (
    <PublicShell>
      <main>
        <section className="border-b border-border bg-white">
          <div className="mx-auto grid w-full max-w-7xl gap-10 px-4 py-16 lg:grid-cols-[0.64fr_0.36fr] lg:items-end lg:py-20">
            <div>
              <h1 className="max-w-4xl text-balance text-4xl font-semibold leading-tight text-foreground sm:text-5xl lg:text-6xl">
                Trust & Security for garment verification.
              </h1>
              <p className="mt-6 max-w-3xl text-base leading-8 text-muted-foreground">
                MSCQR is honest about QR labels: a printed QR code can be photographed or copied. The platform helps
                brands detect misuse by checking label status, print confirmation, scan history, and suspicious scan
                patterns.
              </p>
              <div className="mt-8 flex flex-col gap-3 sm:flex-row sm:flex-wrap">
                <Button asChild size="lg">
                  <Link to="/request-access">
                    Request Access
                    <ArrowRight data-icon="inline-end" />
                  </Link>
                </Button>
                <Button asChild size="lg" variant="outline">
                  <Link to="/verify">
                    <ScanLine data-icon="inline-start" />
                    Verify Product
                  </Link>
                </Button>
              </div>
            </div>
            <div className="rounded-3xl border border-moonlight-300 bg-moonlight-100 p-6">
              <ShieldCheck className="size-9 text-primary" />
              <p className="mt-5 text-xl font-semibold text-foreground">Clear results, reviewable context.</p>
              <p className="mt-3 text-sm leading-7 text-muted-foreground">
                Customers get plain-language verification. Brands get a better signal when scan activity deserves
                review.
              </p>
            </div>
          </div>
        </section>

        <section className="border-b border-border bg-mscqr-background">
          <div className="mx-auto w-full max-w-7xl px-4 py-16 lg:py-20">
            <div className="max-w-3xl">
              <h2 className="text-3xl font-semibold leading-tight text-foreground lg:text-5xl">
                What MSCQR checks before and after a customer scan.
              </h2>
              <p className="mt-4 text-base leading-7 text-muted-foreground">
                The public result should stay simple. The workspace can keep more detail for brand and manufacturer
                teams who need to review suspicious scans.
              </p>
            </div>
            <div className="mt-10 grid gap-4 md:grid-cols-2 lg:grid-cols-4">
              {trustChecks.map((item) => (
                <article key={item.title} className="rounded-2xl border border-border bg-white p-6 shadow-sm">
                  <div className="flex size-11 items-center justify-center rounded-xl bg-accent text-accent-foreground">
                    <item.icon className="size-5" />
                  </div>
                  <h3 className="mt-5 text-lg font-semibold text-foreground">{item.title}</h3>
                  <p className="mt-3 text-sm leading-7 text-muted-foreground">{item.body}</p>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section className="border-b border-border bg-white">
          <div className="mx-auto grid w-full max-w-7xl gap-10 px-4 py-16 lg:grid-cols-[0.5fr_0.5fr] lg:py-20">
            <div>
              <h2 className="text-3xl font-semibold leading-tight text-foreground lg:text-5xl">
                What MSCQR does not claim.
              </h2>
              <p className="mt-5 text-base leading-8 text-muted-foreground">
                MSCQR does not claim that a QR code cannot be copied. It gives brands and manufacturers better context
                so they can decide when a scan result looks genuine, uncertain, or suspicious.
              </p>
            </div>
            <div className="rounded-3xl border border-amber-200 bg-amber-50 p-6">
              <div className="flex items-start gap-3">
                <AlertTriangle className="mt-1 size-5 text-amber-700" />
                <div>
                  <h3 className="text-lg font-semibold text-amber-950">Plain-language security posture</h3>
                  <p className="mt-3 text-sm leading-7 text-amber-900">
                    The right promise is not “impossible to copy.” The right promise is clearer verification, better
                    scan visibility, and simpler recovery when something looks wrong.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="bg-mscqr-background">
          <div className="mx-auto w-full max-w-4xl px-4 py-16 text-center lg:py-20">
            <h2 className="text-3xl font-semibold leading-tight text-foreground lg:text-5xl">
              Build customer trust without overclaiming security.
            </h2>
            <p className="mx-auto mt-5 max-w-2xl text-base leading-7 text-muted-foreground">
              Use MSCQR to give customers a simple garment check and give your team a clearer way to review suspicious
              scan activity.
            </p>
            <div className="mt-8 flex flex-col justify-center gap-3 sm:flex-row">
              <Button asChild size="lg">
                <Link to="/request-access">Request Access</Link>
              </Button>
              <Button asChild size="lg" variant="outline">
                <Link to="/how-scanning-works">See how scanning works</Link>
              </Button>
            </div>
          </div>
        </section>
      </main>
    </PublicShell>
  );
}
