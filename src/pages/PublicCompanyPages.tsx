import { Link } from "react-router";
import { Factory, Mail, MessageSquare, ShieldCheck, Shirt, Users } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  CONTACT_EMAIL,
  ContentBand,
  FeatureGrid,
  PageShell,
  PrimaryActions,
  TwoColumn,
} from "@/pages/PublicMarketing";

export function AboutPage() {
  return (
    <PageShell
      title="About MSCQR."
      intro="MSCQR is a garment authentication QR platform for brands, manufacturers, licensees, and authenticity teams that need clearer verification workflows around clothing labels."
      actions={<PrimaryActions secondaryHref="/contact" secondaryLabel="Contact MSCQR" />}
    >
      <ContentBand>
        <FeatureGrid
          items={[
            {
              title: "Garment-first platform",
              body: "MSCQR focuses on clothing QR labels, customer verification, suspicious scan review, and brand support workflows.",
              icon: Shirt,
            },
            {
              title: "Built for brand trust",
              body: "Brands can connect QR label status, production context, customer scans, and concern reports in one operating model.",
              icon: ShieldCheck,
            },
            {
              title: "Manufacturer-ready",
              body: "Manufacturers can work with assigned labels, printing routes, and completion confirmation for approved garment batches.",
              icon: Factory,
            },
            {
              title: "Plain customer experience",
              body: "Customers get a clear scan result and a route to report concerns when a product, seller, or label looks suspicious.",
              icon: Users,
            },
          ]}
        />
      </ContentBand>
      <ContentBand className="bg-white">
        <TwoColumn
          title="Official MSCQR website and product identity."
          body="MSCQR.com is the official public website for MSCQR. The platform is designed for garment authenticity teams that need secure QR labels, customer scan flows, and review workflows without presenting generic QR-code generator claims."
          ctaHref="/request-access"
          ctaLabel="Request Access"
        />
      </ContentBand>
    </PageShell>
  );
}

export function ContactPage() {
  return (
    <PageShell
      title="Contact MSCQR."
      intro="Contact MSCQR about garment authentication QR labels, manufacturer workflows, scan review, customer support, or platform access."
      actions={<PrimaryActions secondaryHref="/about" secondaryLabel="About MSCQR" />}
    >
      <ContentBand>
        <div className="grid gap-8 lg:grid-cols-[0.42fr_0.58fr]">
          <div>
            <h2 className="text-3xl font-semibold text-foreground">Talk to the MSCQR team.</h2>
            <p className="mt-4 text-sm leading-7 text-muted-foreground">
              Use the contact channel below for platform questions, access requests, brand onboarding, manufacturer
              workflows, and privacy or legal routing.
            </p>
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <article className="rounded-3xl border border-border bg-white p-6 shadow-sm">
              <Mail className="size-6 text-primary" />
              <h2 className="mt-5 text-lg font-semibold text-foreground">Email</h2>
              <p className="mt-3 text-sm leading-7 text-muted-foreground">
                Send operational, brand, manufacturer, or access enquiries to MSCQR administration.
              </p>
              <Button asChild className="mt-5">
                <a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a>
              </Button>
            </article>
            <article className="rounded-3xl border border-border bg-white p-6 shadow-sm">
              <MessageSquare className="size-6 text-primary" />
              <h2 className="mt-5 text-lg font-semibold text-foreground">Access request</h2>
              <p className="mt-3 text-sm leading-7 text-muted-foreground">
                Share your garment volume, country, label workflow, and team role so MSCQR can review fit.
              </p>
              <Button asChild variant="outline" className="mt-5">
                <Link to="/request-access">Request Access</Link>
              </Button>
            </article>
          </div>
        </div>
      </ContentBand>
    </PageShell>
  );
}
