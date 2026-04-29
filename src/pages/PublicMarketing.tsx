import { type ElementType, type FormEvent, type ReactNode, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  AlertTriangle,
  ArrowRight,
  BadgeCheck,
  ClipboardCheck,
  Factory,
  Mail,
  QrCode,
  ScanLine,
  ShieldCheck,
  Shirt,
  Store,
  Users,
} from "lucide-react";

import { PublicShell } from "@/components/public/PublicShell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

const CONTACT_EMAIL = "administration@mscqr.com";

type Icon = ElementType;

type PageShellProps = {
  title: string;
  intro: string;
  children: ReactNode;
  actions?: ReactNode;
};

type Feature = {
  title: string;
  body: string;
  icon: Icon;
};

const platformFeatures: Feature[] = [
  {
    title: "QR labels for garments",
    body: "Prepare labels for clothing batches, collections, and brand-approved manufacturing runs.",
    icon: QrCode,
  },
  {
    title: "Print and attach workflow",
    body: "Give manufacturing teams a clear process to print, attach, and confirm garment labels.",
    icon: Factory,
  },
  {
    title: "Customer verification",
    body: "Let customers scan a garment and see a simple result before any optional follow-up steps.",
    icon: ScanLine,
  },
  {
    title: "Suspicious scan review",
    body: "Help teams review unusual repeat scans without overwhelming customers with technical details.",
    icon: AlertTriangle,
  },
];

const brandFeatures: Feature[] = [
  {
    title: "Protect brand trust",
    body: "Give customers a direct way to check whether a garment is genuine.",
    icon: Store,
  },
  {
    title: "Issue QR labels",
    body: "Prepare QR labels for clothing lines, drops, or approved manufacturing runs.",
    icon: QrCode,
  },
  {
    title: "Review scan patterns",
    body: "See when a label is scanned repeatedly or in ways that deserve attention.",
    icon: BadgeCheck,
  },
  {
    title: "Support customers",
    body: "Explain verification results clearly and give customers a path to report concerns.",
    icon: Users,
  },
];

const manufacturerFeatures: Feature[] = [
  {
    title: "Receive assigned labels",
    body: "Work from brand-approved QR labels intended for garment production.",
    icon: QrCode,
  },
  {
    title: "Print or attach tags",
    body: "Support factory workflows for garment tags, care labels, hang tags, or packaging labels.",
    icon: Shirt,
  },
  {
    title: "Confirm completion",
    body: "Mark print or attachment work complete so brands know labels reached production.",
    icon: ClipboardCheck,
  },
  {
    title: "Support verification",
    body: "Give brands better context when customers scan garments after purchase.",
    icon: Factory,
  },
];

const scanningSteps = [
  {
    title: "Scan the QR label",
    body: "A customer scans the QR label attached to a garment tag, care label, or hang tag.",
    icon: ScanLine,
  },
  {
    title: "See the result",
    body: "MSCQR shows whether the garment can be verified before asking anything else.",
    icon: ShieldCheck,
  },
  {
    title: "Check brand details",
    body: "The result can show brand or manufacturer information that helps the customer understand the item.",
    icon: Store,
  },
  {
    title: "Choose next steps",
    body: "A customer can optionally report a concern, sign in, or register the garment when supported.",
    icon: Users,
  },
] as const;

function PageShell({ title, intro, children, actions }: PageShellProps) {
  return (
    <PublicShell>
      <main>
        <section className="border-b border-border bg-white">
          <div className="mx-auto grid w-full max-w-7xl gap-10 px-4 py-16 lg:grid-cols-[0.68fr_0.32fr] lg:items-end lg:py-20">
            <div>
              <h1 className="max-w-4xl text-balance text-4xl font-semibold leading-tight text-foreground sm:text-5xl lg:text-6xl">
                {title}
              </h1>
              <p className="mt-6 max-w-3xl text-base leading-8 text-muted-foreground">{intro}</p>
              {actions ? <div className="mt-8 flex flex-col gap-3 sm:flex-row sm:flex-wrap">{actions}</div> : null}
            </div>
            <div className="rounded-3xl border border-moonlight-300 bg-moonlight-100 p-6">
              <div className="flex items-center gap-3">
                <img src="/brand/mscqr-mark.svg" alt="" className="size-10" aria-hidden="true" />
                <div>
                  <p className="text-sm font-semibold text-moonlight-900">MSCQR</p>
                  <p className="text-sm text-moonlight-900/75">Garment verification</p>
                </div>
              </div>
              <div className="mt-6 rounded-2xl bg-white p-5">
                <p className="text-sm font-semibold text-foreground">Made for clothing QR labels</p>
                <p className="mt-2 text-sm leading-6 text-muted-foreground">
                  A focused public experience for brands, manufacturers, and customers.
                </p>
              </div>
            </div>
          </div>
        </section>
        {children}
      </main>
    </PublicShell>
  );
}

function ContentBand({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <section className={cn("border-b border-border bg-mscqr-background", className)}>
      <div className="mx-auto w-full max-w-7xl px-4 py-16 lg:py-20">{children}</div>
    </section>
  );
}

function FeatureGrid({ items }: { items: Feature[] }) {
  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
      {items.map((item) => (
        <article key={item.title} className="rounded-2xl border border-border bg-white p-6 shadow-sm">
          <div className="flex size-11 items-center justify-center rounded-xl bg-accent text-accent-foreground">
            <item.icon className="size-5" />
          </div>
          <h2 className="mt-5 text-lg font-semibold text-foreground">{item.title}</h2>
          <p className="mt-3 text-sm leading-7 text-muted-foreground">{item.body}</p>
        </article>
      ))}
    </div>
  );
}

function PrimaryActions({ secondaryHref = "/verify", secondaryLabel = "Verify a Product" }: { secondaryHref?: string; secondaryLabel?: string }) {
  return (
    <>
      <Button asChild size="lg">
        <Link to="/request-access">
          Request Access
          <ArrowRight data-icon="inline-end" />
        </Link>
      </Button>
      <Button asChild size="lg" variant="outline">
        <Link to={secondaryHref}>{secondaryLabel}</Link>
      </Button>
    </>
  );
}

export function PlatformPage() {
  return (
    <PageShell
      title="Garment authentication workspace for brands and manufacturers."
      intro="MSCQR helps clothing teams prepare QR labels, support factory print and attachment workflows, let customers verify garments, and review suspicious scan activity."
      actions={<PrimaryActions secondaryHref="/how-scanning-works" secondaryLabel="See how scanning works" />}
    >
      <ContentBand>
        <FeatureGrid items={platformFeatures} />
      </ContentBand>
      <ContentBand className="bg-white">
        <TwoColumn
          title="Focused on clothing, not generic QR generation."
          body="MSCQR is built for garment labels and authenticity workflows. The public site, customer scan flow, and workspace language should stay focused on brands, manufacturers, garments, labels, scans, and customer trust."
        />
      </ContentBand>
    </PageShell>
  );
}

export function BrandsPage() {
  return (
    <PageShell
      title="QR label verification for clothing brands."
      intro="Protect brand trust, issue QR labels, let customers verify garments, and review suspicious scan patterns without turning your public experience into a technical console."
      actions={<PrimaryActions secondaryHref="/how-scanning-works" secondaryLabel="See how scanning works" />}
    >
      <ContentBand>
        <FeatureGrid items={brandFeatures} />
      </ContentBand>
      <ContentBand className="bg-white">
        <TwoColumn
          title="A customer-first result with brand visibility behind it."
          body="Customers should see whether a garment can be verified first. Brand teams can then review scan history, print confirmation, and unusual repeat activity inside the workspace."
          ctaHref="/request-access"
          ctaLabel="Request Access"
        />
      </ContentBand>
    </PageShell>
  );
}

export function GarmentManufacturersPage() {
  return (
    <PageShell
      title="Garment manufacturer workflows for QR labels."
      intro="Receive assigned QR labels, print or attach garment tags, confirm print completion, and support brand verification workflows from production to customer scan."
      actions={<PrimaryActions secondaryHref="/solutions/brands" secondaryLabel="For Brands" />}
    >
      <ContentBand>
        <FeatureGrid items={manufacturerFeatures} />
      </ContentBand>
      <ContentBand className="bg-white">
        <TwoColumn
          title="Make the production handoff easier to trust."
          body="A manufacturer should know which labels are assigned, what needs to be printed or attached, and when completion has been confirmed for the brand."
          ctaHref="/request-access"
          ctaLabel="Request Access"
        />
      </ContentBand>
    </PageShell>
  );
}

export function ManufacturersPage() {
  return <GarmentManufacturersPage />;
}

export function ApparelAuthenticityPage() {
  return (
    <PageShell
      title="Apparel authenticity and suspicious scan detection."
      intro="MSCQR is built for garment and clothing verification, not broad product categories. It helps brands and manufacturers connect QR labels, print confirmation, customer scans, and suspicious repeat activity."
      actions={<PrimaryActions secondaryHref="/verify" secondaryLabel="Verify a Product" />}
    >
      <ContentBand>
        <FeatureGrid
          items={[
            {
              title: "Garment-only focus",
              body: "Public language, workflows, and scan results are centered on clothing QR labels.",
              icon: Shirt,
            },
            {
              title: "Plain customer results",
              body: "Customers see a simple result first, then optional next steps when useful.",
              icon: ScanLine,
            },
            {
              title: "Brand and factory context",
              body: "Verification can reflect label status, manufacturer workflows, and brand identity.",
              icon: Factory,
            },
            {
              title: "Suspicious scan review",
              body: "Teams can review unusual repeat activity and support customers from clearer context.",
              icon: AlertTriangle,
            },
          ]}
        />
      </ContentBand>
    </PageShell>
  );
}

export function HowScanningWorksPage() {
  return (
    <PageShell
      title="How garment scanning works."
      intro="A customer scans the QR label, sees whether the garment is verified, checks brand or manufacturer information, and can optionally report a concern or register the garment when supported."
      actions={<PrimaryActions secondaryHref="/verify" secondaryLabel="Verify a Product" />}
    >
      <ContentBand>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {scanningSteps.map((step, index) => (
            <article key={step.title} className="rounded-2xl border border-border bg-white p-6 shadow-sm">
              <div className="flex items-center justify-between gap-3">
                <div className="flex size-11 items-center justify-center rounded-xl bg-accent text-accent-foreground">
                  <step.icon className="size-5" />
                </div>
                <span className="text-sm font-semibold text-primary">{index + 1}</span>
              </div>
              <h2 className="mt-5 text-lg font-semibold text-foreground">{step.title}</h2>
              <p className="mt-3 text-sm leading-7 text-muted-foreground">{step.body}</p>
            </article>
          ))}
        </div>
      </ContentBand>
      <ContentBand className="bg-white">
        <TwoColumn
          title="Result first, questions later."
          body="MSCQR should not force customers through a long questionnaire before showing the basic result unless security or business rules require it. Extra questions, sign-in, and registration belong behind optional next steps."
          ctaHref="/verify"
          ctaLabel="Verify a Product"
        />
      </ContentBand>
    </PageShell>
  );
}

export function RequestAccessPage() {
  return (
    <PageShell
      title="Request access to MSCQR."
      intro="Tell us about your clothing brand or garment manufacturing workflow. We will use your details to understand whether MSCQR is a good fit."
    >
      <ContentBand>
        <RequestAccessForm />
      </ContentBand>
    </PageShell>
  );
}

export function BlogPage() {
  return (
    <PageShell
      title="Garment authentication notes from MSCQR."
      intro="Practical guidance for clothing brands and garment manufacturers will appear here once reviewed. The public site should stay focused on real garment verification workflows."
      actions={<PrimaryActions secondaryHref="/solutions/apparel-authenticity" secondaryLabel="Apparel Authenticity" />}
    >
      <ContentBand>
        <FeatureGrid
          items={[
            {
              title: "Brand trust",
              body: "How customer verification can support clothing brand confidence.",
              icon: Store,
            },
            {
              title: "QR labels",
              body: "How garment teams can think about label creation, printing, and attachment.",
              icon: QrCode,
            },
            {
              title: "Suspicious scans",
              body: "How repeat scan patterns can help teams decide what to review.",
              icon: AlertTriangle,
            },
            {
              title: "Customer support",
              body: "How plain-language scan results can reduce confusion.",
              icon: Users,
            },
          ]}
        />
      </ContentBand>
    </PageShell>
  );
}

function TwoColumn({
  title,
  body,
  ctaHref,
  ctaLabel,
}: {
  title: string;
  body: string;
  ctaHref?: string;
  ctaLabel?: string;
}) {
  return (
    <div className="grid gap-8 lg:grid-cols-[0.58fr_0.42fr] lg:items-center">
      <div>
        <h2 className="text-3xl font-semibold leading-tight text-foreground lg:text-5xl">{title}</h2>
        <p className="mt-5 text-base leading-8 text-muted-foreground">{body}</p>
      </div>
      <div className="rounded-3xl border border-moonlight-300 bg-moonlight-100 p-6">
        <div className="rounded-2xl bg-white p-5">
          <p className="text-sm font-semibold text-foreground">Recommended next step</p>
          <p className="mt-2 text-sm leading-6 text-muted-foreground">
            Start with a focused access request so MSCQR can understand your garment volume, country, and workflow.
          </p>
          {ctaHref && ctaLabel ? (
            <Button asChild className="mt-5">
              <Link to={ctaHref}>{ctaLabel}</Link>
            </Button>
          ) : null}
        </div>
      </div>
    </div>
  );
}

type FormValues = {
  fullName: string;
  workEmail: string;
  company: string;
  role: string;
  volume: string;
  country: string;
  message: string;
};

const initialFormValues: FormValues = {
  fullName: "",
  workEmail: "",
  company: "",
  role: "",
  volume: "",
  country: "",
  message: "",
};

function RequestAccessForm() {
  const [values, setValues] = useState<FormValues>(initialFormValues);
  const [errors, setErrors] = useState<Partial<Record<keyof FormValues, string>>>({});
  const [readyToEmail, setReadyToEmail] = useState(false);

  const mailtoHref = useMemo(() => {
    const body = [
      `Full name: ${values.fullName}`,
      `Work email: ${values.workEmail}`,
      `Company / brand name: ${values.company}`,
      `Role: ${values.role}`,
      `Monthly garment volume: ${values.volume}`,
      `Country: ${values.country}`,
      "",
      "Message:",
      values.message,
    ].join("\n");

    return `mailto:${CONTACT_EMAIL}?subject=${encodeURIComponent("MSCQR Request Access")}&body=${encodeURIComponent(body)}`;
  }, [values]);

  const updateField = (field: keyof FormValues, value: string) => {
    setValues((current) => ({ ...current, [field]: value }));
    setReadyToEmail(false);
    setErrors((current) => ({ ...current, [field]: undefined }));
  };

  const validate = () => {
    const nextErrors: Partial<Record<keyof FormValues, string>> = {};
    if (!values.fullName.trim()) nextErrors.fullName = "Enter your full name.";
    if (!values.workEmail.trim()) nextErrors.workEmail = "Enter your work email.";
    if (values.workEmail.trim() && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(values.workEmail)) {
      nextErrors.workEmail = "Enter a valid work email.";
    }
    if (!values.company.trim()) nextErrors.company = "Enter your company or brand name.";
    if (!values.role.trim()) nextErrors.role = "Enter your role.";
    if (!values.volume.trim()) nextErrors.volume = "Enter your monthly garment volume.";
    if (!values.country.trim()) nextErrors.country = "Enter your country.";
    if (!values.message.trim()) nextErrors.message = "Add a short message.";
    return nextErrors;
  };

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const nextErrors = validate();
    setErrors(nextErrors);
    setReadyToEmail(Object.keys(nextErrors).length === 0);
  };

  return (
    <div className="grid gap-8 lg:grid-cols-[0.42fr_0.58fr]">
      <div>
        <h2 className="text-3xl font-semibold text-foreground">Tell us about your garment workflow.</h2>
        <p className="mt-4 text-sm leading-7 text-muted-foreground">
          There is no public self-serve signup connected here yet. This form checks the fields locally and prepares an
          email to MSCQR administration.
        </p>
        <div className="mt-6 rounded-2xl border border-border bg-white p-5">
          <div className="flex items-start gap-3">
            <Mail className="mt-1 size-5 text-primary" />
            <p className="text-sm leading-6 text-muted-foreground">
              Your email app will open after the form is complete. No information is stored by this page until a backend
              request-access endpoint is connected.
            </p>
          </div>
        </div>
      </div>

      <form onSubmit={handleSubmit} noValidate className="rounded-3xl border border-border bg-white p-6 shadow-sm">
        <div className="grid gap-5 sm:grid-cols-2">
          <FormField label="Full name" id="fullName" error={errors.fullName}>
            <Input
              id="fullName"
              value={values.fullName}
              onChange={(event) => updateField("fullName", event.target.value)}
              autoComplete="name"
              aria-invalid={Boolean(errors.fullName)}
              aria-describedby={errors.fullName ? "fullName-error" : undefined}
            />
          </FormField>
          <FormField label="Work email" id="workEmail" error={errors.workEmail}>
            <Input
              id="workEmail"
              type="email"
              value={values.workEmail}
              onChange={(event) => updateField("workEmail", event.target.value)}
              autoComplete="email"
              aria-invalid={Boolean(errors.workEmail)}
              aria-describedby={errors.workEmail ? "workEmail-error" : undefined}
            />
          </FormField>
          <FormField label="Company / brand name" id="company" error={errors.company}>
            <Input
              id="company"
              value={values.company}
              onChange={(event) => updateField("company", event.target.value)}
              autoComplete="organization"
              aria-invalid={Boolean(errors.company)}
              aria-describedby={errors.company ? "company-error" : undefined}
            />
          </FormField>
          <FormField label="Role" id="role" error={errors.role}>
            <Input
              id="role"
              value={values.role}
              onChange={(event) => updateField("role", event.target.value)}
              placeholder="Founder, operations manager, factory lead"
              aria-invalid={Boolean(errors.role)}
              aria-describedby={errors.role ? "role-error" : undefined}
            />
          </FormField>
          <FormField label="Monthly garment volume" id="volume" error={errors.volume}>
            <Input
              id="volume"
              value={values.volume}
              onChange={(event) => updateField("volume", event.target.value)}
              placeholder="Example: 25,000 garments"
              aria-invalid={Boolean(errors.volume)}
              aria-describedby={errors.volume ? "volume-error" : undefined}
            />
          </FormField>
          <FormField label="Country" id="country" error={errors.country}>
            <Input
              id="country"
              value={values.country}
              onChange={(event) => updateField("country", event.target.value)}
              autoComplete="country-name"
              aria-invalid={Boolean(errors.country)}
              aria-describedby={errors.country ? "country-error" : undefined}
            />
          </FormField>
        </div>

        <FormField label="Message" id="message" error={errors.message} className="mt-5">
          <textarea
            id="message"
            value={values.message}
            onChange={(event) => updateField("message", event.target.value)}
            rows={5}
            className="flex w-full rounded-xl border border-input bg-background px-3 py-3 text-base text-foreground shadow-sm ring-offset-background transition-colors placeholder:text-muted-foreground/80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/70 focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:bg-muted disabled:text-muted-foreground md:text-sm"
            placeholder="Tell us what garments you make or sell, how labels are printed, and what you want customers to verify."
            aria-invalid={Boolean(errors.message)}
            aria-describedby={errors.message ? "message-error" : undefined}
          />
        </FormField>

        <div className="mt-6 flex flex-col gap-3 sm:flex-row sm:items-center">
          <Button type="submit">Check form</Button>
          {readyToEmail ? (
            <Button asChild variant="outline">
              <a href={mailtoHref}>Open email draft</a>
            </Button>
          ) : null}
        </div>
        {readyToEmail ? (
          <p className="mt-4 text-sm leading-6 text-emerald-700">
            The form is complete. Open the email draft to send your request to MSCQR administration.
          </p>
        ) : null}
      </form>
    </div>
  );
}

function FormField({
  label,
  id,
  error,
  children,
  className,
}: {
  label: string;
  id: string;
  error?: string;
  children: ReactNode;
  className?: string;
}) {
  const errorId = `${id}-error`;

  return (
    <div className={className}>
      <label htmlFor={id} className="text-sm font-medium text-foreground">
        {label}
      </label>
      <div className="mt-2">{children}</div>
      {error ? (
        <p id={errorId} className="mt-2 text-sm text-destructive">
          {error}
        </p>
      ) : null}
    </div>
  );
}
