import { Link } from "react-router-dom";
import { BarChart3, FileText, ShieldCheck, SlidersHorizontal } from "lucide-react";

import { LegalCallout, LegalDocumentLayout, type LegalSection } from "@/components/trust/LegalDocumentLayout";
import { openCookiePreferences } from "@/lib/cookie-preferences-events";

type StorageRow = {
  name: string;
  type: string;
  purpose: string;
  duration: string;
};

const necessaryStorageRows: StorageRow[] = [
  {
    name: "aq_access",
    type: "Cookie",
    purpose: "Operator/admin access session.",
    duration: "Short-lived access window, currently 15 minutes by default.",
  },
  {
    name: "aq_refresh",
    type: "Cookie",
    purpose: "Operator/admin session renewal and continuity.",
    duration: "Currently 30 days by default.",
  },
  {
    name: "aq_csrf",
    type: "Cookie",
    purpose: "CSRF protection for cookie-backed operator requests.",
    duration: "Aligned to the active session flow.",
  },
  {
    name: "mscqr_verify_session",
    type: "Cookie",
    purpose: "Customer/public verification authentication after email, passkey, or Google verification.",
    duration: "Currently 720 hours by default.",
  },
  {
    name: "mscqr_verify_csrf",
    type: "Cookie",
    purpose: "CSRF protection for customer verification session actions.",
    duration: "Aligned to the customer verification session.",
  },
  {
    name: "aq_vid",
    type: "Cookie",
    purpose: "Anonymous public verification device identifier for fraud prevention and request fingerprinting.",
    duration: "Currently 1 year.",
  },
  {
    name: "gs_device_claim",
    type: "Cookie",
    purpose: "Device claim continuity for public verification and ownership interactions.",
    duration: "Currently 1 year.",
  },
  {
    name: "mscqr_verify_session_proof:<sessionId>",
    type: "sessionStorage",
    purpose: "Proof-bound token for revealing protected verification-session details in the current tab.",
    duration: "Browser tab/session lifetime.",
  },
  {
    name: "mscqr_cookie_consent_state:v1",
    type: "localStorage",
    purpose: "Stores your cookie and browser-storage choices.",
    duration: "Until you change preferences or clear browser storage.",
  },
];

const functionalStorageRows: StorageRow[] = [
  {
    name: "theme",
    type: "localStorage",
    purpose: "Theme preference.",
    duration: "Until changed, withdrawn, or cleared.",
  },
  {
    name: "sidebar:state",
    type: "Cookie",
    purpose: "Dashboard sidebar expanded/collapsed state.",
    duration: "7 days.",
  },
  {
    name: "manufacturer-printer-onboarding:v1:<userId>",
    type: "localStorage",
    purpose: "Manufacturer printer onboarding dismissed/completed state.",
    duration: "Until withdrawn or cleared.",
  },
  {
    name: "manufacturer-printer-dialog-opened:v1:<userId>",
    type: "sessionStorage",
    purpose: "Avoids repeatedly opening the printer dialog in the same browser tab.",
    duration: "Browser tab/session lifetime.",
  },
  {
    name: "printer-calibration:<printerId>",
    type: "localStorage",
    purpose: "Local printer calibration profile for manufacturer printing.",
    duration: "Until withdrawn or cleared.",
  },
  {
    name: "aq_missing_help_requests",
    type: "localStorage",
    purpose: "Local support/help search diagnostics capped by the app.",
    duration: "Until overwritten, withdrawn, or cleared.",
  },
];

function StorageRegister({ rows }: { rows: StorageRow[] }) {
  return (
    <>
      <div className="space-y-3 md:hidden">
        {rows.map((row) => (
          <div key={row.name} className="rounded-lg border border-slate-200 bg-slate-50 p-4">
            <code>{row.name}</code>
            <dl className="mt-3 space-y-2 text-sm">
              <div>
                <dt className="font-semibold text-slate-950">Type</dt>
                <dd>{row.type}</dd>
              </div>
              <div>
                <dt className="font-semibold text-slate-950">Purpose</dt>
                <dd>{row.purpose}</dd>
              </div>
              <div>
                <dt className="font-semibold text-slate-950">Typical duration</dt>
                <dd>{row.duration}</dd>
              </div>
            </dl>
          </div>
        ))}
      </div>

      <table className="hidden md:table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Purpose</th>
            <th>Typical duration</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.name}>
              <td>
                <code>{row.name}</code>
              </td>
              <td>{row.type}</td>
              <td>{row.purpose}</td>
              <td>{row.duration}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

export default function CookieNotice() {
  const sections: LegalSection[] = [
    {
      id: "what-this-covers",
      title: "What this notice covers",
      children: (
        <>
          <p>
            MSCQR uses cookies and similar technologies when you use the platform, including browser cookies,
            localStorage, and sessionStorage. These technologies help the service stay secure, remember consent choices,
            and support optional browser preferences when you allow them.
          </p>
          <p>
            The audited frontend does not use advertising cookies and does not load third-party marketing trackers.
            Your choices apply to optional storage on this browser.
          </p>
        </>
      ),
    },
    {
      id: "strictly-necessary",
      title: "Strictly necessary cookies and storage",
      children: (
        <>
          <p>
            These items are always on because MSCQR cannot provide secure sign-in, protected requests, public
            verification, fraud prevention, or consent records without them.
          </p>
          <LegalCallout title="Always active" icon={ShieldCheck} tone="green">
            <p>
              Necessary cookies and storage cannot be switched off in MSCQR. You can clear them in your browser, but
              essential items may be recreated when you sign in, verify a product, or use protected product flows.
            </p>
          </LegalCallout>
          <StorageRegister rows={necessaryStorageRows} />
        </>
      ),
    },
    {
      id: "functional-preferences",
      title: "Functional preferences",
      children: (
        <>
          <p>
            Functional preferences are optional. When enabled, MSCQR may remember interface and workflow choices that
            make repeated use easier but are not required for core authentication or verification.
          </p>
          <StorageRegister rows={functionalStorageRows} />
        </>
      ),
    },
    {
      id: "analytics-marketing",
      title: "Analytics, performance, marketing, and advertising",
      children: (
        <>
          <p>
            MSCQR does not currently use advertising cookies or frontend marketing trackers in the audited codebase.
            Optional frontend performance and error monitoring, such as Sentry, starts only when configured and when you
            allow analytics and performance storage.
          </p>
          <LegalCallout title="No fake trackers" icon={BarChart3}>
            <p>
              Analytics/performance and marketing categories are present so MSCQR can enforce future choices from one
              place. They do not mean those tools are active today.
            </p>
          </LegalCallout>
        </>
      ),
    },
    {
      id: "manage-preferences",
      title: "Managing your preferences",
      children: (
        <>
          <p>
            You can reopen preferences from the footer on public and authenticated pages, or by using the button on this
            page. If you reject or withdraw a non-essential category, MSCQR removes the functional browser storage it
            owns from this browser where technically possible.
          </p>
          <p>
            Clearing your browser cookies or localStorage may also clear your consent record, in which case MSCQR will
            ask you again.
          </p>
        </>
      ),
    },
    {
      id: "related-notices",
      title: "Related notices",
      children: (
        <p>
          Read the <Link to="/privacy">Privacy Notice</Link> for how MSCQR handles personal data and the{" "}
          <Link to="/terms">Terms of Use</Link> for product use rules.
        </p>
      ),
    },
  ];

  return (
    <LegalDocumentLayout
      title="Cookie Notice"
      tagline="Understanding how and why we use cookies and browser storage."
      updatedAt="5 May 2026"
      version="1.0"
      summary="This notice explains the cookies, localStorage, and sessionStorage MSCQR uses for secure authentication, public verification, fraud prevention, consent records, and optional browser preferences."
      sections={sections}
      primaryAction={{ label: "Manage cookie preferences", onClick: openCookiePreferences, icon: SlidersHorizontal }}
      relatedLinks={[
        { to: "/privacy", label: "Privacy Notice", icon: ShieldCheck },
        { to: "/terms", label: "Terms of Use", icon: FileText },
      ]}
    />
  );
}
