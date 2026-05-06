import { Link } from "react-router-dom";
import { Cookie, FileText, ShieldCheck, UserCheck } from "lucide-react";

import { LegalCallout, LegalDocumentLayout, type LegalSection } from "@/components/trust/LegalDocumentLayout";
import { HELP_SITE_CONFIG } from "@/help/site-config";
import { openCookiePreferences } from "@/lib/cookie-preferences-events";

export default function PrivacyPolicy() {
  const sections: LegalSection[] = [
    {
      id: "who-is-responsible",
      title: "Who is responsible",
      children: (
        <>
          <p>
            MSCQR is responsible for the product experience described in this notice. Enterprise customer agreements may
            define additional controller, processor, retention, or support responsibilities between MSCQR and the
            relevant organization.
          </p>
          <p>
            Privacy contact: <a href={`mailto:${HELP_SITE_CONFIG.dpoEmail}`}>{HELP_SITE_CONFIG.dpoEmail}</a>. If your
            organization has appointed a separate privacy or legal contact for MSCQR, use the contact details in your
            agreement or account materials.
          </p>
        </>
      ),
    },
    {
      id: "who-this-covers",
      title: "Who this notice covers",
      children: (
        <ul>
          <li>Platform operators and super admins who manage MSCQR configuration, security, and governance.</li>
          <li>Brand, licensee, and organization administrators who manage inventory, batches, incidents, and reporting.</li>
          <li>Manufacturer users who receive assigned batches and use printing or connector workflows.</li>
          <li>Public verifiers or customers who scan or manually enter a product code.</li>
          <li>People who submit support tickets, diagnostics, screenshots, incident reports, or authenticity concerns.</li>
        </ul>
      ),
    },
    {
      id: "data-we-handle",
      title: "Data MSCQR handles",
      children: (
        <ul>
          <li>Account data, including name, email address, role, organization, licensee, manufacturer, and access status.</li>
          <li>Authentication and security data, including cookie-backed sessions, CSRF tokens, login events, device signals, rate-limit signals, and audit logs.</li>
          <li>Inventory and QR data, including QR label codes, batch records, allocation history, status, scan events, and verification outcomes.</li>
          <li>Public verification data, including scan or lookup details, verification session identifiers, customer email when supplied, proof/session tokens, and ownership or claim continuity where used.</li>
          <li>Manufacturer printing data, including local printer readiness, selected printer identifiers, connector status, and calibration preferences when functional storage is allowed.</li>
          <li>Support and incident data, including issue descriptions, consent-to-contact choices, contact details, uploaded evidence, screenshots, browser diagnostics, network summaries, and runtime issue summaries.</li>
        </ul>
      ),
    },
    {
      id: "why-we-use-data",
      title: "Why MSCQR uses data",
      children: (
        <ul>
          <li>To authenticate users, enforce role-based permissions, and protect the platform from misuse.</li>
          <li>To generate, allocate, print, track, and verify QR labels for garments.</li>
          <li>To show public verifiers the current product verification status and collect reports where appropriate.</li>
          <li>To investigate suspicious scans, product concerns, support issues, and operational incidents.</li>
          <li>To operate manufacturer connector and printer-readiness workflows.</li>
          <li>To maintain auditability, security monitoring, service reliability, and customer support.</li>
        </ul>
      ),
    },
    {
      id: "cookies-storage",
      title: "Cookies and browser storage",
      children: (
        <>
          <p>
            MSCQR uses necessary cookies and browser storage for secure sign-in, CSRF protection, public verification,
            fraud prevention, and consent records. Optional functional storage, analytics/performance storage, and
            marketing storage are controlled through cookie preferences.
          </p>
          <LegalCallout title="Your optional choices stay off until allowed" icon={Cookie}>
            <p>
              Optional functional, analytics/performance, and marketing storage is disabled until you consent. See the{" "}
              <Link to="/cookies">Cookie Notice</Link> for the current register and controls.
            </p>
          </LegalCallout>
        </>
      ),
    },
    {
      id: "service-providers",
      title: "Service providers and external services",
      children: (
        <p>
          Current implementation evidence shows AWS-hosted infrastructure and object storage for core service delivery.
          MSCQR may also use configured SMTP/email providers for account, incident, and notification email delivery.
          Sentry frontend or backend monitoring may be used when DSNs are configured; frontend Sentry starts only after
          analytics/performance consent. Google may be used when a public verifier chooses Google sign-in, and reCAPTCHA
          server verification may be used for suspicious public verification or incident-reporting activity when enabled.
        </p>
      ),
    },
    {
      id: "support-evidence",
      title: "Support and incident evidence",
      children: (
        <p>
          Support and incident workflows can include screenshots, diagnostics, runtime errors, recent network summaries,
          uploaded evidence, and contact details. Users should avoid submitting unnecessary personal data in free-text
          support fields or screenshots. MSCQR uses this evidence to diagnose issues, investigate reports, and
          communicate with users who have provided contact details or consent to contact.
        </p>
      ),
    },
    {
      id: "retention-deletion",
      title: "Retention and deletion",
      children: (
        <p>
          Retention depends on the record type and the applicable organization agreement. Security, audit, verification,
          support, incident, and operational records may need different retention periods. Browser-side optional
          preference storage can be withdrawn from cookie preferences or cleared in the browser.
        </p>
      ),
    },
    {
      id: "rights-choices",
      title: "Your choices and requests",
      children: (
        <>
          <LegalCallout title="Common privacy choices" icon={UserCheck}>
            <ul>
              <li>Access: you can request a copy of personal data MSCQR handles about you.</li>
              <li>Correction: you can ask MSCQR to correct inaccurate data.</li>
              <li>Deletion: you can request deletion where legally allowable.</li>
              <li>Objection: you can object to certain processing, such as marketing.</li>
              <li>Withdrawal of consent: you can change optional cookie preferences at any time.</li>
            </ul>
          </LegalCallout>
          <p>
            You can change optional cookie and browser-storage preferences from the footer or the{" "}
            <Link to="/cookies">Cookie Notice</Link>. For privacy questions, access or deletion requests, or correction
            requests, contact MSCQR at <a href={`mailto:${HELP_SITE_CONFIG.dpoEmail}`}>{HELP_SITE_CONFIG.dpoEmail}</a>{" "}
            or use the contact route provided by your organization.
          </p>
        </>
      ),
    },
    {
      id: "related-terms",
      title: "Related terms",
      children: (
        <p>
          Use of MSCQR is also governed by the <Link to="/terms">Terms of Use</Link> and any applicable commercial or
          enterprise agreement.
        </p>
      ),
    },
  ];

  return (
    <LegalDocumentLayout
      title="Privacy Notice"
      tagline="Your trust matters. Here is how MSCQR handles personal data."
      updatedAt="5 May 2026"
      version="1.0"
      summary="This notice explains how MSCQR handles personal data for platform operators, brand and licensee administrators, manufacturer users, public product verifiers, and support or incident-reporting users."
      sections={sections}
      primaryAction={{ label: "Manage cookie preferences", onClick: openCookiePreferences, icon: Cookie }}
      relatedLinks={[
        { to: "/cookies", label: "Cookie Notice", icon: Cookie },
        { to: "/terms", label: "Terms of Use", icon: FileText },
      ]}
    />
  );
}
