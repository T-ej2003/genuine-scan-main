import { Link } from "react-router-dom";

import { LegalDocumentLayout } from "@/components/trust/LegalDocumentLayout";
import { HELP_SITE_CONFIG } from "@/help/site-config";

export default function PrivacyPolicy() {
  return (
    <LegalDocumentLayout
      title="Privacy Notice"
      updatedAt="5 May 2026"
      version="1.0"
      summary="This notice explains how MSCQR handles personal data for platform operators, brand and licensee administrators, manufacturer users, public product verifiers, and support or incident-reporting users."
    >
      <h2>1. Who is responsible</h2>
      <p>
        MSCQR is responsible for the product experience described in this notice. Enterprise customer agreements may
        define additional controller, processor, retention, or support responsibilities between MSCQR and the relevant
        organization.
      </p>
      <p>
        Privacy contact: <a href={`mailto:${HELP_SITE_CONFIG.dpoEmail}`}>{HELP_SITE_CONFIG.dpoEmail}</a>. If your
        organization has appointed a separate privacy or legal contact for MSCQR, use the contact details in your
        agreement or account materials.
      </p>

      <h2>2. People covered by this notice</h2>
      <ul>
        <li>Platform operators and super admins who manage MSCQR configuration, security, and governance.</li>
        <li>Brand, licensee, and organization administrators who manage inventory, batches, incidents, and reporting.</li>
        <li>Manufacturer users who receive assigned batches and use printing or connector workflows.</li>
        <li>Public verifiers or customers who scan or manually enter a product code.</li>
        <li>People who submit support tickets, diagnostics, screenshots, incident reports, or authenticity concerns.</li>
      </ul>

      <h2>3. Data MSCQR handles</h2>
      <ul>
        <li>Account data, including name, email address, role, organization, licensee, manufacturer, and access status.</li>
        <li>Authentication and security data, including cookie-backed sessions, CSRF tokens, login events, device signals, rate-limit signals, and audit logs.</li>
        <li>Inventory and QR data, including QR label codes, batch records, allocation history, status, scan events, and verification outcomes.</li>
        <li>Public verification data, including scan or lookup details, verification session identifiers, customer email when supplied, proof/session tokens, and ownership or claim continuity where used.</li>
        <li>Manufacturer printing data, including local printer readiness, selected printer identifiers, connector status, and calibration preferences when functional storage is allowed.</li>
        <li>Support and incident data, including issue descriptions, consent-to-contact choices, contact details, uploaded evidence, screenshots, browser diagnostics, network summaries, and runtime issue summaries.</li>
      </ul>

      <h2>4. Why MSCQR uses data</h2>
      <ul>
        <li>To authenticate users, enforce role-based permissions, and protect the platform from misuse.</li>
        <li>To generate, allocate, print, track, and verify QR labels for garments.</li>
        <li>To show public verifiers the current product verification status and collect reports where appropriate.</li>
        <li>To investigate suspicious scans, product concerns, support issues, and operational incidents.</li>
        <li>To operate manufacturer connector and printer-readiness workflows.</li>
        <li>To maintain auditability, security monitoring, service reliability, and customer support.</li>
      </ul>

      <h2>5. Cookies and browser storage</h2>
      <p>
        MSCQR uses necessary cookies and browser storage for secure sign-in, CSRF protection, public verification,
        fraud prevention, and consent records. Optional functional storage, analytics/performance storage, and marketing
        storage are controlled through cookie preferences. See the <Link to="/cookies">Cookie Notice</Link> for the
        current register and controls.
      </p>

      <h2>6. Service providers and external services</h2>
      <p>
        Current implementation evidence shows AWS-hosted infrastructure and object storage for core service delivery.
        MSCQR may also use configured SMTP/email providers for account, incident, and notification email delivery.
        Sentry frontend or backend monitoring may be used when DSNs are configured; frontend Sentry starts only after
        analytics/performance consent. Google may be used when a public verifier chooses Google sign-in, and reCAPTCHA
        server verification may be used for suspicious public verification or incident-reporting activity when enabled.
      </p>

      <h2>7. Support evidence</h2>
      <p>
        Support and incident workflows can include screenshots, diagnostics, runtime errors, recent network summaries,
        uploaded evidence, and contact details. Users should avoid submitting unnecessary personal data in free-text
        support fields or screenshots. MSCQR uses this evidence to diagnose issues, investigate reports, and communicate
        with users who have provided contact details or consent to contact.
      </p>

      <h2>8. Retention and deletion</h2>
      <p>
        Retention depends on the record type and the applicable organization agreement. Security, audit, verification,
        support, incident, and operational records may need different retention periods. Browser-side optional
        preference storage can be withdrawn from cookie preferences or cleared in the browser.
      </p>

      <h2>9. Your choices and requests</h2>
      <p>
        You can change optional cookie and browser-storage preferences from the footer or the{" "}
        <Link to="/cookies">Cookie Notice</Link>. For privacy questions, access or deletion requests, or correction
        requests, contact MSCQR at <a href={`mailto:${HELP_SITE_CONFIG.dpoEmail}`}>{HELP_SITE_CONFIG.dpoEmail}</a> or
        use the contact route provided by your organization.
      </p>

      <h2>10. Related terms</h2>
      <p>
        Use of MSCQR is also governed by the <Link to="/terms">Terms of Use</Link> and any applicable commercial or
        enterprise agreement.
      </p>
    </LegalDocumentLayout>
  );
}
