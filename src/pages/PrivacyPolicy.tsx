import { LegalDocumentLayout } from "@/components/trust/LegalDocumentLayout";

export default function PrivacyPolicy() {
  return (
    <LegalDocumentLayout
      title="Privacy Notice"
      updatedAt="14 Apr 2026"
      summary="This draft notice reflects MSCQR's current implementation: operator authentication, customer verification sessions, support diagnostics, optional observability, and AWS-hosted service delivery."
    >
      <h2>1. What this draft covers</h2>
      <p>
        MSCQR is a production web platform used by super admins, licensee admins, manufacturers, and public customers
        or consumers verifying products. This draft summarizes the categories of data the product currently handles so
        legal counsel can finalize the public notice.
      </p>

      <h2>2. Data MSCQR currently processes</h2>
      <ul>
        <li>Operator account data such as name, email, role, organization, and licensee associations.</li>
        <li>Authentication and session data used for secure sign-in and CSRF protection.</li>
        <li>Customer verification data such as email, verification session identifiers, and device continuity state.</li>
        <li>Verification event data such as QR code, lifecycle status, IP-derived security signals, and timing.</li>
        <li>Support and incident data such as issue summaries, diagnostics, screenshots, and uploaded evidence.</li>
        <li>Connector and printer-operational data used to help manufacturer-side printing workflows.</li>
      </ul>

      <h2>3. Device and browser-side storage</h2>
      <p>
        MSCQR stores and reads cookies, local storage, and session storage for secure sign-in, verification continuity,
        UI state, help-request drafts, printer onboarding state, and calibration state. See the Cookie Notice for the
        current implementation inventory.
      </p>

      <h2>4. Why MSCQR uses this data</h2>
      <ul>
        <li>To authenticate operators and protect the application against misuse or request forgery.</li>
        <li>To let public users complete a verification journey without losing state between steps.</li>
        <li>To record product verification outcomes, fraud signals, and operational evidence consistently.</li>
        <li>To allow operators to submit actionable support or incident reports with sufficient context.</li>
        <li>To operate manufacturer connector and printer readiness workflows.</li>
      </ul>

      <h2>5. Current hosting and service providers</h2>
      <p>
        Current implementation evidence indicates AWS-hosted infrastructure for the application, database, and object
        storage. Frontend and backend observability may use Sentry when DSNs are configured. Final public disclosure of
        subprocessors, hosting regions, and transfer wording requires legal review.
      </p>

      <h2>6. Retention and deletion</h2>
      <p>
        Retention and deletion handling is still being finalized for launch. Engineering implementation notes and the
        audit artifacts currently track that work. This section must be completed with final retention periods and
        deletion rules before public launch.
      </p>

      <h2>7. Support and incident evidence</h2>
      <p>
        When operators raise support issues, MSCQR can attach diagnostics, browser runtime issue signals, recent network
        log summaries, and screenshots. Public-facing privacy language and support policy wording must remain aligned
        with that implementation.
      </p>

      <h2>8. Contact and legal completion</h2>
      <p>
        Final privacy-contact details, legal bases, rights handling, retention periods, and subprocessor tables must be
        completed by counsel before this page is treated as final public policy text.
      </p>
    </LegalDocumentLayout>
  );
}
