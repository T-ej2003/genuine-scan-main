import { LegalDocumentLayout } from "@/components/trust/LegalDocumentLayout";

export default function PrivacyPolicy() {
  return (
    <LegalDocumentLayout
      title="Privacy Notice"
      updatedAt="14 Apr 2026"
      summary="This notice describes MSCQR's current handling of operator authentication, customer garment verification sessions, support diagnostics, optional observability, and hosted service delivery."
    >
      <h2>1. What this notice covers</h2>
      <p>
        MSCQR is a production web platform used by super admins, brand admins, garment manufacturers, and public customers
        verifying garments. This notice summarizes the categories of data the product currently handles so
        MSCQR administration can maintain the public notice.
      </p>

      <h2>2. Data MSCQR currently processes</h2>
      <ul>
        <li>Operator account data such as name, email, role, organization, and company associations.</li>
        <li>Authentication and session data used for secure sign-in and CSRF protection.</li>
        <li>Customer verification data such as email, verification session identifiers, and browser continuity state.</li>
        <li>Verification event data such as QR label code, garment label status, security signals, and timing.</li>
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
        <li>To record garment verification outcomes, suspicious scan signals, and operational history consistently.</li>
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
        Retention and deletion handling depends on account, verification, support, and operational record type. MSCQR
        administration should keep retention periods and deletion rules aligned with active customer agreements and legal
        requirements.
      </p>

      <h2>7. Support and incident evidence</h2>
      <p>
        When operators raise support issues, MSCQR can attach diagnostics, browser runtime issue signals, recent network
        log summaries, and screenshots. Public-facing privacy language and support policy wording must remain aligned
        with that implementation.
      </p>

      <h2>8. Contact and legal completion</h2>
      <p>
        For privacy questions or requests, contact MSCQR administration. Legal bases, rights handling, retention periods,
        and subprocessor disclosures should be reviewed periodically as the platform and operating regions evolve.
      </p>
    </LegalDocumentLayout>
  );
}
