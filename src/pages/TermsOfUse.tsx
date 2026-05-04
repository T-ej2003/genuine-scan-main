import { Link } from "react-router-dom";

import { LegalDocumentLayout } from "@/components/trust/LegalDocumentLayout";
import { HELP_SITE_CONFIG } from "@/help/site-config";

export default function TermsOfUse() {
  return (
    <LegalDocumentLayout
      title="Terms of Use"
      updatedAt="5 May 2026"
      version="1.0"
      summary="These terms describe responsible use of MSCQR for garment QR-label management, manufacturer printing, public product verification, support, incidents, governance, and audit workflows."
    >
      <h2>1. Who these terms apply to</h2>
      <p>
        These terms apply to MSCQR platform operators, brand or licensee administrators, manufacturer users, and public
        users who verify products or submit support and authenticity reports. Signed customer or enterprise agreements
        may add organization-specific terms.
      </p>

      <h2>2. Permitted use</h2>
      <ul>
        <li>Create, allocate, print, track, and manage QR labels for authorized garment workflows.</li>
        <li>Use manufacturer connector and printer features only for approved organization workstations and printers.</li>
        <li>Review scan activity, incidents, support tickets, governance records, and audit activity for authorized roles.</li>
        <li>Use public verification to check the current MSCQR status for a product code or QR label.</li>
      </ul>

      <h2>3. Verification limits</h2>
      <p>
        MSCQR provides verification context based on the platform record, QR label state, scan signals, and available
        product information. It does not guarantee that a physical garment can never be copied, tampered with, or
        misrepresented outside the MSCQR-controlled record.
      </p>

      <h2>4. Account and access responsibilities</h2>
      <ul>
        <li>Keep account credentials and invited-user links secure.</li>
        <li>Use only the permissions and organization scopes assigned to you.</li>
        <li>Do not share accounts, bypass access controls, interfere with audit logging, or attempt unauthorized access.</li>
        <li>Report suspected account compromise or unauthorized QR-label activity promptly.</li>
      </ul>

      <h2>5. Connector and local printing</h2>
      <p>
        Manufacturer printing workflows may require the MSCQR connector or local printer configuration. Users should
        install connector packages only from approved MSCQR routes, keep workstation access controlled, and use printing
        features only for authorized batch work.
      </p>

      <h2>6. Support, incidents, and evidence</h2>
      <p>
        Support and incident workflows may collect descriptions, screenshots, diagnostics, uploaded evidence, and
        contact information. Do not submit malicious files, abusive content, unrelated personal data, or reports you know
        to be false. Privacy handling is described in the <Link to="/privacy">Privacy Notice</Link>.
      </p>

      <h2>7. Prohibited behavior</h2>
      <ul>
        <li>Do not use MSCQR to facilitate counterfeit, fraudulent, deceptive, or unlawful activity.</li>
        <li>Do not scrape, overload, reverse engineer, or interfere with MSCQR systems except where expressly authorized.</li>
        <li>Do not bypass rate limits, CSRF protection, authentication, printer trust checks, or tenant isolation.</li>
        <li>Do not upload malware or attempt to exfiltrate data from another user, organization, or customer.</li>
      </ul>

      <h2>8. Changes, availability, and agreements</h2>
      <p>
        MSCQR may update product features, security controls, supported connector behavior, and public verification
        language as the platform evolves. Service levels, fees, support commitments, governing law, liability,
        termination, and data-processing terms may be defined in a signed agreement with the relevant organization.
      </p>

      <h2>9. Contact</h2>
      <p>
        For terms or account-use questions, contact MSCQR at{" "}
        <a href={`mailto:${HELP_SITE_CONFIG.superAdminEmail}`}>{HELP_SITE_CONFIG.superAdminEmail}</a>. Cookie and
        browser-storage details are available in the <Link to="/cookies">Cookie Notice</Link>.
      </p>
    </LegalDocumentLayout>
  );
}
