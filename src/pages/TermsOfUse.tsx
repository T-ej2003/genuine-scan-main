import { Link } from "react-router-dom";
import { Cookie, FileText, Printer, ShieldAlert, ShieldCheck } from "lucide-react";

import { LegalCallout, LegalDocumentLayout, type LegalSection } from "@/components/trust/LegalDocumentLayout";
import { HELP_SITE_CONFIG } from "@/help/site-config";

export default function TermsOfUse() {
  const sections: LegalSection[] = [
    {
      id: "who-terms-apply-to",
      title: "Who these terms apply to",
      children: (
        <p>
          These terms apply to MSCQR platform operators, brand or licensee administrators, manufacturer users, and public
          users who verify products or submit support and authenticity reports. Signed customer or enterprise agreements
          may add organization-specific terms.
        </p>
      ),
    },
    {
      id: "permitted-use",
      title: "Permitted use",
      children: (
        <ul>
          <li>Create, allocate, print, track, and manage QR labels for authorized garment workflows.</li>
          <li>Use manufacturer connector and printer features only for approved organization workstations and printers.</li>
          <li>Review scan activity, incidents, support tickets, governance records, and audit activity for authorized roles.</li>
          <li>Use public verification to check the current MSCQR status for a product code or QR label.</li>
        </ul>
      ),
    },
    {
      id: "verification-limits",
      title: "Verification limits",
      children: (
        <>
          <p>
            MSCQR provides verification context based on the platform record, QR label state, scan signals, and available
            product information. It does not guarantee that a physical garment can never be copied, tampered with, or
            misrepresented outside the MSCQR-controlled record.
          </p>
          <LegalCallout title="Verification is record-based" icon={ShieldCheck}>
            <p>
              Public verification results help users understand what MSCQR records currently show. They should not be
              treated as a complete physical inspection or a guarantee against every form of misuse.
            </p>
          </LegalCallout>
        </>
      ),
    },
    {
      id: "account-access",
      title: "Account and access responsibilities",
      children: (
        <ul>
          <li>Keep account credentials and invited-user links secure.</li>
          <li>Use only the permissions and organization scopes assigned to you.</li>
          <li>Do not share accounts, bypass access controls, interfere with audit logging, or attempt unauthorized access.</li>
          <li>Report suspected account compromise or unauthorized QR-label activity promptly.</li>
        </ul>
      ),
    },
    {
      id: "connector-printing",
      title: "Connector and local printing",
      children: (
        <>
          <p>
            Manufacturer printing workflows may require the MSCQR connector or local printer configuration. Users should
            install connector packages only from approved MSCQR routes, keep workstation access controlled, and use
            printing features only for authorized batch work.
          </p>
          <LegalCallout title="Printer setup is an authorized workflow" icon={Printer} tone="green">
            <p>
              Connector software and printer calibration should only be used on approved workstations and with batches
              assigned to the relevant organization.
            </p>
          </LegalCallout>
        </>
      ),
    },
    {
      id: "support-evidence",
      title: "Support, incidents, and evidence",
      children: (
        <p>
          Support and incident workflows may collect descriptions, screenshots, diagnostics, uploaded evidence, and
          contact information. Do not submit malicious files, abusive content, unrelated personal data, or reports you
          know to be false. Privacy handling is described in the <Link to="/privacy">Privacy Notice</Link>.
        </p>
      ),
    },
    {
      id: "prohibited-behavior",
      title: "Prohibited behavior",
      children: (
        <>
          <ul>
            <li>Do not use MSCQR to facilitate counterfeit, fraudulent, deceptive, or unlawful activity.</li>
            <li>Do not scrape, overload, reverse engineer, or interfere with MSCQR systems except where expressly authorized.</li>
            <li>Do not bypass rate limits, CSRF protection, authentication, printer trust checks, or tenant isolation.</li>
            <li>Do not upload malware or attempt to exfiltrate data from another user, organization, or customer.</li>
          </ul>
          <LegalCallout title="Security controls must stay intact" icon={ShieldAlert} tone="amber">
            <p>
              Attempts to bypass authentication, rate limits, tenant boundaries, printer trust checks, or audit logging
              may result in access removal and further investigation.
            </p>
          </LegalCallout>
        </>
      ),
    },
    {
      id: "changes-availability",
      title: "Changes, availability, and agreements",
      children: (
        <p>
          MSCQR may update product features, security controls, supported connector behavior, and public verification
          language as the platform evolves. Service levels, fees, support commitments, governing law, liability,
          termination, and data-processing terms may be defined in a signed agreement with the relevant organization.
        </p>
      ),
    },
    {
      id: "contact",
      title: "Contact",
      children: (
        <p>
          For terms or account-use questions, contact MSCQR at{" "}
          <a href={`mailto:${HELP_SITE_CONFIG.superAdminEmail}`}>{HELP_SITE_CONFIG.superAdminEmail}</a>. Cookie and
          browser-storage details are available in the <Link to="/cookies">Cookie Notice</Link>.
        </p>
      ),
    },
  ];

  return (
    <LegalDocumentLayout
      title="Terms of Use"
      tagline="Guidelines for responsible use of MSCQR."
      updatedAt="5 May 2026"
      version="1.0"
      summary="These terms describe responsible use of MSCQR for garment QR-label management, manufacturer printing, public product verification, support, incidents, governance, and audit workflows."
      sections={sections}
      relatedLinks={[
        { to: "/privacy", label: "Privacy Notice", icon: ShieldCheck },
        { to: "/cookies", label: "Cookie Notice", icon: Cookie },
        { to: "/trust", label: "Trust & Security", icon: FileText },
      ]}
    />
  );
}
