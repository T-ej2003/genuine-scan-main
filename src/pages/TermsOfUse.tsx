import { LegalDocumentLayout } from "@/components/trust/LegalDocumentLayout";

export default function TermsOfUse() {
  return (
    <LegalDocumentLayout
      title="Terms of Use"
      updatedAt="14 Apr 2026"
      summary="These terms describe MSCQR's product behavior, role model, and responsible-use expectations for product authentication workflows."
    >
      <h2>1. Who these terms are for</h2>
      <p>
        MSCQR is used by internal platform administrators, licensee administrators, manufacturers, and public users who
        verify products. Customer-specific commercial terms may add further rights and responsibilities.
      </p>

      <h2>2. Intended use of MSCQR</h2>
      <ul>
        <li>Operate governed QR issuance and verification workflows.</li>
        <li>Support manufacturer-side printing and operational tracking.</li>
        <li>Help operators manage incidents, support, governance, and audit activity.</li>
        <li>Allow customers or consumers to verify a product through the public verification journey.</li>
      </ul>

      <h2>3. Important current product limits</h2>
      <ul>
        <li>MSCQR provides governed verification and audit evidence based on current platform state.</li>
        <li>MSCQR does not claim to make a physical item impossible to counterfeit without additional security layers.</li>
        <li>Manual code lookup is weaker than signed-label verification where signed proof is available.</li>
      </ul>

      <h2>4. Account and access responsibilities</h2>
      <ul>
        <li>Operators are responsible for keeping their credentials secure.</li>
        <li>Manufacturers must only use supported connector packages and approved printing environments.</li>
        <li>Users must not attempt to bypass permissions, misuse support channels, or interfere with verification flows.</li>
      </ul>

      <h2>5. Connector and local install terms</h2>
      <p>
        MSCQR distributes a local print connector for manufacturer-side workflows where authorized by an organization.
        Users should install only the connector package provided through approved MSCQR channels and follow the setup
        guidance for their printing environment.
      </p>

      <h2>6. Support and incident handling</h2>
      <p>
        Support and incident workflows may require logs, screenshots, and operational details to diagnose issues.
        Final service-level language, support hours, escalation commitments, and liability framing still require legal
        and operational approval.
      </p>

      <h2>7. Prohibited behavior</h2>
      <ul>
        <li>Do not misuse QR issuance or verification features for fraudulent activity.</li>
        <li>Do not upload malicious files or abusive content through support or incident flows.</li>
        <li>Do not attempt to bypass rate limits, permission controls, or auditing controls.</li>
      </ul>

      <h2>8. Updates and commercial agreements</h2>
      <p>
        Governing law, liability, termination, commercial terms, acceptable-use language, and dispute handling may be
        further defined in signed agreements between MSCQR and the relevant organization.
      </p>
    </LegalDocumentLayout>
  );
}
