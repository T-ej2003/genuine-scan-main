import { LegalDocumentLayout } from "@/components/trust/LegalDocumentLayout";

export default function CookieNotice() {
  return (
    <LegalDocumentLayout
      title="Cookie Notice"
      updatedAt="14 Apr 2026"
      summary="This notice describes MSCQR's use of cookies and similar storage technologies, including operator auth, public verification continuity, help drafts, and printer workflow state."
    >
      <h2>1. What MSCQR currently uses</h2>
      <p>Current implementation evidence shows that MSCQR uses:</p>
      <ul>
        <li>authentication cookies for operator sign-in and CSRF protection</li>
        <li>verification-session cookies for public customer flows</li>
        <li>device and continuity identifiers for verification support</li>
        <li>local storage and session storage for support, onboarding, and printer workflow state</li>
        <li>optional Sentry observability when configured</li>
      </ul>

      <h2>2. Why MSCQR uses them</h2>
      <ul>
        <li>Keep operators securely signed in.</li>
        <li>Protect state-changing requests against CSRF.</li>
        <li>Let public users complete verification journeys without losing progress.</li>
        <li>Preserve support drafts, printer onboarding state, and calibration state where needed.</li>
        <li>Support operational troubleshooting and service reliability.</li>
      </ul>

      <h2>3. Current implementation categories</h2>
      <ul>
        <li>Strictly necessary security and authentication storage.</li>
        <li>Verification continuity and functional workflow storage.</li>
        <li>Operational diagnostics and support-related storage.</li>
      </ul>

      <h2>4. Consent and configuration</h2>
      <p>
        Cookie consent requirements depend on the deployed runtime stack, operating geography, and active platform
        configuration. MSCQR administration should keep consent UI and policy wording aligned with the live deployment.
      </p>

      <h2>5. Runtime verification</h2>
      <p>
        Runtime verification should include browser-level inspection because proxies, CDNs, or hosting layers can
        introduce cookies not visible in source code alone.
      </p>

      <h2>6. Updates</h2>
      <p>
        MSCQR may update this notice as storage categories, retention wording, consent rules, and user-choice language
        evolve.
      </p>
    </LegalDocumentLayout>
  );
}
