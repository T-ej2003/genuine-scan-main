import { LegalDocumentLayout } from "@/components/trust/LegalDocumentLayout";

export default function CookieNotice() {
  return (
    <LegalDocumentLayout
      title="Cookie Notice"
      updatedAt="14 Apr 2026"
      summary="This draft notice reflects MSCQR's current implementation of cookies and similar storage technologies, including operator auth, public verification continuity, help drafts, and printer workflow state."
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

      <h2>4. Consent implementation status</h2>
      <p>
        MSCQR now includes feature-flagged consent UI plumbing for launch preparation. It remains disabled by default
        until legal review confirms the final live consent requirement for the deployed runtime stack and operating
        geography.
      </p>

      <h2>5. Runtime verification still required</h2>
      <p>
        Final production proof still depends on browser-level inspection because proxies, CDNs, or hosting layers can
        introduce cookies not visible in source code alone. The launch audit manual verification tracker contains the
        exact evidence collection steps.
      </p>

      <h2>6. Final legal completion still required</h2>
      <p>
        Exact classification, final retention wording, consent rules, and user-choice language require lawyer approval
        before this notice is treated as final public policy text.
      </p>
    </LegalDocumentLayout>
  );
}
