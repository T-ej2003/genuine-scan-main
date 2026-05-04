import { Link } from "react-router-dom";

import { Button } from "@/components/ui/button";
import { LegalDocumentLayout } from "@/components/trust/LegalDocumentLayout";
import { openCookiePreferences } from "@/lib/cookie-preferences-events";

export default function CookieNotice() {
  return (
    <LegalDocumentLayout
      title="Cookie Notice"
      updatedAt="5 May 2026"
      version="1.0"
      summary="This notice explains the cookies, localStorage, and sessionStorage MSCQR uses for secure authentication, public verification, fraud prevention, consent records, and optional browser preferences."
    >
      <h2>1. What this notice covers</h2>
      <p>
        MSCQR uses cookies and similar technologies when you use the platform, including browser cookies, localStorage,
        and sessionStorage. The current implementation does not use advertising cookies and does not load third-party
        marketing trackers from the audited frontend.
      </p>
      <p>
        Your choices apply to optional storage on this browser. Strictly necessary storage remains active because MSCQR
        needs it to provide secure sign-in, protect requests, support public verification, prevent abuse, and remember
        your consent choice.
      </p>

      <p>
        <Button type="button" onClick={openCookiePreferences}>
          Manage cookie preferences
        </Button>
      </p>

      <h2>2. Strictly necessary cookies and storage</h2>
      <p>These items are always on because the service cannot operate securely without them.</p>
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Purpose</th>
            <th>Typical duration</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>
              <code>aq_access</code>
            </td>
            <td>Cookie</td>
            <td>Operator/admin access session.</td>
            <td>Short-lived access window, currently 15 minutes by default.</td>
          </tr>
          <tr>
            <td>
              <code>aq_refresh</code>
            </td>
            <td>Cookie</td>
            <td>Operator/admin session renewal and continuity.</td>
            <td>Currently 30 days by default.</td>
          </tr>
          <tr>
            <td>
              <code>aq_csrf</code>
            </td>
            <td>Cookie</td>
            <td>CSRF protection for cookie-backed operator requests.</td>
            <td>Aligned to the active session flow.</td>
          </tr>
          <tr>
            <td>
              <code>mscqr_verify_session</code>
            </td>
            <td>Cookie</td>
            <td>Customer/public verification authentication after email, passkey, or Google verification.</td>
            <td>Currently 720 hours by default.</td>
          </tr>
          <tr>
            <td>
              <code>mscqr_verify_csrf</code>
            </td>
            <td>Cookie</td>
            <td>CSRF protection for customer verification session actions.</td>
            <td>Aligned to the customer verification session.</td>
          </tr>
          <tr>
            <td>
              <code>aq_vid</code>
            </td>
            <td>Cookie</td>
            <td>Anonymous public verification device identifier used for fraud prevention and request fingerprinting.</td>
            <td>Currently 1 year.</td>
          </tr>
          <tr>
            <td>
              <code>gs_device_claim</code>
            </td>
            <td>Cookie</td>
            <td>Device claim continuity for public verification and ownership interactions.</td>
            <td>Currently 1 year.</td>
          </tr>
          <tr>
            <td>
              <code>mscqr_verify_session_proof:&lt;sessionId&gt;</code>
            </td>
            <td>sessionStorage</td>
            <td>Proof-bound token for revealing protected verification-session details in the current tab.</td>
            <td>Browser tab/session lifetime.</td>
          </tr>
          <tr>
            <td>
              <code>mscqr_cookie_consent_state:v1</code>
            </td>
            <td>localStorage</td>
            <td>Stores your cookie and browser-storage choices.</td>
            <td>Until you change preferences or clear browser storage.</td>
          </tr>
        </tbody>
      </table>

      <h2>3. Functional preferences</h2>
      <p>
        Functional preferences are off unless you allow them. If enabled, MSCQR may store interface and workflow
        preferences that make repeated use easier but are not required for core authentication or verification.
      </p>
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Purpose</th>
            <th>Typical duration</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>
              <code>theme</code>
            </td>
            <td>localStorage</td>
            <td>Theme preference.</td>
            <td>Until changed, withdrawn, or cleared.</td>
          </tr>
          <tr>
            <td>
              <code>sidebar:state</code>
            </td>
            <td>Cookie</td>
            <td>Dashboard sidebar expanded/collapsed state.</td>
            <td>7 days.</td>
          </tr>
          <tr>
            <td>
              <code>manufacturer-printer-onboarding:v1:&lt;userId&gt;</code>
            </td>
            <td>localStorage</td>
            <td>Manufacturer printer onboarding dismissed/completed state.</td>
            <td>Until withdrawn or cleared.</td>
          </tr>
          <tr>
            <td>
              <code>manufacturer-printer-dialog-opened:v1:&lt;userId&gt;</code>
            </td>
            <td>sessionStorage</td>
            <td>Avoids repeatedly opening the printer dialog in the same browser tab.</td>
            <td>Browser tab/session lifetime.</td>
          </tr>
          <tr>
            <td>
              <code>printer-calibration:&lt;printerId&gt;</code>
            </td>
            <td>localStorage</td>
            <td>Local printer calibration profile for manufacturer printing.</td>
            <td>Until withdrawn or cleared.</td>
          </tr>
          <tr>
            <td>
              <code>aq_missing_help_requests</code>
            </td>
            <td>localStorage</td>
            <td>Local support/help search diagnostics capped by the app.</td>
            <td>Until overwritten, withdrawn, or cleared.</td>
          </tr>
        </tbody>
      </table>

      <h2>4. Analytics, performance, marketing, and advertising</h2>
      <p>
        MSCQR does not currently use advertising cookies or frontend marketing trackers in the audited codebase.
        Optional frontend performance and error monitoring, such as Sentry, starts only when configured and when you
        allow analytics and performance storage. Backend operational logs and security monitoring needed to run the
        service are handled separately from browser consent choices.
      </p>

      <h2>5. Changing your choices</h2>
      <p>
        You can reopen preferences from the footer on public and authenticated pages, or by using the button on this
        page. If you reject or withdraw a non-essential category, MSCQR removes the functional browser storage it owns
        from this browser where technically possible.
      </p>
      <p>
        Clearing your browser cookies or localStorage may also clear your consent record, in which case MSCQR will ask
        you again. Essential cookies may be recreated when you sign in, verify a product, or use security-protected
        product flows.
      </p>

      <h2>6. Related notices</h2>
      <p>
        Read the <Link to="/privacy">Privacy Notice</Link> for how MSCQR handles personal data and the{" "}
        <Link to="/terms">Terms of Use</Link> for product use rules.
      </p>
    </LegalDocumentLayout>
  );
}
