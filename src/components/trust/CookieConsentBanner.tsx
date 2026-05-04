import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { Button } from "@/components/ui/button";
import { grantAllConsent, hasStoredConsentChoice, setEssentialOnlyConsent } from "@/lib/consent";

const CONSENT_ENABLED = String(import.meta.env.VITE_ENABLE_COOKIE_CONSENT_UI || "").trim().toLowerCase() === "true";

export function CookieConsentBanner() {
  const [choiceRecorded, setChoiceRecorded] = useState(() =>
    CONSENT_ENABLED ? hasStoredConsentChoice() : true
  );

  useEffect(() => {
    if (!CONSENT_ENABLED) return;
    setChoiceRecorded(hasStoredConsentChoice());
  }, []);

  if (!CONSENT_ENABLED || choiceRecorded) return null;

  return (
    <div className="fixed inset-x-0 bottom-0 z-50 border-t border-slate-200 bg-white/95 shadow-[0_-12px_30px_rgba(15,23,42,0.12)] backdrop-blur">
      <div className="mx-auto flex w-full max-w-7xl flex-col gap-4 px-4 py-4 md:flex-row md:items-center md:justify-between">
        <div className="max-w-3xl text-sm leading-6 text-slate-700">
          MSCQR uses cookies and similar technologies for secure sign-in, verification continuity, support diagnostics,
          and optional operational tooling. Review the current implementation in our{" "}
          <Link to="/cookies" className="font-medium text-slate-950 underline underline-offset-4">
            Cookie Notice
          </Link>{" "}
          and{" "}
          <Link to="/privacy" className="font-medium text-slate-950 underline underline-offset-4">
            Privacy Notice
          </Link>
          .
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Button
            type="button"
            variant="outline"
            onClick={() => {
              setEssentialOnlyConsent();
              setChoiceRecorded(true);
            }}
          >
            Essential only
          </Button>
          <Button
            type="button"
            onClick={() => {
              grantAllConsent();
              setChoiceRecorded(true);
            }}
          >
            Accept
          </Button>
        </div>
      </div>
    </div>
  );
}
