import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { Button } from "@/components/ui/button";

const CONSENT_KEY = "mscqr_cookie_consent_choice:v1";
const CONSENT_ENABLED = String(import.meta.env.VITE_ENABLE_COOKIE_CONSENT_UI || "").trim().toLowerCase() === "true";

type ConsentChoice = "accepted" | "essential_only";

const readStoredChoice = (): ConsentChoice | null => {
  if (typeof window === "undefined") return null;
  const raw = String(window.localStorage.getItem(CONSENT_KEY) || "").trim();
  if (raw === "accepted" || raw === "essential_only") return raw;
  return null;
};

const persistChoice = (choice: ConsentChoice) => {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(CONSENT_KEY, choice);
};

export function CookieConsentBanner() {
  const [choice, setChoice] = useState<ConsentChoice | null>(null);

  useEffect(() => {
    if (!CONSENT_ENABLED) return;
    setChoice(readStoredChoice());
  }, []);

  if (!CONSENT_ENABLED || choice) return null;

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
              persistChoice("essential_only");
              setChoice("essential_only");
            }}
          >
            Essential only
          </Button>
          <Button
            type="button"
            onClick={() => {
              persistChoice("accepted");
              setChoice("accepted");
            }}
          >
            Accept
          </Button>
        </div>
      </div>
    </div>
  );
}
