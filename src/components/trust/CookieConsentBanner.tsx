import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { SlidersHorizontal } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { COOKIE_PREFERENCES_OPEN_EVENT } from "@/lib/cookie-preferences-events";
import {
  CONSENT_CHANGED_EVENT,
  grantAllConsent,
  hasStoredConsentChoice,
  readConsentState,
  setEssentialOnlyConsent,
  type ConsentState,
  writeConsentState,
} from "@/lib/consent";
import { cn } from "@/lib/utils";

type ConsentDraft = ConsentState["categories"];

type CategoryRow = {
  id: keyof ConsentDraft;
  title: string;
  status: string;
  description: string;
};

const optionalCategories: CategoryRow[] = [
  {
    id: "functional",
    title: "Functional preferences",
    status: "Active when enabled",
    description:
      "Saves non-essential interface choices such as theme, sidebar state, printer onboarding, printer calibration, and local help diagnostics.",
  },
  {
    id: "analytics",
    title: "Analytics and performance",
    status: "No product analytics active by default",
    description:
      "Allows optional frontend performance/error monitoring such as Sentry when a production DSN is configured. MSCQR does not add advertising or product analytics trackers here.",
  },
  {
    id: "marketing",
    title: "Marketing and advertising",
    status: "Not currently used",
    description:
      "Reserved for future marketing or advertising technologies. MSCQR does not currently use marketing or advertising cookies in the audited frontend.",
  },
];

const readDraft = (): ConsentDraft => readConsentState().categories;

export function CookieConsentBanner() {
  const [choiceRecorded, setChoiceRecorded] = useState(() => hasStoredConsentChoice());
  const [preferencesOpen, setPreferencesOpen] = useState(false);
  const [draft, setDraft] = useState<ConsentDraft>(() => readDraft());

  useEffect(() => {
    const openPreferences = () => {
      setDraft(readDraft());
      setPreferencesOpen(true);
    };
    const syncConsent = (event: Event) => {
      setChoiceRecorded(hasStoredConsentChoice());
      const detail = (event as CustomEvent<ConsentState>).detail;
      if (detail?.categories) setDraft(detail.categories);
    };

    window.addEventListener(COOKIE_PREFERENCES_OPEN_EVENT, openPreferences);
    window.addEventListener(CONSENT_CHANGED_EVENT, syncConsent);
    return () => {
      window.removeEventListener(COOKIE_PREFERENCES_OPEN_EVENT, openPreferences);
      window.removeEventListener(CONSENT_CHANGED_EVENT, syncConsent);
    };
  }, []);

  const recordChoice = (state: ConsentState) => {
    setDraft(state.categories);
    setChoiceRecorded(true);
    setPreferencesOpen(false);
  };

  const acceptAll = () => recordChoice(grantAllConsent());
  const rejectNonEssential = () => recordChoice(setEssentialOnlyConsent());
  const savePreferences = () => recordChoice(writeConsentState(draft));

  return (
    <>
      {!choiceRecorded ? (
        <div className="fixed inset-x-0 bottom-0 z-50 border-t border-slate-200 bg-white/95 shadow-[0_-12px_30px_rgba(15,23,42,0.12)] backdrop-blur">
          <div className="mx-auto flex w-full max-w-7xl flex-col gap-4 px-4 py-4 md:flex-row md:items-center md:justify-between">
            <div className="max-w-3xl text-sm leading-6 text-slate-700">
              MSCQR uses necessary cookies and similar technologies for secure sign-in, verification, fraud prevention,
              and consent records. Functional, analytics/performance, and marketing storage stays off unless you allow
              it. Read the{" "}
              <Link to="/cookies" className="font-medium text-slate-950 underline underline-offset-4">
                Cookie Notice
              </Link>{" "}
              or{" "}
              <Link to="/privacy" className="font-medium text-slate-950 underline underline-offset-4">
                Privacy Notice
              </Link>
              .
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <Button type="button" variant="outline" onClick={rejectNonEssential}>
                Reject non-essential
              </Button>
              <Button type="button" variant="outline" onClick={() => setPreferencesOpen(true)} className="gap-2">
                <SlidersHorizontal className="h-4 w-4" />
                Manage preferences
              </Button>
              <Button type="button" onClick={acceptAll}>
                Accept all
              </Button>
            </div>
          </div>
        </div>
      ) : null}

      <Dialog
        open={preferencesOpen}
        onOpenChange={(open) => {
          setPreferencesOpen(open);
          if (open) setDraft(readDraft());
        }}
      >
        <DialogContent className="max-w-2xl">
          <DialogHeader className="border-b border-slate-200 px-6 pb-4 pt-6">
            <DialogTitle>Cookie preferences</DialogTitle>
            <DialogDescription>
              Choose which optional cookies and similar browser storage MSCQR may use on this device.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-3 px-6">
            <div className="rounded-lg border border-slate-200 bg-slate-50 p-4">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <h3 className="text-sm font-semibold text-slate-950">Strictly necessary</h3>
                  <p className="mt-1 text-sm leading-6 text-slate-600">
                    Required for secure sign-in, CSRF protection, public verification continuity, fraud prevention,
                    and remembering this consent choice.
                  </p>
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  <span className="text-xs font-medium uppercase text-slate-500">Always on</span>
                  <Switch checked disabled aria-label="Strictly necessary cookies are always on" />
                </div>
              </div>
            </div>

            {optionalCategories.map((category) => (
              <div key={category.id} className="rounded-lg border border-slate-200 bg-white p-4">
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <Label htmlFor={`cookie-category-${category.id}`} className="text-sm font-semibold text-slate-950">
                      {category.title}
                    </Label>
                    <p className="mt-1 text-xs font-medium uppercase text-slate-500">{category.status}</p>
                    <p className="mt-2 text-sm leading-6 text-slate-600">{category.description}</p>
                  </div>
                  <Switch
                    id={`cookie-category-${category.id}`}
                    checked={draft[category.id]}
                    onCheckedChange={(checked) => {
                      setDraft((current) => ({ ...current, [category.id]: checked }));
                    }}
                    aria-label={`${category.title} consent`}
                    className={cn("mt-1", draft[category.id] ? "data-[state=checked]:bg-slate-950" : "")}
                  />
                </div>
              </div>
            ))}
          </div>

          <DialogFooter className="gap-2 border-t border-slate-200 px-6 pb-6 pt-4 sm:space-x-0">
            <Button type="button" variant="outline" onClick={rejectNonEssential}>
              Reject non-essential
            </Button>
            <Button type="button" variant="outline" onClick={savePreferences}>
              Save preferences
            </Button>
            <Button type="button" onClick={acceptAll}>
              Accept all
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
