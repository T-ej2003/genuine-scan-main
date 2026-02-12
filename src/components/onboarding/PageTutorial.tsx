import React, { useEffect, useMemo, useState } from "react";
import { useLocation } from "react-router-dom";
import { Compass, Timer, CheckCircle2, Sparkles } from "lucide-react";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useAuth } from "@/contexts/AuthContext";
import type { UserRole } from "@/types";

type TutorialStep = {
  title: string;
  detail: string;
};

type TutorialConfig = {
  title: string;
  objective: string;
  etaSeconds: number;
  steps: TutorialStep[];
  roles?: UserRole[];
};

const TUTORIALS: Record<string, TutorialConfig> = {
  "/dashboard": {
    title: "Dashboard overview",
    objective: "Read operational health in under a minute.",
    etaSeconds: 45,
    steps: [
      { title: "Scan top KPI cards", detail: "Use each card as a shortcut to detailed pages." },
      { title: "Read operational snapshot", detail: "Track lifecycle completion and redemption conversion." },
      { title: "Use quick actions", detail: "Jump to the next operational task without searching menus." },
    ],
  },
  "/qr-requests": {
    title: "QR requests workflow",
    objective: "Create, review, and track allocation requests quickly.",
    etaSeconds: 50,
    roles: ["super_admin", "licensee_admin"],
    steps: [
      { title: "Create/request quantity", detail: "Raise requests with clear quantities and context notes." },
      { title: "Track status", detail: "Watch pending, approved, and rejected requests in one queue." },
      { title: "Finalize decisions", detail: "Approve or reject with a reason for clear audit trails." },
    ],
  },
  "/batches": {
    title: "Batch operations",
    objective: "Handle assignment and print workflows safely.",
    etaSeconds: 55,
    steps: [
      { title: "Filter and locate batch", detail: "Use search and status filters to find the right range." },
      { title: "Run the right action", detail: "Assign manufacturer, create print job, or export audit package." },
      { title: "Verify outcome", detail: "Confirm printed state and remaining quantity after each action." },
    ],
  },
  "/manufacturers": {
    title: "Manufacturer management",
    objective: "Manage factory accounts and operational readiness.",
    etaSeconds: 45,
    roles: ["super_admin", "licensee_admin"],
    steps: [
      { title: "Provision users", detail: "Create accounts with valid role, contact, and tenant mapping." },
      { title: "Control access", detail: "Deactivate/restore users based on production lifecycle." },
      { title: "Monitor hygiene", detail: "Keep only active manufacturers needed for current operations." },
    ],
  },
  "/qr-tracking": {
    title: "QR tracking",
    objective: "Detect anomalies with clear operational context.",
    etaSeconds: 55,
    steps: [
      { title: "Review batch summary", detail: "Understand status distribution before investigating logs." },
      { title: "Filter scan events", detail: "Narrow by code or batch to inspect suspicious activity." },
      { title: "Escalate with evidence", detail: "Use timeline context and metadata for fraud investigations." },
    ],
  },
  "/audit-logs": {
    title: "Audit operations",
    objective: "Trace who did what and when.",
    etaSeconds: 45,
    roles: ["super_admin", "licensee_admin"],
    steps: [
      { title: "Filter by action", detail: "Focus on high-impact events first." },
      { title: "Validate actor and details", detail: "Use user, entity, and detail fields for root-cause." },
      { title: "Export evidence", detail: "Download logs for external compliance or incident reports." },
    ],
  },
  "/licensees": {
    title: "Licensee administration",
    objective: "Operate tenant setup safely.",
    etaSeconds: 50,
    roles: ["super_admin"],
    steps: [
      { title: "Create tenant profile", detail: "Capture accurate prefix, support, and status metadata." },
      { title: "Maintain lifecycle", detail: "Update tenant records before assigning QR inventory." },
      { title: "Use scoped views", detail: "Apply tenant filters before reviewing downstream metrics." },
    ],
  },
  "/qr-codes": {
    title: "Master QR inventory",
    objective: "Search, export, and monitor global QR state.",
    etaSeconds: 50,
    roles: ["super_admin"],
    steps: [
      { title: "Filter by status", detail: "Use status and search to inspect exact subsets." },
      { title: "Validate integrity", detail: "Check generated codes, lifecycle states, and ownership." },
      { title: "Export when needed", detail: "Download scoped datasets for audits and reconciliations." },
    ],
  },
  "/account": {
    title: "Account settings",
    objective: "Keep credentials and profile operationally ready.",
    etaSeconds: 35,
    steps: [
      { title: "Review profile", detail: "Ensure email/name are current for audit clarity." },
      { title: "Update password", detail: "Rotate credentials periodically for security hygiene." },
      { title: "Confirm session", detail: "Return to operations with validated identity context." },
    ],
  },
};

const VERSION = "v1";

export function PageTutorial() {
  const location = useLocation();
  const { user, isAuthenticated } = useAuth();
  const [open, setOpen] = useState(false);

  const tutorial = useMemo(() => {
    const config = TUTORIALS[location.pathname];
    if (!config) return null;
    if (!user) return null;
    if (config.roles && !config.roles.includes(user.role)) return null;
    return config;
  }, [location.pathname, user]);

  const storageKey = useMemo(() => {
    if (!user || !tutorial) return null;
    return `aq:tutorial:${VERSION}:${user.id}:${location.pathname}`;
  }, [location.pathname, tutorial, user]);

  useEffect(() => {
    if (!isAuthenticated || !tutorial || !storageKey) {
      setOpen(false);
      return;
    }
    const seen = localStorage.getItem(storageKey) === "1";
    setOpen(!seen);
  }, [isAuthenticated, storageKey, tutorial]);

  if (!tutorial) return null;

  const markSeen = () => {
    if (storageKey) localStorage.setItem(storageKey, "1");
    setOpen(false);
  };

  const closeForNow = () => {
    setOpen(false);
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="max-w-2xl overflow-hidden border border-slate-200 p-0">
        <div className="bg-[linear-gradient(120deg,#052f2f_0%,#0f4661_52%,#0d3a56_100%)] px-6 py-5 text-white">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <span className="rounded-xl border border-white/25 bg-white/10 p-2.5">
                <Compass className="h-5 w-5" />
              </span>
              <div>
                <DialogTitle className="text-left text-xl font-semibold">{tutorial.title}</DialogTitle>
                <DialogDescription className="mt-1 text-left text-cyan-100/90">
                  {tutorial.objective}
                </DialogDescription>
              </div>
            </div>
            <Badge className="border-white/20 bg-white/15 text-white">
              <Timer className="mr-1 h-3.5 w-3.5" />
              {tutorial.etaSeconds}s quick guide
            </Badge>
          </div>
        </div>

        <div className="space-y-3 px-6 py-5">
          {tutorial.steps.map((step, index) => (
            <div key={step.title} className="rounded-lg border border-slate-200 bg-slate-50 px-4 py-3">
              <div className="flex items-start gap-3">
                <span className="mt-0.5 inline-flex h-6 w-6 items-center justify-center rounded-full bg-teal-600 text-xs font-semibold text-white">
                  {index + 1}
                </span>
                <div>
                  <p className="font-semibold text-slate-900">{step.title}</p>
                  <p className="text-sm text-slate-600">{step.detail}</p>
                </div>
              </div>
            </div>
          ))}

          <div className="flex items-center gap-2 rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-900">
            <CheckCircle2 className="h-4 w-4" />
            Complete these three checks and you can operate this page confidently.
          </div>
        </div>

        <DialogFooter className="flex items-center justify-between border-t border-slate-200 px-6 py-4">
          <div className="flex items-center gap-2 text-sm text-slate-500">
            <Sparkles className="h-4 w-4 text-teal-600" />
            Shown once per page for each user
          </div>
          <div className="flex gap-2">
            <Button variant="outline" onClick={closeForNow}>
              Remind me later
            </Button>
            <Button onClick={markSeen} className="bg-slate-900 text-white hover:bg-slate-800">
              Got it
            </Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
