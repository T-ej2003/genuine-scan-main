import React, { useEffect, useMemo, useRef, useState } from "react";
import { AlertTriangle, Bug, Camera, Loader2, SendHorizontal } from "lucide-react";

import { useAuth } from "@/contexts/AuthContext";
import { useToast } from "@/hooks/use-toast";
import apiClient from "@/lib/api-client";
import {
  buildSupportDiagnosticsPayload,
  captureSupportScreenshot,
  formatSupportIssueSubmissionError,
  getSupportNetworkLogs,
  getSupportRuntimeIssues,
  onSupportIssue,
  reportSupportRuntimeIssue,
  type SupportRuntimeIssue,
} from "@/lib/support-diagnostics";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";

const AUTO_POPUP_COOLDOWN_MS = 30_000;

export function SupportIssueLauncher() {
  const { user } = useAuth();
  const { toast } = useToast();

  const isEligible = user?.role === "licensee_admin" || user?.role === "manufacturer";

  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [capturing, setCapturing] = useState(false);
  const [screenshotFile, setScreenshotFile] = useState<File | null>(null);
  const [screenshotPreviewUrl, setScreenshotPreviewUrl] = useState<string | null>(null);
  const [activeIssue, setActiveIssue] = useState<SupportRuntimeIssue | null>(null);
  const [manualMode, setManualMode] = useState(true);
  const lastAutoPopupAtRef = useRef<number>(0);

  useEffect(() => {
    if (!isEligible) return;
    const onError = (event: ErrorEvent) => {
      const message = String(event.message || "Unexpected app error");
      reportSupportRuntimeIssue({
        source: "runtime",
        message,
        stack: event.error?.stack ? String(event.error.stack) : undefined,
      });
    };
    const onUnhandled = (event: PromiseRejectionEvent) => {
      const reason = event.reason;
      const message =
        reason instanceof Error
          ? reason.message
          : typeof reason === "string"
            ? reason
            : "Unhandled promise rejection";
      reportSupportRuntimeIssue({
        source: "runtime",
        message,
        stack: reason instanceof Error && reason.stack ? String(reason.stack) : undefined,
      });
    };
    window.addEventListener("error", onError);
    window.addEventListener("unhandledrejection", onUnhandled);
    return () => {
      window.removeEventListener("error", onError);
      window.removeEventListener("unhandledrejection", onUnhandled);
    };
  }, [isEligible]);

  useEffect(() => {
    if (!isEligible) return;
    const off = onSupportIssue((issue) => {
      const now = Date.now();
      if (now - lastAutoPopupAtRef.current < AUTO_POPUP_COOLDOWN_MS) return;
      lastAutoPopupAtRef.current = now;
      setManualMode(false);
      setActiveIssue(issue);
      setTitle(`Issue detected: ${issue.message.slice(0, 120)}`);
      setDescription(
        "We detected an issue and pre-collected diagnostics. Add what you were doing, then send this report to super admin."
      );
      setOpen(true);
    });
    return () => {
      off();
    };
  }, [isEligible]);

  useEffect(() => {
    if (!open || !isEligible) return;
    if (screenshotFile || capturing) return;
    setCapturing(true);
    captureSupportScreenshot()
      .then((file) => {
        if (!file) return;
        setScreenshotFile(file);
      })
      .finally(() => setCapturing(false));
  }, [open, screenshotFile, capturing, isEligible]);

  useEffect(() => {
    if (!screenshotFile) {
      setScreenshotPreviewUrl(null);
      return;
    }
    const nextUrl = URL.createObjectURL(screenshotFile);
    setScreenshotPreviewUrl(nextUrl);
    return () => URL.revokeObjectURL(nextUrl);
  }, [screenshotFile]);

  const networkLogCount = useMemo(() => getSupportNetworkLogs().length, [open, submitting]);
  const runtimeIssueCount = useMemo(() => getSupportRuntimeIssues().length, [open, submitting]);

  if (!isEligible) return null;

  const openManualDialog = () => {
    setManualMode(true);
    setActiveIssue(null);
    setTitle("Need help with an issue in MSCQR");
    setDescription("What were you trying to do?");
    setOpen(true);
  };

  const resetDialog = () => {
    setActiveIssue(null);
    setManualMode(true);
    setTitle("");
    setDescription("");
    setScreenshotFile(null);
    setScreenshotPreviewUrl(null);
  };

  const submit = async () => {
    const summary = title.trim();
    if (summary.length < 5) {
      toast({ title: "Add a short summary", description: "Please describe the issue in at least 5 characters.", variant: "destructive" });
      return;
    }

    setSubmitting(true);
    try {
      const diagnostics: Record<string, unknown> = buildSupportDiagnosticsPayload();
      if (activeIssue) diagnostics.triggerIssue = activeIssue;

      const form = new FormData();
      form.append("title", summary);
      form.append("description", description.trim());
      form.append("sourcePath", `${window.location.pathname}${window.location.search}`);
      form.append("pageUrl", window.location.href);
      form.append("autoDetected", String(!manualMode));
      form.append("diagnostics", JSON.stringify(diagnostics));
      if (screenshotFile) {
        form.append("screenshot", screenshotFile);
      }

      const res = await apiClient.createSupportIssueReport(form);
      if (!res.success) {
        toast({
          title: "Could not submit report",
          description: formatSupportIssueSubmissionError(res.error),
          variant: "destructive",
        });
        return;
      }

      toast({
        title: "Report sent to super admin",
        description: "Thanks. We included diagnostics to speed up debugging.",
      });
      setOpen(false);
      resetDialog();
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <>
      <Button variant="ghost" className="mr-1 gap-2" onClick={openManualDialog}>
        <Bug className="h-4 w-4 text-muted-foreground" />
        <span className="hidden sm:inline">Report issue</span>
      </Button>

      <Dialog
        open={open}
        onOpenChange={(next) => {
          setOpen(next);
          if (!next) resetDialog();
        }}
      >
        <DialogContent className="sm:max-w-[640px]">
          <DialogHeader>
            <DialogTitle>Report an issue</DialogTitle>
            <DialogDescription>
              {manualMode
                ? "Send this directly to super admin. We will attach logs automatically."
                : "We detected an error and prefilled diagnostics for you."}
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <Alert className="border-slate-200 bg-slate-50">
              <AlertTitle>Privacy notice for support evidence</AlertTitle>
              <AlertDescription>
                MSCQR attaches recent diagnostics automatically and can capture a screenshot to help super admin
                investigate faster. Review the current handling summary in the{" "}
                <a href="/privacy" className="font-medium underline underline-offset-4">
                  Privacy Notice
                </a>
                .
              </AlertDescription>
            </Alert>

            {!manualMode && activeIssue ? (
              <div className="rounded-md border border-amber-300/50 bg-amber-50 p-3 text-sm text-amber-900">
                <div className="flex items-center gap-2 font-medium">
                  <AlertTriangle className="h-4 w-4" />
                  Auto-detected issue
                </div>
                <div className="mt-1 text-xs">{activeIssue.message}</div>
              </div>
            ) : null}

            <div className="grid gap-2">
              <Label>Summary</Label>
              <Input
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                maxLength={160}
                placeholder="Example: Batch history did not update after assigning manufacturer"
                disabled={submitting}
              />
            </div>

            <div className="grid gap-2">
              <Label>What happened?</Label>
              <Textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                maxLength={5000}
                rows={5}
                placeholder="Describe what you were trying to do and what went wrong."
                disabled={submitting}
              />
            </div>

            <div className="rounded-md border p-3">
              <div className="mb-2 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                <Badge variant="secondary">{networkLogCount} network logs</Badge>
                <Badge variant="secondary">{runtimeIssueCount} error signals</Badge>
                <Badge variant="secondary">device context attached</Badge>
              </div>

              <div className="flex items-center justify-between gap-3">
                <div className="text-xs text-muted-foreground">
                  Screenshot capture, runtime diagnostics, and recent network logs are included to speed up debugging.
                </div>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  disabled={capturing || submitting}
                  onClick={async () => {
                    setCapturing(true);
                    const file = await captureSupportScreenshot();
                    if (file) setScreenshotFile(file);
                    setCapturing(false);
                  }}
                >
                  {capturing ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Camera className="mr-2 h-4 w-4" />}
                  Recapture
                </Button>
              </div>

              {screenshotPreviewUrl ? (
                <img
                  src={screenshotPreviewUrl}
                  alt="Auto-captured diagnostic screenshot"
                  className="mt-3 h-32 w-full rounded-md border object-cover"
                />
              ) : (
                <div className="mt-3 rounded-md border border-dashed p-3 text-xs text-muted-foreground">
                  {capturing ? "Capturing screenshot..." : "No screenshot attached yet."}
                </div>
              )}
            </div>

            <div className="flex justify-end gap-3">
              <Button variant="outline" onClick={() => setOpen(false)} disabled={submitting}>
                Cancel
              </Button>
              <Button onClick={submit} disabled={submitting}>
                {submitting ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <SendHorizontal className="mr-2 h-4 w-4" />}
                Send report
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
