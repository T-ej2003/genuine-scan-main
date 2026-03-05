import React from "react";
import { Loader2, Printer } from "lucide-react";

import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";

type PrintProgressDialogProps = {
  open: boolean;
  phase: string;
  total: number;
  printed: number;
  remaining: number;
  currentCode?: string | null;
  printerName?: string | null;
  modeLabel?: string;
  error?: string | null;
  onOpenChange?: (open: boolean) => void;
};

export function PrintProgressDialog(props: PrintProgressDialogProps) {
  const safeTotal = Math.max(0, Number(props.total || 0));
  const safePrinted = Math.max(0, Number(props.printed || 0));
  const safeRemaining = Math.max(0, Number(props.remaining || Math.max(0, safeTotal - safePrinted)));
  const progressValue = safeTotal > 0 ? Math.max(0, Math.min(100, Math.round((safePrinted / safeTotal) * 100))) : 0;

  return (
    <Dialog open={props.open} onOpenChange={props.onOpenChange}>
      <DialogContent className="sm:max-w-[560px]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Printer className="h-4 w-4" />
            Printing in progress
          </DialogTitle>
          <DialogDescription>
            Live direct-print status for your current secure print session.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="rounded-md border p-3">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="secondary">{props.modeLabel || "Auto path"}</Badge>
              <Badge variant="outline">{props.printerName || "Default printer"}</Badge>
              <Badge variant={props.error ? "destructive" : "default"}>{props.phase}</Badge>
            </div>
            {props.currentCode ? (
              <div className="mt-2 text-xs text-muted-foreground">Current code: {props.currentCode}</div>
            ) : null}
            {props.error ? <div className="mt-2 text-xs text-destructive">{props.error}</div> : null}
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span>{safePrinted.toLocaleString()} printed</span>
              <span>{safeRemaining.toLocaleString()} remaining</span>
            </div>
            <Progress value={progressValue} className="h-3" />
            <div className="text-xs text-muted-foreground">
              {safeTotal.toLocaleString()} total labels · {progressValue}% complete
            </div>
          </div>

          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
            Keep this window open until all labels are confirmed.
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
