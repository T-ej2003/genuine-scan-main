import React from "react";
import { Loader2, Zap } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Progress } from "@/components/ui/progress";
import { cn } from "@/lib/utils";

type OperationProgressDialogProps = {
  open: boolean;
  title: string;
  description: string;
  phaseLabel?: string;
  detail?: string;
  speedLabel?: string;
  value?: number;
  indeterminate?: boolean;
};

export function OperationProgressDialog({
  open,
  title,
  description,
  phaseLabel,
  detail,
  speedLabel,
  value = 0,
  indeterminate = true,
}: OperationProgressDialogProps) {
  const safeValue = Number.isFinite(value) ? Math.min(100, Math.max(0, value)) : 0;

  return (
    <Dialog open={open} onOpenChange={() => undefined}>
      <DialogContent className="w-[calc(100vw-2rem)] max-w-[560px] overflow-hidden border-0 bg-gradient-to-b from-slate-50 via-white to-slate-100 p-0 dark:from-slate-900 dark:via-slate-950 dark:to-slate-900 [&>button]:hidden">
        <div className="border-b border-emerald-500/20 bg-gradient-to-r from-cyan-500/10 via-emerald-500/10 to-teal-500/10 px-6 py-5">
          <DialogHeader className="space-y-2">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <DialogTitle className="flex items-center gap-2 text-lg">
                <span className="flex h-8 w-8 items-center justify-center rounded-lg border border-emerald-500/30 bg-emerald-500/10">
                  <Loader2 className="h-4 w-4 animate-spin text-emerald-600" />
                </span>
                {title}
              </DialogTitle>
              {phaseLabel ? (
                <Badge variant="secondary" className="border border-emerald-500/25 bg-emerald-500/10 text-emerald-700">
                  {phaseLabel}
                </Badge>
              ) : null}
            </div>
            <DialogDescription className="text-sm text-muted-foreground">{description}</DialogDescription>
          </DialogHeader>
        </div>

        <div className="space-y-4 px-6 py-5">
          <Progress value={safeValue} className={cn("h-2 bg-muted/70", indeterminate && "animate-pulse")} />
          <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground">
            <span>{indeterminate ? "Working on your request..." : `${Math.round(safeValue)}% complete`}</span>
            {speedLabel ? (
              <span className="inline-flex items-center gap-1 font-medium text-emerald-700">
                <Zap className="h-3 w-3" />
                {speedLabel}
              </span>
            ) : null}
          </div>
          {detail ? (
            <div className="rounded-lg border border-border/70 bg-background/70 px-3 py-2 text-xs text-muted-foreground">{detail}</div>
          ) : null}
        </div>
      </DialogContent>
    </Dialog>
  );
}
