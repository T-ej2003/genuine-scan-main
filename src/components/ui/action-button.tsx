import type { ReactNode } from "react";
import { Loader2, Lock } from "lucide-react";

import { Button, type ButtonProps } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import { getUiActionReason, isUiActionDisabled, isUiActionVisible, type UiActionState } from "@/lib/ui-actions";

type ActionButtonProps = Omit<ButtonProps, "children"> & {
  state?: UiActionState | null;
  idleLabel: ReactNode;
  pendingLabel?: ReactNode;
  stepUpLabel?: ReactNode;
  helperText?: string | null;
  showReasonBelow?: boolean;
};

export function ActionButton({
  state,
  idleLabel,
  pendingLabel,
  stepUpLabel,
  helperText,
  showReasonBelow = true,
  className,
  ...props
}: ActionButtonProps) {
  if (!isUiActionVisible(state)) return null;

  const disabled = isUiActionDisabled(state) || props.disabled;
  const reason = getUiActionReason(state);
  const label =
    state?.availability === "pending"
      ? pendingLabel || idleLabel
      : state?.availability === "step_up"
        ? stepUpLabel || idleLabel
        : idleLabel;

  const icon =
    state?.availability === "pending" ? (
      <Loader2 className="h-4 w-4 animate-spin" />
    ) : state?.availability === "step_up" ? (
      <Lock className="h-4 w-4" />
    ) : null;

  const button = (
    <Button
      {...props}
      disabled={disabled}
      className={cn(className)}
      aria-description={reason || helperText || undefined}
    >
      {icon}
      {label}
    </Button>
  );

  return (
    <div className="space-y-1">
      {disabled && reason ? (
        <TooltipProvider delayDuration={150}>
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="inline-flex">{button}</span>
            </TooltipTrigger>
            <TooltipContent>{reason}</TooltipContent>
          </Tooltip>
        </TooltipProvider>
      ) : (
        button
      )}

      {showReasonBelow && disabled && reason ? (
        <p className="max-w-xs text-[11px] leading-5 text-muted-foreground">{reason}</p>
      ) : helperText ? (
        <p className="max-w-xs text-[11px] leading-5 text-muted-foreground">{helperText}</p>
      ) : null}
    </div>
  );
}
