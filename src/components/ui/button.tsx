import * as React from "react";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";

import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "relative isolate inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-xl border border-transparent text-sm font-medium tracking-[0.01em] ring-offset-background transition-all duration-200 ease-out focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/70 focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 disabled:saturate-50 active:scale-[0.985] backdrop-blur-md before:pointer-events-none before:absolute before:inset-0 before:rounded-[inherit] before:bg-[linear-gradient(180deg,rgba(255,255,255,0.28),rgba(255,255,255,0.08)_48%,rgba(255,255,255,0))] before:opacity-60 before:transition-opacity before:duration-200 hover:before:opacity-90 active:before:opacity-35 motion-reduce:transition-none motion-reduce:active:scale-100 [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        default:
          "bg-gradient-to-b from-primary via-primary to-emerald-500 text-primary-foreground border-emerald-400/50 shadow-[0_1px_0_rgba(255,255,255,0.24)_inset,0_16px_28px_-18px_rgba(16,185,129,0.8)] hover:-translate-y-[1px] hover:brightness-[1.03] active:translate-y-0 active:brightness-[0.98]",
        destructive:
          "bg-gradient-to-b from-destructive via-destructive to-rose-500 text-destructive-foreground border-rose-400/45 shadow-[0_1px_0_rgba(255,255,255,0.15)_inset,0_16px_28px_-18px_rgba(239,68,68,0.7)] hover:-translate-y-[1px] hover:brightness-[1.04] active:translate-y-0 active:brightness-[0.98]",
        outline:
          "border-border/80 bg-white/70 text-foreground shadow-[0_1px_0_rgba(255,255,255,0.5)_inset,0_10px_20px_-16px_rgba(15,23,42,0.35)] hover:-translate-y-[1px] hover:border-primary/30 hover:bg-white/90 active:translate-y-0 dark:bg-slate-950/60 dark:border-white/10 dark:hover:bg-slate-950/80 dark:hover:border-emerald-300/20",
        secondary:
          "border-slate-300/20 bg-secondary/85 text-secondary-foreground shadow-[0_1px_0_rgba(255,255,255,0.06)_inset,0_14px_24px_-18px_rgba(15,23,42,0.55)] hover:-translate-y-[1px] hover:bg-secondary/95 active:translate-y-0",
        ghost:
          "border-white/0 bg-white/40 text-foreground shadow-[0_1px_0_rgba(255,255,255,0.38)_inset,0_8px_18px_-16px_rgba(15,23,42,0.28)] hover:-translate-y-[1px] hover:border-white/60 hover:bg-white/70 active:translate-y-0 dark:bg-white/5 dark:text-foreground dark:hover:bg-white/10 dark:hover:border-white/10",
        link:
          "rounded-none border-0 bg-transparent p-0 text-primary shadow-none backdrop-blur-0 before:hidden hover:text-primary/90 hover:underline underline-offset-4",
      },
      size: {
        default: "h-10 px-4 py-2",
        sm: "h-9 px-3.5 text-xs",
        lg: "h-11 px-6 text-sm",
        icon: "h-10 w-10 p-0",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  },
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button";

    return (
      <Comp
        className={cn(buttonVariants({ variant, size, className }))}
        ref={ref}
        {...props}
      />
    );
  },
);
Button.displayName = "Button";

export { Button, buttonVariants };
