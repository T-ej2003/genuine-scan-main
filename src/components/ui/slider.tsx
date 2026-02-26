import * as React from "react";
import * as SliderPrimitive from "@radix-ui/react-slider";

import { cn } from "@/lib/utils";

const Slider = React.forwardRef<
  React.ElementRef<typeof SliderPrimitive.Root>,
  React.ComponentPropsWithoutRef<typeof SliderPrimitive.Root>
>(({ className, ...props }, ref) => (
  <SliderPrimitive.Root
    ref={ref}
    className={cn("relative flex w-full touch-none select-none items-center py-1", className)}
    {...props}
  >
    <SliderPrimitive.Track className="relative h-2.5 w-full grow overflow-hidden rounded-full border border-white/25 bg-white/50 shadow-[inset_0_1px_2px_rgba(15,23,42,0.08)] dark:border-white/10 dark:bg-white/5">
      <SliderPrimitive.Range className="absolute h-full rounded-full bg-gradient-to-r from-primary via-primary to-emerald-400 shadow-[0_0_0_1px_rgba(255,255,255,0.1)_inset]" />
    </SliderPrimitive.Track>
    <SliderPrimitive.Thumb className="block h-5 w-5 rounded-full border border-white/70 bg-white/90 shadow-[0_8px_18px_-10px_rgba(15,23,42,0.45),0_1px_0_rgba(255,255,255,0.7)_inset] ring-offset-background transition-all duration-200 ease-out focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/70 focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 data-[disabled]:opacity-50 dark:border-white/20 dark:bg-slate-100" />
  </SliderPrimitive.Root>
));
Slider.displayName = SliderPrimitive.Root.displayName;

export { Slider };
